/**
 * Enumerate a GitHub org's (or user's) repositories for the supply-chain org batch
 * (Scan Queue plan Phase 6 / Section 6). Untrusted GitHub response data.
 *
 * Guarantees:
 *  - injectable `fetchImpl` so the whole thing is unit-testable offline;
 *  - Link-header pagination with a hard `maxPages` cap;
 *  - org-404 falls back to the /users/{owner}/repos endpoint (a user, not an org);
 *  - a 403 is SURFACED AS AN ERROR, never a fallback (rate limit / forbidden must
 *    not be silently treated as "no repos");
 *  - every `owner/repo` is charset-validated before it is returned (and again
 *    before it reaches `git clone` argv, in the route), so no shell/argv injection;
 *  - the token is NEVER placed in a result or an error message (it lives only in
 *    the Authorization header), and any error text is scrubbed of it defensively.
 */

const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/            // GitHub login rules
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/
// A git ref that is safe to hand to `git clone --branch`: no leading '-', no
// whitespace, no shell metacharacters, no '..' path tricks.
const REF_RE = /^[A-Za-z0-9._/-]{1,255}$/

export interface OrgRepo {
  fullName: string        // owner/repo (validated)
  owner: string
  repo: string
  url: string             // https clone url
  defaultBranch: string
  fork: boolean
  archived: boolean
}

export interface ListOwnerReposOptions {
  token?: string
  maxPages?: number
  perPage?: number
  includeForks?: boolean
  includeArchived?: boolean
  maxRepos?: number
  fetchImpl?: typeof fetch
}

export function isValidOwner(owner: string): boolean {
  return OWNER_RE.test(owner)
}

export function isValidGitRef(ref: string): boolean {
  return ref === '' || (REF_RE.test(ref) && !ref.includes('..') && !ref.startsWith('-'))
}

export function parseGithubRepo(fullName: string): { owner: string; repo: string } | null {
  const parts = fullName.split('/')
  if (parts.length !== 2) return null
  const [owner, repo] = parts
  if (!OWNER_RE.test(owner) || !REPO_RE.test(repo)) return null
  return { owner, repo }
}

/** Remove a token substring from any string before it is logged / stored / shown. */
function scrub(text: string, token?: string): string {
  if (token && token.length >= 8) return text.split(token).join('***')
  return text
}

function parseNextLink(linkHeader: string | null): boolean {
  if (!linkHeader) return false
  return /<[^>]+>;\s*rel="next"/.test(linkHeader)
}

export class GithubEnumError extends Error {
  status?: number
  constructor(message: string, status?: number) {
    super(message)
    this.name = 'GithubEnumError'
    this.status = status
  }
}

export async function listOwnerRepos(owner: string, opts: ListOwnerReposOptions = {}): Promise<OrgRepo[]> {
  if (!isValidOwner(owner)) {
    throw new GithubEnumError(`Invalid GitHub owner: ${owner}`)
  }
  const token = opts.token
  const fetchImpl = opts.fetchImpl ?? fetch
  const perPage = Math.min(100, Math.max(1, opts.perPage ?? 100))
  const maxPages = Math.max(1, opts.maxPages ?? 10)
  const maxRepos = opts.maxRepos && opts.maxRepos > 0 ? opts.maxRepos : Infinity

  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  }
  if (token) headers.Authorization = `Bearer ${token}`

  const collected: OrgRepo[] = []

  // Try the org endpoint first; a 404 means it's a user account, not an org.
  // The `type` enum DIFFERS per endpoint: /orgs accepts `sources` (non-forks),
  // /users does NOT (valid: all|owner|member) and 422s on `sources`. Forks are
  // filtered client-side anyway, so `owner` is the right user-endpoint value.
  let base = `https://api.github.com/orgs/${owner}/repos`
  let repoType = 'sources'
  let triedUserFallback = false

  for (let page = 1; page <= maxPages; page++) {
    const url = `${base}?per_page=${perPage}&page=${page}&type=${repoType}&sort=updated`
    let res: Response
    try {
      res = await fetchImpl(url, { headers })
    } catch (e) {
      throw new GithubEnumError(scrub(`GitHub request failed: ${e instanceof Error ? e.message : String(e)}`, token))
    }

    if (res.status === 404 && !triedUserFallback && base.includes('/orgs/')) {
      // Not an org -> fall back to the user endpoint and restart pagination.
      // Switch `type` to a value the /users endpoint accepts (F1).
      base = `https://api.github.com/users/${owner}/repos`
      repoType = 'owner'
      triedUserFallback = true
      page = 0 // loop ++ makes this page 1
      continue
    }
    if (res.status === 403) {
      // Rate limit / forbidden: an ERROR, never a "no repos" fallback.
      const body = await res.text().catch(() => '')
      throw new GithubEnumError(scrub(`GitHub returned 403 (rate limit or forbidden): ${body.slice(0, 200)}`, token), 403)
    }
    if (!res.ok) {
      const body = await res.text().catch(() => '')
      throw new GithubEnumError(scrub(`GitHub returned ${res.status}: ${body.slice(0, 200)}`, token), res.status)
    }

    const arr = await res.json().catch(() => null)
    if (!Array.isArray(arr)) {
      throw new GithubEnumError('GitHub returned an unexpected (non-array) body')
    }

    for (const r of arr as Array<Record<string, unknown>>) {
      const fullName = typeof r.full_name === 'string' ? r.full_name : ''
      const parsed = parseGithubRepo(fullName)
      if (!parsed) continue // skip anything that would not survive argv validation
      const fork = !!r.fork
      const archived = !!r.archived
      if (fork && !opts.includeForks) continue
      if (archived && !opts.includeArchived) continue
      collected.push({
        fullName,
        owner: parsed.owner,
        repo: parsed.repo,
        // Construct the clone URL from the VALIDATED owner/repo, never from the
        // untrusted clone_url field (F2 defense-in-depth): it becomes git clone
        // argv in the scan container.
        url: `https://github.com/${parsed.owner}/${parsed.repo}.git`,
        defaultBranch: typeof r.default_branch === 'string' ? r.default_branch : '',
        fork,
        archived,
      })
      if (collected.length >= maxRepos) return collected
    }

    if (!parseNextLink(res.headers.get('Link'))) break
  }

  return collected
}
