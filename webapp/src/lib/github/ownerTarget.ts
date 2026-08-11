/**
 * Parse "what account do I enumerate, on which host" out of a single operator
 * string, so one field accepts a bare name, an org URL, or a GitHub Enterprise
 * URL.
 *
 * WHY THE ALLOWLIST IS NOT OPTIONAL
 * ---------------------------------
 * The parsed host is used two ways: the webapp container fetches its API
 * server-side, and the scan container builds a `git clone` URL from it. A
 * free-form host would therefore be an SSRF primitive with a bearer token
 * attached (`169.254.169.254`, an internal admin panel, ...). So a host is
 * accepted ONLY when the operator has already registered it in Global Settings;
 * anything else is rejected before a single request goes out. github.com is the
 * one implicit entry.
 *
 * Everything here is shape validation on top of that allowlist: https only, no
 * credentials in the URL, no port, no query/fragment, no IP literals, and the
 * owner is charset-gated to GitHub's own login rules.
 */

export const GITHUB_DOT_COM = 'github.com'

/** GitHub login rules: alphanumerics + dashes, 39 chars. Same for org and user. */
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/
/** A dotted DNS name. The dot is required, which also excludes `localhost`. */
const HOST_RE = /^[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))+$/
/** An IPv4 literal is never a legitimate GitHub host and is a classic SSRF target. */
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/

export interface OwnerTarget {
  /** Lowercased host, always one of the allowed hosts. */
  host: string
  /** The org or user login. Which of the two it is can only be learned from the API. */
  owner: string
}

/**
 * Is this a syntactically usable GitHub host? Says nothing about whether the
 * operator allowed it - see `parseOwnerTarget`.
 */
export function isValidGithubHost(raw: unknown): boolean {
  if (typeof raw !== 'string') return false
  const host = raw.trim().toLowerCase()
  if (!host || host.length > 253) return false
  if (IPV4_RE.test(host)) return false
  return HOST_RE.test(host)
}

/** Normalize an allowlist: lowercased, deduped, github.com always present. */
export function allowedGithubHosts(enterpriseHost?: string | null): string[] {
  const hosts = [GITHUB_DOT_COM]
  const extra = (enterpriseHost || '').trim().toLowerCase()
  if (extra && extra !== GITHUB_DOT_COM && isValidGithubHost(extra)) hosts.push(extra)
  return hosts
}

/** The REST API root for a host. GHE serves the same API under /api/v3. */
export function apiBaseForHost(host: string): string {
  const h = (host || GITHUB_DOT_COM).toLowerCase()
  return h === GITHUB_DOT_COM ? 'https://api.github.com' : `https://${h}/api/v3`
}

/** The web/clone root for a host. */
export function cloneBaseForHost(host: string): string {
  return `https://${(host || GITHUB_DOT_COM).toLowerCase()}`
}

/**
 * The host a target string appears to name, WITHOUT any allowlist check, or null
 * for a bare name. Only for error messages: it lets a rejection say "that host is
 * not configured" instead of "invalid input". Never pass this to a fetch.
 */
export function hostHint(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const value = raw.trim()
  if (!value || value.length > 300) return null
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    try {
      const host = new URL(value).hostname.toLowerCase()
      return host || null
    } catch {
      return null
    }
  }
  const first = value.split('/')[0]
  return first.includes('.') ? first.toLowerCase().slice(0, 253) : null
}

/**
 * `acme`, `github.com/acme`, `https://github.com/orgs/acme`,
 * `https://ghe.example.com/acme` -> { host, owner }.
 *
 * A bare name keeps defaulting to github.com, so every value that worked before
 * this field understood hosts still works. Returns null when the value is not a
 * usable coordinate OR when its host is not in `allowedHosts` - the caller turns
 * that into a message telling the operator to register the host first.
 */
export function parseOwnerTarget(
  raw: unknown,
  allowedHosts: string[] = [GITHUB_DOT_COM],
): OwnerTarget | null {
  if (typeof raw !== 'string') return null
  const value = raw.trim()
  if (!value || value.length > 300) return null

  const allowed = allowedHosts.map(h => h.trim().toLowerCase()).filter(Boolean)
  if (allowed.length === 0) return null

  let host = GITHUB_DOT_COM
  let path = value

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    let url: URL
    try {
      url = new URL(value)
    } catch {
      return null
    }
    // Reject http:// rather than upgrading it: silently "fixing" a downgrade
    // hides that the operator asked for one.
    if (url.protocol !== 'https:') return null
    // Credentials would be sent to the host and could be persisted; a port would
    // let an allowed hostname be pointed at an unrelated internal service.
    if (url.username || url.password || url.port) return null
    if (url.search || url.hash) return null
    host = url.hostname.toLowerCase()
    path = url.pathname
  } else if (value.includes('/')) {
    const [first, ...rest] = value.split('/')
    // A leading segment that looks like a host is one ("ghe.example.com/acme");
    // otherwise this is `owner/repo`, which is a repository, not an account.
    if (!first.includes('.')) return null
    host = first.toLowerCase()
    path = rest.join('/')
  }

  if (!isValidGithubHost(host)) return null
  if (!allowed.includes(host)) return null

  const segments = path.split('/').map(s => s.trim()).filter(Boolean)
  // GitHub's own URLs for an account: /acme, /orgs/acme, /users/acme, and the
  // listing pages that hang off them (/orgs/acme/repositories).
  if (segments.length > 1 && (segments[0] === 'orgs' || segments[0] === 'users')) {
    segments.shift()
    // /orgs/acme/repositories is still the account; /orgs/acme/foo/bar is not.
    if (segments.length > 2) return null
  } else if (segments.length !== 1) {
    // Two bare segments is `owner/repo`: a repository, handled by the
    // single-repo input, not by an account enumeration.
    return null
  }

  const owner = segments[0]
  if (!owner || !OWNER_RE.test(owner)) return null

  return { host, owner }
}
