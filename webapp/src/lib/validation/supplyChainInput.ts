/**
 * Server-side validation for the L1 supply-chain input settings.
 *
 * `supplyChainRepoUrl` and `supplyChainRepoRef` end up as arguments to a
 * `git clone` inside the scan container, so they are attacker-reachable
 * parameters and must be validated HERE, on the server. The Other Scans UI
 * validates too, but a direct PUT to /api/projects/[id] bypasses it entirely.
 *
 * The rules are deliberately narrow - an allowlist of what a GitHub coordinate
 * can look like, not a denylist of what an injection looks like:
 *
 *   - only https, and only github.com or a GitHub Enterprise host the operator
 *     registered in Global Settings (or the bare `owner/repo` shorthand, which
 *     always means github.com)
 *   - `owner` and `repo` restricted to GitHub's own charset
 *   - no credentials in the URL (`https://user:token@github.com/...`), which
 *     would otherwise be persisted in plain text and echoed back by GET
 *   - refs may not start with '-' (it would be read as a git option) and may
 *     not contain the sequences git itself rejects
 */

import { GITHUB_DOT_COM, isValidGithubHost } from '@/lib/github/ownerTarget'

export const SUPPLY_CHAIN_INPUT_MODES = ['upload', 'github'] as const
export type SupplyChainInputMode = (typeof SUPPLY_CHAIN_INPUT_MODES)[number]

// GitHub allows alphanumerics, '-', '_', '.' in owner/repo. Length-capped so a
// pathological value cannot reach the filesystem or a subprocess argv.
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/

// Branch/tag/commit. No whitespace, no '..', no leading '-', no git-special
// sequences. Covers `main`, `v1.2.3`, `release/2026-01`, and a 40-char sha.
const REF_RE = /^[A-Za-z0-9._\/-]{1,255}$/

export interface ParsedRepo {
  owner: string
  repo: string
  /** github.com, or an allowed GitHub Enterprise host. */
  host: string
  /** Canonical clone URL. Always https, always an allowed host, never credentialed. */
  cloneUrl: string
}

/**
 * Accepts `owner/repo`, `https://github.com/owner/repo`, and the same with a
 * trailing `.git` or `/`. A URL on another host is accepted only when that host
 * is in `allowedHosts` (github.com is the default and is always allowed).
 * Returns null when the value is not a safe GitHub coordinate. An empty string
 * is NOT valid here - callers decide whether empty is allowed for their mode.
 */
export function parseGithubRepo(
  raw: unknown,
  allowedHosts: string[] = [GITHUB_DOT_COM],
): ParsedRepo | null {
  let host = GITHUB_DOT_COM
  const allowed = allowedHosts.map(h => h.trim().toLowerCase()).filter(Boolean)
  if (typeof raw !== 'string') return null
  let value = raw.trim()
  if (!value || value.length > 300) return null

  if (/^https?:\/\//i.test(value)) {
    let url: URL
    try {
      url = new URL(value)
    } catch {
      return null
    }
    // Reject http:// outright rather than upgrading it: silently "fixing" a
    // downgrade hides that the operator asked for one.
    if (url.protocol !== 'https:') return null
    // A port would let an allowed hostname be aimed at an unrelated service.
    if (url.port) return null
    host = url.hostname.toLowerCase()
    if (!allowed.includes(host) || !isValidGithubHost(host)) return null
    // Credentials in the URL would be stored in plain text and returned by the
    // project GET. Refuse rather than strip, so the operator knows.
    if (url.username || url.password) return null
    if (url.search || url.hash) return null
    value = url.pathname.replace(/^\/+/, '')
  }

  value = value.replace(/\.git$/i, '').replace(/\/+$/, '')
  const parts = value.split('/')
  if (parts.length !== 2) return null

  const [owner, repo] = parts
  if (!OWNER_RE.test(owner) || !REPO_RE.test(repo)) return null
  // '..' cannot appear given the charsets above, but assert it anyway: this is
  // the value that becomes a directory name inside the scan container.
  if (owner.includes('..') || repo.includes('..')) return null

  return { owner, repo, host, cloneUrl: `https://${host}/${owner}/${repo}.git` }
}

export function isValidGitRef(raw: unknown): boolean {
  if (typeof raw !== 'string') return false
  const value = raw.trim()
  if (!value) return true // empty = the repository's default branch
  if (value.length > 255) return false
  if (value.startsWith('-')) return false        // would be parsed as an option
  if (value.startsWith('/') || value.endsWith('/')) return false
  if (value.includes('..')) return false          // git rejects it; so do we
  if (value.includes('@{')) return false          // reflog syntax
  if (value.endsWith('.lock')) return false
  return REF_RE.test(value)
}

/**
 * Validate the supply-chain fields of a project update. Returns an error string
 * for the caller to return as a 400, or null when the payload is acceptable.
 * Only validates the fields that are actually present.
 */
export function validateSupplyChainInput(
  data: Record<string, unknown>,
  allowedHosts: string[] = [GITHUB_DOT_COM],
): string | null {
  if ('supplyChainInputMode' in data) {
    const mode = data.supplyChainInputMode
    if (!SUPPLY_CHAIN_INPUT_MODES.includes(mode as SupplyChainInputMode)) {
      return `supplyChainInputMode must be one of: ${SUPPLY_CHAIN_INPUT_MODES.join(', ')}`
    }
  }

  if ('supplyChainRepoUrl' in data) {
    const raw = data.supplyChainRepoUrl
    if (typeof raw !== 'string') {
      return 'supplyChainRepoUrl must be a string'
    }
    // Empty clears the setting. Only a non-empty value has to parse.
    if (raw.trim() && !parseGithubRepo(raw, allowedHosts)) {
      const hosts = allowedHosts.join(' or ')
      return `Repository must be a repo on ${hosts}, as owner/repo or https://<host>/owner/repo (no credentials, port, query or fragment in the URL)`
    }
  }

  if ('supplyChainRepoRef' in data) {
    if (!isValidGitRef(data.supplyChainRepoRef)) {
      return 'Branch/tag/commit contains characters git does not allow'
    }
  }

  return null
}
