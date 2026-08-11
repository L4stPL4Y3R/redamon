/**
 * One input field, two shapes (bare name / URL) and an operator-controlled host
 * allowlist. The allowlist is the security control: the parsed host is fetched
 * server-side and lands in `git clone` argv, so "any host the user typed" would
 * be an SSRF primitive with a bearer token attached.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  parseOwnerTarget, allowedGithubHosts, apiBaseForHost, cloneBaseForHost,
  isValidGithubHost, hostHint, GITHUB_DOT_COM,
} from './ownerTarget'

const GHE = 'ghe.example.com'
const BOTH = [GITHUB_DOT_COM, GHE]

describe('parseOwnerTarget', () => {
  test('a bare name still means github.com (every pre-GHE value keeps working)', () => {
    expect(parseOwnerTarget('acme-corp')).toEqual({ host: GITHUB_DOT_COM, owner: 'acme-corp' })
    expect(parseOwnerTarget('  acme-corp  ')).toEqual({ host: GITHUB_DOT_COM, owner: 'acme-corp' })
  })

  test('accepts the github.com URL shapes an operator would paste', () => {
    for (const value of [
      'github.com/acme-corp',
      'https://github.com/acme-corp',
      'https://github.com/acme-corp/',
      'https://github.com/orgs/acme-corp',
      'https://github.com/orgs/acme-corp/repositories',
      'https://github.com/users/acme-corp',
    ]) {
      expect(parseOwnerTarget(value), value).toEqual({ host: GITHUB_DOT_COM, owner: 'acme-corp' })
    }
  })

  test('a GitHub Enterprise host is accepted only when allowlisted', () => {
    expect(parseOwnerTarget(`https://${GHE}/orgs/acme-corp`, BOTH))
      .toEqual({ host: GHE, owner: 'acme-corp' })
    expect(parseOwnerTarget(`${GHE}/acme-corp`, BOTH))
      .toEqual({ host: GHE, owner: 'acme-corp' })
    // Same string, default allowlist: refused.
    expect(parseOwnerTarget(`https://${GHE}/orgs/acme-corp`)).toBeNull()
  })

  test('the host is lowercased and compared case-insensitively', () => {
    expect(parseOwnerTarget(`https://GHE.Example.COM/acme-corp`, BOTH))
      .toEqual({ host: GHE, owner: 'acme-corp' })
  })

  test('SSRF-shaped hosts are refused even if someone allowlists them', () => {
    for (const value of [
      'https://169.254.169.254/acme',
      'https://localhost/acme',
      'https://127.0.0.1/acme',
    ]) {
      // Passed as its own allowlist, so only the host SHAPE can reject it.
      const hint = hostHint(value) as string
      expect(parseOwnerTarget(value, [hint]), value).toBeNull()
    }
  })

  test('rejects a downgrade, credentials, a port, a query and a fragment', () => {
    for (const value of [
      'http://github.com/acme-corp',
      'https://user:ghp_secret@github.com/acme-corp',
      'https://github.com:8443/acme-corp',
      'https://github.com/acme-corp?x=1',
      'https://github.com/acme-corp#frag',
      'ftp://github.com/acme-corp',
    ]) {
      expect(parseOwnerTarget(value, BOTH), value).toBeNull()
    }
  })

  test('a repository is not an account', () => {
    expect(parseOwnerTarget('acme-corp/some-repo')).toBeNull()
    expect(parseOwnerTarget('https://github.com/acme-corp/some-repo')).toBeNull()
    expect(parseOwnerTarget(`https://${GHE}/acme-corp/some-repo`, BOTH)).toBeNull()
  })

  test('rejects junk, oversized input and non-strings', () => {
    for (const value of ['', '   ', '-acme', 'acme corp', 'acme_corp', 'a'.repeat(40),
      'x'.repeat(400), 'ghe.example.com', 'https://github.com/']) {
      expect(parseOwnerTarget(value, BOTH), String(value)).toBeNull()
    }
    expect(parseOwnerTarget(null)).toBeNull()
    expect(parseOwnerTarget(undefined)).toBeNull()
    expect(parseOwnerTarget(42)).toBeNull()
  })

  test('an empty allowlist accepts nothing (fail closed)', () => {
    expect(parseOwnerTarget('acme-corp', [])).toBeNull()
  })
})

describe('allowedGithubHosts', () => {
  test('github.com is always present, a configured host is added', () => {
    expect(allowedGithubHosts('')).toEqual([GITHUB_DOT_COM])
    expect(allowedGithubHosts(null)).toEqual([GITHUB_DOT_COM])
    expect(allowedGithubHosts(` ${GHE.toUpperCase()} `)).toEqual([GITHUB_DOT_COM, GHE])
  })

  test('a junk or duplicate configured host never widens the allowlist', () => {
    expect(allowedGithubHosts('github.com')).toEqual([GITHUB_DOT_COM])
    expect(allowedGithubHosts('localhost')).toEqual([GITHUB_DOT_COM])
    expect(allowedGithubHosts('10.0.0.5')).toEqual([GITHUB_DOT_COM])
    expect(allowedGithubHosts('not a host')).toEqual([GITHUB_DOT_COM])
  })
})

describe('host helpers', () => {
  test('GHE serves the same API under /api/v3', () => {
    expect(apiBaseForHost(GITHUB_DOT_COM)).toBe('https://api.github.com')
    expect(apiBaseForHost(GHE)).toBe(`https://${GHE}/api/v3`)
    expect(cloneBaseForHost(GHE)).toBe(`https://${GHE}`)
  })

  test('isValidGithubHost requires a dotted name that is not an IP', () => {
    expect(isValidGithubHost(GHE)).toBe(true)
    expect(isValidGithubHost('localhost')).toBe(false)
    expect(isValidGithubHost('169.254.169.254')).toBe(false)
    expect(isValidGithubHost('')).toBe(false)
  })

  test('hostHint reports the host for the error message, null for a bare name', () => {
    expect(hostHint('acme-corp')).toBeNull()
    expect(hostHint(`https://${GHE}/orgs/acme`)).toBe(GHE)
    expect(hostHint(`${GHE}/acme`)).toBe(GHE)
  })
})
