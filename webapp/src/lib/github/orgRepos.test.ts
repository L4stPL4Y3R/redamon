/**
 * Scan Queue Phase 6 - GitHub org enumeration. Untrusted response data: pagination
 * bounded, org-404 falls back to user, 403 is an error not a fallback, every
 * owner/repo is validated, and the token never leaks into a result or error.
 */
import { describe, test, expect, vi } from 'vitest'
import { listOwnerRepos, parseGithubRepo, isValidGitRef, isValidOwner, GithubEnumError } from './orgRepos'

function ghResponse(body: unknown, { status = 200, next = false }: { status?: number; next?: boolean } = {}): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
    headers: { get: (h: string) => (h.toLowerCase() === 'link' && next ? '<https://api.github.com/x?page=2>; rel="next"' : null) },
  } as unknown as Response
}

const repo = (fullName: string, over: Record<string, unknown> = {}) => ({
  full_name: fullName, clone_url: `https://github.com/${fullName}.git`, default_branch: 'main', fork: false, archived: false, ...over,
})

describe('validators', () => {
  test('parseGithubRepo accepts owner/repo, rejects junk', () => {
    expect(parseGithubRepo('acme/app')).toEqual({ owner: 'acme', repo: 'app' })
    expect(parseGithubRepo('acme/app/extra')).toBeNull()
    expect(parseGithubRepo('acme/ap p')).toBeNull()
    expect(parseGithubRepo('acme/$(whoami)')).toBeNull()
  })
  test('isValidGitRef rejects injection-y refs', () => {
    expect(isValidGitRef('main')).toBe(true)
    expect(isValidGitRef('')).toBe(true)
    expect(isValidGitRef('v1.2.3')).toBe(true)
    expect(isValidGitRef('--upload-pack=x')).toBe(false)
    expect(isValidGitRef('a b')).toBe(false)
    expect(isValidGitRef('../../etc')).toBe(false)
  })
  test('isValidOwner', () => {
    expect(isValidOwner('acme')).toBe(true)
    expect(isValidOwner('bad owner')).toBe(false)
    expect(isValidOwner('-lead')).toBe(false)
  })
})

describe('listOwnerRepos', () => {
  test('paginates via the Link header up to maxPages', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(ghResponse([repo('acme/a')], { next: true }))
      .mockResolvedValueOnce(ghResponse([repo('acme/b')], { next: true }))
      .mockResolvedValueOnce(ghResponse([repo('acme/c')], { next: true }))
    const repos = await listOwnerRepos('acme', { fetchImpl, maxPages: 2 })
    expect(repos.map(r => r.fullName)).toEqual(['acme/a', 'acme/b'])
    expect(fetchImpl).toHaveBeenCalledTimes(2) // capped
  })

  test('org 404 falls back to the user endpoint', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(ghResponse('not found', { status: 404 }))
      .mockResolvedValueOnce(ghResponse([repo('alice/dotfiles')]))
    const repos = await listOwnerRepos('alice', { fetchImpl })
    expect(repos.map(r => r.fullName)).toEqual(['alice/dotfiles'])
    expect(String(fetchImpl.mock.calls[1][0])).toContain('/users/alice/repos')
  })

  test('403 is thrown, never treated as empty', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(ghResponse('rate limit', { status: 403 }))
    await expect(listOwnerRepos('acme', { fetchImpl })).rejects.toBeInstanceOf(GithubEnumError)
    await expect(listOwnerRepos('acme', { fetchImpl })).rejects.toMatchObject({ status: 403 })
  })

  test('forks and archived are excluded by default, included on request', async () => {
    const body = [repo('acme/a'), repo('acme/forked', { fork: true }), repo('acme/old', { archived: true })]
    const def = await listOwnerRepos('acme', { fetchImpl: vi.fn().mockResolvedValue(ghResponse(body)) })
    expect(def.map(r => r.repo)).toEqual(['a'])
    const all = await listOwnerRepos('acme', { fetchImpl: vi.fn().mockResolvedValue(ghResponse(body)), includeForks: true, includeArchived: true })
    expect(all.map(r => r.repo).sort()).toEqual(['a', 'forked', 'old'])
  })

  test('a repo whose name would not survive argv validation is skipped', async () => {
    const body = [repo('acme/a'), { full_name: 'acme/$(rm -rf)', clone_url: 'x', default_branch: 'main' }]
    const repos = await listOwnerRepos('acme', { fetchImpl: vi.fn().mockResolvedValue(ghResponse(body)) })
    expect(repos.map(r => r.fullName)).toEqual(['acme/a'])
  })

  test('maxRepos caps the result and stops early', async () => {
    const body = [repo('acme/a'), repo('acme/b'), repo('acme/c')]
    const repos = await listOwnerRepos('acme', { fetchImpl: vi.fn().mockResolvedValue(ghResponse(body)), maxRepos: 2 })
    expect(repos).toHaveLength(2)
  })

  test('the token never appears in an error message', async () => {
    const token = 'ghp_SECRET1234567890'
    const fetchImpl = vi.fn().mockResolvedValue(ghResponse(`boom ${token}`, { status: 500 }))
    const err = await listOwnerRepos('acme', { fetchImpl, token }).catch(e => e as Error)
    expect(err.message).not.toContain(token)
    expect(err.message).toContain('***')
  })

  test('an invalid owner is rejected before any fetch', async () => {
    const fetchImpl = vi.fn()
    await expect(listOwnerRepos('bad owner', { fetchImpl })).rejects.toBeInstanceOf(GithubEnumError)
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  test('regression F1: the org endpoint uses type=sources, the user fallback uses type=owner (never sources)', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(ghResponse('not found', { status: 404 }))
      .mockResolvedValueOnce(ghResponse([repo('alice/dotfiles')]))
    await listOwnerRepos('alice', { fetchImpl })
    const orgUrl = String(fetchImpl.mock.calls[0][0])
    const userUrl = String(fetchImpl.mock.calls[1][0])
    expect(orgUrl).toContain('/orgs/alice/repos')
    expect(orgUrl).toContain('type=sources')
    // The /users endpoint 422s on type=sources; it must switch to a valid value.
    expect(userUrl).toContain('/users/alice/repos')
    expect(userUrl).not.toContain('type=sources')
    expect(userUrl).toContain('type=owner')
  })

  test('regression F2: clone url is built from the validated owner/repo, not the untrusted clone_url', async () => {
    const hostile = { full_name: 'acme/app', clone_url: 'https://evil.example/x.git', default_branch: 'main', fork: false, archived: false }
    const repos = await listOwnerRepos('acme', { fetchImpl: vi.fn().mockResolvedValue(ghResponse([hostile])) })
    expect(repos[0].url).toBe('https://github.com/acme/app.git')
    expect(repos[0].url).not.toContain('evil.example')
  })

  test('regression F3: a stalled GitHub (abort/timeout) fails fast with a clear 504, not a hang', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(Object.assign(new Error('The operation was aborted'), { name: 'TimeoutError' }))
    const err = await listOwnerRepos('acme', { fetchImpl, timeoutMs: 5 }).catch(e => e as GithubEnumError)
    expect(err).toBeInstanceOf(GithubEnumError)
    expect((err as GithubEnumError).status).toBe(504)
    expect(err.message).toMatch(/timed out/i)
  })

  test('F3: an abort signal is passed to fetch so a slow request can be cut off', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(ghResponse([repo('acme/a')]))
    await listOwnerRepos('acme', { fetchImpl })
    const opts = fetchImpl.mock.calls[0][1] as RequestInit
    expect(opts.signal).toBeDefined()
  })

  // A personal account's own private repos are only visible via the authenticated
  // /user/repos endpoint; /users/{owner}/repos returns public repos only regardless
  // of token. When the token IS the owner, use /user/repos so private repos scan.
  test("a token for the owner's own account enumerates via /user/repos (private-capable)", async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(ghResponse({ login: 'samugit83' }))                       // resolveTokenLogin
      .mockResolvedValueOnce(ghResponse([repo('samugit83/pub'), repo('samugit83/secret')]))
    const repos = await listOwnerRepos('samugit83', { fetchImpl, token: 'ghp_x' })
    expect(String(fetchImpl.mock.calls[0][0])).toBe('https://api.github.com/user')
    const reposUrl = String(fetchImpl.mock.calls[1][0])
    expect(reposUrl).toContain('/user/repos')
    expect(reposUrl).toContain('visibility=all')
    expect(reposUrl).toContain('affiliation=owner')
    expect(reposUrl).not.toContain('/users/samugit83')  // NOT the public-only endpoint
    expect(repos.map(r => r.fullName)).toEqual(['samugit83/pub', 'samugit83/secret'])
  })

  test('the own-account match is case-insensitive', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(ghResponse({ login: 'SamuGit83' }))
      .mockResolvedValueOnce(ghResponse([repo('samugit83/a')]))
    await listOwnerRepos('samugit83', { fetchImpl, token: 't' })
    expect(String(fetchImpl.mock.calls[1][0])).toContain('/user/repos')
  })

  test('a token for a DIFFERENT account keeps the public org->user path', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(ghResponse({ login: 'someoneelse' }))  // resolveTokenLogin
      .mockResolvedValueOnce(ghResponse([repo('acme/a')]))          // /orgs/acme/repos
    const repos = await listOwnerRepos('acme', { fetchImpl, token: 't' })
    expect(String(fetchImpl.mock.calls[1][0])).toContain('/orgs/acme/repos')
    expect(String(fetchImpl.mock.calls[1][0])).not.toContain('/user/repos')
    expect(repos.map(r => r.fullName)).toEqual(['acme/a'])
  })

  test('an unreadable token login falls back to the public path (no worse than tokenless)', async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(ghResponse('unauthorized', { status: 401 }))  // resolveTokenLogin fails
      .mockResolvedValueOnce(ghResponse([repo('acme/a')]))                 // /orgs/acme/repos
    const repos = await listOwnerRepos('acme', { fetchImpl, token: 't' })
    expect(String(fetchImpl.mock.calls[1][0])).toContain('/orgs/acme/repos')
    expect(repos.map(r => r.fullName)).toEqual(['acme/a'])
  })

  test('without a token there is no /user probe (public path, unchanged)', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(ghResponse([repo('acme/a')]))
    await listOwnerRepos('acme', { fetchImpl })
    expect(String(fetchImpl.mock.calls[0][0])).toContain('/orgs/acme/repos')
  })
})
