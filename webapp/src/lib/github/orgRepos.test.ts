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
})
