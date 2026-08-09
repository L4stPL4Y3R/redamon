/**
 * Scan Queue Phase 6 - supply-chain org batch creation. guardProject first;
 * token from settings never body; enumerate; then batch + items + one
 * supply_chain_repo JobQueue row (priority -10) per repo in one transaction.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  guardProject: vi.fn(),
  effectiveUser: vi.fn(),
  projectFindUnique: vi.fn(),
  userSettingsFindUnique: vi.fn(),
  batchCreate: vi.fn(),
  jobCreate: vi.fn(),
  itemCreate: vi.fn(),
  listOwnerRepos: vi.fn(),
}))

vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => h.guardProject(...a) }))
vi.mock('@/lib/session', () => ({ getEffectiveUser: () => h.effectiveUser() }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.projectFindUnique(...a) },
    userSettings: { findUnique: (...a: unknown[]) => h.userSettingsFindUnique(...a) },
    $transaction: async (cb: (tx: unknown) => unknown) => cb({
      supplyChainBatch: { create: (...a: unknown[]) => h.batchCreate(...a) },
      jobQueue: { create: (...a: unknown[]) => h.jobCreate(...a) },
      supplyChainBatchItem: { create: (...a: unknown[]) => h.itemCreate(...a) },
    }),
  },
}))
vi.mock('@/lib/github/orgRepos', async orig => ({
  ...(await orig<typeof import('@/lib/github/orgRepos')>()),
  listOwnerRepos: (...a: unknown[]) => h.listOwnerRepos(...a),
}))

import { POST } from './route'

const PROJECT = {
  id: 'p1', userId: 'u1', supplyChainOrgName: 'acme', supplyChainOrgIncludeForks: false,
  supplyChainOrgIncludeArchived: false, supplyChainOrgMaxRepos: 50, supplyChainOrgRef: '',
  supplyChainOrgDeepAnalysisEnabled: true, supplyChainRepoScope: '',
  supplyChainInputMode: 'github', supplyChainSbomFile: '', supplyChainRepoUrl: '', supplyChainRepoRef: '',
  supplyChainDeepAnalysisEnabled: false,
}
const REPOS = [
  { fullName: 'acme/a', owner: 'acme', repo: 'a', url: 'https://github.com/acme/a.git', defaultBranch: 'main', fork: false, archived: false },
  { fullName: 'acme/b', owner: 'acme', repo: 'b', url: 'https://github.com/acme/b.git', defaultBranch: 'dev', fork: false, archived: false },
]

const post = (body: unknown = {}) => new NextRequest('http://x', { method: 'POST', body: JSON.stringify(body) })
const sp = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  h.guardProject.mockResolvedValue(null)
  h.effectiveUser.mockResolvedValue({ userId: 'u1' })
  h.projectFindUnique.mockResolvedValue(PROJECT)
  h.userSettingsFindUnique.mockResolvedValue({ githubAccessToken: 'ghp_x' })
  h.listOwnerRepos.mockResolvedValue(REPOS)
  let n = 0
  h.batchCreate.mockResolvedValue({ id: 'batch1' })
  h.jobCreate.mockImplementation(async () => ({ id: `job${++n}` }))
  h.itemCreate.mockResolvedValue({})
})

test('non-ownership yields the guard response, no work', async () => {
  h.guardProject.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
  const res = await POST(post(), sp('p1'))
  expect(res.status).toBe(404)
  expect(h.listOwnerRepos).not.toHaveBeenCalled()
})

test('creates a batch + one supply_chain_repo job per repo (priority -10)', async () => {
  const res = await POST(post(), sp('p1'))
  expect(res.status).toBe(201)
  const body = await res.json()
  expect(body).toMatchObject({ ok: true, batchId: 'batch1', totalItems: 2 })
  expect(h.jobCreate).toHaveBeenCalledTimes(2)
  expect(h.itemCreate).toHaveBeenCalledTimes(2)
  const jobData = h.jobCreate.mock.calls[0][0].data
  expect(jobData).toMatchObject({ kind: 'supply_chain_repo', priority: -10, batchId: 'batch1', status: 'queued' })
  expect(jobData.payload).toMatchObject({ repo_full_name: 'acme/a', repo_url: 'https://github.com/acme/a.git', ref: 'main', deep_analysis: true })
})

test('the token comes from settings, never the request body', async () => {
  await POST(post({ token: 'ghp_EVIL' }), sp('p1'))
  const opts = h.listOwnerRepos.mock.calls[0][1]
  expect(opts.token).toBe('ghp_x')
})

test('an invalid org is a 400 before enumeration', async () => {
  h.projectFindUnique.mockResolvedValue({ ...PROJECT, supplyChainOrgName: '' })
  const res = await POST(post({ org: 'bad org' }), sp('p1'))
  expect(res.status).toBe(400)
  expect(h.listOwnerRepos).not.toHaveBeenCalled()
})

test('a 403 from GitHub surfaces as an error, no batch created', async () => {
  const { GithubEnumError } = await import('@/lib/github/orgRepos')
  h.listOwnerRepos.mockRejectedValue(new GithubEnumError('rate limit', 403))
  const res = await POST(post(), sp('p1'))
  expect(res.status).toBe(403)
  expect(h.batchCreate).not.toHaveBeenCalled()
})

test('zero repos is a 400, no batch', async () => {
  h.listOwnerRepos.mockResolvedValue([])
  const res = await POST(post(), sp('p1'))
  expect(res.status).toBe(400)
  expect(h.batchCreate).not.toHaveBeenCalled()
})
