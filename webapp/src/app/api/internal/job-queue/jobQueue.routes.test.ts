/**
 * Scan Queue — the dispatcher's internal API (plan Phase 2). Internal-key only, so
 * each route rejects non-internal first. Beyond that the DISPATCH route is the
 * fail-closed core: project gone -> failed, settings fingerprint changed ->
 * needs_review with NO start call (C-4), another job for the project -> busy,
 * agent running + full_recon -> deferred (C-5), else the same start path a button
 * uses. The RECONCILE route closes finished 'running' rows even with no browser
 * (C-6), and never closes a still-active one.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { settingsFingerprint } from '@/lib/jobQueue'

const h = vi.hoisted(() => ({
  isInternal: vi.fn(),
  jqFindUnique: vi.fn(),
  jqUpdateMany: vi.fn(),
  jqFindFirst: vi.fn(),
  jqUpdate: vi.fn(),
  jqFindMany: vi.fn(),
  jqCount: vi.fn(),
  projectFindUnique: vi.fn(),
  conversationFindFirst: vi.fn(),
  dispatchStart: vi.fn(),
  stopScan: vi.fn(),
}))

vi.mock('@/lib/session', () => ({ isInternalRequest: (...a: unknown[]) => h.isInternal(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    jobQueue: {
      findUnique: (...a: unknown[]) => h.jqFindUnique(...a),
      updateMany: (...a: unknown[]) => h.jqUpdateMany(...a),
      findFirst: (...a: unknown[]) => h.jqFindFirst(...a),
      update: (...a: unknown[]) => h.jqUpdate(...a),
      findMany: (...a: unknown[]) => h.jqFindMany(...a),
      count: (...a: unknown[]) => h.jqCount(...a),
    },
    project: { findUnique: (...a: unknown[]) => h.projectFindUnique(...a) },
    conversation: { findFirst: (...a: unknown[]) => h.conversationFindFirst(...a) },
  },
}))
vi.mock('@/lib/startScan', () => ({
  dispatchStart: (...a: unknown[]) => h.dispatchStart(...a),
  stopScan: (...a: unknown[]) => h.stopScan(...a),
}))

import { POST as dispatch } from './[id]/dispatch/route'
import { GET as candidates } from './candidates/route'
import { POST as reconcile } from './reconcile/route'

const PROJECT = {
  id: 'p1', userId: 'u1', targetDomain: 'example.com', ipMode: false,
  targetIps: [], scanModules: ['port_scan'], targetGuardrailEnabled: true, stealthMode: false,
}
const HASH = settingsFingerprint('full_recon', PROJECT as unknown as Record<string, unknown>)

function baseRow(over: Record<string, unknown> = {}) {
  return {
    id: 'j1', projectId: 'p1', userId: 'u1', kind: 'full_recon', payload: {},
    settingsHash: HASH, status: 'queued', attempts: 0, maxAttempts: 20, ...over,
  }
}

const post = (url: string, body: unknown = {}) => new NextRequest(url, {
  method: 'POST', headers: { 'x-internal-key': 'k' }, body: JSON.stringify(body),
})
const get = (url: string) => new NextRequest(url, { method: 'GET', headers: { 'x-internal-key': 'k' } })
const sp = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  h.isInternal.mockReturnValue(true)
  h.jqFindUnique.mockResolvedValue(baseRow())
  h.jqUpdateMany.mockResolvedValue({ count: 1 })
  h.jqFindFirst.mockResolvedValue(null)
  h.jqUpdate.mockResolvedValue({})
  h.jqFindMany.mockResolvedValue([])
  h.jqCount.mockResolvedValue(0)
  h.projectFindUnique.mockResolvedValue(PROJECT)
  h.conversationFindFirst.mockResolvedValue(null)
  h.dispatchStart.mockResolvedValue({ ok: true, runId: 'r1', scanJobId: 'sj1' })
  h.stopScan.mockResolvedValue(undefined)
})

describe('dispatch route auth', () => {
  test('rejects a non-internal caller', async () => {
    h.isInternal.mockReturnValue(false)
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect(res.status).toBe(401)
    expect(h.dispatchStart).not.toHaveBeenCalled()
  })
})

describe('dispatch route fail-closed checks', () => {
  test('a changed settings fingerprint -> needs_review and NO start call (C-4)', async () => {
    h.jqFindUnique.mockResolvedValue(baseRow({ settingsHash: 'stale-hash' }))
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.needsReview).toBe(true)
    expect(h.dispatchStart).not.toHaveBeenCalled()
    expect(h.jqUpdate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'needs_review', blockedCode: 'settings_changed' }),
    }))
  })

  test('a deleted project -> failed, never dispatches (C-7)', async () => {
    h.projectFindUnique.mockResolvedValue(null)
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.ok).toBe(false)
    expect(h.dispatchStart).not.toHaveBeenCalled()
    expect(h.jqUpdate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'failed' }),
    }))
  })

  test('another running job for the project -> busy, no start (C-12)', async () => {
    h.jqFindFirst.mockResolvedValue({ id: 'other' })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.blocked).toBe('busy')
    expect(h.dispatchStart).not.toHaveBeenCalled()
  })

  test('agent running + full_recon -> deferred, no start (C-5)', async () => {
    h.conversationFindFirst.mockResolvedValue({ id: 'c1' })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.blocked).toBe('agent_running')
    expect(h.dispatchStart).not.toHaveBeenCalled()
    expect(h.jqUpdate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'queued', blockedCode: 'agent_running' }),
    }))
  })

  test('a claim lost to a concurrent dispatch -> 409, no start', async () => {
    h.jqUpdateMany.mockResolvedValue({ count: 0 })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    expect(res.status).toBe(409)
    expect(h.dispatchStart).not.toHaveBeenCalled()
  })
})

describe('dispatch route happy + failure paths', () => {
  test('all checks pass -> running (conditional on still dispatching), start called, ids recorded', async () => {
    // claim updateMany -> {count:1}; success updateMany -> {count:1} (won the race)
    h.jqUpdateMany.mockResolvedValue({ count: 1 })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.ok).toBe(true)
    expect(h.dispatchStart).toHaveBeenCalledWith('full_recon', 'p1', expect.objectContaining({ actorUserId: 'u1' }))
    // The success write is guarded on status='dispatching' so a concurrent cancel wins.
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: 'j1', status: 'dispatching' }),
      data: expect.objectContaining({ status: 'running', runId: 'r1', scanJobId: 'sj1' }),
    }))
    expect(h.stopScan).not.toHaveBeenCalled()
  })

  test('regression F1: a cancel during dispatch is NOT resurrected; the started scan is stopped', async () => {
    // claim wins (count 1); the success write loses because a cancel flipped the row
    // out of 'dispatching' (count 0).
    h.jqUpdateMany
      .mockResolvedValueOnce({ count: 1 })   // claim
      .mockResolvedValueOnce({ count: 0 })   // success write lost to the cancel
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.ok).toBe(false)
    expect(body.canceledDuringDispatch).toBe(true)
    // The scan already started, so it must be stopped rather than left orphaned.
    expect(h.stopScan).toHaveBeenCalledWith('full_recon', 'p1', 'r1')
  })

  test('a temporary RAM refusal requeues with backoff', async () => {
    h.dispatchStart.mockResolvedValue({ ok: false, status: 429, error: 'no mem', limit: { limitType: 'ram' } })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.temporary).toBe(true)
    expect(h.jqUpdate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'queued', blockedCode: 'ram', attempts: 1 }),
    }))
  })

  test('a permanent refusal fails the job', async () => {
    h.dispatchStart.mockResolvedValue({ ok: false, status: 400, error: 'bad config' })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.failed).toBe(true)
    expect(h.jqUpdate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'failed' }),
    }))
  })

  test('final temporary attempt gives up as failed', async () => {
    h.jqFindUnique.mockResolvedValue(baseRow({ attempts: 19, maxAttempts: 20 }))
    h.dispatchStart.mockResolvedValue({ ok: false, status: 429, error: 'no mem', limit: { limitType: 'ram' } })
    const res = await dispatch(post('http://x/api/internal/job-queue/j1/dispatch'), sp('j1'))
    const body = await res.json()
    expect(body.failed).toBe(true)
  })
})

describe('candidates route', () => {
  test('returns ordered ready rows + activeCount from the in-flight set', async () => {
    h.jqFindMany
      .mockResolvedValueOnce([{ projectId: 'pBusy' }, { projectId: 'pBusy' }]) // in-flight (2 rows, 1 project)
      .mockResolvedValueOnce([
        { id: 'a', projectId: 'p1', userId: 'u1', kind: 'gvm', envelopeBytes: BigInt(2684354560), priority: 10, enqueuedAt: new Date('2026-08-09T00:00:00Z'), attempts: 0, maxAttempts: 20 },
      ])
    const res = await candidates(get('http://x/api/internal/job-queue/candidates'))
    const body = await res.json()
    expect(body.activeCount).toBe(2)
    expect(body.candidates[0]).toMatchObject({ id: 'a', kind: 'gvm', envelopeBytes: 2684354560 })
  })

  test('regression F2: queued jobs of an already-busy project are excluded from candidates', async () => {
    h.jqFindMany
      .mockResolvedValueOnce([{ projectId: 'pBusy' }]) // in-flight for pBusy
      .mockResolvedValueOnce([])
    await candidates(get('http://x/api/internal/job-queue/candidates'))
    // The queued query must exclude pBusy, so its big head job can't trip the
    // dispatcher's head-of-line RAM break and starve other tenants.
    expect(h.jqFindMany).toHaveBeenLastCalledWith(expect.objectContaining({
      where: expect.objectContaining({ projectId: { notIn: ['pBusy'] } }),
    }))
  })

  test('rejects non-internal', async () => {
    h.isInternal.mockReturnValue(false)
    const res = await candidates(get('http://x/api/internal/job-queue/candidates'))
    expect(res.status).toBe(401)
  })
})

describe('reconcile route (C-6)', () => {
  test('closes a running row whose project is no longer active and past grace', async () => {
    h.jqFindMany.mockResolvedValue([
      { id: 'j1', projectId: 'p1', startedAt: new Date(Date.now() - 5 * 60_000) },
    ])
    h.jqUpdateMany.mockResolvedValue({ count: 1 })
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p2'] }))
    const body = await res.json()
    expect(body.closed).toBe(1)
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'done' }),
    }))
  })

  test('does NOT close a row whose project is still active', async () => {
    h.jqFindMany.mockResolvedValue([
      { id: 'j1', projectId: 'p1', startedAt: new Date(Date.now() - 5 * 60_000) },
    ])
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: ['p1'] }))
    const body = await res.json()
    expect(body.closed).toBe(0)
    expect(h.jqUpdateMany).not.toHaveBeenCalled()
  })

  test('does NOT close a freshly-started row inside the grace window', async () => {
    h.jqFindMany.mockResolvedValue([
      { id: 'j1', projectId: 'p1', startedAt: new Date() },
    ])
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    const body = await res.json()
    expect(body.closed).toBe(0)
  })

  test('the close is guarded on status=running, so a repeat reconcile is idempotent', async () => {
    h.jqFindMany.mockResolvedValue([
      { id: 'j1', projectId: 'p1', startedAt: new Date(Date.now() - 5 * 60_000) },
    ])
    h.jqUpdateMany.mockResolvedValue({ count: 1 })
    await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: [] }))
    // The WHERE clause re-checks status='running', so a concurrent close (or a
    // second reconcile pass) can never double-transition the same row.
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ id: 'j1', status: 'running' }),
    }))
  })

  test('a malformed body (activeProjects absent / not an array) is treated as no active projects', async () => {
    h.jqFindMany.mockResolvedValue([{ id: 'j1', projectId: 'p1', startedAt: new Date(Date.now() - 5 * 60_000) }])
    h.jqUpdateMany.mockResolvedValue({ count: 1 })
    const res = await reconcile(post('http://x/api/internal/job-queue/reconcile', { activeProjects: 'oops' }))
    expect((await res.json()).closed).toBe(1) // nothing active -> the stale row closes
  })
})
