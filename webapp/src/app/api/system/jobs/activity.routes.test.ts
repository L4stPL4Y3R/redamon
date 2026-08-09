/**
 * Scan Queue - Activity view API (Phase 5): system/jobs (tenancy), cancel +
 * reconfirm (object-level authz via projectId re-resolved from the row).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { settingsFingerprint } from '@/lib/jobQueue'

const h = vi.hoisted(() => ({
  effectiveUser: vi.fn(),
  guardProject: vi.fn(),
  jqFindUnique: vi.fn(),
  jqFindMany: vi.fn(),
  jqUpdate: vi.fn(),
  jqUpdateMany: vi.fn(),
  jqGroupBy: vi.fn(),
  jqCount: vi.fn(),
  projectFindUnique: vi.fn(),
  orchestratorFetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    jobQueue: {
      findUnique: (...a: unknown[]) => h.jqFindUnique(...a),
      findMany: (...a: unknown[]) => h.jqFindMany(...a),
      update: (...a: unknown[]) => h.jqUpdate(...a),
      updateMany: (...a: unknown[]) => h.jqUpdateMany(...a),
      groupBy: (...a: unknown[]) => h.jqGroupBy(...a),
      count: (...a: unknown[]) => h.jqCount(...a),
    },
    project: { findUnique: (...a: unknown[]) => h.projectFindUnique(...a) },
  },
}))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.effectiveUser(),
  guardProject: (...a: unknown[]) => h.guardProject(...a),
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))

import { GET as systemJobs } from './route'
import { POST as cancel } from '../../job-queue/[id]/cancel/route'
import { POST as reconfirm } from '../../job-queue/[id]/reconfirm/route'

const PROJECT = {
  id: 'p1', targetDomain: 'example.com', ipMode: false, targetIps: [],
  scanModules: ['port_scan'], targetGuardrailEnabled: true, stealthMode: false,
}

const req = () => new NextRequest('http://x')
const sp = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  h.effectiveUser.mockResolvedValue({ userId: 'u1' })
  h.guardProject.mockResolvedValue(null) // access allowed
  h.jqUpdate.mockResolvedValue({})
  h.jqUpdateMany.mockResolvedValue({ count: 1 })
  h.projectFindUnique.mockResolvedValue(PROJECT)
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ remaining_for_new: 123 }) })
})

describe('GET /api/system/jobs', () => {
  test('splits own rows by state and aggregates others', async () => {
    h.jqFindMany.mockImplementation((args: { where: { status: { in: string[] } } }) => {
      if (args.where.status.in.includes('running')) {
        return Promise.resolve([
          { id: 'a', projectId: 'p1', kind: 'full_recon', status: 'running', priority: 10, attempts: 0, blockedCode: '', blockedReason: '', error: '', envelopeBytes: BigInt(2147483648), enqueuedAt: new Date(), startedAt: new Date(), finishedAt: null },
          { id: 'b', projectId: 'p1', kind: 'gvm', status: 'queued', priority: 0, attempts: 1, blockedCode: 'ram', blockedReason: 'no mem', error: '', envelopeBytes: BigInt(2684354560), enqueuedAt: new Date(), startedAt: null, finishedAt: null },
          { id: 'c', projectId: 'p1', kind: 'trufflehog', status: 'needs_review', priority: 0, attempts: 0, blockedCode: 'settings_changed', blockedReason: 'changed', error: '', envelopeBytes: BigInt(805306368), enqueuedAt: new Date(), startedAt: null, finishedAt: null },
        ])
      }
      return Promise.resolve([]) // recent
    })
    h.jqGroupBy.mockResolvedValue([{ status: 'queued', _count: { _all: 3 } }, { status: 'running', _count: { _all: 1 } }])
    h.jqCount.mockResolvedValue(2)

    const res = await systemJobs(req())
    const body = await res.json()
    expect(body.mine.running).toHaveLength(1)
    expect(body.mine.queued).toHaveLength(1)
    expect(body.mine.queued[0]).toMatchObject({ blockedReason: 'no mem', envelopeBytes: 2684354560 })
    expect(body.mine.needsReview).toHaveLength(1)
    expect(body.others).toMatchObject({ queued: 3, running: 1, needsReview: 2 })
    expect(body.ledger).toMatchObject({ remaining_for_new: 123 })
  })

  test('renders even when the orchestrator is unreachable', async () => {
    h.jqFindMany.mockResolvedValue([])
    h.jqGroupBy.mockResolvedValue([])
    h.jqCount.mockResolvedValue(0)
    h.orchestratorFetch.mockRejectedValue(new Error('down'))
    const res = await systemJobs(req())
    expect((await res.json()).ledger).toBeNull()
  })
})

describe('POST cancel', () => {
  test('a missing row is a 404', async () => {
    h.jqFindUnique.mockResolvedValue(null)
    const res = await cancel(req(), sp('x'))
    expect(res.status).toBe(404)
  })

  test('non-ownership yields the guard response (404), never a cancel', async () => {
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p2', status: 'queued' })
    h.guardProject.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await cancel(req(), sp('j1'))
    expect(res.status).toBe(404)
    expect(h.jqUpdateMany).not.toHaveBeenCalled()
  })

  test('a queued row is canceled', async () => {
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p1', status: 'queued' })
    const res = await cancel(req(), sp('j1'))
    expect((await res.json()).ok).toBe(true)
    expect(h.jqUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ status: 'canceled' }),
    }))
  })

  test('a running row cannot be canceled (409)', async () => {
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p1', status: 'running' })
    const res = await cancel(req(), sp('j1'))
    expect(res.status).toBe(409)
    expect(h.jqUpdateMany).not.toHaveBeenCalled()
  })
})

describe('POST reconfirm', () => {
  test('a needs_review row is requeued with a freshly recomputed fingerprint', async () => {
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p1', kind: 'full_recon', status: 'needs_review' })
    const res = await reconfirm(req(), sp('j1'))
    expect((await res.json()).ok).toBe(true)
    expect(h.jqUpdate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        status: 'queued',
        settingsHash: settingsFingerprint('full_recon', PROJECT as unknown as Record<string, unknown>),
        blockedCode: '',
      }),
    }))
  })

  test('a non-needs_review row is a 409', async () => {
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p1', kind: 'full_recon', status: 'queued' })
    const res = await reconfirm(req(), sp('j1'))
    expect(res.status).toBe(409)
    expect(h.jqUpdate).not.toHaveBeenCalled()
  })

  test('non-ownership yields 404', async () => {
    h.jqFindUnique.mockResolvedValue({ id: 'j1', projectId: 'p2', kind: 'full_recon', status: 'needs_review' })
    h.guardProject.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await reconfirm(req(), sp('j1'))
    expect(res.status).toBe(404)
  })
})
