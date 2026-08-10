/**
 * Scan Timeline — retention / GC (Section 5).
 *
 * The policy must never delete the two things a user cannot get back: the current
 * version (the live graph's identity) and anything explicitly pinned.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const prismaMock = vi.hoisted(() => ({
  scanVersion: { findMany: vi.fn(), deleteMany: vi.fn() },
  scanJob: { deleteMany: vi.fn(), findMany: vi.fn() },
}))
vi.mock('@/lib/prisma', () => ({ default: prismaMock }))

import {
  applyRetention,
  applyRetentionSafe,
  retentionKeep,
  failedJobRetentionDays,
} from './scanRetention'

const version = (seq: number) => ({ id: `v${seq}`, seq })

beforeEach(() => {
  vi.clearAllMocks()
  delete process.env.SCAN_VERSION_RETENTION_KEEP
  delete process.env.SCAN_JOB_FAILED_RETENTION_DAYS
  prismaMock.scanVersion.findMany.mockResolvedValue([])
  prismaMock.scanVersion.deleteMany.mockResolvedValue({ count: 0 })
  prismaMock.scanJob.deleteMany.mockResolvedValue({ count: 0 })
  prismaMock.scanJob.findMany.mockResolvedValue([])
})
afterEach(() => {
  delete process.env.SCAN_VERSION_RETENTION_KEEP
  delete process.env.SCAN_JOB_FAILED_RETENTION_DAYS
})

describe('config', () => {
  test('keep defaults to 20 and tolerates garbage', () => {
    expect(retentionKeep()).toBe(20)
    process.env.SCAN_VERSION_RETENTION_KEEP = 'lots'
    expect(retentionKeep()).toBe(20)
    process.env.SCAN_VERSION_RETENTION_KEEP = '3'
    expect(retentionKeep()).toBe(3)
  })

  test('failed-job retention defaults to 30 days', () => {
    expect(failedJobRetentionDays()).toBe(30)
  })
})

describe('C-3: a version referenced by a non-terminal job is protected', () => {
  test('retention skips a doomed version a queued/running ScanJob still points to', async () => {
    process.env.SCAN_VERSION_RETENTION_KEEP = '1'
    // 3 unpinned versions newest-first; keep=1 dooms v2 and v1.
    prismaMock.scanVersion.findMany.mockResolvedValue([version(3), version(2), version(1)])
    // A queued job still references v2, so it must survive.
    prismaMock.scanJob.findMany.mockResolvedValue([{ versionId: 'v2' }])
    const res = await applyRetention('p1')
    expect(res.deletedVersionIds).toEqual(['v1'])
    expect(prismaMock.scanVersion.deleteMany).toHaveBeenCalledWith({ where: { id: { in: ['v1'] } } })
  })

  test('nothing is deleted when the only doomed version is referenced', async () => {
    process.env.SCAN_VERSION_RETENTION_KEEP = '1'
    prismaMock.scanVersion.findMany.mockResolvedValue([version(2), version(1)])
    prismaMock.scanJob.findMany.mockResolvedValue([{ versionId: 'v1' }])
    const res = await applyRetention('p1')
    expect(res.deletedVersionIds).toEqual([])
    expect(prismaMock.scanVersion.deleteMany).not.toHaveBeenCalled()
  })
})

describe('applyRetention', () => {
  test('only considers past, unpinned versions', async () => {
    process.env.SCAN_VERSION_RETENTION_KEEP = '2'
    await applyRetention('p1')
    expect(prismaMock.scanVersion.findMany).toHaveBeenCalledWith(expect.objectContaining({
      where: { projectId: 'p1', isCurrent: false, pinned: false },
      orderBy: { seq: 'desc' },
    }))
  })

  test('keeps the newest N and deletes the rest', async () => {
    process.env.SCAN_VERSION_RETENTION_KEEP = '2'
    prismaMock.scanVersion.findMany.mockResolvedValue([version(5), version(4), version(3), version(2)])
    prismaMock.scanVersion.deleteMany.mockResolvedValue({ count: 2 })
    const res = await applyRetention('p1')
    expect(res.deletedVersionIds).toEqual(['v3', 'v2'])
    expect(prismaMock.scanVersion.deleteMany).toHaveBeenCalledWith({ where: { id: { in: ['v3', 'v2'] } } })
  })

  test('deletes nothing when the timeline is within the policy', async () => {
    process.env.SCAN_VERSION_RETENTION_KEEP = '5'
    prismaMock.scanVersion.findMany.mockResolvedValue([version(3), version(2)])
    const res = await applyRetention('p1')
    expect(res.deletedVersionIds).toEqual([])
    expect(prismaMock.scanVersion.deleteMany).not.toHaveBeenCalled()
  })

  test('keep=0 disables version GC entirely', async () => {
    process.env.SCAN_VERSION_RETENTION_KEEP = '0'
    prismaMock.scanVersion.findMany.mockResolvedValue([version(3), version(2), version(1)])
    const res = await applyRetention('p1')
    expect(res.deletedVersionIds).toEqual([])
    expect(prismaMock.scanVersion.findMany).not.toHaveBeenCalled()
    expect(prismaMock.scanVersion.deleteMany).not.toHaveBeenCalled()
  })

  test('prunes old failed jobs only', async () => {
    prismaMock.scanJob.deleteMany.mockResolvedValue({ count: 4 })
    const res = await applyRetention('p1')
    const where = prismaMock.scanJob.deleteMany.mock.calls[0][0].where
    expect(where.projectId).toBe('p1')
    expect(where.status).toBe('failed')
    expect(where.createdAt.lt).toBeInstanceOf(Date)
    expect(res.deletedFailedJobs).toBe(4)
  })

  test('failed-job retention of 0 days disables job GC', async () => {
    process.env.SCAN_JOB_FAILED_RETENTION_DAYS = '0'
    await applyRetention('p1')
    expect(prismaMock.scanJob.deleteMany).not.toHaveBeenCalled()
  })
})

describe('idempotency', () => {
  test('a second run deletes nothing (the first already trimmed to the policy)', async () => {
    process.env.SCAN_VERSION_RETENTION_KEEP = '2'
    prismaMock.scanVersion.findMany.mockResolvedValueOnce([version(5), version(4), version(3)])
    prismaMock.scanVersion.deleteMany.mockResolvedValue({ count: 1 })
    const first = await applyRetention('p1')
    expect(first.deletedVersionIds).toEqual(['v3'])

    // Second pass sees the trimmed list.
    prismaMock.scanVersion.deleteMany.mockClear()
    prismaMock.scanVersion.findMany.mockResolvedValueOnce([version(5), version(4)])
    const second = await applyRetention('p1')
    expect(second.deletedVersionIds).toEqual([])
    expect(prismaMock.scanVersion.deleteMany).not.toHaveBeenCalled()
  })
})

describe('applyRetentionSafe', () => {
  test('swallows failures so it can never break the request that triggered it', async () => {
    prismaMock.scanVersion.findMany.mockRejectedValue(new Error('db down'))
    await expect(applyRetentionSafe('p1')).resolves.toBeNull()
  })
})
