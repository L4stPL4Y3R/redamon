/**
 * Scan Queue - enqueueJob (Phase 3). It writes a queued JobQueue row with a
 * settings fingerprint computed at enqueue (C-4), refuses an unknown kind, and
 * refuses an ai_attack that carries an inline api_key (the secret must never be
 * stored in a row).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  projectFindUnique: vi.fn(),
  jqCreate: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.projectFindUnique(...a) },
    jobQueue: { create: (...a: unknown[]) => h.jqCreate(...a) },
  },
}))

import { enqueueJob } from './enqueueJob'
import { settingsFingerprint } from './jobQueue'

const PROJECT = {
  id: 'p1', targetDomain: 'example.com', ipMode: false, targetIps: [],
  scanModules: ['port_scan'], targetGuardrailEnabled: true, stealthMode: false,
}

beforeEach(() => {
  vi.clearAllMocks()
  h.projectFindUnique.mockResolvedValue(PROJECT)
  h.jqCreate.mockResolvedValue({ id: 'jq1' })
})

test('an unknown kind is refused with 400 and writes nothing', async () => {
  const r = await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'nope' })
  expect(r).toMatchObject({ ok: false, status: 400 })
  expect(h.jqCreate).not.toHaveBeenCalled()
})

test('a missing project is a 404', async () => {
  h.projectFindUnique.mockResolvedValue(null)
  const r = await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'full_recon' })
  expect(r).toMatchObject({ ok: false, status: 404 })
})

test('ai_attack with an inline api_key is not queueable', async () => {
  const r = await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'ai_attack', payload: { api_key: 'sk-123' } })
  expect(r).toMatchObject({ ok: false, status: 400 })
  expect(h.jqCreate).not.toHaveBeenCalled()
})

test('ai_attack without an api_key is queueable', async () => {
  const r = await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'ai_attack', payload: { api_key: '' } })
  expect(r.ok).toBe(true)
})

test('a valid enqueue stores the fingerprint + envelope + queued status', async () => {
  const r = await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'full_recon', payload: { mode: 'new' } })
  expect(r).toMatchObject({ ok: true, status: 201, id: 'jq1' })
  const arg = h.jqCreate.mock.calls[0][0]
  expect(arg.data.status).toBe('queued')
  expect(arg.data.settingsHash).toBe(settingsFingerprint('full_recon', PROJECT as unknown as Record<string, unknown>))
  expect(arg.data.envelopeBytes).toBe(BigInt(2147483648))
  expect(arg.data.priority).toBe(10)
})
