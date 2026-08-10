import { describe, test, expect } from 'vitest'
import {
  envelopeForKind,
  settingsFingerprint,
  orderCandidates,
  nextBackoff,
  BACKOFF_BASE_MS,
  BACKOFF_MAX_MS,
  FINGERPRINT_FIELDS,
} from './jobQueue'

describe('envelopeForKind', () => {
  test('known kinds map to their profile envelope', () => {
    expect(envelopeForKind('gvm')).toBe(2684354560)
    expect(envelopeForKind('supply_chain')).toBe(1879048192)
    expect(envelopeForKind('supply_chain_repo')).toBe(1879048192)
    expect(envelopeForKind('full_recon')).toBe(2147483648)
  })
  test('unknown kind falls back to _default', () => {
    expect(envelopeForKind('nope')).toBe(2147483648)
  })
})

describe('settingsFingerprint', () => {
  const base = {
    targetDomain: 'example.com',
    ipMode: false,
    targetIps: ['1.1.1.1', '2.2.2.2'],
    scanModules: ['port_scan', 'http_probe'],
    targetGuardrailEnabled: true,
    stealthMode: false,
    githubTargetOrg: 'acme',
  }

  test('is stable across calls and independent of array order', () => {
    const a = settingsFingerprint('full_recon', base)
    const b = settingsFingerprint('full_recon', { ...base, targetIps: ['2.2.2.2', '1.1.1.1'] })
    expect(a).toBe(b)
  })

  test('changes when any subset field changes', () => {
    const a = settingsFingerprint('full_recon', base)
    for (const field of FINGERPRINT_FIELDS.full_recon) {
      const mutated: Record<string, unknown> = { ...base }
      const v = mutated[field]
      mutated[field] = typeof v === 'boolean' ? !v : Array.isArray(v) ? [...(v as string[]), 'x'] : `${v}-changed`
      expect(settingsFingerprint('full_recon', mutated)).not.toBe(a)
    }
  })

  test('ignores fields outside the kind subset', () => {
    const a = settingsFingerprint('full_recon', base)
    // githubTargetOrg is not in the full_recon subset.
    const b = settingsFingerprint('full_recon', { ...base, githubTargetOrg: 'different' })
    expect(a).toBe(b)
  })

  test('different kinds over the same project differ', () => {
    expect(settingsFingerprint('gvm', base)).not.toBe(settingsFingerprint('full_recon', base))
  })

  test('a missing (not-yet-added) column does not throw and is omitted', () => {
    // supplyChainRepoScope may not exist on older rows.
    expect(() => settingsFingerprint('supply_chain', { supplyChainInputMode: 'upload' })).not.toThrow()
  })
})

describe('orderCandidates', () => {
  test('priority desc, then oldest enqueue first, without mutating input', () => {
    const rows = [
      { id: 'a', priority: 0, enqueuedAt: new Date('2026-01-01T00:00:02Z') },
      { id: 'b', priority: 10, enqueuedAt: new Date('2026-01-01T00:00:03Z') },
      { id: 'c', priority: 10, enqueuedAt: new Date('2026-01-01T00:00:01Z') },
      { id: 'd', priority: -10, enqueuedAt: new Date('2026-01-01T00:00:00Z') },
    ]
    const snapshot = rows.map(r => r.id)
    const ordered = orderCandidates(rows).map(r => r.id)
    expect(ordered).toEqual(['c', 'b', 'a', 'd'])
    expect(rows.map(r => r.id)).toEqual(snapshot) // not mutated
  })
})

describe('nextBackoff', () => {
  test('exponential from the base, capped at the max', () => {
    expect(nextBackoff(0)).toBe(BACKOFF_BASE_MS)
    expect(nextBackoff(1)).toBe(BACKOFF_BASE_MS * 2)
    expect(nextBackoff(2)).toBe(BACKOFF_BASE_MS * 4)
    expect(nextBackoff(100)).toBe(BACKOFF_MAX_MS)
  })
  test('negative attempts clamp to the base', () => {
    expect(nextBackoff(-5)).toBe(BACKOFF_BASE_MS)
  })
})
