import { describe, expect, test } from 'vitest'
import {
  DEFAULT_CAPTURE, CAPTURE_KEYS, pickCapture, diffCapture, isCaptureDirty,
  bodyRulesEqual, effectiveBodyPolicy, adoptCanonical, type CaptureSettings,
} from './captureSettingsForm'

const clone = (o: CaptureSettings): CaptureSettings => ({ ...o, captureProxyBodyRules: { ...o.captureProxyBodyRules } })

describe('pickCapture', () => {
  test('fills every field with its default from an empty payload', () => {
    const c = pickCapture({})
    expect(c).toEqual(DEFAULT_CAPTURE)
  })

  test('coerces booleans and adopts real numbers, ignoring wrong types', () => {
    const c = pickCapture({
      captureProxyEnabled: false, captureProxyPort: 9000,
      captureProxyMaxBodyKb: 'nope', captureProxyScope: 'recon',
      captureEgressBlockPrivate: 0,
    } as Record<string, unknown>)
    expect(c.captureProxyEnabled).toBe(false)
    expect(c.captureProxyPort).toBe(9000)
    expect(c.captureProxyMaxBodyKb).toBe(64) // wrong type → default
    expect(c.captureProxyScope).toBe('recon')
    expect(c.captureEgressBlockPrivate).toBe(false) // 0 → false
  })

  test('null/undefined booleans fall back to default (true), not false', () => {
    const c = pickCapture({ captureProxyStoreBodies: null, captureProxyRedactSecrets: undefined } as Record<string, unknown>)
    expect(c.captureProxyStoreBodies).toBe(true)
    expect(c.captureProxyRedactSecrets).toBe(true)
  })
})

describe('bodyRulesEqual / effectiveBodyPolicy', () => {
  test('empty map and explicit-Recommended map are equal (unset = Recommended)', () => {
    const recommended = {
      text: 'auto', json: 'auto', script: 'auto', image: 'meta', font: 'meta',
      video: 'meta', audio: 'meta', document: 'disk', archive: 'disk', binary: 'disk', other: 'auto',
    }
    expect(bodyRulesEqual({}, recommended)).toBe(true)
  })

  test('a single differing family makes them unequal', () => {
    expect(bodyRulesEqual({}, { image: 'disk' })).toBe(false)
  })

  test('effectiveBodyPolicy falls back to the Recommended default for an unset family', () => {
    expect(effectiveBodyPolicy({}, 'document')).toBe('disk')
    expect(effectiveBodyPolicy({ document: 'meta' }, 'document')).toBe('meta')
  })
})

describe('diffCapture', () => {
  test('no edits → empty diff (⇒ no PUT, no respawn)', () => {
    expect(diffCapture(DEFAULT_CAPTURE, clone(DEFAULT_CAPTURE))).toEqual({})
  })

  test('only the changed scalar fields appear in the diff', () => {
    const next = clone(DEFAULT_CAPTURE)
    next.captureProxyPort = 9000
    next.captureProxyRedactSecrets = false
    expect(diffCapture(DEFAULT_CAPTURE, next)).toEqual({
      captureProxyPort: 9000, captureProxyRedactSecrets: false,
    })
  })

  test('clicking the already-active preset is NOT a change (effective-equal maps)', () => {
    const base = clone(DEFAULT_CAPTURE) // rules = {}
    const next = clone(DEFAULT_CAPTURE)
    next.captureProxyBodyRules = {
      text: 'auto', json: 'auto', script: 'auto', image: 'meta', font: 'meta',
      video: 'meta', audio: 'meta', document: 'disk', archive: 'disk', binary: 'disk',
    }
    expect(diffCapture(base, next)).toEqual({})
  })

  test('a real body-rule change appears in the diff', () => {
    const next = clone(DEFAULT_CAPTURE)
    next.captureProxyBodyRules = { image: 'disk' }
    expect(diffCapture(DEFAULT_CAPTURE, next)).toEqual({ captureProxyBodyRules: { image: 'disk' } })
  })

  test('covers every capture field (diff key set ⊆ CAPTURE_KEYS)', () => {
    const next = clone(DEFAULT_CAPTURE)
    const raw = next as unknown as Record<string, unknown>
    for (const k of CAPTURE_KEYS) {
      if (typeof next[k] === 'boolean') raw[k] = !next[k]
      else if (typeof next[k] === 'number') raw[k] = (next[k] as number) + 1
    }
    // String fields are not covered by the generic flip above, so each one is
    // changed explicitly here.
    next.captureProxyScope = 'recon'
    next.scaIntelIgnoreSuffixes = 'example.test'
    next.captureProxyBodyRules = { image: 'disk' }
    const diff = diffCapture(DEFAULT_CAPTURE, next)
    // Every scalar field flipped, plus scope + bodyRules → all keys present.
    expect(new Set(Object.keys(diff))).toEqual(new Set(CAPTURE_KEYS))
  })
})

describe('isCaptureDirty', () => {
  test('false with no edits, true after any real edit', () => {
    const next = clone(DEFAULT_CAPTURE)
    expect(isCaptureDirty(DEFAULT_CAPTURE, next)).toBe(false)
    next.captureProxyMaxStoreMb = 10
    expect(isCaptureDirty(DEFAULT_CAPTURE, next)).toBe(true)
  })
})

describe('adoptCanonical', () => {
  test('adopts server-clamped values for submitted fields', () => {
    const current = clone(DEFAULT_CAPTURE); current.captureProxyPort = 0
    const submitted = clone(current)
    const canonical = clone(DEFAULT_CAPTURE); canonical.captureProxyPort = 1 // server clamped 0 → 1
    const merged = adoptCanonical(current, submitted, canonical, ['captureProxyPort'])
    expect(merged.captureProxyPort).toBe(1)
  })

  test('preserves a field the user re-edited mid-save (not clobbered by canonical)', () => {
    const submitted = clone(DEFAULT_CAPTURE); submitted.captureProxyPort = 9000
    const current = clone(submitted); current.captureProxyPort = 9999 // user typed again during save
    const canonical = clone(DEFAULT_CAPTURE); canonical.captureProxyPort = 9000
    const merged = adoptCanonical(current, submitted, canonical, ['captureProxyPort'])
    expect(merged.captureProxyPort).toBe(9999) // kept the newer edit
  })
})
