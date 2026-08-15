/**
 * A1 (TypeScript half) + the cross-language parity contract.
 *
 * There are two writers of captured_http_transactions. If only one sets the IOC
 * columns, an operator sees some requests flagged and reasonably concludes the
 * unflagged ones were checked and cleared. The last describe block pins this
 * implementation to the Python one by running the SAME case table through both.
 *
 * Run: npx vitest run src/lib/scaIntel.test.ts
 */
import { describe, test, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  loadScaIntel, resetScaIntelCache, matchTransaction, iocColumns,
  DEFAULT_IGNORE_SUFFIXES, type ScaIntel,
} from './scaIntel'

const REC = (id = 'SCA-0001') => ({
  incident_id: id,
  url: `https://supplychainattack.org/i/${id}`,
  title: 'Compromised CDN script',
  summary: 'A CDN-hosted script was replaced with a skimmer.',
  status: 'confirmed',
})

function writeIntel(dir: string, over: Partial<{
  domains: Record<string, unknown>
  wildcards: [string, unknown][]
  ips: Record<string, unknown>
}> = {}) {
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ revised: '2026-08-11' }))
  writeFileSync(join(dir, 'network_iocs.json'), JSON.stringify({
    domains: over.domains ?? { 'cdn.evil.example': REC() },
    wildcards: over.wildcards ?? [['.cf99.workers.dev', REC('SCA-WILD')]],
    ips: over.ips ?? { '1.2.3.4': REC('SCA-IP') },
  }))
}

let dir: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'sca-intel-'))
  process.env.SCA_INTEL_PATH = dir
  delete process.env.CAPTURE_IOC_IGNORE_SUFFIXES
  delete process.env.SCA_INTEL_MATCH_ENABLED
  resetScaIntelCache()
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
  delete process.env.SCA_INTEL_PATH
  delete process.env.CAPTURE_IOC_IGNORE_SUFFIXES
  delete process.env.SCA_INTEL_MATCH_ENABLED
  resetScaIntelCache()
})

describe('loadScaIntel', () => {
  test('a missing volume is unavailable, never a throw', () => {
    process.env.SCA_INTEL_PATH = join(dir, 'nope')
    resetScaIntelCache()
    const intel = loadScaIntel(true)
    expect(intel.available).toBe(false)
    expect(intel.domains).toEqual({})
  })

  test('a truncated manifest is unavailable, never a throw', () => {
    writeIntel(dir)
    writeFileSync(join(dir, 'manifest.json'), '{"revised": ')
    expect(loadScaIntel(true).available).toBe(false)
  })

  test('loads the tables and the feed revision', () => {
    writeIntel(dir)
    const intel = loadScaIntel(true)
    expect(intel.available).toBe(true)
    expect(intel.revised).toBe('2026-08-11')
    expect(Object.keys(intel.domains)).toContain('cdn.evil.example')
  })
})

describe('matchTransaction', () => {
  beforeEach(() => { writeIntel(dir); loadScaIntel(true) })

  test('exact host match', () => {
    expect(matchTransaction('cdn.evil.example')?.incident_id).toBe('SCA-0001')
  })

  test('case and trailing dot are normalised', () => {
    expect(matchTransaction('CDN.Evil.Example.')?.incident_id).toBe('SCA-0001')
  })

  test('a port on the Host header is stripped', () => {
    expect(matchTransaction('cdn.evil.example:8443')?.incident_id).toBe('SCA-0001')
  })

  test('wildcard suffix match', () => {
    expect(matchTransaction('a.cf99.workers.dev')?.incident_id).toBe('SCA-WILD')
  })

  test('a different apex does not match the wildcard', () => {
    expect(matchTransaction('a.other.workers.dev')).toBeNull()
  })

  test('resolved IP match', () => {
    expect(matchTransaction(null, '1.2.3.4')?.incident_id).toBe('SCA-IP')
  })

  test('a clean host matches nothing', () => {
    expect(matchTransaction('www.example.com')).toBeNull()
  })

  test('OAST providers are suppressed by default', () => {
    writeIntel(dir, { domains: { 'abc.oastify.com': REC('SCA-OAST') } })
    loadScaIntel(true)
    expect(matchTransaction('abc.oastify.com')).toBeNull()
    // ...but the record really is there.
    expect(matchTransaction('abc.oastify.com', null, undefined, [])?.incident_id)
      .toBe('SCA-OAST')
  })

  test('the default ignore list covers every OAST provider in the feed', () => {
    expect(DEFAULT_IGNORE_SUFFIXES).toHaveLength(5)
    for (const suffix of ['oastify.com', 'oast.fun', 'mburpcollab.com',
      'canarytokens.com', 'pipedream.net']) {
      expect(DEFAULT_IGNORE_SUFFIXES).toContain(suffix)
    }
  })

  test('the kill switch disables matching entirely', () => {
    process.env.SCA_INTEL_MATCH_ENABLED = 'false'
    expect(matchTransaction('cdn.evil.example')).toBeNull()
  })
})

describe('iocColumns', () => {
  beforeEach(() => { writeIntel(dir); loadScaIntel(true) })

  test('sets both columns on a match', () => {
    expect(iocColumns('cdn.evil.example')).toEqual({
      iocIncidentId: 'SCA-0001',
      iocIncidentUrl: 'https://supplychainattack.org/i/SCA-0001',
    })
  })

  test('both columns are null on a non-match', () => {
    expect(iocColumns('www.example.com')).toEqual({
      iocIncidentId: null, iocIncidentUrl: null,
    })
  })

  test('both columns are null when the catalog was never synced', () => {
    process.env.SCA_INTEL_PATH = join(dir, 'nope')
    resetScaIntelCache()
    expect(iocColumns('cdn.evil.example')).toEqual({
      iocIncidentId: null, iocIncidentUrl: null,
    })
  })
})

/**
 * The parity contract. These cases are duplicated verbatim in
 * tests/test_sca_ioc_match.py (class TestPythonTypeScriptParity) and both
 * suites must agree. Changing behaviour on one side without the other breaks
 * one of the two.
 */
export const PARITY_CASES: {
  host: string | null; ip: string | null; expected: string | null
}[] = [
  { host: 'cdn.evil.example', ip: null, expected: 'SCA-0001' },
  { host: 'CDN.Evil.Example.', ip: null, expected: 'SCA-0001' },
  { host: 'cdn.evil.example:8443', ip: null, expected: 'SCA-0001' },
  { host: 'a.cf99.workers.dev', ip: null, expected: 'SCA-WILD' },
  { host: 'a.other.workers.dev', ip: null, expected: null },
  { host: 'www.example.com', ip: null, expected: null },
  { host: null, ip: '1.2.3.4', expected: 'SCA-IP' },
  { host: null, ip: '9.9.9.9', expected: null },
  { host: 'abc.oastify.com', ip: null, expected: null },
  { host: '', ip: null, expected: null },
]

describe('cross-language parity', () => {
  beforeEach(() => {
    writeIntel(dir, { domains: { 'cdn.evil.example': REC(), 'abc.oastify.com': REC('SCA-OAST') } })
    loadScaIntel(true)
  })

  test.each(PARITY_CASES)('host=$host ip=$ip -> $expected', ({ host, ip, expected }) => {
    expect(iocColumns(host, ip).iocIncidentId).toBe(expected)
  })
})
