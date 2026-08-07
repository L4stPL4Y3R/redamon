/**
 * Pure-helper tests for the Supply-Chain SCA table: the derived Status and
 * Origin columns, which are the two things the graph does not store directly.
 *
 * Run: npx vitest run src/app/graph/components/RedZoneTables/supplyChainScaHelpers.test.ts
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { packageStatus, originOf, worstSeverity } from './SupplyChainScaTable'

function pkg(over: Partial<Parameters<typeof packageStatus>[0]> = {}) {
  return {
    maliciousCount: 0, suspiciousCount: 0, notAnalysedCount: 0,
    advisoryCount: 0, version: '1.0.0' as string | null,
    ...over,
  }
}

describe('packageStatus', () => {
  test('malicious outranks everything', () => {
    expect(packageStatus(pkg({ maliciousCount: 1, advisoryCount: 9, suspiciousCount: 3 }))).toBe('malicious')
  })

  test('a CVE/GHSA advisory makes it vulnerable', () => {
    expect(packageStatus(pkg({ advisoryCount: 2 }))).toBe('vulnerable')
  })

  test('a real GuardDog hit is suspicious', () => {
    expect(packageStatus(pkg({ suspiciousCount: 1 }))).toBe('suspicious')
  })

  test('a soft error is "not analysed", never suspicious and never clean', () => {
    expect(packageStatus(pkg({ notAnalysedCount: 1 }))).toBe('not analysed')
  })

  // The core honesty rule: osv-scanner needs a version to match a
  // version-specific advisory, so a versionless package was never checked.
  // Reporting it as clean is the false-clean the whole feature guards against.
  test('a package with no version is unverdictable, not clean', () => {
    expect(packageStatus(pkg({ version: null }))).toBe('unverdictable')
  })

  test('a versioned package with no findings is clean', () => {
    expect(packageStatus(pkg())).toBe('clean')
  })
})

describe('originOf', () => {
  test('a repo anchor means the L1 repository scan', () => {
    expect(originOf({ repos: ['acme/app'], baseUrls: [], harvestSource: 'osv' })).toBe('L1 repo')
  })

  test('a BaseURL anchor means the L2 live harvest', () => {
    expect(originOf({ repos: [], baseUrls: ['https://t.tld'], harvestSource: 'retirejs' })).toBe('L2 live')
  })

  test('no anchor with an osv harvest source is the uploaded SBOM path', () => {
    expect(originOf({ repos: [], baseUrls: [], harvestSource: 'osv' })).toBe('L1 SBOM')
  })

  test('a package invented by the finding path is labelled as such', () => {
    expect(originOf({ repos: [], baseUrls: [], harvestSource: 'finding' })).toBe('from finding')
  })

  test('anything else is unanchored', () => {
    expect(originOf({ repos: [], baseUrls: [], harvestSource: 'sourcemap' })).toBe('unanchored')
  })
})

describe('worstSeverity', () => {
  test('picks the highest band, not the first or last', () => {
    expect(worstSeverity(['low', 'critical', 'medium'])).toBe('critical')
    expect(worstSeverity(['medium', 'high'])).toBe('high')
  })

  test('an unrecognised band does not outrank a real one', () => {
    expect(worstSeverity(['bogus', 'medium'])).toBe('medium')
  })

  test('an empty list is unknown, not a false "low"', () => {
    expect(worstSeverity([])).toBe('unknown')
  })
})

// A misspelled export key yields a silently EMPTY column in the CSV/JSON/MD
// download - the row data is there, the export just never finds it. Nothing
// typechecks the string keys against the row shape, so assert it here.
describe('export column keys match the row fields the route returns', () => {
  const routeSrc = readFileSync(
    join(process.cwd(), 'src/app/api/analytics/redzone/supplyChainSca/route.ts'), 'utf8')
  const tableSrc = readFileSync(
    join(process.cwd(), 'src/app/graph/components/RedZoneTables/SupplyChainScaTable.tsx'), 'utf8')

  /** Field names the route builds for one sheet, e.g. `purl: (...)`. */
  function routeFields(sheet: string): Set<string> {
    const block = routeSrc.match(new RegExp(`${sheet}: \\w+\\.records\\.map\\([\\s\\S]*?\\n      \\}\\)\\),`))
    expect(block, `route block for ${sheet} not found`).toBeTruthy()
    return new Set([...block![0].matchAll(/^\s{8}(\w+):/gm)].map(m => m[1]))
  }

  /** Keys the table's export config declares for one sheet. */
  function exportKeys(sheet: string): string[] {
    const block = tableSrc.match(new RegExp(`  ${sheet}: \\[([\\s\\S]*?)\\n  \\],`))
    expect(block, `export block for ${sheet} not found`).toBeTruthy()
    return [...block![1].matchAll(/\{ key: '(\w+)'/g)].map(m => m[1])
  }

  for (const sheet of ['verdicts', 'packages', 'advisories']) {
    test(`${sheet}: every export key exists on the row`, () => {
      const fields = routeFields(sheet)
      const missing = exportKeys(sheet).filter(k => !fields.has(k))
      expect(missing, `export keys with no matching row field: ${missing.join(', ')}`).toEqual([])
    })
  }
})
