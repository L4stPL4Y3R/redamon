/**
 * Supply Chain Recon ecosystem multi-select: the stored comma-separated string
 * must stay canonical, because recon matches it EXACTLY against the harvested
 * package ecosystem.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/supplyChainEcosystems.test.ts
 */
import { describe, test, expect } from 'vitest'
import {
  HARVESTED_ECOSYSTEM,
  SUPPLY_CHAIN_ECOSYSTEMS,
  SUPPLY_CHAIN_ECOSYSTEM_LABELS,
  parseEcosystems,
  serializeEcosystems,
  toggleEcosystem,
  unknownEcosystemTokens,
} from './supplyChainEcosystems'

describe('parseEcosystems', () => {
  test('parses the Prisma default', () => {
    expect(parseEcosystems('npm')).toEqual(['npm'])
  })

  test('tolerates whitespace, casing and duplicates from the old free-text field', () => {
    expect(parseEcosystems(' pypi , NPM,npm ,CRATES.IO')).toEqual(['npm', 'PyPI', 'crates.io'])
  })

  test('drops tokens that can never match a harvested package', () => {
    expect(parseEcosystems('npm,cargo,,bogus')).toEqual(['npm'])
  })

  test('empty, null and undefined all mean no selection', () => {
    expect(parseEcosystems('')).toEqual([])
    expect(parseEcosystems(null)).toEqual([])
    expect(parseEcosystems(undefined)).toEqual([])
  })

  test('returns catalogue order regardless of input order', () => {
    expect(parseEcosystems('NuGet,Go,npm')).toEqual(['npm', 'Go', 'NuGet'])
  })
})

describe('serializeEcosystems', () => {
  test('joins in catalogue order without spaces', () => {
    expect(serializeEcosystems(['Go', 'npm'])).toBe('npm,Go')
  })

  test('an empty selection serializes to an empty string', () => {
    expect(serializeEcosystems([])).toBe('')
  })
})

describe('toggleEcosystem', () => {
  test('adds an ecosystem and keeps catalogue order', () => {
    expect(toggleEcosystem('npm', 'Go')).toBe('npm,Go')
    expect(toggleEcosystem('Go', 'npm')).toBe('npm,Go')
  })

  test('removes an already selected ecosystem', () => {
    expect(toggleEcosystem('npm,Go,NuGet', 'Go')).toBe('npm,NuGet')
  })

  test('deselecting the last one yields the empty (no-filter) string', () => {
    expect(toggleEcosystem('npm', 'npm')).toBe('')
  })

  test('canonicalizes a legacy lowercase value on the first toggle', () => {
    expect(toggleEcosystem('pypi', 'Go')).toBe('PyPI,Go')
  })

  test('round-trips every ecosystem in the catalogue', () => {
    let value = ''
    for (const eco of SUPPLY_CHAIN_ECOSYSTEMS) value = toggleEcosystem(value, eco)
    expect(parseEcosystems(value)).toEqual([...SUPPLY_CHAIN_ECOSYSTEMS])
    for (const eco of SUPPLY_CHAIN_ECOSYSTEMS) value = toggleEcosystem(value, eco)
    expect(value).toBe('')
  })
})

describe('unknownEcosystemTokens', () => {
  test('a canonical or legacy-cased value has none', () => {
    expect(unknownEcosystemTokens('npm,PyPI')).toEqual([])
    expect(unknownEcosystemTokens(' pypi , NPM ')).toEqual([])
  })

  test('names the tokens recon would filter on but never match', () => {
    expect(unknownEcosystemTokens('npm,cargo,rust')).toEqual(['cargo', 'rust'])
  })

  test('empty and whitespace-only values have no tokens at all', () => {
    // The distinction the UI warning turns on: "" means no filter, whereas a
    // token that matches nothing means nothing is reported.
    expect(unknownEcosystemTokens('')).toEqual([])
    expect(unknownEcosystemTokens('  ,  ')).toEqual([])
    expect(unknownEcosystemTokens(null)).toEqual([])
  })

  test('reports trimmed tokens in input order', () => {
    expect(unknownEcosystemTokens(' zzz , aaa ')).toEqual(['zzz', 'aaa'])
  })
})

describe('catalogue', () => {
  test('the harvested ecosystem is part of the catalogue', () => {
    expect(SUPPLY_CHAIN_ECOSYSTEMS).toContain(HARVESTED_ECOSYSTEM)
  })

  test('every ecosystem has a label', () => {
    for (const eco of SUPPLY_CHAIN_ECOSYSTEMS) {
      expect(SUPPLY_CHAIN_ECOSYSTEM_LABELS[eco]).toBeTruthy()
    }
  })

  test('matches the ecosystems the offline OSV sync can populate', () => {
    // Mirrors SEED_MANIFESTS in scanners/supply_chain_common/osv_db_sync.py.
    expect([...SUPPLY_CHAIN_ECOSYSTEMS]).toEqual([
      'npm', 'PyPI', 'Go', 'Maven', 'crates.io', 'Packagist', 'RubyGems', 'NuGet',
    ])
  })
})
