/**
 * Cross-layer contract for the Supply Chain Recon ecosystem filter, webapp side.
 *
 * The multi-select is only safe if every OTHER writer of
 * `supplyChainReconEcosystems` also stores canonical OSV names: recon matches
 * the value exactly, so a preset shipping "pypi" (or the Prisma default
 * drifting) silently reports zero packages, with a green scan and an empty
 * table as the only symptom.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/supplyChainEcosystems.integration.test.ts
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, test, expect } from 'vitest'
import { RECON_PRESETS } from '@/lib/recon-presets'
import { reconPresetSchema } from '@/lib/recon-preset-schema'
import {
  SUPPLY_CHAIN_ECOSYSTEMS,
  HARVESTED_ECOSYSTEM,
  parseEcosystems,
  serializeEcosystems,
  unknownEcosystemTokens,
} from './supplyChainEcosystems'

const WEBAPP_ROOT = join(__dirname, '..', '..', '..', '..', '..')

function readWebappFile(...parts: string[]): string {
  return readFileSync(join(WEBAPP_ROOT, ...parts), 'utf8')
}

describe('Prisma is the source of truth for the stored shape', () => {
  const schema = readWebappFile('prisma', 'schema.prisma')

  test('the column default is a canonical, npm-containing selection', () => {
    const match = schema.match(/supplyChainReconEcosystems\s+String\s+@default\("([^"]*)"\)/)
    expect(match).not.toBeNull()
    const value = match![1]
    expect(serializeEcosystems(parseEcosystems(value))).toBe(value)
    expect(unknownEcosystemTokens(value)).toEqual([])
    expect(parseEcosystems(value)).toContain(HARVESTED_ECOSYSTEM)
  })

  test('the column is a plain String, so the widget must serialize it itself', () => {
    // If this ever becomes String[], toggleEcosystem/parseEcosystems and the
    // recon-side split(",") both have to change together.
    expect(schema).toMatch(/supplyChainReconEcosystems\s+String\s+@default/)
    expect(schema).not.toMatch(/supplyChainReconEcosystems\s+String\[\]/)
  })
})

describe('shipped recon presets', () => {
  const withEcosystems = RECON_PRESETS
    .map((p) => ({ id: p.id, value: (p.parameters as Record<string, unknown>).supplyChainReconEcosystems }))
    .filter((p): p is { id: string; value: string } => typeof p.value === 'string')

  test('at least one preset configures the field (the check below is not vacuous)', () => {
    expect(withEcosystems.length).toBeGreaterThan(0)
  })

  test.each(withEcosystems.map((p) => [p.id, p.value] as const))(
    'preset %s stores canonical ecosystems (%s)',
    (_id, value) => {
      expect(unknownEcosystemTokens(value)).toEqual([])
      expect(serializeEcosystems(parseEcosystems(value))).toBe(value)
    },
  )

  test('a preset that enables the module never filters the harvested ecosystem away', () => {
    for (const preset of RECON_PRESETS) {
      const settings = preset.parameters as Record<string, unknown>
      if (!settings.supplyChainReconEnabled) continue
      const value = settings.supplyChainReconEcosystems
      if (typeof value !== 'string' || value.trim() === '') continue // "" = no filter
      expect(parseEcosystems(value), `preset ${preset.id}`).toContain(HARVESTED_ECOSYSTEM)
    }
  })

  test('presets survive the zod schema unchanged', () => {
    for (const preset of RECON_PRESETS) {
      const value = (preset.parameters as Record<string, unknown>).supplyChainReconEcosystems
      if (typeof value !== 'string') continue
      const parsed = reconPresetSchema.parse({ supplyChainReconEcosystems: value })
      expect(parsed.supplyChainReconEcosystems).toBe(value)
    }
  })
})

describe('the LLM-facing preset schema documents the same catalogue', () => {
  const doc = readWebappFile('src', 'lib', 'recon-preset-schema.ts')
  const line = doc.split('\n').find((l) => l.includes('- supplyChainReconEcosystems:'))

  test('the field is documented', () => {
    expect(line).toBeDefined()
  })

  test('every catalogue name appears verbatim in the doc line', () => {
    for (const eco of SUPPLY_CHAIN_ECOSYSTEMS) {
      expect(line, `missing ${eco}`).toContain(eco)
    }
  })

  test('the doc line warns that matching is exact', () => {
    expect(line?.toLowerCase()).toContain('exactly')
  })
})
