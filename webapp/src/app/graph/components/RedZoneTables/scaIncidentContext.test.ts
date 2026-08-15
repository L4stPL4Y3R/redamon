/**
 * Incident context (feature B) in the Supply-Chain SCA table.
 *
 * Two rules that are easy to regress:
 *  - a non-malicious verdict must be described by the tool that produced it.
 *    The tooltip used to hardcode GuardDog for EVERY non-malicious row, so a
 *    typosquat or retire.js finding was labelled a GuardDog behavioural hit.
 *  - a never-synced intel catalog must render as ABSENT, never as "no incident
 *    known": the product cannot make that claim without the data.
 *
 * Run: npx vitest run src/app/graph/components/RedZoneTables/scaIncidentContext.test.ts
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { suspiciousVerdictTitle, hasIncident } from './SupplyChainScaTable'

const SOURCE = readFileSync(
  join(process.cwd(), 'src/app/graph/components/RedZoneTables/SupplyChainScaTable.tsx'),
  'utf8')

describe('suspiciousVerdictTitle', () => {
  test('names GuardDog only for GuardDog findings', () => {
    expect(suspiciousVerdictTitle('guarddog')).toContain('GuardDog')
  })

  test('a typosquat finding is NOT described as a GuardDog hit', () => {
    const title = suspiciousVerdictTitle('typosquat')
    expect(title).not.toContain('GuardDog')
    expect(title).toContain('near-miss')
  })

  test('retire.js findings get their own wording', () => {
    const title = suspiciousVerdictTitle('retirejs')
    expect(title).not.toContain('GuardDog')
    expect(title).toContain('retire.js')
  })

  test('an unknown or missing tool falls back to neutral wording', () => {
    for (const tool of [null, '', 'some-future-tool']) {
      const title = suspiciousVerdictTitle(tool)
      expect(title).not.toContain('GuardDog')
      expect(title.length).toBeGreaterThan(0)
    }
  })

  test('matching is case-insensitive', () => {
    expect(suspiciousVerdictTitle('GuardDog')).toBe(suspiciousVerdictTitle('guarddog'))
  })
})

describe('hasIncident', () => {
  test('true when the catalog matched', () => {
    expect(hasIncident({ incidentId: 'SCA-0001', incidentSummary: null })).toBe(true)
    expect(hasIncident({ incidentId: null, incidentSummary: 'A summary' })).toBe(true)
  })

  test('false when the intel volume was never synced', () => {
    expect(hasIncident({ incidentId: null, incidentSummary: null })).toBe(false)
  })

  test('empty strings do not count as an incident', () => {
    expect(hasIncident({ incidentId: '', incidentSummary: '' })).toBe(false)
  })
})

describe('table wiring', () => {
  test('the packages-sheet suspicious tooltip is tool-neutral', () => {
    // That sheet rolls up findings from several tools, so it cannot name one.
    const match = SOURCE.match(/suspicious: '([^']+)'/)
    expect(match).toBeTruthy()
    expect(match![1]).not.toContain('GuardDog')
  })

  test('every incident column is declared for export and filtering', () => {
    // Without these the columns render but cannot be filtered or exported.
    for (const key of [
      'incidentId', 'incidentStatus', 'incidentSummary', 'incidentBlastRadius',
      'incidentRemediation', 'incidentUrl', 'incidentFeedRevised',
    ]) {
      expect(SOURCE).toContain(`key: '${key}'`)
    }
  })

  test('the detail row carries the required catalog attribution', () => {
    // A licence condition of the feed, not decoration.
    expect(SOURCE).toContain('Incident data: supplychainattack.org')
  })

  test('the incident detail row spans the full verdicts table', () => {
    // A short colSpan leaves a visually broken row; the verdicts sheet has 12
    // columns since the Incident column was added.
    expect(SOURCE).toContain('colSpan={12}')
  })
})
