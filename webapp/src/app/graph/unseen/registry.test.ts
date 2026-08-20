/**
 * The registry is the badge feature's coverage contract: every table tab either
 * carries a badge or is listed as deliberately unbadged. Nothing else enforces
 * that, and the failure is silent - a tab added next month renders fine, filters
 * fine, and just never tells anyone it has new rows.
 *
 * Reads the SOURCE of ViewTabs rather than importing it: that module is a client
 * component pulling in lucide-react and CSS modules, and this needs nothing from
 * it but the list of tab ids.
 *
 * Run: npx vitest run src/app/graph/unseen/registry.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ALL_GRAPH_LABELS, BADGED_TABS, UNBADGED_TABS, UNSEEN_TAB_LABELS, labelsInUse } from './registry'
import { isSafeLabel } from './counts'

const VIEW_TABS = join(__dirname, '../components/ViewTabs/ViewTabs.tsx')
const SCHEMA_PY = join(__dirname, '../../../../../graph_db/schema.py')

/** Every member of the `TableViewMode` union, read out of its declaration. */
function tableViewModes(): string[] {
  const src = readFileSync(VIEW_TABS, 'utf8')
  const union = src.match(/export type TableViewMode =([\s\S]*?)\n\n/)
  if (!union) throw new Error('TableViewMode union not found in ViewTabs.tsx')
  return [...union[1].matchAll(/'([a-zA-Z]+)'/g)].map(m => m[1])
}

describe('the tab list was actually found', () => {
  // A rename would otherwise make every assertion below pass over an empty set.
  test('parses a plausible number of tabs', () => {
    expect(tableViewModes().length).toBeGreaterThanOrEqual(20)
  })
})

describe('every table tab is accounted for', () => {
  test.each(tableViewModes())('%s is badged or explicitly unbadged', mode => {
    const badged = (BADGED_TABS as readonly string[]).includes(mode)
    const unbadged = (UNBADGED_TABS as readonly string[]).includes(mode)
    expect(badged || unbadged).toBe(true)
  })

  test('no registry entry names a tab that no longer exists', () => {
    const modes = new Set(tableViewModes())
    for (const tab of [...BADGED_TABS, ...UNBADGED_TABS]) expect(modes.has(tab)).toBe(true)
  })
})

describe('every badged tab can actually be counted', () => {
  test.each(BADGED_TABS)('%s lists at least one label', tab => {
    expect(UNSEEN_TAB_LABELS[tab].length).toBeGreaterThan(0)
  })

  test('every label is a bare identifier', () => {
    // Labels are interpolated into Cypher, so anything else is an injection.
    for (const label of labelsInUse()) expect(isSafeLabel(label)).toBe(true)
  })

  test('every label is one the graph actually writes', () => {
    const known = new Set<string>(ALL_GRAPH_LABELS)
    for (const label of labelsInUse()) expect(known.has(label)).toBe(true)
  })
})

describe('ALL_GRAPH_LABELS tracks the graph schema', () => {
  // Skipped in the webapp image, which copies only webapp/.
  const available = existsSync(SCHEMA_PY)

  test.skipIf(!available)('matches the tenant-indexed labels, minus the KB corpus', () => {
    const src = readFileSync(SCHEMA_PY, 'utf8')
    const indexed = new Set(
      [...src.matchAll(/FOR \([a-zA-Z_]+:([A-Za-z][A-Za-z0-9_]*)\)/g)].map(m => m[1]),
    )
    indexed.delete('KBChunk')
    expect([...new Set(ALL_GRAPH_LABELS)].sort()).toEqual([...indexed].sort())
  })
})
