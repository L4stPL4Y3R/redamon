/**
 * Structural regression test for the table-view wiring.
 *
 * A TableViewMode is declared in three places that nothing links together at
 * compile time: the union + label map in ViewTabs, the dropdown entry that
 * selects it, and the render branch in page.tsx. Miss the third and the mode is
 * still selectable, still typechecks, and silently renders All Nodes - which is
 * exactly what happened when "supplyChain" was renamed to "jsDepSignals".
 *
 * Source-level assertions rather than a mounted page: rendering /graph needs
 * providers, a router and live data, and none of that is what is being checked.
 *
 * Run: npx vitest run src/app/graph/tableViewWiring.test.ts
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const HERE = join(process.cwd(), 'src/app/graph')
const viewTabsSrc = readFileSync(join(HERE, 'components/ViewTabs/ViewTabs.tsx'), 'utf8')
const pageSrc = readFileSync(join(HERE, 'page.tsx'), 'utf8')

/** Modes declared in the TABLE_MODE_LABELS map (the source of truth). */
function declaredModes(): string[] {
  const block = viewTabsSrc.match(/const TABLE_MODE_LABELS: Record<TableViewMode, string> = \{([\s\S]*?)\n\}/)
  expect(block, 'TABLE_MODE_LABELS block not found').toBeTruthy()
  return [...block![1].matchAll(/^\s{2}(\w+):/gm)].map(m => m[1])
}

// Modes reachable from a dedicated top-level tab rather than the dropdown.
const TOP_LEVEL_TABS = new Set(['reconDelta', 'scanSchedule'])
// The fallback branch: selecting it renders <DataTable>, so it has no `=== 'all'`.
const FALLBACK_MODES = new Set(['all'])

describe('table view wiring', () => {
  test('the label map is non-trivial (guards the regex, not the app)', () => {
    expect(declaredModes().length).toBeGreaterThan(15)
  })

  test('every declared mode has a render branch or is the documented fallback', () => {
    const missing = declaredModes().filter(mode =>
      !FALLBACK_MODES.has(mode) && !pageSrc.includes(`tableViewMode === '${mode}'`))
    expect(missing, `modes with no render branch in page.tsx: ${missing.join(', ')}`).toEqual([])
  })

  test('every declared mode is selectable from the dropdown or a top-level tab', () => {
    const unreachable = declaredModes().filter(mode =>
      !TOP_LEVEL_TABS.has(mode) && !viewTabsSrc.includes(`onTableViewModeChange?.('${mode}')`))
    expect(unreachable, `modes nothing can select: ${unreachable.join(', ')}`).toEqual([])
  })

  test('page.tsx renders no branch for a mode that no longer exists', () => {
    const declared = new Set(declaredModes())
    const branches = [...pageSrc.matchAll(/tableViewMode === '(\w+)'/g)].map(m => m[1])
    const stale = [...new Set(branches)].filter(m => !declared.has(m))
    expect(stale, `dead render branches: ${stale.join(', ')}`).toEqual([])
  })

  // Both supply-chain tables must stay individually reachable; collapsing one
  // into the other is the confusion the rename set out to fix.
  test('JS Dep Signals and Supply-Chain SCA are both wired, under distinct labels', () => {
    const modes = declaredModes()
    expect(modes).toContain('jsDepSignals')
    expect(modes).toContain('supplyChainSca')
    expect(viewTabsSrc).toMatch(/jsDepSignals: 'JS Dep Signals'/)
    expect(viewTabsSrc).toMatch(/supplyChainSca: 'Supply-Chain SCA'/)
    expect(pageSrc).toContain('<JsDepSignalsTable')
    expect(pageSrc).toContain('<SupplyChainScaTable')
  })

  test('the deep-link param is validated, not cast', () => {
    expect(pageSrc).toContain('parseTableViewMode(searchParams.get(\'table\'))')
    expect(pageSrc).not.toContain('setTableViewMode(tableParam as TableViewMode)')
  })
})
