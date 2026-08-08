/**
 * Cross-table smoke test for the filter wiring.
 *
 * The per-table behaviour tests each mount one component; this one reads the
 * source of ALL of them, because the failure it guards against is a table that
 * was never wired rather than one that is wired wrongly. A new Red Zone sheet
 * added next month renders fine, exports fine and passes every test that
 * exists - it just quietly has no Filters button, and nobody notices until a
 * user asks why that one page is different.
 *
 * It also pins two things the behaviour tests cannot see:
 *   - the persistence slug is unique per table (a duplicate makes two sheets
 *     share one saved filter set, which looks like filters "jumping" pages)
 *   - the column list is module-level, so opening the panel does not re-profile
 *     every row on every render
 *
 * Run: npx vitest run src/app/graph/components/RedZoneTables/filterWiring.smoke.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const DIR = __dirname

/** Table components: every .tsx here that renders the shared shell. */
const TABLE_FILES = readdirSync(DIR)
  .filter(f => f.endsWith('.tsx') && !f.includes('.test.'))
  .filter(f => readFileSync(join(DIR, f), 'utf8').includes('<RedZoneTableShell'))

const source = (f: string) => readFileSync(join(DIR, f), 'utf8')

describe('every Red Zone table is wired for filtering', () => {
  test('the file list is not accidentally empty', () => {
    // A rename or a moved directory would otherwise make this whole file pass
    // by testing nothing at all.
    expect(TABLE_FILES.length).toBeGreaterThanOrEqual(15)
  })

  test.each(TABLE_FILES)('%s uses the shared filter hook', file => {
    expect(source(file)).toContain('useRedZoneFilters')
  })

  test.each(TABLE_FILES)('%s hands the panel to the shell', file => {
    expect(source(file)).toContain('filterUi={filterUi}')
  })

  test.each(TABLE_FILES)('%s renders the filtered rows, not the unfiltered ones', file => {
    const s = source(file)
    // The hook returns `filteredRows`; a table that pages or exports from the
    // pre-filter array shows one count in the header and another in the body.
    expect(s).toMatch(/filteredRows:\s*filtered/)
    expect(s).toContain('filteredRowCount={filtered.length}')
  })

  test.each(TABLE_FILES)('%s declares its columns at module level', file => {
    const s = source(file)
    const hasModuleConst = /^const (COLUMNS|EXPORT_COLUMNS)/m.test(s)
    // AiTables builds its columns from a module-level sheet definition instead.
    const hasSheetDefs = /^const AI_\w+_SHEETS/m.test(s)
    expect(hasModuleConst || hasSheetDefs).toBe(true)
  })
})

describe('persistence slugs', () => {
  const slugs = TABLE_FILES.flatMap(f => {
    const s = source(f)
    return [...s.matchAll(/slug:\s*'([^']+)'/g)].map(m => ({ file: f, slug: m[1] }))
  })

  test('every table declares one', () => {
    // AiTables passes the slug through as a prop, so it is allowed to have none.
    const withSlug = new Set(slugs.map(s => s.file))
    const missing = TABLE_FILES.filter(f => !withSlug.has(f) && !source(f).includes('slug,'))
    expect(missing).toEqual([])
  })

  test('no two tables share a slug', () => {
    const seen = new Map<string, string>()
    const clashes: string[] = []
    for (const { file, slug } of slugs) {
      if (seen.has(slug) && seen.get(slug) !== file) clashes.push(`${slug}: ${seen.get(slug)} + ${file}`)
      seen.set(slug, file)
    }
    expect(clashes).toEqual([])
  })

  test('sheeted tables scope by sheet, so their sheets filter independently', () => {
    for (const file of ['AiTables.tsx', 'SupplyChainScaTable.tsx']) {
      expect(source(file)).toMatch(/sheet:\s*\w/)
    }
  })
})

describe('the other two filterable surfaces stay wired', () => {
  const read = (rel: string) => readFileSync(join(DIR, '..', rel), 'utf8')

  test('the Node Inspector filters and persists', () => {
    const s = read('NodeDetailsTable/NodeDetailsTable.tsx')
    expect(s).toContain('useColumnFilterState')
    expect(s).toContain("tableFilterScope('nodeInspector'")
    expect(s).toContain('<ColumnFilterButton')
  })

  test('All Nodes filters under its own scope', () => {
    const s = read('DataTable/DataTable.tsx')
    expect(s).toContain('useColumnFilterState')
    expect(s).toContain("tableFilterScope('allNodes'")
  })

  test('JS Recon filters per sub-tab', () => {
    const s = read('JsReconTable/JsReconTable.tsx')
    expect(s).toContain('useRedZoneFilters')
    expect(s).toMatch(/sheet:\s*activeTab/)
  })

  test('every surface renders the one shared Filters control', () => {
    // The button, its icon and its dropdown live in a single component so the
    // four toolbars cannot drift apart again on size, badge colour or which
    // edge the panel opens from.
    const surfaces = [
      'NodeDetailsTable/NodeDetailsTable.tsx',
      'DataTable/DataTable.tsx',
      'JsReconTable/JsReconTable.tsx',
      'RedZoneTables/RedZoneTableShell.tsx',
    ]
    for (const rel of surfaces) {
      expect(read(rel), rel).toContain('<ColumnFilterButton')
    }
  })

  test('no table styles a Filters button of its own', () => {
    const cssFiles = [
      'NodeDetailsTable/NodeDetailsTable.module.css',
      'DataTable/DataTable.module.css',
      'JsReconTable/JsReconTable.module.css',
      'RedZoneTables/RedZoneTableShell.module.css',
    ]
    for (const rel of cssFiles) {
      const css = read(rel)
      expect(css, rel).not.toMatch(/^\.filterBtn\b/m)
      expect(css, rel).not.toMatch(/^\.filterDropdown\b/m)
      expect(css, rel).not.toMatch(/^\.filterCount\b/m)
    }
  })

  test('nothing reaches into the Node Inspector for the shared engine', () => {
    // The engine and the panel were lifted out precisely so the Red Zone would
    // not depend on another component's internals; this keeps it that way.
    for (const f of TABLE_FILES) {
      expect(source(f)).not.toContain('NodeDetailsTable/')
    }
  })
})
