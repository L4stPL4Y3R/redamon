/**
 * Cross-cutting smoke test for the `Updated` column.
 *
 * The contract is "every row in every table, on every page" - which is exactly
 * the kind of thing that decays one sheet at a time. A Red Zone table added
 * next month renders fine, filters fine and passes every behaviour test that
 * exists; it just quietly has no Updated column, and the one guarantee the
 * feature makes is no longer true.
 *
 * So this reads the SOURCE of all of them - the API routes as well as the
 * components, because a column wired in the UI against a route that never
 * returns the field is a table full of dashes.
 *
 * Run: npx vitest run src/app/graph/components/RedZoneTables/updatedAtWiring.smoke.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const DIR = __dirname
const REDZONE_API = join(DIR, '../../../api/analytics/redzone')
const JS_RECON_ROUTE = join(DIR, '../../../api/js-recon/[projectId]/download/route.ts')

const source = (path: string) => readFileSync(path, 'utf8')

/** Table components: every .tsx here that renders the shared shell. */
const TABLE_FILES = readdirSync(DIR)
  .filter(f => f.endsWith('.tsx') && !f.includes('.test.'))
  .filter(f => source(join(DIR, f)).includes('<RedZoneTableShell'))

/** Every Red Zone API route that backs one of those sheets. */
const ROUTE_FILES = readdirSync(REDZONE_API)
  .filter(d => statSync(join(REDZONE_API, d)).isDirectory())
  .map(d => join(REDZONE_API, d, 'route.ts'))
  .filter(p => {
    try { return statSync(p).isFile() } catch { return false }
  })

describe('the file lists are not accidentally empty', () => {
  // A rename or a moved directory would otherwise make this whole file pass by
  // testing nothing at all.
  test('tables were found', () => expect(TABLE_FILES.length).toBeGreaterThanOrEqual(16))
  test('routes were found', () => expect(ROUTE_FILES.length).toBeGreaterThanOrEqual(17))
})

describe('every Red Zone route returns the timestamp', () => {
  test.each(ROUTE_FILES.map(p => [p.split('/redzone/')[1], p]))(
    '%s projects `AS updatedAt`',
    (_name, path) => {
      expect(source(path as string)).toContain('AS updatedAt')
    },
  )

  test.each(ROUTE_FILES.map(p => [p.split('/redzone/')[1], p]))(
    '%s maps it onto the row it returns',
    (_name, path) => {
      // Projecting it in Cypher but dropping it in the record mapper is the
      // silent half of this failure: the query is right and the table is empty.
      expect(source(path as string)).toMatch(/updatedAt:/)
    },
  )

  test('every Cypher query in a route projects it, not just the first', () => {
    // Several routes UNION-shape two or three queries into one sheet (secrets,
    // netInitAccess, sharedInfra, threatIntel, the AI sheets). Wiring only the
    // first leaves whole arms of the table blank.
    for (const path of ROUTE_FILES) {
      const s = source(path)
      const queries = (s.match(/session\.run\(/g) ?? []).length
      const projections = (s.match(/AS updatedAt/g) ?? []).length
      // `ecoTotals` / `verdictTotals` style aggregate queries feed the meta
      // block rather than a row, so routes may legitimately project fewer.
      expect(projections, `${path}: ${projections} projections for ${queries} queries`)
        .toBeGreaterThan(0)
    }
  })
})

describe('every Red Zone table renders and sorts the column', () => {
  test.each(TABLE_FILES)('%s renders the cell', file => {
    expect(source(join(DIR, file))).toContain('UpdatedAtCell')
  })

  test.each(TABLE_FILES)('%s renders the sortable header', file => {
    expect(source(join(DIR, file))).toContain('UpdatedAtTh')
  })

  test.each(TABLE_FILES)('%s sorts through the shared helper', file => {
    const s = source(join(DIR, file))
    expect(s).toMatch(/useUpdatedAtSort|sortByUpdatedAt/)
  })

  test.each(TABLE_FILES)('%s pages and exports from the SORTED rows', file => {
    const s = source(join(DIR, file))
    // Slicing the unsorted list would show page 1 of an arbitrary order while
    // the header claims it is sorted newest-first.
    expect(s).not.toMatch(/filtered\.slice\(0, limit\)/)
    expect(s).toMatch(/sortedRows/)
  })

  test.each(TABLE_FILES)('%s declares the column for filtering and export', file => {
    const s = source(join(DIR, file))
    // AiTables appends it to each sheet definition by key instead of using the
    // shared descriptor constant.
    expect(s).toMatch(/UPDATED_AT_COLUMN|UPDATED_AT_KEY/)
  })
})

describe('the JS Recon sheets are wired too', () => {
  const jsReconTable = join(DIR, '../JsReconTable/JsReconTable.tsx')

  test('the route returns the timestamp for findings, secrets and endpoints', () => {
    const s = source(JS_RECON_ROUTE)
    expect((s.match(/updated_at AS updatedAt/g) ?? []).length).toBeGreaterThanOrEqual(3)
  })

  test('every sub-table renders the cell', () => {
    const s = source(jsReconTable)
    // 13 sub-tables across 6 tabs; the two stacked tabs render four and five
    // tables from one component each.
    expect((s.match(/UpdatedAtCell/g) ?? []).length).toBeGreaterThanOrEqual(12)
  })

  test('every sub-table sorts by it', () => {
    const s = source(jsReconTable)
    expect((s.match(/sortByUpdatedAt\(/g) ?? []).length).toBeGreaterThanOrEqual(9)
  })

  test('one shared sort direction, so the tabs cannot disagree', () => {
    expect(source(jsReconTable)).toContain('useUpdatedAtSortDir')
  })
})

describe('the node-backed views are wired', () => {
  test('All Nodes has the column and leads with the newest row', () => {
    const s = source(join(DIR, '../DataTable/DataTable.tsx'))
    expect(s).toContain('UpdatedAtCell')
    expect(s).toContain('{ id: UPDATED_AT_KEY, desc: true }')
  })

  test('Node Inspector pins it right and leads with the newest row', () => {
    const s = source(join(DIR, '../NodeDetailsTable/NodeDetailsTable.tsx'))
    expect(s).toContain('UpdatedAtCell')
    expect(s).toContain('{ id: UPDATED_AT_COL_ID, desc: true }')
    // Lifted out of the alphabetical property columns, or it would appear
    // twice - once mid-table and once pinned.
    expect(s).toMatch(/filter\(k => k !== UPDATED_AT_PROP\)/)
  })
})

/**
 * Tables outside the Red Zone that are also backed by graph nodes.
 *
 * These live in other sections (Insights, AI Attack Surface, CypherFix, Recon
 * Delta, Version Manager) and are easy to forget precisely because they are not
 * in the Red Zone directory the loops above walk.
 */
describe('the graph-backed tables in other sections are wired', () => {
  const SRC = join(DIR, '../../../..')
  const CASES: Array<[string, string]> = [
    ['Insights / Chain Findings', 'app/insights/components/TopFindingsTable.tsx'],
    ['AI Attack Surface / Findings', 'app/ai-attack-surface/page.tsx'],
    ['CypherFix / Remediation', 'app/graph/components/CypherFixTab/RemediationDashboard/RemediationDashboard.tsx'],
    ['Recon Delta', 'app/graph/components/ReconDelta/ReconDeltaTable.tsx'],
  ]

  test.each(CASES)('%s renders the cell and a sortable header', (_name, rel) => {
    const src = readFileSync(join(SRC, rel), 'utf8')
    expect(src).toContain('UpdatedAtCell')
    expect(src).toContain('UpdatedAtTh')
    expect(src).toContain('sortByUpdatedAt')
  })

  test('Version Manager shows the version creation time as its own column', () => {
    // Not graph-node backed (scan versions live in Postgres), but it is one of
    // the tables in the same view switcher, so it carries the column too.
    const src = readFileSync(join(SRC, 'app/graph/components/VersionManager/VersionManager.tsx'), 'utf8')
    expect(src).toContain('UpdatedAtCell')
    expect(src).toContain('<th>Created</th>')
  })

  test('their routes return the timestamp', () => {
    const chains = readFileSync(join(SRC, 'app/api/analytics/attack-chains/route.ts'), 'utf8')
    // Prefers updated_at, falling back to created_at for rows written before
    // the universal-stamp sweep.
    expect(chains).toContain('coalesce(f.updated_at, f.created_at) AS updatedAt')

    const ai = readFileSync(join(SRC, 'app/api/ai-attack-surface/[projectId]/findings/route.ts'), 'utf8')
    expect(ai).toContain('v.updated_at AS updatedAt')
  })

  test('Recon Delta resolves it from node properties, needing no API change', () => {
    // Snapshot rows carry the full property map, so the shared resolver works
    // directly - and it must, because Package/Chain* nodes have no updated_at.
    const src = readFileSync(join(SRC, 'app/graph/components/ReconDelta/ReconDeltaTable.tsx'), 'utf8')
    expect(src).toContain('nodeUpdatedAt(n.properties)')
  })
})
