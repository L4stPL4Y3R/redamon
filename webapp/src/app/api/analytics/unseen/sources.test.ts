/**
 * A badge must count the rows its tab WOULD SHOW.
 *
 * The first version counted nodes by label, which put a 4 over Web Cache
 * Poisoning for four ordinary Vulnerability nodes and a 3 over Shared
 * Infrastructure for three new IPs - every one of those tabs opened empty. The
 * tests here pin the replacement: the tab's own route answers, and only rows it
 * actually returns are counted.
 *
 * Run: npx vitest run src/app/api/analytics/unseen/sources.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

/** Rows the stubbed Web Cache Poisoning route will return. */
let webCacheRows: unknown = { rows: [] }
let webCacheStatus = 200
const seenUrls: string[] = []

vi.mock('../redzone/webCachePoison/route', () => ({
  GET: async (request: { nextUrl: URL }) => {
    seenUrls.push(request.nextUrl.toString())
    if (webCacheStatus !== 200) return new Response('nope', { status: webCacheStatus })
    return Response.json(webCacheRows)
  },
}))

const { countUnseenRows, rowUpdatedAtMs, LABEL_TABS, ROUTE_TABS, labelsForTab } =
  await import('./sources')

const T0 = Date.parse('2026-08-20T10:00:00.000Z')
const BEFORE = '2026-08-20T09:00:00.000Z'
const AFTER = '2026-08-20T11:00:00.000Z'

beforeEach(() => {
  webCacheRows = { rows: [] }
  webCacheStatus = 200
  seenUrls.length = 0
})

describe('rowUpdatedAtMs', () => {
  test('reads a Cypher temporal, which arrives as nested integer objects', () => {
    // This is the shape a Red Zone route actually returns; treating it as a
    // string yields null and the badge is permanently zero.
    const temporal = {
      year: { low: 2026, high: 0 }, month: { low: 8, high: 0 }, day: { low: 20, high: 0 },
      hour: { low: 11, high: 0 }, minute: { low: 0, high: 0 }, second: { low: 0, high: 0 },
      nanosecond: { low: 0, high: 0 },
    }
    expect(rowUpdatedAtMs(temporal)).toBe(Date.parse(AFTER))
  })

  test('reads an ISO string', () => {
    expect(rowUpdatedAtMs(AFTER)).toBe(Date.parse(AFTER))
  })

  test('reads a zoneless string as UTC', () => {
    // Otherwise the same instant lands either side of the watermark depending on
    // whether it was stored as a temporal or as text.
    expect(rowUpdatedAtMs('2026-08-20 11:00:00')).toBe(Date.parse(AFTER))
  })

  test.each([null, undefined, '', 'last tuesday', 42, {}])('%s has no time', raw => {
    expect(rowUpdatedAtMs(raw)).toBeNull()
  })
})

describe('countUnseenRows', () => {
  test('counts only rows newer than the watermark', () => {
    webCacheRows = { rows: [{ updatedAt: AFTER }, { updatedAt: AFTER }, { updatedAt: BEFORE }] }
    return expect(countUnseenRows('webCachePoison', 'p1', T0)).resolves.toBe(2)
  })

  test('an empty table is a zero badge, whatever the graph holds', () => {
    // The whole point: the graph gained four Vulnerability nodes, none of them
    // cache poisoning, so this route returns nothing and the badge must be 0.
    webCacheRows = { rows: [] }
    return expect(countUnseenRows('webCachePoison', 'p1', T0)).resolves.toBe(0)
  })

  test('a row with no timestamp is not counted', () => {
    webCacheRows = { rows: [{ updatedAt: null }, { updatedAt: AFTER }] }
    return expect(countUnseenRows('webCachePoison', 'p1', T0)).resolves.toBe(1)
  })

  test('a multi-sheet response counts every sheet', () => {
    webCacheRows = { sheets: { a: [{ updatedAt: AFTER }], b: [{ updatedAt: AFTER }, { updatedAt: BEFORE }] } }
    return expect(countUnseenRows('webCachePoison', 'p1', T0)).resolves.toBe(2)
  })

  test('the project id reaches the route it delegates to', () => {
    return countUnseenRows('webCachePoison', 'p 1/2', T0).then(() => {
      expect(seenUrls[0]).toContain(`projectId=${encodeURIComponent('p 1/2')}`)
    })
  })

  test('a failing route is zero, not a thrown response', async () => {
    // One broken sheet must not blank every badge on the page.
    webCacheStatus = 500
    await expect(countUnseenRows('webCachePoison', 'p1', T0)).resolves.toBe(0)
  })

  test('a tab with no route source is zero rather than an error', async () => {
    await expect(countUnseenRows('nodeDetails', 'p1', T0)).resolves.toBe(0)
  })
})

describe('the source split', () => {
  test('only the unfiltered tabs are counted by label', () => {
    expect([...LABEL_TABS].sort()).toEqual(['all', 'jsRecon', 'nodeDetails'])
    expect(labelsForTab('jsRecon')).toEqual(['JsReconFinding'])
  })

  test('every filtered sheet delegates to its own route', () => {
    for (const tab of ['webCachePoison', 'sharedInfra', 'threatIntel', 'supplyChainSca', 'killChain']) {
      expect(ROUTE_TABS).toContain(tab)
    }
  })
})
