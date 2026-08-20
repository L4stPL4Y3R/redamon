/**
 * Route handler tests for the unseen-badge count endpoint.
 *
 * Same strategy as redzoneRoutes.test.ts: mock `getGraphSession` with a stub
 * that records the Cypher it was handed and replays canned records.
 *
 * Run: npx vitest run src/app/api/analytics/unseen/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const guardProject = vi.fn().mockResolvedValue(null)
vi.mock('@/lib/access', () => ({ guardProject: (...args: unknown[]) => guardProject(...args) }))

const NOW = '2026-08-20T12:00:00.000Z'
const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let countRows: Array<Record<string, unknown>> = []
let shouldThrow: Error | null = null
const closed = { count: 0 }

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string, params: Record<string, unknown>) => {
      runCalls.push({ cypher, params })
      if (shouldThrow) throw shouldThrow
      if (cypher.includes('AS now')) return { records: [{ get: () => NOW }] }
      return { records: countRows.map(row => ({ get: (key: string) => row[key] })) }
    },
    close: async () => { closed.count++ },
  }),
}))

const route = await import('./route')

function makeRequest(body: unknown): any {
  return { json: async () => body }
}

beforeEach(() => {
  runCalls.length = 0
  countRows = []
  shouldThrow = null
  closed.count = 0
  guardProject.mockClear().mockResolvedValue(null)
})

const T1 = '2026-08-01T00:00:00.000Z'

describe('access', () => {
  test('a denied project short-circuits before any Cypher runs', async () => {
    guardProject.mockResolvedValue(new Response('nope', { status: 404 }))
    const res = await route.POST(makeRequest({ projectId: 'other', marks: { dnsEmail: T1 } }))
    expect(res.status).toBe(404)
    expect(runCalls).toHaveLength(0)
  })

  test('a missing projectId is refused by the guard', async () => {
    await route.POST(makeRequest({ marks: {} }))
    expect(guardProject).toHaveBeenCalledWith('')
  })

  test('an unparseable body is a 400', async () => {
    const res = await route.POST({ json: async () => { throw new Error('bad') } } as any)
    expect(res.status).toBe(400)
  })
})

describe('watermarks', () => {
  test('the project id is a parameter, and the query is scoped to it', async () => {
    countRows = [{ label: 'Domain', since: T1, c: { low: 4, high: 0 } }]
    await route.POST(makeRequest({ projectId: 'p1', marks: { dnsEmail: T1 } }))
    const counting = runCalls.find(c => !c.cypher.includes('AS now'))!
    expect(counting.params.pid).toBe('p1')
    expect(counting.cypher).toContain('{project_id: $pid}')
  })

  test('no watermarks at all runs no count query and returns the clock to seed from', async () => {
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: {} }))
    const body = await res.json()
    expect(body).toEqual({ now: NOW, counts: {}, total: 0 })
    expect(runCalls.filter(c => !c.cypher.includes('AS now'))).toHaveLength(0)
  })

  test('a watermark for an unknown tab is ignored', async () => {
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: { notATab: T1 } }))
    expect((await res.json()).counts).toEqual({})
  })

  test('an unparseable watermark is dropped rather than sent to datetime()', async () => {
    // `datetime('last tuesday')` throws in Cypher and would take every badge on
    // the page down with it, so one bad value must not poison the request.
    const res = await route.POST(
      makeRequest({ projectId: 'p1', marks: { dnsEmail: 'last tuesday', dnsDrift: T1 } }),
    )
    const counting = runCalls.find(c => !c.cypher.includes('AS now'))!
    expect(JSON.stringify(counting.params)).not.toContain('last tuesday')
    expect(Object.keys((await res.json()).counts)).toEqual(['dnsDrift'])
  })

  test('a non-string watermark is dropped', async () => {
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: { dnsEmail: 12345 } }))
    expect((await res.json()).counts).toEqual({})
  })
})

describe('counting', () => {
  test('neo4j integers are unwrapped and rolled up per tab', async () => {
    countRows = [
      { label: 'Domain', since: T1, c: { low: 3, high: 0 } },
      { label: 'IP', since: T1, c: { low: 5, high: 0 } },
      { label: 'ThreatPulse', since: T1, c: { low: 2, high: 0 } },
    ]
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: { threatIntel: T1 } }))
    expect((await res.json()).counts.threatIntel).toBe(10)
  })

  test('the bar total counts a label once, not once per tab showing it', async () => {
    countRows = [{ label: 'Domain', since: T1, c: { low: 3, high: 0 } }]
    const res = await route.POST(
      makeRequest({ projectId: 'p1', marks: { nodeDetails: T1, all: T1, dnsEmail: T1 } }),
    )
    const body = await res.json()
    expect(body.counts.dnsEmail).toBe(3)
    expect(body.total).toBe(3)
  })

  test('the clock comes from the graph, not the process', async () => {
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: { dnsEmail: T1 } }))
    expect((await res.json()).now).toBe(NOW)
  })

  test('a Cypher failure is a 500 and still closes the session', async () => {
    shouldThrow = new Error('boom')
    const res = await route.POST(makeRequest({ projectId: 'p1', marks: { dnsEmail: T1 } }))
    expect(res.status).toBe(500)
    expect(closed.count).toBe(1)
  })
})
