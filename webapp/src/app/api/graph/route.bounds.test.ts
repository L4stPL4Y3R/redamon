/**
 * Regression tests for two bugs found reviewing the graph-bounding work.
 * Each is named after the bug so it cannot come back.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ run: vi.fn(), close: vi.fn(), conversations: vi.fn(() => []) }))

vi.mock('./neo4j', () => ({
  getGraphSession: () => ({ run: h.run, close: h.close }),
  neo4j: { int: (n: number) => ({ __int: n }) },
}))
vi.mock('@/lib/prisma', () => ({
  default: { conversation: { findMany: (...a: unknown[]) => h.conversations(...a) } },
}))
vi.mock('./format', () => ({
  formatGraphRecords: (records: unknown[]) => ({
    nodes: records.map((_, i) => ({ id: `n${i}`, name: 'n', type: 'IP', properties: {} })),
    links: [],
  }),
}))

beforeEach(() => {
  h.run.mockReset()
  h.close.mockReset()
  h.conversations.mockReturnValue([])
  vi.unstubAllEnvs()
  vi.resetModules()
})

describe('BUG: the Cypher read was unbounded, so truncation never lowered the peak', () => {
  // Slicing in Node happened AFTER the driver had already materialised every
  // record, so the cap shrank the cached copy and the JSON string but NOT the
  // read that OOM-killed the container. The bound has to be in the query.
  test('LIVE_GRAPH_QUERY carries a LIMIT', async () => {
    const { LIVE_GRAPH_QUERY } = await import('./liveRead')
    expect(LIVE_GRAPH_QUERY).toMatch(/\bLIMIT\s+\$maxRecords\b/)
  })

  test('the UNION is wrapped so the LIMIT applies to the whole result, not one arm', async () => {
    const { LIVE_GRAPH_QUERY } = await import('./liveRead')
    // A bare `LIMIT` after a UNION binds to the final arm only.
    expect(LIVE_GRAPH_QUERY).toMatch(/CALL\s*\{/)
    const limitAt = LIVE_GRAPH_QUERY.lastIndexOf('LIMIT')
    const closeAt = LIVE_GRAPH_QUERY.lastIndexOf('}')
    expect(limitAt).toBeGreaterThan(closeAt)
  })

  test('readLiveGraph passes maxRecords to the driver', async () => {
    h.run.mockResolvedValue({ records: [] })
    const { readLiveGraph } = await import('./liveRead')
    await readLiveGraph('p1')
    const readCall = h.run.mock.calls.find(c => String(c[0]).includes('LIMIT'))
    expect(readCall).toBeDefined()
    expect(readCall![1]).toHaveProperty('maxRecords')
    expect(readCall![1].projectId).toBe('p1')
  })

  test('GRAPH_MAX_RECORDS is honoured and defaults above the node cap', async () => {
    vi.stubEnv('GRAPH_MAX_RECORDS', '77')
    const { GRAPH_MAX_RECORDS } = await import('./config')
    expect(GRAPH_MAX_RECORDS()).toBe(77)

    vi.unstubAllEnvs()
    vi.resetModules()
    const fresh = await import('./config')
    // One record yields at most two nodes, so the record ceiling must exceed
    // the node cap or the node cap could never be reached.
    expect(fresh.GRAPH_MAX_RECORDS()).toBeGreaterThan(fresh.GRAPH_MAX_NODES())
  })

  test.each(['0', '-5', 'abc', ''])('a bad GRAPH_MAX_RECORDS (%o) falls back, never to 0', async raw => {
    vi.stubEnv('GRAPH_MAX_RECORDS', raw)
    const { GRAPH_MAX_RECORDS } = await import('./config')
    // A 0 limit would return an EMPTY graph on every request.
    expect(GRAPH_MAX_RECORDS()).toBeGreaterThan(0)
  })
})

describe('BUG: cache hit and miss disagreed on the response shape', () => {
  // The miss omitted `truncated` when the graph fitted; the hit included
  // `truncated: {truncated:false,...}` -- a TRUTHY object -- so a client doing
  // `if (data.truncated)` got different answers for identical data depending on
  // whether the cache was warm.
  test('a non-truncated graph omits `truncated` on BOTH paths', async () => {
    const { setCached, getCached, clearCache } = await import('./cache')
    clearCache()
    const info = {
      truncated: false, totalNodes: 3, totalLinks: 0,
      returnedNodes: 3, returnedLinks: 0, limit: 20_000,
    }
    setCached('p', { nodes: [], links: [] }, info)
    const cached = getCached('p')!

    const missBody = { projectId: 'p', ...(info.truncated ? { truncated: info } : {}) }
    const hitBody = { projectId: 'p', ...(cached.info?.truncated ? { truncated: cached.info } : {}) }

    expect('truncated' in missBody).toBe(false)
    expect('truncated' in hitBody).toBe(false)
    expect(Boolean((hitBody as Record<string, unknown>).truncated))
      .toBe(Boolean((missBody as Record<string, unknown>).truncated))
    clearCache()
  })

  test('a truncated graph reports `truncated` on BOTH paths, with equal totals', async () => {
    const { setCached, getCached, clearCache } = await import('./cache')
    clearCache()
    const info = {
      truncated: true, totalNodes: 900, totalLinks: 5,
      returnedNodes: 10, returnedLinks: 2, limit: 10,
    }
    setCached('p', { nodes: [], links: [] }, info)
    const cached = getCached('p')!

    const missBody = { ...(info.truncated ? { truncated: info } : {}) }
    const hitBody = { ...(cached.info?.truncated ? { truncated: cached.info } : {}) }

    expect('truncated' in missBody).toBe(true)
    expect('truncated' in hitBody).toBe(true)
    expect(hitBody.truncated).toEqual(missBody.truncated)
    clearCache()
  })

  test('an entry cached without info never yields a truthy `truncated`', async () => {
    const { setCached, getCached, clearCache } = await import('./cache')
    clearCache()
    setCached('p', { nodes: [], links: [] })
    const cached = getCached('p')!
    const body = { ...(cached.info?.truncated ? { truncated: cached.info } : {}) }
    expect('truncated' in body).toBe(false)
    clearCache()
  })
})
