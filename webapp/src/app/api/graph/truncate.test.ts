/**
 * Payload bounding for /api/graph.
 *
 * WHY: the endpoint returned the entire project graph with no limit while
 * holding three copies at once (the object, the cached copy, the JSON string).
 * On a 300K-node project that OOM-killed the webapp container -- the 502s and
 * the never-completing requests that started this work. Raising the memory
 * ceiling only moves that cliff; the cap removes it.
 *
 * @vitest-environment node
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { truncateGraph } from './truncate'

const nodes = (n: number, from = 0) =>
  Array.from({ length: n }, (_, i) => ({ id: `n${i + from}`, name: 'x', type: 'IP', properties: {} }))

afterEach(() => vi.unstubAllEnvs())

describe('truncateGraph', () => {
  test('a graph under the limit is returned untouched and not flagged', () => {
    const n = nodes(10)
    const l = [{ source: 'n0', target: 'n1' }]
    const r = truncateGraph(n, l, 100)
    expect(r.nodes).toBe(n)
    expect(r.links).toBe(l)
    expect(r.info.truncated).toBe(false)
    expect(r.info.totalNodes).toBe(10)
    expect(r.info.returnedNodes).toBe(10)
  })

  test('exactly at the limit is NOT truncated (off by one)', () => {
    const r = truncateGraph(nodes(50), [], 50)
    expect(r.info.truncated).toBe(false)
    expect(r.info.returnedNodes).toBe(50)
  })

  test('one over the limit IS truncated', () => {
    const r = truncateGraph(nodes(51), [], 50)
    expect(r.info.truncated).toBe(true)
    expect(r.nodes).toHaveLength(50)
    expect(r.info.totalNodes).toBe(51)
  })

  test('reports the pre-truncation totals so the UI can say "showing N of M"', () => {
    const r = truncateGraph(nodes(1000), [{ source: 'n0', target: 'n1' }], 10)
    expect(r.info).toMatchObject({
      truncated: true,
      totalNodes: 1000,
      totalLinks: 1,
      returnedNodes: 10,
      limit: 10,
    })
  })

  // The core correctness property: a link to a dropped node is a dangling
  // reference. force-graph either throws on it or invents a ghost node, so a
  // subtly wrong graph would be served instead of an explicitly partial one.
  test('drops links whose endpoints did not survive', () => {
    const r = truncateGraph(
      nodes(100),
      [
        { source: 'n0', target: 'n1' },   // both kept
        { source: 'n0', target: 'n90' },  // target dropped
        { source: 'n95', target: 'n96' }, // both dropped
      ],
      10,
    )
    expect(r.links).toEqual([{ source: 'n0', target: 'n1' }])
    expect(r.info.returnedLinks).toBe(1)
    expect(r.info.totalLinks).toBe(3)
  })

  test('no surviving link references a dropped node', () => {
    const all = nodes(500)
    const links = all.slice(0, 499).map((n, i) => ({ source: n.id, target: `n${i + 1}` }))
    const r = truncateGraph(all, links, 50)
    const kept = new Set(r.nodes.map(n => n.id))
    for (const l of r.links) {
      expect(kept.has(l.source as string)).toBe(true)
      expect(kept.has(l.target as string)).toBe(true)
    }
  })

  test('handles endpoints given as resolved node objects, not just ids', () => {
    const r = truncateGraph(
      nodes(100),
      [
        { source: { id: 'n0' }, target: { id: 'n1' } },
        { source: { id: 'n0' }, target: { id: 'n80' } },
      ],
      10,
    )
    expect(r.links).toHaveLength(1)
  })

  test.each([0, 1])('degenerate input: %i nodes', n => {
    const r = truncateGraph(nodes(n), [], 10)
    expect(r.info.truncated).toBe(false)
    expect(r.nodes).toHaveLength(n)
  })

  test('an empty graph is not flagged as truncated', () => {
    const r = truncateGraph([], [], 10)
    expect(r.info).toMatchObject({ truncated: false, totalNodes: 0, totalLinks: 0 })
  })

  test('GRAPH_MAX_NODES sets the default limit', async () => {
    vi.stubEnv('GRAPH_MAX_NODES', '5')
    vi.resetModules()
    const { truncateGraph: fresh } = await import('./truncate')
    const r = fresh(nodes(20), [])
    expect(r.nodes).toHaveLength(5)
    expect(r.info.limit).toBe(5)
  })

  test.each(['0', '-1', 'abc', ''])('a bad GRAPH_MAX_NODES (%o) falls back to the default', async raw => {
    vi.stubEnv('GRAPH_MAX_NODES', raw)
    vi.resetModules()
    const { truncateGraph: fresh } = await import('./truncate')
    const r = fresh(nodes(3), [])
    expect(r.info.limit).toBe(20_000)
  })
})
