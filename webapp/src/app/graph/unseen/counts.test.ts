/**
 * Run: npx vitest run src/app/graph/unseen/counts.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { barTotal, buildLabelCountQuery, isSafeLabel } from './counts'

describe('buildLabelCountQuery', () => {
  test('no labels yields no query at all', () => {
    expect(buildLabelCountQuery([])).toBeNull()
  })

  test('one UNION ALL branch per label, each scoped to the project', () => {
    const q = buildLabelCountQuery(['Domain', 'Secret'])!
    expect(q.cypher.split('UNION ALL')).toHaveLength(2)
    expect(q.cypher).toContain('MATCH (n:Domain {project_id: $pid})')
    expect(q.cypher).toContain('MATCH (n:Secret {project_id: $pid})')
  })

  test('every branch names its label, so none becomes an all-database scan', () => {
    // A label-free `MATCH (n)` reads every node in the database, every other
    // project included - the same shape as the query_graph tenant leak.
    const q = buildLabelCountQuery(['Domain', 'IP'])!
    for (const branch of q.cypher.split('UNION ALL')) {
      expect(branch).toMatch(/MATCH \(n:[A-Za-z]+ \{project_id: \$pid\}\)/)
    }
  })

  test('reads the same write-time properties the Updated column does', () => {
    // Package and the attack-chain labels stamp first_seen/created_at, not
    // updated_at; dropping the coalesce silences the largest labels in a real
    // graph while every other test still passes.
    const q = buildLabelCountQuery(['Package'])!
    expect(q.cypher).toContain('coalesce(n.updated_at, n.last_seen, n.created_at, n.first_seen)')
  })

  test('the watermark travels as a parameter, never inlined', () => {
    const q = buildLabelCountQuery(['Domain'])!
    expect(q.cypher).toContain('datetime($since)')
    expect(q.cypher).not.toMatch(/\d{4}-\d{2}-\d{2}T/)
  })

  test('a label that is not a bare identifier is dropped, not interpolated', () => {
    const q = buildLabelCountQuery(['Domain) DETACH DELETE n //', 'Secret'])!
    expect(q.cypher).not.toContain('DELETE')
    expect(q.cypher.split('UNION ALL')).toHaveLength(1)
  })
})

describe('isSafeLabel', () => {
  test.each(['Domain', 'MultiscannerFinding', 'IP'])('%s is safe', l => {
    expect(isSafeLabel(l)).toBe(true)
  })
  test.each(['Domain)', 'a-b', '1Domain', '', 'Domain Secret', 'Domain`'])('%s is rejected', l => {
    expect(isSafeLabel(l)).toBe(false)
  })
})

describe('barTotal', () => {
  test('is not the sum of the badges', () => {
    // The bug this exists to prevent: Node Inspector and All Nodes both cover
    // the whole graph, so adding every badge reports each node three times.
    expect(barTotal({ nodeDetails: 513, all: 513, secrets: 300 })).toBe(513)
  })

  test('sums the specialised sheets when they outweigh the whole graph', () => {
    // Right after the user opens All Nodes: its badge is zero, but 300 rows are
    // still waiting in Secrets and the bar has to keep saying so.
    expect(barTotal({ nodeDetails: 0, all: 0, secrets: 300, takeover: 4 })).toBe(304)
  })

  test('is zero when every tab is zero', () => {
    // A bar number over a dropdown of zeroes is the exact complaint this
    // feature has to avoid: a count you cannot click through to anything.
    expect(barTotal({ nodeDetails: 0, all: 0, secrets: 0 })).toBe(0)
  })

  test('is never smaller than the biggest single badge', () => {
    const counts = { nodeDetails: 40, all: 40, secrets: 3, dnsEmail: 1 }
    const biggest = Math.max(...Object.values(counts))
    expect(barTotal(counts)).toBeGreaterThanOrEqual(biggest)
  })

  test('an empty response is zero, not NaN', () => {
    expect(barTotal({})).toBe(0)
  })
})
