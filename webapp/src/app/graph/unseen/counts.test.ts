/**
 * Run: npx vitest run src/app/graph/unseen/counts.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { buildUnseenQuery, distinctUnseenTotal, isSafeLabel, labelThresholds, tallyByTab, type UnseenRow } from './counts'
import { UNSEEN_TAB_LABELS } from './registry'

const T1 = '2026-08-01T00:00:00.000Z'
const T2 = '2026-08-02T00:00:00.000Z'

describe('labelThresholds', () => {
  test('a tab with no watermark contributes nothing', () => {
    // This is the seeding case: an unmarked tab must not be counted at all,
    // rather than counted from the epoch and shown as "everything is new".
    expect(labelThresholds({}).size).toBe(0)
  })

  test('two tabs sharing a label and a watermark cost one scan', () => {
    const t = labelThresholds({ dnsEmail: T1, dnsDrift: T1 })
    expect(t.get('Domain')).toEqual([T1])
  })

  test('two tabs sharing a label with different watermarks keep both', () => {
    const t = labelThresholds({ dnsEmail: T1, dnsDrift: T2 })
    expect(t.get('Domain')?.sort()).toEqual([T1, T2])
  })

  test('a tab covers every label it lists', () => {
    const t = labelThresholds({ supplyChainSca: T1 })
    for (const label of UNSEEN_TAB_LABELS.supplyChainSca) expect(t.get(label)).toEqual([T1])
  })
})

describe('buildUnseenQuery', () => {
  test('nothing to count yields no query at all', () => {
    expect(buildUnseenQuery(new Map())).toBeNull()
  })

  test('one UNION ALL branch per label, each scoped to the project', () => {
    const q = buildUnseenQuery(new Map([['Domain', [T1]], ['Secret', [T2]]]))!
    expect(q.cypher.split('UNION ALL')).toHaveLength(2)
    expect(q.cypher).toContain('MATCH (n:Domain {project_id: $pid})')
    expect(q.cypher).toContain('MATCH (n:Secret {project_id: $pid})')
  })

  test('reads the same write-time properties the Updated column does', () => {
    // Package and the attack-chain labels stamp first_seen/created_at, not
    // updated_at; dropping the coalesce silences the largest labels in a real
    // graph while every other test still passes.
    const q = buildUnseenQuery(new Map([['Package', [T1]]]))!
    expect(q.cypher).toContain('coalesce(n.updated_at, n.last_seen, n.created_at, n.first_seen)')
  })

  test('thresholds travel as parameters, never inlined', () => {
    const q = buildUnseenQuery(new Map([['Domain', [T1, T2]]]))!
    expect(q.cypher).not.toContain(T1)
    expect(Object.values(q.params)).toEqual([[T1, T2]])
  })

  test('a label that is not a bare identifier is dropped, not interpolated', () => {
    const q = buildUnseenQuery(new Map([['Domain) DETACH DELETE n //', [T1]], ['Secret', [T1]]]))
    expect(q!.cypher).not.toContain('DELETE')
    expect(q!.cypher.split('UNION ALL')).toHaveLength(1)
  })

  test('a label with no thresholds gets no branch', () => {
    expect(buildUnseenQuery(new Map([['Domain', []]]))).toBeNull()
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

describe('tallyByTab', () => {
  const rows: UnseenRow[] = [
    { label: 'Domain', since: T1, count: 3 },
    { label: 'Domain', since: T2, count: 1 },
    { label: 'IP', since: T1, count: 5 },
    { label: 'ThreatPulse', since: T1, count: 2 },
  ]

  test('a tab only counts rows measured against ITS watermark', () => {
    // The whole point of grouping by (label, since): dnsDrift asked about
    // Domain since T2 and must not inherit dnsEmail's T1 answer.
    const counts = tallyByTab(rows, { dnsEmail: T1, dnsDrift: T2 })
    expect(counts.dnsEmail).toBe(3)
    expect(counts.dnsDrift).toBe(1)
  })

  test('a multi-label tab sums its labels', () => {
    expect(tallyByTab(rows, { threatIntel: T1 }).threatIntel).toBe(10)
  })

  test('an unmarked tab is absent rather than zero', () => {
    // Absent means "seed me"; zero would mean "counted, nothing new".
    expect(tallyByTab(rows, { dnsEmail: T1 })).not.toHaveProperty('dnsDrift')
  })

  test('a marked tab with no matching rows is an explicit zero', () => {
    expect(tallyByTab([], { dnsEmail: T1 }).dnsEmail).toBe(0)
  })
})

describe('distinctUnseenTotal', () => {
  const rows: UnseenRow[] = [
    { label: 'Domain', since: T1, count: 3 },
    { label: 'Domain', since: T2, count: 1 },
  ]

  test('counts each label once, against its oldest watermark', () => {
    // Two tabs show Domain; the tab that looked longest ago is the one that
    // still has all 3 unseen, so 3 is the honest answer - not 3 + 1.
    expect(distinctUnseenTotal(rows, new Map([['Domain', [T2, T1]]]))).toBe(3)
  })

  test('is not the sum of the tab badges', () => {
    // The bug this exists to prevent: Node Inspector and All Nodes both cover
    // the whole graph, so summing badges reports every new node at least twice.
    const marks = { nodeDetails: T1, all: T1, dnsEmail: T1 }
    const domainRows: UnseenRow[] = [{ label: 'Domain', since: T1, count: 3 }]
    const summed = Object.values(tallyByTab(domainRows, marks)).reduce((a, b) => a + b, 0)
    expect(summed).toBe(9)
    expect(distinctUnseenTotal(domainRows, labelThresholds(marks))).toBe(3)
  })

  test('a label with no answer contributes nothing', () => {
    expect(distinctUnseenTotal([], new Map([['Domain', [T1]]]))).toBe(0)
  })
})
