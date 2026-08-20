/**
 * The unseen-count query and its tally, kept pure so both can be tested without
 * a Neo4j instance.
 *
 * Shape of the problem: ~20 tabs, each with its own watermark, sharing ~45 node
 * labels between them. The naive query - one aggregation per (tab, label) pair -
 * rescans the same label once per tab that uses it. Instead each label is
 * scanned ONCE and counted against every threshold that label is asked about,
 * which is why the thresholds are grouped per label rather than passed as one
 * global list. Two tabs sharing a label and a watermark cost one pass, not two.
 */
import { UNSEEN_TAB_LABELS } from './registry'

/**
 * A Cypher label is interpolated, never parameterised - Neo4j has no parameter
 * form for a label. Everything reaching here comes from the registry, so this
 * is a belt-and-braces check that a future edit cannot turn into injection.
 */
export function isSafeLabel(label: string): boolean {
  return /^[A-Za-z][A-Za-z0-9_]*$/.test(label)
}

export interface UnseenRow {
  label: string
  since: string
  count: number
}

export interface UnseenQuery {
  cypher: string
  params: Record<string, unknown>
}

/**
 * Group each label with the distinct watermarks it must be counted against.
 *
 * A tab with no watermark is absent from `marks` and contributes nothing: a
 * first-time user is seeded with the server clock instead of being shown every
 * row in the database as "new".
 */
export function labelThresholds(marks: Record<string, string | undefined>): Map<string, string[]> {
  const perLabel = new Map<string, Set<string>>()
  for (const [tab, labels] of Object.entries(UNSEEN_TAB_LABELS)) {
    const since = marks[tab]
    if (!since) continue
    for (const label of labels) {
      const set = perLabel.get(label) ?? new Set<string>()
      set.add(since)
      perLabel.set(label, set)
    }
  }
  return new Map([...perLabel].map(([label, set]) => [label, [...set]]))
}

/**
 * One UNION ALL branch per label.
 *
 * `coalesce` over the four write-time properties mirrors UPDATED_AT_PROPS: the
 * attack-chain and Package labels stamp `created_at` / `first_seen` instead of
 * `updated_at`, and reading only `updated_at` would leave the largest labels in
 * a real graph permanently silent.
 *
 * A node whose timestamp was stored as a STRING rather than a Cypher temporal
 * compares as null against `datetime(since)` and is simply not counted. That is
 * an undercount, never an error - the alternative (`datetime(toString(ts))`)
 * throws on one malformed value and takes every badge on the page down with it.
 */
export function buildUnseenQuery(thresholds: Map<string, string[]>): UnseenQuery | null {
  const params: Record<string, unknown> = {}
  const branches: string[] = []
  let i = 0

  for (const [label, sinces] of thresholds) {
    if (!isSafeLabel(label) || sinces.length === 0) continue
    const key = `t${i++}`
    params[key] = sinces
    branches.push([
      `MATCH (n:${label} {project_id: $pid})`,
      `WITH coalesce(n.updated_at, n.last_seen, n.created_at, n.first_seen) AS ts`,
      `WHERE ts IS NOT NULL`,
      `UNWIND $${key} AS since`,
      `WITH since, ts WHERE ts > datetime(since)`,
      `RETURN '${label}' AS label, since, count(*) AS c`,
    ].join('\n'))
  }

  if (branches.length === 0) return null
  return { cypher: branches.join('\nUNION ALL\n'), params }
}

/**
 * Roll the per-label counts up to per-tab badges.
 *
 * Deliberately a SUM over labels, which double-counts a row built by joining
 * two labels that both changed. The badge is a "something moved here" cue, not
 * a row count: over-reporting sends the user to look, under-reporting hides the
 * finding. The tab itself shows the true row count once opened.
 */
export function tallyByTab(
  rows: UnseenRow[],
  marks: Record<string, string | undefined>,
): Record<string, number> {
  const byLabelSince = new Map<string, number>()
  for (const row of rows) {
    const key = `${row.label} ${row.since}`
    byLabelSince.set(key, (byLabelSince.get(key) ?? 0) + row.count)
  }

  const counts: Record<string, number> = {}
  for (const [tab, labels] of Object.entries(UNSEEN_TAB_LABELS)) {
    const since = marks[tab]
    if (!since) continue
    let total = 0
    for (const label of labels) total += byLabelSince.get(`${label} ${since}`) ?? 0
    counts[tab] = total
  }
  return counts
}

/**
 * The one number for the tab bar: how many nodes are unseen by SOME tab.
 *
 * Not the sum of the badges. Node Inspector and All Nodes each cover the whole
 * graph, so summing tabs counts every new node at least twice and anything a
 * specialised sheet also shows three times - 1326 shown for 513 real findings,
 * which teaches the user the number means nothing.
 *
 * A node is unseen if it is newer than the OLDEST watermark among the tabs that
 * would show it, and that count is already in `rows`: the oldest threshold is
 * one of the thresholds the label was scanned against, so this costs no extra
 * query. Nodes carrying two labels are still counted twice, which in this graph
 * is a handful of rows rather than a factor of three.
 */
export function distinctUnseenTotal(rows: UnseenRow[], thresholds: Map<string, string[]>): number {
  const byLabelSince = new Map<string, number>()
  for (const row of rows) byLabelSince.set(`${row.label} ${row.since}`, row.count)

  let total = 0
  for (const [label, sinces] of thresholds) {
    if (sinces.length === 0) continue
    const oldest = sinces.reduce((a, b) => (Date.parse(a) <= Date.parse(b) ? a : b))
    total += byLabelSince.get(`${label} ${oldest}`) ?? 0
  }
  return total
}
