/**
 * The whole-graph label count and the bar total, kept pure so both test without
 * a Neo4j instance.
 *
 * Only the two whole-graph tabs (Node Inspector, All Nodes) and JS Recon are
 * counted this way, because for them "every node with this label" IS the row
 * set. Every other tab is a filtered view and is counted by running its own
 * route - see `api/analytics/unseen/sources.ts` for why that distinction is the
 * difference between a badge that means something and one that does not.
 */

/**
 * A Cypher label is interpolated, never parameterised - Neo4j has no parameter
 * form for a label. Everything reaching here comes from the registry, so this
 * is a belt-and-braces check that a future edit cannot turn into injection.
 */
export function isSafeLabel(label: string): boolean {
  return /^[A-Za-z][A-Za-z0-9_]*$/.test(label)
}

export interface UnseenQuery {
  cypher: string
  params: Record<string, unknown>
}

/**
 * Count the project's nodes, per label, written after `since`.
 *
 * `coalesce` over the four write-time properties mirrors UPDATED_AT_PROPS: the
 * attack-chain and Package labels stamp `created_at` / `first_seen` instead of
 * `updated_at`, and reading only `updated_at` would leave the largest labels in
 * a real graph permanently silent.
 *
 * A node whose timestamp was stored as a STRING rather than a Cypher temporal
 * compares as null against `datetime($since)` and is simply not counted. That is
 * an undercount, never an error - the alternative (`datetime(toString(ts))`)
 * throws on one malformed value and takes every badge on the page down with it.
 *
 * One UNION ALL branch per label so each uses its own label scan; a single
 * label-free `MATCH (n)` would read every node in the database, every project
 * included.
 */
export function buildLabelCountQuery(labels: readonly string[]): UnseenQuery | null {
  const branches = labels
    .filter(isSafeLabel)
    .map(label => [
      `MATCH (n:${label} {project_id: $pid})`,
      `WITH coalesce(n.updated_at, n.last_seen, n.created_at, n.first_seen) AS ts`,
      `WHERE ts IS NOT NULL AND ts > datetime($since)`,
      `RETURN count(*) AS c`,
    ].join('\n'))

  if (branches.length === 0) return null
  return { cypher: branches.join('\nUNION ALL\n'), params: {} }
}

/**
 * The one number beside the tab selector.
 *
 * Not a sum of the badges. Node Inspector and All Nodes each cover the whole
 * graph, so adding every badge together reports each new node at least twice
 * and often three times - 1326 for 513 real findings on a live project, which
 * teaches the user the number means nothing.
 *
 * The larger of "rows waiting across the specialised sheets" and "nodes waiting
 * in the whole-graph tabs". Both are real quantities, and taking the larger
 * means the bar is never bigger than something the user can actually go and
 * look at, and never non-zero when every tab is zero.
 */
export function barTotal(counts: Record<string, number>): number {
  const WHOLE_GRAPH = ['nodeDetails', 'all']
  let sheets = 0
  for (const [tab, n] of Object.entries(counts)) {
    if (!WHOLE_GRAPH.includes(tab) && n > 0) sheets += n
  }
  const wholeGraph = Math.max(...WHOLE_GRAPH.map(t => counts[t] ?? 0), 0)
  return Math.max(sheets, wholeGraph)
}
