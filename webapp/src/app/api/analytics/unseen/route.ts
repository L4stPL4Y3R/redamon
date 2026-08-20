/**
 * Unseen-row badge counts for every graph table tab, in one round trip.
 *
 * The alternative is calling all ~20 Red Zone routes to see whether any of them
 * has anything new, which transfers the entire attack surface to render twenty
 * small numbers. This route transfers only the numbers.
 *
 * POST rather than GET because the request carries the caller's per-tab
 * watermark map; it is a read and performs no writes.
 */
import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { BADGED_TABS } from '@/app/graph/unseen/registry'
import { buildUnseenQuery, distinctUnseenTotal, labelThresholds, tallyByTab, type UnseenRow } from '@/app/graph/unseen/counts'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

const BADGED = new Set<string>(BADGED_TABS)

/**
 * Keep only watermarks that name a real tab and parse as an instant.
 *
 * Unparseable values are dropped rather than 400'd: they reach Cypher as
 * `datetime($since)`, which THROWS on a malformed string, and one stale value in
 * a preferences blob would take every badge on the page down with it. A dropped
 * tab is re-seeded with the server clock on the next response.
 */
function sanitiseMarks(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== 'object') return {}
  const out: Record<string, string> = {}
  for (const [tab, value] of Object.entries(raw as Record<string, unknown>)) {
    if (!BADGED.has(tab) || typeof value !== 'string') continue
    const ms = Date.parse(value)
    if (Number.isNaN(ms)) continue
    out[tab] = new Date(ms).toISOString()
  }
  return out
}

export async function POST(request: NextRequest) {
  let body: { projectId?: unknown; marks?: unknown }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
  }

  const projectId = typeof body.projectId === 'string' ? body.projectId : ''
  const denied = await guardProject(projectId)
  if (denied) return denied

  const marks = sanitiseMarks(body.marks)
  const thresholds = labelThresholds(marks)
  const query = buildUnseenQuery(thresholds)

  const session = getGraphSession()
  try {
    // The graph's own clock, not the browser's and not the webapp's. Watermarks
    // are compared against timestamps Neo4j stamped, so a client that is a
    // minute fast would write a watermark into the future and hide the next
    // scan's findings permanently.
    const nowResult = await session.run('RETURN toString(datetime()) AS now')
    const now = nowResult.records[0]?.get('now') as string

    // No watermarks yet (a first-ever visit) means nothing to count: the client
    // seeds every tab from `now` and starts at zero.
    if (!query) return NextResponse.json({ now, counts: {}, total: 0 })

    const result = await session.run(query.cypher, { pid: projectId, ...query.params })
    const rows: UnseenRow[] = result.records.map(r => ({
      label: r.get('label') as string,
      since: r.get('since') as string,
      count: toNum(r.get('c')),
    }))

    return NextResponse.json({
      now,
      counts: tallyByTab(rows, marks),
      total: distinctUnseenTotal(rows, thresholds),
    })
  } catch (error) {
    console.error('Failed to compute unseen counts:', error)
    return NextResponse.json({ error: 'Failed to compute unseen counts' }, { status: 500 })
  } finally {
    await session.close()
  }
}
