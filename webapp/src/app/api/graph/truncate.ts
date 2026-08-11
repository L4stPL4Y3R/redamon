import { GRAPH_MAX_NODES } from './config'

export interface TruncationInfo {
  /** True when the payload is a subset of the project's graph. */
  truncated: boolean
  /** Totals BEFORE truncation, so the UI can say "showing N of M". */
  totalNodes: number
  totalLinks: number
  returnedNodes: number
  returnedLinks: number
  limit: number
}

// Generic over the caller's own node/link shapes: this only needs `id` on a
// node and the two endpoints on a link, and must not force every caller to
// widen its formatted types.
type HasId = { id: string | number }
type HasEndpoints = { source: unknown; target: unknown }

/** A link endpoint may be an id or an already-resolved node object. */
function endpointId(v: unknown): string {
  if (typeof v === 'string') return v
  if (v && typeof v === 'object' && 'id' in v) return String((v as { id: unknown }).id)
  return String(v)
}

/**
 * Bound a graph payload to `GRAPH_MAX_NODES`.
 *
 * Links are filtered to those whose BOTH endpoints survived: keeping a link to a
 * dropped node would hand the renderer a dangling reference, which force-graph
 * libraries either throw on or silently materialise as a ghost node -- a subtly
 * wrong graph is worse than an explicitly partial one.
 *
 * The caller reports `TruncationInfo` in the response so a partial graph is
 * never presented as complete.
 */
export function truncateGraph<N extends HasId, L extends HasEndpoints>(
  nodes: N[],
  links: L[],
  limit: number = GRAPH_MAX_NODES(),
): { nodes: N[]; links: L[]; info: TruncationInfo } {
  const totalNodes = nodes.length
  const totalLinks = links.length

  if (totalNodes <= limit) {
    return {
      nodes,
      links,
      info: {
        truncated: false,
        totalNodes,
        totalLinks,
        returnedNodes: totalNodes,
        returnedLinks: totalLinks,
        limit,
      },
    }
  }

  const kept = nodes.slice(0, limit)
  const keptIds = new Set(kept.map(n => String(n.id)))
  const keptLinks = links.filter(
    l => keptIds.has(endpointId(l.source)) && keptIds.has(endpointId(l.target)),
  )

  return {
    nodes: kept,
    links: keptLinks,
    info: {
      truncated: true,
      totalNodes,
      totalLinks,
      returnedNodes: kept.length,
      returnedLinks: keptLinks.length,
      limit,
    },
  }
}
