/**
 * Bounds for the graph read path.
 *
 * WHY: `/api/graph` used to return the whole project graph with no limit, while
 * holding three copies at once -- the object, the cached copy, and the complete
 * JSON string. On a 300K-node project that exhausted the container and the
 * request either 502'd (OOM kill) or sat pending forever. Raising the memory
 * ceiling only moves that cliff; these bounds remove it.
 */

/** Verbose per-request timing logs. Was hardcoded `true`, i.e. on in production. */
export const GRAPH_PERF_DEBUG = process.env.GRAPH_PERF_DEBUG === '1'

function intEnv(name: string, dflt: number): number {
  const raw = Number(process.env[name])
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : dflt
}

/**
 * Maximum nodes returned in one response. Beyond this the payload is truncated
 * and the response says so explicitly (`truncated`), so the UI can render
 * "showing N of M" instead of silently presenting a partial graph as complete.
 */
export const GRAPH_MAX_NODES = () => intEnv('GRAPH_MAX_NODES', 20_000)

/** Cache bounds: entries, and total nodes+links held across all entries. */
export const GRAPH_CACHE_MAX_ENTRIES = () => intEnv('GRAPH_CACHE_MAX_ENTRIES', 8)
export const GRAPH_CACHE_MAX_ELEMENTS = () => intEnv('GRAPH_CACHE_MAX_ELEMENTS', 200_000)

/**
 * Hard record ceiling applied INSIDE the Cypher query.
 *
 * One record is one (n)-[r]->(m) row, so it yields at most two nodes; 2.5x the
 * node cap leaves generous headroom for duplicate endpoints across UNION arms
 * while still bounding what the driver can ever materialise.
 */
export const GRAPH_MAX_RECORDS = () => intEnv('GRAPH_MAX_RECORDS', GRAPH_MAX_NODES() * 5 / 2)
