import { NextRequest, NextResponse } from 'next/server'
import { getGraphSession } from './neo4j'
import { readLiveGraph } from './liveRead'
import { getCached, setCached, invalidateCache } from './cache'
import { truncateGraph } from './truncate'
import { GRAPH_PERF_DEBUG } from './config'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const projectId = searchParams.get('projectId')

  if (!projectId) {
    return NextResponse.json(
      { error: 'projectId is required' },
      { status: 400 }
    )
  }

  // The graph is scoped to a project; the caller's effective user must own that
  // project. Since a project has exactly one owner, proving ownership here scopes
  // the returned subgraph to the effective user (blocks the impersonation-URL BOLA
  // where an admin simulating X, or any user, reads another user's graph by id).
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, projectId)
  if (access instanceof NextResponse) return access

  if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] GET /api/graph projectId=${projectId}`)

  // Allow clients to bypass server cache (used after pipeline completion
  // to ensure background graph-DB writes are picked up)
  const fresh = searchParams.get('fresh') === '1'
  if (fresh) {
    invalidateCache(projectId)
    if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] Fresh request -- cache invalidated for ${projectId}`)
  }

  // Check If-None-Match header for ETag-based conditional request
  const ifNoneMatch = request.headers.get('if-none-match')

  // Check server-side cache
  const cached = getCached(projectId)
  if (cached) {
    const cacheAge = Date.now() - cached.timestamp
    if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] Cache HIT for ${projectId} (age=${cacheAge}ms)`)

    // If client has same ETag, return 304
    if (ifNoneMatch && ifNoneMatch === `"${cached.etag}"`) {
      if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] 304 Not Modified -- ETag matched for ${projectId}`)
      return new NextResponse(null, {
        status: 304,
        headers: {
          'ETag': `"${cached.etag}"`,
          'Cache-Control': 'private, no-cache',
        },
      })
    }

    // Return cached data with ETag
    return NextResponse.json(
      { nodes: cached.data.nodes, links: cached.data.links, projectId, ...(cached.info ? { truncated: cached.info } : {}) },
      {
        headers: {
          'ETag': `"${cached.etag}"`,
          'Cache-Control': 'private, no-cache',
        },
      }
    )
  }

  if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] Cache MISS for ${projectId}`)

  try {
    // Same read path the version endpoint uses for the CURRENT version
    // (Scan Timeline Section 4.1), including the orphan-chain reconcile.
    const full = await readLiveGraph(projectId)

    // Bound the payload BEFORE it is cached or serialised: the response object,
    // the cached copy and the JSON string are all live at once, so an unbounded
    // graph is held three times over.
    const { nodes, links, info } = truncateGraph(full.nodes, full.links)
    if (info.truncated) {
      console.warn(
        `[Graph] project=${projectId} truncated to ${info.returnedNodes}/${info.totalNodes} nodes ` +
        `(${info.returnedLinks}/${info.totalLinks} links); raise GRAPH_MAX_NODES to change`,
      )
    }

    // Cache the result and get ETag
    const etag = setCached(projectId, { nodes, links }, info)

    // Check if client already has this version
    if (ifNoneMatch && ifNoneMatch === `"${etag}"`) {
      if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] 304 Not Modified -- fresh data matches client ETag for ${projectId}`)
      return new NextResponse(null, {
        status: 304,
        headers: {
          'ETag': `"${etag}"`,
          'Cache-Control': 'private, no-cache',
        },
      })
    }

    const responseData = JSON.stringify({ nodes, links, projectId, ...(info.truncated ? { truncated: info } : {}) })
    if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] Response size: ${(responseData.length / 1024).toFixed(1)}KB`)

    return new NextResponse(responseData, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'ETag': `"${etag}"`,
        'Cache-Control': 'private, no-cache',
      },
    })
  } catch (error) {
    console.error('Graph query error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  }
}

export async function DELETE(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const nodeId = searchParams.get('nodeId')
  const projectId = searchParams.get('projectId')

  if (!nodeId || !projectId) {
    return NextResponse.json(
      { error: 'nodeId and projectId are required' },
      { status: 400 }
    )
  }

  // Only the project's effective owner may delete its graph nodes.
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, projectId)
  if (access instanceof NextResponse) return access

  const session = getGraphSession()

  try {
    // Delete any node except Domain and Subdomain (protected)
    const result = await session.run(
      `
      MATCH (n)
      WHERE id(n) = toInteger($nodeId)
        AND n.project_id = $projectId
        AND NOT (n:Domain OR n:Subdomain)
      DETACH DELETE n
      RETURN count(n) as deleted
      `,
      { nodeId, projectId }
    )

    const deleted = result.records[0]?.get('deleted')?.low ?? 0

    if (deleted === 0) {
      return NextResponse.json(
        { error: 'Node not found or not deletable' },
        { status: 404 }
      )
    }

    // Invalidate cache after deletion
    invalidateCache(projectId)

    return NextResponse.json({ success: true, deleted })
  } catch (error) {
    console.error('Graph delete error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Delete failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}

// getNodeName and serializeProperties are now in ./format.ts
