import { NextRequest } from 'next/server'
import { guardProject } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; source: string }>
}

/** Proxies one source's SSE log stream. The orchestrator redacts credentials
 *  before the lines leave it, so this is a plain pass-through. */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { projectId, source } = await params
  const __denied = await guardProject(projectId)
  if (__denied) return __denied

  const response = await orchestratorFetch(
    `${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/${encodeURIComponent(source)}/logs`,
    { headers: { Accept: 'text/event-stream' }, signal: request.signal },
  )

  if (!response.ok) {
    return new Response(
      JSON.stringify({ error: 'Failed to connect to TruffleHog log stream' }),
      { status: response.status, headers: { 'Content-Type': 'application/json' } },
    )
  }

  return new Response(response.body, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
    },
  })
}
