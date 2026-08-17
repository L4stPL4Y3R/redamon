import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { reconcileScanJobStatus } from '@/lib/scanTimeline'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; source: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, source } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    const response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/${encodeURIComponent(source)}/status`,
      { method: 'GET', headers: { 'Content-Type': 'application/json' } },
    )

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      return NextResponse.json(
        { error: errorData.detail || 'Failed to get TruffleHog status' },
        { status: response.status },
      )
    }

    const data = await response.json()
    // The orchestrator owns liveness; this only mirrors a TERMINAL state onto
    // the history row. runId is the source, or this would close another
    // source's row instead of its own.
    await reconcileScanJobStatus(projectId, data?.status, { kind: 'trufflehog', runId: source })
    return NextResponse.json(data)
  } catch (error) {
    console.error('Error getting TruffleHog status:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
