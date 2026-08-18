import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; source: string }>
}

/** Stops ONE source's run; the project's other sources keep going. */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, source } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    const response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/${encodeURIComponent(source)}/stop`,
      { method: 'POST' },
    )

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      return NextResponse.json(
        { error: errorData.detail || 'Failed to stop Secret Multiscanner scan' },
        { status: response.status },
      )
    }

    return NextResponse.json(await response.json())
  } catch (error) {
    console.error('Error stopping TruffleHog scan:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
