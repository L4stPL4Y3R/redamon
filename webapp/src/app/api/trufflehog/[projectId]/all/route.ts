import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'
import { reconcileRunScanJobs } from '@/lib/scanTimeline'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

/**
 * Every TruffleHog run for a project, one row per source.
 *
 * The queue reconcile, the version-save guard and the graph activation guard all
 * read this instead of a project-level status. With N sources running in
 * parallel a single status can only describe one of them, so the other N-1 look
 * idle to every caller — which is how a version snapshot gets taken while a scan
 * is still writing findings.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    const response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/all`,
      { method: 'GET', headers: { 'Content-Type': 'application/json' } },
    )

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      return NextResponse.json(
        { error: errorData.detail || 'Failed to list Secret Multiscanner runs' },
        { status: response.status },
      )
    }

    const data = await response.json()
    // Run-granular: closing "the project's open job" would end only the newest
    // of N parallel rows and leave the rest stuck at `running` forever.
    await reconcileRunScanJobs(projectId, 'trufflehog', data?.runs)
    return NextResponse.json(data)
  } catch (error) {
    console.error('Error listing TruffleHog runs:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
