import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { reconcileRunScanJobs } from '@/lib/scanTimeline'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

// GET /api/ai-attack-surface/{projectId}/all - list all runs for a project.
export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params
  const __denied = await guardProject(projectId)
  if (__denied) return __denied
  try {
    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/ai-attack-surface/${projectId}/all`, {
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    })
    if (!response.ok) {
      return NextResponse.json({ project_id: projectId, runs: [] })
    }
    const data = await response.json()
    await reconcileRunScanJobs(projectId, 'ai_attack', data?.runs)
    return NextResponse.json(data)
  } catch {
    // Orchestrator unreachable - degrade to empty list.
    return NextResponse.json({ project_id: projectId, runs: [] })
  }
}
