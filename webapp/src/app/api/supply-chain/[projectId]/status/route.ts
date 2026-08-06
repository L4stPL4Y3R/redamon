import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams { params: Promise<{ projectId: string }> }

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/supply-chain/${projectId}/status`, {
      method: 'GET', headers: { 'Content-Type': 'application/json' },
    })
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      return NextResponse.json({ error: errorData.detail || 'Failed to get Supply-Chain status' }, { status: response.status })
    }
    return NextResponse.json(await response.json())
  } catch (error) {
    if (error instanceof TypeError && error.message.includes('fetch')) {
      return NextResponse.json({
        project_id: (await params).projectId, status: 'idle', current_phase: null,
        phase_number: null, total_phases: 1, started_at: null, completed_at: null, error: null,
      })
    }
    return NextResponse.json({ error: error instanceof Error ? error.message : 'Internal server error' }, { status: 500 })
  }
}
