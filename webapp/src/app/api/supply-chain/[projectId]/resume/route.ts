import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams { params: Promise<{ projectId: string }> }

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/supply-chain/${projectId}/resume`, { method: 'POST' })
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      return NextResponse.json({ error: errorData.detail || 'Failed to resume Supply-Chain scan' }, { status: response.status })
    }
    return NextResponse.json(await response.json())
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : 'Internal server error' }, { status: 500 })
  }
}
