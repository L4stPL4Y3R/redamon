import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { normalizeOrchestratorStartError } from '@/lib/orchestratorError'
import { assertGraphNotActivating } from '@/lib/activationLock'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    // A supply-chain scan writes Package/MalPackageFinding nodes into the live
    // graph, so it must not start into an in-flight version swap.
    const __activating = await assertGraphNotActivating(projectId)
    if (__activating) return __activating

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true, userId: true, supplyChainSbomFile: true },
    })
    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }
    if (!project.supplyChainSbomFile) {
      return NextResponse.json(
        { error: 'No SBOM/lockfile uploaded. Upload one in Other Scans -> Supply Chain first.' },
        { status: 400 }
      )
    }

    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/supply-chain/${projectId}/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: projectId,
        user_id: project.userId,
        webapp_api_url: WEBAPP_URL,
      }),
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      const { error, limit } = normalizeOrchestratorStartError(errorData, 'Failed to start Supply-Chain scan')
      return NextResponse.json({ error, ...(limit ? { limit } : {}) }, { status: response.status })
    }

    return NextResponse.json(await response.json())
  } catch (error) {
    console.error('Error starting Supply-Chain scan:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
