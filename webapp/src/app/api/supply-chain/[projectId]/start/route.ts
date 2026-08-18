import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { getEffectiveUser } from '@/lib/session'
import { recordScanStart } from '@/lib/scanTimeline'
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
      select: {
        id: true, userId: true, supplyChainSbomFile: true,
        supplyChainInputMode: true, supplyChainRepoUrl: true,
      },
    })
    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    // Gate on the source the operator actually selected. Checking only the
    // uploaded file would refuse to start a perfectly valid GitHub scan, and
    // checking neither would start a scan with no input at all.
    if (project.supplyChainInputMode === 'org') {
      // Not an input this scan can read: the org mode queues one scan per repo
      // (supply_chain_repo) instead of running the project's single scan.
      return NextResponse.json(
        { error: 'This project scans a GitHub organization. Use "Queue org batch" in Other Scans, '
          + 'or set an SBOM/repository input in project settings.' },
        { status: 400 }
      )
    } else if (project.supplyChainInputMode === 'github') {
      if (!project.supplyChainRepoUrl) {
        return NextResponse.json(
          { error: 'No repository set. Add a GitHub repository under Project Settings -> Other Scans -> Supply Chain Scanner first.' },
          { status: 400 }
        )
      }
    } else if (!project.supplyChainSbomFile) {
      return NextResponse.json(
        { error: 'No SBOM/lockfile uploaded. Upload one under Project Settings -> Other Scans -> Supply Chain Scanner first.' },
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

    // The scan is live now: give it a history row. Only full recon used to get
    // one, so every other kind vanished from Run history the moment it ended.
    // The scan is already running: recording who started it must never be able
    // to turn a successful start into an error response.
    const __eff = await getEffectiveUser().catch(() => null)
    await recordScanStart({ projectId, kind: 'supply_chain', initiatedByUserId: __eff?.userId ?? null })

    return NextResponse.json(await response.json())
  } catch (error) {
    console.error('Error starting Supply-Chain scan:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
