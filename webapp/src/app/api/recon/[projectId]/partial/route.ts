import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { getEffectiveUser } from '@/lib/session'
import { recordScanStart } from '@/lib/scanTimeline'
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { assertGraphNotActivating } from '@/lib/activationLock'
import { normalizeOrchestratorStartError } from '@/lib/orchestratorError'

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

    // Scan Timeline 4A.3: a partial recon writes the live graph, so it must not
    // start while a version activation is swapping it.
    const activating = await assertGraphNotActivating(projectId)
    if (activating) return activating

    const body = await request.json()

    // Verify project exists
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true, userId: true, targetDomain: true }
    })

    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    // Forward to orchestrator
    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: projectId,
        user_id: project.userId,
        webapp_api_url: WEBAPP_URL,
        tool_id: body.tool_id,
        graph_inputs: body.graph_inputs,
        user_inputs: body.user_inputs || [],
        user_targets: body.user_targets || null,
        include_graph_targets: body.include_graph_targets ?? true,
        settings_overrides: body.settings_overrides || {},
      }),
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      // Governor rejections carry a structured object detail; normalize to a
      // string message (+ limit) so it is never rendered as a raw React child.
      const { error, limit } = normalizeOrchestratorStartError(errorData, 'Failed to start partial recon')
      return NextResponse.json(
        { error, ...(limit ? { limit } : {}) },
        { status: response.status }
      )
    }

    const data = await response.json()
    // Run-keyed: several partial recons can be in flight for one project, so the
    // history row carries the orchestrator run id that identifies this one.
    // The scan is already running: recording who started it must never be able
    // to turn a successful start into an error response.
    const __eff = await getEffectiveUser().catch(() => null)
    await recordScanStart({
      projectId,
      kind: 'partial_recon',
      runId: typeof data?.run_id === 'string' ? data.run_id : '',
      initiatedByUserId: __eff?.userId ?? null,
    })
    return NextResponse.json(data)

  } catch (error) {
    console.error('Error starting partial recon:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
