import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { getEffectiveUser } from '@/lib/session'
import { parseScanMode, type ScanMode } from '@/lib/scanTimeline'
import { startFullScan } from '@/lib/startFullScan'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    // Scan Timeline: `mode` decides what happens to the graph this scan is about
    // to destroy. Default 'new' (keep the current graph as a saved version) is the
    // safe choice, so a client that does not send a mode never silently discards.
    let mode: ScanMode = 'new'
    const body = await request.json().catch(() => null)
    if (body && typeof body === 'object' && 'mode' in body) {
      const parsed = parseScanMode((body as { mode?: unknown }).mode)
      if (!parsed) {
        return NextResponse.json(
          { error: "Invalid mode: expected 'new' or 'overwrite'" },
          { status: 400 }
        )
      }
      mode = parsed
    }

    const eff = await getEffectiveUser()

    // Same path a scheduled scan takes (lib/startFullScan.ts): activation lock,
    // freeze-before-start, orchestrator start (RoE + admission), ScanJob history.
    const result = await startFullScan({
      projectId,
      mode,
      trigger: 'manual',
      actorUserId: eff?.userId ?? null,
    })

    if (!result.ok) {
      return NextResponse.json(
        {
          error: result.error,
          ...(result.limit ? { limit: result.limit } : {}),
          ...(result.snapshotFailed ? { snapshotFailed: true } : {}),
          ...(result.activationInProgress ? { activationInProgress: true } : {}),
          ...(result.busy ? { busy: result.busy } : {}),
        },
        { status: result.status }
      )
    }

    return NextResponse.json({
      ...result.state,
      scanVersion: {
        id: result.versionId,
        seq: result.versionSeq,
        label: result.versionLabel,
      },
      frozenVersionId: result.frozenVersionId,
      frozenNodeCount: result.frozenNodeCount,
      mode,
    })

  } catch (error) {
    console.error('Error starting recon:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
