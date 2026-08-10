/**
 * Scan Queue - close out finished 'running' jobs (plan Phase 2, C-6). Internal-key
 * only. The orchestrator reaper posts the set of projectIds that currently have a
 * live scan container, so a job that finished with every browser tab closed is
 * still marked terminal (job completion must never depend on a browser being open).
 *
 * Fail-safe: a row is only closed when its project is NOT in the active set AND it
 * has been running past a short grace window, so a container that has not yet
 * appeared in the live set right after dispatch is never closed prematurely.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'

export const runtime = 'nodejs'

// A just-dispatched container may take a beat to appear in the orchestrator's live
// run set; do not close a running row younger than this.
const RECONCILE_GRACE_MS = 90_000

export async function POST(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  try {
    const body = await request.json().catch(() => ({}))
    const activeProjects: string[] = Array.isArray(body?.activeProjects)
      ? body.activeProjects.filter((p: unknown): p is string => typeof p === 'string')
      : []
    const activeSet = new Set(activeProjects)

    const cutoff = new Date(Date.now() - RECONCILE_GRACE_MS)
    const running = await prisma.jobQueue.findMany({
      where: { status: 'running' },
      select: { id: true, projectId: true, startedAt: true },
    })

    const toClose = running.filter(
      r => !activeSet.has(r.projectId) && (r.startedAt == null || r.startedAt <= cutoff),
    )

    let closed = 0
    for (const r of toClose) {
      // The ScanJob history row (linked via scanJobId) carries the real
      // completed/failed outcome; the queue row only needs to leave 'running'.
      await prisma.jobQueue
        .updateMany({
          where: { id: r.id, status: 'running' },
          data: { status: 'done', finishedAt: new Date() },
        })
        .then(res => { closed += res.count })
        .catch(() => {})
    }

    return NextResponse.json({ ok: true, closed, running: running.length })
  } catch (error) {
    console.error('[jobQueue] reconcile failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
