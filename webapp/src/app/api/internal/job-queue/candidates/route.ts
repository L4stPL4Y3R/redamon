/**
 * Scan Queue - the dispatcher's non-reserving peek (plan Phase 2, R1).
 *
 * Returns ready queued rows in dispatch order (priority desc, then oldest first)
 * plus the current count of in-flight rows, so the orchestrator dispatcher can
 * apply its own ceiling (JOB_QUEUE_MAX_CONCURRENT) and head-of-line reserve
 * against the ledger. This route RESERVES NOTHING: try_admit remains the only
 * thing that reserves, at dispatch. Internal-key only.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'

export const runtime = 'nodejs'

const CANDIDATE_LIMIT = 50

export async function GET(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  try {
    const now = new Date()

    // Projects that already have an in-flight job (one-per-project, C-12). Their
    // queued jobs CANNOT run this pass, so exclude them from candidates entirely
    // (Finding 2): otherwise a big, per-project-blocked job at the head of the
    // queue would trigger the dispatcher's head-of-line RAM `break` and starve
    // other tenants' fittable jobs. The in-flight rows also give the concurrency
    // count in one query.
    const inflight = await prisma.jobQueue.findMany({
      where: { status: { in: ['dispatching', 'running'] } },
      select: { projectId: true },
    })
    const activeCount = inflight.length
    const busyProjectIds = Array.from(new Set(inflight.map(r => r.projectId)))

    const rows = await prisma.jobQueue.findMany({
      where: {
        status: 'queued',
        OR: [{ notBefore: null }, { notBefore: { lte: now } }],
        ...(busyProjectIds.length ? { projectId: { notIn: busyProjectIds } } : {}),
      },
      orderBy: [{ priority: 'desc' }, { enqueuedAt: 'asc' }],
      take: CANDIDATE_LIMIT,
      select: {
        id: true,
        projectId: true,
        userId: true,
        kind: true,
        envelopeBytes: true,
        priority: true,
        enqueuedAt: true,
        attempts: true,
        maxAttempts: true,
      },
    })

    const candidates = rows.map(r => ({
      id: r.id,
      projectId: r.projectId,
      userId: r.userId,
      kind: r.kind,
      // BigInt -> Number: envelopes are well under 2^53, and JSON cannot carry BigInt.
      envelopeBytes: Number(r.envelopeBytes),
      priority: r.priority,
      enqueuedAt: r.enqueuedAt.toISOString(),
      attempts: r.attempts,
      maxAttempts: r.maxAttempts,
    }))

    return NextResponse.json({ candidates, activeCount })
  } catch (error) {
    console.error('[jobQueue] candidates failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
