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
    const rows = await prisma.jobQueue.findMany({
      where: {
        status: 'queued',
        OR: [{ notBefore: null }, { notBefore: { lte: now } }],
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

    // In-flight rows count against the dispatcher's hard concurrency ceiling.
    const activeCount = await prisma.jobQueue.count({
      where: { status: { in: ['dispatching', 'running'] } },
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
