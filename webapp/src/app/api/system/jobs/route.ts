/**
 * Scan Queue - the Activity view data (plan Phase 5). The canonical surface for
 * queue state. Tenancy: the caller sees THEIR OWN rows in full, and everyone
 * else's in-flight work only as an anonymised aggregate count. Also returns the
 * orchestrator ledger snapshot so the UI can show why the queue is waiting.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'

export const runtime = 'nodejs'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const RECENT_LIMIT = 20

type Row = {
  id: string
  projectId: string
  kind: string
  status: string
  priority: number
  attempts: number
  blockedCode: string
  blockedReason: string
  error: string
  envelopeBytes: bigint
  enqueuedAt: Date
  startedAt: Date | null
  finishedAt: Date | null
}

function serialize(r: Row) {
  return {
    id: r.id,
    projectId: r.projectId,
    kind: r.kind,
    status: r.status,
    priority: r.priority,
    attempts: r.attempts,
    blockedCode: r.blockedCode,
    blockedReason: r.blockedReason,
    error: r.error,
    envelopeBytes: Number(r.envelopeBytes),
    enqueuedAt: r.enqueuedAt.toISOString(),
    startedAt: r.startedAt ? r.startedAt.toISOString() : null,
    finishedAt: r.finishedAt ? r.finishedAt.toISOString() : null,
  }
}

const SELECT = {
  id: true, projectId: true, kind: true, status: true, priority: true, attempts: true,
  blockedCode: true, blockedReason: true, error: true, envelopeBytes: true,
  enqueuedAt: true, startedAt: true, finishedAt: true,
} as const

export async function GET(_request: NextRequest) {
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff

  try {
    const [mine, recent, othersActive, othersNeedsReview] = await Promise.all([
      prisma.jobQueue.findMany({
        where: { userId: eff.userId, status: { in: ['running', 'dispatching', 'queued', 'needs_review'] } },
        orderBy: [{ priority: 'desc' }, { enqueuedAt: 'asc' }],
        select: SELECT,
      }),
      prisma.jobQueue.findMany({
        where: { userId: eff.userId, status: { in: ['done', 'failed', 'canceled'] } },
        orderBy: { finishedAt: 'desc' },
        take: RECENT_LIMIT,
        select: SELECT,
      }),
      prisma.jobQueue.groupBy({
        by: ['status'],
        where: { userId: { not: eff.userId }, status: { in: ['running', 'dispatching', 'queued'] } },
        _count: { _all: true },
      }),
      prisma.jobQueue.count({
        where: { userId: { not: eff.userId }, status: 'needs_review' },
      }),
    ])

    const running = mine.filter(r => r.status === 'running' || r.status === 'dispatching').map(serialize)
    const queued = mine.filter(r => r.status === 'queued').map(serialize)
    const needsReview = mine.filter(r => r.status === 'needs_review').map(serialize)

    const othersAgg = { queued: 0, running: 0, needsReview: othersNeedsReview }
    for (const g of othersActive) {
      const n = g._count._all
      if (g.status === 'queued') othersAgg.queued += n
      else othersAgg.running += n // running + dispatching
    }

    // Best-effort ledger snapshot from the orchestrator (drives the "waiting for
    // memory/capacity" hint). Never fails the request.
    let ledger: unknown = null
    try {
      const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/system/stats`, { method: 'GET' })
      if (res.ok) ledger = await res.json()
    } catch {
      /* orchestrator unreachable: the queue view still renders */
    }

    return NextResponse.json({
      mine: { running, queued, needsReview, recent: recent.map(serialize) },
      others: othersAgg,
      ledger,
    })
  } catch (error) {
    console.error('[jobQueue] system/jobs failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
