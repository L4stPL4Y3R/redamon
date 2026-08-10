/**
 * Scan Timeline - retention / GC (Section 5).
 *
 * Snapshots are copies of the graph, so an unbounded timeline grows Postgres
 * without limit. Policy: keep the newest N UNPINNED past versions per project;
 * older unpinned ones are deleted (row + bytes). Pinned versions and the current
 * version are never touched - pinning is the user's explicit "keep this".
 *
 * Also prunes old FAILED ScanJob rows, which are pure noise in the run history.
 *
 * Runs opportunistically after a new version is created; never fatal.
 */
import prisma from '@/lib/prisma'

/** 0 (or a negative/invalid value) disables version GC entirely. */
export function retentionKeep(): number {
  const raw = parseInt(process.env.SCAN_VERSION_RETENTION_KEEP || '', 10)
  return Number.isFinite(raw) && raw >= 0 ? raw : 20
}

export function failedJobRetentionDays(): number {
  const raw = parseInt(process.env.SCAN_JOB_FAILED_RETENTION_DAYS || '', 10)
  return Number.isFinite(raw) && raw >= 0 ? raw : 30
}

export interface RetentionResult {
  deletedVersionIds: string[]
  deletedFailedJobs: number
}

export async function applyRetention(projectId: string): Promise<RetentionResult> {
  const result: RetentionResult = { deletedVersionIds: [], deletedFailedJobs: 0 }

  const keep = retentionKeep()
  if (keep > 0) {
    // Candidates: past (non-current), unpinned versions, newest first.
    const candidates = await prisma.scanVersion.findMany({
      where: { projectId, isCurrent: false, pinned: false },
      orderBy: { seq: 'desc' },
      select: { id: true, seq: true },
    })
    const doomed = candidates.slice(keep)
    if (doomed.length > 0) {
      let ids = doomed.map(d => d.id)
      // C-3: never delete a version a NON-TERMINAL ScanJob still points to. That
      // FK is onDelete: Cascade, so deleting the version would silently take the
      // job row (a queued/running scan) with it. A queued job waiting through 20
      // rotations would otherwise vanish.
      const protectedJobs = await prisma.scanJob.findMany({
        where: { versionId: { in: ids }, status: { in: ['queued', 'running'] } },
        select: { versionId: true },
      })
      const protectedIds = new Set(protectedJobs.map(j => j.versionId).filter((v): v is string => !!v))
      if (protectedIds.size > 0) ids = ids.filter(id => !protectedIds.has(id))
      if (ids.length > 0) {
        await prisma.scanVersion.deleteMany({ where: { id: { in: ids } } })
        result.deletedVersionIds = ids
        console.info(
          `[scanTimeline] retention removed ${ids.length} old unpinned version(s) for project ${projectId} ` +
          `(keep=${keep}${protectedIds.size ? `, skipped ${protectedIds.size} referenced by a live job` : ''})`
        )
      }
    }
  }

  const days = failedJobRetentionDays()
  if (days > 0) {
    const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000)
    const gc = await prisma.scanJob.deleteMany({
      where: { projectId, status: 'failed', createdAt: { lt: cutoff } },
    })
    result.deletedFailedJobs = gc.count
  }

  return result
}

/** Fire-and-forget wrapper: retention must never break the request that triggered it. */
export async function applyRetentionSafe(projectId: string): Promise<RetentionResult | null> {
  try {
    return await applyRetention(projectId)
  } catch (err) {
    console.error('[scanTimeline] retention failed (continuing):', err)
    return null
  }
}
