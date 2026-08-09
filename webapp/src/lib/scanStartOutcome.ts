/**
 * Classify a failed scan-start response body + HTTP status into "temporary"
 * (the work could succeed later, so it is queueable) vs "permanent" (a config or
 * request error that queueing cannot fix). Scan Queue plan Phase 1.
 *
 * Temporary:
 *   - a RAM admission limit   (body.limit.limitType === 'ram')
 *   - a hard admission limit  (body.limit.limitType === 'hard')  -- frees when
 *     other scans finish, so retrying later is the right move
 *   - an activation in progress (body.activationInProgress)
 *   - ANY 409. "Already active for project X" refusals arrive as plain strings
 *     with no limit object, so the status is the only reliable signal.
 *
 * Permanent: everything else, notably 400 (bad config), 404 (missing project),
 * 500 (server error). Nothing about queueing changes those.
 *
 * Pure: no I/O, no globals. Given (status, body) it always returns the same value.
 */

export type StartFailureKind = 'temporary' | 'permanent'

/** Mirrors JobQueue.blockedCode so a queued row can record why it is waiting. */
export type StartBlockedCode =
  | ''
  | 'ram'
  | 'hard'
  | 'activating'
  | 'busy'

export interface StartFailureBody {
  error?: string
  limit?: { limitType?: 'ram' | 'hard' | string } | null
  activationInProgress?: boolean
  snapshotFailed?: boolean
  busy?: string
}

export interface StartFailureClassification {
  kind: StartFailureKind
  /** True when queueing is a sensible offer. */
  temporary: boolean
  /** The JobQueue.blockedCode to seed a queued row with (empty for permanent). */
  blockedCode: StartBlockedCode
  /** A short human reason, safe to render (always a string). */
  reason: string
}

export function classifyStartFailure(
  status: number | undefined,
  body: StartFailureBody | null | undefined,
): StartFailureClassification {
  const b = body ?? {}
  const limitType = b.limit?.limitType

  if (limitType === 'ram') {
    return {
      kind: 'temporary',
      temporary: true,
      blockedCode: 'ram',
      reason: b.error || 'Not enough memory to start this scan now.',
    }
  }
  if (limitType === 'hard') {
    return {
      kind: 'temporary',
      temporary: true,
      blockedCode: 'hard',
      reason: b.error || 'A configured concurrency limit is currently reached.',
    }
  }
  if (b.activationInProgress) {
    return {
      kind: 'temporary',
      temporary: true,
      blockedCode: 'activating',
      reason: b.error || 'A version activation is in progress for this project.',
    }
  }
  if (status === 409) {
    return {
      kind: 'temporary',
      temporary: true,
      blockedCode: 'busy',
      reason: b.error || b.busy || 'The project is busy with another scan right now.',
    }
  }

  return {
    kind: 'permanent',
    temporary: false,
    blockedCode: '',
    reason: b.error || 'The scan could not be started.',
  }
}
