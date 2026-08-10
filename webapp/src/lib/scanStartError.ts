/**
 * Shared shape of a failed scan-start attempt, readable synchronously right after
 * a start* call resolves (via each status hook's getLastStartError()).
 *
 * `status` is the HTTP status of the rejected start. It is the ONLY reliable
 * temporary-vs-permanent signal: a memory-governor refusal without a structured
 * `limit` object still arrives as a 409, and an "already active for project X"
 * refusal is a plain string with no limit at all. All seven start hooks used to
 * drop it (see Scan Queue plan Phase 0.2); they now keep it.
 */
export interface ScanStartLimit {
  limitType?: 'hard' | 'ram'
  settingName?: string | null
  detail?: string
  current?: number
  ceiling?: number
}

export interface ScanStartError {
  message: string
  limit?: ScanStartLimit
  status?: number
}
