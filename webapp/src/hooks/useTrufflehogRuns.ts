'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { ScanStartError } from '@/lib/scanStartError'
import type { TrufflehogState, TrufflehogStatus } from '@/lib/recon-types'

/**
 * Every TruffleHog run for a project, plus the profiles that define them.
 *
 * Replaces the project-level `useTrufflehogStatus`: runs are keyed by SOURCE and
 * several execute in parallel, so a single status can only ever describe one of
 * them and the rest would render as idle while their containers are up.
 *
 * Mirrors `useMultiPartialReconStatus`, which solved the same shape for
 * partial recon.
 */

export interface TrufflehogProfileSummary {
  id: string
  source: string
  label: string
  config: Record<string, unknown>
  validationErrors?: string[]
  missingCredentials?: { settingsKey: string; label: string }[]
}

interface UseTrufflehogRunsOptions {
  projectId: string | null
  enabled?: boolean
  pollingInterval?: number
  onRunComplete?: (source: string) => void
  onRunError?: (source: string, error: string) => void
}

interface UseTrufflehogRunsReturn {
  runs: TrufflehogState[]
  profiles: TrufflehogProfileSummary[]
  /** Run state by source, for rendering one row per profile. */
  bySource: Record<string, TrufflehogState | undefined>
  activeRuns: TrufflehogState[]
  isAnyRunning: boolean
  isLoading: boolean
  error: string | null
  startTrufflehog: (source: string) => Promise<TrufflehogState | null>
  stopTrufflehog: (source: string) => Promise<TrufflehogState | null>
  refetch: () => Promise<void>
  refetchProfiles: () => Promise<void>
  getLastStartError: () => ScanStartError | null
}

const DEFAULT_POLLING_INTERVAL = 5000
const IDLE_POLLING_INTERVAL = 30000

const ACTIVE: TrufflehogStatus[] = ['running', 'starting', 'stopping']

export function useTrufflehogRuns({
  projectId,
  enabled = true,
  pollingInterval = DEFAULT_POLLING_INTERVAL,
  onRunComplete,
  onRunError,
}: UseTrufflehogRunsOptions): UseTrufflehogRunsReturn {
  const [runs, setRuns] = useState<TrufflehogState[]>([])
  const [profiles, setProfiles] = useState<TrufflehogProfileSummary[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const pollingRef = useRef<NodeJS.Timeout | null>(null)
  const lastStartErrorRef = useRef<ScanStartError | null>(null)
  const previousStatusesRef = useRef<Record<string, TrufflehogStatus>>({})
  const onRunCompleteRef = useRef(onRunComplete)
  const onRunErrorRef = useRef(onRunError)

  useEffect(() => {
    onRunCompleteRef.current = onRunComplete
    onRunErrorRef.current = onRunError
  }, [onRunComplete, onRunError])

  const fetchRuns = useCallback(async () => {
    if (!projectId) return
    try {
      const response = await fetch(`/api/trufflehog/${projectId}/all`)
      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data.error || 'Failed to fetch Secret Multiscanner runs')
      }
      const data = await response.json()
      const next: TrufflehogState[] = Array.isArray(data?.runs) ? data.runs : []
      setRuns(next)
      setError(null)

      for (const run of next) {
        const key = run.source || run.run_id || ''
        if (!key) continue
        if (previousStatusesRef.current[key] !== run.status) {
          previousStatusesRef.current[key] = run.status
          if (run.status === 'completed') onRunCompleteRef.current?.(key)
          if (run.status === 'error') onRunErrorRef.current?.(key, run.error || 'Scan failed')
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    }
  }, [projectId])

  const fetchProfiles = useCallback(async () => {
    if (!projectId) return
    try {
      const response = await fetch(`/api/trufflehog/${projectId}/profiles`)
      if (!response.ok) return
      const data = await response.json()
      setProfiles(Array.isArray(data?.profiles) ? data.profiles : [])
    } catch {
      // A failed profile list must not blank the runs already on screen.
    }
  }, [projectId])

  const startTrufflehog = useCallback(async (source: string): Promise<TrufflehogState | null> => {
    if (!projectId) return null
    setIsLoading(true)
    lastStartErrorRef.current = null
    try {
      const response = await fetch(`/api/trufflehog/${projectId}/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source }),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) {
        // Carries the governor's structured limit payload so the caller can
        // offer the queue instead of just showing an error.
        const message = data?.error || 'Failed to start Secret Multiscanner scan'
        lastStartErrorRef.current = { status: response.status, message, limit: data?.limit }
        throw new Error(message)
      }
      await fetchRuns()
      return data as TrufflehogState
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
      return null
    } finally {
      setIsLoading(false)
    }
  }, [projectId, fetchRuns])

  const stopTrufflehog = useCallback(async (source: string): Promise<TrufflehogState | null> => {
    if (!projectId) return null
    try {
      const response = await fetch(
        `/api/trufflehog/${projectId}/${encodeURIComponent(source)}/stop`, { method: 'POST' },
      )
      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data.error || 'Failed to stop Secret Multiscanner scan')
      }
      const data = await response.json()
      await fetchRuns()
      return data as TrufflehogState
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
      return null
    }
  }, [projectId, fetchRuns])

  const activeRuns = runs.filter(r => ACTIVE.includes(r.status))
  const isAnyRunning = activeRuns.length > 0

  useEffect(() => {
    if (!projectId || !enabled) return
    void fetchRuns()
    void fetchProfiles()
  }, [projectId, enabled, fetchRuns, fetchProfiles])

  useEffect(() => {
    if (!projectId || !enabled) return
    // Poll fast only while something is live; an idle project is checked rarely
    // so a page left open does not hammer the orchestrator.
    const interval = isAnyRunning ? pollingInterval : IDLE_POLLING_INTERVAL
    pollingRef.current = setInterval(() => { void fetchRuns() }, interval)
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
      pollingRef.current = null
    }
  }, [projectId, enabled, isAnyRunning, pollingInterval, fetchRuns])

  const bySource: Record<string, TrufflehogState | undefined> = {}
  for (const run of runs) {
    if (run.source) bySource[run.source] = run
  }

  return {
    runs,
    profiles,
    bySource,
    activeRuns,
    isAnyRunning,
    isLoading,
    error,
    startTrufflehog,
    stopTrufflehog,
    refetch: fetchRuns,
    refetchProfiles: fetchProfiles,
    getLastStartError: () => lastStartErrorRef.current,
  }
}
