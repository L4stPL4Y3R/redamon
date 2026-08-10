'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { ScanStartError } from '@/lib/scanStartError'
import type { TrufflehogState, TrufflehogStatus } from '@/lib/recon-types'

interface UseTrufflehogStatusOptions {
  projectId: string | null
  enabled?: boolean
  pollingInterval?: number
  onStatusChange?: (status: TrufflehogStatus) => void
  onComplete?: () => void
  onError?: (error: string) => void
}

interface UseTrufflehogStatusReturn {
  state: TrufflehogState | null
  isLoading: boolean
  error: string | null
  refetch: () => Promise<void>
  startTrufflehog: () => Promise<TrufflehogState | null>
  stopTrufflehog: () => Promise<TrufflehogState | null>
  pauseTrufflehog: () => Promise<TrufflehogState | null>
  resumeTrufflehog: () => Promise<TrufflehogState | null>
  getLastStartError: () => ScanStartError | null
}

const DEFAULT_POLLING_INTERVAL = 5000
const IDLE_POLLING_INTERVAL = 30000

export function useTrufflehogStatus({
  projectId,
  enabled = true,
  pollingInterval = DEFAULT_POLLING_INTERVAL,
  onStatusChange,
  onComplete,
  onError,
}: UseTrufflehogStatusOptions): UseTrufflehogStatusReturn {
  const [state, setState] = useState<TrufflehogState | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const previousStatusRef = useRef<TrufflehogStatus | null>(null)
  const pollingRef = useRef<NodeJS.Timeout | null>(null)
  // A pause/stop request is in flight. Docker's freeze can take several seconds,
  // so hold the optimistic status ('pausing' / 'stopping') and skip polling until
  // the request resolves -- a poll landing mid-freeze would revert the button.
  const transitionRef = useRef(false)
  const lastStartErrorRef = useRef<ScanStartError | null>(null)

  const onStatusChangeRef = useRef(onStatusChange)
  const onCompleteRef = useRef(onComplete)
  const onErrorRef = useRef(onError)

  useEffect(() => {
    onStatusChangeRef.current = onStatusChange
    onCompleteRef.current = onComplete
    onErrorRef.current = onError
  }, [onStatusChange, onComplete, onError])

  const fetchStatus = useCallback(async () => {
    if (!projectId) return
    if (transitionRef.current) return

    try {
      const response = await fetch(`/api/trufflehog/${projectId}/status`)
      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to fetch trufflehog status')
      }

      const data: TrufflehogState = await response.json()
      setState(data)
      setError(null)

      if (previousStatusRef.current !== data.status) {
        onStatusChangeRef.current?.(data.status)

        if (data.status === 'completed') {
          onCompleteRef.current?.()
        } else if (data.status === 'error' && data.error) {
          onErrorRef.current?.(data.error)
        }

        previousStatusRef.current = data.status
      }

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
    }
  }, [projectId])

  const startTrufflehog = useCallback(async (): Promise<TrufflehogState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setError(null)
    lastStartErrorRef.current = null

    try {
      const response = await fetch(`/api/trufflehog/${projectId}/start`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        lastStartErrorRef.current = { message: data.error || 'Failed to start TruffleHog scan', limit: data.limit, status: response.status }
        throw new Error(data.error || 'Failed to start TruffleHog scan')
      }

      const data: TrufflehogState = await response.json()
      setState(data)
      previousStatusRef.current = data.status
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      if (!lastStartErrorRef.current) lastStartErrorRef.current = { message: errorMessage }
      setError(errorMessage)
      onErrorRef.current?.(errorMessage)
      // Re-throw so the caller's catch fires (Scan Queue Phase 0.3): this hook
      // used to swallow the failure and return null, so the user saw nothing.
      throw err instanceof Error ? err : new Error(errorMessage)

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const getLastStartError = useCallback(() => lastStartErrorRef.current, [])

  const stopTrufflehog = useCallback(async (): Promise<TrufflehogState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    transitionRef.current = true
    setState(prev => prev ? { ...prev, status: 'stopping' as TrufflehogState['status'] } : prev)

    try {
      const response = await fetch(`/api/trufflehog/${projectId}/stop`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to stop TruffleHog scan')
      }

      const data: TrufflehogState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      return null

    } finally {
      transitionRef.current = false
      setIsLoading(false)
    }
  }, [projectId])

  const pauseTrufflehog = useCallback(async (): Promise<TrufflehogState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    transitionRef.current = true
    setState(prev => prev ? { ...prev, status: 'pausing' as TrufflehogState['status'] } : prev)

    try {
      const response = await fetch(`/api/trufflehog/${projectId}/pause`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to pause trufflehog')
      }

      const data: TrufflehogState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      return null

    } finally {
      transitionRef.current = false
      setIsLoading(false)
    }
  }, [projectId])

  const resumeTrufflehog = useCallback(async (): Promise<TrufflehogState | null> => {
    if (!projectId) return null

    setIsLoading(true)

    try {
      const response = await fetch(`/api/trufflehog/${projectId}/resume`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to resume trufflehog')
      }

      const data: TrufflehogState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  // Initial fetch on mount
  useEffect(() => {
    if (!projectId || !enabled) {
      setState(null)
      return
    }

    fetchStatus()
  }, [projectId, enabled, fetchStatus])

  // Smart polling
  useEffect(() => {
    if (!projectId || !enabled) return

    if (pollingRef.current) {
      clearInterval(pollingRef.current)
      pollingRef.current = null
    }

    const isRunning = state?.status === 'running' || state?.status === 'starting' || state?.status === 'paused'
    const interval = isRunning ? pollingInterval : IDLE_POLLING_INTERVAL

    pollingRef.current = setInterval(fetchStatus, interval)

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
    }
  }, [projectId, enabled, pollingInterval, fetchStatus, state?.status])

  return {
    state,
    isLoading,
    error,
    refetch: fetchStatus,
    startTrufflehog,
    stopTrufflehog,
    pauseTrufflehog,
    resumeTrufflehog,
    getLastStartError,
  }
}

export default useTrufflehogStatus
