'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { SupplyChainState, SupplyChainStatus } from '@/lib/recon-types'

interface UseSupplyChainStatusOptions {
  projectId: string | null
  enabled?: boolean
  pollingInterval?: number
  onStatusChange?: (status: SupplyChainStatus) => void
  onComplete?: () => void
  onError?: (error: string) => void
}

interface UseSupplyChainStatusReturn {
  state: SupplyChainState | null
  isLoading: boolean
  error: string | null
  refetch: () => Promise<void>
  startSupplyChain: () => Promise<SupplyChainState | null>
  stopSupplyChain: () => Promise<SupplyChainState | null>
  pauseSupplyChain: () => Promise<SupplyChainState | null>
  resumeSupplyChain: () => Promise<SupplyChainState | null>
}

const DEFAULT_POLLING_INTERVAL = 5000
const IDLE_POLLING_INTERVAL = 30000

export function useSupplyChainStatus({
  projectId,
  enabled = true,
  pollingInterval = DEFAULT_POLLING_INTERVAL,
  onStatusChange,
  onComplete,
  onError,
}: UseSupplyChainStatusOptions): UseSupplyChainStatusReturn {
  const [state, setState] = useState<SupplyChainState | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const previousStatusRef = useRef<SupplyChainStatus | null>(null)
  const pollingRef = useRef<NodeJS.Timeout | null>(null)
  // A pause/stop request is in flight. Docker's freeze can take several seconds,
  // so hold the optimistic status ('pausing' / 'stopping') and skip polling until
  // the request resolves -- a poll landing mid-freeze would revert the button.
  const transitionRef = useRef(false)

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
      const response = await fetch(`/api/supply-chain/${projectId}/status`)
      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to fetch supply-chain status')
      }

      const data: SupplyChainState = await response.json()
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

  const startSupplyChain = useCallback(async (): Promise<SupplyChainState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setError(null)

    try {
      const response = await fetch(`/api/supply-chain/${projectId}/start`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to start Supply-Chain scan')
      }

      const data: SupplyChainState = await response.json()
      setState(data)
      previousStatusRef.current = data.status
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      onErrorRef.current?.(errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const stopSupplyChain = useCallback(async (): Promise<SupplyChainState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    transitionRef.current = true
    setState(prev => prev ? { ...prev, status: 'stopping' as SupplyChainState['status'] } : prev)

    try {
      const response = await fetch(`/api/supply-chain/${projectId}/stop`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to stop Supply-Chain scan')
      }

      const data: SupplyChainState = await response.json()
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

  const pauseSupplyChain = useCallback(async (): Promise<SupplyChainState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    transitionRef.current = true
    setState(prev => prev ? { ...prev, status: 'pausing' as SupplyChainState['status'] } : prev)

    try {
      const response = await fetch(`/api/supply-chain/${projectId}/pause`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to pause supply-chain')
      }

      const data: SupplyChainState = await response.json()
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

  const resumeSupplyChain = useCallback(async (): Promise<SupplyChainState | null> => {
    if (!projectId) return null

    setIsLoading(true)

    try {
      const response = await fetch(`/api/supply-chain/${projectId}/resume`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to resume supply-chain')
      }

      const data: SupplyChainState = await response.json()
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
    startSupplyChain,
    stopSupplyChain,
    pauseSupplyChain,
    resumeSupplyChain,
  }
}

export default useSupplyChainStatus
