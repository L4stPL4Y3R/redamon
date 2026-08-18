'use client'

import { useCallback, useEffect, useState } from 'react'
import { useOptionalProject } from '@/providers/ProjectProvider'

/**
 * Read/write access to the Global Settings credentials from wherever a scan is
 * configured or started, so a missing key can be fixed in place instead of
 * navigating away from a half-filled form.
 *
 * These are USER-level settings, not project ones. A shortcut that writes them
 * from inside a project form is editing a value shared by every project, which
 * is why the UI built on this hook has to say so.
 *
 * GET returns secrets masked ('••••••••abcd'), never the real value, so this
 * hook can report whether a key is SET but can never show what it is. PUT
 * accepts a partial body and treats a '••••' prefix as "keep what you have", so
 * writing one key here cannot clobber the other twenty-one.
 */

/** The prefix the API masks secrets with. Writing it back is a no-op server-side. */
export const MASK_PREFIX = '••••'

export interface CredentialKeysApi {
  loading: boolean
  /** True once the key has a stored value. Never reveals what it is. */
  isSet: (name: string) => boolean
  /** The masked value for display, or '' when unset. */
  masked: (name: string) => string
  /** Persists one key. Resolves true on success. */
  save: (name: string, value: string) => Promise<boolean>
  /** The key currently being written, or null. */
  saving: string | null
  error: string
  refresh: () => Promise<void>
}

export function useCredentialKeys(): CredentialKeysApi {
  // Optional on purpose: this hook is embedded in scan cards that also render
  // outside a ProjectProvider, and a throw here would blank the whole surface
  // rather than degrade one input.
  const userId = useOptionalProject()?.userId ?? null
  const [values, setValues] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState<string | null>(null)
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    if (!userId) { setLoading(false); return }
    try {
      const res = await fetch(`/api/users/${userId}/settings`)
      if (!res.ok) return
      setValues(await res.json())
    } catch {
      // A failed read must not break the form this is embedded in; the shortcut
      // simply shows the key as unset and the user can still type into it.
    } finally {
      setLoading(false)
    }
  }, [userId])

  useEffect(() => { void refresh() }, [refresh])

  const isSet = useCallback(
    (name: string) => Boolean((values[name] ?? '').trim()),
    [values],
  )

  const masked = useCallback((name: string) => values[name] ?? '', [values])

  const save = useCallback(async (name: string, value: string) => {
    if (!userId) { setError('No user in session'); return false }
    setSaving(name)
    setError('')
    try {
      const res = await fetch(`/api/users/${userId}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [name]: value }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        setError(body.error ?? 'Could not save the key')
        return false
      }
      // Re-read rather than storing what was typed: the value we hold must be
      // the masked one, so a later save of a DIFFERENT key cannot send this
      // plaintext secret back to the server.
      await refresh()
      return true
    } catch {
      setError('Could not save the key')
      return false
    } finally {
      setSaving(null)
    }
  }, [userId, refresh])

  return { loading, isSet, masked, save, saving, error, refresh }
}
