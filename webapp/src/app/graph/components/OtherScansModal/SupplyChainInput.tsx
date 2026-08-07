'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { Upload, Github, FileText, Loader2, Trash2 } from 'lucide-react'
import { parseGithubRepo, isValidGitRef } from '@/lib/validation/supplyChainInput'
import styles from './OtherScansModal.module.css'

export type SupplyChainSource = 'upload' | 'github'

interface Props {
  projectId: string
  /** Disabled while a scan is in flight - changing the input mid-scan would
   *  make the running scan's inputs disagree with what the card shows. */
  disabled?: boolean
  /** Bubbles up whether a usable input exists, so the card can gate Start. */
  onInputAvailabilityChange?: (hasInput: boolean) => void
}

interface UploadedFile {
  name: string
  size: number
  uploaded_at: string
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

/**
 * The L1 scan's input configuration, inline in the Other Scans card.
 *
 * This used to live in Project Settings, which meant "run a supply-chain scan"
 * was a two-screen errand: open Other Scans, discover the Start button is
 * disabled, navigate away to upload, come back. The input belongs where the
 * scan is launched.
 *
 * The scan consumes exactly ONE input, so the source is mutually exclusive and
 * each new upload REPLACES the previous file rather than accumulating.
 */
export default function SupplyChainInput({
  projectId,
  disabled = false,
  onInputAvailabilityChange,
}: Props) {
  const [source, setSource] = useState<SupplyChainSource>('upload')
  const [file, setFile] = useState<UploadedFile | null>(null)
  const [repoUrl, setRepoUrl] = useState('')
  const [repoRef, setRepoRef] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Report input availability to the parent so Start can be gated on the
  // SELECTED source - a repo is not a substitute for a missing upload.
  useEffect(() => {
    const hasInput = source === 'github' ? !!parseGithubRepo(repoUrl) : !!file
    onInputAvailabilityChange?.(hasInput)
  }, [source, file, repoUrl, onInputAvailabilityChange])

  const load = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    try {
      const [filesRes, projectRes] = await Promise.all([
        fetch(`/api/supply-chain/${projectId}/upload`),
        fetch(`/api/projects/${projectId}`),
      ])
      if (filesRes.ok) {
        const data = await filesRes.json()
        setFile((data.files || [])[0] || null)
      }
      if (projectRes.ok) {
        const p = await projectRes.json()
        setSource(p.supplyChainInputMode === 'github' ? 'github' : 'upload')
        setRepoUrl(p.supplyChainRepoUrl || '')
        setRepoRef(p.supplyChainRepoRef || '')
      }
    } catch {
      setError('Could not load the current supply-chain input')
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => { void load() }, [load])

  const persist = useCallback(async (patch: Record<string, unknown>) => {
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        setError(body.error || 'Could not save the supply-chain input')
        return false
      }
      setError(null)
      return true
    } catch {
      setError('Could not save the supply-chain input')
      return false
    }
  }, [projectId])

  const chooseSource = async (next: SupplyChainSource) => {
    if (next === source || disabled) return
    setSource(next)
    await persist({ supplyChainInputMode: next })
  }

  const onFilePicked = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const picked = e.target.files?.[0]
    // Always clear the input: picking the SAME file twice must still fire a
    // change event, otherwise a re-upload after a delete silently does nothing.
    e.target.value = ''
    if (!picked) return

    setBusy(true)
    setError(null)
    try {
      const form = new FormData()
      form.append('file', picked)
      const res = await fetch(`/api/supply-chain/${projectId}/upload`, {
        method: 'POST',
        body: form,
      })
      const body = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(body.error || 'Upload failed')
        return
      }
      await load()
    } catch {
      setError('Upload failed')
    } finally {
      setBusy(false)
    }
  }

  const removeFile = async () => {
    if (!file) return
    setBusy(true)
    try {
      await fetch(
        `/api/supply-chain/${projectId}/upload?filename=${encodeURIComponent(file.name)}`,
        { method: 'DELETE' })
      await load()
    } catch {
      setError('Could not remove the file')
    } finally {
      setBusy(false)
    }
  }

  const repoInvalid = repoUrl.trim() !== '' && !parseGithubRepo(repoUrl)
  const refInvalid = !isValidGitRef(repoRef)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <div className={styles.sourceToggle} role="radiogroup" aria-label="Supply-chain scan input source">
        <button
          type="button"
          role="radio"
          aria-checked={source === 'upload'}
          disabled={disabled}
          onClick={() => void chooseSource('upload')}
          className={`${styles.sourceOption} ${source === 'upload' ? styles.sourceOptionActive : ''}`}
        >
          <FileText size={13} />
          <span>Uploaded SBOM / lockfile</span>
        </button>
        <button
          type="button"
          role="radio"
          aria-checked={source === 'github'}
          disabled={disabled}
          onClick={() => void chooseSource('github')}
          className={`${styles.sourceOption} ${source === 'github' ? styles.sourceOptionActive : ''}`}
        >
          <Github size={13} />
          <span>GitHub repository</span>
        </button>
      </div>

      <div className={styles.inputPanel}>
        {loading ? (
          <span className={styles.hint}>Loading current input...</span>
        ) : source === 'upload' ? (
          <>
            <div className={styles.inputRow}>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,.xml,.txt,.lock,.toml,.mod,.sum,.yaml,.yml"
                onChange={onFilePicked}
                disabled={disabled || busy}
                style={{ display: 'none' }}
                aria-label="Upload SBOM or lockfile"
              />
              <button
                type="button"
                className={styles.sourceOption}
                style={{ flex: '0 0 auto' }}
                disabled={disabled || busy}
                onClick={() => fileInputRef.current?.click()}
              >
                {busy ? <Loader2 size={13} className={styles.spinner} /> : <Upload size={13} />}
                <span>{file ? 'Replace file' : 'Upload file'}</span>
              </button>

              {file ? (
                <div className={styles.activeFile}>
                  <FileText size={13} />
                  <span className={styles.activeFileName} title={file.name}>{file.name}</span>
                  <span>({formatSize(file.size)})</span>
                  <button
                    type="button"
                    className={styles.sourceOption}
                    style={{ flex: '0 0 auto', padding: '4px 8px' }}
                    disabled={disabled || busy}
                    onClick={() => void removeFile()}
                    aria-label={`Remove ${file.name}`}
                    title="Remove"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              ) : (
                <span className={styles.hint}>No file uploaded yet.</span>
              )}
            </div>
            <p className={styles.hint}>
              CycloneDX / SPDX SBOMs and lockfiles (package-lock.json, yarn.lock,
              poetry.lock, go.sum, Gemfile.lock, ...). Max 10 MB. A new upload
              replaces the current file.
            </p>
          </>
        ) : (
          <>
            <div className={styles.inputRow}>
              <label className={styles.fieldLabel} htmlFor="sc-repo-url">Repository</label>
              <input
                id="sc-repo-url"
                type="text"
                className={styles.textField}
                placeholder="owner/repo or https://github.com/owner/repo"
                value={repoUrl}
                disabled={disabled}
                onChange={(e) => setRepoUrl(e.target.value)}
                onBlur={() => {
                  if (!repoInvalid) void persist({ supplyChainRepoUrl: repoUrl.trim() })
                }}
              />
            </div>
            <div className={styles.inputRow}>
              <label className={styles.fieldLabel} htmlFor="sc-repo-ref">Branch / tag</label>
              <input
                id="sc-repo-ref"
                type="text"
                className={styles.textField}
                placeholder="default branch"
                value={repoRef}
                disabled={disabled}
                onChange={(e) => setRepoRef(e.target.value)}
                onBlur={() => {
                  if (!refInvalid) void persist({ supplyChainRepoRef: repoRef.trim() })
                }}
              />
            </div>
            {repoInvalid && (
              <p className={styles.inlineError}>
                Must be a github.com repository, as owner/repo or
                https://github.com/owner/repo.
              </p>
            )}
            {refInvalid && (
              <p className={styles.inlineError}>
                Branch/tag contains characters git does not allow.
              </p>
            )}
            <p className={styles.hint}>
              The repository is cloned shallowly inside the scan sandbox and its
              lockfiles are audited. Private repos use the GitHub token from
              Global Settings.
            </p>
          </>
        )}
        {error && <p className={styles.inlineError}>{error}</p>}
      </div>
    </div>
  )
}
