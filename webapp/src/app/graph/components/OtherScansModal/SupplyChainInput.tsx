'use client'

import { useCallback, useEffect, useImperativeHandle, useRef, useState } from 'react'
import Link from 'next/link'
import { Upload, Github, FileText, Loader2, Trash2, Building2 } from 'lucide-react'
import { parseGithubRepo, isValidGitRef } from '@/lib/validation/supplyChainInput'
import { parseOwnerTarget, hostHint, GITHUB_DOT_COM } from '@/lib/github/ownerTarget'
import { SETTINGS_KEYS_HREF } from '@/lib/settingsLinks'
import { useToast } from '@/components/ui'
import { useAlertModal } from '@/components/ui/AlertModal/AlertModal'
import styles from './OtherScansModal.module.css'

/** 'upload' and 'github' are the project's PERSISTED input for one scan. 'org' is
 *  a different action entirely - it queues one scan per repo in an organization -
 *  so it is a view-only mode here and is never written to supplyChainInputMode. */
export type SupplyChainSource = 'upload' | 'github' | 'org'

/**
 * Client-side shape check only: a bare owner name, or a URL that resolves to
 * host + owner. Which HOSTS are actually reachable is the server's call (it owns
 * the operator's allowlist), so a well-formed value for an unregistered host
 * gets a specific error back from the API rather than being guessed at here.
 */
function orgTargetShapeOk(value: string): boolean {
  return parseOwnerTarget(value, [GITHUB_DOT_COM]) !== null
    || (hostHint(value) !== null && parseOwnerTarget(value, [hostHint(value) as string]) !== null)
}

/** The same shape-only check for a single `owner/repo` coordinate. */
function repoShapeOk(value: string): boolean {
  return parseGithubRepo(value, [GITHUB_DOT_COM]) !== null
    || (hostHint(value) !== null && parseGithubRepo(value, [hostHint(value) as string]) !== null)
}

/** Org-mode readiness, reported up so the card's action row can swap its Start
 *  button for "Queue org batch". Null whenever another source is selected. */
export interface OrgBatchState {
  canQueue: boolean
  busy: boolean
}

/** The org batch lives in the card's action row but its state (the typed
 *  account) lives here, so the parent triggers it through this handle rather
 *  than owning a copy of the input's state. */
export interface SupplyChainInputHandle {
  launchOrgBatch: () => void
}

interface Props {
  projectId: string
  /** Disabled while a scan is in flight - changing the input mid-scan would
   *  make the running scan's inputs disagree with what the card shows. */
  disabled?: boolean
  /** Bubbles up whether a usable input exists, so the card can gate Start. */
  onInputAvailabilityChange?: (hasInput: boolean) => void
  /** Bubbles up org-mode readiness so the card can render the queue button. */
  onOrgBatchStateChange?: (state: OrgBatchState | null) => void
  ref?: React.Ref<SupplyChainInputHandle>
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
  onOrgBatchStateChange,
  ref,
}: Props) {
  const [source, setSource] = useState<SupplyChainSource>('upload')
  const [file, setFile] = useState<UploadedFile | null>(null)
  const [repoUrl, setRepoUrl] = useState('')
  const [repoRef, setRepoRef] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [org, setOrg] = useState('')
  const [orgBusy, setOrgBusy] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const toast = useToast()
  const { alertError } = useAlertModal()

  // Report input availability to the parent so Start can be gated on the
  // SELECTED source - a repo is not a substitute for a missing upload.
  useEffect(() => {
    // In 'org' mode there is nothing for Start to run: the batch has its own
    // button and queues N scans rather than starting this project's single one.
    const hasInput = source === 'org' ? false
      : source === 'github' ? repoShapeOk(repoUrl)
      : !!file
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
    // 'org' is not a scan input, so it must not overwrite the project's saved
    // mode - coming back to the card would otherwise find no input at all.
    if (next !== 'org') await persist({ supplyChainInputMode: next })
  }

  const orgValid = orgTargetShapeOk(org.trim())

  /**
   * Enumerate the org's repositories server-side and queue one supply_chain_repo
   * scan per repo (priority -10). The dispatcher runs them as capacity frees up,
   * so this returns immediately with a count rather than starting anything.
   */
  const launchOrgBatch = useCallback(async () => {
    if (!projectId || !orgValid || orgBusy) return
    setOrgBusy(true)
    try {
      const res = await fetch(`/api/projects/${projectId}/supply-chain-batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org: org.trim() }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        await alertError(data.error || 'Could not start the org batch.', 'Supply-chain org batch')
        return
      }
      toast.success(
        `Queued ${data.totalItems} repo scan${data.totalItems === 1 ? '' : 's'} for ` +
        `${data.org || org.trim()} on ${data.host || GITHUB_DOT_COM}. ` +
        'They run as capacity frees up - follow them in Scans -> Scan queue.'
      )
      setOrg('')
    } catch {
      await alertError('Could not start the org batch.', 'Supply-chain org batch')
    } finally {
      setOrgBusy(false)
    }
  }, [projectId, org, orgValid, orgBusy, toast, alertError])

  useImperativeHandle(ref, () => ({
    launchOrgBatch: () => { void launchOrgBatch() },
  }), [launchOrgBatch])

  // Report org-mode readiness up to the card. Only primitives change here, so
  // the parent re-renders when the button's enabled state actually flips, not
  // on every keystroke.
  useEffect(() => {
    onOrgBatchStateChange?.(
      source === 'org' ? { canQueue: orgValid, busy: orgBusy } : null,
    )
  }, [source, orgValid, orgBusy, onOrgBatchStateChange])

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

  const repoInvalid = repoUrl.trim() !== '' && !repoShapeOk(repoUrl)
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
        <button
          type="button"
          role="radio"
          aria-checked={source === 'org'}
          disabled={disabled}
          onClick={() => void chooseSource('org')}
          className={`${styles.sourceOption} ${source === 'org' ? styles.sourceOptionActive : ''}`}
        >
          <Building2 size={13} />
          <span>GitHub organization</span>
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
              replaces the current file. No API key is needed for an upload; keys
              and tokens live in{' '}
              <Link href={SETTINGS_KEYS_HREF} style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                Global Settings
              </Link>.
            </p>
          </>
        ) : source === 'org' ? (
          <>
            <div className={styles.inputRow}>
              <label className={styles.fieldLabel} htmlFor="sc-org">Organization or user</label>
              <input
                id="sc-org"
                type="text"
                className={styles.textField}
                placeholder="acme-corp or https://ghe.example.com/orgs/acme-corp"
                value={org}
                disabled={disabled || orgBusy}
                onChange={(e) => setOrg(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') void launchOrgBatch() }}
              />
            </div>
            {org.trim() !== '' && !orgValid && (
              <p className={styles.inlineError}>
                An organization or user name (letters, digits and dashes, 39 characters
                max), or its URL - github.com, or a GitHub Enterprise host you configured
                in Global Settings.
              </p>
            )}
            <p className={styles.hint}>
              Enumerates the account&apos;s repos and queues one supply-chain scan per
              repo, which run as capacity frees up (follow them in Scans &rarr; Scan
              queue). Works for a user or an org you belong to; you only ever see your
              own repos, never another user&apos;s private ones.
            </p>
            <p className={styles.hint}>
              What you type decides which credential is used, both set in{' '}
              <Link href={SETTINGS_KEYS_HREF} style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                Global Settings
              </Link>:
            </p>
            <ul className={styles.hintList}>
              <li>
                An org name or a github.com URL uses the GitHub Access Token. Public
                repos don&apos;t need it; private repos do, and it lifts the anonymous
                rate limit.
              </li>
              <li>
                A GitHub Enterprise URL (e.g. https://ghe.example.com/orgs/acme-corp)
                uses the GitHub Enterprise Token. That host must first be registered as
                the GitHub Enterprise Host (the allowlist).
              </li>
              <li>
                Any other host is refused before anything runs; no token is sent and no
                connection is made.
              </li>
            </ul>
            <p className={styles.hint}>
              The two tokens are never swapped. If the matching one is missing, the scan
              runs anonymously (public repos only).
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
                Must be a repository as owner/repo, or its https URL on github.com
                or a GitHub Enterprise host you configured in Global Settings.
              </p>
            )}
            {refInvalid && (
              <p className={styles.inlineError}>
                Branch/tag contains characters git does not allow.
              </p>
            )}
            <p className={styles.hint}>
              The repository is cloned shallowly inside the scan sandbox and its
              lockfiles are audited. Public repos clone anonymously; private ones
              use the GitHub Access Token from{' '}
              <Link href={SETTINGS_KEYS_HREF} style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                Global Settings
              </Link>.
            </p>
          </>
        )}
        {error && <p className={styles.inlineError}>{error}</p>}
      </div>
    </div>
  )
}
