'use client'

/**
 * Scan Queue - the Activity view (plan Phase 5). The canonical surface for queue
 * state, opened from the bottom-bar SystemMeter. Shows the caller's own running /
 * queued / needs-review / recent jobs (others' work only as an anonymised count),
 * with Cancel and (for needs_review) Re-confirm actions.
 */
import { useCallback, useEffect, useState } from 'react'
import { Drawer } from '@/components/ui'
import styles from './ActivityDrawer.module.css'

interface JobRow {
  id: string
  projectId: string
  kind: string
  status: string
  attempts: number
  blockedCode: string
  blockedReason: string
  error: string
  enqueuedAt: string
  startedAt: string | null
  finishedAt: string | null
}

interface ActivityData {
  mine: { running: JobRow[]; queued: JobRow[]; needsReview: JobRow[]; recent: JobRow[] }
  others: { queued: number; running: number; needsReview: number }
  ledger: { remaining_for_new?: number } | null
}

const KIND_LABEL: Record<string, string> = {
  full_recon: 'Full recon',
  partial_recon: 'Partial recon',
  gvm: 'GVM',
  github_hunt: 'GitHub hunt',
  trufflehog: 'TruffleHog',
  supply_chain: 'Supply chain',
  supply_chain_repo: 'Supply chain (repo)',
  ai_attack: 'AI attack surface',
}

function kindLabel(k: string) { return KIND_LABEL[k] ?? k }
function gb(bytes?: number) { return bytes ? `${(bytes / 1024 ** 3).toFixed(1)} GB` : '' }

export function ActivityDrawer({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const [data, setData] = useState<ActivityData | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const res = await fetch('/api/system/jobs')
      if (!res.ok) { setError('Could not load the queue.'); return }
      setData(await res.json())
      setError(null)
    } catch {
      setError('Could not load the queue.')
    }
  }, [])

  useEffect(() => {
    if (!isOpen) return
    refresh()
    const t = setInterval(refresh, 5000)
    return () => clearInterval(t)
  }, [isOpen, refresh])

  const act = useCallback(async (id: string, action: 'cancel' | 'reconfirm') => {
    setBusyId(id)
    try {
      const res = await fetch(`/api/job-queue/${id}/${action}`, { method: 'POST' })
      if (!res.ok) {
        const d = await res.json().catch(() => ({}))
        setError(d.error || `Could not ${action} the job.`)
      } else {
        await refresh()
      }
    } catch {
      setError(`Could not ${action} the job.`)
    } finally {
      setBusyId(null)
    }
  }, [refresh])

  const row = (j: JobRow, actions: React.ReactNode) => (
    <li key={j.id} className={styles.row}>
      <div className={styles.rowMain}>
        <span className={`${styles.badge} ${styles[`s_${j.status}`] ?? ''}`}>{j.status.replace('_', ' ')}</span>
        <span className={styles.kind}>{kindLabel(j.kind)}</span>
      </div>
      {(j.blockedReason || j.error) && (
        <div className={styles.reason}>{j.blockedReason || j.error}</div>
      )}
      {actions && <div className={styles.actions}>{actions}</div>}
    </li>
  )

  const cancelBtn = (id: string) => (
    <button type="button" className={styles.btnSecondary} disabled={busyId === id} onClick={() => act(id, 'cancel')}>Cancel</button>
  )
  const reconfirmBtn = (id: string) => (
    <button type="button" className={styles.btnPrimary} disabled={busyId === id} onClick={() => act(id, 'reconfirm')}>Re-confirm</button>
  )

  const mine = data?.mine
  const others = data?.others
  const remaining = data?.ledger?.remaining_for_new

  return (
    <Drawer isOpen={isOpen} onClose={onClose} position="right" title="Scan activity">
      <div className={styles.wrap}>
        {typeof remaining === 'number' && (
          <div className={styles.ledger}>{gb(remaining)} available for a new scan</div>
        )}
        {error && <div className={styles.err}>{error}</div>}

        <Section title="Running" count={mine?.running.length ?? 0}>
          {mine?.running.map(j => row(j, null))}
        </Section>

        <Section title="Needs review" count={mine?.needsReview.length ?? 0}>
          {mine?.needsReview.map(j => row(j, <>{reconfirmBtn(j.id)}{cancelBtn(j.id)}</>))}
        </Section>

        <Section title="Queued" count={mine?.queued.length ?? 0}>
          {mine?.queued.map(j => row(j, cancelBtn(j.id)))}
        </Section>

        <Section title="Recent" count={mine?.recent.length ?? 0}>
          {mine?.recent.map(j => row(j, null))}
        </Section>

        {others && (others.queued + others.running + others.needsReview > 0) && (
          <div className={styles.others}>
            Other users: {others.running} running, {others.queued} queued
            {others.needsReview ? `, ${others.needsReview} awaiting review` : ''}
          </div>
        )}
      </div>
    </Drawer>
  )
}

function Section({ title, count, children }: { title: string; count: number; children: React.ReactNode }) {
  return (
    <div className={styles.section}>
      <div className={styles.sectionHead}>{title} <span className={styles.count}>{count}</span></div>
      {count > 0 ? <ul className={styles.list}>{children}</ul> : <div className={styles.empty}>None</div>}
    </div>
  )
}

export default ActivityDrawer
