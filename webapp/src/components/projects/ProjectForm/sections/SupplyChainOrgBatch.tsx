'use client'

/**
 * Scan Queue Phase 6 - launch a supply-chain org batch. Self-contained (no
 * FormData cascade): the operator types a GitHub org/user, and this enumerates its
 * repos server-side and queues one supply_chain_repo scan per repo (priority -10),
 * which the dispatcher runs as capacity frees up. Uses the project's saved
 * supply-chain org options (forks/archived/max repos/deep analysis).
 */
import { useCallback, useState } from 'react'
import { PackageSearch, Loader2 } from 'lucide-react'
import { useToast } from '@/components/ui'
import { useAlertModal } from '@/components/ui/AlertModal/AlertModal'

const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/

export function SupplyChainOrgBatch({ projectId }: { projectId: string | null | undefined }) {
  const [org, setOrg] = useState('')
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  const { alertError } = useAlertModal()

  const valid = OWNER_RE.test(org.trim())

  const launch = useCallback(async () => {
    if (!projectId || !valid) return
    setBusy(true)
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
      toast.success(`Queued ${data.totalItems} repo scan${data.totalItems === 1 ? '' : 's'} for ${org.trim()}. They run as capacity frees up.`)
      setOrg('')
    } catch {
      await alertError('Could not start the org batch.', 'Supply-chain org batch')
    } finally {
      setBusy(false)
    }
  }, [projectId, org, valid, toast, alertError])

  if (!projectId) return null

  return (
    <div style={{ marginTop: 12, padding: '10px 12px', border: '1px solid var(--border, #333)', borderRadius: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
        <PackageSearch size={14} /> Scan a whole GitHub org
      </div>
      <p style={{ fontSize: 12, color: 'var(--text-secondary, #9aa)', margin: '0 0 8px' }}>
        Enumerate an organization&apos;s repositories and queue one supply-chain scan per repo.
        Uses this project&apos;s saved org options (forks, archived, max repos, deep analysis).
      </p>
      <div style={{ display: 'flex', gap: 6 }}>
        <input
          type="text"
          className="textInput"
          style={{ flex: 1 }}
          value={org}
          onChange={(e) => setOrg(e.target.value)}
          placeholder="github-org-or-user"
          onKeyDown={(e) => { if (e.key === 'Enter' && valid && !busy) launch() }}
        />
        <button
          type="button"
          disabled={!valid || busy}
          onClick={launch}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 10px',
            borderRadius: 6, border: '1px solid rgba(34,197,94,0.3)',
            background: 'rgba(34,197,94,0.1)', color: '#22c55e',
            cursor: valid && !busy ? 'pointer' : 'default', fontSize: 12, fontWeight: 500,
            opacity: valid && !busy ? 1 : 0.5,
          }}
        >
          {busy ? <Loader2 size={12} className="spin" /> : <PackageSearch size={12} />} Queue org batch
        </button>
      </div>
    </div>
  )
}

export default SupplyChainOrgBatch
