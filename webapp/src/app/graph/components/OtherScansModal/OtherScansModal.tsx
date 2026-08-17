'use client'

import { useRef, useState } from 'react'
import { Play, Pause, Square, Terminal, Download, Loader2, Github, Search, AlertTriangle, PackageSearch, Settings } from 'lucide-react'
import Link from 'next/link'
import { SETTINGS_KEYS_HREF } from '@/lib/settingsLinks'
import { CredentialShortcut } from '@/components/settings/CredentialShortcut'
import { useCredentialKeys } from '@/hooks/useCredentialKeys'
import { TRUFFLEHOG_SOURCES } from '@/lib/trufflehogSources'
import type { TrufflehogProfileSummary } from '@/hooks/useTrufflehogRuns'
import { projectSettingsHref } from '@/lib/projectSettingsLinks'
import { Modal, WikiInfoButton } from '@/components/ui'
import type { GithubHuntStatus, TrufflehogStatus, SupplyChainStatus } from '@/lib/recon-types'
import SupplyChainInput, { type OrgBatchState, type SupplyChainInputHandle } from './SupplyChainInput'
import styles from './OtherScansModal.module.css'

interface OtherScansModalProps {
  isOpen: boolean
  onClose: () => void
  hasReconData: boolean
  hasGithubToken: boolean
  /** True while a PAST version is being viewed: these scans write the LIVE graph,
   *  and the downloadable JSON is always the latest scan, so both are disabled. */
  viewingPastVersion?: boolean
  /** True while a version activation (graph swap) is in flight. */
  isActivatingVersion?: boolean
  // GitHub Hunt
  onStartGithubHunt?: () => void
  onPauseGithubHunt?: () => void
  onResumeGithubHunt?: () => void
  onStopGithubHunt?: () => void
  onDownloadGithubHuntJSON?: () => void
  onToggleGithubHuntLogs?: () => void
  githubHuntStatus?: GithubHuntStatus
  hasGithubHuntData?: boolean
  isGithubHuntLogsOpen?: boolean
  // TruffleHog — run-keyed: one row per configured SOURCE, each with its own
  // status, Start, Stop and Logs. A single project-level set of controls could
  // only ever drive one of N parallel runs.
  onStartTrufflehog?: (source: string) => void
  onStopTrufflehog?: (source: string) => void
  onDownloadTrufflehogJSON?: () => void
  onToggleTrufflehogLogs?: (source: string) => void
  /** One entry per configured source, from /api/trufflehog/{id}/profiles. */
  trufflehogProfiles?: TrufflehogProfileSummary[]
  /** Live run state keyed by source, from /api/trufflehog/{id}/all. */
  trufflehogRunsBySource?: Record<string, { status: TrufflehogStatus; target?: string } | undefined>
  hasTrufflehogData?: boolean
  /** Which source's log drawer is open, if any. */
  openTrufflehogLogsSource?: string | null

  // Supply Chain (L1)
  onStartSupplyChain?: () => void
  onPauseSupplyChain?: () => void
  onResumeSupplyChain?: () => void
  onStopSupplyChain?: () => void
  onDownloadSupplyChainJSON?: () => void
  onToggleSupplyChainLogs?: () => void
  supplyChainStatus?: SupplyChainStatus
  hasSupplyChainData?: boolean
  isSupplyChainLogsOpen?: boolean
  /** Needed to configure the scan input inline (upload / repository). Without
   *  it the card renders read-only and Start stays disabled. */
  projectId?: string
}

function StatusBadge({ status }: { status: string }) {
  const styleMap: Record<string, string> = {
    idle: styles.statusIdle,
    starting: styles.statusRunning,
    running: styles.statusRunning,
    paused: styles.statusPaused,
    stopping: styles.statusRunning,
    completed: styles.statusCompleted,
    error: styles.statusError,
  }
  return (
    <span className={`${styles.statusBadge} ${styleMap[status] || styles.statusIdle}`}>
      {status}
    </span>
  )
}

export function OtherScansModal({
  isOpen,
  onClose,
  hasReconData,
  hasGithubToken,
  viewingPastVersion = false,
  isActivatingVersion = false,
  // GitHub Hunt
  onStartGithubHunt,
  onPauseGithubHunt,
  onResumeGithubHunt,
  onStopGithubHunt,
  onDownloadGithubHuntJSON,
  onToggleGithubHuntLogs,
  githubHuntStatus = 'idle',
  hasGithubHuntData = false,
  isGithubHuntLogsOpen = false,
  // TruffleHog
  onStartTrufflehog,
  onStopTrufflehog,
  onDownloadTrufflehogJSON,
  onToggleTrufflehogLogs,
  trufflehogProfiles = [],
  trufflehogRunsBySource = {},
  hasTrufflehogData = false,
  openTrufflehogLogsSource = null,

  // Supply Chain (L1)
  onStartSupplyChain,
  onPauseSupplyChain,
  onResumeSupplyChain,
  onStopSupplyChain,
  onDownloadSupplyChainJSON,
  onToggleSupplyChainLogs,
  supplyChainStatus = 'idle',
  hasSupplyChainData = false,
  isSupplyChainLogsOpen = false,
  projectId,
}: OtherScansModalProps) {
  // GitHub Hunt derived state
  const isGHBusy = githubHuntStatus === 'running' || githubHuntStatus === 'starting' || githubHuntStatus === 'pausing'
  const isGHStopping = githubHuntStatus === 'stopping'
  const isGHPausing = githubHuntStatus === 'pausing'
  const isGHRunning = isGHBusy || isGHStopping
  const isGHPaused = githubHuntStatus === 'paused'
  const isGHActive = isGHRunning || isGHPaused

  // TruffleHog derived state: aggregated across every source, used only for the
  // card-level badge and the Download button (the JSON download is per project).
  const trufflehogStatuses = trufflehogProfiles
    .map(p => trufflehogRunsBySource[p.source]?.status ?? 'idle')
  const isTHActive = trufflehogStatuses.some(
    st => st === 'running' || st === 'starting' || st === 'stopping')
  const trufflehogCardStatus: TrufflehogStatus =
    trufflehogStatuses.find(st => st === 'running' || st === 'starting') ??
    (trufflehogStatuses.includes('error') ? 'error'
      : trufflehogStatuses.includes('completed') ? 'completed' : 'idle')

  // Whether the SELECTED input source actually has a usable value. Reported by
  // SupplyChainInput, because only it knows which source is active - a
  // configured repository must not make Start clickable while the upload
  // source is selected, and vice versa.
  const [scInputReady, setInputReady] = useState(false)

  // Org mode queues N scans instead of starting this project's single one, so
  // its action replaces Start in the row below rather than sitting beside a
  // button that can never be enabled. Non-null only while 'org' is selected.
  const [orgBatch, setOrgBatch] = useState<OrgBatchState | null>(null)
  const supplyChainRef = useRef<SupplyChainInputHandle>(null)

  // The keys the scan cards below can set in place. `hasGithubToken` is resolved
  // by the page that owns this modal and does not change when a key is saved
  // here, so the live value is OR-ed in to release the Start button at once.
  const credentialKeys = useCredentialKeys()
  const githubTokenSet = hasGithubToken || credentialKeys.isSet('githubAccessToken')

  // Supply Chain derived state
  const isSCBusy = supplyChainStatus === 'running' || supplyChainStatus === 'starting' || supplyChainStatus === 'pausing'
  const isSCStopping = supplyChainStatus === 'stopping'
  const isSCPausing = supplyChainStatus === 'pausing'
  const isSCRunning = isSCBusy || isSCStopping
  const isSCPaused = supplyChainStatus === 'paused'
  const isSCActive = isSCRunning || isSCPaused

  // Read-only past version (or an in-flight swap): no scan may start/resume, and the
  // JSON download is disabled because it would return the latest scan, not this view.
  const scanBlocked = viewingPastVersion || isActivatingVersion
  const blockedTitle = viewingPastVersion
    ? 'Viewing a saved version - switch back to the active version to run scans'
    : 'A version activation is in progress'

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Other Scans"
      size="large"
    >
      <div className={styles.content}>
        <div className={styles.row}>
        {/* GitHub Secret Hunt Card */}
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Github size={18} className={styles.cardIcon} />
            <h3 className={styles.cardTitle}>GitHub Secret Hunt</h3>
            <WikiInfoButton target="Github" title="GitHub Secret Hunting wiki" />
            <StatusBadge status={githubHuntStatus} />
          </div>
          <p className={styles.cardDescription}>
            Search GitHub repositories for exposed secrets, API keys, and credentials related to your target domain.
          </p>
          {!githubTokenSet && (
            <CredentialShortcut settingsKey="githubAccessToken" keys={credentialKeys} compact />
          )}
          <div className={styles.cardActions}>
            {isGHPaused ? (
              <button
                className={styles.resumeButton}
                onClick={onResumeGithubHunt}
                disabled={!githubTokenSet || scanBlocked}
                title={scanBlocked ? blockedTitle : !githubTokenSet ? 'GitHub token required' : 'Resume GitHub Hunt'}
              >
                <Play size={12} />
                <span>Resume</span>
              </button>
            ) : (
              <button
                className={styles.startButton}
                onClick={onStartGithubHunt}
                disabled={!githubTokenSet || isGHRunning || (!hasReconData && !isGHPaused) || scanBlocked}
                title={scanBlocked ? blockedTitle : !githubTokenSet ? 'GitHub token required' : !hasReconData ? 'Run recon first' : isGHRunning ? 'In progress...' : 'Start GitHub Hunt'}
              >
                {isGHRunning ? (
                  <Loader2 size={12} className={styles.spinner} />
                ) : (
                  <Play size={12} />
                )}
                <span>{isGHPausing ? 'Pausing...' : isGHBusy ? 'Running...' : isGHStopping ? 'Stopping...' : 'Start'}</span>
              </button>
            )}

            {isGHBusy && (
              <button
                className={styles.pauseButton}
                onClick={onPauseGithubHunt}
                disabled={isGHPausing}
                title="Pause"
              >
                {isGHPausing ? <Loader2 size={12} className={styles.spinner} /> : <Pause size={12} />}
                <span>Pause</span>
              </button>
            )}

            {isGHActive && (
              <button
                className={styles.stopButton}
                onClick={onStopGithubHunt}
                disabled={isGHStopping}
                title="Stop"
              >
                <Square size={12} />
                <span>Stop</span>
              </button>
            )}

            <button
              className={`${styles.logsButton} ${isGithubHuntLogsOpen ? styles.logsButtonActive : ''}`}
              onClick={onToggleGithubHuntLogs}
              disabled={!isGHActive}
              title="View Logs"
            >
              <Terminal size={12} />
              <span>Logs</span>
            </button>

            <button
              className={styles.downloadButton}
              onClick={onDownloadGithubHuntJSON}
              disabled={!hasGithubHuntData || isGHActive || viewingPastVersion}
              title={viewingPastVersion ? 'Download reflects the active version, not this saved view' : hasGithubHuntData ? 'Download JSON' : 'No data available'}
            >
              <Download size={12} />
              <span>Download</span>
            </button>

            {projectId && (
              <Link
                href={projectSettingsHref(projectId, 'github-secret-hunting')}
                className={styles.settingsButton}
                title="Configure the target org, repos and scan options in project settings"
                aria-label="Configure GitHub Secret Hunt in project settings"
              >
                <Settings size={13} />
              </Link>
            )}
          </div>
        </div>

        {/* TruffleHog Scanner Card — one row per configured source */}
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Search size={18} className={styles.cardIcon} />
            <h3 className={styles.cardTitle}>TruffleHog Scanner</h3>
            <WikiInfoButton target="Trufflehog" title="TruffleHog Secret Scanning wiki" />
            <StatusBadge status={trufflehogCardStatus} />
          </div>
          <p className={styles.cardDescription}>
            Deep secret scanning with 700+ detectors across git hosts, container registries,
            Hugging Face, object storage and CI systems. Sources run independently and in parallel.
          </p>

          {trufflehogProfiles.length === 0 ? (
            <p className={styles.cardDescription} style={{ opacity: 0.75 }}>
              No sources configured.{' '}
              {projectId && (
                <Link
                  href={projectSettingsHref(projectId, 'trufflehog-scanner')}
                  style={{ color: 'var(--accent-primary)', fontWeight: 500 }}
                >
                  Add one in project settings
                </Link>
              )}
              {' '}to make it startable here.
            </p>
          ) : (
            trufflehogProfiles.map(profile => {
              const run = trufflehogRunsBySource[profile.source]
              const status = run?.status ?? 'idle'
              const busy = status === 'running' || status === 'starting'
              const stopping = status === 'stopping'
              const active = busy || stopping
              const missing = (profile.missingCredentials ?? [])
                .filter(m => !credentialKeys.isSet(m.settingsKey))
              const invalid = (profile.validationErrors ?? []).length > 0
              // Fails closed in the UI too, and the start route re-checks: a key
              // cleared after this rendered must not produce an opaque failure.
              const blockedReason = missing.length
                ? `Set ${missing.map(m => m.label).join(', ')} in Global Settings > API Keys`
                : invalid ? 'This source is not fully configured'
                : scanBlocked ? blockedTitle : ''

              return (
                <div key={profile.id}>
                <div className={styles.cardActions} style={{ alignItems: 'center' }}>
                  <span style={{ minWidth: '150px', fontSize: '13px', fontWeight: 500 }}>
                    {TRUFFLEHOG_SOURCES[profile.source]?.label ?? profile.source}
                    {run?.target && (
                      <span style={{ display: 'block', fontSize: '11px', opacity: 0.7, fontWeight: 400 }}>
                        {run.target}
                      </span>
                    )}
                  </span>
                  <StatusBadge status={status} />

                  <button
                    className={styles.startButton}
                    onClick={() => onStartTrufflehog?.(profile.source)}
                    disabled={active || Boolean(blockedReason)}
                    title={blockedReason || (active ? 'In progress...' : `Start ${profile.source}`)}
                  >
                    {busy ? <Loader2 size={12} className={styles.spinner} /> : <Play size={12} />}
                    <span>{busy ? 'Running...' : stopping ? 'Stopping...' : 'Start'}</span>
                  </button>

                  {active && (
                    <button
                      className={styles.stopButton}
                      onClick={() => onStopTrufflehog?.(profile.source)}
                      disabled={stopping}
                      title="Stop this source"
                    >
                      <Square size={12} />
                      <span>Stop</span>
                    </button>
                  )}

                  <button
                    className={`${styles.logsButton} ${openTrufflehogLogsSource === profile.source ? styles.logsButtonActive : ''}`}
                    onClick={() => onToggleTrufflehogLogs?.(profile.source)}
                    disabled={!active}
                    title="View Logs"
                  >
                    <Terminal size={12} />
                    <span>Logs</span>
                  </button>

                  {missing.length > 0 && (
                    <span style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: '#f59e0b' }}>
                      <AlertTriangle size={12} />
                      <Link href={`${SETTINGS_KEYS_HREF}#trufflehog-keys`} style={{ color: 'inherit' }}>
                        {missing.map(m => m.label).join(', ')} required
                      </Link>
                    </span>
                  )}
                </div>

                {/* Only the keys that actually block THIS source, so a row that
                    can start stays a single line. */}
                {missing.length > 0 && (
                  <div className={styles.credentialStack}>
                    {missing.map(m => (
                      <CredentialShortcut
                        key={m.settingsKey}
                        settingsKey={m.settingsKey}
                        keys={credentialKeys}
                        compact
                      />
                    ))}
                  </div>
                )}
                </div>
              )
            })
          )}

          <div className={styles.cardActions}>
            <button
              className={styles.downloadButton}
              onClick={onDownloadTrufflehogJSON}
              disabled={!hasTrufflehogData || isTHActive || viewingPastVersion}
              title={viewingPastVersion ? 'Download reflects the active version, not this saved view' : hasTrufflehogData ? 'Download JSON' : 'No data available'}
            >
              <Download size={12} />
              <span>Download</span>
            </button>

            {projectId && (
              <Link
                href={projectSettingsHref(projectId, 'trufflehog-scanner')}
                className={styles.settingsButton}
                title="Configure which sources to scan and their options in project settings"
                aria-label="Configure TruffleHog Scanner in project settings"
              >
                <Settings size={13} />
              </Link>
            )}
          </div>
        </div>

      </div>

        {/* Supply Chain Scanner (L1) - full-width second row.
            It carries its own input configuration, so it needs more room than
            the two hunters above and no longer sends the operator to Project
            Settings to pick a file. */}
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Search size={18} className={styles.cardIcon} />
            <h3 className={styles.cardTitle}>Supply Chain Scanner</h3>
            <WikiInfoButton target="SupplyChainScan" title="Supply-Chain Scanning wiki" />
            <StatusBadge status={supplyChainStatus} />
          </div>
          <p className={styles.cardDescription}>
            Audit an SBOM / lockfile, or a GitHub repository, against the offline OSV database for known-malicious (MAL) and known-vulnerable packages. The OSV verdict is fully offline.
          </p>

          {projectId && (
            <SupplyChainInput
              ref={supplyChainRef}
              projectId={projectId}
              disabled={isSCActive}
              onInputAvailabilityChange={setInputReady}
              onOrgBatchStateChange={setOrgBatch}
            />
          )}

          <div className={styles.cardActions}>
            {isSCPaused ? (
              <button className={styles.resumeButton} onClick={onResumeSupplyChain} disabled={scanBlocked}
                title={scanBlocked ? blockedTitle : 'Resume Supply-Chain scan'}>
                <Play size={12} /><span>Resume</span>
              </button>
            ) : orgBatch ? (
              <button className={styles.startButton}
                onClick={() => supplyChainRef.current?.launchOrgBatch()}
                disabled={!orgBatch.canQueue || orgBatch.busy || isSCActive || scanBlocked}
                title={scanBlocked ? blockedTitle : !orgBatch.canQueue ? 'Enter an organization or user above first' : 'Queue one scan per repository'}>
                {orgBatch.busy ? <Loader2 size={12} className={styles.spinner} /> : <PackageSearch size={12} />}
                <span>{orgBatch.busy ? 'Queuing...' : 'Queue org batch'}</span>
              </button>
            ) : (
              <button className={styles.startButton} onClick={onStartSupplyChain}
                disabled={!scInputReady || isSCRunning || scanBlocked}
                title={scanBlocked ? blockedTitle : !scInputReady ? 'Choose an input above first' : isSCRunning ? 'In progress...' : 'Start Supply-Chain scan'}>
                {isSCRunning ? <Loader2 size={12} className={styles.spinner} /> : <Play size={12} />}
                <span>{isSCPausing ? 'Pausing...' : isSCBusy ? 'Running...' : isSCStopping ? 'Stopping...' : 'Start'}</span>
              </button>
            )}
            {isSCBusy && (
              <button className={styles.pauseButton} onClick={onPauseSupplyChain} disabled={isSCPausing} title="Pause">
                {isSCPausing ? <Loader2 size={12} className={styles.spinner} /> : <Pause size={12} />}<span>Pause</span>
              </button>
            )}
            {isSCActive && (
              <button className={styles.stopButton} onClick={onStopSupplyChain} disabled={isSCStopping} title="Stop">
                <Square size={12} /><span>Stop</span>
              </button>
            )}
            <button className={`${styles.logsButton} ${isSupplyChainLogsOpen ? styles.logsButtonActive : ''}`}
              onClick={onToggleSupplyChainLogs} disabled={!isSCActive} title="View Logs">
              <Terminal size={12} /><span>Logs</span>
            </button>
            <button className={styles.downloadButton} onClick={onDownloadSupplyChainJSON}
              disabled={!hasSupplyChainData || isSCActive || viewingPastVersion}
              title={viewingPastVersion ? 'Download reflects the active version, not this saved view' : hasSupplyChainData ? 'Download JSON' : 'No data available'}>
              <Download size={12} /><span>Download</span>
            </button>
          </div>
        </div>
      </div>
    </Modal>
  )
}

export default OtherScansModal
