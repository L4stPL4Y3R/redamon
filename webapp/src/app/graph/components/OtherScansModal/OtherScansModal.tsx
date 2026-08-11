'use client'

import { useRef, useState } from 'react'
import { Play, Pause, Square, Terminal, Download, Loader2, Github, Search, AlertTriangle, PackageSearch, Settings } from 'lucide-react'
import Link from 'next/link'
import { SETTINGS_KEYS_HREF } from '@/lib/settingsLinks'
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
  // TruffleHog
  onStartTrufflehog?: () => void
  onPauseTrufflehog?: () => void
  onResumeTrufflehog?: () => void
  onStopTrufflehog?: () => void
  onDownloadTrufflehogJSON?: () => void
  onToggleTrufflehogLogs?: () => void
  trufflehogStatus?: TrufflehogStatus
  hasTrufflehogData?: boolean
  isTrufflehogLogsOpen?: boolean

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
  onPauseTrufflehog,
  onResumeTrufflehog,
  onStopTrufflehog,
  onDownloadTrufflehogJSON,
  onToggleTrufflehogLogs,
  trufflehogStatus = 'idle',
  hasTrufflehogData = false,
  isTrufflehogLogsOpen = false,

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

  // TruffleHog derived state
  const isTHBusy = trufflehogStatus === 'running' || trufflehogStatus === 'starting' || trufflehogStatus === 'pausing'
  const isTHStopping = trufflehogStatus === 'stopping'
  const isTHPausing = trufflehogStatus === 'pausing'
  const isTHRunning = isTHBusy || isTHStopping
  const isTHPaused = trufflehogStatus === 'paused'
  const isTHActive = isTHRunning || isTHPaused

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
          <p className={styles.cardRequirement}>
            Requires a GitHub Access Token in{' '}
            <Link href={SETTINGS_KEYS_HREF} style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
              Global Settings
            </Link>
            . Mandatory even for public repositories: without one GitHub allows 60 requests
            per hour, which this scan exhausts immediately. Private repositories additionally
            need a token with repo scope.
          </p>
          {!hasGithubToken && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 12px',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              borderRadius: '6px',
            }}>
              <AlertTriangle size={14} style={{ color: '#f59e0b', flexShrink: 0 }} />
              <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                GitHub Access Token required.{' '}
                <Link href={SETTINGS_KEYS_HREF} style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                  Global Settings
                </Link>
              </span>
            </div>
          )}
          <div className={styles.cardActions}>
            {isGHPaused ? (
              <button
                className={styles.resumeButton}
                onClick={onResumeGithubHunt}
                disabled={!hasGithubToken || scanBlocked}
                title={scanBlocked ? blockedTitle : !hasGithubToken ? 'GitHub token required' : 'Resume GitHub Hunt'}
              >
                <Play size={12} />
                <span>Resume</span>
              </button>
            ) : (
              <button
                className={styles.startButton}
                onClick={onStartGithubHunt}
                disabled={!hasGithubToken || isGHRunning || (!hasReconData && !isGHPaused) || scanBlocked}
                title={scanBlocked ? blockedTitle : !hasGithubToken ? 'GitHub token required' : !hasReconData ? 'Run recon first' : isGHRunning ? 'In progress...' : 'Start GitHub Hunt'}
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

        {/* TruffleHog Scanner Card */}
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Search size={18} className={styles.cardIcon} />
            <h3 className={styles.cardTitle}>TruffleHog Scanner</h3>
            <WikiInfoButton target="Trufflehog" title="TruffleHog Secret Scanning wiki" />
            <StatusBadge status={trufflehogStatus} />
          </div>
          <p className={styles.cardDescription}>
            Deep secret scanning with 700+ detectors and optional verification against live APIs.
          </p>
          <p className={styles.cardRequirement}>
            Requires a GitHub Access Token in{' '}
            <Link href={SETTINGS_KEYS_HREF} style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
              Global Settings
            </Link>
            . Mandatory even for public repositories: without one GitHub allows 60 requests
            per hour, which this scan exhausts immediately. Private repositories additionally
            need a token with repo scope.
          </p>
          {!hasGithubToken && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 12px',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              borderRadius: '6px',
            }}>
              <AlertTriangle size={14} style={{ color: '#f59e0b', flexShrink: 0 }} />
              <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                GitHub Access Token required.{' '}
                <Link href={SETTINGS_KEYS_HREF} style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                  Global Settings
                </Link>
              </span>
            </div>
          )}
          <div className={styles.cardActions}>
            {isTHPaused ? (
              <button
                className={styles.resumeButton}
                onClick={onResumeTrufflehog}
                disabled={!hasGithubToken || scanBlocked}
                title={scanBlocked ? blockedTitle : !hasGithubToken ? 'GitHub token required' : 'Resume TruffleHog'}
              >
                <Play size={12} />
                <span>Resume</span>
              </button>
            ) : (
              <button
                className={styles.startButton}
                onClick={onStartTrufflehog}
                disabled={!hasGithubToken || isTHRunning || (!hasReconData && !isTHPaused) || scanBlocked}
                title={scanBlocked ? blockedTitle : !hasGithubToken ? 'GitHub token required' : !hasReconData ? 'Run recon first' : isTHRunning ? 'In progress...' : 'Start TruffleHog'}
              >
                {isTHRunning ? (
                  <Loader2 size={12} className={styles.spinner} />
                ) : (
                  <Play size={12} />
                )}
                <span>{isTHPausing ? 'Pausing...' : isTHBusy ? 'Running...' : isTHStopping ? 'Stopping...' : 'Start'}</span>
              </button>
            )}

            {isTHBusy && (
              <button
                className={styles.pauseButton}
                onClick={onPauseTrufflehog}
                disabled={isTHPausing}
                title="Pause"
              >
                {isTHPausing ? <Loader2 size={12} className={styles.spinner} /> : <Pause size={12} />}
                <span>Pause</span>
              </button>
            )}

            {isTHActive && (
              <button
                className={styles.stopButton}
                onClick={onStopTrufflehog}
                disabled={isTHStopping}
                title="Stop"
              >
                <Square size={12} />
                <span>Stop</span>
              </button>
            )}

            <button
              className={`${styles.logsButton} ${isTrufflehogLogsOpen ? styles.logsButtonActive : ''}`}
              onClick={onToggleTrufflehogLogs}
              disabled={!isTHActive}
              title="View Logs"
            >
              <Terminal size={12} />
              <span>Logs</span>
            </button>

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
                title="Configure the target org, repos and scan options in project settings"
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
