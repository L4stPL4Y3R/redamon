'use client'

import { Download, Loader2, Shield, Github, Pause, Square } from 'lucide-react'
import type { ScanControls } from '@/hooks/useScanControls'
import styles from '@/app/graph/components/GraphToolbar/GraphToolbar.module.css'

/**
 * The graph toolbar's scan cluster, usable outside the graph page.
 *
 * It imports GraphToolbar.module.css on purpose rather than restyling: these
 * are meant to be the SAME buttons, and a second stylesheet would drift from
 * the original the first time either is touched.
 *
 * State comes from useScanControls, which owns the polling. This component is
 * presentational.
 */
export function ScanActions({
  scans,
  showReconDownload = true,
  disabledReason = '',
}: {
  scans: ScanControls
  /** The recon download; off where the surface already has its own. */
  showReconDownload?: boolean
  /** Non-empty disables every action and explains why (e.g. a past version). */
  disabledReason?: string
}) {
  const { gvm, githubHunt, trufflehog } = scans
  const blocked = Boolean(disabledReason)

  return (
    <>
      {showReconDownload && (
        <button
          type="button"
          className={styles.downloadButton}
          onClick={scans.downloadReconJSON}
          disabled={!scans.hasReconData || blocked}
          title={disabledReason || (scans.hasReconData ? 'Download Recon JSON' : 'No data available')}
        >
          <Download size={14} />
        </button>
      )}

      <div className={styles.actionGroup}>
        <button
          type="button"
          className={`${styles.gvmButton} ${gvm.isActive ? styles.gvmButtonActive : ''}`}
          onClick={() => void (gvm.isPaused ? gvm.resumeGvm() : gvm.startGvm())}
          disabled={blocked || gvm.isRunning}
          title={
            disabledReason ||
            (gvm.isStopping ? 'Stopping...'
              : gvm.isRunning ? 'GVM scan in progress...'
              : gvm.isPaused ? 'Resume GVM Scan'
              : 'Start GVM Vulnerability Scan')
          }
        >
          {gvm.isRunning ? <Loader2 size={14} className={styles.spinner} /> : <Shield size={14} />}
          <span>
            {gvm.isStopping ? 'Stopping...'
              : gvm.isPausing ? 'Pausing...'
              : gvm.isBusy ? 'Scanning...'
              : gvm.isPaused ? 'Resume'
              : 'GVM Scan'}
          </span>
        </button>

        {gvm.isBusy && (
          <button
            type="button"
            className={styles.pauseButton}
            onClick={() => void gvm.pauseGvm()}
            disabled={gvm.isPausing}
            title={gvm.isPausing ? 'Pausing...' : 'Pause GVM Scan'}
          >
            <Pause size={14} />
          </button>
        )}

        {gvm.isActive && (
          <button
            type="button"
            className={styles.stopButton}
            onClick={() => void gvm.stopGvm()}
            disabled={gvm.isStopping}
            title="Stop GVM Scan"
          >
            <Square size={14} />
          </button>
        )}

        <button
          type="button"
          className={styles.downloadButton}
          onClick={gvm.download}
          disabled={!gvm.hasData || gvm.isRunning || blocked}
          title={disabledReason || (gvm.hasData ? 'Download GVM JSON' : 'No data available')}
        >
          <Download size={14} />
        </button>
      </div>

      <div className={styles.actionGroup}>
        <button
          type="button"
          className={`${styles.githubHuntButton} ${(githubHunt.isActive || trufflehog.isActive) ? styles.githubHuntButtonActive : ''}`}
          onClick={scans.toggleOtherScans}
          title="Other Scans (GitHub Hunt, Secret Multiscanner, Supply Chain)"
        >
          {(githubHunt.isRunning || trufflehog.isRunning)
            ? <Loader2 size={14} className={styles.spinner} />
            : <Github size={14} />}
          <span>{(githubHunt.isBusy || trufflehog.isRunning) ? 'Scanning...' : 'Other Scans'}</span>
        </button>
      </div>
    </>
  )
}
