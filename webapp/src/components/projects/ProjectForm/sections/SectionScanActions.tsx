'use client'

import { Save, Play, Loader2 } from 'lucide-react'
import styles from '../ProjectForm.module.css'

interface SectionScanActionsProps {
  /** The header's Update Settings, in place: same save, and it leaves for the
   *  graph page exactly as that button does. */
  onUpdateSettings: () => void
  /** Save first (if there is anything to save), then open this scan's modal. */
  onStartScan: () => void
  /** What the scan button will open, for its tooltip. */
  scanLabel: string
  isDirty: boolean
  isSubmitting: boolean
}

/**
 * Update Settings + Start to Scan, on the header of the section that configures
 * that scan. Scans are started from the graph page, so configuring one here used
 * to mean saving at the top of the page, then finding the toolbar button that
 * opens the matching modal; these two do it from where the settings are.
 */
export function SectionScanActions({
  onUpdateSettings, onStartScan, scanLabel, isDirty, isSubmitting,
}: SectionScanActionsProps) {
  // The whole header is the collapse toggle, so a click that reaches it would
  // fold the section shut behind the action that was just taken.
  const act = (run: () => void) => (e: React.MouseEvent) => {
    e.stopPropagation()
    run()
  }

  return (
    <div className={styles.sectionHeaderActions}>
      <button
        type="button"
        className={styles.sectionHeaderButton}
        onClick={act(onUpdateSettings)}
        disabled={isSubmitting || !isDirty}
        title={isDirty
          ? 'Save all changes and open the graph page - the header button, from here'
          : 'No unsaved changes'}
      >
        {isSubmitting ? <Loader2 size={12} className={styles.spinner} /> : <Save size={12} />}
        Update Settings
      </button>
      <button
        type="button"
        className={`${styles.sectionHeaderButton} ${styles.sectionHeaderButtonPrimary}`}
        onClick={act(onStartScan)}
        disabled={isSubmitting}
        title={`Save the settings and open ${scanLabel} on the graph page`}
      >
        <Play size={12} />
        Start to Scan
      </button>
    </div>
  )
}
