/**
 * Deep link from a project-settings section straight to the scan it configures.
 *
 * Project settings can only configure a scan; every scan is STARTED from the
 * graph page's toolbar modals. So "Start to Scan" in a section header saves and
 * then hands off to /graph with the matching modal already open, rather than
 * leaving the operator to find the button that opens it.
 *
 * Producer (the settings sections) and consumer (the graph page) both go through
 * here: an href built by hand would silently open no modal at all the day the
 * param is renamed. Unknown values parse to null - the graph page then behaves
 * exactly as if no param were present.
 */

/** GVM has its own confirm modal; the other three scans share Other Scans. */
export type ScanModal = 'gvm' | 'other'

const SCAN_MODALS = new Set<string>(['gvm', 'other'])

export function graphScanHref(projectId: string, scan: ScanModal): string {
  return `/graph?project=${encodeURIComponent(projectId)}&scan=${scan}`
}

export function parseScanModal(raw: string | null | undefined): ScanModal | null {
  if (!raw) return null
  return SCAN_MODALS.has(raw) ? raw as ScanModal : null
}
