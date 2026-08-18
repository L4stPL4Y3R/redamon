/**
 * Deep links into a PROJECT's settings form (not the global /settings page -
 * that one lives in settingsLinks.ts).
 *
 * ProjectForm opens on the 'target' tab, so a bare /projects/<id>/settings href
 * drops the operator on an unrelated screen and leaves them to hunt for the
 * section the card sent them to configure.
 *
 * An anchor names the SECTION. The tab is carried alongside it because the
 * section is not in the DOM until its tab is selected, so ProjectForm has to
 * switch tabs before it can scroll.
 *
 * Both halves are guarded by projectSettingsLinks.test.ts: the tab must be a
 * real id in ProjectForm's TAB_GROUPS, and the anchor must exist as an element
 * id on a section component. Drift in either direction is a SILENT no-op at
 * runtime (unknown anchor = no scroll), which is exactly the broken behaviour
 * this module exists to prevent.
 */

export const PROJECT_SECTION_ANCHORS = {
  'github-secret-hunting': { tab: 'integrations' },
  'trufflehog-scanner': { tab: 'integrations' },
  'supply-chain-scanner': { tab: 'integrations' },
} as const

export type ProjectSectionAnchor = keyof typeof PROJECT_SECTION_ANCHORS

/** Href for one section of a project's settings form. */
export function projectSettingsHref(projectId: string, anchor: ProjectSectionAnchor): string {
  return `/projects/${encodeURIComponent(projectId)}/settings#${anchor}`
}

/** The tab an anchor lives on, or null when the anchor is not one of ours. */
export function tabForAnchor(anchor: string): string | null {
  const entry = (PROJECT_SECTION_ANCHORS as Record<string, { tab: string } | undefined>)[anchor]
  return entry ? entry.tab : null
}
