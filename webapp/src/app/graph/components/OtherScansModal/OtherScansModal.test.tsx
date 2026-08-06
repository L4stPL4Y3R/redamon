/**
 * Scan Timeline alignment — GVM/GitHub-Hunt/TruffleHog on a past version.
 *
 * These scans write the LIVE/active graph, and their downloadable JSON is always
 * the latest scan. So when a saved (past) version is being viewed, or a version
 * activation is swapping the graph, no scan may start/resume and the JSON download
 * is disabled (it would not match the graph on screen).
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { OtherScansModal } from './OtherScansModal'

afterEach(cleanup)

/** Buttons carry a <span> label; find them by that visible text. */
function buttonsByLabel(label: string): HTMLButtonElement[] {
  return screen.getAllByRole('button').filter(b => b.textContent?.includes(label)) as HTMLButtonElement[]
}

const baseProps = {
  isOpen: true,
  onClose: () => {},
  hasReconData: true,
  hasGithubToken: true,
  githubHuntStatus: 'idle' as const,
  trufflehogStatus: 'idle' as const,
  hasGithubHuntData: true,
  hasTrufflehogData: true,
}

describe('OtherScansModal — past-version / activation gating', () => {
  test('with a live/current version, Start and Download are enabled', () => {
    render(<OtherScansModal {...baseProps} viewingPastVersion={false} isActivatingVersion={false} />)
    for (const b of buttonsByLabel('Start')) expect(b.disabled).toBe(false)
    for (const b of buttonsByLabel('Download')) expect(b.disabled).toBe(false)
  })

  test('viewing a past version disables every Start and Download', () => {
    render(<OtherScansModal {...baseProps} viewingPastVersion={true} isActivatingVersion={false} />)
    const starts = buttonsByLabel('Start')
    const downloads = buttonsByLabel('Download')
    expect(starts.length).toBe(2) // GitHub Hunt + TruffleHog
    expect(downloads.length).toBe(2)
    for (const b of starts) expect(b.disabled).toBe(true)
    for (const b of downloads) expect(b.disabled).toBe(true)
  })

  test('an in-flight activation disables Start (Download stays governed by view, not swap)', () => {
    render(<OtherScansModal {...baseProps} viewingPastVersion={false} isActivatingVersion={true} />)
    for (const b of buttonsByLabel('Start')) expect(b.disabled).toBe(true)
    // Download reads a project-level file on disk, independent of the graph swap.
    for (const b of buttonsByLabel('Download')) expect(b.disabled).toBe(false)
  })

  test('a paused scan shows Resume, and it too is blocked on a past version', () => {
    render(
      <OtherScansModal
        {...baseProps}
        githubHuntStatus={'paused' as const}
        trufflehogStatus={'paused' as const}
        viewingPastVersion={true}
      />
    )
    const resumes = buttonsByLabel('Resume')
    expect(resumes.length).toBe(2)
    for (const b of resumes) expect(b.disabled).toBe(true)
  })
})
