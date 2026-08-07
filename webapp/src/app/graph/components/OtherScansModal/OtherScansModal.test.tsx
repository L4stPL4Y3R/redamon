/**
 * Scan Timeline alignment — GitHub-Hunt / TruffleHog / Supply-Chain on a past version.
 *
 * These scans write the LIVE/active graph, and their downloadable JSON is always
 * the latest scan. So when a saved (past) version is being viewed, or a version
 * activation is swapping the graph, no scan may start/resume and the JSON download
 * is disabled (it would not match the graph on screen).
 *
 * The Supply-Chain card was added to this modal after these tests were written,
 * so they asserted "exactly 2" Start/Download buttons and that EVERY Start is
 * enabled on a live version. Both stopped holding: there are three cards now,
 * and Supply-Chain has a second, independent gate (an SBOM/lockfile or repo must
 * be chosen first). The gating those tests actually exist to protect is
 * unchanged and is asserted per-card below.
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
  hasSupplyChainData: true,
}

const CARDS = 3 // GitHub Hunt + TruffleHog + Supply Chain

describe('OtherScansModal — past-version / activation gating', () => {
  test('every card is rendered with its own Start and Download', () => {
    render(<OtherScansModal {...baseProps} viewingPastVersion={false} isActivatingVersion={false} />)
    expect(buttonsByLabel('Start')).toHaveLength(CARDS)
    expect(buttonsByLabel('Download')).toHaveLength(CARDS)
  })

  test('on a live version nothing is blocked by the version gate', () => {
    render(<OtherScansModal {...baseProps} viewingPastVersion={false} isActivatingVersion={false} />)
    // Supply-Chain has a SECOND gate - no SBOM/repo chosen yet - so it stays
    // disabled here for a reason that has nothing to do with versioning. Its
    // title says which gate is active, so assert on that rather than skipping it.
    for (const b of buttonsByLabel('Start')) {
      expect(b.title).not.toMatch(/saved version|activating/i)
    }
    for (const b of buttonsByLabel('Download')) expect(b.disabled).toBe(false)
  })

  test('viewing a past version disables every Start and Download', () => {
    render(<OtherScansModal {...baseProps} viewingPastVersion={true} isActivatingVersion={false} />)
    const starts = buttonsByLabel('Start')
    const downloads = buttonsByLabel('Download')
    expect(starts).toHaveLength(CARDS)
    expect(downloads).toHaveLength(CARDS)
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
        supplyChainStatus={'paused' as const}
        viewingPastVersion={true}
      />
    )
    const resumes = buttonsByLabel('Resume')
    expect(resumes).toHaveLength(CARDS)
    for (const b of resumes) expect(b.disabled).toBe(true)
  })

  // The Supply-Chain scan writes Package / MalPackageFinding nodes into the LIVE
  // graph exactly like the other two, so it must never be startable from a saved
  // view - the results would not belong to the graph on screen.
  test('the Supply-Chain card is version-gated like the others', () => {
    render(<OtherScansModal {...baseProps} viewingPastVersion={true} />)
    const starts = buttonsByLabel('Start')
    expect(starts.some(b => /saved version|activating/i.test(b.title))).toBe(true)
    for (const b of starts) expect(b.disabled).toBe(true)
  })
})
