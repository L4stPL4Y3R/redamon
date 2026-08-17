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

// TruffleHog is run-keyed: the card renders one row per CONFIGURED SOURCE, each
// with its own Start/Stop/Logs. Two profiles here so the tests cover the
// multi-row shape rather than accidentally passing on a single-row special case.
const TRUFFLEHOG_PROFILES = [
  { id: 'p-docker', source: 'docker', label: '', config: { images: ['nginx:1.25'] } },
  { id: 'p-github', source: 'github', label: '', config: { orgs: ['acme'] } },
]

const baseProps = {
  isOpen: true,
  onClose: () => {},
  hasReconData: true,
  hasGithubToken: true,
  githubHuntStatus: 'idle' as const,
  trufflehogProfiles: TRUFFLEHOG_PROFILES,
  trufflehogRunsBySource: {},
  hasGithubHuntData: true,
  hasTrufflehogData: true,
  hasSupplyChainData: true,
}

// GitHub Hunt + Supply Chain, plus one TruffleHog row per configured source.
const CARDS = 2 + TRUFFLEHOG_PROFILES.length

describe('OtherScansModal — past-version / activation gating', () => {
  test('every card is rendered with its own Start and Download', () => {
    render(<OtherScansModal {...baseProps} viewingPastVersion={false} isActivatingVersion={false} />)
    expect(buttonsByLabel('Start')).toHaveLength(CARDS)
    // The TruffleHog JSON download is project-level (one file), so there are
    // three Download buttons for four Start buttons.
    expect(buttonsByLabel('Download')).toHaveLength(3)
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
    expect(downloads).toHaveLength(3)
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
        supplyChainStatus={'paused' as const}
        viewingPastVersion={true}
      />
    )
    // TruffleHog has no pause/resume any more (dropped with the multi-source
    // migration, matching ai_attack), so only the two pausable cards offer it.
    const resumes = buttonsByLabel('Resume')
    expect(resumes).toHaveLength(2)
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


// The multi-source behaviour the card exists for.
describe('OtherScansModal — TruffleHog sources', () => {
  test('one row per configured source, each with its own Start', () => {
    render(<OtherScansModal {...baseProps} viewingPastVersion={false} isActivatingVersion={false} />)
    expect(screen.getByText('Docker registry')).toBeTruthy()
    expect(screen.getByText('GitHub')).toBeTruthy()
  })

  test('a running source shows Stop while the other still shows Start', () => {
    // The whole point of run-keying: stopping Docker must not touch GitHub.
    render(
      <OtherScansModal
        {...baseProps}
        viewingPastVersion={false}
        isActivatingVersion={false}
        trufflehogRunsBySource={{ docker: { status: 'running' as const } }}
      />
    )
    expect(buttonsByLabel('Stop')).toHaveLength(1)
    const running = buttonsByLabel('Running...')
    expect(running).toHaveLength(1)
    expect(running[0].disabled).toBe(true)
  })

  test('a source missing its mandatory credential cannot be started', () => {
    render(
      <OtherScansModal
        {...baseProps}
        viewingPastVersion={false}
        isActivatingVersion={false}
        trufflehogProfiles={[{
          ...TRUFFLEHOG_PROFILES[1],
          missingCredentials: [{ settingsKey: 'trufflehogGithubToken', label: 'TruffleHog GitHub Token' }],
        }]}
      />
    )
    const start = buttonsByLabel('Start').find(b => /GitHub Token/.test(b.title))
    expect(start?.disabled).toBe(true)
    expect(screen.getByText(/TruffleHog GitHub Token required/)).toBeTruthy()
  })

  test('an incompletely configured source cannot be started', () => {
    render(
      <OtherScansModal
        {...baseProps}
        viewingPastVersion={false}
        isActivatingVersion={false}
        trufflehogProfiles={[{
          ...TRUFFLEHOG_PROFILES[0],
          config: {},
          validationErrors: ['Docker: set at least one image or a namespace'],
        }]}
      />
    )
    const start = buttonsByLabel('Start').find(b => /not fully configured/.test(b.title))
    expect(start?.disabled).toBe(true)
  })

  test('with no sources configured the card points at project settings', () => {
    render(
      <OtherScansModal
        {...baseProps}
        viewingPastVersion={false}
        isActivatingVersion={false}
        trufflehogProfiles={[]}
      />
    )
    // (projectId is omitted deliberately: with it, the Supply-Chain input renders
    // and needs a ToastProvider, which is not what this test is about.)
    expect(screen.getByText(/No sources configured/)).toBeTruthy()
    // ...and TruffleHog offers no Start at all until a source is added.
    expect(buttonsByLabel('Start').length).toBe(2)
  })
})
