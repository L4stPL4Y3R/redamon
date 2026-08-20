/**
 * The "configure this in project settings" links inside Other Scans.
 *
 * From /graph the plain href works: it is a real route change, the graph page
 * unmounts and the modal goes with it. Opened from the project settings page
 * itself the SAME href only swaps the hash - no navigation, no unmount - so the
 * gear looked dead: the modal stayed up and the form never moved. The host page
 * therefore gets to handle the jump itself via onOpenProjectSettings, and the
 * link must yield to it (preventDefault) rather than both firing.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'

vi.mock('@/components/ui', () => ({
  useToast: () => ({ success: vi.fn(), info: vi.fn(), error: vi.fn() }),
  Modal: ({ isOpen, children }: { isOpen: boolean; children: React.ReactNode }) =>
    isOpen ? <div>{children}</div> : null,
  WikiInfoButton: () => null,
}))
vi.mock('@/components/ui/AlertModal/AlertModal', () => ({
  useAlertModal: () => ({ alertError: vi.fn() }),
}))

import { OtherScansModal } from './OtherScansModal'

const TRUFFLEHOG_PROFILES = [
  { id: 'p-docker', source: 'docker', label: '', config: { images: ['nginx:1.25'] } },
]

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderModal(extra: Record<string, unknown> = {}) {
  return render(
    <OtherScansModal
      isOpen
      onClose={() => {}}
      hasReconData
      hasGithubToken
      projectId="p1"
      trufflehogProfiles={TRUFFLEHOG_PROFILES}
      {...extra}
    />
  )
}

const gear = (label: string) => screen.getByLabelText(label) as HTMLAnchorElement

describe('Other Scans - project settings links', () => {
  test('without a host handler the gears are plain deep links', () => {
    renderModal()
    expect(gear('Configure Secret Multiscanner in project settings').getAttribute('href'))
      .toBe('/projects/p1/settings#trufflehog-scanner')
    expect(gear('Configure GitHub Secret Hunt in project settings').getAttribute('href'))
      .toBe('/projects/p1/settings#github-secret-hunting')
    expect(gear('Configure Supply Chain Scanner in project settings').getAttribute('href'))
      .toBe('/projects/p1/settings#supply-chain-scanner')
  })

  test('a host handler takes over the click and the navigation is cancelled', () => {
    const onOpenProjectSettings = vi.fn()
    renderModal({ onOpenProjectSettings })

    const notDefaulted = fireEvent.click(gear('Configure Secret Multiscanner in project settings'))
    expect(onOpenProjectSettings).toHaveBeenCalledWith('trufflehog-scanner')
    expect(notDefaulted).toBe(false)  // preventDefault was called
  })

  test('every gear reports its own section', () => {
    const onOpenProjectSettings = vi.fn()
    renderModal({ onOpenProjectSettings })

    fireEvent.click(gear('Configure GitHub Secret Hunt in project settings'))
    fireEvent.click(gear('Configure Supply Chain Scanner in project settings'))
    expect(onOpenProjectSettings.mock.calls.map(c => c[0]))
      .toEqual(['github-secret-hunting', 'supply-chain-scanner'])
  })
})
