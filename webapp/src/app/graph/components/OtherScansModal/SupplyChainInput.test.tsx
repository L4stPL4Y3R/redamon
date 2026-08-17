/**
 * Supply Chain Scanner input, including the org batch that moved here from the
 * JS Recon tab of Project Settings (where it sat next to the unrelated L2
 * supply-chain recon phase and could not be found).
 *
 * The two things that must not regress: 'org' is an ACTION, not an input, so it
 * must never be persisted as the project's scan input mode, and Start must not
 * think the project has something to scan while it is selected.
 *
 * The queue button now lives in the CARD's action row (it replaces a Start that
 * can never be enabled in this mode), while the account it acts on lives in this
 * component. That seam is the thing most likely to break silently, so the tests
 * that press the button render the real modal rather than a stand-in harness.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

const toastSuccess = vi.fn()
const alertError = vi.fn()

vi.mock('@/components/ui', () => ({
  useToast: () => ({ success: (...a: unknown[]) => toastSuccess(...a), info: vi.fn(), error: vi.fn() }),
  // The card is rendered for real; only its chrome is stubbed.
  Modal: ({ isOpen, children }: { isOpen: boolean; children: React.ReactNode }) =>
    isOpen ? <div>{children}</div> : null,
  WikiInfoButton: () => null,
}))
vi.mock('@/components/ui/AlertModal/AlertModal', () => ({
  useAlertModal: () => ({ alertError: (...a: unknown[]) => alertError(...a) }),
}))

import SupplyChainInput from './SupplyChainInput'
import { OtherScansModal } from './OtherScansModal'

const PROJECT = {
  supplyChainInputMode: 'upload',
  supplyChainRepoUrl: '',
  supplyChainRepoRef: '',
}

let fetchMock: ReturnType<typeof vi.fn>

/** Routes the component's loads; per-test overrides go through mockImplementationOnce. */
function defaultFetch(url: string) {
  if (String(url).includes('/upload')) return Promise.resolve({ ok: true, json: async () => ({ files: [] }) })
  return Promise.resolve({ ok: true, json: async () => PROJECT })
}

beforeEach(() => {
  vi.clearAllMocks()
  fetchMock = vi.fn().mockImplementation((url: string) => defaultFetch(url))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

/** Renders the whole Supply-Chain card, so the queue button under test is the
 *  one the operator actually presses. */
const openOrgMode = async () => {
  render(
    <OtherScansModal
      isOpen
      onClose={() => {}}
      hasReconData
      hasGithubToken
      projectId="p1"
      // TruffleHog renders one row per configured source; give it exactly one so
      // the Start-button counts below stay about the Supply-Chain card.
      trufflehogProfiles={[{ id: 'p-docker', source: 'docker', label: '', config: { images: ['nginx:1.25'] } }]}
    />
  )
  await waitFor(() => expect(screen.getByText('GitHub organization')).toBeTruthy())
  fireEvent.click(screen.getByText('GitHub organization'))
  await waitFor(() => expect(screen.getByLabelText('Organization or user')).toBeTruthy())
}

/** Buttons carry a <span> label; find them by that visible text. */
function buttonsByLabel(label: string): HTMLButtonElement[] {
  return screen.getAllByRole('button').filter(b => b.textContent?.includes(label)) as HTMLButtonElement[]
}

describe('SupplyChainInput - org batch', () => {
  test('offers the organization mode alongside upload and repository', async () => {
    render(<SupplyChainInput projectId="p1" />)
    await waitFor(() => expect(screen.getByText('Uploaded SBOM / lockfile')).toBeTruthy())
    expect(screen.getByText('GitHub repository')).toBeTruthy()
    expect(screen.getByText('GitHub organization')).toBeTruthy()
  })

  // Persisting 'org' would leave the project with an input mode no scan can run,
  // so returning to the card would find nothing to scan.
  test('selecting it never writes org as the project input mode', async () => {
    await openOrgMode()
    const puts = fetchMock.mock.calls.filter(c => c[1]?.method === 'PUT')
    expect(puts).toHaveLength(0)
  })

  test('queues the batch and reports how many repos it covers', async () => {
    await openOrgMode()
    fireEvent.change(screen.getByLabelText('Organization or user'), { target: { value: 'acme-corp' } })
    fetchMock.mockImplementationOnce(() =>
      Promise.resolve({ ok: true, json: async () => ({ totalItems: 12 }) }))
    fireEvent.click(screen.getByText('Queue org batch'))

    await waitFor(() => {
      const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST')
      expect(post).toBeTruthy()
      expect(String(post![0])).toBe('/api/projects/p1/supply-chain-batch')
      expect(JSON.parse(post![1].body as string)).toEqual({ org: 'acme-corp' })
    })
    await waitFor(() => expect(toastSuccess).toHaveBeenCalledWith(expect.stringContaining('12 repo scans')))
  })

  test('a rejected batch surfaces the server reason instead of a silent no-op', async () => {
    await openOrgMode()
    fireEvent.change(screen.getByLabelText('Organization or user'), { target: { value: 'acme-corp' } })
    fetchMock.mockImplementationOnce(() =>
      Promise.resolve({ ok: false, status: 403, json: async () => ({ error: 'token lacks org scope' }) }))
    fireEvent.click(screen.getByText('Queue org batch'))
    await waitFor(() => expect(alertError).toHaveBeenCalledWith('token lacks org scope', 'Supply-chain org batch'))
  })

  test('an invalid org name cannot be queued', async () => {
    await openOrgMode()
    fireEvent.change(screen.getByLabelText('Organization or user'), { target: { value: 'not a valid org!' } })
    await waitFor(() => expect(screen.getByText(/letters, digits and dashes/)).toBeTruthy())
    fireEvent.click(screen.getByText('Queue org batch'))
    expect(fetchMock.mock.calls.find(c => c[1]?.method === 'POST')).toBeUndefined()
  })

  // GitHub Enterprise: the field takes a URL as well as a name. Which HOSTS are
  // reachable is the server's decision (it owns the operator's allowlist), so the
  // client sends a well-formed target and surfaces the server's refusal.
  test('a GitHub Enterprise org URL is accepted and sent verbatim', async () => {
    await openOrgMode()
    fireEvent.change(screen.getByLabelText('Organization or user'),
      { target: { value: 'https://ghe.example.com/orgs/acme-corp' } })
    expect(screen.queryByText(/letters, digits and dashes/)).toBeNull()
    fetchMock.mockImplementationOnce(() =>
      Promise.resolve({ ok: true, json: async () => ({ totalItems: 3, org: 'acme-corp', host: 'ghe.example.com' }) }))
    fireEvent.click(screen.getByText('Queue org batch'))

    await waitFor(() => {
      const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST')
      expect(post).toBeTruthy()
      expect(JSON.parse(post![1].body as string)).toEqual({ org: 'https://ghe.example.com/orgs/acme-corp' })
    })
    // The toast names the host the batch actually ran against.
    await waitFor(() => expect(toastSuccess).toHaveBeenCalledWith(
      expect.stringContaining('acme-corp on ghe.example.com')))
  })

  test('an unconfigured host is refused by the server and the reason is shown', async () => {
    await openOrgMode()
    fireEvent.change(screen.getByLabelText('Organization or user'),
      { target: { value: 'https://ghe.example.com/orgs/acme-corp' } })
    fetchMock.mockImplementationOnce(() => Promise.resolve({
      ok: false, status: 400,
      json: async () => ({ error: "'ghe.example.com' is not a configured GitHub host." }),
    }))
    fireEvent.click(screen.getByText('Queue org batch'))
    await waitFor(() => expect(alertError).toHaveBeenCalledWith(
      "'ghe.example.com' is not a configured GitHub host.", 'Supply-chain org batch'))
  })

  test('a repository URL is not an account and cannot be queued', async () => {
    await openOrgMode()
    fireEvent.change(screen.getByLabelText('Organization or user'),
      { target: { value: 'https://github.com/acme-corp/some-repo' } })
    await waitFor(() => expect(screen.getByText(/letters, digits and dashes/)).toBeTruthy())
    fireEvent.click(screen.getByText('Queue org batch'))
    expect(fetchMock.mock.calls.find(c => c[1]?.method === 'POST')).toBeUndefined()
  })

  // Start can never be enabled in org mode (this queues N scans rather than
  // running the project's single input), so the card swaps it for the queue
  // action instead of showing a button that is permanently dead.
  test('the card swaps its Start button for the queue action in org mode', async () => {
    await openOrgMode()
    expect(buttonsByLabel('Queue org batch')).toHaveLength(1)
    // GitHub Hunt and TruffleHog keep theirs; only Supply-Chain's is replaced.
    expect(buttonsByLabel('Start')).toHaveLength(2)
  })

  test('the queue button stays disabled until an account is typed', async () => {
    await openOrgMode()
    expect(buttonsByLabel('Queue org batch')[0].disabled).toBe(true)
    fireEvent.change(screen.getByLabelText('Organization or user'), { target: { value: 'acme-corp' } })
    await waitFor(() => expect(buttonsByLabel('Queue org batch')[0].disabled).toBe(false))
  })

  // Leaving org mode must give Start back, or the card would be stuck with an
  // action that no longer matches the selected source.
  test('choosing another source restores Start', async () => {
    await openOrgMode()
    fireEvent.click(screen.getByText('Uploaded SBOM / lockfile'))
    await waitFor(() => expect(buttonsByLabel('Queue org batch')).toHaveLength(0))
    expect(buttonsByLabel('Start')).toHaveLength(3)
  })

  // Start runs the project's single configured input; in org mode there is none.
  test('reports no runnable input while the org mode is selected', async () => {
    const onAvail = vi.fn()
    render(<SupplyChainInput projectId="p1" onInputAvailabilityChange={onAvail} />)
    await waitFor(() => expect(screen.getByText('GitHub organization')).toBeTruthy())
    fireEvent.click(screen.getByText('GitHub organization'))
    await waitFor(() => expect(onAvail).toHaveBeenLastCalledWith(false))
  })
})
