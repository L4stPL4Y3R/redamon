/**
 * Supply Chain Scanner input, including the org batch that moved here from the
 * JS Recon tab of Project Settings (where it sat next to the unrelated L2
 * supply-chain recon phase and could not be found).
 *
 * The two things that must not regress: 'org' is an ACTION, not an input, so it
 * must never be persisted as the project's scan input mode, and Start must not
 * think the project has something to scan while it is selected.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

const toastSuccess = vi.fn()
const alertError = vi.fn()

vi.mock('@/components/ui', () => ({
  useToast: () => ({ success: (...a: unknown[]) => toastSuccess(...a), info: vi.fn(), error: vi.fn() }),
}))
vi.mock('@/components/ui/AlertModal/AlertModal', () => ({
  useAlertModal: () => ({ alertError: (...a: unknown[]) => alertError(...a) }),
}))

import SupplyChainInput from './SupplyChainInput'

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

const openOrgMode = async () => {
  render(<SupplyChainInput projectId="p1" />)
  await waitFor(() => expect(screen.getByText('GitHub organization')).toBeTruthy())
  fireEvent.click(screen.getByText('GitHub organization'))
  await waitFor(() => expect(screen.getByLabelText('Organization or user')).toBeTruthy())
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

  // Start runs the project's single configured input; in org mode there is none.
  test('reports no runnable input while the org mode is selected', async () => {
    const onAvail = vi.fn()
    render(<SupplyChainInput projectId="p1" onInputAvailabilityChange={onAvail} />)
    await waitFor(() => expect(screen.getByText('GitHub organization')).toBeTruthy())
    fireEvent.click(screen.getByText('GitHub organization'))
    await waitFor(() => expect(onAvail).toHaveBeenLastCalledWith(false))
  })
})
