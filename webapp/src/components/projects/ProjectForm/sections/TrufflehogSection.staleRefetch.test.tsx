/**
 * TruffleHog section: a late profiles refetch must not discard what was typed.
 *
 * Regression, found while proving the `gitlab` source end to end and confirmed
 * from a Playwright network trace of the failure. The card PATCHes its whole
 * config on every change. Two edits in a row produced these two bodies:
 *
 *     PATCH {"config":{"groupIds":["<id>"]}}                       (37 bytes)
 *     PATCH {"config":{"excludeRepos":["<group>/b*"]}}             (59 bytes)
 *
 * The second one merged onto an EMPTY config instead of onto the first, so the
 * profile was saved without `groupIds` at all. Between the two PATCHes sat a
 * `GET /profiles` whose response still carried the config as it was before the
 * first edit; the card reset its local state on every change of the
 * `profile.config` prop, so that stale payload silently reverted the field.
 *
 * The consequence is not cosmetic, and on gitlab it is invisible. A profile that
 * loses `repos`/`groupIds` is still VALID: empty targets means "scan every
 * project this token can reach". So the run completes, reports findings, and the
 * only symptom is that it scanned the operator's whole account instead of the
 * one project they asked for.
 *
 * StrictMode here is not decoration. It runs the mount effect twice, which is
 * what produces the second, later-resolving GET; the same double fetch is
 * visible in the production trace this test was written from.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/TrufflehogSection.staleRefetch.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { StrictMode } from 'react'
import { render, screen, fireEvent, cleanup, waitFor, act } from '@testing-library/react'
import { TrufflehogSection } from './TrufflehogSection'

// vitest runs without `globals: true`, so RTL's auto-cleanup never registers.
afterEach(() => cleanup())
afterEach(() => vi.unstubAllGlobals())

const PROJECT = 'p1'
const PROFILE_ID = 'prof1'
/** What the server still believes, i.e. what a stale GET replies with. */
const STALE = { id: PROFILE_ID, source: 'gitlab', label: 'GitLab', config: {} }

let saved: Record<string, unknown>[]
/** One resolver per GET /profiles, so a response can be held back deliberately. */
let pendingGets: ((profiles: unknown[]) => void)[]

beforeEach(() => {
  saved = []
  pendingGets = []
  vi.stubGlobal('fetch', vi.fn((url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (url.includes('/profiles') && method === 'PATCH') {
      saved.push(JSON.parse(String(init?.body)).config)
      return Promise.resolve({ ok: true, json: async () => ({}) } as Response)
    }
    if (url.includes('/profiles') && method === 'GET') {
      return new Promise<Response>(resolve => {
        pendingGets.push(profiles =>
          resolve({ ok: true, json: async () => ({ profiles }) } as Response))
      })
    }
    return Promise.resolve({ ok: true, json: async () => ({}) } as Response)
  }))
})

describe('TrufflehogSection stale refetch', () => {
  test('a profiles response that predates an edit does not revert it', async () => {
    render(
      <StrictMode>
        <TrufflehogSection
          data={{} as never}
          updateField={(() => {}) as never}
          mode="edit"
          projectId={PROJECT}
        />
      </StrictMode>,
    )

    // Two GETs are in flight (the double mount). Answer only the first, so the
    // second stays pending exactly as it did in production.
    await waitFor(() => expect(pendingGets.length).toBe(2))
    pendingGets[0]([STALE])

    const header = await screen.findByText('GitLab', { selector: 'strong' })
    fireEvent.click(header)

    const groupIds = await screen.findByLabelText('Group IDs')
    fireEvent.change(groupIds, { target: { value: '90210' } })
    await waitFor(() => expect(saved.length).toBe(1))
    expect(saved[0]).toEqual({ groupIds: ['90210'] })

    // The late one lands now, still carrying the pre-edit config. Flushed
    // properly: the clobber happens in the effect that runs after that
    // response updates the parent's list, so an unflushed test would assert
    // before the damage and pass against the broken code.
    await act(async () => {
      pendingGets[1]([STALE])
      await new Promise(resolve => setTimeout(resolve, 20))
    })

    const excludeRepos = screen.getByLabelText('Exclude repos')
    fireEvent.change(excludeRepos, { target: { value: 'group/b*' } })
    await waitFor(() => expect(saved.length).toBe(2))

    // The whole point. Without this the profile is saved with no target at all,
    // which the gitlab source reads as "scan everything this token can reach".
    expect(saved[1]).toEqual({
      groupIds: ['90210'],
      excludeRepos: ['group/b*'],
    })
  })
})
