/**
 * The three rules that make the badges trustworthy, each with a silent failure
 * mode behind it:
 *
 *  - **Seed, never accuse.** A user with no stored watermarks has not got
 *    twenty thousand unread rows, they have never had badges before. Getting
 *    this wrong ships a page covered in four-digit counts on upgrade day.
 *  - **Wait for the preferences blob.** Polling before it loads sends an empty
 *    watermark map, and the seeding branch then overwrites every real watermark
 *    the user has - permanently losing where they had got to.
 *  - **Stamp from the graph's clock.** A browser running fast would write a
 *    watermark into the future and hide the next scan's findings for good.
 *
 * Run: npx vitest run src/app/graph/hooks/useUnseenCounts.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createElement, type ReactNode } from 'react'

import { useUnseenCounts } from './useUnseenCounts'
import { BADGED_TABS } from '../unseen/registry'

const CLIENT_NOW = new Date('2026-08-20T12:00:00.000Z')
/** The graph is a minute ahead of this browser. */
const SERVER_NOW = '2026-08-20T12:01:00.000Z'
const T1 = '2026-08-01T00:00:00.000Z'

function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  })
  return ({ children }: { children: ReactNode }) =>
    createElement(QueryClientProvider, { client }, children)
}

interface ServerOpts {
  prefs?: Record<string, unknown>
  counts?: Record<string, number>
  total?: number
  /** Leave the preferences GET pending forever. */
  hangPrefs?: boolean
  failUnseen?: boolean
}

function installServer(opts: ServerOpts = {}) {
  const prefs: Record<string, unknown> = { ...(opts.prefs ?? {}) }
  const unseenBodies: Array<{ projectId: string; marks: Record<string, string> }> = []
  let counts = opts.counts ?? {}
  const total = opts.total ?? 0
  let failUnseen = opts.failUnseen ?? false

  globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const href = String(url)
    if (href.includes('/api/analytics/unseen')) {
      unseenBodies.push(JSON.parse(init!.body as string))
      if (failUnseen) return new Response('nope', { status: 500 })
      return Response.json({ now: SERVER_NOW, counts, total })
    }
    if (href.includes('/api/user/preferences')) {
      if (opts.hangPrefs) return new Promise<Response>(() => {})
      if (init?.method === 'PATCH') {
        const body = JSON.parse(init.body as string)
        prefs[body.featureKey] = body.value
      }
      return Response.json(prefs)
    }
    throw new Error(`unexpected fetch: ${href}`)
  }) as typeof fetch

  return {
    prefs,
    unseenBodies,
    setCounts: (c: Record<string, number>) => { counts = c },
    setFailUnseen: (v: boolean) => { failUnseen = v },
    marks: () => (prefs.unseenSeenAt as Record<string, Record<string, string>>)?.p1 ?? {},
  }
}

/** Let the preference debounce (400ms) and any pending promises settle. */
async function settle() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(600)
  })
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(CLIENT_NOW)
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('first run', () => {
  test('seeds every badged tab from the server clock and shows nothing', async () => {
    const server = installServer({ counts: {} })
    const { result } = renderHook(() => useUnseenCounts('p1', null), { wrapper: makeWrapper() })
    await settle()

    expect(Object.keys(server.marks()).sort()).toEqual([...BADGED_TABS].sort())
    expect(Object.values(server.marks()).every(v => v === SERVER_NOW)).toBe(true)
    expect(result.current.total).toBe(0)
  })

  test('sends no watermarks it does not have, so the route counts nothing', async () => {
    const server = installServer()
    renderHook(() => useUnseenCounts('p1', null), { wrapper: makeWrapper() })
    await settle()

    expect(server.unseenBodies[0]).toEqual({ projectId: 'p1', marks: {} })
  })
})

describe('waiting for the preferences blob', () => {
  test('does not poll while preferences are still loading', async () => {
    const server = installServer({ hangPrefs: true })
    renderHook(() => useUnseenCounts('p1', null), { wrapper: makeWrapper() })
    await settle()

    expect(server.unseenBodies).toHaveLength(0)
  })

  test('an existing watermark survives the first poll rather than being re-seeded', async () => {
    const server = installServer({
      prefs: { unseenSeenAt: { p1: { dnsEmail: T1 } } },
      counts: { dnsEmail: 7 },
    })
    const { result } = renderHook(() => useUnseenCounts('p1', null), { wrapper: makeWrapper() })
    await settle()

    expect(server.unseenBodies[0].marks).toEqual({ dnsEmail: T1 })
    expect(server.marks().dnsEmail).toBe(T1)
    expect(result.current.counts.dnsEmail).toBe(7)
  })
})

describe('counts', () => {
  test('the bar total is the route\'s figure, not the sum of the badges', async () => {
    // Summing them here would double-count: Node Inspector and All Nodes each
    // cover the whole graph, so only the route can say how many nodes are new.
    installServer({
      prefs: { unseenSeenAt: { p1: Object.fromEntries(BADGED_TABS.map(t => [t, T1])) } },
      counts: { dnsEmail: 7, secrets: 3, nodeDetails: 10, all: 10 },
      total: 10,
    })
    const { result } = renderHook(() => useUnseenCounts('p1', null), { wrapper: makeWrapper() })
    await settle()

    expect(result.current.total).toBe(10)
  })

  test('a failed poll keeps the last numbers instead of blanking every badge', async () => {
    const server = installServer({
      prefs: { unseenSeenAt: { p1: Object.fromEntries(BADGED_TABS.map(t => [t, T1])) } },
      counts: { dnsEmail: 7 },
    })
    const { result } = renderHook(() => useUnseenCounts('p1', null), { wrapper: makeWrapper() })
    await settle()
    expect(result.current.counts.dnsEmail).toBe(7)

    server.setFailUnseen(true)
    await act(async () => { await vi.advanceTimersByTimeAsync(46_000) })

    expect(result.current.counts.dnsEmail).toBe(7)
  })
})

describe('marking seen', () => {
  test('opening a tab clears its badge and stamps the graph clock, not the browser', async () => {
    const server = installServer({
      prefs: { unseenSeenAt: { p1: Object.fromEntries(BADGED_TABS.map(t => [t, T1])) } },
      counts: { secrets: 4 },
    })
    const { result } = renderHook(() => useUnseenCounts('p1', null), { wrapper: makeWrapper() })
    await settle()
    expect(result.current.counts.secrets).toBe(4)

    act(() => { result.current.markSeen('secrets') })
    await settle()

    expect(result.current.counts.secrets).toBe(0)
    // Skew-corrected: the browser is a minute behind the graph, so the stamp
    // lands on the graph's clock rather than on this process's.
    const stamped = Date.parse(server.marks().secrets)
    expect(Math.abs(stamped - Date.parse(SERVER_NOW))).toBeLessThan(1_000)
    expect(stamped - CLIENT_NOW.getTime()).toBeGreaterThan(30_000)
  })

  test('a tab left open stays at zero on the next poll', async () => {
    const server = installServer({
      prefs: { unseenSeenAt: { p1: Object.fromEntries(BADGED_TABS.map(t => [t, T1])) } },
      counts: { secrets: 4 },
    })
    const { result } = renderHook(() => useUnseenCounts('p1', 'secrets'), { wrapper: makeWrapper() })
    await settle()

    expect(result.current.counts.secrets).toBe(0)
    expect(server.marks().secrets).toBe(SERVER_NOW)
  })

  test('an unknown tab id is ignored rather than written', async () => {
    const server = installServer({
      prefs: { unseenSeenAt: { p1: { dnsEmail: T1 } } },
    })
    const { result } = renderHook(() => useUnseenCounts('p1', null), { wrapper: makeWrapper() })
    await settle()

    act(() => { result.current.markSeen('reconDelta') })
    await settle()

    expect(server.marks()).not.toHaveProperty('reconDelta')
  })
})
