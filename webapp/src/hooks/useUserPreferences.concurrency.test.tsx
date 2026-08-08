/**
 * Two writers, one preferences row.
 *
 * The graph page mounts several independent preference writers at once - the
 * Node Inspector alone holds two (hidden columns and column filters), and the
 * theme bridge is a third. They share one react-query cache entry and one
 * debounce window each, so their writes interleave routinely.
 *
 * The failure this file pins is quiet: a PATCH response is the server's WHOLE
 * blob, and it is stale for any key still sitting in another writer's debounce.
 * Adopting it wholesale drops that key from the cache, and because `updatePref`
 * computes its next value FROM the cache, the following edit to that key starts
 * from a blob missing its current value - which is how filters saved for other
 * tables and other projects silently disappear.
 *
 * Run: npx vitest run src/hooks/useUserPreferences.concurrency.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { createElement } from 'react'

import { useUserPreferences, useTableFilterPrefs, useNodeDetailsPrefs } from './useUserPreferences'

/** One client shared by both hooks, exactly as the real page has. */
function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  })
  const wrapper = ({ children }: { children: ReactNode }) =>
    createElement(QueryClientProvider, { client }, children)
  return { wrapper, client }
}

/**
 * A server that only knows what it has actually been told, and answers with its
 * whole blob - the real route's behaviour, and the reason a response can be
 * stale for a key that is still queued in the browser.
 */
function installServer(initial: Record<string, unknown> = {}) {
  const state: Record<string, unknown> = { ...initial }
  const received: { featureKey: string; value: unknown }[] = []
  globalThis.fetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
    if (init?.method === 'PATCH') {
      const body = JSON.parse(init.body as string)
      received.push(body)
      state[body.featureKey] = body.value
    }
    return new Response(JSON.stringify(state), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    })
  }) as typeof fetch
  return { state, received }
}

async function tick(ms: number) {
  await act(async () => {
    vi.advanceTimersByTime(ms)
    await vi.advanceTimersByTimeAsync(0)
  })
}

beforeEach(() => vi.useFakeTimers())
afterEach(() => vi.useRealTimers())

describe('interleaved writes from two hook instances', () => {
  test('one writer\'s response does not drop another writer\'s queued value', async () => {
    const { received } = installServer()
    const { wrapper, client } = makeWrapper()

    const columns = renderHook(() => useNodeDetailsPrefs('Domain'), { wrapper })
    const filters = renderHook(() => useTableFilterPrefs('p1', 'nodeInspector:Domain'), { wrapper })
    await vi.waitFor(() => expect(filters.result.current.isLoading).toBe(false))

    act(() => { columns.result.current.setHiddenColumns(['port']) })
    await tick(100)
    act(() => { filters.result.current.setStoredFilters({ 'prop:status': { selected: ['live'] } }) })

    // The hidden-columns write lands first; its response has never seen the filter.
    await tick(350)
    expect(received.map(r => r.featureKey)).toEqual(['nodeDetailsTable'])

    const cached = client.getQueryData(['user-preferences']) as Record<string, any>
    expect(cached.tableFilters?.p1?.['nodeInspector:Domain']).toBeTruthy()
  })

  test('a later edit is computed from the full blob, not a clobbered one', async () => {
    // The consequence of the above, and the one that loses user data: the
    // second scope is written from a `prev` that must still contain the first.
    const { state } = installServer()
    const { wrapper } = makeWrapper()

    const columns = renderHook(() => useNodeDetailsPrefs('Domain'), { wrapper })
    const sheetA = renderHook(() => useTableFilterPrefs('p1', 'redzone:takeover'), { wrapper })
    await vi.waitFor(() => expect(sheetA.result.current.isLoading).toBe(false))

    act(() => { sheetA.result.current.setStoredFilters({ verdict: { selected: ['confirmed'] } }) })
    act(() => { columns.result.current.setHiddenColumns(['port']) })
    await tick(500)

    // Now a different sheet writes. Its updater reads the cache; if the earlier
    // response had wiped `tableFilters`, takeover's filter is dropped here.
    const sheetB = renderHook(() => useTableFilterPrefs('p1', 'redzone:secrets'), { wrapper })
    act(() => { sheetB.result.current.setStoredFilters({ severity: { selected: ['high'] } }) })
    await tick(500)

    const stored = state.tableFilters as Record<string, any>
    expect(Object.keys(stored.p1).sort()).toEqual(['redzone:secrets', 'redzone:takeover'])
  })

  test('the server value for the written key still wins over the optimistic one', async () => {
    // Merging must not become "ignore the response": the route may normalise or
    // reject part of a value, and the cache has to reflect what was stored.
    const { wrapper, client } = makeWrapper()
    const state: Record<string, unknown> = {}
    globalThis.fetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      if (init?.method === 'PATCH') {
        const body = JSON.parse(init.body as string)
        state[body.featureKey] = 'normalised-by-server'
      }
      return new Response(JSON.stringify(state), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      })
    }) as typeof fetch

    const { result } = renderHook(() => useUserPreferences(), { wrapper })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))

    act(() => { result.current.updatePref('theme', 'dark') })
    await tick(500)

    const cached = client.getQueryData(['user-preferences']) as Record<string, unknown>
    expect(cached.theme).toBe('normalised-by-server')
  })

  test('a response that omits the key keeps what was sent rather than blanking it', async () => {
    // A malformed or truncated response must not wipe a setting the user just
    // made; the route always echoes the merged blob, so a missing key is a bug
    // on the wire, not a deletion.
    const { wrapper, client } = makeWrapper()
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify({}), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    ) as typeof fetch

    const { result } = renderHook(() => useUserPreferences(), { wrapper })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))

    act(() => { result.current.updatePref('theme', 'dark') })
    await tick(500)

    expect((client.getQueryData(['user-preferences']) as Record<string, unknown>).theme).toBe('dark')
  })

  test('a failed write rolls back only its own key', async () => {
    const { wrapper, client } = makeWrapper()
    let failNext = false
    const state: Record<string, unknown> = {}
    globalThis.fetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      if (init?.method === 'PATCH') {
        const body = JSON.parse(init.body as string)
        if (failNext && body.featureKey === 'theme') {
          return new Response('boom', { status: 500 })
        }
        state[body.featureKey] = body.value
      }
      return new Response(JSON.stringify(state), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      })
    }) as typeof fetch

    const { result } = renderHook(() => useUserPreferences(), { wrapper })
    await vi.waitFor(() => expect(result.current.isLoading).toBe(false))

    act(() => { result.current.updatePref('tableFilters', { p1: { s: {} } }) })
    await tick(500)

    failNext = true
    act(() => { result.current.updatePref('theme', 'dark') })
    await tick(500)

    const cached = client.getQueryData(['user-preferences']) as Record<string, any>
    expect(cached.theme).toBeUndefined()          // rolled back
    expect(cached.tableFilters).toBeTruthy()      // untouched by the failure
  })
})
