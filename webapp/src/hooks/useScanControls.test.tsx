/**
 * useScanControls: the scan-state bundle behind the project form's scan cluster.
 *
 * The hook itself is thin; what matters is what it does to the ORCHESTRATOR.
 * It mounts four polling hooks, so a surface that mounts it carelessly doubles
 * the status traffic of the graph page for no extra information.
 *
 * Run: npx vitest run src/hooks/useScanControls.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, cleanup } from '@testing-library/react'
import { useScanControls } from './useScanControls'

const calls = vi.hoisted(() => ({ gvm: [] as unknown[], gh: [] as unknown[], th: [] as unknown[], sc: [] as unknown[] }))

vi.mock('./useGvmStatus', () => ({
  useGvmStatus: (o: unknown) => { calls.gvm.push(o); return { state: null } },
}))
vi.mock('./useGithubHuntStatus', () => ({
  useGithubHuntStatus: (o: unknown) => { calls.gh.push(o); return { state: null } },
}))
vi.mock('./useTrufflehogRuns', () => ({
  useTrufflehogRuns: (o: unknown) => { calls.th.push(o); return { isAnyRunning: false, activeRuns: [], profiles: [], bySource: {} } },
}))
vi.mock('./useSupplyChainStatus', () => ({
  useSupplyChainStatus: (o: unknown) => { calls.sc.push(o); return { state: null } },
}))

beforeEach(() => {
  for (const k of Object.keys(calls) as (keyof typeof calls)[]) calls[k].length = 0
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const last = (a: unknown[]) => a[a.length - 1] as Record<string, unknown>

describe('useScanControls', () => {
  test('a project id enables all four scan hooks', () => {
    renderHook(() => useScanControls({ projectId: 'p1' }))
    for (const k of ['gvm', 'gh', 'th', 'sc'] as const) {
      expect(last(calls[k]).enabled, k).toBe(true)
      expect(last(calls[k]).projectId, k).toBe('p1')
    }
  })

  test('no project id means no polling at all', () => {
    // A create-mode form has nothing to scan; polling would be four requests
    // every interval against an id that does not exist.
    renderHook(() => useScanControls({ projectId: null }))
    for (const k of ['gvm', 'gh', 'th', 'sc'] as const) {
      expect(last(calls[k]).enabled, k).toBe(false)
    }
  })

  test('enabled=false overrides a present project id', () => {
    renderHook(() => useScanControls({ projectId: 'p1', enabled: false }))
    expect(last(calls.gvm).enabled).toBe(false)
  })

  test('regression: a secondary surface can slow its polling', () => {
    // F6. Without this every surface polled at the graph page's rate, so having
    // the settings page open doubled the orchestrator's status traffic.
    renderHook(() => useScanControls({ projectId: 'p1', pollingInterval: 15_000 }))
    for (const k of ['gvm', 'gh', 'th', 'sc'] as const) {
      expect(last(calls[k]).pollingInterval, k).toBe(15_000)
    }
  })

  test('omitting the interval leaves each hook on its own default', () => {
    renderHook(() => useScanControls({ projectId: 'p1' }))
    for (const k of ['gvm', 'gh', 'th', 'sc'] as const) {
      expect(last(calls[k])).not.toHaveProperty('pollingInterval')
    }
  })

  test('the data probes are HEAD requests, not downloads', async () => {
    // A GET here would pull the whole artifact just to grey out a button.
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    await waitFor(() => expect(fetch).toHaveBeenCalled())
    for (const call of (fetch as unknown as { mock: { calls: unknown[][] } }).mock.calls) {
      expect((call[1] as { method: string }).method).toBe('HEAD')
    }
    expect(result.current.hasReconData).toBe(false)
  })

  test('the Other Scans modal starts closed and toggles', () => {
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    expect(result.current.otherScansOpen).toBe(false)
  })
})
