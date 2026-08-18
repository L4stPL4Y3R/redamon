/**
 * Unit tests for the agent WebSocket connection lifecycle.
 *
 * Issue #173 (second symptom): the agent FAILS CLOSED on the init frame and
 * closes the socket with 1008 when the ws-ticket is missing or does not verify
 * (agentic/websocket_api.py). The hook treated that like any other drop and
 * reconnected, so a stack whose .env predates AGENT_WS_TICKET_SECRET showed
 * "Connecting..." forever with nothing to act on. A 1008 must stop the loop and
 * name the cause.
 *
 * Run: npx vitest run src/hooks/useAgentWebSocket.test.tsx
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { ConnectionStatus } from '@/lib/websocket-types'

vi.mock('./agentWsUrl', () => ({ buildAgentWsUrl: () => 'ws://agent.test/ws/agent' }))

import { useAgentWebSocket } from './useAgentWebSocket'

// Minimal WebSocket stand-in: records what was sent and lets a test drive the
// close event with a specific code.
class FakeSocket {
  static instances: FakeSocket[] = []
  static OPEN = 1
  readyState = 1
  sent: string[] = []
  onopen: (() => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onerror: ((e: Event) => void) | null = null
  onclose: ((e: CloseEvent) => void) | null = null

  constructor(public url: string) {
    FakeSocket.instances.push(this)
  }
  send(data: string) { this.sent.push(data) }
  close() { /* the hook detaches handlers before calling this */ }
  fireClose(code: number) { this.onclose?.({ code, reason: '', wasClean: false } as CloseEvent) }
}

const config = {
  userId: 'u1',
  projectId: 'p1',
  sessionId: 's1',
  maxReconnectAttempts: 5,
  reconnectInterval: 10,
}

beforeEach(() => {
  FakeSocket.instances = []
  vi.stubGlobal('WebSocket', FakeSocket as unknown as typeof WebSocket)
  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: true,
    json: async () => ({ ticket: 'tkt' }),
  }) as unknown as Response))
})
afterEach(() => { vi.unstubAllGlobals() })

describe('useAgentWebSocket auth rejection (#173)', () => {
  test('close 1008 → FAILED with an actionable error, and NO reconnect', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const sock = FakeSocket.instances[0]

    await act(async () => { sock.onopen?.() })
    act(() => { sock.fireClose(1008) })

    expect(result.current.status).toBe(ConnectionStatus.FAILED)
    expect(result.current.error?.message).toContain('authentication failed')

    // The reconnect timer must never fire for a configuration failure.
    await new Promise(r => setTimeout(r, 60))
    expect(FakeSocket.instances).toHaveLength(1)
  })

  test('a ticketless init names the missing secret in the error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ ticket: null }),
    }) as unknown as Response))

    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const sock = FakeSocket.instances[0]

    await act(async () => { sock.onopen?.() })
    await waitFor(() => expect(sock.sent).toHaveLength(1))
    act(() => { sock.fireClose(1008) })

    expect(result.current.status).toBe(ConnectionStatus.FAILED)
    expect(result.current.error?.message).toContain('AGENT_WS_TICKET_SECRET')
  })

  test('an ordinary drop (1006) still reconnects', async () => {
    const { result } = renderHook(() => useAgentWebSocket(config))
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1))

    await act(async () => { FakeSocket.instances[0].onopen?.() })
    act(() => { FakeSocket.instances[0].fireClose(1006) })

    expect(result.current.status).toBe(ConnectionStatus.RECONNECTING)
    await waitFor(() => expect(FakeSocket.instances.length).toBeGreaterThan(1))
  })
})
