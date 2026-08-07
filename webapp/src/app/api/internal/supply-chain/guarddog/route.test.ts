/**
 * POST /api/internal/supply-chain/guarddog — the agent->orchestrator passthrough
 * for the L3 GuardDog behavioural analysis. Verifies: internal-key gating,
 * ecosystem + charset (incl. leading-dash) validation at the edge, body
 * normalization, and that a valid request is re-issued to the orchestrator with
 * the orchestrator key (never the raw internal key) and its result relayed.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockIsInternal = vi.fn()
const mockOrchestratorFetch = vi.fn()

vi.mock('@/lib/session', () => ({
  isInternalRequest: (...a: unknown[]) => mockIsInternal(...a),
}))
vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: (...a: unknown[]) => mockOrchestratorFetch(...a),
}))

import { POST } from './route'

function req(body: unknown): NextRequest {
  return new NextRequest('http://webapp/api/internal/supply-chain/guarddog', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

function orchOk(payload: unknown, status = 200) {
  return { status, json: async () => payload }
}

beforeEach(() => {
  mockIsInternal.mockReset().mockReturnValue(true)
  mockOrchestratorFetch.mockReset().mockResolvedValue(
    orchOk({ issues: 0, rules_fired: [], errors: [], error: null }),
  )
})

describe('auth', () => {
  test('non-internal caller gets 401 and never reaches the orchestrator', async () => {
    mockIsInternal.mockReturnValue(false)
    const res = await POST(req({ ecosystem: 'npm', name: 'lodash' }))
    expect(res.status).toBe(401)
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
  })
})

describe('validation (rejected at the edge, orchestrator untouched)', () => {
  test('unsupported ecosystem → 400', async () => {
    const res = await POST(req({ ecosystem: 'cargo', name: 'left-pad' }))
    expect(res.status).toBe(400)
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
  })

  test('leading-dash name → 400 (no flag smuggling into guarddog)', async () => {
    const res = await POST(req({ ecosystem: 'npm', name: '--help' }))
    expect(res.status).toBe(400)
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
  })

  test('hostile name charset → 400', async () => {
    const res = await POST(req({ ecosystem: 'npm', name: 'evil;rm -rf' }))
    expect(res.status).toBe(400)
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
  })

  test('leading-dash version → 400', async () => {
    const res = await POST(req({ ecosystem: 'npm', name: 'lodash', version: '-rf' }))
    expect(res.status).toBe(400)
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
  })

  test('malformed JSON body → 400', async () => {
    const res = await POST(req('{not json'))
    expect(res.status).toBe(400)
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
  })
})

describe('passthrough', () => {
  test('valid request is normalized and forwarded via orchestratorFetch', async () => {
    mockOrchestratorFetch.mockResolvedValue(
      orchOk({ issues: 2, rules_fired: ['typosquatting'], errors: [], error: null }),
    )
    const res = await POST(req({ ecosystem: 'NPM', name: 'event-stream', version: '3.3.6' }))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.issues).toBe(2)

    expect(mockOrchestratorFetch).toHaveBeenCalledTimes(1)
    const [url, opts] = mockOrchestratorFetch.mock.calls[0]
    expect(String(url)).toMatch(/\/supply-chain\/guarddog$/)
    // ecosystem lowercased; body is the validated triple.
    expect(JSON.parse(opts.body)).toEqual({ ecosystem: 'npm', name: 'event-stream', version: '3.3.6' })
    // The route must NOT leak the internal key onward; orchestratorFetch owns the
    // orchestrator key. The passthrough sends only the JSON content-type here.
    expect(opts.headers?.['X-Internal-Key']).toBeUndefined()
  })

  test('scoped npm name is accepted and forwarded', async () => {
    const res = await POST(req({ ecosystem: 'npm', name: '@angular/core', version: '12.0.0' }))
    expect(res.status).toBe(200)
    expect(mockOrchestratorFetch).toHaveBeenCalledTimes(1)
  })

  test('an orchestrator error result is relayed with its status', async () => {
    mockOrchestratorFetch.mockResolvedValue(
      orchOk({ issues: 0, rules_fired: [], errors: [], error: 'guarddog dispatch failed' }, 200),
    )
    const res = await POST(req({ ecosystem: 'npm', name: 'evil' }))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.error).toMatch(/dispatch failed/)
  })

  test('a thrown orchestratorFetch becomes a 502, not an unhandled crash', async () => {
    mockOrchestratorFetch.mockRejectedValue(new Error('econnrefused'))
    const res = await POST(req({ ecosystem: 'npm', name: 'evil' }))
    expect(res.status).toBe(502)
  })
})
