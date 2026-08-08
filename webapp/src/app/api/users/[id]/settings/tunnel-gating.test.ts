/**
 * STRIDE I19 — settings PUT is the tunnel ACTIVATION path. Tunnels come up ONLY
 * when the operator explicitly enables them; a credential edit while disabled
 * must NOT start a tunnel; disabling pushes a stop config; and the push carries
 * the TUNNEL_AUTH_TOKEN.
 *
 * Run: npx vitest run "src/app/api/users/[id]/settings/tunnel-gating.test.ts"
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindUnique = vi.fn()
const mockUpsert = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      upsert: (...a: unknown[]) => mockUpsert(...a),
    },
    apiKeyRotationConfig: {
      findMany: vi.fn().mockResolvedValue([]),
      findUnique: vi.fn(),
      update: vi.fn(),
      deleteMany: vi.fn(),
      upsert: vi.fn(),
    },
  },
}))

// Ownership is exercised separately in settings.access.test.ts; here we stub the
// guard open so these tests stay focused on the tunnel-activation logic.
vi.mock('@/lib/session', () => ({
  requireUserAccess: vi.fn().mockResolvedValue(null),
  isInternalRequest: vi.fn().mockReturnValue(false),
  // Mocking the module wholesale means every export the route reaches for has
  // to be listed; a missing one fails inside the handler as a 500, which reads
  // like a route bug rather than a test-setup one.
  isScannerRequest: vi.fn().mockReturnValue(false),
  getSession: vi.fn().mockResolvedValue({ userId: 'u1', role: 'admin' }),
}))

import { PUT } from './route'

const WORKER_URL = 'http://kali-sandbox:8015/tunnel/configure'

function put(id: string, body: unknown): NextRequest {
  return new NextRequest(`http://x/api/users/${id}/settings`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

/** upsert echoes the resulting row from create/update payloads. */
function wireUpsert(existing: Record<string, unknown>) {
  mockFindUnique.mockResolvedValue(existing)
  mockUpsert.mockImplementation(({ create }: { create: Record<string, unknown> }) =>
    Promise.resolve({
      ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', tunnelsEnabled: false,
      ...existing, ...create,
    }),
  )
}

function lastPush(fetchSpy: ReturnType<typeof vi.fn>) {
  const call = fetchSpy.mock.calls.find(c => c[0] === WORKER_URL)
  if (!call) return null
  const opts = call[1] as RequestInit
  return { headers: opts.headers as Record<string, string>, body: JSON.parse(opts.body as string) }
}

beforeEach(() => {
  mockFindUnique.mockReset()
  mockUpsert.mockReset()
  process.env.TUNNEL_AUTH_TOKEN = 'ttok'
})
afterEach(() => {
  vi.unstubAllGlobals()
  delete process.env.TUNNEL_AUTH_TOKEN
})

describe('settings PUT tunnel activation gating — I19', () => {
  test('enable + creds → activates with real creds and Authorization header', async () => {
    wireUpsert({ tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })
    const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)

    await PUT(put('u1', { tunnelsEnabled: true, ngrokAuthtoken: 'ng-tok' }), params('u1'))

    const push = lastPush(fetchSpy)
    expect(push).not.toBeNull()
    expect(push!.body).toEqual({ ngrokAuthtoken: 'ng-tok', chiselServerUrl: '', chiselAuth: '' })
    expect(push!.headers['Authorization']).toBe('Bearer ttok')
  })

  test('credential edit while DISABLED → pushes empty stop config (no activation)', async () => {
    wireUpsert({ tunnelsEnabled: false, ngrokAuthtoken: 'old', chiselServerUrl: '', chiselAuth: '' })
    const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)

    await PUT(put('u1', { ngrokAuthtoken: 'new-secret' }), params('u1'))

    const push = lastPush(fetchSpy)
    expect(push).not.toBeNull()
    expect(push!.body).toEqual({ ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })
  })

  test('disable → pushes empty stop config', async () => {
    wireUpsert({ tunnelsEnabled: true, ngrokAuthtoken: 'ng', chiselServerUrl: '', chiselAuth: '' })
    const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)

    await PUT(put('u1', { tunnelsEnabled: false }), params('u1'))

    const push = lastPush(fetchSpy)
    expect(push).not.toBeNull()
    expect(push!.body).toEqual({ ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })
  })

  test('non-tunnel settings change → NO push at all', async () => {
    wireUpsert({ tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' })
    const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)

    await PUT(put('u1', { shodanApiKey: 'x' }), params('u1'))

    expect(lastPush(fetchSpy)).toBeNull()
  })
})
