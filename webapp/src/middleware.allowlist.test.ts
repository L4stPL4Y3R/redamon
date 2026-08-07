/**
 * S2/E2 — internal-key route allowlist (middleware scoping).
 * Run: npx vitest run src/middleware.allowlist.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { internalKeyRouteAllowed, scannerKeyRouteAllowed } from './middleware'

describe('internalKeyRouteAllowed — enumerated internal routes pass', () => {
  test.each([
    ['GET', '/api/users/abc/llm-providers'],
    ['GET', '/api/users/abc/settings'],
    ['GET', '/api/users/abc/tradecraft-resources'],
    ['GET', '/api/projects/p1'],
    ['POST', '/api/internal/codefix-sandbox/job1/exec'],
    ['POST', '/api/internal/supply-chain/guarddog'],  // agent-driven L3 GuardDog passthrough
    ['GET', '/api/internal/capture-config'],       // orchestrator polls the DB->file config
    ['GET', '/api/conversations/by-session/s1'],
    ['POST', '/api/conversations/by-session/s1/messages'],
    ['POST', '/api/remediations'],
    ['POST', '/api/remediations/batch'],
    ['PATCH', '/api/remediations/r1'],
    ['GET', '/api/global/tunnel-config'],
  ])('%s %s → allowed', (method, path) => {
    expect(internalKeyRouteAllowed(method, path)).toBe(true)
  })
})

describe('internalKeyRouteAllowed — off-allowlist routes are NOT allowed', () => {
  test.each([
    ['POST', '/api/users'],                       // mint-admin path
    ['PUT', '/api/users/abc'],                     // user update
    ['DELETE', '/api/users/abc'],                  // user delete
    ['POST', '/api/users/abc/llm-providers'],      // add provider (write)
    ['GET', '/api/users'],                         // list all users
    ['GET', '/api/analytics/redzone'],             // arbitrary route
    ['POST', '/api/users/abc/settings'],           // settings is GET-only for the key
    ['POST', '/api/internal/capture-config'],      // capture-config is GET-only
    ['GET', '/api/internal/supply-chain/guarddog'], // guarddog is POST-only
    ['GET', '/api/projects'],                      // projects LIST (only /[id] allowed)
  ])('%s %s → NOT allowed', (method, path) => {
    expect(internalKeyRouteAllowed(method, path)).toBe(false)
  })
})

describe('scannerKeyRouteAllowed — S3/E6 scoped scanner token', () => {
  test.each([
    ['GET', '/api/users/abc/settings'],   // OSINT keys recon needs
    ['GET', '/api/projects/p1'],          // project config
  ])('%s %s → allowed for scanner', (method, path) => {
    expect(scannerKeyRouteAllowed(method, path)).toBe(true)
  })

  test.each([
    ['GET', '/api/users/abc/llm-providers'],       // key harvest — MUST be blocked
    ['GET', '/api/users/abc/tradecraft-resources'],
    ['POST', '/api/users'],                        // mint-admin — MUST be blocked
    ['PUT', '/api/users/abc'],
    ['POST', '/api/internal/codefix-sandbox/j/exec'],
    ['POST', '/api/remediations'],
    ['GET', '/api/global/tunnel-config'],
    ['POST', '/api/users/abc/settings'],           // scanner is GET-only
    ['GET', '/api/traffic/p1/ingest'],             // ingest is POST-only
    ['POST', '/api/traffic/p1'],                    // list route is not a write target
    ['GET', '/api/traffic/p1'],                     // read routes use JWT, not scanner key
  ])('%s %s → NOT allowed for scanner', (method, path) => {
    expect(scannerKeyRouteAllowed(method, path)).toBe(false)
  })
})

describe('traffic-capture ingest route allowlisting', () => {
  test('scanner key may POST the ingest route (recon capture)', () => {
    expect(scannerKeyRouteAllowed('POST', '/api/traffic/proj-123/ingest')).toBe(true)
  })
  test('internal key may POST the ingest route (agent capture, Phase 1)', () => {
    expect(internalKeyRouteAllowed('POST', '/api/traffic/proj-123/ingest')).toBe(true)
  })
  test('ingest allowlisting does not leak to the read routes', () => {
    // Only /ingest is opened; the tenant-scoped read routes stay JWT-only.
    expect(scannerKeyRouteAllowed('GET', '/api/traffic/proj-123')).toBe(false)
    expect(scannerKeyRouteAllowed('GET', '/api/traffic/proj-123/facets')).toBe(false)
    expect(internalKeyRouteAllowed('GET', '/api/traffic/proj-123/some-id')).toBe(false)
  })
  test('cannot smuggle a different route via the projectId segment', () => {
    // The [^/]+ segment cannot contain a slash, so no path traversal into other APIs.
    expect(scannerKeyRouteAllowed('POST', '/api/traffic/p1/ingest/../../users/x/settings')).toBe(false)
  })
})
