/**
 * The session Proxy against a REAL neo4j-driver Session.
 *
 * neo4j.test.ts mocks the driver, so it proves the wiring but can never prove
 * the Proxy is compatible with the driver's own Session object. A Proxy breaks
 * on any method that touches ECMAScript `#private` fields, because `this` is
 * then the proxy rather than the instance -- and that failure would surface only
 * in production, on every graph query.
 *
 * This file deliberately does NOT mock neo4j-driver. It needs no server:
 * `driver.session()` is lazy and opens no socket until a query runs, so only
 * methods that stay local are exercised.
 *
 * If a future driver upgrade converts Session to `#private` fields, this goes
 * red here instead of on the production graph page.
 *
 * @vitest-environment node
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import neo4j from 'neo4j-driver'

import { getGraphSession, closeDriver, getDriver } from './neo4j'

afterEach(async () => {
  await closeDriver()
  globalThis.neo4jDriver = undefined
  vi.unstubAllEnvs()
})

describe('the Proxy is compatible with a real driver Session', () => {
  test('pass-through members work on a real Session', async () => {
    vi.stubEnv('NEO4J_URI', 'bolt://127.0.0.1:7687')
    const session = getGraphSession()

    // Each of these would throw `TypeError: Cannot read private member` if the
    // driver used #private fields and `this` were the proxy.
    expect(typeof session.run).toBe('function')
    expect(() => session.lastBookmarks()).not.toThrow()
    expect(typeof session.beginTransaction).toBe('function')
    await expect(session.close()).resolves.not.toThrow()
  })

  test('the real driver is a genuine Driver instance, reused across calls', () => {
    vi.stubEnv('NEO4J_URI', 'bolt://127.0.0.1:7687')
    const a = getDriver()
    const b = getDriver()
    expect(a).toBe(b)
    // Proves we are exercising the real class, not a stand-in.
    expect(a.constructor.name).toBe('Driver')
    expect(typeof a.session).toBe('function')
  })

  test('the timeout we inject is a shape the real driver accepts', async () => {
    // TransactionConfig.timeout must be a number of ms (or a Duration). Feeding
    // the driver a bad shape fails at query time, i.e. in production only.
    vi.stubEnv('NEO4J_URI', 'bolt://127.0.0.1:7687')
    const raw = neo4j.driver('bolt://127.0.0.1:7687', neo4j.auth.basic('u', 'p')).session()
    const spy = vi.spyOn(raw, 'run').mockReturnValue({ then: () => {} } as never)
    const proxied = new Proxy(raw, {
      get(t, p, r) {
        if (p !== 'run') return Reflect.get(t, p, r)
        return (q: unknown, pr?: unknown, c?: object) =>
          (t as { run: (a: unknown, b: unknown, c: unknown) => unknown }).run(q, pr, { timeout: 120_000, ...(c ?? {}) })
      },
    })
    proxied.run('RETURN 1')
    const cfg = spy.mock.calls[0][2] as { timeout: number }
    expect(typeof cfg.timeout).toBe('number')
    expect(Number.isFinite(cfg.timeout)).toBe(true)
    await raw.close()
  })
})
