import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { BrowserContext } from '@playwright/test'

/**
 * A session cookie minted directly from AUTH_SECRET.
 *
 * Logging in through the form would mean holding a real password in the test
 * harness. The app's own token is an HS256 JWT over `{ sub, role }`
 * (webapp/src/lib/auth.ts), so it can be signed here from the same secret the
 * server verifies with - no credentials, and no dependency on the login page's
 * markup staying put.
 */

const AUTH_COOKIE_NAME = 'redamon-auth'

function repoRoot(): string {
  return join(__dirname, '..', '..')
}

export function authSecret(): string {
  const env = readFileSync(join(repoRoot(), '.env'), 'utf8')
  const line = env.split('\n').find(l => l.startsWith('AUTH_SECRET='))
  if (!line) throw new Error('AUTH_SECRET not found in .env')
  const value = line.slice('AUTH_SECRET='.length).trim().replace(/^["']|["']$/g, '')
  if (!value || value === 'changeme') throw new Error('AUTH_SECRET is unset or still the placeholder')
  return value
}

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

export function mintToken(userId: string, role = 'admin'): string {
  const now = Math.floor(Date.now() / 1000)
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = b64url(JSON.stringify({
    sub: userId, role, iat: now, exp: now + 3600,
  }))
  const data = `${header}.${payload}`
  const sig = b64url(createHmac('sha256', authSecret()).update(data).digest())
  return `${data}.${sig}`
}

export async function signIn(context: BrowserContext, userId: string, baseURL: string) {
  const url = new URL(baseURL)
  await context.addCookies([{
    name: AUTH_COOKIE_NAME,
    value: mintToken(userId),
    domain: url.hostname,
    path: '/',
    httpOnly: true,
    sameSite: 'Lax',
  }])
}
