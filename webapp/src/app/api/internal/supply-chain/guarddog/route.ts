import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

// Internal passthrough so the AGENT can run a one-shot GuardDog behavioural
// analysis (execute_guarddog, L3) WITHOUT reaching the privileged orchestrator
// directly: only the webapp holds ORCHESTRATOR_API_KEY. The agent authenticates
// here with X-Internal-Key; this route re-issues the request to the orchestrator
// with the orchestrator key. Same trust-consistent lane as codefix-sandbox
// (T6/E10): GuardDog downloads an attacker-authored tarball, so it must run in
// the hardened analyzer image dispatched by the orchestrator, never in the
// least-trusted Kali worker.

const ECOSYSTEMS = new Set(['npm', 'pypi', 'go', 'crates', 'rubygems', 'github_action', 'extension'])
// Package name / version charset gate, mirrored from the orchestrator's own
// check so a bad request is rejected at the edge, not deep in the dispatcher.
// First char must be alphanumeric or @ (npm scopes): a leading '-' would let a
// name like "--help" reach GuardDog's argv as a flag.
const SAFE = /^[A-Za-z0-9@][A-Za-z0-9._@/+-]{0,213}$/

export async function POST(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  let body: { ecosystem?: unknown; name?: unknown; version?: unknown }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
  }

  const ecosystem = String(body.ecosystem ?? '').trim().toLowerCase()
  const name = String(body.name ?? '').trim()
  const version = String(body.version ?? '').trim()

  if (!ECOSYSTEMS.has(ecosystem)) {
    return NextResponse.json({ error: `Unsupported ecosystem: ${ecosystem || '(empty)'}` }, { status: 400 })
  }
  if (!SAFE.test(name) || (version && !SAFE.test(version))) {
    return NextResponse.json({ error: 'Invalid package name/version' }, { status: 400 })
  }

  try {
    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/supply-chain/guarddog`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ecosystem, name, version }),
    })
    const data = await response.json().catch(() => ({}))
    return NextResponse.json(data, { status: response.status })
  } catch (err) {
    return NextResponse.json(
      { error: `GuardDog passthrough failed: ${err instanceof Error ? err.message : String(err)}` },
      { status: 502 },
    )
  }
}
