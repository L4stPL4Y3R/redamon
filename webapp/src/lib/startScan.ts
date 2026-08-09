/**
 * One dispatch entry point that routes a JobQueue `kind` to the SAME start path
 * the user's button uses (Scan Queue plan, R2). The queue dispatcher never spawns
 * a container: it asks the webapp, and the webapp re-runs the identical start path,
 * so RoE, guardrails, the activation lock, target validation, the version freeze
 * and admission all re-run at dispatch, hours after enqueue.
 *
 * full_recon goes through lib/startFullScan.ts (the shared full-scan path with the
 * version freeze). Every other kind forwards to its orchestrator start endpoint,
 * mirroring its /api/.../start route body exactly.
 */
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { normalizeOrchestratorStartError } from '@/lib/orchestratorError'
import { startFullScan } from '@/lib/startFullScan'
import { parseScanMode, type ScanTrigger } from '@/lib/scanTimeline'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'

export interface DispatchStartResult {
  ok: boolean
  status: number
  error?: string
  limit?: Record<string, unknown>
  activationInProgress?: boolean
  busy?: string
  state?: unknown
  scanJobId?: string | null
  runId?: string
}

export type StartScanPayload = Record<string, unknown>

/** Kinds whose orchestrator start body is just {project_id, user_id, webapp_api_url}. */
const SIMPLE_KIND_ENDPOINT: Record<string, { path: (p: string) => string; fallback: string }> = {
  gvm: { path: p => `/gvm/${p}/start`, fallback: 'Failed to start GVM scan' },
  github_hunt: { path: p => `/github-hunt/${p}/start`, fallback: 'Failed to start GitHub Secret Hunt' },
  trufflehog: { path: p => `/trufflehog/${p}/start`, fallback: 'Failed to start TruffleHog scan' },
  supply_chain: { path: p => `/supply-chain/${p}/start`, fallback: 'Failed to start Supply-Chain scan' },
  // A per-repo batch item runs the supply-chain container; its repo config is
  // applied by the env-override layer in supply_chain_scan/project_settings.py.
  supply_chain_repo: { path: p => `/supply-chain/${p}/start`, fallback: 'Failed to start Supply-Chain scan' },
}

function runId(state: unknown): string {
  if (state && typeof state === 'object') {
    const s = state as Record<string, unknown>
    const v = s.run_id ?? s.runId
    if (typeof v === 'string') return v
  }
  return ''
}

export async function dispatchStart(
  kind: string,
  projectId: string,
  opts: { actorUserId?: string | null; payload?: StartScanPayload } = {},
): Promise<DispatchStartResult> {
  const payload = opts.payload ?? {}

  // full_recon: the shared full-scan path (version freeze + ScanJob history).
  if (kind === 'full_recon') {
    const mode = parseScanMode(payload.mode) ?? 'new'
    const trigger: ScanTrigger = 'scheduled'
    const r = await startFullScan({ projectId, mode, trigger, actorUserId: opts.actorUserId ?? null })
    if (r.ok) {
      return { ok: true, status: 200, state: r.state, scanJobId: r.scanJobId ?? null, runId: runId(r.state) }
    }
    return {
      ok: false,
      status: r.status,
      error: r.error,
      limit: r.limit,
      activationInProgress: r.activationInProgress,
      busy: r.busy,
      scanJobId: r.scanJobId ?? null,
    }
  }

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: { id: true, userId: true },
  })
  if (!project) return { ok: false, status: 404, error: 'Project not found' }

  let path: string
  let body: Record<string, unknown>
  let fallback: string

  const simple = SIMPLE_KIND_ENDPOINT[kind]
  if (simple) {
    path = simple.path(projectId)
    fallback = simple.fallback
    body = { project_id: projectId, user_id: project.userId, webapp_api_url: WEBAPP_URL }
  } else if (kind === 'ai_attack') {
    path = `/ai-attack-surface/${projectId}/start`
    fallback = 'Failed to start AI Attack Surface scan'
    body = {
      project_id: projectId,
      user_id: project.userId,
      webapp_api_url: WEBAPP_URL,
      tool: payload.tool ?? 'garak',
      targets: payload.targets ?? [],
      bounds: payload.bounds ?? {},
      roe_confirmed: payload.roe_confirmed ?? false,
      dry_run: payload.dry_run ?? false,
      probes: payload.probes ?? [],
      strategies: payload.strategies ?? [],
      objective: payload.objective ?? '',
      target_model: payload.target_model ?? '',
      target_purpose: payload.target_purpose ?? '',
      // The GitHub token / api_key is never carried in a queue payload (see the
      // enqueue guard: ai_attack with a non-empty api_key is not queueable).
      api_key: payload.api_key ?? '',
      auth_header: payload.auth_header ?? '',
      auth_scheme: payload.auth_scheme ?? '',
    }
  } else if (kind === 'partial_recon') {
    path = `/recon/${projectId}/partial`
    fallback = 'Failed to start partial recon'
    body = {
      project_id: projectId,
      user_id: project.userId,
      webapp_api_url: WEBAPP_URL,
      tool_id: payload.tool_id,
      graph_inputs: payload.graph_inputs,
      user_inputs: payload.user_inputs ?? [],
      user_targets: payload.user_targets ?? null,
      include_graph_targets: payload.include_graph_targets ?? true,
      settings_overrides: payload.settings_overrides ?? {},
    }
  } else {
    return { ok: false, status: 400, error: `Unknown scan kind: ${kind}` }
  }

  const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}))
    const { error, limit } = normalizeOrchestratorStartError(errorData, fallback)
    return {
      ok: false,
      status: response.status,
      error,
      ...(limit ? { limit: limit as Record<string, unknown> } : {}),
    }
  }

  const state = await response.json().catch(() => ({}))
  return { ok: true, status: 200, state, runId: runId(state) }
}
