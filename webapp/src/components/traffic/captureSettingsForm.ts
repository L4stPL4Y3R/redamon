/**
 * Pure state helpers for the TrafficMind settings dialog.
 *
 * The dialog batches the whole global capture config behind a single **Apply**
 * button: edits mutate local state only, and one PUT of the changed fields is
 * sent on Apply (so at most ONE proxy respawn per Apply, never one-per-click).
 * This module owns the shape of that config slice, its defaults, the
 * server-normalization (`pickCapture`), and the dirty/diff engine that drives the
 * button. It is deliberately framework-free so the diff logic is unit-tested
 * without rendering the modal.
 */
import { BODY_FAMILIES, BODY_RULES_RECOMMENDED } from '@/lib/captureBodyRules'

// Capture settings slice - only the fields the TrafficMind dialog owns. Mirrors
// the capture* columns on userSettings and the CAPTURE_* env the proxy reads.
export interface CaptureSettings {
  captureProxyEnabled: boolean
  captureProxyPort: number
  captureProxyScope: string
  captureProxyStoreBodies: boolean
  captureProxyMaxBodyKb: number
  captureProxyMaxStoreMb: number
  captureProxyRetentionDays: number
  captureProxyRedactSecrets: boolean
  captureProxyPassiveDetect: boolean
  captureProxyStoreReqBodies: boolean
  captureProxyStoreRespBodies: boolean
  captureProxyBodyRules: Record<string, string>
  captureEgressBlockEmptyHost: boolean
  captureEgressBlockHardGuardrail: boolean
  captureEgressFailClosed: boolean
  captureEgressBlockUnresolvable: boolean
  captureEgressBlockPrivate: boolean
  captureEgressBlockLoopback: boolean
  captureEgressBlockLinkLocal: boolean
  captureEgressBlockCgnat: boolean
  captureEgressBlockReserved: boolean
  captureEgressBlockMulticast: boolean
  captureEgressBlockUnspecified: boolean
  // Comma-separated hosts excluded from the supply-chain incident match (A1).
  // Read by both ingest paths; empty falls back to the shipped provider list.
  scaIntelIgnoreSuffixes: string
}

export const DEFAULT_CAPTURE: CaptureSettings = {
  captureProxyEnabled: true, captureProxyPort: 8888, captureProxyScope: 'both',
  captureProxyStoreBodies: true, captureProxyMaxBodyKb: 64, captureProxyMaxStoreMb: 5,
  captureProxyRetentionDays: 14, captureProxyRedactSecrets: true, captureProxyPassiveDetect: true,
  captureProxyStoreReqBodies: true, captureProxyStoreRespBodies: true, captureProxyBodyRules: {},
  captureEgressBlockEmptyHost: true, captureEgressBlockHardGuardrail: true, captureEgressFailClosed: true,
  captureEgressBlockUnresolvable: true, captureEgressBlockPrivate: true, captureEgressBlockLoopback: true,
  captureEgressBlockLinkLocal: true, captureEgressBlockCgnat: true, captureEgressBlockReserved: true,
  captureEgressBlockMulticast: true, captureEgressBlockUnspecified: true,
  scaIntelIgnoreSuffixes: 'oastify.com,oast.fun,mburpcollab.com,canarytokens.com,pipedream.net',
}

// The canonical field set to diff over. Derived from DEFAULT_CAPTURE so a new
// setting is picked up by the dirty engine the moment it is added there.
export const CAPTURE_KEYS = Object.keys(DEFAULT_CAPTURE) as (keyof CaptureSettings)[]

/** Coerce a raw settings payload (any source) into a fully-typed slice with
 *  defaults for missing/typed-wrong fields. Booleans: null → default, else
 *  Boolean(); numbers: only adopt real numbers. */
export function pickCapture(d: Record<string, unknown>): CaptureSettings {
  const b = (v: unknown, def: boolean) => (v == null ? def : Boolean(v))
  const n = (v: unknown, def: number) => (typeof v === 'number' ? v : def)
  return {
    captureProxyEnabled: b(d.captureProxyEnabled, true),
    captureProxyPort: n(d.captureProxyPort, 8888),
    captureProxyScope: (d.captureProxyScope as string) || 'both',
    captureProxyStoreBodies: b(d.captureProxyStoreBodies, true),
    captureProxyMaxBodyKb: n(d.captureProxyMaxBodyKb, 64),
    captureProxyMaxStoreMb: n(d.captureProxyMaxStoreMb, 5),
    captureProxyRetentionDays: n(d.captureProxyRetentionDays, 14),
    captureProxyRedactSecrets: b(d.captureProxyRedactSecrets, true),
    captureProxyPassiveDetect: b(d.captureProxyPassiveDetect, true),
    captureProxyStoreReqBodies: b(d.captureProxyStoreReqBodies, true),
    captureProxyStoreRespBodies: b(d.captureProxyStoreRespBodies, true),
    captureProxyBodyRules: (d.captureProxyBodyRules as Record<string, string>) ?? {},
    captureEgressBlockEmptyHost: b(d.captureEgressBlockEmptyHost, true),
    captureEgressBlockHardGuardrail: b(d.captureEgressBlockHardGuardrail, true),
    captureEgressFailClosed: b(d.captureEgressFailClosed, true),
    captureEgressBlockUnresolvable: b(d.captureEgressBlockUnresolvable, true),
    captureEgressBlockPrivate: b(d.captureEgressBlockPrivate, true),
    captureEgressBlockLoopback: b(d.captureEgressBlockLoopback, true),
    captureEgressBlockLinkLocal: b(d.captureEgressBlockLinkLocal, true),
    captureEgressBlockCgnat: b(d.captureEgressBlockCgnat, true),
    captureEgressBlockReserved: b(d.captureEgressBlockReserved, true),
    captureEgressBlockMulticast: b(d.captureEgressBlockMulticast, true),
    captureEgressBlockUnspecified: b(d.captureEgressBlockUnspecified, true),
    // The FORM preserves an empty string (so the box round-trips what the
    // operator typed and the dirty-check works), but note the matchers treat
    // empty as "use the shipped provider list" - that is what the field's
    // tooltip promises, and both the Python and TypeScript matchers implement
    // it. Suppression therefore cannot be turned off by clearing the box; to
    // see OAST hits, replace the list with a host you never use.
    scaIntelIgnoreSuffixes: typeof d.scaIntelIgnoreSuffixes === 'string'
      ? d.scaIntelIgnoreSuffixes
      : DEFAULT_CAPTURE.scaIntelIgnoreSuffixes,
  }
}

/** Effective policy for a family: an unset family falls back to Recommended
 *  (mirrors the proxy, where a missing rule means the Recommended default). */
export function effectiveBodyPolicy(rules: Record<string, string> | undefined, fam: string): string {
  return rules?.[fam] ?? BODY_RULES_RECOMMENDED[fam as keyof typeof BODY_RULES_RECOMMENDED]
}

/** Two rule maps are equivalent when every family resolves to the same EFFECTIVE
 *  policy. This keeps the form from flagging `{}` vs an explicit-but-identical
 *  map (e.g. clicking the already-active preset) as a dirty change. */
export function bodyRulesEqual(a: Record<string, string> | undefined, b: Record<string, string> | undefined): boolean {
  return BODY_FAMILIES.every((f) => effectiveBodyPolicy(a, f) === effectiveBodyPolicy(b, f))
}

/** The changed fields between server truth (`base`) and the local edits (`next`).
 *  bodyRules compares by effective policy; every other field is a scalar. The
 *  result is exactly what gets PUT on Apply, so an empty object means no save
 *  (and therefore no proxy respawn). */
export function diffCapture(base: CaptureSettings, next: CaptureSettings): Partial<CaptureSettings> {
  const out: Record<string, unknown> = {}
  for (const k of CAPTURE_KEYS) {
    if (k === 'captureProxyBodyRules') {
      if (!bodyRulesEqual(base.captureProxyBodyRules, next.captureProxyBodyRules)) out[k] = next[k]
    } else if (base[k] !== next[k]) {
      out[k] = next[k]
    }
  }
  return out as Partial<CaptureSettings>
}

/** True when the local edits differ from server truth (⇒ show/enable Apply). */
export function isCaptureDirty(base: CaptureSettings, next: CaptureSettings): boolean {
  return Object.keys(diffCapture(base, next)).length > 0
}

/** After a successful save, adopt the server's canonical values for the fields we
 *  submitted - but only where the user hasn't since re-edited that field (so an
 *  edit made mid-save is never clobbered). `submitted` is the snapshot sent. */
export function adoptCanonical(
  current: CaptureSettings, submitted: CaptureSettings, canonical: CaptureSettings,
  keys: (keyof CaptureSettings)[],
): CaptureSettings {
  const merged: CaptureSettings = { ...current }
  for (const k of keys) {
    const unchangedSinceSubmit = k === 'captureProxyBodyRules'
      ? bodyRulesEqual(current.captureProxyBodyRules, submitted.captureProxyBodyRules)
      : current[k] === submitted[k]
    if (unchangedSinceSubmit) (merged as unknown as Record<string, unknown>)[k] = canonical[k]
  }
  return merged
}
