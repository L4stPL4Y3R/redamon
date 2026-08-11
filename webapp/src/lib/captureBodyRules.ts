/**
 * Shared allowlists + sanitizer for the capture-proxy body-storage policy.
 *
 * The family list, policy list, and Recommended defaults MUST mirror the backend
 * (scanners/capture_proxy/capture_lib.py: DEFAULT_BODY_RULES / classify_family). Keeping
 * them here means the settings route (server) and settings page (client) can't
 * drift from each other.
 */
export const BODY_FAMILIES = [
  'text', 'json', 'script', 'image', 'font', 'video', 'audio', 'document', 'archive', 'binary', 'other',
] as const
export type BodyFamily = typeof BODY_FAMILIES[number]

export const BODY_POLICIES = ['auto', 'inline', 'disk', 'meta'] as const
export type BodyPolicy = typeof BODY_POLICIES[number]

const FAM: ReadonlySet<string> = new Set(BODY_FAMILIES)
const POL: ReadonlySet<string> = new Set(BODY_POLICIES)

/**
 * Keep only allowlisted family -> policy pairs; drop unknown families, non-string
 * or invalid policies, and non-object input. Never throws. The proxy env is built
 * from this, so a bad value must not survive to the container.
 */
export function sanitizeBodyRules(input: unknown): Record<string, string> {
  const clean: Record<string, string> = {}
  if (!input || typeof input !== 'object' || Array.isArray(input)) return clean
  for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
    if (FAM.has(k) && typeof v === 'string' && POL.has(v)) clean[k] = v
  }
  return clean
}

/** Recommended default policy map. Mirrors capture_lib.DEFAULT_BODY_RULES. */
export const BODY_RULES_RECOMMENDED: Record<BodyFamily, BodyPolicy> = {
  text: 'auto', json: 'auto', script: 'auto', image: 'meta', font: 'meta',
  video: 'meta', audio: 'meta', document: 'disk', archive: 'disk', binary: 'disk', other: 'auto',
}
