/**
 * A1 (TypeScript half): match a captured request against the incident catalog.
 *
 * There are TWO writers of captured_http_transactions - the Python spool worker
 * and this app's ingest route - and both must set the same two columns for the
 * same input, or the flag misrepresents coverage: an operator would see some
 * requests flagged and conclude the unflagged ones were checked and cleared.
 * `scaIntel.parity.test.ts` pins the two implementations to the same behaviour.
 *
 * Mirrors scanners/capture_proxy/ioc_match.py + the matching half of
 * supply_chain_common/intel.py. Kept deliberately small for that reason: every
 * rule added here has to be added there too.
 */
import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Where the read-only intel volume is mounted into the webapp container.
 *
 * Read per call, NOT captured at module load: a module-level const is frozen at
 * import time, which makes the path impossible to point elsewhere once anything
 * has imported this file.
 */
function intelPath(): string {
  return process.env.SCA_INTEL_PATH || '/sca-intel'
}

/** Kill switch, deliberately not surfaced in the UI. */
function enabled(): boolean {
  const raw = (process.env.SCA_INTEL_MATCH_ENABLED || 'true').toLowerCase()
  return !['0', 'false', 'no'].includes(raw)
}

/**
 * OAST / interaction-server providers. These ARE real IOCs in the feed (30 of
 * its 216 domains), so the sync keeps them; they are suppressed at match time,
 * because an operator running Burp Collaborator would otherwise flag their own
 * callbacks on every engagement.
 */
export const DEFAULT_IGNORE_SUFFIXES = [
  'oastify.com', 'oast.fun', 'mburpcollab.com', 'canarytokens.com',
  'pipedream.net',
]

export interface IncidentRecord {
  incident_id?: string
  url?: string
  title?: string
  summary?: string
  status?: string
}

export interface ScaIntel {
  available: boolean
  domains: Record<string, IncidentRecord>
  wildcards: [string, IncidentRecord][]
  ips: Record<string, IncidentRecord>
  revised: string
}

function emptyIntel(): ScaIntel {
  // A fresh object each time: a shared frozen-ish constant would be handed out
  // by reference to every caller of loadScaIntel().
  return { available: false, domains: {}, wildcards: [], ips: {}, revised: '' }
}

/**
 * How often this process re-checks whether the volume was re-synced.
 *
 * Next.js runs for days and the refresh sidecar rewrites the volume underneath
 * it, so without a re-check the route would answer from the copy it loaded at
 * boot forever and a freshly synced IOC would never apply. Mirrors the Python
 * reader's window so the two ingest paths cannot disagree about how fresh their
 * view is.
 */
const RELOAD_CHECK_MS = 60_000

let cache: ScaIntel | null = null
let cacheMtimeMs: number | null = null
let cacheCheckedAt = 0

function readJson(name: string): unknown {
  try {
    return JSON.parse(readFileSync(join(intelPath(), name), 'utf8'))
  } catch {
    return null
  }
}

function manifestMtimeMs(): number | null {
  try {
    return statSync(join(intelPath(), 'manifest.json')).mtimeMs
  } catch {
    return null
  }
}

/**
 * Load the intel tables, re-reading them after a re-sync. Never throws: a
 * missing volume, an unreadable file and a never-synced deploy all yield
 * available=false.
 */
export function loadScaIntel(force = false): ScaIntel {
  if (cache && !force) {
    const now = Date.now()
    if (now - cacheCheckedAt < RELOAD_CHECK_MS) return cache
    cacheCheckedAt = now
    // manifest.json is written last and only on a successful sync, so its
    // mtime is exactly "the data changed".
    if (manifestMtimeMs() === cacheMtimeMs) return cache
  }
  const manifest = readJson('manifest.json') as { revised?: string } | null
  if (!manifest || typeof manifest !== 'object') {
    cache = emptyIntel()
    cacheMtimeMs = manifestMtimeMs()
    cacheCheckedAt = Date.now()
    return cache
  }
  const network = (readJson('network_iocs.json') || {}) as {
    domains?: Record<string, IncidentRecord>
    wildcards?: [string, IncidentRecord][]
    ips?: Record<string, IncidentRecord>
  }
  cache = {
    available: true,
    domains: network.domains || {},
    wildcards: Array.isArray(network.wildcards)
      ? network.wildcards.filter(w => Array.isArray(w) && typeof w[0] === 'string')
        .map(w => [String(w[0]).toLowerCase(), w[1]] as [string, IncidentRecord])
      : [],
    ips: network.ips || {},
    revised: String(manifest.revised || ''),
  }
  cacheMtimeMs = manifestMtimeMs()
  cacheCheckedAt = Date.now()
  return cache
}

/** Test seam: drop the module-level cache. */
export function resetScaIntelCache(): void {
  cache = null
  cacheMtimeMs = null
  cacheCheckedAt = 0
}

function ignoreSuffixes(): string[] {
  const raw = process.env.CAPTURE_IOC_IGNORE_SUFFIXES
  const list = raw
    ? raw.split(/[,\s]+/).filter(Boolean)
    : DEFAULT_IGNORE_SUFFIXES
  return list.map(s => s.toLowerCase().replace(/^\.+/, ''))
}

/**
 * Return the incident for a captured request, or null.
 *
 * Exact host, then wildcard suffix, then the resolved IP - the same order and
 * the same normalisation (lowercase, trailing dot and port stripped) as the
 * Python matcher.
 */
export function matchTransaction(
  host: string | null | undefined,
  targetIp?: string | null,
  intel?: ScaIntel,
  ignore?: string[],
): IncidentRecord | null {
  if (!enabled()) return null
  const tables = intel || loadScaIntel()
  if (!tables.available) return null

  const ignored = ignore || ignoreSuffixes()
  if (host) {
    let candidate = String(host).trim().toLowerCase().replace(/\.+$/, '')
    // Strip a port if one rode along on the Host header.
    if (candidate.includes(':') && !candidate.startsWith('[')) {
      candidate = candidate.split(':')[0]
    }
    if (candidate) {
      for (const suffix of ignored) {
        if (candidate === suffix || candidate.endsWith('.' + suffix)) return null
      }
      const exact = tables.domains[candidate]
      if (exact) return exact
      // An IP-literal Host belongs in the ips table (mirrors the Python matcher
      // and the sync, which routes IP literals out of the feed's domains array).
      const asIp = tables.ips[candidate]
      if (asIp) return asIp
      for (const [suffix, rec] of tables.wildcards) {
        if (candidate.endsWith(suffix)) return rec
      }
    }
  }
  if (targetIp) {
    return tables.ips[String(targetIp).trim()] || null
  }
  return null
}

/** The two columns both ingest paths must set. */
export function iocColumns(
  host: string | null | undefined,
  targetIp?: string | null,
  intel?: ScaIntel,
): { iocIncidentId: string | null; iocIncidentUrl: string | null } {
  try {
    const rec = matchTransaction(host, targetIp, intel)
    if (!rec) return { iocIncidentId: null, iocIncidentUrl: null }
    return {
      iocIncidentId: rec.incident_id || null,
      iocIncidentUrl: rec.url || null,
    }
  } catch {
    // Ingest must never fail over enrichment.
    return { iocIncidentId: null, iocIncidentUrl: null }
  }
}
