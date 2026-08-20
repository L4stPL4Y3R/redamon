/**
 * Which graph nodes back which table tab - the single source of truth for the
 * unseen-rows badges.
 *
 * The badge answers "has anything in this tab changed since I last looked at
 * it", and the only signal every row in every sheet is guaranteed to carry is
 * its write time (see UPDATED_AT_PROPS in the RedZoneTables `updatedAt`
 * module). So a tab's badge is a count of its backing nodes stamped after that
 * user's watermark for that tab.
 *
 * One entry per tab, labels unioned across ALL of the tab's sheets: opening
 * "AI Risk" shows every sheet's toolbar, so its badge covers every sheet too.
 *
 * Adding a tab means adding a row here - `registry.test.ts` fails the build
 * otherwise. That test is the whole reason this file exists rather than the
 * mapping living inside the count route: a feature whose contract is "on every
 * tab" decays one tab at a time when nothing enforces the list.
 */
import type { TableViewMode } from '../components/ViewTabs'

/**
 * Every label a scan writes into a project's graph, from the tenant indexes in
 * `graph_db/schema.py`. Backs the two tabs that show the graph as a whole.
 *
 * KBChunk is deliberately absent: it is the imported knowledge-base corpus, not
 * anything a scan found, and loading it would light up every badge with tens of
 * thousands of rows the user cannot act on. CVE / Capec / MitreData / Malware /
 * ThreatPulse look like reference data but are written per project by the
 * enrichment mixins, so they stay.
 */
export const ALL_GRAPH_LABELS = [
  'AttackChain', 'BaseURL', 'Capec', 'Certificate', 'ChainDecision', 'ChainFailure',
  'ChainFinding', 'ChainStep', 'CVE', 'DNSRecord', 'Domain', 'Endpoint', 'Exploit',
  'ExploitGvm', 'ExternalDomain', 'GithubHunt', 'GithubPath', 'GithubRepository',
  'GithubSecret', 'GithubSensitiveFile', 'Header', 'IP', 'JsReconFinding',
  'MalPackageFinding', 'Malware', 'MitreData', 'MultiscannerBucket',
  'MultiscannerEndpoint', 'MultiscannerFinding', 'MultiscannerImage',
  'MultiscannerModel', 'MultiscannerRepository', 'MultiscannerScan', 'Package',
  'Parameter', 'Port', 'SbomDocument', 'Secret', 'Service', 'Subdomain',
  'Technology', 'ThreatPulse', 'Traceroute', 'UserInput', 'Vulnerability',
] as const

/**
 * Tabs with no badge, and why.
 *
 * Recon Delta and Scans are not row tables over the graph: Delta compares two
 * scan versions on demand and Scans lists orchestrator jobs from Postgres.
 * Neither has "rows the user has not seen yet" to count.
 */
export const UNBADGED_TABS: readonly TableViewMode[] = ['reconDelta', 'scanSchedule']

/**
 * Tab -> the labels whose write time drives its badge.
 *
 * These are the labels a row is BUILT FROM, not every label its Cypher
 * traverses. A tab that joins several labels (Kill-Chain, Net Initial-Access)
 * lists all of them, because a change to any one of them changes the row.
 */
export const UNSEEN_TAB_LABELS: Record<Exclude<TableViewMode, 'reconDelta' | 'scanSchedule'>, readonly string[]> = {
  nodeDetails: ALL_GRAPH_LABELS,
  all: ALL_GRAPH_LABELS,
  jsRecon: ['JsReconFinding'],
  aiSurface: ['Endpoint', 'Technology'],
  aiRisk: ['Vulnerability', 'Parameter', 'Endpoint', 'Technology'],
  killChain: ['Technology', 'Port', 'IP', 'Subdomain', 'ExploitGvm'],
  blastRadius: ['Technology'],
  takeover: ['Vulnerability'],
  secrets: ['Secret', 'GithubSecret', 'GithubSensitiveFile', 'MultiscannerFinding', 'ChainFinding'],
  netInitAccess: ['Port', 'Vulnerability', 'IP'],
  graphql: ['Endpoint'],
  webInitAccess: ['BaseURL'],
  paramMatrix: ['Parameter', 'Vulnerability'],
  sharedInfra: ['Certificate', 'IP'],
  dnsEmail: ['Domain'],
  threatIntel: ['Domain', 'IP', 'ThreatPulse'],
  jsDepSignals: ['JsReconFinding'],
  supplyChainSca: ['Package', 'MalPackageFinding', 'Vulnerability'],
  dnsDrift: ['Domain'],
  webCachePoison: ['BaseURL', 'Endpoint', 'Vulnerability'],
}

/** Tab ids that carry a badge, in no particular order. */
export const BADGED_TABS = Object.keys(UNSEEN_TAB_LABELS) as (keyof typeof UNSEEN_TAB_LABELS)[]

/** The distinct labels the count query has to scan, across all tabs. */
export function labelsInUse(): string[] {
  const seen = new Set<string>()
  for (const labels of Object.values(UNSEEN_TAB_LABELS)) labels.forEach(l => seen.add(l))
  return [...seen].sort()
}

/** A user's per-tab watermarks: the instant they last saw each tab. */
export type UnseenMarks = Partial<Record<string, string>>

/** What the count endpoint returns. */
export interface UnseenResponse {
  /** Server time, the only clock a watermark may ever be stamped from. */
  now: string
  counts: Partial<Record<string, number>>
  /** Nodes unseen by SOME tab - not the sum of `counts`. See `distinctUnseenTotal`. */
  total: number
}
