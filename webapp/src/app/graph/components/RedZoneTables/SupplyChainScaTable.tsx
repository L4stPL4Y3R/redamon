'use client'

import { memo, useCallback, useEffect, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import type { RedZoneExportConfig } from './exportCsv'
import {
  SeverityBadge, Mono, Truncated, NumCell, ListCell, LinkedListCell, filterRowsByText,
} from './formatters'
import { normalizeSeverity, SEVERITY_RANK, type Severity } from './types'
import rowStyles from './RedZoneTableRow.module.css'

/**
 * Supply-Chain SCA: the Package / MalPackageFinding / Vulnerability model that
 * L1 (SBOM or repo scan) and L2 (live-target recon harvest) both MERGE into,
 * deduped on the purl so all layers converge on the same rows.
 *
 * Not to be confused with the JS Dep Signals table, which reads JsReconFinding
 * nodes (source maps, dev comments, dependency confusion).
 */

type SheetKey = 'verdicts' | 'packages' | 'advisories'

interface VerdictRow {
  findingId: string
  verdict: string
  severity: string
  sourceTool: string | null
  advisoryId: string | null
  title: string | null
  detail: string | null
  confidence: string | null
  softError: boolean
  aliases: string[]
  firstSeen: string | null
  lastSeen: string | null
  purl: string
  name: string | null
  version: string | null
  ecosystem: string | null
  harvestSource: string | null
  sourcePath: string | null
  baseUrls: string[]
  repos: string[]
}

interface PackageRow {
  purl: string
  name: string | null
  version: string | null
  ecosystem: string | null
  harvestSource: string | null
  sourcePath: string | null
  firstSeen: string | null
  lastSeen: string | null
  baseUrls: string[]
  repos: string[]
  maliciousCount: number
  suspiciousCount: number
  notAnalysedCount: number
  advisoryCount: number
  advisorySeverities: string[]
}

interface AdvisoryRow {
  advisoryId: string
  severity: string
  cvss: string | null
  title: string | null
  description: string | null
  purl: string
  name: string | null
  version: string | null
  ecosystem: string | null
  harvestSource: string | null
  sourcePath: string | null
  firstSeen: string | null
  updatedAt: string | null
  baseUrls: string[]
  repos: string[]
}

interface ScaMeta {
  totalPackages: number
  unversioned: number
  malicious: number
  suspicious: number
  notAnalysed: number
  advisories: number
  byEcosystem?: { ecosystem: string; count: number; unversioned: number }[]
  truncated?: Record<SheetKey, boolean>
}

interface ScaResponse {
  sheets: { verdicts: VerdictRow[]; packages: PackageRow[]; advisories: AdvisoryRow[] }
  meta: ScaMeta
}

const PAGE_SIZE = 100

// --------------------------------------------------------------------------
// Chips
// --------------------------------------------------------------------------

/**
 * A verdict is one of three things, and conflating the third with the second is
 * the failure mode the whole feature is built to avoid: "GuardDog ran and found
 * something" and "GuardDog never ran" must not look alike.
 */
function VerdictChip({ row }: { row: Pick<VerdictRow, 'verdict' | 'softError' | 'advisoryId'> }) {
  const notAnalysed = row.softError || row.advisoryId === 'guarddog-not-run'
  if (notAnalysed) {
    return <span className={`${rowStyles.sevBadge} ${rowStyles.sevInfo}`} title="The behavioural pass did not produce a verdict for this package. It is UNCHECKED, not clean.">not analysed</span>
  }
  if (row.verdict === 'malicious') {
    return <span className={`${rowStyles.sevBadge} ${rowStyles.sevCritical}`} title="OSV MAL- advisory: the package itself is malware">malicious</span>
  }
  return <span className={`${rowStyles.sevBadge} ${rowStyles.sevMedium}`} title="GuardDog behavioural hit, not a terminal verdict">{row.verdict}</span>
}

type PkgStatus = 'malicious' | 'vulnerable' | 'suspicious' | 'not analysed' | 'unverdictable' | 'clean'

const STATUS_CLASS: Record<PkgStatus, string> = {
  malicious: rowStyles.sevCritical,
  vulnerable: rowStyles.sevHigh,
  suspicious: rowStyles.sevMedium,
  'not analysed': rowStyles.sevInfo,
  unverdictable: rowStyles.sevInfo,
  clean: rowStyles.sevLow,
}

const STATUS_TITLE: Record<PkgStatus, string> = {
  malicious: 'An OSV MAL- advisory matched this package',
  vulnerable: 'One or more CVE/GHSA advisories match this version',
  suspicious: 'GuardDog flagged behaviour, not a terminal verdict',
  'not analysed': 'The behavioural pass never produced a verdict for this package',
  unverdictable:
    'No version was ever resolved, so osv-scanner could not match a version-specific advisory. This package was never actually checked.',
  clean: 'Verdicted with a version and nothing matched',
}

export function packageStatus(r: Pick<PackageRow, 'maliciousCount' | 'advisoryCount' | 'suspiciousCount' | 'notAnalysedCount' | 'version'>): PkgStatus {
  if (r.maliciousCount > 0) return 'malicious'
  if (r.advisoryCount > 0) return 'vulnerable'
  if (r.suspiciousCount > 0) return 'suspicious'
  if (r.notAnalysedCount > 0) return 'not analysed'
  if (!r.version) return 'unverdictable'
  return 'clean'
}

function StatusChip({ status }: { status: PkgStatus }) {
  return <span className={`${rowStyles.sevBadge} ${STATUS_CLASS[status]}`} title={STATUS_TITLE[status]}>{status}</span>
}

/**
 * Which layer put this package in the graph. Derived rather than stored: the
 * anchor label is the discriminator (L1 repo scans anchor to GithubRepository,
 * L2 to every served BaseURL, an uploaded SBOM to nothing at all).
 */
export function originOf(r: { repos: string[]; baseUrls: string[]; harvestSource: string | null }): string {
  if (r.repos.length > 0) return 'L1 repo'
  if (r.baseUrls.length > 0) return 'L2 live'
  if (r.harvestSource === 'osv') return 'L1 SBOM'
  if (r.harvestSource === 'finding') return 'from finding'
  return 'unanchored'
}

function AnchorCell({ row }: { row: { repos: string[]; baseUrls: string[] } }) {
  if (row.repos.length > 0) return <ListCell items={row.repos} max={2} />
  if (row.baseUrls.length > 0) return <LinkedListCell items={row.baseUrls} max={2} />
  return <span className={rowStyles.nullCell}>floating</span>
}

function VersionCell({ version }: { version: string | null }) {
  if (version) return <Mono>{version}</Mono>
  return (
    <span className={`${rowStyles.listChip}`} title="No version resolved, so this package could not be OSV-verdicted">
      no version
    </span>
  )
}

export function worstSeverity(list: string[]): Severity {
  let worst: Severity = 'unknown'
  for (const s of list) {
    const n = normalizeSeverity(s)
    if (SEVERITY_RANK[n] < SEVERITY_RANK[worst]) worst = n
  }
  return worst
}

// --------------------------------------------------------------------------

const EXPORT_COLUMNS: Record<SheetKey, { key: string; header: string }[]> = {
  verdicts: [
    { key: 'verdict', header: 'Verdict' },
    { key: 'severity', header: 'Severity' },
    { key: 'advisoryId', header: 'Advisory / Rule' },
    { key: 'aliases', header: 'Aliases' },
    { key: 'name', header: 'Package' },
    { key: 'version', header: 'Version' },
    { key: 'ecosystem', header: 'Ecosystem' },
    { key: 'purl', header: 'purl' },
    { key: 'sourceTool', header: 'Tool' },
    { key: 'confidence', header: 'Confidence' },
    { key: 'softError', header: 'Not Analysed' },
    { key: 'title', header: 'Title' },
    { key: 'detail', header: 'Detail' },
    { key: 'harvestSource', header: 'Harvest Source' },
    { key: 'sourcePath', header: 'Manifest Path' },
    { key: 'baseUrls', header: 'Served By' },
    { key: 'repos', header: 'Repository' },
    { key: 'firstSeen', header: 'First Seen' },
    { key: 'lastSeen', header: 'Last Seen' },
  ],
  packages: [
    { key: 'name', header: 'Package' },
    { key: 'version', header: 'Version' },
    { key: 'ecosystem', header: 'Ecosystem' },
    { key: 'purl', header: 'purl' },
    { key: 'harvestSource', header: 'Harvest Source' },
    { key: 'sourcePath', header: 'Manifest Path' },
    { key: 'maliciousCount', header: 'Malicious' },
    { key: 'suspiciousCount', header: 'Suspicious' },
    { key: 'notAnalysedCount', header: 'Not Analysed' },
    { key: 'advisoryCount', header: 'Advisories' },
    { key: 'baseUrls', header: 'Served By' },
    { key: 'repos', header: 'Repository' },
    { key: 'firstSeen', header: 'First Seen' },
    { key: 'lastSeen', header: 'Last Seen' },
  ],
  advisories: [
    { key: 'advisoryId', header: 'Advisory' },
    { key: 'severity', header: 'Severity' },
    { key: 'cvss', header: 'CVSS' },
    { key: 'name', header: 'Package' },
    { key: 'version', header: 'Version' },
    { key: 'ecosystem', header: 'Ecosystem' },
    { key: 'purl', header: 'purl' },
    { key: 'title', header: 'Title' },
    { key: 'description', header: 'Description' },
    { key: 'harvestSource', header: 'Harvest Source' },
    { key: 'sourcePath', header: 'Manifest Path' },
    { key: 'baseUrls', header: 'Served By' },
    { key: 'repos', header: 'Repository' },
    { key: 'firstSeen', header: 'First Seen' },
    { key: 'updatedAt', header: 'Updated' },
  ],
}

const SHEET_LABEL: Record<SheetKey, string> = {
  verdicts: 'Verdicts',
  packages: 'Packages',
  advisories: 'Advisories',
}

const SHEET_EMPTY: Record<SheetKey, string> = {
  verdicts:
    'No malicious or suspicious package verdicts. Enable Supply-Chain Recon on a scan, or run a Supply-Chain scan from Other Scans (the offline OSV DB must be synced first).',
  packages:
    'No packages harvested yet. L2 mines them from source maps, imports, detected technologies and retire.js during recon; L1 reads an uploaded SBOM/lockfile or a cloned repo.',
  advisories:
    'No CVE/GHSA advisories matched. Note that packages with no resolved version are never checked at all - see the "unversioned" count above.',
}

interface Props {
  projectId: string | null
  /** Sheet to pre-select, e.g. from `/graph?table=supplyChainSca&sheet=advisories`. */
  initialSheet?: string | null
}

function isSheetKey(v: string | null | undefined): v is SheetKey {
  return v === 'verdicts' || v === 'packages' || v === 'advisories'
}

export const SupplyChainScaTable = memo(function SupplyChainScaTable({ projectId, initialSheet }: Props) {
  const [data, setData] = useState<ScaResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [active, setActive] = useState<SheetKey>(isSheetKey(initialSheet) ? initialSheet : 'verdicts')
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const fetchData = useCallback(async () => {
    if (!projectId) { setData(null); return }
    setIsLoading(true); setError(null)
    try {
      const res = await fetch(`/api/analytics/redzone/supplyChainSca?projectId=${encodeURIComponent(projectId)}`)
      if (!res.ok) {
        const b = await res.json().catch(() => ({ error: `HTTP ${res.status}` }))
        throw new Error(b.error || `HTTP ${res.status}`)
      }
      setData((await res.json()) as ScaResponse)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load')
    } finally { setIsLoading(false) }
  }, [projectId])

  useEffect(() => { fetchData() }, [fetchData])

  // The three sheets have disjoint row shapes; the shell + text filter work on
  // plain records, and each table body narrows back to its own row type.
  const rows = useMemo(
    () => (data?.sheets?.[active] ?? []) as unknown as Record<string, unknown>[],
    [data, active])
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const selectSheet = useCallback((key: SheetKey) => {
    setActive(key); setSearch(''); setLimit(PAGE_SIZE)
  }, [])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    filtered.length > 0
      ? { rows: filtered, sheetName: SHEET_LABEL[active], fileSlug: `supply-chain-sca-${active}`, columns: EXPORT_COLUMNS[active] }
      : undefined,
    [filtered, active])

  const m = data?.meta
  // The unversioned count is deliberately loud: those packages were inventoried
  // but never verdicted, so a short verdict list next to a big unversioned count
  // means "mostly unchecked", not "mostly clean".
  const meta = m
    ? [
        `packages: ${m.totalPackages}`,
        m.unversioned ? `unversioned (unchecked): ${m.unversioned}` : null,
        `malicious: ${m.malicious}`,
        `suspicious: ${m.suspicious}`,
        m.notAnalysed ? `not analysed: ${m.notAnalysed}` : null,
        `advisories: ${m.advisories}`,
        m.byEcosystem?.length ? m.byEcosystem.map(e => `${e.ecosystem} ${e.count}`).join(', ') : null,
        m.truncated?.[active] ? `SHEET CAPPED - showing the first ${rows.length}` : null,
      ].filter(Boolean).join(' · ')
    : undefined

  const counts: Record<SheetKey, number> = {
    verdicts: data?.sheets?.verdicts?.length ?? 0,
    packages: data?.sheets?.packages?.length ?? 0,
    advisories: data?.sheets?.advisories?.length ?? 0,
  }

  return (
    <RedZoneTableShell
      title="Supply-Chain SCA (packages, verdicts, advisories)"
      meta={meta}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder={`Search ${SHEET_LABEL[active].toLowerCase()}...`}
      exportConfig={exportConfig}
      onRefresh={fetchData}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel={SHEET_EMPTY[active]}
      toolbar={(
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', padding: '8px 4px' }}>
          {(Object.keys(SHEET_LABEL) as SheetKey[]).map(key => {
            const isActive = key === active
            return (
              <button
                key={key}
                onClick={() => selectSheet(key)}
                style={{
                  fontSize: 12, padding: '4px 10px', borderRadius: 6, cursor: 'pointer',
                  border: '1px solid ' + (isActive ? '#f59e0b' : 'rgba(255,255,255,0.15)'),
                  background: isActive ? 'rgba(245,158,11,0.15)' : 'transparent',
                  color: isActive ? '#f59e0b' : 'inherit', fontWeight: isActive ? 600 : 400,
                }}
              >
                {SHEET_LABEL[key]} <span style={{ opacity: 0.6 }}>({counts[key]})</span>
              </button>
            )
          })}
        </div>
      )}
    >
      {active === 'verdicts' ? (
        <table className={rowStyles.table}>
          <thead>
            <tr>
              <th>Verdict</th><th>Sev</th><th>Advisory / Rule</th><th>Package</th>
              <th>Version</th><th>Eco</th><th>Tool</th><th>Origin</th>
              <th>Anchor</th><th>Title</th><th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {(sliced as unknown as VerdictRow[]).map((r, i) => (
              <tr key={r.findingId || `${r.purl}-${i}`}>
                <td><VerdictChip row={r} /></td>
                <td><SeverityBadge severity={normalizeSeverity(r.severity)} /></td>
                <td>
                  <Mono>{r.advisoryId || '-'}</Mono>
                  {r.aliases.length > 0 && <ListCell items={r.aliases} max={2} />}
                </td>
                <td>{r.name ? <Mono>{r.name}</Mono> : <span className={rowStyles.nullCell}>-</span>}</td>
                <td><VersionCell version={r.version} /></td>
                <td>{r.ecosystem || '-'}</td>
                <td>{r.sourceTool || '-'}</td>
                <td><span className={rowStyles.listChip}>{originOf(r)}</span></td>
                <td><AnchorCell row={r} /></td>
                <td><Truncated text={r.title} max={240} /></td>
                <td><Truncated text={r.detail} max={240} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : active === 'packages' ? (
        <table className={rowStyles.table}>
          <thead>
            <tr>
              <th>Status</th><th>Package</th><th>Version</th><th>Eco</th>
              <th>Harvest</th><th>Origin</th><th>Anchor</th>
              <th>Mal</th><th>Susp</th><th>Unchecked</th><th>Advisories</th><th>Worst</th>
            </tr>
          </thead>
          <tbody>
            {(sliced as unknown as PackageRow[]).map((r, i) => (
              <tr key={r.purl || i}>
                <td><StatusChip status={packageStatus(r)} /></td>
                <td>{r.name ? <Mono>{r.name}</Mono> : <Truncated text={r.purl} max={200} />}</td>
                <td><VersionCell version={r.version} /></td>
                <td>{r.ecosystem || '-'}</td>
                <td><span className={rowStyles.listChip}>{r.harvestSource || 'unknown'}</span></td>
                <td><span className={rowStyles.listChip}>{originOf(r)}</span></td>
                <td><AnchorCell row={r} /></td>
                <td><NumCell value={r.maliciousCount} /></td>
                <td><NumCell value={r.suspiciousCount} /></td>
                <td><NumCell value={r.notAnalysedCount} /></td>
                <td><NumCell value={r.advisoryCount} /></td>
                <td>
                  {r.advisorySeverities.length > 0
                    ? <SeverityBadge severity={worstSeverity(r.advisorySeverities)} />
                    : <span className={rowStyles.nullCell}>-</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <table className={rowStyles.table}>
          <thead>
            <tr>
              <th>Advisory</th><th>Sev</th><th>CVSS</th><th>Package</th>
              <th>Version</th><th>Eco</th><th>Origin</th><th>Anchor</th>
              <th>Title</th><th>Description</th>
            </tr>
          </thead>
          <tbody>
            {(sliced as unknown as AdvisoryRow[]).map((r, i) => (
              <tr key={`${r.advisoryId}-${r.purl}-${i}`}>
                <td><Mono>{r.advisoryId}</Mono></td>
                <td><SeverityBadge severity={normalizeSeverity(r.severity)} /></td>
                <td>{r.cvss ? <Truncated text={r.cvss} max={200} /> : <span className={rowStyles.nullCell}>-</span>}</td>
                <td>{r.name ? <Mono>{r.name}</Mono> : <Truncated text={r.purl} max={200} />}</td>
                <td><VersionCell version={r.version} /></td>
                <td>{r.ecosystem || '-'}</td>
                <td><span className={rowStyles.listChip}>{originOf(r)}</span></td>
                <td><AnchorCell row={r} /></td>
                <td><Truncated text={r.title} max={240} /></td>
                <td><Truncated text={r.description} max={280} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {limit < filtered.length && (
        <div className={rowStyles.loadMoreBar}>
          <button className={rowStyles.loadMoreBtn} onClick={() => setLimit(l => l + PAGE_SIZE)}>
            Showing {sliced.length} of {filtered.length} - Load more
          </button>
        </div>
      )}
    </RedZoneTableShell>
  )
})
