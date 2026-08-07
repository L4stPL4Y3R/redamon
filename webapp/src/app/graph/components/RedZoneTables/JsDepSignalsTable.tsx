'use client'

import { memo, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneTable } from './useRedZoneTable'
import type { RedZoneExportConfig } from './exportCsv'
import { ExternalLink } from '@/components/ui'
import { githubSlugToUrl, isGithubSlug } from '@/lib/url-utils'
import {
  SeverityBadge,
  Mono,
  Truncated,
  UrlCell,
  HostCell,
  filterRowsByText,
} from './formatters'
import { normalizeSeverity } from './types'
import rowStyles from './RedZoneTableRow.module.css'

/**
 * JS Dep Signals: JsReconFinding nodes that carry dependency/build-hygiene
 * signal (exposed source maps, dev comments, dependency confusion, detected
 * frameworks, referenced cloud assets).
 *
 * This is NOT the package supply-chain feature. Malicious/vulnerable package
 * verdicts (Package / MalPackageFinding / OSV advisories) live in
 * SupplyChainScaTable. This table used to be labelled "Supply-Chain", which
 * made the two indistinguishable in the UI.
 *
 * The API slug stays `supplyChain` - the route and its tests predate the
 * rename and renaming the endpoint would buy nothing.
 */
interface JsDepSignalsRow {
  id: string
  findingType: string
  severity: string
  confidence: string | null
  title: string | null
  detail: string | null
  evidence: string | null
  sourceUrl: string | null
  baseUrlProp: string | null
  packageName: string | null
  version: string | null
  cloudProvider: string | null
  cloudAssetType: string | null
  discoveredAt: string | null
  baseUrl: string | null
  subdomain: string | null
  parentJsUrl: string | null
}

const PAGE_SIZE = 100

const TYPE_LABELS: Record<string, string> = {
  dependency_confusion: 'dep-confusion',
  source_map_exposure: 'sourcemap',
  source_map_reference: 'map-ref',
  dev_comment: 'dev-comment',
  framework: 'framework',
  cloud_asset: 'cloud-asset',
}

function TypeChip({ t }: { t: string }) {
  return <span className={rowStyles.listChip}>{TYPE_LABELS[t] || t}</span>
}

interface Props { projectId: string | null }

export const JsDepSignalsTable = memo(function JsDepSignalsTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<JsDepSignalsRow>('supplyChain', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    rows.length > 0
      ? {
          rows: filtered,
          sheetName: 'JS-Dep-Signals',
          fileSlug: 'redzone-js-dep-signals',
          columns: [
            { key: 'findingType', header: 'Type' },
            { key: 'severity', header: 'Severity' },
            { key: 'confidence', header: 'Confidence' },
            { key: 'title', header: 'Title' },
            { key: 'detail', header: 'Detail' },
            { key: 'evidence', header: 'Evidence' },
            { key: 'packageName', header: 'Package / Framework' },
            { key: 'version', header: 'Version' },
            { key: 'cloudProvider', header: 'Cloud Provider' },
            { key: 'cloudAssetType', header: 'Cloud Asset Type' },
            { key: 'sourceUrl', header: 'Source URL' },
            { key: 'parentJsUrl', header: 'Parent JS File' },
            { key: 'baseUrl', header: 'BaseURL' },
            { key: 'subdomain', header: 'Subdomain' },
            { key: 'discoveredAt', header: 'Discovered At' },
          ],
        }
      : undefined,
    [filtered, rows.length],
  )

  const m = data?.meta as any
  const meta = rows.length && m?.byType
    ? Object.entries(m.byType).map(([k, v]) => `${k}:${v}`).join(' · ')
    : undefined

  return (
    <RedZoneTableShell
      title="JS Dep Signals (source maps, dev comments, dependency confusion)"
      meta={meta}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search package, framework, title, URL..."
      exportConfig={exportConfig}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No JS dependency signals yet. Enable js_recon with dependency-confusion + source-map + framework detection. Malicious/vulnerable package verdicts live in the Supply-Chain SCA table."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <th>Type</th>
            <th>Sev</th>
            <th>Title</th>
            <th>Package / Framework</th>
            <th>Version</th>
            <th>Source URL</th>
            <th>Subdomain</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={r.id || `${r.findingType}-${i}`}>
              <td><TypeChip t={r.findingType} /></td>
              <td><SeverityBadge severity={normalizeSeverity(r.severity)} /></td>
              <td><Truncated text={r.title} max={260} /></td>
              <td>
                {r.packageName ? (
                  <Mono>
                    {isGithubSlug(r.packageName)
                      ? <ExternalLink href={githubSlugToUrl(r.packageName)}>{r.packageName}</ExternalLink>
                      : r.packageName}
                  </Mono>
                ) : r.cloudProvider ? <Mono>{r.cloudProvider}{r.cloudAssetType ? ' · ' + r.cloudAssetType : ''}</Mono>
                  : <span className={rowStyles.nullCell}>-</span>}
              </td>
              <td>{r.version ? <Mono>{r.version}</Mono> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td><UrlCell url={r.sourceUrl} max={260} /></td>
              <td>{r.subdomain ? <HostCell host={r.subdomain} /> : <Truncated text={r.subdomain} max={160} />}</td>
              <td><Truncated text={r.evidence || r.detail} max={260} /></td>
            </tr>
          ))}
        </tbody>
      </table>
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
