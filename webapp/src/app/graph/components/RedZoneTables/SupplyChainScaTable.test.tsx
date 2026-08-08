/**
 * Render tests for the Supply-Chain SCA table.
 *
 * The helper tests cover the derivation rules; this covers what an operator
 * actually sees: the three-state verdict chip, the unversioned marker, sheet
 * switching, and the fact that a capped sheet says so.
 *
 * Run: npx vitest run src/app/graph/components/RedZoneTables/SupplyChainScaTable.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createElement } from 'react'
import { SupplyChainScaTable } from './SupplyChainScaTable'

/**
 * The shared shell now restores per-column filters from user preferences, so
 * every table mounts a react-query consumer. Each test gets a fresh client so
 * one test's cached preferences cannot leak into the next.
 */
function renderWithClient(ui: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return render(createElement(QueryClientProvider, { client }, ui))
}


const RESPONSE = {
  sheets: {
    verdicts: [
      {
        findingId: 'f-mal', verdict: 'malicious', severity: 'high', sourceTool: 'osv',
        advisoryId: 'MAL-2026-9999', title: 'planted malware', detail: 'typosquat',
        confidence: 'malicious', softError: false, aliases: ['GHSA-0001'],
        firstSeen: null, lastSeen: null, purl: 'pkg:npm/axios@1.14.1', name: 'axios',
        version: '1.14.1', ecosystem: 'npm', harvestSource: 'retirejs',
        sourcePath: 'web/package-lock.json', baseUrls: ['https://t.invalid'], repos: [], sboms: [],
      },
      {
        findingId: 'f-soft', verdict: 'suspicious', severity: 'low', sourceTool: 'guarddog',
        advisoryId: 'download-package', title: 'download-package', detail: 'registry down',
        confidence: 'suspicious', softError: true, aliases: [],
        firstSeen: null, lastSeen: null, purl: 'pkg:npm/axios@1.14.1', name: 'axios',
        version: '1.14.1', ecosystem: 'npm', harvestSource: 'retirejs',
        sourcePath: null, baseUrls: [], repos: ['acme/app'], sboms: [],
      },
    ],
    packages: [
      {
        purl: 'pkg:npm/lodash', name: 'lodash', version: null, ecosystem: 'npm',
        harvestSource: 'sourcemap', sourcePath: null, firstSeen: null, lastSeen: null,
        baseUrls: ['https://t.invalid'], repos: [], sboms: [],
        maliciousCount: 0, suspiciousCount: 0, notAnalysedCount: 0,
        advisoryCount: 0, advisorySeverities: [],
      },
    ],
    advisories: [
      {
        advisoryId: 'GHSA-it-cve', severity: 'critical', cvss: 'CVSS:3.1/AV:N',
        title: 'SSRF', description: 'server side request forgery',
        purl: 'pkg:npm/axios@1.14.1', name: 'axios', version: '1.14.1',
        ecosystem: 'npm', harvestSource: 'retirejs', sourcePath: null,
        firstSeen: null, updatedAt: null, baseUrls: [], repos: [], sboms: [],
      },
    ],
  },
  meta: {
    totalPackages: 12, unversioned: 5, malicious: 1, suspicious: 1,
    notAnalysed: 1, advisories: 1,
    byEcosystem: [{ ecosystem: 'npm', count: 12, unversioned: 5 }],
    truncated: { verdicts: false, packages: false, advisories: false },
  },
}

function mockFetch(body: unknown, ok = true) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok,
    json: async () => body,
  }))
}

beforeEach(() => mockFetch(RESPONSE))
// vitest runs without `globals: true`, so RTL's auto-cleanup never registers
// and mounted trees would accumulate across tests (every query then finds
// duplicates). Same explicit cleanup the other table tests use.
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('SupplyChainScaTable', () => {
  test('renders the verdicts sheet first and marks the malicious row', async () => {
    renderWithClient(<SupplyChainScaTable projectId="p1" />)
    expect(await screen.findByText('MAL-2026-9999')).toBeInTheDocument()
    expect(screen.getByText('malicious')).toBeInTheDocument()
  })

  // The distinction the whole feature turns on: a package GuardDog never
  // analysed must not render as a suspicious hit.
  test('a soft-error finding renders as "not analysed", not "suspicious"', async () => {
    renderWithClient(<SupplyChainScaTable projectId="p1" />)
    expect(await screen.findByText('not analysed')).toBeInTheDocument()
    expect(screen.queryByText('suspicious')).toBeNull()
  })

  test('the header surfaces the unversioned (unchecked) count', async () => {
    renderWithClient(<SupplyChainScaTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText(/unversioned \(unchecked\): 5/)).toBeInTheDocument())
  })

  test('switching to Packages shows the unverdictable status and "no version"', async () => {
    renderWithClient(<SupplyChainScaTable projectId="p1" />)
    await screen.findByText('MAL-2026-9999')
    fireEvent.click(screen.getByRole('button', { name: /Packages/ }))
    expect(await screen.findByText('unverdictable')).toBeInTheDocument()
    expect(screen.getByText('no version')).toBeInTheDocument()
  })

  test('initialSheet deep-links straight into the advisories sheet', async () => {
    renderWithClient(<SupplyChainScaTable projectId="p1" initialSheet="advisories" />)
    expect(await screen.findByText('GHSA-it-cve')).toBeInTheDocument()
  })

  test('an unknown initialSheet falls back to verdicts instead of blanking', async () => {
    renderWithClient(<SupplyChainScaTable projectId="p1" initialSheet="bogus" />)
    expect(await screen.findByText('MAL-2026-9999')).toBeInTheDocument()
  })

  test('a capped sheet says so instead of presenting a partial list as complete', async () => {
    mockFetch({ ...RESPONSE, meta: { ...RESPONSE.meta, truncated: { verdicts: true, packages: false, advisories: false } } })
    renderWithClient(<SupplyChainScaTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText(/SHEET CAPPED/)).toBeInTheDocument())
  })

  test('a response with no meta renders rather than crashing', async () => {
    mockFetch({ sheets: RESPONSE.sheets })
    renderWithClient(<SupplyChainScaTable projectId="p1" />)
    expect(await screen.findByText('MAL-2026-9999')).toBeInTheDocument()
  })

  test('a malformed response renders the empty state, not a crash', async () => {
    mockFetch({})
    renderWithClient(<SupplyChainScaTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText(/No malicious or suspicious package verdicts/)).toBeInTheDocument())
  })

  test('a failed request surfaces the error', async () => {
    mockFetch({ error: 'neo4j down' }, false)
    renderWithClient(<SupplyChainScaTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('neo4j down')).toBeInTheDocument())
  })
})
