'use client'

import { useMemo } from 'react'
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Tooltip } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartPalette, getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { GraphOverviewData, VulnerabilityData, AttackSurfaceData } from '../types'

interface SecurityPostureRadarProps {
  graphData: GraphOverviewData | undefined
  vulnData: VulnerabilityData | undefined
  surfaceData: AttackSurfaceData | undefined
  exploitSuccessCount: number
  chainFindingsCount: number
  isLoading: boolean
}

/** Logarithmic normalization: min(100, round(scale * ln(value + 1)))
 *  Gives meaningful scores to small values without saturating too fast */
function logNorm(value: number, scale: number): number {
  if (value <= 0) return 0
  return Math.min(100, Math.round(scale * Math.log(value + 1)))
}

export function SecurityPostureRadar({ graphData, vulnData, surfaceData, exploitSuccessCount, chainFindingsCount, isLoading }: SecurityPostureRadarProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getChartPalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  const chartData = useMemo(() => {
    if (!graphData) return []

    // Vuln density: Vulnerability nodes + CVE nodes + GitHub secrets + chain findings
    const totalVulns = vulnData?.severityDistribution?.reduce((s, d) => s + d.count, 0) || 0
    const totalCves = vulnData?.cveSeverity?.reduce((s, d) => s + d.count, 0) || 0
    const secretsCount = (vulnData?.githubSecrets?.secrets || 0) + (vulnData?.githubSecrets?.sensitiveFiles || 0)
    // Exploitability: GVM exploits + attack chain successes + CISA KEV + CVEs with attack patterns
    const gvmExploits = vulnData?.exploits?.length || 0
    const kevCount = vulnData?.exploits?.filter(e => e.cisaKev)?.length || 0
    const cvesWithCapec = new Set(vulnData?.cveChains?.filter(c => c.capecId).map(c => c.cveId)).size
    const exploitCount = gvmExploits + exploitSuccessCount + kevCount + cvesWithCapec
    const infraStats = graphData.infrastructureStats
    // Attack surface: subdomains + IPs + open ports + web apps + endpoints + params + techs
    const openPorts = surfaceData?.ports?.reduce((s, p) => s + p.count, 0) || 0
    const techCount = surfaceData?.technologies?.length || 0
    const attackSurfaceRaw = graphData.subdomainStats.total + infraStats.totalIps + openPorts
      + graphData.endpointCoverage.baseUrls + graphData.endpointCoverage.endpoints
      + graphData.endpointCoverage.parameters + techCount
    // Injectable ratio: injectable params / total params across all positions
    const totalParams = surfaceData?.parameterAnalysis?.reduce((s, p) => s + p.total, 0) || 0
    const injectableParams = surfaceData?.parameterAnalysis?.reduce((s, p) => s + p.injectable, 0) || 0
    // Security headers: weighted coverage across all BaseURLs
    // Weight reflects severity: 3=critical, 2=high, 1=low
    const SEC_HEADERS: [string, number][] = [
      ['strict-transport-security', 3],   // Critical — MITM prevention
      ['content-security-policy', 3],     // Critical — XSS/injection defense
      ['x-frame-options', 2],            // High — clickjacking prevention
      ['x-content-type-options', 2],     // High — MIME sniffing prevention
      ['x-xss-protection', 1],           // Low — deprecated, CSP supersedes
      ['referrer-policy', 1],            // Low — data leakage prevention
      ['permissions-policy', 1],         // Low — browser feature restriction
    ]
    const totalBaseUrls = graphData.endpointCoverage.baseUrls
    let secHeaderScore = 0
    if (totalBaseUrls > 0 && surfaceData?.securityHeaders?.length) {
      const headerMap = new Map(surfaceData.securityHeaders.map(h => [h.name.toLowerCase(), h.count]))
      const totalWeight = SEC_HEADERS.reduce((s, [, w]) => s + w, 0)
      const weightedSum = SEC_HEADERS.reduce((sum, [hdr, weight]) => {
        const coverage = Math.min((headerMap.get(hdr) || 0) / totalBaseUrls, 1)
        return sum + weight * coverage
      }, 0)
      secHeaderScore = Math.round((weightedSum / totalWeight) * 100)
    }
    const certTotal = graphData.certificateHealth.total
    const certHealthy = Math.max(0, certTotal - graphData.certificateHealth.expired - graphData.certificateHealth.expiringSoon)

    return [
      {
        metric: 'Attack Surface',
        value: logNorm(attackSurfaceRaw, 13),
        raw: attackSurfaceRaw,
      },
      {
        metric: 'Vuln Density',
        value: logNorm(totalVulns + totalCves + secretsCount + chainFindingsCount, 15),
        raw: totalVulns + totalCves + secretsCount + chainFindingsCount,
      },
      {
        metric: 'Exploitability',
        value: logNorm(exploitCount, 25),
        raw: exploitCount,
      },
      {
        metric: 'Cert Health',
        value: certTotal > 0 ? Math.round((certHealthy / certTotal) * 100) : 0,
        raw: certHealthy,
      },
      {
        metric: 'Injectable',
        value: totalParams > 0 ? Math.round((injectableParams / totalParams) * 100) : 0,
        raw: injectableParams,
      },
      {
        metric: 'Sec Headers',
        value: secHeaderScore,
        raw: secHeaderScore,
      },
    ]
  }, [graphData, vulnData, surfaceData, exploitSuccessCount, chainFindingsCount])

  const isEmpty = !graphData || graphData.totalNodes === 0

  return (
    <ChartCard title="Security Posture" subtitle="Overall risk profile" isLoading={isLoading} isEmpty={isEmpty}>
      <ResponsiveContainer width="100%" height={280}>
        <RadarChart data={chartData}>
          <PolarGrid stroke={chrome.gridColor} />
          <PolarAngleAxis dataKey="metric" tick={{ fontSize: 12, fill: chrome.axisColor }} />
          <PolarRadiusAxis tick={false} axisLine={false} domain={[0, 100]} />
          <Radar
            name="Posture"
            dataKey="value"
            stroke={palette[0]}
            fill={palette[0]}
            fillOpacity={0.2}
            strokeWidth={2}
          />
          <Tooltip
            contentStyle={tooltipStyle}
            itemStyle={tooltipItemStyle}
            labelStyle={tooltipLabelStyle}
            formatter={(value: number, _name: string, props: { payload?: { raw?: number } }) =>
              [`${value}% (${props.payload?.raw ?? 0} raw)`, 'Score']
            }
          />
        </RadarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
