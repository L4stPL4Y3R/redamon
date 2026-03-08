'use client'

import { useMemo } from 'react'
import { useTheme } from '@/hooks/useTheme'
import { ChartCard } from './ChartCard'
import type { VulnerabilityData, AttackSurfaceData, GraphOverviewData } from '../types'

interface RiskScoreGaugeProps {
  vulnData: VulnerabilityData | undefined
  surfaceData: AttackSurfaceData | undefined
  graphData: GraphOverviewData | undefined
  exploitSuccessCount: number
  chainFindingsBySeverity: { severity: string; count: number }[] | undefined
  isLoading: boolean
}

function severityWeight(severity: string): number {
  switch (severity?.toLowerCase()) {
    case 'critical': return 40
    case 'high': return 20
    case 'medium': return 5
    case 'low': return 1
    default: return 0
  }
}

function scoreColor(score: number): string {
  if (score >= 80) return '#e53935'
  if (score >= 60) return '#f97316'
  if (score >= 40) return '#f59e0b'
  if (score >= 20) return '#3b82f6'
  return '#22c55e'
}

function scoreLabel(score: number): string {
  if (score >= 80) return 'Critical'
  if (score >= 60) return 'High'
  if (score >= 40) return 'Medium'
  if (score >= 20) return 'Low'
  return 'Minimal'
}

export function RiskScoreGauge({ vulnData, surfaceData, graphData, exploitSuccessCount, chainFindingsBySeverity, isLoading }: RiskScoreGaugeProps) {
  useTheme()

  const { score, color, label } = useMemo(() => {
    if (!vulnData) return { score: 0, color: '#22c55e', label: 'N/A' }

    // 1. Vulnerability nodes × severity weight
    const vulnScore = (vulnData.severityDistribution || []).reduce(
      (sum, d) => sum + d.count * severityWeight(d.severity), 0
    )
    // 2. CVE nodes × severity weight
    const cveScore = (vulnData.cveSeverity || []).reduce(
      (sum, d) => sum + d.count * severityWeight(d.severity), 0
    )
    // 3. GVM exploits (QoD=100 = confirmed compromise)
    const gvmExploitScore = (vulnData.exploits?.length || 0) * 100
    // 4. CISA KEV (known exploited in the wild — highest threat)
    const kevScore = (vulnData.exploits?.filter(e => e.cisaKev)?.length || 0) * 120
    // 5. Chain exploit successes (agent actually exploited it)
    const chainExploitScore = exploitSuccessCount * 100
    // 6. Chain findings by severity (non-exploit: credential_found, access_gained, etc.)
    const chainFindingsScore = (chainFindingsBySeverity || []).reduce(
      (sum, d) => sum + d.count * severityWeight(d.severity), 0
    )
    // 7. CVEs with CAPEC attack patterns (mapped = more actionable)
    const cvesWithCapec = new Set(
      vulnData.cveChains?.filter(c => c.capecId).map(c => c.cveId)
    ).size
    const capecScore = cvesWithCapec * 15
    // 8. GitHub secrets (direct credential exposure)
    const secretsScore = (vulnData.githubSecrets?.secrets || 0) * 60
    // 9. GitHub sensitive files (indirect exposure — .env, config)
    const sensitiveFilesScore = (vulnData.githubSecrets?.sensitiveFiles || 0) * 30
    // 10. Injectable parameters (DAST-confirmed injection points)
    const injectableCount = surfaceData?.parameterAnalysis?.reduce(
      (s, p) => s + p.injectable, 0
    ) || 0
    const injectableScore = injectableCount * 25
    // 11. Expired certificates (MITM / trust risk)
    const expiredCertScore = (graphData?.certificateHealth?.expired || 0) * 10
    // 12. Missing security headers penalty (defensive weakness)
    // Each missing critical header across BaseURLs adds risk
    const SEC_HEADERS = [
      'strict-transport-security', 'content-security-policy',
      'x-frame-options', 'x-content-type-options',
    ]
    let missingHeaderScore = 0
    const totalBaseUrls = graphData?.endpointCoverage?.baseUrls || 0
    if (totalBaseUrls > 0 && surfaceData?.securityHeaders) {
      const headerMap = new Map(
        surfaceData.securityHeaders.map(h => [h.name.toLowerCase(), h.count])
      )
      for (const hdr of SEC_HEADERS) {
        const coverage = (headerMap.get(hdr) || 0) / totalBaseUrls
        // Penalty for missing headers: up to 5 per header × BaseURLs without it
        missingHeaderScore += Math.round((1 - Math.min(coverage, 1)) * 5)
      }
    }

    const raw = vulnScore + cveScore + gvmExploitScore + kevScore
      + chainExploitScore + chainFindingsScore + capecScore
      + secretsScore + sensitiveFilesScore + injectableScore
      + expiredCertScore + missingHeaderScore
    // Logarithmic scale: score = min(100, 15 * ln(raw + 1))
    // k=15 (tuned down from 20 to accommodate broader input range)
    const normalized = Math.min(100, Math.round(15 * Math.log(raw + 1)))

    return {
      score: normalized,
      color: scoreColor(normalized),
      label: scoreLabel(normalized),
    }
  }, [vulnData, surfaceData, graphData, exploitSuccessCount, chainFindingsBySeverity])

  const isEmpty = !vulnData

  // SVG gauge — use a canvas-like approach: draw everything relative to a
  // generous viewBox so nothing gets clipped by the .card overflow:hidden
  const sw = 14
  const r = 70
  // Arc from ~172° to ~8° so round caps don't stick out sideways
  const arcStart = Math.PI - 0.14
  const arcEnd = 0.14
  const arcRange = arcStart - arcEnd
  const scoreAngle = arcStart - (score / 100) * arcRange
  // viewBox sized so arc + stroke + caps fit with room to spare
  const cx = 100
  const cy = 90
  const vbW = 200
  const vbH = 130

  const bgArcD = describeArc(cx, cy, r, arcEnd, arcStart)
  const fgArcD = describeArc(cx, cy, r, scoreAngle, arcStart)

  return (
    <ChartCard title="Risk Score" subtitle={label} isLoading={isLoading} isEmpty={isEmpty}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', height: 220, padding: '8px 0' }}>
        <svg
          viewBox={`0 0 ${vbW} ${vbH}`}
          style={{ width: '100%', maxWidth: 240, flex: '1 1 auto', marginTop: -80 }}
        >
          {/* Background arc */}
          <path d={bgArcD} fill="none" stroke="var(--border-secondary)" strokeWidth={sw} strokeLinecap="round" />
          {/* Score arc */}
          {score > 0 && (
            <path d={fgArcD} fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" />
          )}
          {/* Score text */}
          <text x={cx} y={cy - 10} textAnchor="middle" fontSize={38} fontWeight={700} fill={color}>
            {score}
          </text>
          <text x={cx} y={cy + 14} textAnchor="middle" fontSize={13} fill="var(--text-tertiary)">
            / 100
          </text>
        </svg>
        <div style={{ fontSize: 11, color: 'var(--text-tertiary)', paddingBottom: 4, textAlign: 'center' }}>
          12 signals: vulns, CVEs, exploits, KEV, chains, secrets, injection & headers
        </div>
      </div>
    </ChartCard>
  )
}

function describeArc(cx: number, cy: number, r: number, startAngle: number, endAngle: number): string {
  const x1 = cx + r * Math.cos(startAngle)
  const y1 = cy - r * Math.sin(startAngle)
  const x2 = cx + r * Math.cos(endAngle)
  const y2 = cy - r * Math.sin(endAngle)
  const largeArc = Math.abs(endAngle - startAngle) > Math.PI ? 1 : 0
  return `M ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2}`
}
