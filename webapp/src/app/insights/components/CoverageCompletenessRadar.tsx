'use client'

import { useMemo } from 'react'
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Tooltip } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartPalette, getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { GraphOverviewData } from '../types'

interface CoverageCompletenessRadarProps {
  data: GraphOverviewData | undefined
  isLoading: boolean
}

const METRICS = [
  { key: 'DNS Enum', nodeType: 'Subdomain' },
  { key: 'Port Scan', nodeType: 'Port' },
  { key: 'HTTP Probe', nodeType: 'BaseURL' },
  { key: 'Tech Detect', nodeType: 'Technology' },
  { key: 'Vuln Scan', nodeType: 'Vulnerability' },
  { key: 'Crawling', nodeType: 'Endpoint' },
]

export function CoverageCompletenessRadar({ data, isLoading }: CoverageCompletenessRadarProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getChartPalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.nodeCounts?.length) return []

    const counts = new Map<string, number>()
    for (const n of data.nodeCounts) {
      counts.set(n.label, n.count)
    }

    const values = METRICS.map(m => counts.get(m.nodeType) || 0)
    const maxVal = Math.max(...values, 1)

    return METRICS.map((m, i) => ({
      metric: m.key,
      value: Math.round((values[i] / maxVal) * 100),
      raw: values[i],
    }))
  }, [data])

  const isEmpty = !data || data.totalNodes === 0

  return (
    <ChartCard title="Recon Coverage" subtitle="Phase completeness" isLoading={isLoading} isEmpty={isEmpty}>
      <ResponsiveContainer width="100%" height={220}>
        <RadarChart data={chartData}>
          <PolarGrid stroke={chrome.gridColor} />
          <PolarAngleAxis dataKey="metric" tick={{ fontSize: 9, fill: chrome.axisColor }} />
          <PolarRadiusAxis tick={false} axisLine={false} domain={[0, 100]} />
          <Radar
            name="Coverage"
            dataKey="value"
            stroke={palette[4]}
            fill={palette[4]}
            fillOpacity={0.2}
            strokeWidth={2}
          />
          <Tooltip
            contentStyle={tooltipStyle}
            itemStyle={tooltipItemStyle}
            labelStyle={tooltipLabelStyle}
            formatter={(value: number, _name: string, props: { payload?: { raw?: number } }) =>
              [`${value}% (${props.payload?.raw ?? 0} nodes)`, 'Coverage']
            }
          />
        </RadarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
