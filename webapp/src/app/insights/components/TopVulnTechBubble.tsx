'use client'

import { useMemo } from 'react'
import { ScatterChart, Scatter, XAxis, YAxis, ZAxis, ResponsiveContainer, Tooltip, Cell } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartChrome, getChartPalette, getTooltipStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { CveChain } from '../types'

interface TopVulnTechBubbleProps {
  data: CveChain[] | undefined
  isLoading: boolean
}

interface TechBubble {
  tech: string
  cveCount: number
  maxCvss: number
  criticalCount: number
  index: number
}

export function TopVulnTechBubble({ data, isLoading }: TopVulnTechBubbleProps) {
  const { theme } = useTheme()
  const chrome = useMemo(() => getChartChrome(), [theme])
  const palette = useMemo(() => getChartPalette(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []

    const byTech = new Map<string, { cves: Set<string>; maxCvss: number; criticals: number }>()
    for (const chain of data) {
      const existing = byTech.get(chain.tech)
      if (existing) {
        existing.cves.add(chain.cveId)
        if (chain.cvss != null && chain.cvss > existing.maxCvss) existing.maxCvss = chain.cvss
        if (chain.cveSeverity?.toLowerCase() === 'critical') existing.criticals++
      } else {
        byTech.set(chain.tech, {
          cves: new Set([chain.cveId]),
          maxCvss: chain.cvss ?? 0,
          criticals: chain.cveSeverity?.toLowerCase() === 'critical' ? 1 : 0,
        })
      }
    }

    return Array.from(byTech.entries())
      .map(([tech, info]) => ({
        tech,
        cveCount: info.cves.size,
        maxCvss: info.maxCvss,
        criticalCount: info.criticals,
      }))
      .sort((a, b) => b.cveCount - a.cveCount)
      .slice(0, 12)
      .map((d, i) => ({ ...d, index: i + 1 } as TechBubble))
  }, [data])

  const totalTechs = chartData.length

  return (
    <ChartCard
      title="Riskiest Technologies"
      subtitle={`${totalTechs} technologies`}
      isLoading={isLoading}
      isEmpty={chartData.length === 0}
    >
      <ResponsiveContainer width="100%" height={220}>
        <ScatterChart margin={{ left: 0, right: 8, top: 8, bottom: 8 }}>
          <XAxis
            dataKey="index"
            type="number"
            tick={false}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            dataKey="cveCount"
            type="number"
            name="CVEs"
            tick={{ fontSize: 11, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={35}
            label={{ value: 'CVEs', angle: -90, position: 'insideLeft', fontSize: 10, fill: chrome.axisColor }}
          />
          <ZAxis dataKey="maxCvss" range={[60, 400]} name="Max CVSS" />
          <Tooltip
            content={({ payload }) => {
              if (!payload?.length) return null
              const d = payload[0].payload as TechBubble
              return (
                <div style={{ ...tooltipStyle, padding: '8px 12px' }}>
                  <div style={{ fontWeight: 600, marginBottom: 4 }}>{d.tech}</div>
                  <div style={{ fontSize: 11 }}>CVEs: {d.cveCount}</div>
                  <div style={{ fontSize: 11 }}>Max CVSS: {d.maxCvss}</div>
                  <div style={{ fontSize: 11 }}>Critical: {d.criticalCount}</div>
                </div>
              )
            }}
          />
          <Scatter data={chartData} isAnimationActive={false}>
            {chartData.map((entry, i) => (
              <Cell
                key={i}
                fill={palette[i % palette.length]}
                opacity={0.75}
              />
            ))}
          </Scatter>
        </ScatterChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
