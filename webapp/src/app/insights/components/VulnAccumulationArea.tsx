'use client'

import { useMemo } from 'react'
import { AreaChart, Area, XAxis, YAxis, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getSeverityPalette, getChartChrome, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { formatDate } from '../utils/formatters'
import { ChartCard } from './ChartCard'

interface VulnAccumulationAreaProps {
  data: { date: string; count: number; [severity: string]: unknown }[] | undefined
  isLoading: boolean
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']

export function VulnAccumulationArea({ data, isLoading }: VulnAccumulationAreaProps) {
  const { theme } = useTheme()
  const sevPalette = useMemo(() => getSeverityPalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  // Detect which severity keys exist and pass data through for stacked area
  const { chartData, activeSeverities } = useMemo(() => {
    if (!data?.length) return { chartData: [], activeSeverities: [] }

    // Find all severity keys present in the data
    const sevKeys = new Set<string>()
    for (const d of data) {
      for (const key of Object.keys(d)) {
        if (key !== 'date' && key !== 'count' && SEVERITY_ORDER.includes(key)) {
          sevKeys.add(key)
        }
      }
    }

    const active = SEVERITY_ORDER.filter(s => sevKeys.has(s))

    // Use raw daily counts — Recharts stackId handles the stacking
    const result = data.map(d => {
      const row: Record<string, unknown> = { date: d.date }
      for (const s of active) {
        row[s] = typeof d[s] === 'number' ? d[s] : 0
      }
      return row
    })

    return { chartData: result, activeSeverities: active }
  }, [data])

  const totalDays = chartData.length

  return (
    <ChartCard
      title="Vuln Accumulation"
      subtitle={`${totalDays} days`}
      isLoading={isLoading}
      isEmpty={chartData.length === 0}
    >
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={chartData} margin={{ left: 0, right: 8, top: 8, bottom: 8 }}>
          <defs>
            {activeSeverities.map(sev => (
              <linearGradient key={sev} id={`grad-accum-${sev}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={sevPalette[sev as keyof typeof sevPalette]} stopOpacity={0.4} />
                <stop offset="95%" stopColor={sevPalette[sev as keyof typeof sevPalette]} stopOpacity={0.05} />
              </linearGradient>
            ))}
          </defs>
          <XAxis
            dataKey="date"
            tickFormatter={formatDate}
            tick={{ fontSize: 10, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            tick={{ fontSize: 11, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={35}
          />
          <Tooltip
            contentStyle={tooltipStyle}
            itemStyle={tooltipItemStyle}
            labelStyle={tooltipLabelStyle}
            labelFormatter={formatDate}
          />
          {activeSeverities.map(sev => (
            <Area
              key={sev}
              type="monotone"
              dataKey={sev}
              stackId="1"
              stroke={sevPalette[sev as keyof typeof sevPalette]}
              fill={`url(#grad-accum-${sev})`}
              strokeWidth={1.5}
            />
          ))}
          <Legend
            formatter={(value: string) => <span style={{ fontSize: 10, textTransform: 'capitalize' }}>{value}</span>}
          />
        </AreaChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
