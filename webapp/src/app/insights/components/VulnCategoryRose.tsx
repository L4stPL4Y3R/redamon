'use client'

import { useMemo } from 'react'
import { RadialBarChart, RadialBar, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartPalette, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { SecurityFinding } from '../types'

interface VulnCategoryRoseProps {
  data: SecurityFinding[] | undefined
  isLoading: boolean
}

export function VulnCategoryRose({ data, isLoading }: VulnCategoryRoseProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getChartPalette(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []

    const counts = new Map<string, number>()
    for (const f of data) {
      const cat = f.category || 'other'
      counts.set(cat, (counts.get(cat) || 0) + 1)
    }

    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([category, count], i) => ({
        name: category,
        count,
        fill: palette[i % palette.length],
      }))
  }, [data, palette])

  const total = chartData.reduce((s, d) => s + d.count, 0)

  return (
    <ChartCard
      title="Vulnerability Categories"
      subtitle={`${total} findings`}
      isLoading={isLoading}
      isEmpty={chartData.length === 0}
    >
      <ResponsiveContainer width="100%" height={220}>
        <RadialBarChart
          innerRadius="20%"
          outerRadius="90%"
          data={chartData}
          startAngle={180}
          endAngle={-180}
        >
          <RadialBar
            dataKey="count"
            background={{ fill: 'var(--border-secondary)' }}
            cornerRadius={4}
          />
          <Tooltip
            contentStyle={tooltipStyle}
            itemStyle={tooltipItemStyle}
            labelStyle={tooltipLabelStyle}
            formatter={(value: number, _name: string, props: { payload?: { name?: string } }) =>
              [value, props.payload?.name || '']
            }
          />
          <Legend
            formatter={(value: string) =>
              <span style={{ fontSize: 10 }}>{value}</span>
            }
            wrapperStyle={{ fontSize: 10 }}
          />
        </RadialBarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
