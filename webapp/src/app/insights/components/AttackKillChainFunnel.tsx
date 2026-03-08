'use client'

import { useMemo } from 'react'
import { FunnelChart, Funnel, LabelList, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'

interface AttackKillChainFunnelProps {
  data: { phase: string; totalSteps: number; successSteps: number }[] | undefined
  isLoading: boolean
}

const PHASE_COLORS: Record<string, string> = {
  informational: '#3b82f6',
  exploitation: '#f97316',
  post_exploitation: '#e53935',
}

const PHASE_LABELS: Record<string, string> = {
  informational: 'Recon',
  exploitation: 'Exploitation',
  post_exploitation: 'Post-Exploit',
}

export function AttackKillChainFunnel({ data, isLoading }: AttackKillChainFunnelProps) {
  const { theme } = useTheme()
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])

  const chartData = useMemo(() => {
    if (!data?.length) return []
    const order = ['informational', 'exploitation', 'post_exploitation']
    return order
      .map(phase => {
        const match = data.find(d => d.phase === phase)
        return match ? {
          name: PHASE_LABELS[phase] || phase,
          value: match.totalSteps,
          success: match.successSteps,
          fill: PHASE_COLORS[phase] || '#71717a',
        } : null
      })
      .filter((d): d is NonNullable<typeof d> => d !== null && d.value > 0)
  }, [data])

  const total = chartData.reduce((s, d) => s + d.value, 0)

  return (
    <ChartCard
      title="Kill Chain Funnel"
      subtitle={`${total} total steps`}
      isLoading={isLoading}
      isEmpty={chartData.length === 0}
    >
      <ResponsiveContainer width="100%" height={280}>
        <FunnelChart>
          <Tooltip
            contentStyle={tooltipStyle}
            itemStyle={tooltipItemStyle}
            labelStyle={tooltipLabelStyle}
            formatter={(value: number, name: string, props: { payload?: { success?: number } }) => {
              const success = props.payload?.success ?? 0
              return [`${value} steps (${success} successful)`, name]
            }}
          />
          <Funnel dataKey="value" data={chartData} isAnimationActive>
            {chartData.map((entry, i) => (
              <Cell key={i} fill={entry.fill} />
            ))}
            <LabelList
              position="center"
              dataKey="name"
              style={{ fontSize: 12, fill: '#fff', fontWeight: 600 }}
            />
          </Funnel>
        </FunnelChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
