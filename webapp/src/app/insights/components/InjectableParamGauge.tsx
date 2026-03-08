'use client'

import { useMemo } from 'react'
import { useTheme } from '@/hooks/useTheme'
import { ChartCard } from './ChartCard'

interface InjectableParamGaugeProps {
  data: { position: string; total: number; injectable: number }[] | undefined
  isLoading: boolean
}

function ratioColor(ratio: number): string {
  if (ratio >= 0.5) return '#e53935'
  if (ratio >= 0.25) return '#f97316'
  if (ratio >= 0.1) return '#f59e0b'
  if (ratio > 0) return '#3b82f6'
  return '#22c55e'
}

export function InjectableParamGauge({ data, isLoading }: InjectableParamGaugeProps) {
  useTheme()

  const { totalParams, injectableParams, ratio, color } = useMemo(() => {
    if (!data?.length) return { totalParams: 0, injectableParams: 0, ratio: 0, color: '#22c55e' }

    const total = data.reduce((s, d) => s + d.total, 0)
    const injectable = data.reduce((s, d) => s + d.injectable, 0)
    const r = total > 0 ? injectable / total : 0

    return {
      totalParams: total,
      injectableParams: injectable,
      ratio: r,
      color: ratioColor(r),
    }
  }, [data])

  const pct = Math.round(ratio * 100)

  // SVG semicircle gauge — pad viewBox to prevent stroke clipping
  const pad = 10
  const r = 60
  const svgW = 2 * (r + pad)
  const svgH = r + pad + 30
  const cx = r + pad
  const cy = r + pad
  const startAngle = Math.PI
  const scoreAngle = startAngle - ratio * Math.PI

  const bgArc = describeArc(cx, cy, r, 0, Math.PI)
  const fgArc = ratio > 0 ? describeArc(cx, cy, r, scoreAngle, startAngle) : ''

  return (
    <ChartCard
      title="Injectable Parameters"
      subtitle={`${injectableParams} of ${totalParams} params`}
      isLoading={isLoading}
      isEmpty={totalParams === 0}
    >
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 220 }}>
        <svg width={svgW} height={svgH} viewBox={`0 0 ${svgW} ${svgH}`}>
          <path d={bgArc} fill="none" stroke="var(--border-secondary)" strokeWidth={12} strokeLinecap="round" />
          {ratio > 0 && (
            <path d={fgArc} fill="none" stroke={color} strokeWidth={12} strokeLinecap="round" />
          )}
          <text x={cx} y={cy - 8} textAnchor="middle" fontSize={32} fontWeight={700} fill={color}>
            {pct}%
          </text>
          <text x={cx} y={cy + 14} textAnchor="middle" fontSize={11} fill="var(--text-tertiary)">
            injectable
          </text>
        </svg>

        {/* Breakdown by position */}
        {data && data.length > 0 && (
          <div style={{ display: 'flex', gap: 16, marginTop: 8 }}>
            {data.filter(d => d.injectable > 0).slice(0, 4).map(d => (
              <div key={d.position} style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 14, fontWeight: 600, color }}>{d.injectable}</div>
                <div style={{ fontSize: 9, color: 'var(--text-tertiary)' }}>{d.position}</div>
              </div>
            ))}
          </div>
        )}
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
