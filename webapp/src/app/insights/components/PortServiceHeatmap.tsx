'use client'

import { useMemo } from 'react'
import { useTheme } from '@/hooks/useTheme'
import { ChartCard } from './ChartCard'
import styles from './PortServiceHeatmap.module.css'

interface PortServiceHeatmapProps {
  services: { service: string; port: number; count: number }[] | undefined
  isLoading: boolean
}

function heatColor(value: number, max: number): string {
  if (value === 0) return 'var(--border-secondary)'
  const ratio = value / max
  if (ratio >= 0.75) return '#e53935'
  if (ratio >= 0.5) return '#f97316'
  if (ratio >= 0.25) return '#f59e0b'
  return '#3b82f6'
}

export function PortServiceHeatmap({ services, isLoading }: PortServiceHeatmapProps) {
  useTheme()

  const { uniqueServices, uniquePorts, matrix, maxCount } = useMemo(() => {
    if (!services?.length) return { uniqueServices: [], uniquePorts: [], matrix: new Map(), maxCount: 0 }

    // Build service->port->count matrix
    const svcSet = new Set<string>()
    const portSet = new Set<number>()
    const mat = new Map<string, number>()
    let max = 0

    for (const s of services) {
      svcSet.add(s.service)
      portSet.add(s.port)
      const key = `${s.service}|${s.port}`
      mat.set(key, (mat.get(key) || 0) + s.count)
      const v = mat.get(key)!
      if (v > max) max = v
    }

    const sortedSvcs = Array.from(svcSet).sort()
    const sortedPorts = Array.from(portSet).sort((a, b) => a - b).slice(0, 15)

    return { uniqueServices: sortedSvcs.slice(0, 12), uniquePorts: sortedPorts, matrix: mat, maxCount: max }
  }, [services])

  const isEmpty = uniqueServices.length === 0 || uniquePorts.length === 0

  return (
    <ChartCard
      title="Port × Service Matrix"
      subtitle={`${uniqueServices.length} services × ${uniquePorts.length} ports`}
      isLoading={isLoading}
      isEmpty={isEmpty}
    >
      <div className={styles.container}>
        <div className={styles.grid}>
          {/* Header row with port numbers */}
          <div className={styles.headerRow}>
            {uniquePorts.map(port => (
              <div key={port} className={styles.headerCell}>{port}</div>
            ))}
          </div>

          {/* Data rows */}
          {uniqueServices.map(svc => (
            <div key={svc} className={styles.row}>
              <div className={styles.rowLabel} title={svc}>{svc}</div>
              {uniquePorts.map(port => {
                const count = matrix.get(`${svc}|${port}`) || 0
                return (
                  <div
                    key={port}
                    className={styles.cell}
                    style={{ backgroundColor: heatColor(count, maxCount) }}
                    title={count > 0 ? `${svc}:${port} — ${count} instances` : `${svc}:${port} — none`}
                  />
                )
              })}
            </div>
          ))}
        </div>
      </div>
    </ChartCard>
  )
}
