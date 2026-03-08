'use client'

import { useMemo, useState, useCallback } from 'react'
import { useTheme } from '@/hooks/useTheme'
import { getChartChrome, severityColor } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import styles from './AttackFlowSankey.module.css'

interface AttackChainSankeyProps {
  data: { target: string; tool: string; findingType: string; severity: string }[] | undefined
  isLoading: boolean
}

interface SankeyNode {
  id: string
  label: string
  column: number
  y: number
  height: number
  color: string
  count: number
}

interface SankeyLink {
  source: string
  target: string
  value: number
  color: string
}

const COLUMNS = ['Target', 'Tool', 'Finding', 'Severity']
const COL_X = [40, 220, 400, 580]
const NODE_WIDTH = 14
const NODE_GAP = 4
const SVG_WIDTH = 700
const MAX_NODES_PER_COL = 10

const COLUMN_COLORS = ['#3b82f6', '#8b5cf6', '#f97316', '#e53935']

const FINDING_LABELS: Record<string, string> = {
  vulnerability_confirmed: 'Vuln Confirmed',
  credential_found: 'Credential Found',
  exploit_success: 'Exploit Success',
  access_gained: 'Access Gained',
  privilege_escalation: 'Priv Escalation',
  service_identified: 'Service ID',
  exploit_module_found: 'Exploit Module',
  defense_detected: 'Defense Detected',
  configuration_found: 'Config Found',
  custom: 'Custom',
}

export function AttackChainSankey({ data, isLoading }: AttackChainSankeyProps) {
  const { theme } = useTheme()
  const chrome = useMemo(() => getChartChrome(), [theme])
  const [hovered, setHovered] = useState<string | null>(null)

  const { nodes, links, svgHeight } = useMemo(() => {
    if (!data?.length) return { nodes: [], links: [], svgHeight: 200 }

    // Count items per column
    const targetCounts = new Map<string, number>()
    const toolCounts = new Map<string, number>()
    const findingCounts = new Map<string, number>()
    const sevCounts = new Map<string, number>()

    // Count links between columns
    const linkMap = new Map<string, number>()

    for (const row of data) {
      const t = row.target
      const tool = row.tool
      const ft = row.findingType
      const sev = row.severity

      targetCounts.set(t, (targetCounts.get(t) || 0) + 1)
      toolCounts.set(tool, (toolCounts.get(tool) || 0) + 1)
      findingCounts.set(ft, (findingCounts.get(ft) || 0) + 1)
      sevCounts.set(sev, (sevCounts.get(sev) || 0) + 1)

      // target -> tool
      const tt = `${t}|${tool}`
      linkMap.set(tt, (linkMap.get(tt) || 0) + 1)
      // tool -> findingType
      const tf = `${tool}|${ft}`
      linkMap.set(tf, (linkMap.get(tf) || 0) + 1)
      // findingType -> severity
      const fs = `${ft}|${sev}`
      linkMap.set(fs, (linkMap.get(fs) || 0) + 1)
    }

    // Top N per column
    const topN = (m: Map<string, number>) =>
      Array.from(m.entries()).sort((a, b) => b[1] - a[1]).slice(0, MAX_NODES_PER_COL)

    const columns = [
      topN(targetCounts),
      topN(toolCounts),
      topN(findingCounts),
      topN(sevCounts),
    ]

    // Build nodes with positions
    const allNodes: SankeyNode[] = []
    let maxHeight = 0

    for (let col = 0; col < columns.length; col++) {
      const items = columns[col]
      const maxCount = Math.max(...items.map(([, c]) => c), 1)
      let y = 40

      for (const [id, count] of items) {
        const height = Math.max(8, Math.round((count / maxCount) * 40))
        // Severity column uses severity colors, others use column colors
        let color: string
        if (col === 3) {
          color = severityColor(id)
        } else {
          color = COLUMN_COLORS[col]
        }

        const label = col === 2
          ? (FINDING_LABELS[id] || id)
          : id.length > 22 ? id.slice(0, 20) + '...' : id

        allNodes.push({
          id: `${col}-${id}`,
          label,
          column: col,
          y,
          height,
          color,
          count,
        })
        y += height + NODE_GAP
      }
      if (y > maxHeight) maxHeight = y
    }

    // Build links
    const allLinks: SankeyLink[] = []
    const nodeIdSet = new Set(allNodes.map(n => n.id))

    for (const [key, value] of linkMap.entries()) {
      const [sourceId, targetId] = key.split('|')
      let sourceCol = -1, targetCol = -1
      if (targetCounts.has(sourceId)) sourceCol = 0
      else if (toolCounts.has(sourceId)) sourceCol = 1
      else if (findingCounts.has(sourceId)) sourceCol = 2
      if (toolCounts.has(targetId)) targetCol = 1
      else if (findingCounts.has(targetId)) targetCol = 2
      else if (sevCounts.has(targetId)) targetCol = 3

      const sKey = `${sourceCol}-${sourceId}`
      const tKey = `${targetCol}-${targetId}`

      if (nodeIdSet.has(sKey) && nodeIdSet.has(tKey)) {
        allLinks.push({
          source: sKey,
          target: tKey,
          value,
          color: COLUMN_COLORS[sourceCol] || '#71717a',
        })
      }
    }

    return { nodes: allNodes, links: allLinks, svgHeight: Math.max(maxHeight + 20, 200) }
  }, [data])

  const nodeMap = useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes])

  const handleHover = useCallback((id: string | null) => setHovered(id), [])

  const isEmpty = nodes.length === 0

  return (
    <ChartCard
      title="Attack Execution Flow"
      subtitle="Target → Tool → Finding → Severity"
      isLoading={isLoading}
      isEmpty={isEmpty}
    >
      <div className={styles.container}>
        <svg width="100%" viewBox={`0 0 ${SVG_WIDTH} ${svgHeight}`} preserveAspectRatio="xMidYMid meet">
          {/* Column labels */}
          {COLUMNS.map((label, i) => (
            <text
              key={label}
              x={COL_X[i] + NODE_WIDTH / 2}
              y={16}
              textAnchor="middle"
              className={styles.columnLabel}
              fill={chrome.axisColor}
            >
              {label}
            </text>
          ))}

          {/* Links */}
          {links.map((link, i) => {
            const sNode = nodeMap.get(link.source)
            const tNode = nodeMap.get(link.target)
            if (!sNode || !tNode) return null

            const x1 = COL_X[sNode.column] + NODE_WIDTH
            const y1 = sNode.y + sNode.height / 2
            const x2 = COL_X[tNode.column]
            const y2 = tNode.y + tNode.height / 2
            const cpx = (x1 + x2) / 2

            const isHighlighted = hovered === link.source || hovered === link.target
            const opacity = hovered ? (isHighlighted ? 0.5 : 0.08) : 0.2

            return (
              <path
                key={i}
                d={`M ${x1} ${y1} C ${cpx} ${y1}, ${cpx} ${y2}, ${x2} ${y2}`}
                fill="none"
                stroke={link.color}
                strokeWidth={Math.max(1, Math.min(link.value, 6))}
                opacity={opacity}
              />
            )
          })}

          {/* Nodes */}
          {nodes.map(node => {
            const isHighlighted = hovered === node.id
            const opacity = hovered ? (isHighlighted ? 1 : 0.3) : 0.85

            return (
              <g
                key={node.id}
                onMouseEnter={() => handleHover(node.id)}
                onMouseLeave={() => handleHover(null)}
                style={{ cursor: 'default' }}
              >
                <rect
                  x={COL_X[node.column]}
                  y={node.y}
                  width={NODE_WIDTH}
                  height={node.height}
                  rx={3}
                  fill={node.color}
                  opacity={opacity}
                />
                <text
                  x={COL_X[node.column] + NODE_WIDTH + 6}
                  y={node.y + node.height / 2 + 3}
                  className={styles.nodeLabel}
                  fill={chrome.axisColor}
                  opacity={opacity}
                >
                  {node.label} ({node.count})
                </text>
              </g>
            )
          })}
        </svg>
      </div>
    </ChartCard>
  )
}
