'use client'

import { useMemo, useState, useCallback } from 'react'
import { useTheme } from '@/hooks/useTheme'
import { getChartPalette, getChartChrome } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { CveChain } from '../types'
import styles from './AttackFlowSankey.module.css'

interface AttackFlowSankeyProps {
  data: CveChain[] | undefined
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

const COLUMNS = ['Technology', 'CVE', 'CWE', 'CAPEC']
const COL_X = [40, 220, 400, 580]
const NODE_WIDTH = 14
const NODE_GAP = 4
const SVG_WIDTH = 700
const MAX_NODES_PER_COL = 10

export function AttackFlowSankey({ data, isLoading }: AttackFlowSankeyProps) {
  const { theme } = useTheme()
  const palette = useMemo(() => getChartPalette(), [theme])
  const chrome = useMemo(() => getChartChrome(), [theme])
  const [hovered, setHovered] = useState<string | null>(null)

  const { nodes, links, svgHeight } = useMemo(() => {
    if (!data?.length) return { nodes: [], links: [], svgHeight: 200 }

    // Count unique items per column
    const techCounts = new Map<string, number>()
    const cveCounts = new Map<string, number>()
    const cweCounts = new Map<string, number>()
    const capecCounts = new Map<string, number>()

    // Count links
    const linkMap = new Map<string, number>()

    for (const chain of data) {
      const techKey = chain.tech
      techCounts.set(techKey, (techCounts.get(techKey) || 0) + 1)
      cveCounts.set(chain.cveId, (cveCounts.get(chain.cveId) || 0) + 1)

      // tech -> cve link
      const tc = `${techKey}|${chain.cveId}`
      linkMap.set(tc, (linkMap.get(tc) || 0) + 1)

      if (chain.cweId) {
        const cweKey = chain.cweId
        cweCounts.set(cweKey, (cweCounts.get(cweKey) || 0) + 1)
        const cc = `${chain.cveId}|${cweKey}`
        linkMap.set(cc, (linkMap.get(cc) || 0) + 1)

        if (chain.capecId) {
          const capecKey = chain.capecId
          capecCounts.set(capecKey, (capecCounts.get(capecKey) || 0) + 1)
          const cp = `${cweKey}|${capecKey}`
          linkMap.set(cp, (linkMap.get(cp) || 0) + 1)
        }
      }
    }

    // Build top-N node lists per column
    const topN = (m: Map<string, number>) =>
      Array.from(m.entries()).sort((a, b) => b[1] - a[1]).slice(0, MAX_NODES_PER_COL)

    const columns = [
      topN(techCounts),
      topN(cveCounts),
      topN(cweCounts),
      topN(capecCounts),
    ]

    // Build nodes with y positions
    const allNodes: SankeyNode[] = []
    const nodeYMap = new Map<string, { y: number; height: number }>()
    let maxHeight = 0

    for (let col = 0; col < columns.length; col++) {
      const items = columns[col]
      const maxCount = Math.max(...items.map(([, c]) => c), 1)
      let y = 40

      for (const [id, count] of items) {
        const height = Math.max(8, Math.round((count / maxCount) * 40))
        const node: SankeyNode = {
          id: `${col}-${id}`,
          label: id.length > 20 ? id.slice(0, 18) + '...' : id,
          column: col,
          y,
          height,
          color: palette[col % palette.length],
          count,
        }
        allNodes.push(node)
        nodeYMap.set(`${col}-${id}`, { y, height })
        y += height + NODE_GAP
      }
      if (y > maxHeight) maxHeight = y
    }

    // Build links
    const allLinks: SankeyLink[] = []
    const nodeIdSet = new Set(allNodes.map(n => n.id))

    for (const [key, value] of linkMap.entries()) {
      const [sourceId, targetId] = key.split('|')
      // Determine columns
      let sourceCol = -1, targetCol = -1
      if (techCounts.has(sourceId)) sourceCol = 0
      else if (cveCounts.has(sourceId)) sourceCol = 1
      else if (cweCounts.has(sourceId)) sourceCol = 2
      if (cveCounts.has(targetId)) targetCol = 1
      else if (cweCounts.has(targetId)) targetCol = 2
      else if (capecCounts.has(targetId)) targetCol = 3

      const sKey = `${sourceCol}-${sourceId}`
      const tKey = `${targetCol}-${targetId}`

      if (nodeIdSet.has(sKey) && nodeIdSet.has(tKey)) {
        allLinks.push({
          source: sKey,
          target: tKey,
          value,
          color: palette[sourceCol % palette.length],
        })
      }
    }

    return { nodes: allNodes, links: allLinks, svgHeight: Math.max(maxHeight + 20, 200) }
  }, [data, palette])

  const nodeMap = useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes])

  const handleHover = useCallback((id: string | null) => setHovered(id), [])

  const isEmpty = nodes.length === 0

  return (
    <ChartCard
      title="Attack CVE Flow"
      subtitle="Technology → CVE → CWE → CAPEC"
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
