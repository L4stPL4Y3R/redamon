'use client'

/**
 * The `Updated` column every graph table carries.
 *
 * Every row in every sheet is backed by at least one graph node, and every
 * graph write stamps `updated_at`. Surfacing it uniformly is what lets a user
 * ask "what did the last scan touch" from any table without leaving it, so the
 * column is not opt-in: it is appended to every sheet, rendered last, and the
 * table lands sorted newest-first.
 *
 * Everything here reads the value through `toDateMs`/`formatNeo4jDateTime` so
 * the cell, the sort and the date-range filter all agree on one instant. Those
 * already accept both shapes a timestamp arrives in - a Cypher temporal object
 * and an ISO string - so no route needs to normalise before returning one.
 */
import { useCallback, useMemo, useState } from 'react'
import { formatNeo4jDateTime } from '../../utils/formatters'
import { toDateMs } from '../../utils/columnFilters'
import type { RedZoneFilterColumn } from './useRedZoneFilters'
import styles from './RedZoneTableRow.module.css'

/**
 * The row key every Red Zone / JS Recon API returns the timestamp under.
 *
 * NOT the same string as the graph property below, and the two are easy to
 * confuse: those routes alias the value in Cypher (`n.updated_at AS updatedAt`)
 * so their rows are camelCase, while a table reading a node's raw property map
 * sees the Neo4j name. Using this one against a node property silently yields
 * `undefined` and renders an empty column - it did, in All Nodes.
 */
export const UPDATED_AT_KEY = 'updatedAt'

/**
 * The property name on a graph node, as Neo4j stores it. Use this whenever the
 * value comes from `node.properties` rather than from a route's row mapper.
 */
export const UPDATED_AT_PROP = 'updated_at'

/**
 * Where to look for a node's write time, best first.
 *
 * `updated_at` is near-universal but not actually universal, and the labels
 * that lack it are not rare ones: Package and MalPackageFinding stamp
 * `first_seen`/`last_seen`, and the attack-chain labels (ChainStep,
 * ChainFinding, ChainFailure) stamp `created_at`. Reading only `updated_at`
 * left every one of those rows blank - on a real graph that is the single
 * largest label in the database.
 *
 * The order encodes "most recently written wins": a `last_seen` is a later
 * fact than the `first_seen` beside it, and `created_at` is only a fallback
 * for labels that never update in place.
 */
export const UPDATED_AT_PROPS = ['updated_at', 'last_seen', 'created_at', 'first_seen'] as const

/**
 * A graph node's write time, or `undefined` when it has none.
 *
 * `undefined` rather than null on purpose: it is what TanStack's
 * `sortUndefined: 'last'` keys on, so an undated node stays at the bottom in
 * both sort directions instead of flipping to the top on reverse.
 */
export function nodeUpdatedAt(properties: Record<string, unknown>): unknown {
  for (const key of UPDATED_AT_PROPS) {
    const value = properties[key]
    if (toDateMs(value) !== null) return value
  }
  return undefined
}

/** Header text, shared so the column reads the same on all ~40 sheets. */
export const UPDATED_AT_HEADER = 'Updated'

/** Filter + export descriptor. Append LAST so it stays the rightmost column. */
export const UPDATED_AT_COLUMN: RedZoneFilterColumn = {
  key: UPDATED_AT_KEY,
  header: UPDATED_AT_HEADER,
}

/**
 * Appends the Updated column to a sheet's column list.
 *
 * Call this at module level on the existing `COLUMNS` constant rather than
 * inline in the component: `useRedZoneFilters` re-profiles every row when the
 * array identity changes.
 */
export function withUpdatedAt(
  columns: readonly RedZoneFilterColumn[],
): RedZoneFilterColumn[] {
  return [...columns, UPDATED_AT_COLUMN]
}

/** The cell. Renders `-` for a node that predates the timestamp sweep. */
export function UpdatedAtCell({ value }: { value: unknown }) {
  const text = formatUpdatedAt(value)
  if (!text) return <span className={styles.nullCell}>-</span>
  return <span className={styles.mono} title={text}>{text}</span>
}

/**
 * `2026-08-20 14:32:58`, or null when the value is not a timestamp.
 *
 * A plain ISO string is normalised through the same formatter as a temporal
 * object so a sheet whose route returns one shape does not render differently
 * from a sheet returning the other.
 */
export function formatUpdatedAt(value: unknown): string | null {
  const temporal = formatNeo4jDateTime(value)
  if (temporal) return temporal
  const ms = toDateMs(value)
  if (ms === null) return null
  return new Date(ms).toISOString().slice(0, 19).replace('T', ' ')
}

export type SortDir = 'desc' | 'asc'

/**
 * Sorts rows by `updated_at`. Pure, so a view that renders several tables from
 * one component can sort each of them without adding a hook per table.
 *
 * Rows with no timestamp sink to the bottom in BOTH directions: they are
 * "unknown", not "oldest", and floating them to the top on the first click
 * would bury the recent rows the user just asked to see. Ties keep the order
 * the route returned, which is each sheet's own severity/score ranking, so the
 * secondary ordering stays meaningful instead of arbitrary.
 */
export function sortByUpdatedAt<T>(
  rows: readonly T[],
  dir: SortDir,
  // A plain key for API rows (`row.updatedAt`); a resolver for rows that are
  // graph nodes, where the value is looked up across several property names.
  key: string | ((row: T) => unknown) = UPDATED_AT_KEY,
): T[] {
  const read = typeof key === 'function'
    ? key
    : (row: T) => (row as Record<string, unknown>)[key]
  const decorated = rows.map((row, index) => ({
    row,
    index,
    ms: toDateMs(read(row)),
  }))
  decorated.sort((a, b) => {
    if (a.ms === null && b.ms === null) return a.index - b.index
    if (a.ms === null) return 1
    if (b.ms === null) return -1
    if (a.ms === b.ms) return a.index - b.index
    return dir === 'desc' ? b.ms - a.ms : a.ms - b.ms
  })
  return decorated.map(d => d.row)
}

/** Newest-first on load, with a toggle bound to the `Updated` header. */
export function useUpdatedAtSort<T>(rows: readonly T[], key: string = UPDATED_AT_KEY) {
  const [dir, setDir] = useState<SortDir>('desc')
  const sorted = useMemo(() => sortByUpdatedAt(rows, dir, key), [rows, dir, key])
  const toggle = useCallback(() => setDir(d => (d === 'desc' ? 'asc' : 'desc')), [])
  return { sortedRows: sorted, sortDir: dir, toggleSort: toggle }
}

/** The same toggle without the sorting, for a view that sorts several lists. */
export function useUpdatedAtSortDir() {
  const [sortDir, setDir] = useState<SortDir>('desc')
  const toggleSort = useCallback(() => setDir(d => (d === 'desc' ? 'asc' : 'desc')), [])
  return { sortDir, toggleSort }
}

interface ThProps {
  dir: SortDir
  onToggle: () => void
  header?: string
}

/** The clickable `Updated` header. Pair with `useUpdatedAtSort`. */
export function UpdatedAtTh({ dir, onToggle, header = UPDATED_AT_HEADER }: ThProps) {
  return (
    <th
      className={styles.sortable}
      onClick={onToggle}
      aria-sort={dir === 'asc' ? 'ascending' : 'descending'}
      title={`Sorted ${dir === 'desc' ? 'newest' : 'oldest'} first - click to reverse`}
    >
      {header}
      <span className={styles.sortArrow}>{dir === 'desc' ? '▼' : '▲'}</span>
    </th>
  )
}
