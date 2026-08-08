'use client'

import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Search, X, AlertTriangle } from 'lucide-react'
import {
  emptyFilter,
  facetCountsFor,
  isFilterActive,
  isInvalidRegex,
  type ColumnFilter,
  type ColumnKind,
  type CellAccessor,
  type ColumnProfile,
  type Presence,
  type TextMode,
} from '../../utils/columnFilters'
import styles from './ColumnFilterPanel.module.css'

interface Props<R> {
  profiles: ColumnProfile[]
  filters: Record<string, ColumnFilter>
  kinds: Record<string, ColumnKind>
  /** Rows for the current view, pre-filter. Used for live facet counts. */
  rows: readonly R[]
  /** How a row yields the value for a column id. */
  accessor: CellAccessor<R>
  onChange: (columnId: string, next: ColumnFilter) => void
  onClearColumn: (columnId: string) => void
  onClearAll: () => void
}

const KIND_LABEL: Record<ColumnKind, string> = {
  boolean: 'yes/no', number: 'range', date: 'dates',
  enum: 'pick', list: 'tags', text: 'text',
}

const PRESENCE_OPTIONS: { value: Presence; label: string }[] = [
  { value: 'any', label: 'Any' },
  { value: 'filled', label: 'Has value' },
  { value: 'empty', label: 'Empty' },
]

const TEXT_MODES: { value: TextMode; label: string }[] = [
  { value: 'contains', label: 'contains' },
  { value: 'equals', label: 'is exactly' },
  { value: 'startsWith', label: 'starts with' },
  { value: 'regex', label: 'regex' },
]

/**
 * A range bound from a text input. Blank and unparseable both mean "no bound":
 * a NaN would otherwise be stored, look active in the chip bar, and filter
 * nothing.
 */
function parseBound(raw: string): number | null {
  if (raw.trim() === '') return null
  const n = Number(raw)
  return Number.isFinite(n) ? n : null
}

/** How many facet checkboxes to render before the in-card search is the only way in. */
const FACET_VISIBLE = 12

function FacetList({ profile, filter, counts, onChange }: {
  profile: ColumnProfile
  filter: ColumnFilter
  counts: Map<string, number>
  onChange: (next: ColumnFilter) => void
}) {
  const [q, setQ] = useState('')
  const [showAll, setShowAll] = useState(false)

  // Selected values stay visible even when they fall out of the search or the
  // live counts, otherwise ticking a box can make its own checkbox disappear.
  const options = useMemo(() => {
    const seen = new Set<string>()
    const all = [
      ...filter.selected.map(value => ({ value, count: counts.get(value) ?? 0 })),
      ...profile.facets.map(f => ({ value: f.value, count: counts.get(f.value) ?? 0 })),
    ].filter(o => (seen.has(o.value) ? false : (seen.add(o.value), true)))
    const needle = q.trim().toLowerCase()
    return needle ? all.filter(o => o.value.toLowerCase().includes(needle)) : all
  }, [profile.facets, filter.selected, counts, q])

  const shown = showAll ? options : options.slice(0, FACET_VISIBLE)

  function toggle(value: string) {
    const selected = filter.selected.includes(value)
      ? filter.selected.filter(v => v !== value)
      : [...filter.selected, value]
    onChange({ ...filter, selected })
  }

  return (
    <div className={styles.facetBlock}>
      {profile.facets.length > FACET_VISIBLE && (
        <input
          className={styles.facetSearch}
          placeholder={`Search ${profile.label} values…`}
          value={q}
          onChange={e => setQ(e.target.value)}
          aria-label={`Search values for ${profile.label}`}
        />
      )}

      {profile.kind === 'list' && (
        <div className={styles.segmented} role="group" aria-label="Match mode">
          {(['any', 'all'] as const).map(mode => (
            <button
              key={mode}
              type="button"
              className={filter.listMode === mode ? styles.segActive : styles.seg}
              onClick={() => onChange({ ...filter, listMode: mode })}
            >
              {mode === 'any' ? 'Any of' : 'All of'}
            </button>
          ))}
        </div>
      )}

      <div className={styles.facetList}>
        {shown.length === 0 && <span className={styles.hint}>No values match.</span>}
        {shown.map(opt => (
          <label key={opt.value} className={styles.facetRow}>
            <input
              type="checkbox"
              checked={filter.selected.includes(opt.value)}
              onChange={() => toggle(opt.value)}
            />
            <span className={styles.facetValue} title={opt.value}>{opt.value}</span>
            <span className={styles.facetCount}>{opt.count}</span>
          </label>
        ))}
      </div>

      {options.length > FACET_VISIBLE && (
        <button type="button" className={styles.linkBtn} onClick={() => setShowAll(s => !s)}>
          {showAll ? 'Show fewer' : `Show all ${options.length}`}
        </button>
      )}
    </div>
  )
}

function ColumnCard({ profile, filter, counts, expanded, onToggleExpand, onChange, onClear }: {
  profile: ColumnProfile
  filter: ColumnFilter
  counts: Map<string, number>
  expanded: boolean
  onToggleExpand: () => void
  onChange: (next: ColumnFilter) => void
  onClear: () => void
}) {
  const active = isFilterActive(filter)
  const badRegex = isInvalidRegex(filter)

  return (
    <div className={`${styles.card} ${active ? styles.cardActive : ''}`}>
      {/* Explicit label: the visible children concatenate to "statuspick",
          which is what a screen reader would otherwise announce. */}
      <button
        type="button"
        className={styles.cardHeader}
        onClick={onToggleExpand}
        aria-expanded={expanded}
        aria-label={`Filter by ${profile.label}${active ? ' (active)' : ''}`}
      >
        {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <span className={styles.cardLabel} title={profile.label}>{profile.label}</span>
        <span className={styles.kindBadge}>{KIND_LABEL[profile.kind]}</span>
        {active && <span className={styles.activeDot} aria-label="filter active" />}
      </button>

      {expanded && (
        <div className={styles.cardBody}>
          <div className={styles.segmented} role="group" aria-label="Presence">
            {PRESENCE_OPTIONS.map(p => (
              <button
                key={p.value}
                type="button"
                className={filter.presence === p.value ? styles.segActive : styles.seg}
                onClick={() => onChange({ ...filter, presence: p.value })}
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* An "Empty" selection makes every other control meaningless, so they
              are hidden rather than left visible and inert. */}
          {filter.presence !== 'empty' && (
            <>
              {(profile.kind === 'enum' || profile.kind === 'list' || profile.kind === 'boolean') && (
                <FacetList profile={profile} filter={filter} counts={counts} onChange={onChange} />
              )}

              {profile.kind === 'number' && (
                <div className={styles.rangeRow}>
                  <input
                    type="number"
                    className={styles.rangeInput}
                    placeholder={profile.min !== null ? `min ${profile.min}` : 'min'}
                    value={filter.min ?? ''}
                    onChange={e => onChange({ ...filter, min: parseBound(e.target.value) })}
                    aria-label={`Minimum ${profile.label}`}
                  />
                  <span className={styles.rangeDash}>to</span>
                  <input
                    type="number"
                    className={styles.rangeInput}
                    placeholder={profile.max !== null ? `max ${profile.max}` : 'max'}
                    value={filter.max ?? ''}
                    onChange={e => onChange({ ...filter, max: parseBound(e.target.value) })}
                    aria-label={`Maximum ${profile.label}`}
                  />
                </div>
              )}

              {profile.kind === 'date' && (
                <div className={styles.rangeRow}>
                  <input
                    type="date"
                    className={styles.rangeInput}
                    value={filter.from}
                    onChange={e => onChange({ ...filter, from: e.target.value })}
                    aria-label={`${profile.label} from`}
                  />
                  <span className={styles.rangeDash}>to</span>
                  <input
                    type="date"
                    className={styles.rangeInput}
                    value={filter.to}
                    onChange={e => onChange({ ...filter, to: e.target.value })}
                    aria-label={`${profile.label} to`}
                  />
                </div>
              )}

              {/* Text search is offered for EVERY kind, not just text columns:
                  narrowing a 400-value picker by typing is often faster than
                  hunting for the checkbox. */}
              <div className={styles.textRow}>
                <select
                  className={styles.modeSelect}
                  value={filter.textMode}
                  onChange={e => onChange({ ...filter, textMode: e.target.value as TextMode })}
                  aria-label={`Match mode for ${profile.label}`}
                >
                  {TEXT_MODES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                </select>
                <input
                  className={styles.textInput}
                  placeholder="value…"
                  value={filter.q}
                  onChange={e => onChange({ ...filter, q: e.target.value })}
                  aria-label={`Text filter for ${profile.label}`}
                />
                <label className={styles.negateLabel} title="Invert this text match">
                  <input
                    type="checkbox"
                    checked={filter.negate}
                    onChange={e => onChange({ ...filter, negate: e.target.checked })}
                  />
                  not
                </label>
              </div>
              {badRegex && (
                <span className={styles.warn}>
                  <AlertTriangle size={11} /> Invalid regex - no rows will match.
                </span>
              )}
            </>
          )}

          <div className={styles.cardFooter}>
            <span className={styles.hint}>
              {profile.emptyCount > 0 && `${profile.emptyCount} empty`}
              {profile.kind === 'text' && profile.distinctCount > 0 && (
                profile.emptyCount > 0
                  ? ` · ${profile.distinctCount} distinct`
                  : `${profile.distinctCount} distinct`
              )}
            </span>
            {active && (
              <button type="button" className={styles.linkBtn} onClick={onClear}>Clear</button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export function ColumnFilterPanel<R>({
  profiles, filters, kinds, rows, accessor, onChange, onClearColumn, onClearAll,
}: Props<R>) {
  const [columnQuery, setColumnQuery] = useState('')
  // Only the open card computes live facet counts, so a type with 60 properties
  // does not pay for 60 passes over the rows on every keystroke.
  const [openColumn, setOpenColumn] = useState<string | null>(
    () => profiles.find(p => isFilterActive(filters[p.columnId]))?.columnId ?? profiles[0]?.columnId ?? null,
  )

  const visible = useMemo(() => {
    const needle = columnQuery.trim().toLowerCase()
    if (!needle) return profiles
    return profiles.filter(p => p.label.toLowerCase().includes(needle))
  }, [profiles, columnQuery])

  const openCounts = useMemo(() => {
    if (!openColumn) return new Map<string, number>()
    const profile = profiles.find(p => p.columnId === openColumn)
    if (!profile || (profile.kind !== 'enum' && profile.kind !== 'list' && profile.kind !== 'boolean')) {
      return new Map<string, number>()
    }
    return facetCountsFor(rows, openColumn, filters, kinds, accessor)
  }, [openColumn, profiles, rows, filters, kinds, accessor])

  const activeCount = profiles.filter(p => isFilterActive(filters[p.columnId])).length

  return (
    <div className={styles.panel}>
      <div className={styles.panelHeader}>
        <div className={styles.panelSearch}>
          <Search size={12} className={styles.panelSearchIcon} />
          <input
            className={styles.panelSearchInput}
            placeholder="Find a column…"
            value={columnQuery}
            onChange={e => setColumnQuery(e.target.value)}
            aria-label="Find a column to filter"
          />
        </div>
        <button
          type="button"
          className={styles.linkBtn}
          onClick={onClearAll}
          disabled={activeCount === 0}
        >
          Clear all
        </button>
      </div>

      <div className={styles.cardList}>
        {visible.length === 0 && <span className={styles.hint}>No column matches that name.</span>}
        {visible.map(profile => (
          <ColumnCard
            key={profile.columnId}
            profile={profile}
            filter={filters[profile.columnId] ?? emptyFilter()}
            counts={profile.columnId === openColumn ? openCounts : new Map()}
            expanded={profile.columnId === openColumn}
            onToggleExpand={() => setOpenColumn(c => (c === profile.columnId ? null : profile.columnId))}
            onChange={next => onChange(profile.columnId, next)}
            onClear={() => onClearColumn(profile.columnId)}
          />
        ))}
      </div>
    </div>
  )
}

/** Removable summary chips for whatever is currently narrowing the table. */
export function ActiveFilterChips({ chips, onRemove, onClearAll }: {
  chips: { columnId: string; text: string }[]
  onRemove: (columnId: string) => void
  onClearAll: () => void
}) {
  if (chips.length === 0) return null
  return (
    <div className={styles.chipBar}>
      {chips.map(chip => (
        <span key={chip.columnId} className={styles.chip}>
          <span className={styles.chipText} title={chip.text}>{chip.text}</span>
          <button
            type="button"
            className={styles.chipX}
            onClick={() => onRemove(chip.columnId)}
            aria-label={`Remove filter: ${chip.text}`}
          >
            <X size={10} />
          </button>
        </span>
      ))}
      <button type="button" className={styles.linkBtn} onClick={onClearAll}>Clear all</button>
    </div>
  )
}
