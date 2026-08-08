'use client'

import { useEffect, useRef, useState } from 'react'
import { Filter, ChevronDown } from 'lucide-react'
import { ColumnFilterPanel } from './ColumnFilterPanel'
import type { CellAccessor, ColumnFilter, ColumnKind, ColumnProfile } from '../../utils/columnFilters'
import styles from './ColumnFilterButton.module.css'

/** Icon size is fixed here rather than passed in - it is the thing that drifted. */
const ICON = 12

interface Props<R> {
  profiles: ColumnProfile[]
  filters: Record<string, ColumnFilter>
  kinds: Record<string, ColumnKind>
  /** Rows before filtering, for live facet counts. */
  rows: readonly R[]
  accessor: CellAccessor<R>
  /** How many columns are currently filtered; drives the badge and the active state. */
  activeCount: number
  onChange: (columnId: string, next: ColumnFilter) => void
  onClearColumn: (columnId: string) => void
  onClearAll: () => void
  /** Called the first time the panel opens, so column inference stays lazy. */
  onArm?: () => void
  disabled?: boolean
  /**
   * Which edge the panel hangs from. Right by default because the control is
   * right-aligned in every toolbar; only pass "left" if it is not.
   */
  align?: 'left' | 'right'
}

/**
 * The Filters button and its panel, for any table.
 *
 * Owning the open state here (rather than in each table) is what keeps the
 * click-away behaviour identical everywhere: the panel covers the rows it is
 * filtering, so leaving it open after a click elsewhere hides the result the
 * user just asked for.
 */
export function ColumnFilterButton<R>({
  profiles, filters, kinds, rows, accessor, activeCount,
  onChange, onClearColumn, onClearAll, onArm,
  disabled = false, align = 'right',
}: Props<R>) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  return (
    <div ref={ref} className={styles.menu}>
      <button
        type="button"
        className={`${styles.button} ${activeCount > 0 ? styles.buttonActive : ''}`}
        onClick={() => { onArm?.(); setOpen(o => !o) }}
        disabled={disabled}
        aria-haspopup="dialog"
        aria-expanded={open}
        title="Filter rows by column"
      >
        <Filter size={ICON} />
        <span>Filters</span>
        {activeCount > 0 && <span className={styles.count}>{activeCount}</span>}
        <ChevronDown size={ICON} />
      </button>

      {open && (
        <div className={`${styles.dropdown} ${align === 'left' ? styles.dropdownLeft : styles.dropdownRight}`}>
          <ColumnFilterPanel
            profiles={profiles}
            filters={filters}
            kinds={kinds}
            rows={rows}
            accessor={accessor}
            onChange={onChange}
            onClearColumn={onClearColumn}
            onClearAll={onClearAll}
          />
        </div>
      )}
    </div>
  )
}
