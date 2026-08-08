/**
 * Schema-free per-column filtering, shared by every table in the graph views.
 *
 * Neither the Node Inspector nor the Red Zone sheets have a fixed column set
 * the UI can be written against: the Inspector shows one node type at a time
 * and derives its columns from whatever properties that type happens to carry,
 * and each Red Zone sheet has its own row shape. So the filter control for a
 * column cannot be declared ahead of time - it is INFERRED from the values
 * actually present, which is what makes a checkbox list appear for `status`, a
 * range for `port` and a date picker for `last_seen` without anyone
 * maintaining a mapping.
 *
 * Rows are reached only through a `CellAccessor`, so the same engine serves
 * the Inspector's `TableRow` (name / connection counts / node properties) and
 * the Red Zone's plain records without either shape leaking in here.
 *
 * Everything is pure so the inference rules can be tested directly rather than
 * through the DOM.
 */
import { formatNeo4jDateTime } from './formatters'

/** How a row yields the value for one column. */
export type CellAccessor<R> = (row: R, columnId: string) => unknown

/** For rows that are already plain `{ columnId: value }` records. */
export const recordAccessor: CellAccessor<Record<string, unknown>> = (row, columnId) => row[columnId]

// ---------------------------------------------------------------------------
// Emptiness
// ---------------------------------------------------------------------------

/**
 * "Empty" has to cover four different shapes because Neo4j properties arrive as
 * any of them: absent, null, blank string, and empty array. Treating only
 * null as empty would make "Empty" miss most of the rows a user means.
 */
export function isEmptyValue(raw: unknown): boolean {
  if (raw === null || raw === undefined) return true
  if (typeof raw === 'string') return raw.trim() === ''
  if (Array.isArray(raw)) return raw.length === 0
  return false
}

// ---------------------------------------------------------------------------
// Value normalisation
// ---------------------------------------------------------------------------

/**
 * Neo4j integers arrive as `{low, high}`; everything else passes through.
 *
 * `high` is load-bearing even though the graph API currently hands back plain
 * numbers: the driver's Integer is a 64-bit value split across two signed
 * 32-bit words, so reading `low` alone turns 2^32+1 into 1 - a wrong number
 * that looks perfectly ordinary in a facet list and in a range. Anything that
 * does not fit a JS safe integer is treated as not-a-number rather than
 * silently rounded.
 */
export function toNumeric(raw: unknown): number | null {
  if (typeof raw === 'number') return Number.isFinite(raw) ? raw : null
  if (raw && typeof raw === 'object' && 'low' in (raw as object)) {
    const { low, high } = raw as { low: unknown; high?: unknown }
    if (typeof low !== 'number' || !Number.isFinite(low)) return null
    if (high === undefined || high === 0) return low
    if (typeof high !== 'number' || !Number.isFinite(high)) return null
    const n = high * 4294967296 + (low >>> 0)
    return Number.isSafeInteger(n) ? n : null
  }
  if (typeof raw === 'string' && raw.trim() !== '') {
    const n = Number(raw)
    return Number.isFinite(n) ? n : null
  }
  if (typeof raw === 'boolean') return null
  return null
}

/**
 * Deliberately strict: only an ISO-ish leading date counts. `Date.parse` alone
 * would happily turn "443" or "8.1" into a date and hand the user a date-range
 * picker for a port number.
 */
const ISO_DATE_LEAD = /^\d{4}-\d{2}-\d{2}([T ]|$)/

/**
 * A timestamp carrying no zone at all: `2026-08-07 15:32:58`, or the same with
 * a `T`. These are read as UTC below - see `toDateMs`.
 */
const ZONELESS_TIMESTAMP = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?$/

export function toDateMs(raw: unknown): number | null {
  // Cypher `datetime()` reaches the browser as a temporal OBJECT, not a string.
  // Without this branch every graph timestamp profiles as plain text and the
  // date range picker is never offered for the columns that most need it.
  const temporal = formatNeo4jDateTime(raw)
  if (temporal !== null) {
    // Neo4j stores UTC and the display formatter prints those raw UTC
    // components, so the value is read back as UTC to agree with the range
    // bounds below - otherwise a timestamp near midnight lands on the day
    // either side of the one the cell shows.
    const ms = Date.parse(`${temporal.replace(' ', 'T')}Z`)
    return Number.isFinite(ms) ? ms : null
  }
  if (typeof raw !== 'string') return null
  const s = raw.trim()
  if (!ISO_DATE_LEAD.test(s)) return null

  // A zoneless timestamp string is read as UTC, matching both the temporal
  // branch above and the range bounds below. `Date.parse` would otherwise apply
  // the VIEWER's offset to it, so the same instant stored as a string and as a
  // Neo4j temporal - displayed identically, to the second - would land on
  // different sides of a date filter for anyone not on UTC.
  const ms = Date.parse(ZONELESS_TIMESTAMP.test(s) ? `${s.replace(' ', 'T')}Z` : s)
  return Number.isFinite(ms) ? ms : null
}

export function toBool(raw: unknown): boolean | null {
  if (typeof raw === 'boolean') return raw
  if (typeof raw === 'string') {
    const s = raw.trim().toLowerCase()
    if (s === 'true') return true
    if (s === 'false') return false
  }
  return null
}

/**
 * One scalar to its display/compare string.
 *
 * The Neo4j object cases are load-bearing: `String({low: 8080, high: 0})` is
 * "[object Object]", which would put that literal string in facet lists and
 * make text search on any integer property match nothing. The same is true of
 * temporal values, and those are worse because the CELL renders a formatted
 * timestamp - so the user would be typing a pattern against a string the filter
 * never sees. Both must agree with `formatNeo4jDateTime`, which is what the
 * table renders through.
 */
function tokenOf(v: unknown): string {
  if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
    const temporal = formatNeo4jDateTime(v)
    if (temporal !== null) return temporal
    if ('low' in (v as object)) {
      const n = toNumeric(v)
      if (n !== null) return String(n)
    }
    try { return JSON.stringify(v) } catch { return String(v) }
  }
  return String(v)
}

/** Flattens a cell to the string tokens a facet list should offer. */
export function valueTokens(raw: unknown): string[] {
  if (isEmptyValue(raw)) return []
  if (Array.isArray(raw)) {
    return raw.filter(v => !isEmptyValue(v)).map(tokenOf)
  }
  return [tokenOf(raw)]
}

/** The single string a text/enum filter compares against. */
export function valueText(raw: unknown): string {
  if (isEmptyValue(raw)) return ''
  if (Array.isArray(raw)) return raw.map(tokenOf).join(', ')
  return tokenOf(raw)
}

// ---------------------------------------------------------------------------
// Inference
// ---------------------------------------------------------------------------

export type ColumnKind = 'boolean' | 'number' | 'date' | 'enum' | 'list' | 'text'

export interface FacetValue { value: string; count: number }

export interface ColumnProfile {
  columnId: string
  label: string
  kind: ColumnKind
  /** Distinct values with counts. Present for enum + list. */
  facets: FacetValue[]
  /** Populated for number. */
  min: number | null
  max: number | null
  /** Populated for date (epoch ms). */
  minDate: number | null
  maxDate: number | null
  emptyCount: number
  total: number
  /** Distinct non-empty values seen, used by the UI to explain a text column. */
  distinctCount: number
}

/**
 * A column becomes a checkbox list rather than a text box when it has few
 * enough distinct values to actually pick from, AND those values repeat. The
 * second condition is what stops a 900-row table of unique URLs from rendering
 * a 900-entry checkbox list just because 900 < some larger threshold.
 */
export const ENUM_MAX_DISTINCT = 25
const ENUM_MAX_UNIQUE_RATIO = 0.6

/** Facet lists are capped so a pathological column cannot freeze the panel. */
export const MAX_FACETS = 500

export function profileColumn<R>(
  columnId: string,
  label: string,
  rows: readonly R[],
  accessor: CellAccessor<R>,
): ColumnProfile {
  const counts = new Map<string, number>()
  let emptyCount = 0
  let nonEmpty = 0
  let allArray = true
  let allBool = true
  let allNum = true
  let allDate = true
  // Ranges are accumulated from the VALUES, not re-parsed from the facet tokens
  // afterwards: a Neo4j integer tokenises fine but a re-parse round trip is one
  // more place for the object form to be silently dropped from min/max.
  let numMin: number | null = null
  let numMax: number | null = null
  let dateMin: number | null = null
  let dateMax: number | null = null

  for (const row of rows) {
    const raw = accessor(row, columnId)
    if (isEmptyValue(raw)) {
      emptyCount++
      continue
    }
    nonEmpty++
    if (!Array.isArray(raw)) allArray = false
    if (toBool(raw) === null) allBool = false

    const n = toNumeric(raw)
    if (n === null) allNum = false
    else {
      numMin = numMin === null || n < numMin ? n : numMin
      numMax = numMax === null || n > numMax ? n : numMax
    }

    const ms = toDateMs(raw)
    if (ms === null) allDate = false
    else {
      dateMin = dateMin === null || ms < dateMin ? ms : dateMin
      dateMax = dateMax === null || ms > dateMax ? ms : dateMax
    }

    // Deduped per row: a facet count answers "how many ROWS have this value",
    // so tags: ['prod', 'prod'] must contribute 1, not 2. Otherwise a facet can
    // advertise 12 and then filter down to 8.
    for (const token of new Set(valueTokens(raw))) {
      counts.set(token, (counts.get(token) ?? 0) + 1)
    }
  }

  const distinctCount = counts.size
  let kind: ColumnKind
  if (nonEmpty === 0) {
    // Nothing to infer from. Text is the only control that degrades gracefully
    // to "no options", and the presence toggle still works.
    kind = 'text'
  } else if (allArray) {
    kind = 'list'
  } else if (allBool) {
    kind = 'boolean'
  } else if (allNum) {
    kind = 'number'
  } else if (allDate) {
    kind = 'date'
  } else if (distinctCount <= ENUM_MAX_DISTINCT && distinctCount <= nonEmpty * ENUM_MAX_UNIQUE_RATIO) {
    kind = 'enum'
  } else if (distinctCount <= ENUM_MAX_DISTINCT && nonEmpty <= 3) {
    // Tiny samples never satisfy the ratio rule (2 rows, 2 distinct values is
    // 100% unique), yet a 2-option picker is exactly what the user wants there.
    kind = 'enum'
  } else {
    kind = 'text'
  }

  // Only surfaced for the kind that renders them, so a mixed column cannot show
  // a range built from the handful of its values that happened to parse.
  const min = kind === 'number' ? numMin : null
  const max = kind === 'number' ? numMax : null
  const minDate = kind === 'date' ? dateMin : null
  const maxDate = kind === 'date' ? dateMax : null

  const facets: FacetValue[] =
    kind === 'enum' || kind === 'list' || kind === 'boolean'
      ? [...counts.entries()]
          .map(([value, count]) => ({ value, count }))
          .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
          .slice(0, MAX_FACETS)
      : []

  return {
    columnId, label, kind, facets,
    min, max, minDate, maxDate,
    emptyCount, total: rows.length, distinctCount,
  }
}

// ---------------------------------------------------------------------------
// Filter model
// ---------------------------------------------------------------------------

export type Presence = 'any' | 'empty' | 'filled'
export type TextMode = 'contains' | 'equals' | 'startsWith' | 'regex'

export interface ColumnFilter {
  presence: Presence
  /** Selected values for enum / list / boolean. OR-ed together. */
  selected: string[]
  /** list only: does a row need one of the selected values, or all of them? */
  listMode: 'any' | 'all'
  /** number */
  min: number | null
  max: number | null
  /** date, as yyyy-mm-dd (inclusive on both ends) */
  from: string
  to: string
  /** text */
  q: string
  textMode: TextMode
  negate: boolean
}

export function emptyFilter(): ColumnFilter {
  return {
    presence: 'any', selected: [], listMode: 'any',
    min: null, max: null, from: '', to: '',
    q: '', textMode: 'contains', negate: false,
  }
}

/**
 * A bound of NaN is not a bound. `Number('abc')` is NaN, and NaN compares false
 * against everything, so such a filter would sit in the chip bar claiming to
 * narrow the table while changing nothing.
 */
function hasBound(n: number | null): n is number {
  return n !== null && Number.isFinite(n)
}

export function isFilterActive(f: ColumnFilter | undefined): boolean {
  if (!f) return false
  return (
    f.presence !== 'any' ||
    f.selected.length > 0 ||
    hasBound(f.min) || hasBound(f.max) ||
    f.from !== '' || f.to !== '' ||
    f.q.trim() !== ''
  )
}

/** Compiled once per keystroke rather than per row - a regex per row is slow. */
function compileRegex(q: string): RegExp | null {
  try { return new RegExp(q, 'i') } catch { return null }
}

export function matchesFilter(raw: unknown, f: ColumnFilter, kind: ColumnKind, rx?: RegExp | null): boolean {
  const empty = isEmptyValue(raw)

  if (f.presence === 'empty') return empty
  if (f.presence === 'filled' && empty) return false

  // Any positive criterion below implies "must have a value"; without this an
  // empty cell would sail through a range filter it cannot possibly satisfy.
  const hasCriteria =
    f.selected.length > 0 || hasBound(f.min) || hasBound(f.max) ||
    f.from !== '' || f.to !== '' || f.q.trim() !== ''
  if (empty) return !hasCriteria

  if (f.selected.length > 0) {
    const tokens = valueTokens(raw)
    if (kind === 'list' && f.listMode === 'all') {
      if (!f.selected.every(s => tokens.includes(s))) return false
    } else if (!tokens.some(t => f.selected.includes(t))) {
      return false
    }
  }

  if (hasBound(f.min) || hasBound(f.max)) {
    const n = toNumeric(raw)
    if (n === null) return false
    if (hasBound(f.min) && n < f.min) return false
    if (hasBound(f.max) && n > f.max) return false
  }

  if (f.from !== '' || f.to !== '') {
    const ms = toDateMs(raw)
    if (ms === null) return false
    if (f.from !== '') {
      const fromMs = Date.parse(`${f.from}T00:00:00Z`)
      if (Number.isFinite(fromMs) && ms < fromMs) return false
    }
    if (f.to !== '') {
      // Inclusive: "to 2026-08-08" must include everything on the 8th.
      const toMs = Date.parse(`${f.to}T23:59:59.999Z`)
      if (Number.isFinite(toMs) && ms > toMs) return false
    }
  }

  const q = f.q.trim()
  if (q !== '') {
    const hay = valueText(raw)
    let hit: boolean
    switch (f.textMode) {
      case 'equals': hit = hay.toLowerCase() === q.toLowerCase(); break
      case 'startsWith': hit = hay.toLowerCase().startsWith(q.toLowerCase()); break
      // An invalid regex matches nothing rather than throwing mid-render; the
      // panel flags it so the user sees why the table went empty.
      case 'regex': hit = rx ? rx.test(hay) : false; break
      default: hit = hay.toLowerCase().includes(q.toLowerCase())
    }
    if (f.negate ? hit : !hit) return false
  }

  return true
}

/** Prebuilt regex per column so `matchesFilter` never compiles inside a loop. */
export function regexFor(f: ColumnFilter): RegExp | null {
  if (f.textMode !== 'regex' || f.q.trim() === '') return null
  return compileRegex(f.q)
}

export function isInvalidRegex(f: ColumnFilter): boolean {
  return f.textMode === 'regex' && f.q.trim() !== '' && compileRegex(f.q) === null
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/**
 * Filters survive a reload by riding in the user-preferences JSON blob, which
 * means what comes back is whatever was written by a POSSIBLY OLDER build of
 * this file - or by anyone with the user's session and a PATCH. It is parsed
 * field by field rather than cast, so a renamed mode or a hand-edited blob
 * degrades to "no filter" instead of putting the table in a state its own UI
 * cannot describe or clear.
 */
const TEXT_MODES: readonly TextMode[] = ['contains', 'equals', 'startsWith', 'regex']
const PRESENCES: readonly Presence[] = ['any', 'empty', 'filled']

/** Bounds what a stored blob can cost us on the next mount. */
export const MAX_STORED_SELECTED = 200
const MAX_STORED_QUERY = 500

function storedNumber(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

function storedString(v: unknown, max = MAX_STORED_QUERY): string {
  return typeof v === 'string' ? v.slice(0, max) : ''
}

export function parseStoredFilter(raw: unknown): ColumnFilter | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const o = raw as Record<string, unknown>
  const base = emptyFilter()
  return {
    presence: PRESENCES.includes(o.presence as Presence) ? (o.presence as Presence) : base.presence,
    selected: Array.isArray(o.selected)
      ? o.selected.filter((s): s is string => typeof s === 'string').slice(0, MAX_STORED_SELECTED)
      : base.selected,
    listMode: o.listMode === 'all' ? 'all' : 'any',
    min: storedNumber(o.min),
    max: storedNumber(o.max),
    from: storedString(o.from, 32),
    to: storedString(o.to, 32),
    q: storedString(o.q),
    textMode: TEXT_MODES.includes(o.textMode as TextMode) ? (o.textMode as TextMode) : base.textMode,
    negate: o.negate === true,
  }
}

/**
 * Restores one node type's filter set. Inactive entries are dropped on the way
 * in as well as on the way out: an entry that survives parsing but filters
 * nothing would still light up the "Filters (3)" badge and the chip bar.
 */
export function parseStoredFilters(raw: unknown): Record<string, ColumnFilter> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
  const out: Record<string, ColumnFilter> = {}
  for (const [columnId, value] of Object.entries(raw as Record<string, unknown>)) {
    const parsed = parseStoredFilter(value)
    if (parsed && isFilterActive(parsed)) out[columnId] = parsed
  }
  return out
}

/**
 * Only active filters are written back. Every touched column would otherwise
 * leave a permanent empty object in the blob - one per column the user ever
 * expanded, per node type, per project, in a row that is read on every page.
 */
export function toStoredFilters(filters: Record<string, ColumnFilter>): Record<string, ColumnFilter> {
  const out: Record<string, ColumnFilter> = {}
  for (const [columnId, f] of Object.entries(filters)) {
    if (!isFilterActive(f)) continue
    // Truncated on the way OUT as well as on the way in. A facet list runs to
    // MAX_FACETS (500) and the reader caps at MAX_STORED_SELECTED, so writing
    // uncapped would save a selection that comes back smaller - the table
    // showing different rows after a reload than before it, with no error.
    out[columnId] = f.selected.length > MAX_STORED_SELECTED
      ? { ...f, selected: f.selected.slice(0, MAX_STORED_SELECTED) }
      : f
  }
  return out
}

// ---------------------------------------------------------------------------
// Faceting
// ---------------------------------------------------------------------------

/**
 * Counts for one column computed over the rows surviving every OTHER active
 * filter. This is what makes the numbers next to each checkbox mean "how many
 * you would get if you also picked this", instead of a static total that stops
 * matching the table as soon as a second filter is added.
 */
export function facetCountsFor<R>(
  rows: readonly R[],
  columnId: string,
  filters: Record<string, ColumnFilter>,
  kinds: Record<string, ColumnKind>,
  accessor: CellAccessor<R>,
): Map<string, number> {
  const others = Object.entries(filters).filter(([id, f]) => id !== columnId && isFilterActive(f))
  const compiled = others.map(([id, f]) => [id, f, regexFor(f)] as const)

  const counts = new Map<string, number>()
  for (const row of rows) {
    let ok = true
    for (const [id, f, rx] of compiled) {
      if (!matchesFilter(accessor(row, id), f, kinds[id] ?? 'text', rx)) { ok = false; break }
    }
    if (!ok) continue
    for (const token of new Set(valueTokens(accessor(row, columnId)))) {
      counts.set(token, (counts.get(token) ?? 0) + 1)
    }
  }
  return counts
}

// ---------------------------------------------------------------------------
// Chip labels
// ---------------------------------------------------------------------------

const TEXT_MODE_LABEL: Record<TextMode, string> = {
  contains: 'contains', equals: 'is', startsWith: 'starts with', regex: 'matches',
}

/** Human-readable summary of one column's filter, for the active-filter chips. */
export function describeFilter(label: string, f: ColumnFilter): string {
  const parts: string[] = []
  if (f.presence === 'empty') return `${label} is empty`
  if (f.presence === 'filled') parts.push('has value')

  if (f.selected.length > 0) {
    const joiner = f.listMode === 'all' ? ' & ' : ', '
    const shown = f.selected.slice(0, 3).join(joiner)
    const extra = f.selected.length > 3 ? ` +${f.selected.length - 3}` : ''
    parts.push(`${f.selected.length > 1 ? 'in ' : 'is '}${shown}${extra}`)
  }
  if (hasBound(f.min) && hasBound(f.max)) parts.push(`${f.min}-${f.max}`)
  else if (hasBound(f.min)) parts.push(`>= ${f.min}`)
  else if (hasBound(f.max)) parts.push(`<= ${f.max}`)

  if (f.from !== '' && f.to !== '') parts.push(`${f.from} to ${f.to}`)
  else if (f.from !== '') parts.push(`after ${f.from}`)
  else if (f.to !== '') parts.push(`before ${f.to}`)

  if (f.q.trim() !== '') {
    parts.push(`${f.negate ? 'not ' : ''}${TEXT_MODE_LABEL[f.textMode]} "${f.q.trim()}"`)
  }
  return `${label} ${parts.join(' & ')}`
}
