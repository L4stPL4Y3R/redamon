/**
 * Unit tests for Node Inspector column filtering.
 *
 * The interesting surface here is INFERENCE: the Node Inspector has no schema,
 * so which control a column gets is a judgement made from the data. Most of
 * these tests pin that judgement, because getting it wrong is not a crash - it
 * is a 900-entry checkbox list where a text box belonged, which only a human
 * would notice.
 *
 * Run: npx vitest run src/app/graph/components/NodeDetailsTable/nodeFilterHelpers.test.ts
 */
import { describe, test, expect } from 'vitest'
import type { TableRow } from '../../hooks/useTableData'
import {
  getCellValue, isEmptyValue, toNumeric, toDateMs, toBool, valueTokens, valueText,
  profileColumn, emptyFilter, isFilterActive, matchesFilter, regexFor, isInvalidRegex,
  facetCountsFor, describeFilter, propColumnId, MAX_FACETS,
  parseStoredFilter, parseStoredFilters, toStoredFilters, MAX_STORED_SELECTED,
  NAME_COLUMN_ID, IN_COLUMN_ID, OUT_COLUMN_ID,
  type ColumnFilter, type ColumnKind,
} from './nodeFilterHelpers'

function row(name: string, properties: Record<string, unknown>, inN = 0, outN = 0): TableRow {
  return {
    node: { id: `n-${name}`, name, type: 'Subdomain', properties } as any,
    connectionsIn: Array.from({ length: inN }, (_, i) => ({
      nodeId: `i${i}`, nodeName: `i${i}`, nodeType: 'IP', relationType: 'R',
    })),
    connectionsOut: Array.from({ length: outN }, (_, i) => ({
      nodeId: `o${i}`, nodeName: `o${i}`, nodeType: 'IP', relationType: 'R',
    })),
    getLevel2: () => [],
    getLevel3: () => [],
  }
}

function withFilter(patch: Partial<ColumnFilter>): ColumnFilter {
  return { ...emptyFilter(), ...patch }
}

// ---------------------------------------------------------------------------

describe('getCellValue', () => {
  const r = row('a.example.com', { port: 443 }, 2, 5)

  test('reads name, connection counts and properties', () => {
    expect(getCellValue(r, NAME_COLUMN_ID)).toBe('a.example.com')
    expect(getCellValue(r, IN_COLUMN_ID)).toBe(2)
    expect(getCellValue(r, OUT_COLUMN_ID)).toBe(5)
    expect(getCellValue(r, propColumnId('port'))).toBe(443)
  })

  test('an unknown column is undefined, not a crash', () => {
    expect(getCellValue(r, 'prop:nope')).toBeUndefined()
    expect(getCellValue(r, 'garbage')).toBeUndefined()
  })

  // A property literally named "prop:x" must not be reachable by accident.
  test('slices the prefix exactly once', () => {
    const weird = row('w', { 'prop:x': 'inner' })
    expect(getCellValue(weird, 'prop:prop:x')).toBe('inner')
  })
})

describe('isEmptyValue', () => {
  test.each([null, undefined, '', '   ', []])('%j is empty', v => {
    expect(isEmptyValue(v)).toBe(true)
  })
  test.each([0, false, 'x', ['a'], {}])('%j is not empty', v => {
    expect(isEmptyValue(v)).toBe(false)
  })
})

describe('value coercion', () => {
  test('toNumeric handles Neo4j integers, numeric strings and rejects booleans', () => {
    expect(toNumeric(443)).toBe(443)
    expect(toNumeric({ low: 80, high: 0 })).toBe(80)
    expect(toNumeric('8080')).toBe(8080)
    expect(toNumeric('')).toBeNull()
    expect(toNumeric('abc')).toBeNull()
    expect(toNumeric(true)).toBeNull()
    expect(toNumeric(NaN)).toBeNull()
  })

  // The whole point of the strict pattern: a port must not become a date.
  test('toDateMs accepts ISO leads only', () => {
    expect(toDateMs('2026-08-08')).toBeGreaterThan(0)
    expect(toDateMs('2026-08-08T12:00:00Z')).toBeGreaterThan(0)
    expect(toDateMs('443')).toBeNull()
    expect(toDateMs('8.1')).toBeNull()
    expect(toDateMs('August 8 2026')).toBeNull()
    expect(toDateMs(20260808)).toBeNull()
  })

  test('toBool accepts real and stringified booleans only', () => {
    expect(toBool(true)).toBe(true)
    expect(toBool('false')).toBe(false)
    expect(toBool('TRUE')).toBe(true)
    expect(toBool('yes')).toBeNull()
    expect(toBool(1)).toBeNull()
  })

  test('valueTokens flattens arrays and drops empties', () => {
    expect(valueTokens(['a', '', 'b', null])).toEqual(['a', 'b'])
    expect(valueTokens('solo')).toEqual(['solo'])
    expect(valueTokens([])).toEqual([])
  })

  test('valueText joins arrays and stringifies objects', () => {
    expect(valueText(['a', 'b'])).toBe('a, b')
    expect(valueText({ k: 1 })).toBe('{"k":1}')
    expect(valueText(null)).toBe('')
  })
})

// ---------------------------------------------------------------------------
// Cypher `datetime()` (first_seen / last_seen on every supply-chain node) does
// NOT arrive as a string - it arrives as a temporal object whose components are
// themselves `{low, high}` integers. The cell renders it through
// `formatNeo4jDateTime`, so a filter that compared `String(value)` would be
// matching the user's pattern against "[object Object]": every text, regex and
// facet filter on a timestamp column would quietly match nothing while the
// column visibly contained dates.
// ---------------------------------------------------------------------------

/** The exact shape the Neo4j driver serialises `datetime()` into. */
function neoDateTime(y: number, mo: number, d: number, h: number, mi: number, s: number) {
  const i = (low: number) => ({ low, high: 0 })
  return {
    year: i(y), month: i(mo), day: i(d),
    hour: i(h), minute: i(mi), second: i(s),
    nanosecond: i(0), timeZoneOffsetSeconds: i(0),
  }
}

describe('Neo4j temporal values', () => {
  const lastSeen = neoDateTime(2026, 8, 7, 15, 32, 58)

  test('tokenise to exactly what the cell displays', () => {
    expect(valueText(lastSeen)).toBe('2026-08-07 15:32:58')
    expect(valueTokens(lastSeen)).toEqual(['2026-08-07 15:32:58'])
  })

  test('a plain-number component shape is accepted too', () => {
    const plain = { year: 2026, month: 8, day: 7, hour: 9, minute: 5, second: 1 }
    expect(valueText(plain)).toBe('2026-08-07 09:05:01')
  })

  test('an object that is not a temporal still stringifies as JSON', () => {
    expect(valueText({ year: 2026, month: 8 })).toBe('{"year":2026,"month":8}')
  })

  test('parse as a date, in UTC, so the range agrees with the displayed day', () => {
    expect(toDateMs(lastSeen)).toBe(Date.parse('2026-08-07T15:32:58Z'))
  })

  test('a timestamp column profiles as a date range, not text', () => {
    const rows = [
      row('a', { last_seen: neoDateTime(2026, 8, 7, 15, 32, 58) }),
      row('b', { last_seen: neoDateTime(2026, 8, 7, 16, 14, 17) }),
    ]
    const p = profileColumn(propColumnId('last_seen'), 'last_seen', rows, getCellValue)
    expect(p.kind).toBe('date')
    expect(p.minDate).toBe(Date.parse('2026-08-07T15:32:58Z'))
    expect(p.maxDate).toBe(Date.parse('2026-08-07T16:14:17Z'))
  })

  test('the hour-window regex a user would actually type selects the right rows', () => {
    const f = withFilter({ q: '^\\d{4}-\\d{2}-\\d{2} 15:\\d{2}:\\d{2}$', textMode: 'regex' })
    const rx = regexFor(f)
    expect(matchesFilter(neoDateTime(2026, 8, 7, 15, 32, 58), f, 'date', rx)).toBe(true)
    expect(matchesFilter(neoDateTime(2026, 8, 7, 16, 14, 17), f, 'date', rx)).toBe(false)
  })

  test('contains-search on a timestamp finds the displayed text', () => {
    const f = withFilter({ q: '15:32' })
    expect(matchesFilter(lastSeen, f, 'date')).toBe(true)
  })
})

// ---------------------------------------------------------------------------

describe('profileColumn inference', () => {
  test('all-boolean values become a boolean picker', () => {
    const rows = [row('a', { live: true }), row('b', { live: false }), row('c', { live: 'true' })]
    expect(profileColumn(propColumnId('live'), 'live', rows, getCellValue).kind).toBe('boolean')
  })

  test('all-numeric values become a range', () => {
    const rows = [row('a', { port: 443 }), row('b', { port: 80 }), row('c', { port: { low: 8080, high: 0 } })]
    const p = profileColumn(propColumnId('port'), 'port', rows, getCellValue)
    expect(p.kind).toBe('number')
    expect(p.min).toBe(80)
    expect(p.max).toBe(8080)
  })

  test('ISO strings become a date range', () => {
    const rows = [row('a', { seen: '2026-01-02' }), row('b', { seen: '2026-08-08T10:00:00Z' })]
    const p = profileColumn(propColumnId('seen'), 'seen', rows, getCellValue)
    expect(p.kind).toBe('date')
    expect(p.minDate).toBeLessThan(p.maxDate!)
  })

  test('array values become a list picker with per-token facets', () => {
    const rows = [row('a', { tags: ['x', 'y'] }), row('b', { tags: ['x'] })]
    const p = profileColumn(propColumnId('tags'), 'tags', rows, getCellValue)
    expect(p.kind).toBe('list')
    expect(p.facets).toEqual([{ value: 'x', count: 2 }, { value: 'y', count: 1 }])
  })

  test('a low-cardinality repeating column becomes a checkbox list', () => {
    const rows = [
      ...Array.from({ length: 5 }, (_, i) => row(`a${i}`, { status: 'live' })),
      ...Array.from({ length: 5 }, (_, i) => row(`b${i}`, { status: 'dead' })),
    ]
    const p = profileColumn(propColumnId('status'), 'status', rows, getCellValue)
    expect(p.kind).toBe('enum')
    expect(p.facets).toEqual([{ value: 'dead', count: 5 }, { value: 'live', count: 5 }])
  })

  // The rule that stops a checkbox list per unique URL.
  test('a mostly-unique column stays a text box even when short', () => {
    const rows = Array.from({ length: 10 }, (_, i) => row(`u${i}`, { url: `https://x/${i}` }))
    const p = profileColumn(propColumnId('url'), 'url', rows, getCellValue)
    expect(p.kind).toBe('text')
    expect(p.facets).toEqual([])
    expect(p.distinctCount).toBe(10)
  })

  test('a high-cardinality column stays a text box', () => {
    const rows = Array.from({ length: 200 }, (_, i) => row(`u${i}`, { title: `t${i}` }))
    expect(profileColumn(propColumnId('title'), 'title', rows, getCellValue).kind).toBe('text')
  })

  // 2 rows / 2 distinct values is 100% unique, so the ratio rule alone would
  // send it to a text box - useless when there are literally two options.
  test('a tiny sample still offers a picker', () => {
    const rows = [row('a', { env: 'prod' }), row('b', { env: 'stage' })]
    expect(profileColumn(propColumnId('env'), 'env', rows, getCellValue).kind).toBe('enum')
  })

  test('a column that is empty everywhere degrades to text and counts the empties', () => {
    const rows = [row('a', { note: null }), row('b', {}), row('c', { note: '' })]
    const p = profileColumn(propColumnId('note'), 'note', rows, getCellValue)
    expect(p.kind).toBe('text')
    expect(p.emptyCount).toBe(3)
    expect(p.total).toBe(3)
  })

  test('mixed types fall back to a picker or text, never a broken range', () => {
    const rows = [row('a', { v: 443 }), row('b', { v: 'http' })]
    const p = profileColumn(propColumnId('v'), 'v', rows, getCellValue)
    expect(p.kind).not.toBe('number')
    expect(p.min).toBeNull()
  })

  test('connection-count columns profile as numbers', () => {
    const rows = [row('a', {}, 1, 2), row('b', {}, 5, 0)]
    const p = profileColumn(IN_COLUMN_ID, 'In', rows, getCellValue)
    expect(p.kind).toBe('number')
    expect(p.min).toBe(1)
    expect(p.max).toBe(5)
  })
})

// ---------------------------------------------------------------------------

describe('matchesFilter', () => {
  const K: ColumnKind = 'text'

  test('an inactive filter matches everything, including empties', () => {
    const f = emptyFilter()
    expect(isFilterActive(f)).toBe(false)
    expect(matchesFilter('anything', f, K)).toBe(true)
    expect(matchesFilter(null, f, K)).toBe(true)
  })

  test('presence empty / filled', () => {
    const empty = withFilter({ presence: 'empty' })
    const filled = withFilter({ presence: 'filled' })
    expect(matchesFilter('', empty, K)).toBe(true)
    expect(matchesFilter('x', empty, K)).toBe(false)
    expect(matchesFilter('x', filled, K)).toBe(true)
    expect(matchesFilter([], filled, K)).toBe(false)
  })

  // Without this an empty cell would pass a range it cannot satisfy, and the
  // table would show rows the user explicitly filtered out.
  test('an empty cell fails any positive criterion', () => {
    expect(matchesFilter(null, withFilter({ min: 1 }), 'number')).toBe(false)
    expect(matchesFilter(null, withFilter({ selected: ['a'] }), 'enum')).toBe(false)
    expect(matchesFilter(null, withFilter({ q: 'a' }), K)).toBe(false)
  })

  test('selected values OR together', () => {
    const f = withFilter({ selected: ['live', 'dead'] })
    expect(matchesFilter('live', f, 'enum')).toBe(true)
    expect(matchesFilter('dead', f, 'enum')).toBe(true)
    expect(matchesFilter('other', f, 'enum')).toBe(false)
  })

  test('list mode any vs all', () => {
    const any = withFilter({ selected: ['x', 'y'], listMode: 'any' })
    const all = withFilter({ selected: ['x', 'y'], listMode: 'all' })
    expect(matchesFilter(['x'], any, 'list')).toBe(true)
    expect(matchesFilter(['x'], all, 'list')).toBe(false)
    expect(matchesFilter(['x', 'y', 'z'], all, 'list')).toBe(true)
  })

  test('numeric range is inclusive on both ends', () => {
    const f = withFilter({ min: 80, max: 443 })
    expect(matchesFilter(80, f, 'number')).toBe(true)
    expect(matchesFilter(443, f, 'number')).toBe(true)
    expect(matchesFilter(79, f, 'number')).toBe(false)
    expect(matchesFilter(444, f, 'number')).toBe(false)
    expect(matchesFilter({ low: 100, high: 0 }, f, 'number')).toBe(true)
  })

  test('a non-numeric cell cannot satisfy a numeric range', () => {
    expect(matchesFilter('http', withFilter({ min: 1 }), 'number')).toBe(false)
  })

  // "to 2026-08-08" must include the whole of the 8th, not stop at midnight.
  test('date range end is inclusive of the whole day', () => {
    const f = withFilter({ from: '2026-08-01', to: '2026-08-08' })
    expect(matchesFilter('2026-08-08T23:30:00Z', f, 'date')).toBe(true)
    expect(matchesFilter('2026-08-01T00:00:00Z', f, 'date')).toBe(true)
    expect(matchesFilter('2026-07-31T23:59:59Z', f, 'date')).toBe(false)
    expect(matchesFilter('2026-08-09T00:00:01Z', f, 'date')).toBe(false)
  })

  test.each([
    ['contains', 'exam', 'a.example.com', true],
    ['contains', 'zzz', 'a.example.com', false],
    ['equals', 'a.example.com', 'a.example.com', true],
    ['equals', 'a.example', 'a.example.com', false],
    ['startsWith', 'a.ex', 'a.example.com', true],
    ['startsWith', 'example', 'a.example.com', false],
    ['regex', '^a\\..*com$', 'a.example.com', true],
    ['regex', '^b\\.', 'a.example.com', false],
  ])('text mode %s "%s" vs "%s" -> %s', (mode, q, value, expected) => {
    const f = withFilter({ q, textMode: mode as any })
    expect(matchesFilter(value, f, K, regexFor(f))).toBe(expected)
  })

  test('text matching is case-insensitive', () => {
    const f = withFilter({ q: 'EXAM' })
    expect(matchesFilter('a.example.com', f, K)).toBe(true)
  })

  test('negate inverts the text criterion only', () => {
    const f = withFilter({ q: 'exam', negate: true })
    expect(matchesFilter('a.example.com', f, K)).toBe(false)
    expect(matchesFilter('b.other.com', f, K)).toBe(true)
  })

  test('an invalid regex matches nothing and is reported, rather than throwing', () => {
    const f = withFilter({ q: '([', textMode: 'regex' })
    expect(isInvalidRegex(f)).toBe(true)
    expect(() => matchesFilter('anything', f, K, regexFor(f))).not.toThrow()
    expect(matchesFilter('anything', f, K, regexFor(f))).toBe(false)
  })

  test('criteria on one column are cumulative (AND)', () => {
    const f = withFilter({ min: 80, max: 500, q: '4' })
    expect(matchesFilter(443, f, 'number')).toBe(true)
    expect(matchesFilter(80, f, 'number')).toBe(false) // in range, no "4"
  })

  test('an array cell matches text against its joined form', () => {
    expect(matchesFilter(['alpha', 'beta'], withFilter({ q: 'beta' }), 'list')).toBe(true)
  })
})

// ---------------------------------------------------------------------------

describe('facetCountsFor', () => {
  const rows = [
    row('a', { status: 'live', env: 'prod' }),
    row('b', { status: 'live', env: 'stage' }),
    row('c', { status: 'dead', env: 'prod' }),
  ]
  const kinds: Record<string, ColumnKind> = {
    [propColumnId('status')]: 'enum',
    [propColumnId('env')]: 'enum',
  }

  test('with no other filters, counts are the raw totals', () => {
    const counts = facetCountsFor(rows, propColumnId('status'), {}, kinds, getCellValue)
    expect(counts.get('live')).toBe(2)
    expect(counts.get('dead')).toBe(1)
  })

  // The defining property of faceted counting: a column's own selection must
  // not shrink its own list, or unticking a box becomes impossible to undo.
  test("a column's own filter does not narrow its own counts", () => {
    const filters = { [propColumnId('status')]: withFilter({ selected: ['live'] }) }
    const counts = facetCountsFor(rows, propColumnId('status'), filters, kinds, getCellValue)
    expect(counts.get('dead')).toBe(1)
  })

  test('another column\'s filter does narrow the counts', () => {
    const filters = { [propColumnId('env')]: withFilter({ selected: ['prod'] }) }
    const counts = facetCountsFor(rows, propColumnId('status'), filters, kinds, getCellValue)
    expect(counts.get('live')).toBe(1)
    expect(counts.get('dead')).toBe(1)
  })
})

describe('pathological columns cannot blow up the panel', () => {
  // Array columns are typed as `list` regardless of cardinality (there is no
  // sensible text box for a tag array), so the cap is the only thing standing
  // between a 5000-tag property and 5000 checkboxes.
  test('a huge list column is capped at MAX_FACETS and stays a list', () => {
    const rows = Array.from({ length: 600 }, (_, i) => row(`r${i}`, { tags: [`tag${i}`, 'shared'] }))
    const p = profileColumn(propColumnId('tags'), 'tags', rows, getCellValue)
    expect(p.kind).toBe('list')
    expect(p.facets.length).toBe(MAX_FACETS)
  })

  // Ordering by count is what makes the cap tolerable: the values a user is
  // most likely to want survive it.
  test('the cap keeps the most common values', () => {
    const rows = Array.from({ length: 600 }, (_, i) => row(`r${i}`, { tags: [`tag${i}`, 'shared'] }))
    const p = profileColumn(propColumnId('tags'), 'tags', rows, getCellValue)
    expect(p.facets[0]).toEqual({ value: 'shared', count: 600 })
  })
})

describe('facet counts are per-row, not per-occurrence', () => {
  // A facet count answers "how many rows would I get", so a repeated tag inside
  // one row must not inflate it. Otherwise a facet advertises 12 and the filter
  // then yields 8, and the numbers next to the checkboxes stop being trustable.
  test('a duplicated token in one row counts once (profile)', () => {
    const rows = [row('a', { tags: ['prod', 'prod', 'web'] }), row('b', { tags: ['prod'] })]
    const p = profileColumn(propColumnId('tags'), 'tags', rows, getCellValue)
    expect(p.facets.find(f => f.value === 'prod')?.count).toBe(2)
    expect(p.facets.find(f => f.value === 'web')?.count).toBe(1)
  })

  test('a duplicated token in one row counts once (live facets)', () => {
    const rows = [row('a', { tags: ['prod', 'prod'] })]
    const counts = facetCountsFor(rows, propColumnId('tags'), {}, { [propColumnId('tags')]: 'list' }, getCellValue)
    expect(counts.get('prod')).toBe(1)
  })

  // The property that makes the count meaningful: it must equal the number of
  // rows the same selection actually returns.
  test('the advertised count equals the rows the selection yields', () => {
    const rows = [
      row('a', { tags: ['prod', 'prod'] }),
      row('b', { tags: ['prod'] }),
      row('c', { tags: ['dev'] }),
    ]
    const colId = propColumnId('tags')
    const counts = facetCountsFor(rows, colId, {}, { [colId]: 'list' }, getCellValue)
    const f = withFilter({ selected: ['prod'] })
    const matched = rows.filter(r => matchesFilter(getCellValue(r, colId), f, 'list')).length
    expect(counts.get('prod')).toBe(matched)
  })
})

describe('non-finite range bounds', () => {
  // Number('abc') is NaN, and NaN compares false against everything: such a
  // filter would sit in the chip bar claiming to narrow the table while
  // changing nothing at all.
  test('a NaN bound is not an active filter', () => {
    expect(isFilterActive(withFilter({ min: NaN }))).toBe(false)
    expect(isFilterActive(withFilter({ max: NaN }))).toBe(false)
    expect(isFilterActive(withFilter({ min: NaN, max: NaN }))).toBe(false)
  })

  test('a NaN bound does not reject rows', () => {
    expect(matchesFilter(443, withFilter({ min: NaN }), 'number')).toBe(true)
    expect(matchesFilter(null, withFilter({ min: NaN }), 'number')).toBe(true)
  })

  test('a NaN bound is not described in a chip', () => {
    expect(describeFilter('port', withFilter({ min: NaN, max: 443 }))).toBe('port <= 443')
  })

  test('Infinity is treated the same as NaN', () => {
    expect(isFilterActive(withFilter({ min: Infinity }))).toBe(false)
  })

  // Zero is a real bound; a truthiness check here would silently drop it.
  test('a zero bound is honoured', () => {
    expect(isFilterActive(withFilter({ max: 0 }))).toBe(true)
    expect(matchesFilter(1, withFilter({ max: 0 }), 'number')).toBe(false)
    expect(matchesFilter(0, withFilter({ max: 0 }), 'number')).toBe(true)
    expect(describeFilter('port', withFilter({ max: 0 }))).toBe('port <= 0')
  })
})

// ---------------------------------------------------------------------------
// What comes back from `users.ui_preferences` is untrusted: it may have been
// written by an older build, or by anyone holding the user's session.
// ---------------------------------------------------------------------------

describe('parseStoredFilter', () => {
  test('a round trip through JSON preserves every field', () => {
    const f = withFilter({
      presence: 'filled', selected: ['a', 'b'], listMode: 'all',
      min: 1, max: 9, from: '2026-01-01', to: '2026-02-02',
      q: 'needle', textMode: 'regex', negate: true,
    })
    expect(parseStoredFilter(JSON.parse(JSON.stringify(f)))).toEqual(f)
  })

  test('unknown enum values fall back rather than reaching the UI', () => {
    const f = parseStoredFilter({ presence: 'sideways', textMode: 'lasers', listMode: 'maybe' })!
    expect(f.presence).toBe('any')
    expect(f.textMode).toBe('contains')
    expect(f.listMode).toBe('any')
  })

  test('wrong-typed fields degrade to the neutral value', () => {
    const f = parseStoredFilter({ selected: 'live', q: 42, min: 'eight', negate: 'yes' })!
    expect(f.selected).toEqual([])
    expect(f.q).toBe('')
    expect(f.min).toBeNull()
    expect(f.negate).toBe(false)
  })

  test('non-string entries inside selected are dropped, not stringified', () => {
    const f = parseStoredFilter({ selected: ['ok', 3, null, { a: 1 }] })!
    expect(f.selected).toEqual(['ok'])
  })

  test('a NaN or Infinity bound does not come back as an active filter', () => {
    // JSON cannot carry them, but a hand-written PATCH can.
    const f = parseStoredFilter({ min: Number.NaN, max: Number.POSITIVE_INFINITY })!
    expect(f.min).toBeNull()
    expect(f.max).toBeNull()
    expect(isFilterActive(f)).toBe(false)
  })

  test('an oversized query is truncated instead of stored unbounded', () => {
    const f = parseStoredFilter({ q: 'x'.repeat(5000) })!
    expect(f.q.length).toBe(500)
  })

  test('a selected list is capped', () => {
    const f = parseStoredFilter({ selected: Array.from({ length: 1000 }, (_, i) => `v${i}`) })!
    expect(f.selected).toHaveLength(MAX_STORED_SELECTED)
  })

  test('non-objects are not filters', () => {
    expect(parseStoredFilter(null)).toBeNull()
    expect(parseStoredFilter('live')).toBeNull()
    expect(parseStoredFilter([])).toBeNull()
  })
})

describe('parseStoredFilters / toStoredFilters', () => {
  test('an entry that survives parsing but filters nothing is dropped', () => {
    // Otherwise it lights up the chip bar and the Filters badge while the table
    // is not actually narrowed.
    const parsed = parseStoredFilters({ 'prop:status': { presence: 'any', q: '' } })
    expect(parsed).toEqual({})
  })

  test('only active filters are written back', () => {
    const stored = toStoredFilters({
      'prop:status': withFilter({ selected: ['live'] }),
      'prop:port': emptyFilter(),
    })
    expect(Object.keys(stored)).toEqual(['prop:status'])
  })

  test('a stored set round trips through both directions unchanged', () => {
    const filters = { 'prop:status': withFilter({ selected: ['live'] }) }
    expect(parseStoredFilters(JSON.parse(JSON.stringify(toStoredFilters(filters))))).toEqual(filters)
  })

  test('a garbage blob yields no filters rather than throwing', () => {
    expect(parseStoredFilters(null)).toEqual({})
    expect(parseStoredFilters('nope')).toEqual({})
    expect(parseStoredFilters([1, 2])).toEqual({})
    expect(parseStoredFilters({ 'prop:x': 7 })).toEqual({})
  })
})

describe('describeFilter', () => {
  test.each([
    [withFilter({ presence: 'empty' }), 'status is empty'],
    [withFilter({ presence: 'filled' }), 'status has value'],
    [withFilter({ selected: ['live'] }), 'status is live'],
    [withFilter({ selected: ['live', 'dead'] }), 'status in live, dead'],
    [withFilter({ min: 80, max: 443 }), 'status 80-443'],
    [withFilter({ min: 80 }), 'status >= 80'],
    [withFilter({ max: 443 }), 'status <= 443'],
    [withFilter({ from: '2026-01-01' }), 'status after 2026-01-01'],
    [withFilter({ to: '2026-01-01' }), 'status before 2026-01-01'],
    [withFilter({ q: 'abc' }), 'status contains "abc"'],
    [withFilter({ q: 'abc', negate: true }), 'status not contains "abc"'],
    [withFilter({ q: 'abc', textMode: 'regex' }), 'status matches "abc"'],
  ])('renders a readable chip', (f, expected) => {
    expect(describeFilter('status', f)).toBe(expected)
  })

  test('truncates long value lists', () => {
    const f = withFilter({ selected: ['a', 'b', 'c', 'd', 'e'] })
    expect(describeFilter('tags', f)).toBe('tags in a, b, c +2')
  })
})
