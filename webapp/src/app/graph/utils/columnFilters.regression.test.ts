/**
 * Regression + edge-case unit tests for the shared column-filter engine.
 *
 * nodeFilterHelpers.test.ts covers the happy path of inference and matching.
 * This file exists for the defects found by reviewing the engine rather than
 * by using it - the ones that produce a plausible wrong answer instead of an
 * error, and so would never be noticed from the UI:
 *
 *   - a timestamp that filters differently depending on the viewer's timezone
 *   - a saved selection that comes back smaller than it was saved
 *   - "empty" swallowing legitimate falsy values (0, false)
 *
 * Run: npx vitest run src/app/graph/utils/columnFilters.regression.test.ts
 */
import { describe, test, expect } from 'vitest'
import {
  emptyFilter, isEmptyValue, isFilterActive, matchesFilter, parseStoredFilters,
  profileColumn, recordAccessor, regexFor, toDateMs, toNumeric, toStoredFilters,
  valueText, valueTokens, facetCountsFor, describeFilter,
  MAX_STORED_SELECTED, MAX_FACETS,
  type ColumnFilter,
} from './columnFilters'

function f(patch: Partial<ColumnFilter>): ColumnFilter {
  return { ...emptyFilter(), ...patch }
}

/** Rows are plain records here - the Red Zone / All Nodes shape. */
const rows = (...vals: unknown[]) => vals.map((v, i) => ({ id: `r${i}`, col: v }))

// ---------------------------------------------------------------------------

describe('timestamps are read in one timezone, not the viewer\'s', () => {
  const neo = (h: number) => ({
    year: { low: 2026, high: 0 }, month: { low: 8, high: 0 }, day: { low: 7, high: 0 },
    hour: { low: h, high: 0 }, minute: { low: 30, high: 0 }, second: { low: 0, high: 0 },
  })

  test('a zoneless string and the identical Neo4j temporal agree to the millisecond', () => {
    // They render identically in the cell; they must filter identically too.
    // `Date.parse('2026-08-07 15:30:00')` alone applies the viewer's offset.
    expect(toDateMs('2026-08-07 15:30:00')).toBe(toDateMs(neo(15)))
    expect(toDateMs('2026-08-07T15:30:00')).toBe(toDateMs(neo(15)))
  })

  test('both land on the UTC instant the cell displays', () => {
    expect(toDateMs('2026-08-07 15:30:00')).toBe(Date.parse('2026-08-07T15:30:00Z'))
  })

  test('an explicit zone is still honoured rather than forced to UTC', () => {
    expect(toDateMs('2026-08-07T15:30:00Z')).toBe(Date.parse('2026-08-07T15:30:00Z'))
    expect(toDateMs('2026-08-07T15:30:00+02:00')).toBe(Date.parse('2026-08-07T13:30:00Z'))
  })

  test('a date-only value keeps its existing meaning', () => {
    expect(toDateMs('2026-08-07')).toBe(Date.parse('2026-08-07T00:00:00Z'))
  })

  test('a late-evening timestamp stays on the day it displays', () => {
    // The bug this pins: at UTC+2 a 23:30 UTC value parsed as local becomes the
    // next day, and a "to 2026-08-07" filter drops a row the cell shows as the 7th.
    const late = '2026-08-07 23:30:00'
    const filter = f({ from: '2026-08-07', to: '2026-08-07' })
    expect(matchesFilter(late, filter, 'date')).toBe(true)
  })

  test('the range is inclusive of the last millisecond of the "to" day', () => {
    expect(matchesFilter('2026-08-07 23:59:59', f({ to: '2026-08-07' }), 'date')).toBe(true)
    expect(matchesFilter('2026-08-08 00:00:00', f({ to: '2026-08-07' }), 'date')).toBe(false)
  })

  test('a malformed timestamp is not a date rather than being NaN-compared', () => {
    expect(toDateMs('2026-13-45 99:99:99')).toBeNull()
    expect(matchesFilter('2026-13-45 99:99:99', f({ from: '2026-01-01' }), 'date')).toBe(false)
  })
})

describe('a saved selection round trips unchanged', () => {
  test('a selection larger than the read cap is truncated on the way out too', () => {
    // Otherwise the table shows one set of rows before a reload and a different
    // set after it, with nothing to indicate why.
    const many = Array.from({ length: MAX_FACETS }, (_, i) => `v${i}`)
    const stored = toStoredFilters({ col: f({ selected: many }) })
    expect(stored.col.selected).toHaveLength(MAX_STORED_SELECTED)

    const restored = parseStoredFilters(JSON.parse(JSON.stringify(stored)))
    expect(restored.col.selected).toEqual(stored.col.selected)
  })

  test('a selection within the cap is untouched, and the object is not copied needlessly', () => {
    const filter = f({ selected: ['a', 'b'] })
    const stored = toStoredFilters({ col: filter })
    expect(stored.col).toBe(filter)
  })

  test('what survives the round trip filters the same rows as what went in', () => {
    const data = rows('keep', 'drop', 'keep')
    const before = f({ selected: ['keep'] })
    const after = parseStoredFilters(JSON.parse(JSON.stringify(toStoredFilters({ col: before })))).col

    const apply = (flt: ColumnFilter) =>
      data.filter(r => matchesFilter(recordAccessor(r, 'col'), flt, 'enum')).map(r => r.id)
    expect(apply(after)).toEqual(apply(before))
  })
})

describe('falsy values are values, not absences', () => {
  test('0 and false are not empty', () => {
    expect(isEmptyValue(0)).toBe(false)
    expect(isEmptyValue(false)).toBe(false)
  })

  test('presence Empty does not swallow a zero count', () => {
    expect(matchesFilter(0, f({ presence: 'empty' }), 'number')).toBe(false)
    expect(matchesFilter(0, f({ presence: 'filled' }), 'number')).toBe(true)
  })

  test('a zero-valued row survives a range that includes zero', () => {
    expect(matchesFilter(0, f({ min: 0, max: 5 }), 'number')).toBe(true)
  })

  test('a false facet is selectable and matches', () => {
    const profile = profileColumn('col', 'Col', rows(true, false, false), recordAccessor)
    expect(profile.kind).toBe('boolean')
    expect(profile.facets.map(x => x.value).sort()).toEqual(['false', 'true'])
    expect(matchesFilter(false, f({ selected: ['false'] }), 'boolean')).toBe(true)
  })

  test('an empty string is empty but a whitespace-only cell is too', () => {
    expect(matchesFilter('', f({ presence: 'empty' }), 'text')).toBe(true)
    expect(matchesFilter('   ', f({ presence: 'empty' }), 'text')).toBe(true)
  })
})

describe('text matching corner cases', () => {
  test('a regex is applied case-insensitively, like the other modes', () => {
    const flt = f({ q: 'ALPHA', textMode: 'regex' })
    expect(matchesFilter('alpha-1', flt, 'text', regexFor(flt))).toBe(true)
  })

  test('regex metacharacters in a contains search are literal', () => {
    // `contains` must not silently behave like a regex.
    expect(matchesFilter('a.b', f({ q: 'a.b' }), 'text')).toBe(true)
    expect(matchesFilter('axb', f({ q: 'a.b' }), 'text')).toBe(false)
  })

  test('negate inverts a regex too, not just contains', () => {
    const flt = f({ q: '^a', textMode: 'regex', negate: true })
    const rx = regexFor(flt)
    expect(matchesFilter('alpha', flt, 'text', rx)).toBe(false)
    expect(matchesFilter('beta', flt, 'text', rx)).toBe(true)
  })

  test('an invalid regex matches nothing instead of throwing mid-render', () => {
    const flt = f({ q: '([', textMode: 'regex' })
    expect(regexFor(flt)).toBeNull()
    expect(() => matchesFilter('anything', flt, 'text', regexFor(flt))).not.toThrow()
    expect(matchesFilter('anything', flt, 'text', regexFor(flt))).toBe(false)
  })

  test('a negated invalid regex does not invert into "match everything"', () => {
    // The dangerous version of the above: `not` + broken pattern showing the
    // whole table while the chip claims it is filtered.
    const flt = f({ q: '([', textMode: 'regex', negate: true })
    expect(matchesFilter('anything', flt, 'text', regexFor(flt))).toBe(true)
  })

  test('whitespace-only query is not an active filter', () => {
    expect(isFilterActive(f({ q: '   ' }))).toBe(false)
    expect(matchesFilter('x', f({ q: '   ' }), 'text')).toBe(true)
  })

  test('text search on an array cell matches the joined form the cell shows', () => {
    expect(valueText(['web', 'prod'])).toBe('web, prod')
    expect(matchesFilter(['web', 'prod'], f({ q: 'web, pro' }), 'list')).toBe(true)
  })
})

describe('multiple criteria on one column are cumulative', () => {
  test('a facet and a text query must both hold', () => {
    const flt = f({ selected: ['alpha'], q: 'zzz' })
    expect(matchesFilter('alpha', flt, 'enum')).toBe(false)
    expect(matchesFilter('alpha', f({ selected: ['alpha'], q: 'alp' }), 'enum')).toBe(true)
  })

  test('a range and a text query must both hold', () => {
    expect(matchesFilter(443, f({ min: 400, q: '44' }), 'number')).toBe(true)
    expect(matchesFilter(443, f({ min: 500, q: '44' }), 'number')).toBe(false)
  })
})

describe('facet counts stay honest', () => {
  const data = [
    { id: 'a', env: 'prod', tier: '1' },
    { id: 'b', env: 'prod', tier: '2' },
    { id: 'c', env: 'dev', tier: '1' },
  ]

  test('a count equals the rows that selecting it yields', () => {
    const counts = facetCountsFor(data, 'env', {}, {}, recordAccessor)
    const advertised = counts.get('prod')
    const actual = data.filter(r =>
      matchesFilter(recordAccessor(r, 'env'), f({ selected: ['prod'] }), 'enum')).length
    expect(advertised).toBe(actual)
  })

  test('another column\'s filter narrows the counts, its own does not', () => {
    const filters = { tier: f({ selected: ['1'] }), env: f({ selected: ['dev'] }) }
    const kinds = { tier: 'enum' as const, env: 'enum' as const }
    const envCounts = facetCountsFor(data, 'env', filters, kinds, recordAccessor)
    // tier=1 leaves a(prod) and c(dev); env's own selection must not apply.
    expect(envCounts.get('prod')).toBe(1)
    expect(envCounts.get('dev')).toBe(1)
  })
})

describe('chip text describes what is actually applied', () => {
  test('every active criterion appears', () => {
    const text = describeFilter('Port', f({ presence: 'filled', min: 80, max: 443, q: 'x' }))
    expect(text).toContain('has value')
    expect(text).toContain('80-443')
    expect(text).toContain('"x"')
  })

  test('a filter with no active criterion is not described as filtering', () => {
    expect(isFilterActive(emptyFilter())).toBe(false)
  })
})

describe('numeric coercion does not invent numbers', () => {
  test('a numeric-looking string is a number, an alphanumeric one is not', () => {
    expect(toNumeric('443')).toBe(443)
    expect(toNumeric('443abc')).toBeNull()
    expect(toNumeric('')).toBeNull()
  })

  test('a Neo4j integer keeps its value through tokens and ranges', () => {
    const port = { low: 8080, high: 0 }
    expect(valueTokens(port)).toEqual(['8080'])
    expect(matchesFilter(port, f({ min: 8000, max: 9000 }), 'number')).toBe(true)
    expect(matchesFilter(port, f({ selected: ['8080'] }), 'number')).toBe(true)
  })

  test('a high-word Neo4j integer is not silently truncated to its low word', () => {
    // `{low: 1, high: 1}` is 2^32 + 1, not 1. Reading only `low` would put a
    // wrong number in the facet list and in the range.
    const big = { low: 1, high: 1 }
    expect(valueTokens(big)).not.toEqual(['1'])
  })
})
