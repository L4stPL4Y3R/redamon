/**
 * The shared `Updated` column: sorting, formatting, and the cell.
 *
 * Every graph table now leads with the most recently written row, so the
 * ordering rules here are what a user actually sees first on ~40 sheets. The
 * cases that matter are the ones a naive `b - a` gets wrong: a Cypher temporal
 * arrives as an OBJECT (not a string), and a node with no timestamp at all is
 * unknown rather than oldest.
 *
 * Run: npx vitest run src/app/graph/components/RedZoneTables/updatedAt.test.tsx
 */
import { describe, test, expect } from 'vitest'
import { render } from '@testing-library/react'
import {
  UPDATED_AT_COLUMN,
  UPDATED_AT_KEY,
  UPDATED_AT_PROP,
  UpdatedAtCell,
  formatUpdatedAt,
  nodeUpdatedAt,
  sortByUpdatedAt,
  withUpdatedAt,
} from './updatedAt'

/** A Cypher `datetime()` as the neo4j driver hands it to the browser. */
function temporal(y: number, mo: number, d: number, h = 0, mi = 0, sec = 0) {
  const int = (n: number) => ({ low: n, high: 0 })
  return { year: int(y), month: int(mo), day: int(d), hour: int(h), minute: int(mi), second: int(sec) }
}

describe('formatUpdatedAt', () => {
  test('renders a Cypher temporal object', () => {
    expect(formatUpdatedAt(temporal(2026, 8, 20, 14, 32, 58))).toBe('2026-08-20 14:32:58')
  })

  test('zero-pads single-digit parts', () => {
    expect(formatUpdatedAt(temporal(2026, 1, 2, 3, 4, 5))).toBe('2026-01-02 03:04:05')
  })

  test('renders an ISO string the same way a temporal renders', () => {
    // The supply-chain routes `toString()` their timestamps, so one sheet
    // returns a string where its neighbour returns an object. They must not
    // look different in the table.
    expect(formatUpdatedAt('2026-08-20T14:32:58.123000000Z')).toBe('2026-08-20 14:32:58')
  })

  test('rejects values that are not timestamps', () => {
    for (const v of [null, undefined, '', 'n/a', 443, { low: 8080, high: 0 }]) {
      expect(formatUpdatedAt(v)).toBeNull()
    }
  })
})

describe('sortByUpdatedAt', () => {
  const rows = [
    { id: 'old', updatedAt: temporal(2026, 1, 1) },
    { id: 'new', updatedAt: temporal(2026, 8, 20) },
    { id: 'mid', updatedAt: temporal(2026, 5, 5) },
  ]

  test('desc puts the most recent row first', () => {
    expect(sortByUpdatedAt(rows, 'desc').map(r => r.id)).toEqual(['new', 'mid', 'old'])
  })

  test('asc reverses it', () => {
    expect(sortByUpdatedAt(rows, 'asc').map(r => r.id)).toEqual(['old', 'mid', 'new'])
  })

  test('compares a temporal against an ISO string correctly', () => {
    const mixed = [
      { id: 'iso-new', updatedAt: '2026-08-20T00:00:00Z' },
      { id: 'obj-old', updatedAt: temporal(2026, 1, 1) },
    ]
    expect(sortByUpdatedAt(mixed, 'desc').map(r => r.id)).toEqual(['iso-new', 'obj-old'])
  })

  test('rows with no timestamp sink to the bottom in BOTH directions', () => {
    // "Unknown", not "oldest": floating them to the top on the first click
    // would bury exactly the rows the user asked to see.
    const withGaps = [
      { id: 'none', updatedAt: null },
      { id: 'new', updatedAt: temporal(2026, 8, 20) },
      { id: 'old', updatedAt: temporal(2026, 1, 1) },
    ]
    expect(sortByUpdatedAt(withGaps, 'desc').map(r => r.id)).toEqual(['new', 'old', 'none'])
    expect(sortByUpdatedAt(withGaps, 'asc').map(r => r.id)).toEqual(['old', 'new', 'none'])
  })

  test('ties keep the order the route returned', () => {
    // Each sheet orders by its own severity/score ranking; that must survive as
    // the secondary ordering rather than being scrambled.
    const sameInstant = [
      { id: 'critical', updatedAt: temporal(2026, 8, 20) },
      { id: 'high', updatedAt: temporal(2026, 8, 20) },
      { id: 'low', updatedAt: temporal(2026, 8, 20) },
    ]
    expect(sortByUpdatedAt(sameInstant, 'desc').map(r => r.id)).toEqual(['critical', 'high', 'low'])
  })

  test('does not mutate the input array', () => {
    const input = [...rows]
    sortByUpdatedAt(input, 'desc')
    expect(input.map(r => r.id)).toEqual(['old', 'new', 'mid'])
  })

  test('a list with no timestamps anywhere is left untouched', () => {
    // JS Recon's Subdomains sheet is bare strings with no node behind them.
    const bare = [{ id: 'a' }, { id: 'b' }, { id: 'c' }]
    expect(sortByUpdatedAt(bare, 'desc').map(r => r.id)).toEqual(['a', 'b', 'c'])
  })
})

describe('the column descriptor', () => {
  test('key matches what every route returns', () => {
    expect(UPDATED_AT_COLUMN.key).toBe(UPDATED_AT_KEY)
    expect(UPDATED_AT_KEY).toBe('updatedAt')
  })

  test('withUpdatedAt appends, so the column stays rightmost', () => {
    const cols = withUpdatedAt([{ key: 'a', header: 'A' }, { key: 'b', header: 'B' }])
    expect(cols.map(c => c.key)).toEqual(['a', 'b', UPDATED_AT_KEY])
  })
})

describe('UpdatedAtCell', () => {
  test('renders the formatted timestamp', () => {
    const { container } = render(<UpdatedAtCell value={temporal(2026, 8, 20, 14, 32, 58)} />)
    expect(container.textContent).toBe('2026-08-20 14:32:58')
  })

  test('renders a dash for a node written before the timestamp existed', () => {
    const { container } = render(<UpdatedAtCell value={null} />)
    expect(container.textContent).toBe('-')
  })

  test('never leaks a raw object into the cell', () => {
    const { container } = render(<UpdatedAtCell value={{ not: 'a date' }} />)
    expect(container.textContent).not.toContain('object Object')
  })
})

describe('nodeUpdatedAt', () => {
  // Measured against the live graph: these are the labels whose nodes carry a
  // write time under a name other than `updated_at`, and between them they are
  // the largest single label in the database.
  test('prefers updated_at when present', () => {
    expect(nodeUpdatedAt({ updated_at: temporal(2026, 8, 20), last_seen: temporal(2026, 1, 1) }))
      .toEqual(temporal(2026, 8, 20))
  })

  test('falls back to last_seen (Package, MalPackageFinding)', () => {
    expect(formatUpdatedAt(nodeUpdatedAt({
      first_seen: '2026-01-01T00:00:00Z',
      last_seen: '2026-08-20T14:32:58Z',
    }))).toBe('2026-08-20 14:32:58')
  })

  test('falls back to created_at (ChainStep, ChainFinding, ChainFailure)', () => {
    expect(formatUpdatedAt(nodeUpdatedAt({ created_at: temporal(2026, 8, 20, 9, 0, 0) })))
      .toBe('2026-08-20 09:00:00')
  })

  test('prefers last_seen over created_at, and created_at over first_seen', () => {
    // "Most recently written wins": last_seen is a later fact than the
    // first_seen beside it.
    expect(nodeUpdatedAt({ first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-02-01T00:00:00Z' }))
      .toBe('2026-02-01T00:00:00Z')
  })

  test('returns undefined - not null - when nothing is readable', () => {
    // undefined is what TanStack `sortUndefined: 'last'` keys on; null would
    // fall through to the comparator and flip to the top on reverse sort.
    expect(nodeUpdatedAt({ name: 'x' })).toBeUndefined()
    expect(nodeUpdatedAt({ updated_at: 'not-a-date' })).toBeUndefined()
  })

  test('skips an unreadable updated_at and keeps looking', () => {
    expect(nodeUpdatedAt({ updated_at: '', last_seen: '2026-08-20T00:00:00Z' }))
      .toBe('2026-08-20T00:00:00Z')
  })

  test('UPDATED_AT_PROP is the Neo4j name, not the API row key', () => {
    expect(UPDATED_AT_PROP).toBe('updated_at')
    expect(UPDATED_AT_KEY).toBe('updatedAt')
    expect(UPDATED_AT_PROP).not.toBe(UPDATED_AT_KEY)
  })
})
