/**
 * One component of a Neo4j temporal. The driver serialises integers as
 * `{low, high}`, but a value that has been through a lossless-integer-disabled
 * driver or a JSON round trip arrives as a plain number. Reading `.low` blindly
 * turns the second shape into `undefined` and the whole timestamp into
 * "undefined-NaN-undefined", so both are accepted and anything else rejects the
 * value as not-a-datetime.
 */
function temporalPart(v: unknown): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null
  if (v !== null && typeof v === 'object' && 'low' in (v as object)) {
    const n = (v as { low: unknown }).low
    return typeof n === 'number' && Number.isFinite(n) ? n : null
  }
  return null
}

/**
 * Format Neo4j datetime objects to readable string.
 *
 * This is the single definition of how a graph timestamp LOOKS, so anything
 * that searches, filters or exports one must go through it too - otherwise a
 * user filters on what the cell displays and the code compares against
 * `[object Object]`.
 */
export function formatNeo4jDateTime(value: unknown): string | null {
  if (typeof value !== 'object' || value === null) return null

  const parts = ['year', 'month', 'day', 'hour', 'minute', 'second'].map(k =>
    k in value ? temporalPart((value as Record<string, unknown>)[k]) : null
  )
  if (parts.some(p => p === null)) return null

  const [year, month, day, hour, minute, second] = parts as number[]
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${year}-${pad(month)}-${pad(day)} ${pad(hour)}:${pad(minute)}:${pad(second)}`
}

/**
 * Format a property value for display in the drawer
 */
export function formatPropertyValue(value: unknown): React.ReactNode {
  const formattedDate = formatNeo4jDateTime(value)

  if (formattedDate) {
    return formattedDate
  }

  if (
    value === null ||
    value === undefined ||
    value === 'none' ||
    value === 'None' ||
    value === 'null' ||
    value === 'NULL'
  ) {
    return '---'
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return '---'
    }
    return value.join(', ')
  }

  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2)
  }

  if (value === '') {
    return '---'
  }

  return String(value)
}
