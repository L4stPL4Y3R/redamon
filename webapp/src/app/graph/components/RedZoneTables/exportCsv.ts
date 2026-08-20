import { formatNeo4jDateTime } from '../../utils/formatters'
import {
  timestampSlug,
  downloadStreaming,
  streamCsvChunks,
  streamJsonArrayChunks,
  streamMarkdownTableChunks,
  CSV_MIME,
} from '../../utils/exportHelpers'

export interface RedZoneExportColumn {
  key: string
  header: string
}

export interface RedZoneExportConfig {
  // Readonly: exporting only ever iterates, and the rows handed in are a
  // filtered view the table also renders from.
  rows: readonly object[]
  sheetName: string
  fileSlug: string
  columns: readonly RedZoneExportColumn[]
}

function* lazyDictRows(rows: readonly object[], columns: readonly RedZoneExportColumn[]): Iterable<Record<string, unknown>> {
  for (const row of rows) {
    const out: Record<string, unknown> = {}
    for (const col of columns) {
      out[col.header] = (row as Record<string, unknown>)[col.key]
    }
    yield out
  }
}

function* lazyDictRowsForJson(rows: readonly object[], columns: readonly RedZoneExportColumn[]): Iterable<Record<string, unknown>> {
  for (const row of rows) {
    const out: Record<string, unknown> = {}
    for (const col of columns) {
      const v = (row as Record<string, unknown>)[col.key]
      // A Neo4j temporal would serialise as a nested {year:{low..}} object and
      // make the JSON export disagree with the CSV and with the cell.
      const temporal = typeof v === 'object' && v !== null ? formatNeo4jDateTime(v) : null
      out[col.header] = temporal ?? v ?? null
    }
    yield out
  }
}

export async function exportRedZoneCsv<T extends object>(
  rows: readonly T[],
  _sheetName: string,
  columns: readonly RedZoneExportColumn[],
  fileSlug: string,
): Promise<void> {
  const headers = columns.map(c => c.header)
  await downloadStreaming(
    `${fileSlug}-${timestampSlug()}.csv`,
    CSV_MIME,
    () => streamCsvChunks(headers, lazyDictRows(rows, columns)),
  )
}

export async function exportRedZoneJson<T extends object>(
  rows: readonly T[],
  _sheetName: string,
  columns: readonly RedZoneExportColumn[],
  fileSlug: string,
): Promise<void> {
  await downloadStreaming(
    `${fileSlug}-${timestampSlug()}.json`,
    'application/json;charset=utf-8',
    () => streamJsonArrayChunks(lazyDictRowsForJson(rows, columns)),
  )
}

export async function exportRedZoneMarkdown<T extends object>(
  rows: readonly T[],
  sheetName: string,
  columns: readonly RedZoneExportColumn[],
  fileSlug: string,
): Promise<void> {
  const headers = columns.map(c => c.header)
  const preamble = `# ${sheetName}\n\nGenerated: ${new Date().toISOString()}\nRows: ${rows.length}\n\n`

  async function* combined(): AsyncGenerator<string> {
    yield preamble
    yield* streamMarkdownTableChunks(
      headers,
      rows,
      (row, h) => {
        const col = columns.find(c => c.header === h)
        return col ? (row as Record<string, unknown>)[col.key] : undefined
      },
    )
    yield '\n'
  }

  await downloadStreaming(
    `${fileSlug}-${timestampSlug()}.md`,
    'text/markdown;charset=utf-8',
    () => combined(),
  )
}

export async function runRedZoneExport(
  format: 'csv' | 'json' | 'md',
  config: RedZoneExportConfig,
) {
  if (format === 'csv') return exportRedZoneCsv(config.rows, config.sheetName, config.columns, config.fileSlug)
  if (format === 'json') return exportRedZoneJson(config.rows, config.sheetName, config.columns, config.fileSlug)
  return exportRedZoneMarkdown(config.rows, config.sheetName, config.columns, config.fileSlug)
}
