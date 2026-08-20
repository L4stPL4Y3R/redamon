/**
 * The settings -> graph scan deep link. The parser is the guard: the graph page
 * opens a modal off this value, so anything it does not recognise must come back
 * as null rather than as a truthy inherited property.
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { graphScanHref, parseScanModal } from './scanModalLink'

describe('graphScanHref', () => {
  test('carries the project and the modal to open', () => {
    expect(graphScanHref('p1', 'gvm')).toBe('/graph?project=p1&scan=gvm')
    expect(graphScanHref('p1', 'other')).toBe('/graph?project=p1&scan=other')
  })

  test('the project id is encoded', () => {
    expect(graphScanHref('a/b', 'other')).toBe('/graph?project=a%2Fb&scan=other')
  })
})

describe('parseScanModal', () => {
  test('accepts the two real modals', () => {
    expect(parseScanModal('gvm')).toBe('gvm')
    expect(parseScanModal('other')).toBe('other')
  })

  test('rejects everything else, prototype keys included', () => {
    for (const bad of ['GVM', 'otherScans', 'constructor', 'toString', '', null, undefined]) {
      expect(parseScanModal(bad as string | null | undefined)).toBeNull()
    }
  })
})

/**
 * Structural wiring: the href is only useful if the graph page reads the param
 * and opens the matching modal, and if every scan section actually renders the
 * actions. Neither link is enforced by the type system.
 */
describe('scan deep-link wiring', () => {
  const read = (rel: string) =>
    readFileSync(join(process.cwd(), rel), 'utf8')

  test('the graph page validates the param and opens both modals', () => {
    const page = read('src/app/graph/page.tsx')
    expect(page).toContain("parseScanModal(searchParams.get('scan'))")
    expect(page).toContain('setIsGvmModalOpen(true)')
    expect(page).toContain('setIsOtherScansModalOpen(true)')
  })

  test('all four scan sections get the header actions', () => {
    const form = read('src/components/projects/ProjectForm/ProjectForm.tsx')
    for (const section of ['GvmScanSection', 'GithubSection', 'TrufflehogSection', 'SupplyChainScanSection']) {
      const tag = form.slice(form.indexOf(`<${section}`), form.indexOf(`<${section}`) + 400)
      expect(tag, `${section} has no actions prop`).toContain('actions={sectionScanActions(')
    }
  })
})
