/**
 * These links only work if THREE things agree: the anchor, an element id in a
 * section component, and a tab id in ProjectForm's TAB_GROUPS. Every mismatch
 * fails SILENTLY at runtime (unknown anchor = no tab switch and no scroll, so
 * the operator lands on the 'target' tab wondering where the section went), so
 * the pairing is asserted against the real sources rather than a copy.
 */
import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import {
  PROJECT_SECTION_ANCHORS, projectSettingsHref, tabForAnchor,
} from './projectSettingsLinks'

const FORM = join(process.cwd(), 'src/components/projects/ProjectForm/ProjectForm.tsx')
const SECTIONS = join(process.cwd(), 'src/components/projects/ProjectForm/sections')

/** Every `id: '...'` inside ProjectForm's TAB_GROUPS declaration. */
function formTabIds(): string[] {
  const src = readFileSync(FORM, 'utf8')
  const start = src.indexOf('const TAB_GROUPS')
  if (start < 0) throw new Error('TAB_GROUPS not found in ProjectForm.tsx - update this test')
  const end = src.indexOf('type TabId', start)
  return [...src.slice(start, end).matchAll(/id:\s*'([^']+)'/g)].map(m => m[1])
}

/** Every `id="..."` present on a section component. */
function sectionElementIds(): string[] {
  const ids: string[] = []
  for (const file of readdirSync(SECTIONS).filter(f => f.endsWith('.tsx'))) {
    const src = readFileSync(join(SECTIONS, file), 'utf8')
    ids.push(...[...src.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]))
  }
  return ids
}

describe('projectSettingsHref', () => {
  test('builds a section-anchored href', () => {
    expect(projectSettingsHref('p1', 'github-secret-hunting'))
      .toBe('/projects/p1/settings#github-secret-hunting')
    expect(projectSettingsHref('p1', 'trufflehog-scanner'))
      .toBe('/projects/p1/settings#trufflehog-scanner')
  })

  // A project id reaches this from route params; it must not be able to break
  // out of the path segment.
  test('escapes the project id', () => {
    expect(projectSettingsHref('a/b', 'trufflehog-scanner'))
      .toBe('/projects/a%2Fb/settings#trufflehog-scanner')
  })

  test('every anchor points at a tab ProjectForm actually has', () => {
    const tabs = formTabIds()
    expect(tabs.length).toBeGreaterThan(0)
    for (const [anchor, { tab }] of Object.entries(PROJECT_SECTION_ANCHORS)) {
      expect(tabs, `anchor '${anchor}' targets tab '${tab}', which ProjectForm does not define`)
        .toContain(tab)
    }
  })

  test('every anchor exists as an element id on a section', () => {
    const ids = sectionElementIds()
    for (const anchor of Object.keys(PROJECT_SECTION_ANCHORS)) {
      expect(ids, `no section renders id="${anchor}", so the scroll target is missing`)
        .toContain(anchor)
    }
  })
})

describe('tabForAnchor', () => {
  test('resolves a known anchor', () => {
    expect(tabForAnchor('github-secret-hunting')).toBe('integrations')
  })

  // ProjectForm passes any hash through this; an unrelated one must be ignored
  // rather than switching tabs to something arbitrary.
  test('returns null for an anchor that is not ours', () => {
    expect(tabForAnchor('some-other-hash')).toBeNull()
    expect(tabForAnchor('')).toBeNull()
  })
})
