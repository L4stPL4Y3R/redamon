/**
 * The credential catalogue is the join between three lists that live in
 * different languages and files, and every pairing has a silent failure mode:
 *
 *   - a source registry key with no catalogue entry -> the inline shortcut
 *     renders an unlabelled box, or nothing at all, and the user is told to set
 *     a key the UI cannot name.
 *   - a catalogue name missing from the settings route's writable `fields` list
 *     -> the form accepts the value, reports success, and never persists it.
 *   - a duplicate name -> one entry's hint silently wins.
 *
 * None of these throw at runtime, so they are pinned here.
 *
 * Run: npx vitest run src/lib/credentialFields.test.ts
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  TRUFFLEHOG_KEY_FIELDS,
  SHARED_SCANNER_KEY_FIELDS,
  CREDENTIAL_FIELD_NAMES,
  credentialField,
  isSecretField,
} from './credentialFields'
import { TRUFFLEHOG_SOURCES } from './trufflehogSources'

const SETTINGS_ROUTE = join(process.cwd(), 'src/app/api/users/[id]/settings/route.ts')

/** The `fields` allowlist the PUT handler writes. Anything outside it is dropped. */
function writableSettingsFields(): string[] {
  const src = readFileSync(SETTINGS_ROUTE, 'utf8')
  const m = src.match(/const fields = \[([\s\S]*?)\] as const/)
  if (!m) throw new Error('writable `fields` array not found in the settings route - update this test')
  return [...m[1].matchAll(/'([A-Za-z0-9_]+)'/g)].map(x => x[1])
}

describe('credential catalogue', () => {
  test('every name is unique', () => {
    const seen = new Set<string>()
    for (const name of CREDENTIAL_FIELD_NAMES) {
      expect(seen.has(name), `duplicate catalogue entry for '${name}'`).toBe(false)
      seen.add(name)
    }
  })

  test('every entry has a label and a hint', () => {
    for (const name of CREDENTIAL_FIELD_NAMES) {
      const f = credentialField(name)!
      expect(f.label.length, `'${name}' has no label`).toBeGreaterThan(0)
      expect(f.hint.length, `'${name}' has no hint`).toBeGreaterThan(0)
    }
  })

  // The shortcut cannot prompt for a key it cannot describe.
  test('every credential in the Secret Multiscanner source registry has a catalogue entry', () => {
    for (const source of Object.values(TRUFFLEHOG_SOURCES)) {
      for (const cred of source.credentials) {
        expect(
          credentialField(cred.settingsKey),
          `source '${source.id}' needs '${cred.settingsKey}', which has no credentialFields entry`,
        ).toBeDefined()
      }
    }
  })

  // A key the PUT handler does not list is accepted by the UI and thrown away.
  test('every catalogue name is writable by the settings route', () => {
    const writable = writableSettingsFields()
    for (const name of CREDENTIAL_FIELD_NAMES) {
      expect(
        writable,
        `'${name}' is not in the settings route's writable fields, so saving it is a no-op`,
      ).toContain(name)
    }
  })

  test('the Secret Multiscanner fields all carry a source id that exists', () => {
    const ids = new Set(Object.values(TRUFFLEHOG_SOURCES).map(s => s.id))
    for (const f of TRUFFLEHOG_KEY_FIELDS) {
      expect(ids, `'${f.name}' claims source '${f.source}', which is not a registered source`).toContain(f.source)
    }
  })

  test('secrets are masked by default and the GHE host opts out', () => {
    expect(isSecretField('trufflehogGithubToken')).toBe(true)
    expect(isSecretField('githubAccessToken')).toBe(true)
    // A hostname is configuration, not a credential: masking it hides the
    // allowlist value the user needs to be able to read back.
    expect(isSecretField('githubEnterpriseHost')).toBe(false)
  })

  test('an unknown key resolves to undefined rather than throwing', () => {
    expect(credentialField('notAKey')).toBeUndefined()
    expect(isSecretField('notAKey')).toBe(true)
  })

  test('the shared scanner keys cover GitHub Secret Hunt and Supply Chain', () => {
    const names = SHARED_SCANNER_KEY_FIELDS.map(f => f.name)
    expect(names).toContain('githubAccessToken')
    expect(names).toContain('githubEnterpriseHost')
    expect(names).toContain('githubEnterpriseToken')
  })
})
