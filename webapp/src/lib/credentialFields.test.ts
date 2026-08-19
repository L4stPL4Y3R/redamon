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
  githubKeyGroups,
  CREDENTIAL_FIELD_NAMES,
  credentialField,
  isSecretField,
  shortCredentialLabel,
  trufflehogKeyGroups,
} from './credentialFields'
import {
  TRUFFLEHOG_SOURCES,
  resolveMissingCredentials,
  trufflehogCredentialRequirement,
} from './trufflehogSources'

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
    expect(names).toContain('supplyChainGithubToken')
    expect(names).toContain('githubEnterpriseHost')
    expect(names).toContain('githubEnterpriseToken')
  })

  // Three github.com PATs, one per consumer. Sharing one meant a scope change
  // for Supply Chain silently widened what Secret Hunt could reach, and
  // revoking it stopped both.
  test('Secret Hunt and Supply Chain hold different columns', () => {
    const groups = githubKeyGroups()
    const byId = Object.fromEntries(groups.map(g => [g.source, g]))
    expect(byId['github-secret-hunt'].fields.map(f => f.name)).toEqual(['githubAccessToken'])
    expect(byId['supply-chain'].fields.map(f => f.name)).toEqual(['supplyChainGithubToken'])
    // The Enterprise PAT is one credential for one server and is NOT split.
    expect(byId['github-enterprise'].fields.map(f => f.name))
      .toEqual(['githubEnterpriseHost', 'githubEnterpriseToken'])
  })

  test('every GitHub key lands in exactly one group', () => {
    const grouped = githubKeyGroups().flatMap(g => g.fields.map(f => f.name))
    expect(grouped.sort()).toEqual(SHARED_SCANNER_KEY_FIELDS.map(f => f.name).sort())
  })

  test('only Secret Hunt is required: it cannot run unauthenticated at all', () => {
    const byId = Object.fromEntries(githubKeyGroups().map(g => [g.source, g.requirement]))
    expect(byId['github-secret-hunt']).toBe('required')
    // Public repos clone anonymously, so a Supply Chain token is conditional.
    expect(byId['supply-chain']).toBe('conditional')
    expect(byId['github-enterprise']).toBe('optional')
  })
})

/**
 * The grouped rendering in Global Settings. What it can get wrong is not
 * cosmetic: a key that lands in no group is a key the page stops offering, and
 * a group chipped "Optional" over a key the Start gate blocks on tells the user
 * to skip the one thing standing between them and a scan.
 */
describe('Secret Multiscanner key groups', () => {
  test('every key lands in exactly one group, and no key is dropped', () => {
    const grouped = trufflehogKeyGroups().flatMap(g => g.fields.map(f => f.name))
    expect(new Set(grouped).size).toBe(grouped.length)
    expect(grouped.sort()).toEqual(TRUFFLEHOG_KEY_FIELDS.map(f => f.name).sort())
  })

  test('a key the Start gate can block a scan on is never chipped Optional', () => {
    // One config per source that makes its credential mandatory; the docker /
    // s3 / gcs entries are the configs trufflehogCredentialRequired() keys on.
    const BLOCKING: [string, Record<string, unknown>][] = [
      ['github', {}], ['github_experimental', {}], ['gitlab', {}], ['postman', {}],
      ['circleci', {}], ['travisci', {}], ['docker', { namespace: 'acme' }],
      ['s3', {}], ['gcs', {}],
    ]
    for (const [sourceId, config] of BLOCKING) {
      const missing = resolveMissingCredentials(sourceId, config, {})
      expect(missing.length, `'${sourceId}' has no mandatory credential to check`).toBeGreaterThan(0)
      for (const cred of missing) {
        expect(
          trufflehogCredentialRequirement(cred.settingsKey),
          `'${cred.settingsKey}' blocks a ${sourceId} scan but is chipped optional`,
        ).not.toBe('optional')
      }
    }
  })

  test('a source that scans unauthenticated chips its keys Optional', () => {
    for (const key of ['trufflehogHuggingfaceToken', 'trufflehogJenkinsUsername',
      'trufflehogElasticApiKey', 'trufflehogGitToken', 'trufflehogAwsSessionToken']) {
      expect(trufflehogCredentialRequirement(key), key).toBe('optional')
    }
  })

  test('a config-dependent key is neither required nor optional', () => {
    for (const key of ['trufflehogDockerToken', 'trufflehogAwsAccessKeyId', 'trufflehogGcpServiceAccount']) {
      expect(trufflehogCredentialRequirement(key), key).toBe('conditional')
    }
  })

  // The GitHub token feeds two sources. A user who set it for GitHub and then
  // sees "GitHub deleted commits" ask for a token has no way to know it is the
  // same one unless the group says so.
  test('a group names the other sources reading its keys', () => {
    const github = trufflehogKeyGroups().find(g => g.source === 'github')!
    expect(github.alsoUsedBy).toContain('GitHub deleted commits')
    const gitlab = trufflehogKeyGroups().find(g => g.source === 'gitlab')!
    expect(gitlab.alsoUsedBy).toEqual([])
  })

  test('a group takes the strongest requirement of its keys', () => {
    const s3 = trufflehogKeyGroups().find(g => g.source === 's3')!
    // The session token alone is optional; the group still has to say the
    // access key is not.
    expect(s3.fields.map(f => f.requirement)).toContain('optional')
    expect(s3.requirement).toBe('conditional')
  })

  test('the label loses its scanner prefix and nothing else', () => {
    expect(shortCredentialLabel('Secret Multiscanner GitHub Token')).toBe('GitHub Token')
    expect(shortCredentialLabel('GitHub Access Token')).toBe('GitHub Access Token')
  })
})
