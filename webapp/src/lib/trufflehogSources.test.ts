/**
 * The TS half of the source registry: form validation and the Start-button gate.
 *
 * The Python mirror is compared field-for-field by
 * tests/test_trufflehog_registry_parity.py; this file exercises the behaviour
 * that only exists here — what the operator is told, and when Start is disabled.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  isValidScanTargetName,
  TRUFFLEHOG_SOURCES,
  TRUFFLEHOG_SOURCE_IDS,
  TRUFFLEHOG_CREDENTIAL_FIELDS,
  describeTrufflehogTarget,
  getTrufflehogSource,
  resolveMissingCredentials,
  trufflehogCredentialRequired,
  validateTrufflehogConfig,
} from './trufflehogSources'

describe('registry shape', () => {
  test('14 sources, each with an asset label and kind', () => {
    expect(TRUFFLEHOG_SOURCE_IDS).toHaveLength(14)
    for (const src of Object.values(TRUFFLEHOG_SOURCES)) {
      expect(src.assetLabel).toMatch(/^Multiscanner/)
      expect(['repository', 'image', 'model', 'bucket', 'endpoint']).toContain(src.assetKind)
    }
  })

  test('the dash spelling the CLI uses resolves', () => {
    expect(getTrufflehogSource('github-experimental')?.id).toBe('github_experimental')
    expect(getTrufflehogSource('GitHub')?.id).toBe('github')
    expect(getTrufflehogSource('slack')).toBeUndefined()
  })

  test('no field is named like a credential', () => {
    // A profile row is exported verbatim into project.json; a token stored in
    // `config` would leave with the export zip.
    for (const src of Object.values(TRUFFLEHOG_SOURCES)) {
      for (const f of src.fields) {
        expect(f.key).not.toMatch(/(?:token|password|secret|apikey)$/i)
      }
    }
  })

  test('every credential field is a UserSettings column name', () => {
    expect(TRUFFLEHOG_CREDENTIAL_FIELDS).toHaveLength(19)
    for (const field of TRUFFLEHOG_CREDENTIAL_FIELDS) {
      expect(field).toMatch(/^trufflehog[A-Z]/)
    }
  })
})

describe('validateTrufflehogConfig', () => {
  test('a valid minimal config for every source passes', () => {
    const minimal: Record<string, Record<string, unknown>> = {
      git: { uri: 'https://example.com/a.git' },
      github: { orgs: ['acme'] },
      github_experimental: { repo: 'acme/api' },
      gitlab: { repos: ['https://gitlab.com/acme/api.git'] },
      docker: { images: ['nginx:1.25'] },
      huggingface: { models: ['acme/m'] },
      s3: { buckets: ['b'] },
      gcs: { projectId: 'p' },
      filesystem: {},
      jenkins: { url: 'https://ci.example.com' },
      elasticsearch: { nodes: ['es:9200'] },
      postman: { workspaceIds: ['w'] },
      circleci: {},
      travisci: {},
    }
    expect(Object.keys(minimal).sort()).toEqual([...TRUFFLEHOG_SOURCE_IDS].sort())
    for (const [id, config] of Object.entries(minimal)) {
      expect(validateTrufflehogConfig(id, config)).toEqual([])
    }
  })

  test('github needs a repo or an org', () => {
    expect(validateTrufflehogConfig('github', {})).toContainEqual(
      expect.stringContaining('repository or organization'))
  })

  test('org-only options are refused without an org', () => {
    expect(validateTrufflehogConfig('github', { repos: ['a/b'], includeRepos: ['a/t*'] }))
      .toContainEqual(expect.stringContaining('includeRepos'))
  })

  test('s3 buckets and ignore-buckets are mutually exclusive, not merged', () => {
    expect(validateTrufflehogConfig('s3', { buckets: ['a'], ignoreBuckets: ['b'] }))
      .toContainEqual(expect.stringContaining('mutually exclusive'))
  })

  test('gcs project id conflicts with without-auth, and one is required', () => {
    expect(validateTrufflehogConfig('gcs', { projectId: 'p', withoutAuth: true })).not.toEqual([])
    expect(validateTrufflehogConfig('gcs', {})).not.toEqual([])
    expect(validateTrufflehogConfig('gcs', { withoutAuth: true })).toEqual([])
  })

  test('docker refuses scheme-prefixed references', () => {
    // docker:// needs the Docker socket, which a scan container never gets;
    // file:// reads the container's own filesystem.
    for (const ref of ['docker://nginx', 'file:///tmp/img.tar']) {
      expect(validateTrufflehogConfig('docker', { images: [ref] })).not.toEqual([])
    }
  })

  test('docker refuses option injection and shell metacharacters', () => {
    for (const ref of ['-oProxyCommand=id', 'nginx;id', 'nginx$(id)']) {
      expect(validateTrufflehogConfig('docker', { images: [ref] })).not.toEqual([])
    }
  })

  test('docker accepts digests and registry hosts', () => {
    expect(validateTrufflehogConfig('docker', {
      images: ['ghcr.io/acme/app:1.2', `nginx@sha256:${'a'.repeat(64)}`],
    })).toEqual([])
  })

  test('filesystem takes no target, so there is nothing to get wrong', () => {
    expect(validateTrufflehogConfig('filesystem', {})).toEqual([])
  })

  test('a local git repo name may not escape its folder', () => {
    for (const bad of ['../work/job.json', '/work/job.json', 'a/b', '..', '.']) {
      expect(isValidScanTargetName(bad), bad).toBe(false)
      expect(validateTrufflehogConfig('git', { localRepo: bad }), bad).not.toEqual([])
    }
    expect(isValidScanTargetName('myrepo.git')).toBe(true)
    expect(validateTrufflehogConfig('git', { localRepo: 'myrepo.git' })).toEqual([])
  })

  test('git takes a URI or a local repo, never both and never neither', () => {
    expect(validateTrufflehogConfig('git', { uri: 'https://x/y.git', localRepo: 'z' })).not.toEqual([])
    expect(validateTrufflehogConfig('git', {})).not.toEqual([])
  })

  test('huggingface sweep mode needs an org or a user', () => {
    expect(validateTrufflehogConfig('huggingface', { mode: 'sweep' })).not.toEqual([])
    expect(validateTrufflehogConfig('huggingface', { mode: 'sweep', orgs: ['acme'] })).toEqual([])
  })

  test('an unknown source is an error, not silence', () => {
    expect(validateTrufflehogConfig('slack', {})).toEqual(['Unknown Secret Multiscanner source: slack'])
  })
})

describe('the credential gate', () => {
  test('always-mandatory sources', () => {
    for (const id of ['github', 'github_experimental', 'gitlab', 'postman', 'circleci', 'travisci']) {
      expect(trufflehogCredentialRequired(id, {})).toBe(true)
    }
  })

  test('docker is conditional: a public image scans anonymously, a namespace does not', () => {
    // Docker Hub allows 10 anonymous pulls/hour per IP, which a namespace scan
    // exhausts at once.
    expect(trufflehogCredentialRequired('docker', { images: ['nginx:1.25'] })).toBe(false)
    expect(trufflehogCredentialRequired('docker', { namespace: 'acme' })).toBe(true)
    expect(trufflehogCredentialRequired('docker', { images: ['a'], includePrivate: true })).toBe(true)
  })

  test('s3 and gcs follow their cloud toggles', () => {
    expect(trufflehogCredentialRequired('s3', {})).toBe(true)
    expect(trufflehogCredentialRequired('s3', { cloudEnvironment: true })).toBe(false)
    expect(trufflehogCredentialRequired('gcs', { projectId: 'p' })).toBe(true)
    expect(trufflehogCredentialRequired('gcs', { withoutAuth: true })).toBe(false)
  })

  test('an unauthenticated service is itself a finding, so no key is demanded', () => {
    for (const id of ['jenkins', 'elasticsearch', 'huggingface', 'filesystem']) {
      expect(trufflehogCredentialRequired(id, {})).toBe(false)
    }
  })

  test('resolveMissingCredentials names the exact settings field', () => {
    const missing = resolveMissingCredentials('github', {}, {})
    expect(missing.map(m => m.settingsKey)).toEqual(['trufflehogGithubToken'])
    expect(missing[0].label).toBe('Secret Multiscanner GitHub Token')
  })

  test('a set key clears the gate', () => {
    expect(resolveMissingCredentials('github', {}, { trufflehogGithubToken: 'ghp_x' })).toEqual([])
  })

  test('whitespace is not a credential', () => {
    expect(resolveMissingCredentials('gitlab', {}, { trufflehogGitlabToken: '   ' })).toHaveLength(1)
  })

  test('optional keys within a multi-key source are never demanded', () => {
    // S3 needs key+secret; the session token is only for temporary credentials.
    expect(resolveMissingCredentials('s3', {}, {}).map(m => m.settingsKey).sort())
      .toEqual(['trufflehogAwsAccessKeyId', 'trufflehogAwsSecretKey'])
  })

  test('a source with no mandatory credential returns nothing to set', () => {
    expect(resolveMissingCredentials('jenkins', { url: 'https://ci' }, {})).toEqual([])
  })

  test('null settings are treated as no keys set, not as an error', () => {
    expect(resolveMissingCredentials('github', {}, null)).toHaveLength(1)
  })
})

describe('describeTrufflehogTarget', () => {
  test('summarises each source target', () => {
    expect(describeTrufflehogTarget('github', { orgs: ['acme'], repos: ['acme/api'] }))
      .toBe('acme, acme/api')
    expect(describeTrufflehogTarget('docker', { images: ['nginx:1.25'] })).toBe('nginx:1.25')
    expect(describeTrufflehogTarget('docker', { namespace: 'acme' })).toBe('acme')
    expect(describeTrufflehogTarget('s3', {})).toBe('all reachable buckets')
    expect(describeTrufflehogTarget('gcs', { withoutAuth: true })).toBe('public buckets')
  })

  test('a git URI is shown without its credentials', () => {
    expect(describeTrufflehogTarget('git', { uri: 'https://svc:glpat_secret@git.example.com/a.git' }))
      .toBe('https://git.example.com/a.git')
  })
})
