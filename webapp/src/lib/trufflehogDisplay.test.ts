/**
 * The per-source display registry.
 *
 * `asset`, `location` and `extra_data` are generic on the node by necessity —
 * one shape has to hold a repository, a container image, a bucket and a Jenkins
 * job. The registry is what turns them back into something an operator can read,
 * and its failure mode is quiet: a wrong label reads as a real fact.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  TRUFFLEHOG_DISPLAY,
  trufflehogDisplayFields,
  trufflehogDisplaySpec,
  trufflehogLocationLabel,
} from './trufflehogDisplay'
import { TRUFFLEHOG_SOURCE_IDS } from './trufflehogSources'

describe('registry coverage', () => {
  test('every source the scanner supports has a display spec', () => {
    // A source without one renders as bare "Asset"/"Location", which is exactly
    // the unlabelled output this registry exists to replace.
    for (const id of TRUFFLEHOG_SOURCE_IDS) {
      expect(TRUFFLEHOG_DISPLAY[id]).toBeDefined()
    }
  })

  test('the dash spelling resolves, and an unknown source degrades safely', () => {
    expect(trufflehogDisplaySpec('github-experimental').asset).toBe('Repository')
    expect(trufflehogDisplaySpec('slack')).toEqual({ asset: 'Asset', location: 'Location', extra: [] })
    expect(trufflehogDisplaySpec(null).asset).toBe('Asset')
  })

  test('each source labels its asset as what it actually is', () => {
    expect(TRUFFLEHOG_DISPLAY.docker.asset).toBe('Image')
    expect(TRUFFLEHOG_DISPLAY.s3.asset).toBe('Bucket')
    expect(TRUFFLEHOG_DISPLAY.jenkins.asset).toBe('Instance URL')
    expect(TRUFFLEHOG_DISPLAY.huggingface.asset).toMatch(/Model/)
  })
})

describe('trufflehogLocationLabel', () => {
  test('a build-history finding is named, not shown as a path', () => {
    // The synthetic path exists in no filesystem; printing it sends the operator
    // looking for a file that is not there.
    expect(trufflehogLocationLabel('image-metadata:history:3:created-by', 'image_history'))
      .toBe('Dockerfile (build history)')
  })

  test('an ordinary location passes through', () => {
    expect(trufflehogLocationLabel('/app/.env', 'secret')).toBe('/app/.env')
  })
})

describe('trufflehogDisplayFields', () => {
  const dockerFinding = {
    source: 'docker',
    detector_name: 'AWS',
    asset: 'acme/app:1.0',
    location: '/app/.env',
    line: 12,
    redacted: 'AKIA****',
    commit: '',
    finding_kind: 'secret',
    extra_data: JSON.stringify({ Tag: '1.0', Layer: 'sha256:abcd' }),
  }

  test('a docker finding is labelled with image / layer terms', () => {
    const fields = trufflehogDisplayFields(dockerFinding)
    const byLabel = Object.fromEntries(fields.map(f => [f.label, f.value]))
    expect(byLabel.Image).toBe('acme/app:1.0')
    expect(byLabel['Layer / File']).toBe('/app/.env')
    expect(byLabel.Tag).toBe('1.0')
    expect(byLabel['Layer digest']).toBe('sha256:abcd')
  })

  test('extra_data is unpacked into named fields, never shown as a blob', () => {
    const values = trufflehogDisplayFields(dockerFinding).map(f => f.value)
    expect(values.some(v => v.startsWith('{'))).toBe(false)
  })

  test('a field that is empty for this source is omitted, not shown blank', () => {
    // "Commit: (empty)" on a docker finding is noise: that source has no commits.
    const labels = trufflehogDisplayFields(dockerFinding).map(f => f.label)
    expect(labels).not.toContain('Commit')
  })

  test('a git finding surfaces its commit and author', () => {
    const byLabel = Object.fromEntries(trufflehogDisplayFields({
      source: 'github', detector_name: 'AWS', asset: 'acme/api', location: 'src/app.py',
      extra_data: JSON.stringify({ commit: 'c0ffee', email: 'dev@acme.io' }),
    }).map(f => [f.label, f.value]))
    expect(byLabel.Repository).toBe('acme/api')
    expect(byLabel.File).toBe('src/app.py')
    expect(byLabel.Commit).toBe('c0ffee')
    expect(byLabel['Author email']).toBe('dev@acme.io')
  })

  test('the deprecated repository/file aliases still render', () => {
    // Nodes written before the rename keep only the old names.
    const byLabel = Object.fromEntries(trufflehogDisplayFields({
      source: 'github', detector_name: 'AWS', repository: 'acme/api', file: 'a.py',
    }).map(f => [f.label, f.value]))
    expect(byLabel.Repository).toBe('acme/api')
    expect(byLabel.File).toBe('a.py')
  })

  test('a malformed extra_data blob does not blank the drawer', () => {
    const fields = trufflehogDisplayFields({
      source: 'docker', detector_name: 'AWS', asset: 'a', extra_data: '{not json',
    })
    expect(fields.find(f => f.label === 'Detector')?.value).toBe('AWS')
  })

  test('a build-history docker finding shows the friendly location', () => {
    const byLabel = Object.fromEntries(trufflehogDisplayFields({
      ...dockerFinding,
      location: 'image-metadata:history:3:created-by',
      finding_kind: 'image_history',
    }).map(f => [f.label, f.value]))
    expect(byLabel['Layer / File']).toBe('Dockerfile (build history)')
  })

  test('a non-finding node produces nothing', () => {
    expect(trufflehogDisplayFields({})).toEqual([])
  })
})
