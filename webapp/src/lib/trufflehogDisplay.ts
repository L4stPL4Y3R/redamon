/**
 * How a TruffleHog finding is LABELLED per source.
 *
 * `asset` and `location` are deliberately generic on the node — they have to
 * hold a repo and a file, an image and a layer path, a bucket and an object key.
 * But a drawer that prints `asset: acme/app:1.0` and `location: /app/.env` next
 * to `extra_data: {"Tag":"1.0","Layer":"sha256:…"}` tells the operator nothing
 * about what they are looking at.
 *
 * One registry, mirrored per source, rather than a component per source: adding
 * source 15 is one entry here, not a new renderer.
 */

export interface TrufflehogDisplaySpec {
  /** What `asset` means for this source. */
  asset: string
  /** What `location` means for this source. */
  location: string
  /** Keys inside `extra_data` worth surfacing, in order, with their labels. */
  extra: { key: string; label: string }[]
}

const GIT_LIKE: TrufflehogDisplaySpec = {
  asset: 'Repository',
  location: 'File',
  extra: [
    { key: 'commit', label: 'Commit' },
    { key: 'email', label: 'Author email' },
    { key: 'link', label: 'Link' },
  ],
}

export const TRUFFLEHOG_DISPLAY: Record<string, TrufflehogDisplaySpec> = {
  git: GIT_LIKE,
  github: GIT_LIKE,
  github_experimental: { ...GIT_LIKE, location: 'Object (deleted/force-pushed)' },
  gitlab: GIT_LIKE,
  docker: {
    asset: 'Image',
    location: 'Layer / File',
    extra: [
      { key: 'Tag', label: 'Tag' },
      { key: 'Layer', label: 'Layer digest' },
    ],
  },
  huggingface: {
    asset: 'Model / Space / Dataset',
    location: 'File',
    extra: [
      { key: 'commit', label: 'Revision' },
      { key: 'link', label: 'Link' },
    ],
  },
  s3: {
    asset: 'Bucket',
    location: 'Object key',
    extra: [{ key: 'link', label: 'Link' }],
  },
  gcs: {
    asset: 'Bucket',
    location: 'Object key',
    extra: [
      { key: 'link', label: 'Link' },
      { key: 'acl', label: 'ACL' },
    ],
  },
  filesystem: { asset: 'Scan root', location: 'File', extra: [] },
  jenkins: {
    asset: 'Instance URL',
    location: 'Job / build',
    extra: [{ key: 'build_number', label: 'Build number' }],
  },
  elasticsearch: {
    asset: 'Node',
    location: 'Index',
    extra: [{ key: 'document_id', label: 'Document id' }],
  },
  postman: {
    asset: 'Workspace',
    location: 'Collection / request',
    extra: [{ key: 'environment', label: 'Environment' }],
  },
  circleci: {
    asset: 'Project',
    location: 'Build / step',
    extra: [{ key: 'build_number', label: 'Build number' }],
  },
  travisci: {
    asset: 'Repository',
    location: 'Job',
    extra: [{ key: 'link', label: 'Link' }],
  },
}

const FALLBACK: TrufflehogDisplaySpec = { asset: 'Asset', location: 'Location', extra: [] }

export function trufflehogDisplaySpec(source: string | undefined | null): TrufflehogDisplaySpec {
  return TRUFFLEHOG_DISPLAY[String(source ?? '').replace(/-/g, '_')] ?? FALLBACK
}

/** A finding's `location`, rendered as what it actually is. Secrets baked into a
 *  Docker image's build history carry a synthetic path that exists in no
 *  filesystem, so showing it raw sends the operator looking for a missing file. */
export function trufflehogLocationLabel(
  location: string | null | undefined,
  findingKind: string | null | undefined,
): string {
  if (findingKind === 'image_history') return 'Dockerfile (build history)'
  return String(location ?? '')
}

export interface TrufflehogDisplayField {
  label: string
  value: string
}

/**
 * A TruffleHog finding's properties as labelled rows, ready to render.
 *
 * Empty fields are dropped, because "Commit: (empty)" on a Docker finding is
 * noise: that source has no commits. `extra_data` is unpacked into named fields
 * instead of shown as a JSON blob.
 */
export function trufflehogDisplayFields(
  properties: Record<string, unknown>,
): TrufflehogDisplayField[] {
  const source = String(properties.source ?? '')
  const spec = trufflehogDisplaySpec(source)
  const out: TrufflehogDisplayField[] = []

  const push = (label: string, value: unknown) => {
    const text = value == null ? '' : String(value)
    if (text && text !== '0') out.push({ label, value: text })
  }

  push('Detector', properties.detector_name)
  push('Source', source)
  push(spec.asset, properties.asset ?? properties.repository)
  push(
    spec.location,
    trufflehogLocationLabel(
      (properties.location ?? properties.file) as string | null,
      properties.finding_kind as string | null,
    ),
  )
  push('Line', properties.line)
  push('Redacted', properties.redacted)

  let extra: Record<string, unknown> = {}
  try {
    const raw = properties.extra_data
    if (typeof raw === 'string' && raw.trim()) extra = JSON.parse(raw)
    else if (raw && typeof raw === 'object') extra = raw as Record<string, unknown>
  } catch {
    // A malformed blob must not blank the whole drawer.
  }

  for (const { key, label } of spec.extra) {
    push(label, extra[key] ?? properties[key])
  }

  return out
}
