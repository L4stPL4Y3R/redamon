/**
 * TruffleHog source registry — the TypeScript mirror.
 *
 * The Python original is `scanners/trufflehog_scan/sources.py`, which builds the
 * actual command line. This side renders the form and gates the Start button.
 * The two must agree field-for-field: a field present here and missing there is
 * stored and silently never passed to the binary; a field there and missing here
 * can never be set. `tests/test_trufflehog_registry_parity.py` compares them.
 *
 * No field may hold a secret. Credentials are flat `UserSettings.trufflehog*`
 * columns selected by source, resolved server-side at start time and injected
 * into the scan container as environment variables — because a scan profile (and
 * the whole Project row) is spread verbatim into `project.json` in the
 * downloadable export zip.
 */

export type TrufflehogFieldType =
  | 'text' | 'multi' | 'csv' | 'pathfile' | 'toggle'
  | 'number' | 'select' | 'bytes' | 'textarea'

export interface TrufflehogField {
  key: string
  type: TrufflehogFieldType
  label: string
  /** Required to start. Cross-field requirements ("one of repos/orgs") live in
   *  validateTrufflehogConfig, not here. */
  required?: boolean
  hint?: string
  /** Rendered disabled unless this other field has a value (org-only options). */
  requires?: string
  options?: { value: string; label: string }[]
  /** Consumed by the scanner's own runner, never passed to TruffleHog (the
   *  docker tag/architecture expansion, the Hugging Face mode selector). */
  client?: boolean
}

export interface TrufflehogCredential {
  /** UserSettings column the value is read from. */
  settingsKey: string
  /** Human name, used verbatim in the "set the key" alert. */
  label: string
  /** Part of a multi-key source and never individually mandatory. */
  optional?: boolean
}

export interface TrufflehogSource {
  id: string
  label: string
  /** Graph label its assets get; drives the node colour on /graph. */
  assetLabel: string
  assetKind: 'repository' | 'image' | 'model' | 'bucket' | 'endpoint'
  description: string
  fields: TrufflehogField[]
  credentials: TrufflehogCredential[]
}

const CRED = {
  github: { settingsKey: 'trufflehogGithubToken', label: 'TruffleHog GitHub Token' },
  gitlab: { settingsKey: 'trufflehogGitlabToken', label: 'TruffleHog GitLab Token' },
  docker: { settingsKey: 'trufflehogDockerToken', label: 'TruffleHog Docker Token' },
  huggingface: { settingsKey: 'trufflehogHuggingfaceToken', label: 'TruffleHog Hugging Face Token' },
  postman: { settingsKey: 'trufflehogPostmanToken', label: 'TruffleHog Postman Token' },
  circleci: { settingsKey: 'trufflehogCircleciToken', label: 'TruffleHog CircleCI Token' },
  travisci: { settingsKey: 'trufflehogTravisciToken', label: 'TruffleHog Travis CI Token' },
  awsKey: { settingsKey: 'trufflehogAwsAccessKeyId', label: 'TruffleHog AWS Access Key ID' },
  awsSecret: { settingsKey: 'trufflehogAwsSecretKey', label: 'TruffleHog AWS Secret Key' },
  awsSession: { settingsKey: 'trufflehogAwsSessionToken', label: 'TruffleHog AWS Session Token', optional: true },
  gcp: { settingsKey: 'trufflehogGcpServiceAccount', label: 'TruffleHog GCP Service Account' },
  jenkinsUser: { settingsKey: 'trufflehogJenkinsUsername', label: 'TruffleHog Jenkins Username', optional: true },
  jenkinsPass: { settingsKey: 'trufflehogJenkinsPassword', label: 'TruffleHog Jenkins Password', optional: true },
  esUser: { settingsKey: 'trufflehogElasticUsername', label: 'TruffleHog Elasticsearch Username', optional: true },
  esPass: { settingsKey: 'trufflehogElasticPassword', label: 'TruffleHog Elasticsearch Password', optional: true },
  esApiKey: { settingsKey: 'trufflehogElasticApiKey', label: 'TruffleHog Elasticsearch API Key', optional: true },
  esServiceToken: { settingsKey: 'trufflehogElasticServiceToken', label: 'TruffleHog Elasticsearch Service Token', optional: true },
  gitUser: { settingsKey: 'trufflehogGitUsername', label: 'TruffleHog Git Username', optional: true },
  gitToken: { settingsKey: 'trufflehogGitToken', label: 'TruffleHog Git Token', optional: true },
} as const

/** Allowlisted filesystem scan roots. Never a free-text host path: a typed path
 *  plus a scan container is a file-disclosure primitive. */
export const TRUFFLEHOG_FILESYSTEM_ROOTS = [
  { value: 'recon_output', label: 'Recon output' },
  { value: 'capture_spool', label: 'Capture proxy spool' },
  { value: 'supply_chain_uploads', label: 'Supply-chain uploads' },
]

export const TRUFFLEHOG_SOURCES: Record<string, TrufflehogSource> = {
  git: {
    id: 'git', label: 'Git repository', assetLabel: 'TrufflehogRepository', assetKind: 'repository',
    description: 'Any Git host over https://, ssh:// or file://.',
    credentials: [CRED.gitUser, CRED.gitToken],
    fields: [
      { key: 'uri', type: 'text', label: 'Repository URI', required: true, hint: 'https://, ssh:// or file://' },
      { key: 'branch', type: 'text', label: 'Branch', hint: 'Default: all branches' },
      { key: 'sinceCommit', type: 'text', label: 'Since commit', hint: 'Scan forward from this SHA' },
      { key: 'maxDepth', type: 'number', label: 'Max commit depth' },
      { key: 'bare', type: 'toggle', label: 'Bare repository' },
      { key: 'includePaths', type: 'pathfile', label: 'Include paths', hint: 'One regex per line' },
      { key: 'excludePaths', type: 'pathfile', label: 'Exclude paths', hint: 'One regex per line' },
      { key: 'excludeGlobs', type: 'csv', label: 'Exclude globs', hint: 'Filters at git-log level; faster than exclude paths' },
    ],
  },
  github: {
    id: 'github', label: 'GitHub', assetLabel: 'TrufflehogRepository', assetKind: 'repository',
    description: 'Repositories, organizations, wikis, gists and issue/PR comments.',
    credentials: [CRED.github],
    fields: [
      { key: 'endpoint', type: 'text', label: 'Endpoint', hint: 'Default https://api.github.com; set for GitHub Enterprise' },
      { key: 'repos', type: 'multi', label: 'Repositories', hint: 'Full URL or org/repo' },
      { key: 'orgs', type: 'multi', label: 'Organizations' },
      { key: 'includeRepos', type: 'multi', label: 'Include repos', hint: 'Glob, org scans only', requires: 'orgs' },
      { key: 'excludeRepos', type: 'multi', label: 'Exclude repos', hint: 'Glob, org scans only', requires: 'orgs' },
      { key: 'includeForks', type: 'toggle', label: 'Include forks' },
      { key: 'includeMembers', type: 'toggle', label: 'Include member repos', requires: 'orgs' },
      { key: 'includeWikis', type: 'toggle', label: 'Include wikis' },
      { key: 'excludeArchived', type: 'toggle', label: 'Exclude archived' },
      { key: 'ignoreGists', type: 'toggle', label: 'Ignore gists' },
      { key: 'issueComments', type: 'toggle', label: 'Scan issue comments' },
      { key: 'prComments', type: 'toggle', label: 'Scan PR comments' },
      { key: 'gistComments', type: 'toggle', label: 'Scan gist comments' },
      { key: 'commentsTimeframe', type: 'number', label: 'Comments timeframe (days)', hint: 'Only meaningful with a comments toggle on' },
      { key: 'includePaths', type: 'pathfile', label: 'Include paths' },
      { key: 'excludePaths', type: 'pathfile', label: 'Exclude paths' },
    ],
  },
  github_experimental: {
    id: 'github_experimental', label: 'GitHub deleted commits',
    assetLabel: 'TrufflehogRepository', assetKind: 'repository',
    description: 'Finds secrets in force-pushed and deleted commits. Far slower, and its findings have no live file path.',
    credentials: [CRED.github],
    fields: [
      { key: 'repo', type: 'text', label: 'Repository', required: true, hint: 'A single repo, not an org' },
      { key: 'collisionThreshold', type: 'number', label: 'Collision threshold', hint: 'Default 1; raise to widen the short-SHA search' },
      { key: 'deleteCachedData', type: 'toggle', label: 'Delete cached data', hint: 'Recommended: it caches repo objects to disk' },
    ],
  },
  gitlab: {
    id: 'gitlab', label: 'GitLab', assetLabel: 'TrufflehogRepository', assetKind: 'repository',
    description: 'GitLab.com or a self-hosted instance.',
    credentials: [CRED.gitlab],
    fields: [
      { key: 'endpoint', type: 'text', label: 'Endpoint', hint: 'Default https://gitlab.com; set for self-hosted' },
      { key: 'repos', type: 'multi', label: 'Repositories', hint: 'Empty scans every project the token can reach' },
      { key: 'groupIds', type: 'multi', label: 'Group IDs', hint: 'Includes subgroups' },
      { key: 'includeRepos', type: 'multi', label: 'Include repos', hint: 'Glob' },
      { key: 'excludeRepos', type: 'multi', label: 'Exclude repos', hint: 'Glob' },
      { key: 'includePaths', type: 'pathfile', label: 'Include paths' },
      { key: 'excludePaths', type: 'pathfile', label: 'Exclude paths' },
    ],
  },
  docker: {
    id: 'docker', label: 'Docker registry', assetLabel: 'TrufflehogImage', assetKind: 'image',
    description: 'Docker Hub or any OCI registry. Scans image layers and the build history baked into RUN/ENV directives.',
    credentials: [CRED.docker],
    fields: [
      { key: 'images', type: 'multi', label: 'Images', hint: 'nginx:1.25, ghcr.io/org/app@sha256:... — bare references only' },
      { key: 'namespace', type: 'text', label: 'Namespace', hint: 'acme; include the host for other registries, e.g. ghcr.io/acme' },
      // csv here, a file everywhere else — the same flag name takes incompatible input per source.
      { key: 'excludePaths', type: 'csv', label: 'Exclude paths', hint: 'Comma-separated, e.g. /usr/share,/var/lib/apt' },
      { key: 'maxImages', type: 'number', client: true, label: 'Max images', hint: 'Ceiling when expanding a namespace or tag list' },
      { key: 'scanAllTags', type: 'toggle', client: true, label: 'Scan all tags', hint: 'Multiplies pull count; Docker Hub allows 10 anonymous pulls/hour per IP' },
      { key: 'scanAllArchitectures', type: 'toggle', client: true, label: 'Scan all architectures', hint: 'Each architecture can hold different secrets. Multiplies pull count again' },
      { key: 'includePrivate', type: 'toggle', label: 'Include private images', hint: 'Sends the registry token; needs a Docker token' },
    ],
  },
  huggingface: {
    id: 'huggingface', label: 'Hugging Face', assetLabel: 'TrufflehogModel', assetKind: 'model',
    description: 'Models, spaces and datasets — either named assets or a whole org/user sweep.',
    credentials: [CRED.huggingface],
    fields: [
      { key: 'mode', type: 'select', label: 'Mode', client: true, options: [
        { value: 'assets', label: 'Specific assets' },
        { value: 'sweep', label: 'Organization / user sweep' },
      ] },
      { key: 'endpoint', type: 'text', label: 'Endpoint', hint: 'Default https://huggingface.co' },
      { key: 'models', type: 'multi', label: 'Models' },
      { key: 'spaces', type: 'multi', label: 'Spaces' },
      { key: 'datasets', type: 'multi', label: 'Datasets' },
      { key: 'buckets', type: 'multi', label: 'Buckets' },
      { key: 'orgs', type: 'multi', label: 'Organizations' },
      { key: 'users', type: 'multi', label: 'Users' },
      { key: 'skipAllModels', type: 'toggle', label: 'Skip all models', requires: 'sweep' },
      { key: 'skipAllSpaces', type: 'toggle', label: 'Skip all spaces', requires: 'sweep' },
      { key: 'skipAllDatasets', type: 'toggle', label: 'Skip all datasets', requires: 'sweep' },
      { key: 'skipAllBuckets', type: 'toggle', label: 'Skip all buckets', requires: 'sweep' },
      { key: 'includeModels', type: 'multi', label: 'Include models', requires: 'sweep' },
      { key: 'includeSpaces', type: 'multi', label: 'Include spaces', requires: 'sweep' },
      { key: 'includeDatasets', type: 'multi', label: 'Include datasets', requires: 'sweep' },
      { key: 'includeBuckets', type: 'multi', label: 'Include buckets', requires: 'sweep' },
      { key: 'ignoreModels', type: 'multi', label: 'Ignore models', requires: 'sweep' },
      { key: 'ignoreSpaces', type: 'multi', label: 'Ignore spaces', requires: 'sweep' },
      { key: 'ignoreDatasets', type: 'multi', label: 'Ignore datasets', requires: 'sweep' },
      { key: 'ignoreBuckets', type: 'multi', label: 'Ignore buckets', requires: 'sweep' },
      { key: 'includeDiscussions', type: 'toggle', label: 'Include discussions' },
      { key: 'includePrs', type: 'toggle', label: 'Include PRs' },
    ],
  },
  s3: {
    id: 's3', label: 'AWS S3', assetLabel: 'TrufflehogBucket', assetKind: 'bucket',
    description: 'S3 buckets, optionally across assumed roles.',
    credentials: [CRED.awsKey, CRED.awsSecret, CRED.awsSession],
    fields: [
      { key: 'buckets', type: 'multi', label: 'Buckets', hint: 'Cannot be combined with Ignore buckets' },
      { key: 'ignoreBuckets', type: 'multi', label: 'Ignore buckets', hint: 'Cannot be combined with Buckets' },
      { key: 'roleArns', type: 'multi', label: 'Role ARNs', hint: 'Assume-role per ARN' },
      { key: 'cloudEnvironment', type: 'toggle', label: 'Use cloud environment IAM', hint: 'Instance-profile credentials; no key needed' },
      { key: 'maxObjectSize', type: 'bytes', label: 'Max object size', hint: 'Default 250MB' },
    ],
  },
  gcs: {
    id: 'gcs', label: 'Google Cloud Storage', assetLabel: 'TrufflehogBucket', assetKind: 'bucket',
    description: 'GCS buckets, authenticated or public-only.',
    credentials: [CRED.gcp],
    fields: [
      { key: 'projectId', type: 'text', label: 'Project ID', hint: 'Cannot be combined with Without auth' },
      { key: 'withoutAuth', type: 'toggle', label: 'Without auth', hint: 'Public buckets only' },
      { key: 'cloudEnvironment', type: 'toggle', label: 'Use cloud environment ADC' },
      { key: 'includeBuckets', type: 'multi', label: 'Include buckets', hint: 'Globs supported' },
      { key: 'excludeBuckets', type: 'multi', label: 'Exclude buckets', hint: 'Globs supported' },
      { key: 'includeObjects', type: 'multi', label: 'Include objects', hint: 'Globs supported' },
      { key: 'excludeObjects', type: 'multi', label: 'Exclude objects', hint: 'Globs supported' },
      { key: 'maxObjectSize', type: 'bytes', label: 'Max object size', hint: 'Default 10MB' },
    ],
  },
  filesystem: {
    id: 'filesystem', label: 'Filesystem', assetLabel: 'TrufflehogEndpoint', assetKind: 'endpoint',
    description: 'Scans a RedAmon-owned artifact directory. No credential, and no free-text paths.',
    credentials: [],
    fields: [
      { key: 'scanRoot', type: 'select', label: 'Scan root', required: true, options: TRUFFLEHOG_FILESYSTEM_ROOTS },
      { key: 'includePaths', type: 'pathfile', label: 'Include paths' },
      { key: 'excludePaths', type: 'pathfile', label: 'Exclude paths' },
      { key: 'maxSymlinkDepth', type: 'number', label: 'Max symlink depth' },
    ],
  },
  jenkins: {
    id: 'jenkins', label: 'Jenkins', assetLabel: 'TrufflehogEndpoint', assetKind: 'endpoint',
    description: 'A Jenkins instance. An exposed unauthenticated one scans without a credential — and is itself a finding.',
    credentials: [CRED.jenkinsUser, CRED.jenkinsPass],
    fields: [
      { key: 'url', type: 'text', label: 'Jenkins URL', required: true },
      { key: 'insecureSkipVerifyTls', type: 'toggle', label: 'Skip TLS verification', hint: 'For self-signed internal instances' },
    ],
  },
  elasticsearch: {
    id: 'elasticsearch', label: 'Elasticsearch', assetLabel: 'TrufflehogEndpoint', assetKind: 'endpoint',
    description: 'An Elasticsearch cluster. If secured, set exactly ONE of username+password, API key, or service token.',
    credentials: [CRED.esUser, CRED.esPass, CRED.esApiKey, CRED.esServiceToken],
    fields: [
      { key: 'nodes', type: 'multi', label: 'Nodes', hint: 'e.g. 192.168.14.3:9200' },
      { key: 'cloudId', type: 'text', label: 'Cloud ID', hint: 'Elastic Cloud' },
      { key: 'indexPattern', type: 'text', label: 'Index pattern', hint: 'Default *' },
      { key: 'queryJson', type: 'textarea', label: 'Query JSON', hint: 'Document filter' },
      { key: 'sinceTimestamp', type: 'text', label: 'Since timestamp', hint: 'Overrides any timestamp in Query JSON' },
    ],
  },
  postman: {
    id: 'postman', label: 'Postman', assetLabel: 'TrufflehogEndpoint', assetKind: 'endpoint',
    description: 'Postman workspaces, collections and environments.',
    credentials: [CRED.postman],
    fields: [
      { key: 'workspaceIds', type: 'multi', label: 'Workspace IDs' },
      { key: 'collectionIds', type: 'multi', label: 'Collection IDs' },
      { key: 'environments', type: 'multi', label: 'Environments' },
      { key: 'includeCollectionIds', type: 'multi', label: 'Include collection IDs' },
      { key: 'excludeCollectionIds', type: 'multi', label: 'Exclude collection IDs' },
      { key: 'includeEnvironments', type: 'multi', label: 'Include environments' },
      { key: 'excludeEnvironments', type: 'multi', label: 'Exclude environments' },
    ],
  },
  circleci: {
    id: 'circleci', label: 'CircleCI', assetLabel: 'TrufflehogEndpoint', assetKind: 'endpoint',
    description: 'The token defines the scan scope; there is nothing else to configure.',
    credentials: [CRED.circleci],
    fields: [],
  },
  travisci: {
    id: 'travisci', label: 'Travis CI', assetLabel: 'TrufflehogEndpoint', assetKind: 'endpoint',
    description: 'The token defines the scan scope; there is nothing else to configure.',
    credentials: [CRED.travisci],
    fields: [],
  },
}

export const TRUFFLEHOG_SOURCE_IDS = Object.keys(TRUFFLEHOG_SOURCES)

/** Normalises the dash spelling the CLI uses (github-experimental). */
export function getTrufflehogSource(id: string): TrufflehogSource | undefined {
  return TRUFFLEHOG_SOURCES[(id || '').trim().toLowerCase().replace(/-/g, '_')]
}

const asList = (v: unknown): string[] => {
  if (v == null) return []
  if (Array.isArray(v)) return v.map(x => String(x).trim()).filter(Boolean)
  return String(v).split(',').map(x => x.trim()).filter(Boolean)
}
const asBool = (v: unknown): boolean =>
  typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(String(v ?? '').toLowerCase())
const asText = (v: unknown): string => (v == null ? '' : String(v).trim())

/**
 * Cross-field validation. Mirrors validate_config() in sources.py; the server
 * re-runs the Python side at start, so this is the fast feedback path, never the
 * only gate.
 */
export function validateTrufflehogConfig(sourceId: string, config: Record<string, unknown>): string[] {
  const src = getTrufflehogSource(sourceId)
  if (!src) return [`Unknown TruffleHog source: ${sourceId}`]
  const cfg = config || {}
  const errors: string[] = []

  for (const f of src.fields) {
    if (f.required && !asText(cfg[f.key]) && asList(cfg[f.key]).length === 0) {
      errors.push(`${src.label}: '${f.label}' is required`)
    }
  }

  switch (src.id) {
    case 'github':
      if (!asList(cfg.repos).length && !asList(cfg.orgs).length) {
        errors.push('GitHub: set at least one repository or organization')
      }
      if (!asList(cfg.orgs).length) {
        for (const key of ['includeRepos', 'excludeRepos', 'includeMembers'] as const) {
          if (asList(cfg[key]).length || asBool(cfg[key])) {
            errors.push(`GitHub: '${key}' only applies to organization scans`)
          }
        }
      }
      break
    case 'docker': {
      const images = asList(cfg.images)
      if (!images.length && !asText(cfg.namespace)) {
        errors.push('Docker: set at least one image or a namespace')
      }
      for (const image of images) {
        if (image.includes('://')) {
          // docker:// needs the Docker socket, which a scan container never
          // gets; file:// reads the container's own filesystem.
          errors.push(`Docker: '${image}' must be a bare registry reference`)
        } else if (!/^[A-Za-z0-9][A-Za-z0-9._\-/]*(:[A-Za-z0-9._-]+)?(@sha256:[a-f0-9]{64})?$/.test(image)) {
          errors.push(`Docker: '${image}' is not a valid image reference`)
        }
      }
      break
    }
    case 'huggingface': {
      const mode = asText(cfg.mode) || 'assets'
      if (mode === 'assets') {
        if (!['models', 'spaces', 'datasets', 'buckets'].some(k => asList(cfg[k]).length)) {
          errors.push('Hugging Face: set at least one model, space, dataset or bucket')
        }
      } else if (!asList(cfg.orgs).length && !asList(cfg.users).length) {
        errors.push('Hugging Face: sweep mode needs an organization or a user')
      }
      break
    }
    case 's3':
      if (asList(cfg.buckets).length && asList(cfg.ignoreBuckets).length) {
        errors.push("S3: 'Buckets' and 'Ignore buckets' are mutually exclusive")
      }
      break
    case 'gcs':
      if (asText(cfg.projectId) && asBool(cfg.withoutAuth)) {
        errors.push("GCS: 'Project ID' cannot be combined with 'Without auth'")
      }
      if (!asText(cfg.projectId) && !asBool(cfg.withoutAuth)) {
        errors.push("GCS: set a Project ID or enable 'Without auth'")
      }
      break
    case 'filesystem':
      if (asText(cfg.scanRoot) && !TRUFFLEHOG_FILESYSTEM_ROOTS.some(r => r.value === cfg.scanRoot)) {
        errors.push(`Filesystem: '${asText(cfg.scanRoot)}' is not an allowed scan root`)
      }
      break
    case 'elasticsearch':
      if (!asList(cfg.nodes).length && !asText(cfg.cloudId)) {
        errors.push('Elasticsearch: set at least one node or a Cloud ID')
      }
      break
    case 'postman':
      if (!['workspaceIds', 'collectionIds', 'environments'].some(k => asList(cfg[k]).length)) {
        errors.push('Postman: set at least one workspace, collection or environment')
      }
      break
    case 'git': {
      const uri = asText(cfg.uri)
      if (uri && !/^(https?|ssh|git|file):\/\//.test(uri)) {
        errors.push(`Git: '${uri}' must be an https://, ssh:// or file:// URI`)
      }
      break
    }
    case 'jenkins': {
      const url = asText(cfg.url)
      if (url && !/^https?:\/\//.test(url)) {
        errors.push('Jenkins: URL must be http:// or https://')
      }
      break
    }
  }

  return errors
}

/**
 * Whether a credential is mandatory for this source WITH THIS CONFIG.
 *
 * Not static per source: a single public Docker image scans anonymously, a
 * namespace scan does not (10 anonymous pulls/hour per IP exhausts instantly).
 * Mirrors credential_required() in sources.py.
 */
export function trufflehogCredentialRequired(sourceId: string, config: Record<string, unknown>): boolean {
  const src = getTrufflehogSource(sourceId)
  if (!src) return false
  const cfg = config || {}
  if (['github', 'github_experimental', 'gitlab', 'postman', 'circleci', 'travisci'].includes(src.id)) return true
  if (src.id === 'docker') return Boolean(asText(cfg.namespace)) || asBool(cfg.includePrivate)
  if (src.id === 's3') return !asBool(cfg.cloudEnvironment)
  if (src.id === 'gcs') return !(asBool(cfg.withoutAuth) || asBool(cfg.cloudEnvironment))
  // Best effort: a private SSH URL needs a key, a public HTTPS one does not.
  if (src.id === 'git') return asText(cfg.uri).startsWith('ssh://')
  // jenkins / elasticsearch / huggingface / filesystem: unauthenticated access
  // works, and for the first two it is itself a finding.
  return false
}

/**
 * Which mandatory credentials are missing. Drives the disabled Start button and
 * the inline "set the key" warning; the orchestrator re-checks server-side, so
 * a queued job whose key was cleared meanwhile still fails closed.
 */
export function resolveMissingCredentials(
  sourceId: string,
  config: Record<string, unknown>,
  settings: Record<string, unknown> | null | undefined,
): TrufflehogCredential[] {
  if (!trufflehogCredentialRequired(sourceId, config)) return []
  const src = getTrufflehogSource(sourceId)
  if (!src) return []
  return src.credentials
    .filter(c => !c.optional)
    .filter(c => !asText((settings || {})[c.settingsKey]))
}

/** Every UserSettings column this feature reads. Used by the start route to
 *  select only the fields it needs, and by the settings page to render them. */
export const TRUFFLEHOG_CREDENTIAL_FIELDS: string[] = Array.from(
  new Set(Object.values(TRUFFLEHOG_SOURCES).flatMap(s => s.credentials.map(c => c.settingsKey))),
)

/** A short human descriptor of what a profile scans; shown on the scan card. */
export function describeTrufflehogTarget(sourceId: string, config: Record<string, unknown>): string {
  const cfg = config || {}
  switch (getTrufflehogSource(sourceId)?.id) {
    case 'git': return asText(cfg.uri).replace(/\/\/[^/@]+@/, '//')
    case 'github': return [...asList(cfg.orgs), ...asList(cfg.repos)].join(', ')
    case 'github_experimental': return asText(cfg.repo)
    case 'gitlab': return [...asList(cfg.repos), ...asList(cfg.groupIds).map(g => `group:${g}`)].join(', ')
      || asText(cfg.endpoint) || 'gitlab.com (all visible)'
    case 'docker': return asList(cfg.images).join(', ') || asText(cfg.namespace)
    case 'huggingface': return [...asList(cfg.orgs), ...asList(cfg.users), ...asList(cfg.models),
      ...asList(cfg.spaces), ...asList(cfg.datasets), ...asList(cfg.buckets)].join(', ')
    case 's3': return asList(cfg.buckets).join(', ') || 'all reachable buckets'
    case 'gcs': return asText(cfg.projectId) || 'public buckets'
    case 'filesystem': return asText(cfg.scanRoot)
    case 'jenkins': return asText(cfg.url)
    case 'elasticsearch': return asList(cfg.nodes).join(', ') || asText(cfg.cloudId)
    case 'postman': return [...asList(cfg.workspaceIds), ...asList(cfg.collectionIds),
      ...asList(cfg.environments)].join(', ')
    default: return getTrufflehogSource(sourceId)?.label ?? sourceId
  }
}
