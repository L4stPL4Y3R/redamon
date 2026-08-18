/**
 * The catalogue of scanner credentials that live in Global Settings.
 *
 * These fields are rendered in two very different places: the canonical API Keys
 * tab, and the inline "shortcut" input each scan section shows when its key is
 * missing. Both read from here, so a key cannot acquire one label in Settings
 * and a different one on the scan card, and a key added to a source registry
 * without a description here fails a parity test rather than rendering blank.
 *
 * Every `name` is a UserSettings column and MUST also appear in the writable
 * `fields` list in api/users/[id]/settings/route.ts. A name missing there is
 * accepted by the form and silently never persisted.
 */

export interface CredentialField {
  /** The UserSettings column, camelCase. */
  name: string
  label: string
  hint: string
  signupUrl?: string
  /**
   * Masked on read and rendered behind a reveal toggle. False for plain
   * configuration values (a hostname) that are not credentials.
   */
  secret?: boolean
}

/** TruffleHog's per-source keys. `source` is the source id it belongs to. */
export const TRUFFLEHOG_KEY_FIELDS: (CredentialField & { source: string })[] = [
  {
    name: 'trufflehogGithubToken', label: 'Secret Multiscanner GitHub Token', source: 'github',
    signupUrl: 'https://github.com/settings/tokens',
    hint: 'Mandatory for the GitHub and GitHub-deleted-commits sources — even for public repos, because unauthenticated GitHub allows only 60 requests/hour, which this scan exhausts immediately. Use repo scope for private repositories.',
  },
  {
    name: 'trufflehogGitlabToken', label: 'Secret Multiscanner GitLab Token', source: 'gitlab',
    signupUrl: 'https://gitlab.com/-/user_settings/personal_access_tokens',
    hint: 'Mandatory for the GitLab source. With no repository or group set, it scans every project the token can reach.',
  },
  {
    name: 'trufflehogPostmanToken', label: 'Secret Multiscanner Postman Token', source: 'postman',
    hint: 'Mandatory for the Postman source.',
  },
  {
    name: 'trufflehogCircleciToken', label: 'Secret Multiscanner CircleCI Token', source: 'circleci',
    hint: 'Mandatory for the CircleCI source; the token defines the scan scope.',
  },
  {
    name: 'trufflehogTravisciToken', label: 'Secret Multiscanner Travis CI Token', source: 'travisci',
    hint: 'Mandatory for the Travis CI source; the token defines the scan scope.',
  },
  {
    name: 'trufflehogDockerToken', label: 'Secret Multiscanner Docker Token', source: 'docker',
    signupUrl: 'https://app.docker.com/settings/personal-access-tokens',
    hint: 'Optional for a single public image. Mandatory for a namespace scan: Docker Hub allows only 10 anonymous pulls/hour per IP, which a namespace scan exhausts at once. Used as both the bearer and the registry token.',
  },
  {
    name: 'trufflehogAwsAccessKeyId', label: 'Secret Multiscanner AWS Access Key ID', source: 's3',
    hint: "Mandatory for the S3 source unless 'Use cloud environment IAM' is enabled on the scan.",
  },
  {
    name: 'trufflehogAwsSecretKey', label: 'Secret Multiscanner AWS Secret Key', source: 's3',
    hint: "Mandatory for the S3 source unless 'Use cloud environment IAM' is enabled on the scan.",
  },
  {
    name: 'trufflehogAwsSessionToken', label: 'Secret Multiscanner AWS Session Token', source: 's3',
    hint: 'Optional. Only for temporary (STS) credentials.',
  },
  {
    name: 'trufflehogGcpServiceAccount', label: 'Secret Multiscanner GCP Service Account (JSON)', source: 'gcs',
    hint: "Mandatory for the GCS source unless 'Without auth' (public buckets) is enabled. Paste the service-account JSON.",
  },
  {
    name: 'trufflehogHuggingfaceToken', label: 'Secret Multiscanner Hugging Face Token', source: 'huggingface',
    signupUrl: 'https://huggingface.co/settings/tokens',
    hint: 'Optional. Public models, spaces and datasets scan without it; set it for private or gated assets, or for higher rate limits.',
  },
  {
    name: 'trufflehogJenkinsUsername', label: 'Secret Multiscanner Jenkins Username', source: 'jenkins',
    hint: 'Optional. An exposed, unauthenticated Jenkins scans without it (and is itself a finding). Set both username and password for an instance behind a login.',
  },
  {
    name: 'trufflehogJenkinsPassword', label: 'Secret Multiscanner Jenkins Password', source: 'jenkins',
    hint: 'Optional. Pairs with the Jenkins username above.',
  },
  {
    name: 'trufflehogElasticUsername', label: 'Secret Multiscanner Elasticsearch Username', source: 'elasticsearch',
    hint: 'Optional. An exposed cluster scans without it. If secured, provide exactly ONE of: username+password, API key, or service token.',
  },
  {
    name: 'trufflehogElasticPassword', label: 'Secret Multiscanner Elasticsearch Password', source: 'elasticsearch',
    hint: 'Optional. Pairs with the Elasticsearch username above.',
  },
  {
    name: 'trufflehogElasticApiKey', label: 'Secret Multiscanner Elasticsearch API Key', source: 'elasticsearch',
    hint: 'Optional. Use INSTEAD of username+password or a service token, not alongside them.',
  },
  {
    name: 'trufflehogElasticServiceToken', label: 'Secret Multiscanner Elasticsearch Service Token', source: 'elasticsearch',
    hint: 'Optional. Use INSTEAD of username+password or an API key, not alongside them.',
  },
  {
    name: 'trufflehogGitUsername', label: 'Secret Multiscanner Git Username', source: 'git',
    hint: 'Optional. Public Git URLs clone anonymously. Set both username and token only to reach a private repository over HTTPS.',
  },
  {
    name: 'trufflehogGitToken', label: 'Secret Multiscanner Git Token', source: 'git',
    hint: 'Optional. Pairs with the Git username above.',
  },
]

/** GitHub Secret Hunt and Supply Chain share these; TruffleHog deliberately does not. */
export const SHARED_SCANNER_KEY_FIELDS: CredentialField[] = [
  {
    name: 'githubAccessToken', label: 'GitHub Access Token',
    signupUrl: 'https://github.com/settings/tokens',
    hint: 'Required for GitHub Secret Hunt, and for Supply Chain scans of a private repository (public repos clone anonymously). Use repo scope for private repos, or a fine-grained token for specific repos only. NOT used by Secret Multiscanner — it has its own GitHub token.',
  },
  {
    name: 'githubEnterpriseHost', label: 'GitHub Enterprise Host', secret: false,
    hint: 'Optional. A self-hosted or custom-domain GitHub Enterprise server, hostname only (no https://, port or path). This is also the allowlist: a Supply Chain target may name this host and github.com, nothing else.',
  },
  {
    name: 'githubEnterpriseToken', label: 'GitHub Enterprise Token',
    hint: 'The PAT for the GitHub Enterprise Host. Kept separate from the GitHub Access Token on purpose: an Enterprise credential is never sent to github.com, and vice versa.',
  },
]

const ALL_FIELDS: CredentialField[] = [...TRUFFLEHOG_KEY_FIELDS, ...SHARED_SCANNER_KEY_FIELDS]

const BY_NAME: Record<string, CredentialField> = Object.fromEntries(
  ALL_FIELDS.map(f => [f.name, f]),
)

/** Every credential this app can prompt for inline. */
export const CREDENTIAL_FIELD_NAMES = ALL_FIELDS.map(f => f.name)

/**
 * Look a credential up by its UserSettings column. Returns undefined for an
 * unknown key so a caller can decide between rendering nothing and throwing;
 * the parity test is what makes an unknown key a build-time problem instead.
 */
export function credentialField(name: string): CredentialField | undefined {
  return BY_NAME[name]
}

/** A field is a masked secret unless it explicitly opts out. */
export function isSecretField(name: string): boolean {
  return credentialField(name)?.secret !== false
}
