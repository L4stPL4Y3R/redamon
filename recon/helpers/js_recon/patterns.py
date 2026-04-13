"""
JS Recon Secret Detection Patterns

90+ hardcoded regex patterns for detecting secrets, credentials, tokens,
infrastructure URLs, and sensitive information in JavaScript files.

Superset of github_secret_hunt SECRET_PATTERNS with 30+ JS-specific additions.
"""

import re
import json
import math
import hashlib
from typing import Optional


# Each pattern: name, regex (raw string), severity, confidence, category, validator_ref (optional)
_RAW_PATTERNS = [
    # ========== CLOUD CREDENTIALS (Critical) ==========
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "critical", "high", "cloud", "validate_aws"),
    ("AWS Secret Key", r"(?i)aws(?:_secret|_key|secret_key|_access).{0,10}['\"][0-9a-zA-Z/+]{40}['\"]", "critical", "high", "cloud", "validate_aws"),
    ("AWS MWS Key", r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "critical", "high", "cloud", None),
    ("GCP API Key", r"AIza[0-9A-Za-z\-_]{35}", "critical", "high", "cloud", "validate_google_maps"),
    ("GCP OAuth Client", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "high", "high", "cloud", None),
    ("GCP Service Account", r"\"type\":\s*\"service_account\"", "critical", "high", "cloud", None),
    ("Firebase URL", r"https://[a-z0-9-]+\.firebaseio\.com", "high", "high", "cloud", "validate_firebase"),
    ("Firebase API Key", r"(?i)firebase[^\"']{0,50}['\"][A-Za-z0-9_]{30,}['\"]", "high", "medium", "cloud", None),
    ("Firebase Storage", r"https://[a-z0-9-]+\.firebasestorage\.app", "medium", "high", "cloud", None),
    ("Azure Storage Key", r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "critical", "high", "cloud", None),
    ("Azure Connection String", r"(?i)(AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{40,}", "critical", "high", "cloud", None),
    ("Azure SAS Token", r"(?i)[?&]sig=[A-Za-z0-9%]{40,}", "high", "medium", "cloud", None),
    ("Azure AD Client Secret", r"(?i)azure.*client.?secret.*['\"][a-zA-Z0-9~._-]{34,}['\"]", "critical", "high", "cloud", None),
    ("DigitalOcean Token", r"dop_v1_[a-f0-9]{64}", "critical", "high", "cloud", "validate_digitalocean"),
    ("DigitalOcean OAuth", r"doo_v1_[a-f0-9]{64}", "critical", "high", "cloud", None),
    ("Cloudflare API Key", r"(?i)cloudflare.*['\"][a-z0-9]{37}['\"]", "high", "medium", "cloud", "validate_cloudflare"),
    ("Cloudflare API Token", r"(?i)cloudflare.*['\"][A-Za-z0-9_-]{40}['\"]", "high", "medium", "cloud", "validate_cloudflare"),

    # ========== PAYMENT / FINANCIAL (Critical) ==========
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24,}", "critical", "high", "payment", "validate_stripe"),
    ("Stripe Test Key", r"sk_test_[0-9a-zA-Z]{24,}", "medium", "high", "payment", None),
    ("Stripe Restricted Key", r"rk_live_[0-9a-zA-Z]{24,}", "critical", "high", "payment", None),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24,}", "low", "high", "payment", None),
    ("PayPal Client ID", r"(?i)paypal.*client[_-]?id.*['\"][A-Za-z0-9-]{20,}['\"]", "high", "medium", "payment", None),
    ("Square Access Token", r"sq0atp-[0-9A-Za-z\-_]{22}", "critical", "high", "payment", None),
    ("Square OAuth Secret", r"sq0csp-[0-9A-Za-z\-_]{43}", "critical", "high", "payment", None),
    ("Razorpay Key", r"rzp_(live|test)_[a-zA-Z0-9]{14}", "high", "high", "payment", None),

    # ========== AUTHENTICATION TOKENS (High) ==========
    ("GitHub Token Classic", r"ghp_[0-9a-zA-Z]{36}", "high", "high", "auth", "validate_github"),
    ("GitHub Fine-grained Token", r"github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}", "high", "high", "auth", "validate_github"),
    ("GitHub OAuth Token", r"gho_[0-9a-zA-Z]{36}", "high", "high", "auth", "validate_github"),
    ("GitHub App Token", r"(?:ghu|ghs)_[0-9a-zA-Z]{36}", "high", "high", "auth", "validate_github"),
    ("GitHub Refresh Token", r"ghr_[0-9a-zA-Z]{36}", "high", "high", "auth", None),
    ("GitLab Token", r"glpat-[0-9a-zA-Z\-_]{20}", "high", "high", "auth", "validate_gitlab"),
    ("GitLab Runner Token", r"GR1348941[0-9a-zA-Z\-_]{20}", "high", "high", "auth", None),
    ("Slack Token", r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", "high", "high", "auth", "validate_slack"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "high", "high", "auth", None),
    ("Discord Bot Token", r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", "high", "high", "auth", "validate_discord"),
    ("Discord Webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "high", "high", "auth", None),
    ("Twilio API Key", r"\bSK[0-9a-fA-F]{32}\b", "high", "high", "auth", "validate_twilio"),
    ("Twilio Account SID", r"\bAC[0-9a-f]{32}\b", "medium", "high", "auth", "validate_twilio_format"),
    ("SendGrid API Key", r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9\-_]{43}", "high", "high", "auth", "validate_sendgrid"),
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", "high", "high", "auth", "validate_mailgun"),
    ("Mailchimp API Key", r"[0-9a-f]{32}-us[0-9]{1,2}", "high", "high", "auth", "validate_mailchimp"),
    ("Telegram Bot Token", r"[0-9]+:AA[0-9A-Za-z\-_]{33}", "high", "high", "auth", "validate_telegram"),
    ("Postmark Server Token", r"(?i)postmark.*['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "high", "medium", "auth", "validate_postmark"),
    ("Okta API Token", r"(?i)okta.*['\"][0-9a-zA-Z_-]{42}['\"]", "high", "medium", "auth", "validate_okta"),
    ("Auth0 Client Secret", r"(?i)auth0.*client.?secret.*['\"][a-zA-Z0-9_-]{32,}['\"]", "high", "medium", "auth", None),
    ("Heroku API Key", r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", "high", "medium", "auth", "validate_heroku"),
    ("HubSpot API Key", r"(?i)hubspot.*['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "high", "medium", "auth", "validate_hubspot"),
    ("Shopify Token", r"shpat_[a-fA-F0-9]{32}", "high", "high", "auth", "validate_shopify"),
    ("Shopify Shared Secret", r"shpss_[a-fA-F0-9]{32}", "high", "high", "auth", None),

    # ========== JS-SPECIFIC SERVICES (High/Medium) ==========
    ("Sentry DSN", r"https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io/[0-9]+", "medium", "high", "js_service", None),
    ("Algolia API Key", r"(?i)algolia.*['\"][a-f0-9]{32}['\"]", "high", "medium", "js_service", None),
    ("Algolia App ID", r"(?i)algolia.*app.?id.*['\"][A-Z0-9]{10}['\"]", "low", "medium", "js_service", None),
    ("Mapbox Token", r"pk\.[a-zA-Z0-9]{60,}", "medium", "high", "js_service", None),
    ("Pusher Key", r"(?i)pusher.*key.*['\"][a-f0-9]{20}['\"]", "medium", "medium", "js_service", None),
    ("Pusher Secret", r"(?i)pusher.*secret.*['\"][a-f0-9]{40}['\"]", "high", "medium", "js_service", None),
    ("Intercom App ID", r"(?i)intercom.*app.?id.*['\"][a-z0-9]{8}['\"]", "low", "medium", "js_service", None),
    ("Segment Write Key", r"(?i)segment.*write.?key.*['\"][a-zA-Z0-9]{32}['\"]", "medium", "medium", "js_service", None),
    ("Amplitude API Key", r"(?i)amplitude.*api.?key.*['\"][a-f0-9]{32}['\"]", "medium", "medium", "js_service", None),
    ("LaunchDarkly SDK Key", r"(?i)sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "medium", "high", "js_service", None),
    ("Contentful Token", r"(?i)contentful.*['\"][a-zA-Z0-9_-]{43}['\"]", "medium", "medium", "js_service", None),
    ("Supabase Key", r"(?i)supabase.*(?:anon|service).*key.*eyJ[A-Za-z0-9-_]+", "high", "medium", "js_service", None),
    ("PlanetScale Token", r"pscale_tkn_[a-zA-Z0-9_-]{43}", "high", "high", "js_service", None),
    ("Vercel Token", r"(?i)vercel.*['\"][a-zA-Z0-9]{24}['\"]", "high", "medium", "js_service", None),
    ("Next.js Env Leak", r"__NEXT_DATA__.*(?:apiKey|secret|token|password)", "high", "medium", "js_service", None),
    ("OpenAI API Key", r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}", "critical", "high", "js_service", "validate_openai"),
    ("OpenAI Project Key", r"sk-proj-[a-zA-Z0-9_-]{80,}", "critical", "high", "js_service", "validate_openai"),

    # ========== GENERAL SECRETS (Medium) ==========
    ("JWT Token", r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "medium", "high", "secret", None),
    ("Basic Auth Header", r"(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]+", "high", "high", "secret", None),
    ("Bearer Token", r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}", "high", "medium", "secret", None),
    ("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "critical", "high", "secret", None),
    ("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "critical", "high", "secret", None),
    ("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "critical", "high", "secret", None),
    ("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "critical", "high", "secret", None),
    ("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "critical", "high", "secret", None),
    ("Generic Private Key", r"-----BEGIN PRIVATE KEY-----", "critical", "high", "secret", None),
    ("MongoDB URI", r"\bmongodb(?:\+srv)?://[^\s'\"]+", "high", "high", "secret", None),
    ("PostgreSQL URI", r"\bpostgres(?:ql)?://[^\s'\"]+", "high", "high", "secret", None),
    ("MySQL URI", r"\bmysql://[^\s'\"]+", "high", "high", "secret", None),
    ("Redis URL", r"\bredis://[^\s'\"]+", "high", "high", "secret", None),
    ("NPM Token", r"(?i)//registry\.npmjs\.org/:_authToken=[0-9a-f-]{36}", "high", "high", "secret", None),
    ("PyPI Token", r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}", "high", "high", "secret", None),
    ("Docker Hub Token", r"dckr_pat_[A-Za-z0-9_-]{27}", "high", "high", "secret", None),
    ("Generic API Key", r"(?i)(api[_-]?key|apikey|api_secret)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?", "medium", "low", "secret", None),
    ("Generic Secret", r"(?i)(secret|password|passwd|pwd)[\"']?\s*[:=]\s*[\"'][^\"']{8,}[\"']", "medium", "low", "secret", None),
    ("Generic Token", r"(?i)(access[_-]?token|auth[_-]?token)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?", "medium", "low", "secret", None),
    ("Hardcoded Password", r"(?i)(password|passwd|pwd)\s*=\s*[\"'][^\"']{4,}[\"']", "medium", "low", "secret", None),
    ("Twitter Bearer Token", r"(?<![A-Za-z0-9+/=])AAAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{30,}(?![A-Za-z0-9+/=])", "high", "medium", "auth", "validate_twitter_format"),
    ("Facebook Access Token", r"EAACEdEose0cBA[0-9A-Za-z]+", "high", "high", "auth", None),

    # ========== INFRASTRUCTURE (Medium) ==========
    ("S3 Bucket (path-style)", r"https?://s3(?:[.-][\w-]+)?\.amazonaws\.com/([a-zA-Z0-9._-]+)", "medium", "high", "infrastructure", None),
    ("S3 Bucket (virtual-hosted)", r"https?://([a-zA-Z0-9._-]+)\.s3(?:[.-][\w-]+)?\.amazonaws\.com", "medium", "high", "infrastructure", None),
    ("S3 ARN", r"arn:aws:s3:::([a-zA-Z0-9._-]+)", "medium", "high", "infrastructure", None),
    ("GCP Storage", r"https?://storage\.googleapis\.com/([a-zA-Z0-9._-]+)", "medium", "high", "infrastructure", None),
    ("GCP gs:// URL", r"gs://([a-zA-Z0-9._-]+)", "medium", "high", "infrastructure", None),
    ("Azure Blob Storage", r"https?://([a-zA-Z0-9]+)\.blob\.core\.windows\.net", "medium", "high", "infrastructure", None),
    ("Internal/Staging URL", r"https?://[a-zA-Z0-9.-]*(staging|internal|dev|test|local|admin)[a-zA-Z0-9.-]*\.[a-zA-Z]{2,}", "low", "low", "infrastructure", None),
    ("Localhost with Port", r"(?:localhost|127\.0\.0\.1):\d{2,5}", "low", "medium", "infrastructure", None),

    # ========== LOW / INFO ==========
    ("Email Address", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "info", "low", "info", None),
    ("Private IP (RFC1918)", r"(?:^|[^0-9])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})(?:[^0-9]|$)", "low", "medium", "info", None),
    ("UUID v4", r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", "info", "low", "info", None),
    ("Debug Flag", r"(?i)(debug|NODE_ENV)\s*[:=]\s*['\"]?(true|development|1)['\"]?", "low", "medium", "info", None),
]

# Pre-compile all patterns at module load time
JS_SECRET_PATTERNS = []
for name, regex, severity, confidence, category, validator_ref in _RAW_PATTERNS:
    try:
        compiled = re.compile(regex)
        JS_SECRET_PATTERNS.append({
            'name': name,
            'regex': compiled,
            'severity': severity,
            'confidence': confidence,
            'category': category,
            'validator_ref': validator_ref,
        })
    except re.error:
        print(f"[!][JsRecon] Failed to compile pattern: {name}")

# Email false positive domains to filter out
_EMAIL_FILTER_DOMAINS = {
    'example.com', 'test.com', 'localhost', 'email.com',
    'domain.com', 'company.com', 'yourcompany.com',
    'placeholder.com', 'sample.com', 'fake.com',
    'sentry.io', 'w3.org',
}

# Dev comment patterns
DEV_COMMENT_KEYWORDS = [
    'TODO', 'FIXME', 'HACK', 'XXX', 'BUG', 'TEMP', 'REMOVEME',
    'WORKAROUND', 'DEPRECATED', 'REFACTOR',
]

DEV_COMMENT_SENSITIVE_KEYWORDS = [
    'password', 'secret', 'key', 'token', 'credential',
    'admin', 'debug', 'bypass', 'hardcod', 'temporary',
]

_DEV_COMMENT_RE = re.compile(
    r'(?://|/\*|\*)\s*(?:' +
    '|'.join(DEV_COMMENT_KEYWORDS) +
    r')[\s:]+(.{1,200})',
    re.IGNORECASE
)

_DEV_SENSITIVE_COMMENT_RE = re.compile(
    r'(?://|/\*|\*)\s*.*(?:' +
    '|'.join(DEV_COMMENT_SENSITIVE_KEYWORDS) +
    r').*',
    re.IGNORECASE
)

# Confidence ordering for filtering
CONFIDENCE_ORDER = {'high': 3, 'medium': 2, 'low': 1}
SEVERITY_ORDER = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}


def _make_finding_id(name: str, matched_text: str, source_url: str) -> str:
    """Generate a deterministic ID for deduplication."""
    raw = f"{name}:{matched_text}:{source_url}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _is_false_positive_email(email: str) -> bool:
    """Filter out placeholder/test email addresses."""
    domain = email.split('@')[-1].lower()
    return domain in _EMAIL_FILTER_DOMAINS


# ---------------------------------------------------------------------------
# False-positive filters for embedded binary / font / base64 data
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy. Real secrets > 3.5, binary junk < 3.0."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


_BASE64_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')


def _is_inside_base64_blob(line: str, start: int, end: int, threshold: int = 200) -> bool:
    """Check if match sits inside a continuous base64-like run > threshold chars."""
    left = start
    while left > 0 and line[left - 1] in _BASE64_CHARS:
        left -= 1
    right = end
    while right < len(line) and line[right] in _BASE64_CHARS:
        right += 1
    return (right - left) > threshold


_BINARY_CONTEXT_RE = re.compile(
    r'glyf|loca|hhea|hmtx|GSUB|cmap|IcoMoon|woff|font-face|@font-face|'
    r'data:application/font|data:font/|base64,|opentype|truetype|'
    r'data:application/x-font|\.eot|\.ttf|\.woff|FontFace|fontFamily',
    re.IGNORECASE,
)


def _has_binary_context(context: str) -> bool:
    """Check if surrounding code contains font/binary data indicators."""
    return bool(_BINARY_CONTEXT_RE.search(context))


def _has_repetitive_pattern(text: str) -> bool:
    """Detect strings with suspiciously repetitive chars (e.g., 'AAAAAA...')."""
    if len(text) < 16:
        return False
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    max_freq = max(freq.values())
    if max_freq / len(text) > 0.4:
        return True
    # Check for runs of 6+ identical characters
    for i in range(len(text) - 5):
        if len(set(text[i:i + 6])) == 1:
            return True
    return False


_STAGING_URL_WHITELIST = {
    'developer.mozilla.org', 'docs.microsoft.com', 'learn.microsoft.com',
    'w3.org', 'stackoverflow.com', 'github.com', 'devdocs.io',
    'developer.apple.com', 'developers.google.com', 'reactjs.org',
    'nodejs.org', 'npmjs.com', 'pypi.org',
}


def _is_whitelisted_staging_url(matched_text: str) -> bool:
    """Filter known non-interesting domains from Internal/Staging URL pattern."""
    lower = matched_text.lower()
    return any(domain in lower for domain in _STAGING_URL_WHITELIST)


def scan_js_content(
    content: str,
    source_url: str,
    custom_patterns: Optional[list] = None,
    min_confidence: str = 'low',
) -> tuple[list, dict]:
    """
    Scan JavaScript content for secrets using hardcoded + optional custom patterns.

    Args:
        content: JavaScript file content
        source_url: URL the JS file was downloaded from
        custom_patterns: Optional list of dicts with keys: name, regex, severity, confidence, category
        min_confidence: Minimum confidence level to include ('low', 'medium', 'high')

    Returns:
        Tuple of (findings list, filtered_counts dict).
        Each finding dict has: id, name, matched_text, severity, confidence,
        category, line_number, source_url, validator_ref
    """
    findings = []
    seen_hashes = set()
    min_conf_val = CONFIDENCE_ORDER.get(min_confidence, 1)
    filtered_counts = {
        'low_entropy': 0,
        'base64_blob': 0,
        'binary_context': 0,
        'repetitive': 0,
        'url_whitelist': 0,
    }

    # Categories where false-positive filters apply
    _FP_FILTER_CATEGORIES = {'auth', 'cloud', 'payment', 'secret', 'js_service'}
    # Patterns that rely on structural prefixes, not randomness -- skip entropy check
    _SKIP_ENTROPY_KEYWORDS = ('Private Key', 'URL', 'URI', 'DSN', 'Header')

    # Merge custom patterns if provided
    patterns = list(JS_SECRET_PATTERNS)
    if custom_patterns:
        for cp in custom_patterns:
            try:
                compiled = re.compile(cp['regex']) if isinstance(cp.get('regex'), str) else cp.get('regex')
                patterns.append({
                    'name': cp.get('name', 'Custom Pattern'),
                    'regex': compiled,
                    'severity': cp.get('severity', 'medium'),
                    'confidence': cp.get('confidence', 'medium'),
                    'category': cp.get('category', 'custom'),
                    'validator_ref': cp.get('validator_ref'),
                })
            except (re.error, TypeError, KeyError):
                continue

    lines = content.split('\n')

    for pattern in patterns:
        conf_val = CONFIDENCE_ORDER.get(pattern['confidence'], 1)
        if conf_val < min_conf_val:
            continue

        for line_num, line in enumerate(lines, 1):
            # Skip extremely long lines to prevent regex performance issues
            if len(line) > 500_000:
                continue
            for match in pattern['regex'].finditer(line):
                matched_text = match.group(0)

                # Skip email false positives
                if pattern['name'] == 'Email Address' and _is_false_positive_email(matched_text):
                    continue

                # Skip whitelisted staging URLs
                if pattern['name'] == 'Internal/Staging URL' and _is_whitelisted_staging_url(matched_text):
                    filtered_counts['url_whitelist'] += 1
                    continue

                # --- False-positive filters for embedded binary/font data ---
                # Only apply to secret-type categories, not infrastructure/info
                if pattern['category'] in _FP_FILTER_CATEGORIES:
                    skip_entropy = any(kw in pattern['name'] for kw in _SKIP_ENTROPY_KEYWORDS)
                    if not skip_entropy and len(matched_text) >= 16 and _shannon_entropy(matched_text) < 3.0:
                        filtered_counts['low_entropy'] += 1
                        continue
                    if _is_inside_base64_blob(line, match.start(), match.end()):
                        filtered_counts['base64_blob'] += 1
                        continue
                    # Binary context check: only check same line to avoid
                    # false-filtering real secrets near font declarations
                    if len(lines) <= 3 and len(line) > 1000:
                        nearby = line[max(0, match.start() - 300):min(len(line), match.end() + 300)]
                    else:
                        nearby = line
                    if _has_binary_context(nearby):
                        filtered_counts['binary_context'] += 1
                        continue
                    if _has_repetitive_pattern(matched_text):
                        filtered_counts['repetitive'] += 1
                        continue

                # Deduplicate by content hash
                finding_id = _make_finding_id(pattern['name'], matched_text, source_url)
                if finding_id in seen_hashes:
                    continue
                seen_hashes.add(finding_id)

                # Redact the matched text for storage (show first/last chars)
                if len(matched_text) > 12:
                    redacted = matched_text[:6] + '...' + matched_text[-4:]
                elif len(matched_text) > 4:
                    redacted = matched_text[:3] + '...'
                else:
                    redacted = '***'

                # Extract context (surrounding code)
                if len(lines) <= 3 and len(line) > 1000:
                    # Minified JS: extract chars around match position
                    ctx_start_char = max(0, match.start() - 150)
                    ctx_end_char = min(len(line), match.end() + 150)
                    context = line[ctx_start_char:ctx_end_char]
                else:
                    # Multi-line JS: extract surrounding lines
                    ctx_start = max(0, line_num - 2)
                    ctx_end = min(len(lines), line_num + 1)
                    context = '\n'.join(lines[ctx_start:ctx_end])

                findings.append({
                    'id': finding_id,
                    'name': pattern['name'],
                    'matched_text': matched_text,
                    'redacted_value': redacted,
                    'severity': pattern['severity'],
                    'confidence': pattern['confidence'],
                    'category': pattern['category'],
                    'line_number': line_num,
                    'source_url': source_url,
                    'context': context[:500],
                    'validator_ref': pattern['validator_ref'],
                    'detection_method': 'regex',
                })

    return findings, filtered_counts


def scan_dev_comments(content: str, source_url: str) -> list:
    """
    Extract developer comments containing sensitive keywords or TODO/FIXME markers.

    Returns:
        List of finding dicts with: type, content, source_url, line, severity
    """
    findings = []
    lines = content.split('\n')

    for line_num, line in enumerate(lines, 1):
        # Check for TODO/FIXME/HACK style comments
        match = _DEV_COMMENT_RE.search(line)
        if match:
            comment_text = match.group(0).strip()
            # Check if it contains sensitive keywords (higher severity)
            is_sensitive = any(kw in comment_text.lower() for kw in DEV_COMMENT_SENSITIVE_KEYWORDS)
            finding_id = hashlib.sha256(f"devcmt:{source_url}:{line_num}".encode()).hexdigest()[:16]
            findings.append({
                'id': finding_id,
                'type': 'dev_comment',
                'content': comment_text[:300],
                'source_url': source_url,
                'line': line_num,
                'severity': 'medium' if is_sensitive else 'info',
                'confidence': 'high' if is_sensitive else 'low',
            })
            continue

        # Check for comments with sensitive keywords
        sens_match = _DEV_SENSITIVE_COMMENT_RE.search(line)
        if sens_match:
            comment_text = sens_match.group(0).strip()
            # Avoid duplicating findings from the previous check
            if not _DEV_COMMENT_RE.search(line):
                finding_id = hashlib.sha256(f"senscmt:{source_url}:{line_num}".encode()).hexdigest()[:16]
                findings.append({
                    'id': finding_id,
                    'type': 'sensitive_comment',
                    'content': comment_text[:300],
                    'source_url': source_url,
                    'line': line_num,
                    'severity': 'medium',
                    'confidence': 'medium',
                })

    return findings


def load_custom_patterns(file_path: str) -> list:
    """
    Load custom patterns from a user-uploaded JSON or TXT file.

    JSON format: [{"name": "...", "regex": "...", "severity": "...", "confidence": "..."}]
    TXT format: name|regex|severity|confidence (one per line)

    Returns:
        List of pattern dicts ready to pass to scan_js_content(custom_patterns=...)
    """
    patterns = []
    if not file_path:
        return patterns

    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()

        if file_path.endswith('.json'):
            raw = json.loads(content)
            if isinstance(raw, list):
                patterns = raw
        else:
            # TXT format: name|regex|severity|confidence
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('|')
                if len(parts) >= 2:
                    patterns.append({
                        'name': parts[0].strip(),
                        'regex': parts[1].strip(),
                        'severity': parts[2].strip() if len(parts) > 2 else 'medium',
                        'confidence': parts[3].strip() if len(parts) > 3 else 'medium',
                        'category': 'custom',
                    })
    except Exception as e:
        print(f"[!][JsRecon] Failed to load custom patterns from {file_path}: {e}")

    return patterns
