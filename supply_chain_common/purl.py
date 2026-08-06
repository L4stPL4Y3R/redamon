"""Package-URL (purl) construction and ecosystem name normalization.

purl is the canonical identity we MERGE `Package` nodes on:
  pkg:npm/lodash@4.17.21
  pkg:npm/%40angular/core@12.0.0     (scoped npm, '@' url-encoded per spec)
  pkg:pypi/requests@2.31.0           (PyPI name lowercased, PEP 503 normalized)

Only building/normalizing here; no I/O. Every name passed in is expected to
have already cleared `security.sanitize_name`.
"""

from urllib.parse import quote

from .security import sanitize_name, sanitize_version

__all__ = [
    "build_purl",
    "normalize_name",
    "ECOSYSTEM_PURL_TYPE",
    "OSV_ECOSYSTEMS",
]

# OSV ecosystem string  ->  purl type. OSV uses capitalized/branded names
# ("PyPI", "Go", "crates.io"); purl uses lowercase type slugs.
ECOSYSTEM_PURL_TYPE = {
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "golang",
    "crates.io": "cargo",
    "Maven": "maven",
    "Packagist": "composer",
    "RubyGems": "gem",
    "NuGet": "nuget",
}

# The reverse-friendly set of OSV ecosystem values we support, for validation.
OSV_ECOSYSTEMS = set(ECOSYSTEM_PURL_TYPE.keys())


def normalize_name(ecosystem, name):
    """Normalize a package name to its ecosystem's canonical form.

    PyPI is case-insensitive and treats runs of '.', '-', '_' as equivalent
    (PEP 503), so 'Flask_Login' and 'flask-login' are the same package; we fold
    to the dashed lowercase form so the purl (and thus the MERGE key) is stable.
    Other ecosystems are returned as-is (npm scopes are case-sensitive).
    """
    sanitize_name(name)
    purl_type = ECOSYSTEM_PURL_TYPE.get(ecosystem, ecosystem)
    if purl_type == "pypi":
        import re

        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def build_purl(ecosystem, name, version=None):
    """Build a canonical purl string. Raises SanitizeError on a hostile name."""
    sanitize_name(name)
    sanitize_version(version)
    purl_type = ECOSYSTEM_PURL_TYPE.get(ecosystem, ecosystem)
    norm = normalize_name(ecosystem, name)

    if purl_type == "npm" and norm.startswith("@") and "/" in norm:
        # Scoped npm package: the leading '@scope' is the purl namespace. Encode
        # the '@' as %40 so the purl round-trips through URL parsers.
        scope, _, pkg = norm.partition("/")
        base = "pkg:npm/{}/{}".format(quote(scope, safe=""), quote(pkg, safe=""))
    elif purl_type == "maven" and ":" in norm:
        # Maven coordinates arrive as "group:artifact" (the OSV form); the purl
        # spec puts the group in the namespace and the artifact in the name.
        group, _, artifact = norm.partition(":")
        base = "pkg:maven/{}/{}".format(quote(group, safe=""), quote(artifact, safe=""))
    else:
        # For namespaced types (maven group:artifact, go host/path) keep the
        # separators readable; only percent-encode characters that would break
        # a URL. sanitize_name already blocked the dangerous ones.
        base = "pkg:{}/{}".format(purl_type, quote(norm, safe="/@"))

    if version:
        base = "{}@{}".format(base, quote(version, safe=""))
    return base
