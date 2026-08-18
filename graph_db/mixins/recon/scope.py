"""Scan-scope host filtering shared by the recon graph mixins.

The mixins must not create nodes for hosts outside the scan scope (a crawler
can wander onto a third-party CDN, and Nuclei follows redirects off-target).
The allowed-host set is assembled here so every mixin agrees on it.
"""
from urllib.parse import urlparse


def _normalize_host(value: str) -> str:
    """Reduce a host-ish string to a bare comparable hostname.

    Accepts what the scanners actually emit: 'example.com', 'example.com:8443',
    'https://example.com/foo' (Nuclei writes the full URL into `host` for some
    template types) and '[::1]:443'.
    """
    if not value:
        return ""
    host = value.strip().lower()
    if "://" in host:
        host = urlparse(host).netloc or host.split("://", 1)[1]
    host = host.split("/")[0]
    if host.startswith("["):                      # IPv6 literal: [::1]:443
        return host[1:].split("]")[0]
    return host.split(":")[0]


def build_host_scope(recon_data: dict) -> set:
    """Hosts the graph is allowed to create nodes for, or an empty set for "no filter".

    IP mode is the reason this is not just `subdomains`: run_ip_recon mints a
    dashed placeholder name per IP ("21.40.250.84" -> "21-40-250-84") because a
    Subdomain node needs a name, but every scanner targets the IP literal and
    reports findings under it. Scoping on `subdomains` alone therefore discards
    100% of an IP-mode scan's results. `metadata.subdomain_filter` is the
    allowed-host list httpx already filters on and holds the real IPs.
    """
    scope = {_normalize_host(h) for h in recon_data.get("subdomains") or []}
    metadata = recon_data.get("metadata") or {}
    scope |= {_normalize_host(h) for h in metadata.get("subdomain_filter") or []}
    scope |= {_normalize_host(ip) for ip in metadata.get("expanded_ips") or []}
    scope.discard("")

    # Bare-domain scan with no subdomains discovered: the apex is the scope.
    if not scope:
        domain = _normalize_host(recon_data.get("domain", ""))
        if domain:
            scope.add(domain)
    return scope


def host_in_scope(value: str, scope: set) -> bool:
    """True when `value` (host, host:port or URL) is in scope. Empty scope = no filter."""
    if not scope:
        return True
    return _normalize_host(value) in scope
