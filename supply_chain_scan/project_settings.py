"""Supply-Chain Scan project settings (mirrors trufflehog_scan/project_settings.py).

Fetches per-project supply-chain settings from the webapp API when PROJECT_ID +
WEBAPP_API_URL are set; otherwise falls back to defaults for standalone use.
"""

import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_SUPPLY_CHAIN_SETTINGS: dict[str, Any] = {
    'SUPPLY_CHAIN_ENABLED': False,
    # v1 input: an uploaded SBOM / lockfile (basename inside the uploads volume).
    'SUPPLY_CHAIN_SBOM_FILE': '',
    # Comma-separated OSV ecosystem names to report (osv auto-detects from the
    # file; this is an allow-filter for the graph write).
    'SUPPLY_CHAIN_ECOSYSTEMS': 'npm,PyPI,Go,Maven,crates.io,Packagist,RubyGems,NuGet',
    # GuardDog deep analysis (downloads untrusted tarballs). OFF by default (S5.5).
    # v1 runs OSV-only; deep analysis dispatch to the DIRTY analyzer is v2.
    'SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED': False,
}


def fetch_supply_chain_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    import requests

    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    logger.info(f"Fetching Supply-Chain settings from {url}")
    headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
    response = requests.get(url, timeout=30, headers=headers)
    response.raise_for_status()
    project = response.json()

    settings = DEFAULT_SUPPLY_CHAIN_SETTINGS.copy()
    settings['SUPPLY_CHAIN_ENABLED'] = project.get(
        'supplyChainEnabled', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_ENABLED'])
    settings['SUPPLY_CHAIN_SBOM_FILE'] = project.get(
        'supplyChainSbomFile', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_SBOM_FILE'])
    settings['SUPPLY_CHAIN_ECOSYSTEMS'] = project.get(
        'supplyChainEcosystems', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_ECOSYSTEMS'])
    settings['SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED'] = project.get(
        'supplyChainDeepAnalysisEnabled',
        DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED'])

    logger.info(f"Loaded {len(settings)} Supply-Chain settings for project {project_id}")
    return settings


_settings: Optional[dict[str, Any]] = None
_current_project_id: Optional[str] = None


def load_project_settings(project_id: str) -> dict[str, Any]:
    global _settings, _current_project_id
    if _current_project_id == project_id and _settings is not None:
        return _settings

    webapp_url = os.environ.get('WEBAPP_API_URL')
    if not webapp_url:
        logger.warning("WEBAPP_API_URL not set, using DEFAULT_SUPPLY_CHAIN_SETTINGS")
        _settings = DEFAULT_SUPPLY_CHAIN_SETTINGS.copy()
        _current_project_id = project_id
        return _settings

    try:
        _settings = fetch_supply_chain_settings(project_id, webapp_url)
        _current_project_id = project_id
        return _settings
    except Exception as e:
        logger.error(f"Failed to fetch Supply-Chain settings for {project_id}: {e}")
        _settings = DEFAULT_SUPPLY_CHAIN_SETTINGS.copy()
        _current_project_id = project_id
        return _settings


def get_settings() -> dict[str, Any]:
    global _settings
    return _settings if _settings is not None else DEFAULT_SUPPLY_CHAIN_SETTINGS.copy()


def get_setting(key: str, default: Any = None) -> Any:
    return get_settings().get(key, default)
