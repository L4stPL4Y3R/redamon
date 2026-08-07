"""Supply-Chain Scan project settings (mirrors trufflehog_scan/project_settings.py).

Fetches per-project supply-chain settings from the webapp API when PROJECT_ID +
WEBAPP_API_URL are set; otherwise falls back to defaults for standalone use.
"""

import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_SUPPLY_CHAIN_SETTINGS: dict[str, Any] = {
    # Which input the scan reads: 'upload' (the SBOM/lockfile in the uploads
    # volume) or 'github' (a repository cloned by the scan itself).
    'SUPPLY_CHAIN_INPUT_MODE': 'upload',
    # 'upload' input: the basename inside the uploads volume. Uploads REPLACE
    # each other, so this always names the only file present for the project.
    'SUPPLY_CHAIN_SBOM_FILE': '',
    # 'github' input.
    'SUPPLY_CHAIN_REPO_URL': '',
    'SUPPLY_CHAIN_REPO_REF': '',
    # Comma-separated OSV ecosystem names to report (osv auto-detects from the
    # file; this is an allow-filter for the graph write).
    'SUPPLY_CHAIN_ECOSYSTEMS': 'npm,PyPI,Go,Maven,crates.io,Packagist,RubyGems,NuGet',
    # GuardDog deep analysis (downloads untrusted tarballs). OFF by default (S5.5).
    'SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED': False,
    # Read from the USER's global settings, and only in the github input mode.
    # Empty means clone anonymously (public repositories only).
    'GITHUB_ACCESS_TOKEN': '',
}


def fetch_supply_chain_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    import requests

    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    logger.info(f"Fetching Supply-Chain settings from {url}")
    # S3/E6: scanners receive the SCOPED SCANNER_API_KEY; fall back to the master
    # INTERNAL_API_KEY only on pre-secret installs. The webapp accepts either.
    internal_key = os.environ.get("SCANNER_API_KEY") or os.environ.get("INTERNAL_API_KEY", "")
    headers = {"X-Internal-Key": internal_key}
    response = requests.get(url, timeout=30, headers=headers)
    response.raise_for_status()
    project = response.json()

    settings = DEFAULT_SUPPLY_CHAIN_SETTINGS.copy()
    settings['SUPPLY_CHAIN_INPUT_MODE'] = project.get(
        'supplyChainInputMode', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_INPUT_MODE'])
    settings['SUPPLY_CHAIN_SBOM_FILE'] = project.get(
        'supplyChainSbomFile', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_SBOM_FILE'])
    settings['SUPPLY_CHAIN_REPO_URL'] = project.get(
        'supplyChainRepoUrl', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_REPO_URL'])
    settings['SUPPLY_CHAIN_REPO_REF'] = project.get(
        'supplyChainRepoRef', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_REPO_REF'])
    settings['SUPPLY_CHAIN_ECOSYSTEMS'] = project.get(
        'supplyChainEcosystems', DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_ECOSYSTEMS'])
    settings['SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED'] = project.get(
        'supplyChainDeepAnalysisEnabled',
        DEFAULT_SUPPLY_CHAIN_SETTINGS['SUPPLY_CHAIN_DEEP_ANALYSIS_ENABLED'])

    # The GitHub token lives in the USER's global settings, not the project -
    # the same one the secret hunter and trufflehog use, so a private repo needs
    # no second credential. Only fetched for the github input mode: an
    # SBOM-upload scan has no business holding a token.
    if settings['SUPPLY_CHAIN_INPUT_MODE'] == 'github':
        user_id = os.environ.get('USER_ID', '')
        if user_id:
            try:
                user_url = f"{webapp_url.rstrip('/')}/api/users/{user_id}/settings?internal=true"
                user_resp = requests.get(user_url, timeout=30, headers=headers)
                user_resp.raise_for_status()
                settings['GITHUB_ACCESS_TOKEN'] = (
                    user_resp.json().get('githubAccessToken') or '')
            except Exception as exc:
                # Not fatal: public repositories clone anonymously. Say so, or a
                # private-repo failure later looks like a missing repository.
                logger.warning(f"No GitHub token available ({exc}); "
                               "private repositories will fail to clone")

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
