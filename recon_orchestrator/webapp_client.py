"""
Shared blocking JSON client for the webapp's internal API.

Lifted out of scan_scheduler.py (Scan Queue plan Phase 2) so both the scheduler
worker and the queue dispatcher speak to the webapp the same way: an internal-key
request that returns the parsed body on 200/201, or None on ANY failure. A worker
must never die on I/O, so callers treat None as "skip this tick".

scan_scheduler.py keeps a module-level name ``_request`` bound to ``request_json``
so existing ``mock.patch.object(scan_scheduler, "_request", ...)`` tests still work.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Optional

logger = logging.getLogger(__name__)


def webapp_base() -> str:
    return (os.environ.get("WEBAPP_API_URL", "http://webapp:3000") or "").rstrip("/")


def internal_key() -> str:
    return os.environ.get("INTERNAL_API_KEY", "")


def request_json(url: str, key: str, method: str = "GET", payload: Optional[dict] = None,
                 timeout: float = 15.0, tag: str = "webapp") -> Optional[dict]:
    """Blocking JSON request to the webapp's internal API. None on any failure —
    the caller treats that as "skip" rather than guessing."""
    data = None
    headers = {"x-internal-key": key}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if getattr(r, "status", 200) not in (200, 201):
                return None
            body = r.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        logger.warning("[%s] %s %s -> HTTP %s", tag, method, url, e.code)
        return None
    except Exception as e:  # noqa: BLE001 - a worker must never die on I/O
        logger.warning("[%s] %s %s failed: %s", tag, method, url, e)
        return None
