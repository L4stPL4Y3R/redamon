"""
Smoke test against a LIVE recon-orchestrator.

Hits the real /local-llm/* HTTP endpoints (stdlib urllib only) to confirm the
routes are wired and return the expected JSON shape. It does NOT spawn Ollama or
pull a model (that is the heavy lifecycle gate, exercised manually / in the
integration harness), so it is fast and side-effect free: it only reads status.

Skips automatically if no orchestrator is reachable, so it is safe in CI.

    # from inside the container (localhost:8010 is the orchestrator itself):
    docker compose exec -T recon-orchestrator python -m unittest \
        tests.test_local_llm_smoke -v
"""
import json
import os
import unittest
import urllib.error
import urllib.request

ORCH_URL = os.environ.get("ORCH_SMOKE_URL", "http://localhost:8010")

_STATUS_KEYS = {
    "available", "running", "containerId", "baseUrl", "model",
    "modelPresent", "leases", "models", "warning",
}


def _reachable() -> bool:
    try:
        with urllib.request.urlopen(f"{ORCH_URL}/health", timeout=3) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


# Every route except /health now sits behind the X-Orchestrator-Key middleware.
# /health is the ONE exempt path, so reachability alone never implied the smoke
# calls would be authorized: without this header they 401 and the suite errors
# out on a healthy stack. Read from the environment, which is where the
# orchestrator process itself gets the key - running these from inside the
# container (the documented invocation above) therefore needs no extra setup.
_ORCH_KEY = os.environ.get("ORCHESTRATOR_API_KEY", "")


def _get(path: str):
    req = urllib.request.Request(f"{ORCH_URL}{path}")
    if _ORCH_KEY:
        req.add_header("X-Orchestrator-Key", _ORCH_KEY)
    return urllib.request.urlopen(req, timeout=5)


@unittest.skipUnless(_reachable(), f"no orchestrator at {ORCH_URL}")
@unittest.skipUnless(_ORCH_KEY, "ORCHESTRATOR_API_KEY unset (run inside the orchestrator container)")
class TestLocalLlmSmoke(unittest.TestCase):
    def test_status_endpoint_shape(self):
        with _get("/local-llm/status") as r:
            self.assertEqual(r.status, 200)
            body = json.loads(r.read().decode("utf-8"))
        self.assertEqual(set(body.keys()), _STATUS_KEYS)
        self.assertIsInstance(body["leases"], int)
        self.assertIsInstance(body["models"], list)
        self.assertTrue(str(body["baseUrl"]).startswith("http://"))

    def test_status_is_read_only(self):
        # Two status reads must not change the lease count (no side effects).
        def leases():
            with _get("/local-llm/status") as r:
                return json.loads(r.read().decode("utf-8"))["leases"]
        self.assertEqual(leases(), leases())


if __name__ == "__main__":
    unittest.main(verbosity=2)
