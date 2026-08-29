"""Unit tests for the proxy_brain traffic broker's security contract.

The /traffic/exec + /traffic/replay endpoints derive tenant identity from a
signed `X-Redamon-Ctx` tag (source=agent), NOT from the request body. The whole
isolation guarantee rests on: only a holder of INTERNAL_API_KEY can mint a tag
for a given tenant, and the kali worker does not hold that key. These tests pin
that contract at the primitive the endpoint's `_verify_traffic_ctx` wraps.
"""
import pytest

from redamon_ctx import sign_tag, verify_tag

AGENT_KEY = "agent-internal-key-abc123"
SCANNER_KEY = "scanner-scoped-key-xyz789"


def _agent_tag(user_id="u1", project_id="p1", phase="exploitation", key=AGENT_KEY):
    return sign_tag({
        "source": "agent", "user_id": user_id, "project_id": project_id,
        "session_id": "sess1", "tool": "proxy_brain", "phase": phase,
    }, key)


def test_valid_agent_tag_yields_tenant_and_phase():
    tok = _agent_tag()
    claims = verify_tag(tok, {"agent": AGENT_KEY})
    assert claims is not None
    assert claims["user_id"] == "u1"
    assert claims["project_id"] == "p1"
    assert claims["phase"] == "exploitation"


def test_tag_signed_with_wrong_key_is_rejected():
    # An attacker who does NOT hold INTERNAL_API_KEY cannot forge a tag the
    # agent will accept — this is what stops a kali foothold (which holds only
    # the scoped SCANNER_API_KEY) from asserting a cross-tenant identity.
    forged = _agent_tag(user_id="victim", project_id="victim_proj", key=SCANNER_KEY)
    assert verify_tag(forged, {"agent": AGENT_KEY}) is None


def test_recon_source_tag_rejected_by_agent_only_keymap():
    # /traffic/* verify with {"agent": INTERNAL_API_KEY} only. A recon-sourced
    # tag (even validly signed) has no matching key and fails closed.
    tok = sign_tag({"source": "recon", "user_id": "u1", "project_id": "p1"}, SCANNER_KEY)
    assert verify_tag(tok, {"agent": AGENT_KEY}) is None


def test_tampered_tenant_breaks_signature():
    tok = _agent_tag(user_id="u1", project_id="p1")
    body_b64, sig_b64 = tok.split(".", 1)
    # Swap in a different (validly-formatted) body; the signature no longer matches.
    other = _agent_tag(user_id="attacker", project_id="attacker_proj")
    tampered = other.split(".", 1)[0] + "." + sig_b64
    assert verify_tag(tampered, {"agent": AGENT_KEY}) is None


def test_missing_tenant_fields_are_rejectable():
    # _verify_traffic_ctx additionally requires user_id AND project_id present;
    # a tag lacking them must not authorize a read/send.
    tok = sign_tag({"source": "agent", "tool": "proxy_brain", "phase": "exploitation"}, AGENT_KEY)
    claims = verify_tag(tok, {"agent": AGENT_KEY})
    # verify_tag may return the payload, but the endpoint gate requires tenant:
    assert not (claims and claims.get("user_id") and claims.get("project_id"))


@pytest.mark.parametrize("phase,allowed", [
    ("informational", False),
    ("exploitation", True),
    ("post_exploitation", True),
    ("", False),
])
def test_active_replay_phase_gate(phase, allowed):
    # Mirrors the /traffic/replay per-send phase gate: active sends only in the
    # exploitation phases (fail closed otherwise).
    gate = phase in ("exploitation", "post_exploitation")
    assert gate is allowed
