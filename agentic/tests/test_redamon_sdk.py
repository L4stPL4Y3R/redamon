"""Unit tests for the kali-side `redamon` SDK's response parser (Row 4).

`redamon._parse_curl` turns the `curl -i` output of a proxied replay into the
Response the agent's proxy_brain code reads as an oracle (.status/.headers/.body).
If it mis-reads the boundary, every replay-based finding is wrong. The SDK lives
in mcp/servers (kali PYTHONPATH); it imports only `requests` + stdlib, so it is
importable in the agent test image once mcp/servers is on the path.
"""
import os
import sys

_MCP_SERVERS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "mcp", "servers",
)
if _MCP_SERVERS not in sys.path:
    sys.path.insert(0, _MCP_SERVERS)

import redamon  # noqa: E402


def test_parse_curl_extracts_status_headers_body():
    raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: a=b\r\n\r\n<html>hi</html>"
    r = redamon._parse_curl(raw, None)
    assert r.status == 200
    assert r.headers["content-type"] == "text/html"
    assert r.headers["set-cookie"] == "a=b"
    assert r.body == "<html>hi</html>"
    assert r.length == len("<html>hi</html>")


def test_parse_curl_empty_body_status_only():
    r = redamon._parse_curl("HTTP/1.1 204 No Content\r\n\r\n", None)
    assert r.status == 204
    assert r.body == ""
    assert r.length == 0


def test_parse_curl_error_output_has_no_status():
    # A curl failure (no HTTP response) must not fabricate a status.
    r = redamon._parse_curl("curl: (7) Failed to connect to host", "1001")
    assert r.status is None
    assert "Failed to connect" in r.body
    assert r.payload == "1001"


def test_parse_curl_carries_payload_label():
    r = redamon._parse_curl("HTTP/1.1 500 Server Error\r\n\r\nSQL syntax error", "1001'")
    assert r.status == 500
    assert "SQL syntax error" in r.body
    assert r.payload == "1001'"


def test_search_accepts_dict_and_kwargs():
    # The skills call redamon.search({...}) (dict); code may also use kwargs. Both
    # must reach the endpoint as endpoint-shaped (camelCase) filters.
    seen = {}
    orig = redamon._read
    redamon._read = lambda op, args=None: seen.update(args or {}) or ""
    try:
        redamon.search({"hasAuth": True, "method": "POST"})
        assert seen == {"hasAuth": True, "method": "POST"}
        seen.clear()
        redamon.search(has_auth=True, host="x")           # snake_case kwargs -> aliased
        assert seen == {"hasAuth": True, "host": "x"}
        seen.clear()
        redamon.search(**{"q": "admin"})
        assert seen == {"q": "admin"}
    finally:
        redamon._read = orig
