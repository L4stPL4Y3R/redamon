"""
Unit tests for the payload-settings prompt (utils.get_session_config_prompt).

Regression cover for issue #180 ("LHOST IP prompts/confirms from AI Agent"):
when no payload direction is configured the agent must be told that LHOST is the
HOST machine's LAN IP and that it must NOT auto-detect an IP from inside the
kali-sandbox container (that container's own `172.x` address is unreachable by
the target). The reverse/bind branches must keep working unchanged.

Run (inside agent container):
    ./agentic/run_tests.sh tests/test_payload_settings.py
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

import utils  # noqa: E402


def _fake_settings(values: dict):
    """Return a get_setting stand-in backed by `values` with a default fallback."""
    def _get(key, default=None):
        return values.get(key, default)
    return _get


class AskBranchGuidanceTests(unittest.TestCase):
    """All-empty settings -> ASK branch must steer the agent to the host LAN IP."""

    def _render(self, values):
        with patch.object(utils, "get_setting", _fake_settings(values)):
            return utils.get_session_config_prompt()

    def test_ask_branch_triggers_when_nothing_configured(self):
        out = self._render({})
        self.assertIn("PAYLOAD DIRECTION NOT CONFIGURED", out)

    def test_ask_branch_names_the_host_lan_ip_as_lhost(self):
        out = self._render({})
        self.assertIn("host machine's LAN IP", out)

    def test_ask_branch_forbids_container_ip_autodetection(self):
        out = self._render({})
        # The exact failure from issue #180: the agent ran `ip`/`ifconfig` inside
        # the container and got the unreachable 172.x veth address.
        self.assertIn("DO NOT GUESS OR AUTO-DETECT", out)
        self.assertIn("172.x", out)
        for cmd in ("ip addr", "ifconfig", "hostname -I"):
            self.assertIn(cmd, out)
        self.assertIn("ASK THE USER", out)

    def test_ask_branch_explains_the_4444_host_forward(self):
        out = self._render({})
        self.assertIn("4444", out)
        self.assertIn("host-LAN-IP:LPORT", out)


class ModeRegressionTests(unittest.TestCase):
    """Configured reverse/bind modes are unaffected by the new guidance."""

    def _render(self, values):
        with patch.object(utils, "get_setting", _fake_settings(values)):
            return utils.get_session_config_prompt()

    def test_reverse_mode_still_selected_and_prints_lhost(self):
        out = self._render({"LHOST": "203.0.113.9", "LPORT": 4444})
        self.assertIn("Mode: REVERSE", out)
        self.assertIn("203.0.113.9", out)
        # The ask-branch-only guidance must NOT leak into a fully configured run.
        self.assertNotIn("PAYLOAD DIRECTION NOT CONFIGURED", out)
        self.assertNotIn("DO NOT GUESS OR AUTO-DETECT", out)

    def test_bind_mode_still_selected(self):
        out = self._render({"BIND_PORT_ON_TARGET": 4444})
        self.assertIn("Mode: BIND", out)
        self.assertNotIn("DO NOT GUESS OR AUTO-DETECT", out)

    def test_lhost_without_lport_falls_to_ask_with_guidance(self):
        # Discordant config (LHOST set, LPORT missing) -> ASK, and the host-IP
        # guidance still shows so the user knows which value to complete.
        out = self._render({"LHOST": "203.0.113.9"})
        self.assertIn("PAYLOAD DIRECTION NOT CONFIGURED", out)
        self.assertIn("LPORT is missing", out)
        self.assertIn("host machine's LAN IP", out)


if __name__ == "__main__":
    unittest.main()
