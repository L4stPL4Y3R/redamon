"""Unit tests for docker_broker/broker.py memory-cap injection (Part 4d).

Verifies inject_limits() adds/caps HostConfig.Memory correctly and _parse_size
parses sizes. Run: python3 -m unittest tests.test_broker_inject
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'docker_broker'))

import broker  # stdlib-only module; importing does not start the server

GB = 1024 ** 3


class TestParseSize(unittest.TestCase):
    def test_sizes(self):
        self.assertEqual(broker._parse_size("2g", 0), 2 * GB)
        self.assertEqual(broker._parse_size("512m", 0), 512 * 1024 * 1024)
        self.assertEqual(broker._parse_size("1073741824", 0), GB)
        self.assertEqual(broker._parse_size("512mb", 0), 512 * 1024 * 1024)

    def test_default_on_invalid(self):
        self.assertEqual(broker._parse_size("", 7), 7)
        self.assertEqual(broker._parse_size("abc", 7), 7)
        self.assertEqual(broker._parse_size(None, 7), 7)


class TestInjectLimits(unittest.TestCase):
    def setUp(self):
        self._mem = broker.BROKER_TOOL_MEM
        self._pids = broker.BROKER_TOOL_PIDS
        broker.BROKER_TOOL_MEM = 2 * GB
        broker.BROKER_TOOL_PIDS = 0

    def tearDown(self):
        broker.BROKER_TOOL_MEM = self._mem
        broker.BROKER_TOOL_PIDS = self._pids

    def test_adds_hostconfig_and_memory(self):
        cfg = {"Image": "projectdiscovery/katana"}
        out = broker.inject_limits(cfg)
        self.assertEqual(out["HostConfig"]["Memory"], 2 * GB)

    def test_sets_memory_when_absent(self):
        cfg = {"Image": "x", "HostConfig": {"NetworkMode": "host"}}
        broker.inject_limits(cfg)
        self.assertEqual(cfg["HostConfig"]["Memory"], 2 * GB)
        self.assertEqual(cfg["HostConfig"]["NetworkMode"], "host")  # untouched

    def test_caps_larger_memory_down(self):
        cfg = {"HostConfig": {"Memory": 8 * GB}}
        broker.inject_limits(cfg)
        self.assertEqual(cfg["HostConfig"]["Memory"], 2 * GB)

    def test_respects_lower_explicit_memory(self):
        cfg = {"HostConfig": {"Memory": 512 * 1024 * 1024}}
        broker.inject_limits(cfg)
        self.assertEqual(cfg["HostConfig"]["Memory"], 512 * 1024 * 1024)

    def test_pids_only_when_configured(self):
        cfg = {"HostConfig": {}}
        broker.inject_limits(cfg)
        self.assertNotIn("PidsLimit", cfg["HostConfig"])
        broker.BROKER_TOOL_PIDS = 4096
        cfg2 = {"HostConfig": {}}
        broker.inject_limits(cfg2)
        self.assertEqual(cfg2["HostConfig"]["PidsLimit"], 4096)

    def test_disabled_when_mem_zero(self):
        broker.BROKER_TOOL_MEM = 0
        cfg = {"HostConfig": {}}
        broker.inject_limits(cfg)
        self.assertNotIn("Memory", cfg["HostConfig"])

    def test_reserialized_body_roundtrips(self):
        import json
        cfg = {"Image": "x", "HostConfig": {"NetworkMode": "host"}}
        broker.inject_limits(cfg)
        body = json.dumps(cfg).encode("utf-8")
        reparsed = json.loads(body)
        self.assertEqual(reparsed["HostConfig"]["Memory"], 2 * GB)
        self.assertEqual(len(body), len(json.dumps(cfg).encode("utf-8")))  # stable


if __name__ == "__main__":
    unittest.main()
