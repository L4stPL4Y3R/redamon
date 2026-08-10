"""
Unit tests for the DB-sourced egress policy contract (egress.policy_from_dict /
policy_to_dict) added for the "DB is the single source of truth" refactor.

The invariant that matters for security: EVERY field defaults to BLOCK, so a
missing / partial / malformed config can never silently OPEN the egress guard.

Run: python3 -m unittest capture_proxy.tests.test_egress_config
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import egress  # noqa: E402

FIELDS = list(egress.POLICY_ENV.keys())  # the 11 EgressPolicy toggles


class TestPolicyFromDict(unittest.TestCase):
    def test_explicit_false_is_honored(self):
        p = egress.policy_from_dict({"block_private": False})
        self.assertFalse(p.block_private)
        # every other field stays blocked (fail-safe default)
        self.assertTrue(p.block_loopback)
        self.assertTrue(p.block_reserved)

    def test_missing_fields_default_to_block(self):
        p = egress.policy_from_dict({})
        for f in FIELDS:
            self.assertTrue(getattr(p, f), f"{f} should default to block")

    def test_none_input_all_block(self):
        p = egress.policy_from_dict(None)
        for f in FIELDS:
            self.assertTrue(getattr(p, f), f)

    def test_bool_values(self):
        p = egress.policy_from_dict({f: False for f in FIELDS})
        for f in FIELDS:
            self.assertFalse(getattr(p, f), f)

    def test_string_false_like_values_turn_off(self):
        for falsey in ("false", "0", "no", "off", "False", "OFF"):
            p = egress.policy_from_dict({"block_private": falsey})
            self.assertFalse(p.block_private, falsey)

    def test_string_true_like_and_garbage_stay_blocked(self):
        for truthy in ("true", "1", "yes", "on", "banana", ""):
            p = egress.policy_from_dict({"block_private": truthy})
            self.assertTrue(p.block_private, truthy)

    def test_adversarial_value_types_never_open_the_guard(self):
        # Anything that is not an explicit false-like scalar must stay BLOCKED, so a
        # malformed / hostile config value cannot silently disable a guard.
        for val in ([], {}, {"nested": True}, [1, 2], 0.0, 1, 2, -1, "banana", "TRUE"):
            p = egress.policy_from_dict({"block_private": val})
            self.assertTrue(p.block_private, f"value {val!r} must keep the guard blocked")

    def test_only_explicit_false_scalars_disable(self):
        # The exact set that turns a toggle OFF: int 0, and the false-like strings.
        for val in (0, "0", "false", "no", "off", "False"):
            p = egress.policy_from_dict({"block_private": val})
            self.assertFalse(p.block_private, f"value {val!r} should disable the toggle")

    def test_unknown_keys_ignored(self):
        p = egress.policy_from_dict({"block_private": False, "not_a_field": True, "x": 1})
        self.assertFalse(p.block_private)
        # constructing did not raise and unknown keys are dropped
        self.assertTrue(p.block_loopback)

    def test_roundtrip_to_dict_from_dict(self):
        original = egress.EgressPolicy(block_private=False, block_cgnat=False)
        d = egress.policy_to_dict(original)
        self.assertEqual(set(d.keys()), set(FIELDS))
        self.assertFalse(d["block_private"])
        self.assertFalse(d["block_cgnat"])
        self.assertTrue(d["block_loopback"])
        restored = egress.policy_from_dict(d)
        self.assertEqual(restored, original)

    def test_from_env_and_from_dict_agree(self):
        # policy_from_env(no env) and policy_from_dict({}) must both be all-block.
        self.assertEqual(egress.policy_from_dict({}), egress.policy_from_env({}))


class TestPolicyToDict(unittest.TestCase):
    def test_serializes_all_fields_as_bools(self):
        d = egress.policy_to_dict(egress.EgressPolicy())
        self.assertEqual(set(d.keys()), set(FIELDS))
        for f in FIELDS:
            self.assertIsInstance(d[f], bool)
            self.assertTrue(d[f])


if __name__ == "__main__":
    unittest.main()
