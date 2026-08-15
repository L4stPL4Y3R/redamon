"""Typosquat detection (feature D).

The ground truth for the fuzzy check is the catalog's own labelled pairs, and the
important number is not "does it catch them" but "what does it flag that it
should not". This suite asserts a false-positive CEILING against the real popular
list, rather than leaving that as a comment.

Section: recon.
"""

import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for p in (_REPO, os.path.join(_REPO, "scanners")):
    if p not in sys.path:
        sys.path.insert(0, p)

from recon.helpers.supply_chain.typosquat import (  # noqa: E402
    detect_typosquats, levenshtein_within, load_popular_names,
    MAX_EDIT_DISTANCE, MIN_NAME_LEN,
)


class _Intel:
    """Stand-in for supply_chain_common.intel.Intel."""

    def __init__(self, typosquats=None, packages=None, available=True):
        self.typosquats = typosquats or {}
        self.packages = packages or {}
        self.available = available


def _pkgs(*names, ecosystem="npm"):
    return [{"name": n, "ecosystem": ecosystem,
             "purl": "pkg:{}/{}@1.0.0".format(ecosystem, n)} for n in names]


class TestLevenshtein(unittest.TestCase):

    def test_identical(self):
        self.assertEqual(levenshtein_within("lodash", "lodash"), 0)

    def test_one_substitution(self):
        self.assertEqual(levenshtein_within("lodesh", "lodash"), 1)

    def test_one_transposition_costs_two(self):
        # Plain Levenshtein, not Damerau: a swap is a delete plus an insert.
        self.assertEqual(levenshtein_within("lodahs", "lodash"), 2)

    def test_length_gap_short_circuits(self):
        self.assertGreater(levenshtein_within("a", "abcdefgh"), MAX_EDIT_DISTANCE)

    def test_far_apart_returns_over_the_ceiling(self):
        self.assertGreater(levenshtein_within("react", "webpack"), MAX_EDIT_DISTANCE)


class TestCatalogHits(unittest.TestCase):

    def test_labelled_typosquat_is_flagged_without_the_toggle(self):
        """The catalog lookup always runs: it asserts nothing new."""
        intel = _Intel(typosquats={"lodahs": {"original": "lodash",
                                              "incident_id": "SCA-0001"}})
        findings, stats = detect_typosquats(_pkgs("lodahs"), intel=intel,
                                            fuzzy_enabled=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["advisory_id"], "typosquat-of-lodash")
        self.assertEqual(findings[0]["rule"], "typosquat")
        self.assertEqual(stats["catalog_hits"], 1)

    def test_known_bad_package_name_is_flagged(self):
        intel = _Intel(packages={"npm/evil-pkg": {"incident_id": "SCA-0002"}})
        findings, _ = detect_typosquats(_pkgs("evil-pkg"), intel=intel)
        self.assertEqual(len(findings), 1)
        self.assertIn("SCA-0002", findings[0]["message"])

    def test_findings_are_never_malicious(self):
        """Only an OSV MAL- id makes a package malware."""
        intel = _Intel(typosquats={"lodahs": {"original": "lodash"}})
        findings, _ = detect_typosquats(_pkgs("lodahs"), intel=intel)
        for f in findings:
            self.assertEqual(f["confidence"], "suspicious")
            self.assertIn(f["severity"], ("medium", "low"))

    def test_unavailable_catalog_is_recorded_not_silent(self):
        findings, stats = detect_typosquats(_pkgs("lodahs"),
                                            intel=_Intel(available=False))
        self.assertEqual(findings, [])
        self.assertFalse(stats["catalog_available"])


class TestFuzzyCheck(unittest.TestCase):

    POPULAR = {"lodash", "express", "react-dom", "chalk", "webpack", "typescript"}

    def test_off_by_default(self):
        findings, stats = detect_typosquats(_pkgs("lodashh"), intel=_Intel(),
                                            popular=self.POPULAR)
        self.assertEqual(findings, [])
        self.assertFalse(stats["fuzzy_enabled"])

    def test_one_edit_is_flagged_when_enabled(self):
        findings, stats = detect_typosquats(_pkgs("lodashh"), intel=_Intel(),
                                            fuzzy_enabled=True,
                                            popular=self.POPULAR)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["advisory_id"], "typosquat-of-lodash")
        self.assertEqual(findings[0]["severity"], "low")
        self.assertEqual(stats["fuzzy_hits"], 1)

    def test_the_popular_package_itself_is_not_flagged(self):
        findings, _ = detect_typosquats(_pkgs("lodash"), intel=_Intel(),
                                        fuzzy_enabled=True, popular=self.POPULAR)
        self.assertEqual(findings, [])

    def test_short_names_are_skipped(self):
        """1-2 edits reaches half the registry at 2-3 characters."""
        short = "ab" * 2  # 4 chars, below MIN_NAME_LEN
        self.assertLess(len(short), MIN_NAME_LEN)
        findings, _ = detect_typosquats(_pkgs(short), intel=_Intel(),
                                        fuzzy_enabled=True,
                                        popular={"abcd", "abce"})
        self.assertEqual(findings, [])

    def test_unrelated_name_is_not_flagged(self):
        findings, _ = detect_typosquats(_pkgs("my-internal-utils"), intel=_Intel(),
                                        fuzzy_enabled=True, popular=self.POPULAR)
        self.assertEqual(findings, [])

    def test_duplicate_names_are_checked_once(self):
        findings, stats = detect_typosquats(
            _pkgs("lodashh") + _pkgs("lodashh"), intel=_Intel(),
            fuzzy_enabled=True, popular=self.POPULAR)
        self.assertEqual(len(findings), 1)
        self.assertEqual(stats["checked"], 1)


class TestPopularList(unittest.TestCase):

    def test_the_baked_in_list_loads(self):
        names = load_popular_names()
        self.assertGreater(len(names), 100,
                           "the baked-in npm_popular.txt did not load")
        self.assertIn("lodash", names)
        self.assertIn("express", names)

    def test_comments_and_blanks_are_ignored(self):
        names = load_popular_names()
        self.assertFalse(any(n.startswith("#") for n in names))
        self.assertFalse(any(not n.strip() for n in names))

    def test_missing_file_disables_rather_than_raises(self):
        names = load_popular_names(path="/nonexistent/npm_popular.txt")
        self.assertEqual(names, set())


class TestFalsePositiveCeiling(unittest.TestCase):
    """The number that decides whether D is shippable.

    Every popular name is 0 edits from itself, but pairs of DIFFERENT popular
    names that sit within the threshold are exactly the shape of a false
    positive: a real, legitimate package that would be reported as a squat of
    its neighbour. Asserted as a ceiling so widening the list or the threshold
    cannot quietly make the check noisy.
    """

    MAX_COLLIDING_PAIRS = 12

    def test_popular_names_do_not_collide_with_each_other(self):
        names = sorted(n for n in load_popular_names() if len(n) >= MIN_NAME_LEN)
        collisions = []
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                if levenshtein_within(a, b) <= MAX_EDIT_DISTANCE:
                    collisions.append((a, b))
        self.assertLessEqual(
            len(collisions), self.MAX_COLLIDING_PAIRS,
            "too many near-identical entries in npm_popular.txt; each one is a "
            "legitimate package that would be flagged as a squat of its "
            "neighbour: {}".format(collisions))

    def test_real_packages_are_not_flagged_against_the_real_list(self):
        # A sample of legitimate names that are NOT in the list and should not
        # look like a squat of anything in it.
        legit = ["my-company-design-system", "internal-auth-client",
                 "acme-widgets", "telemetry-collector", "feature-flags-sdk"]
        findings, _ = detect_typosquats(_pkgs(*legit), intel=_Intel(),
                                        fuzzy_enabled=True)
        self.assertEqual(
            findings, [],
            "legitimate internal-looking names were flagged: {}".format(
                [f["name"] for f in findings]))


if __name__ == "__main__":
    unittest.main()
