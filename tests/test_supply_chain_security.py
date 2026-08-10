"""Phase 0.5 security gate tests (the feature's real acceptance tests).

Covers the controls that do NOT need a live Docker daemon:
  - S1 no-install invariant: a grep over supply-chain source fails if any
    package-manager install/resolve command appears.
  - S6/S7 injection-name fuzz: sanitize_name rejects shell/path payloads.
  - S5 boundary: validate_artifact caps/rejects oversized + hostile artifacts.

The Docker-posture assertions (sandbox cap_drop/read_only/isolated-net/no-secrets)
and the broker allow/deny case run against a live daemon and live in the
orchestrator test suite added with Phase 0.5c wiring.

Run: python -m unittest tests.test_supply_chain_security
"""

import os
import re
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from supply_chain_common.security import (
    sanitize_name, sanitize_version, SanitizeError,
    validate_artifact, ArtifactError,
    ARTIFACT_SCHEMA_VERSION, MAX_PACKAGES, MAX_STRING_LEN,
)


class TestReviewRegressions(unittest.TestCase):
    """Named regression tests for bugs found in the deep-review pass."""

    def _base(self, **o):
        a = {"schema_version": ARTIFACT_SCHEMA_VERSION, "mode": "lockfile",
             "packages": [], "malicious": [], "vulnerable": [],
             "suspicious": [], "errors": []}
        a.update(o)
        return a

    def test_F1_boundary_rejects_hostile_purl_version_ecosystem(self):
        # F1: validate_artifact must charset-check purl/version/ecosystem/advisory,
        # not only `name`, or a compromised analyzer smuggles path/shell chars.
        hostile = [
            {"packages": [{"name": "lodash", "purl": "pkg:npm/../../etc/passwd"}]},
            {"packages": [{"name": "lodash", "purl": "pkg:npm/x; rm -rf"}]},
            {"packages": [{"name": "lodash", "version": "1;rm -rf /"}]},
            {"packages": [{"name": "lodash", "ecosystem": "npm|evil"}]},
            {"malicious": [{"name": "lodash", "advisory_id": "MAL-1;id"}]},
            {"suspicious": [{"name": "lodash", "rule": "npm|evil"}]},
        ]
        for h in hostile:
            with self.assertRaises(ArtifactError, msg=repr(h)):
                validate_artifact(self._base(**h))

    def test_F1_valid_purl_still_accepted(self):
        # percent-encoded scoped purl (%40) and crates.io ecosystem must pass.
        out = validate_artifact(self._base(packages=[{
            "name": "core", "purl": "pkg:npm/%40angular/core@12.0.0",
            "version": "12.0.0", "ecosystem": "crates.io"}]))
        self.assertEqual(len(out["packages"]), 1)

    def test_F2_trailing_newline_rejected(self):
        # F2: `$` anchor let "evil\n" through; `\Z` fixes it.
        for bad in ["evil\n", "evil\r", "pkg\n"]:
            with self.assertRaises(SanitizeError):
                sanitize_name(bad)
        with self.assertRaises(SanitizeError):
            sanitize_version("1.0.0\n")

    def test_F6_non_list_aliases_coerced(self):
        # F6: a string aliases must become a list, never a bare string downstream.
        out = validate_artifact(self._base(
            malicious=[{"name": "x", "aliases": "GHSA-1"}]))
        self.assertEqual(out["malicious"][0]["aliases"], ["GHSA-1"])

# Directories/files that make up the supply-chain feature. Extend as phases add
# code; the no-install grep must cover every supply-chain source tree.
_SUPPLY_CHAIN_PATHS = [
    os.path.join("scanners", "supply_chain_common"),
    os.path.join("scanners", "supply_chain_scan"),       # Phase 2 (may not exist yet)
    os.path.join("scanners", "supply_chain_analyzer"),   # Phase 0.5 (may not exist yet)
    os.path.join("recon", "helpers", "supply_chain"),        # Phase 3
    os.path.join("recon", "main_recon_modules", "supply_chain_recon.py"),
    os.path.join("recon", "partial_recon_modules", "supply_chain.py"),
]

# Commands that would resolve/install a target-derived manifest and thereby run
# lifecycle scripts (postinstall, setup.py) = arbitrary code execution (S1).
_FORBIDDEN_INSTALL = re.compile(
    r"\b(npm\s+(install|ci)|yarn\s+install|pnpm\s+install|"
    r"pip\s+install|pip3\s+install|poetry\s+install|"
    r"bundle\s+install|gem\s+install|"
    r"mvn\s+(install|package|compile)|gradle\s+\w|"
    r"go\s+get|cargo\s+build|composer\s+install)\b"
)

# Lines that legitimately contain the words (comments explaining the ban, the
# regex above, seed-manifest content). Skip lines carrying this marker.
_ALLOW_MARKER = "no-install-ok"


class TestNoInstallInvariant(unittest.TestCase):
    def test_no_package_manager_install_in_supply_chain_source(self):
        offenders = []
        for rel in _SUPPLY_CHAIN_PATHS:
            path = os.path.join(_REPO, rel)
            if os.path.isfile(path):
                offenders += self._scan_file(path)
            elif os.path.isdir(path):
                for root, _dirs, files in os.walk(path):
                    if "__pycache__" in root:
                        continue
                    for fn in files:
                        if fn.endswith((".py", ".sh", ".js", ".ts")):
                            offenders += self._scan_file(os.path.join(root, fn))
        self.assertEqual(
            offenders, [],
            "S1 no-install invariant violated (found package-manager install/"
            "resolve commands):\n" + "\n".join(offenders))

    def _scan_file(self, path):
        hits = []
        try:
            with open(path, "r", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    if _ALLOW_MARKER in line:
                        continue
                    if _FORBIDDEN_INSTALL.search(line):
                        hits.append("{}:{}: {}".format(
                            os.path.relpath(path, _REPO), i, line.strip()[:120]))
        except OSError:
            pass
        return hits


class TestInjectionNameFuzz(unittest.TestCase):
    HOSTILE = [
        "; id", "$(whoami)", "`id`", "a|b", "a&&b", "a;b", "a>b", "a<b",
        "../../etc/passwd", "@scope/../../x", "..\\..\\win", "/etc/shadow",
        "-rf", "--force", "name with space", "name\nwith\nnewline",
        "pkg$IFS$9", "pkg\t", "\u202eRTL", "a\x00b", "a" * 1000,
        "$(curl evil)", "pkg;rm -rf /", "@a/$(x)",
    ]

    def test_all_hostile_names_rejected(self):
        for bad in self.HOSTILE:
            with self.assertRaises(SanitizeError, msg="not rejected: {!r}".format(bad)):
                sanitize_name(bad)

    def test_never_mutates_a_valid_name(self):
        # sanitize is a validator, not a transformer: a valid name comes back
        # byte-identical (a silent rewrite would scan the wrong package).
        for good in ["@angular/core", "flask-login", "left_pad"]:
            self.assertEqual(sanitize_name(good), good)


class TestArtifactSchemaFuzz(unittest.TestCase):
    def _base(self, **over):
        art = {"schema_version": ARTIFACT_SCHEMA_VERSION, "mode": "lockfile",
               "packages": [], "malicious": [], "vulnerable": [],
               "suspicious": [], "errors": []}
        art.update(over)
        return art

    def test_valid_artifact_passes(self):
        art = self._base(
            packages=[{"purl": "pkg:npm/lodash@4.17.21", "name": "lodash",
                       "version": "4.17.21", "ecosystem": "npm", "source": "lockfile"}],
            malicious=[{"purl": "pkg:npm/lodahs@1.0.0", "name": "lodahs",
                        "advisory_id": "MAL-2025-25502", "severity": "high",
                        "confidence": "malicious", "title": "bad"}])
        out = validate_artifact(art)
        self.assertEqual(len(out["packages"]), 1)
        self.assertEqual(len(out["malicious"]), 1)

    def test_unknown_top_level_field_rejected(self):
        with self.assertRaises(ArtifactError):
            validate_artifact(self._base(evil="payload"))

    def test_wrong_schema_version_rejected(self):
        with self.assertRaises(ArtifactError):
            validate_artifact(self._base(schema_version=999))

    def test_oversized_array_truncated_not_dropped(self):
        # F4 regression: an oversized array is TRUNCATED to the cap (blast radius
        # still bounded) and the loss recorded in errors - NOT rejected whole,
        # which would silently drop a MAL- verdict anywhere in the list.
        huge = [{"name": "p{}".format(i)} for i in range(MAX_PACKAGES + 5)]
        out = validate_artifact(self._base(packages=huge))
        self.assertEqual(len(out["packages"]), MAX_PACKAGES)
        self.assertTrue(any("packages truncated" in e for e in out["errors"]))

    def test_oversized_string_is_capped_not_stored_whole(self):
        art = self._base(packages=[{"name": "lodash", "title": "x" * (MAX_STRING_LEN * 4)}])
        # 'title' is not a package field -> unknown-field rejection.
        with self.assertRaises(ArtifactError):
            validate_artifact(art)
        # A cappable field on a finding is truncated, never stored whole.
        art2 = self._base(malicious=[{"name": "lodash", "detail": "y" * (MAX_STRING_LEN * 4)}])
        out = validate_artifact(art2)
        self.assertLessEqual(len(out["malicious"][0]["detail"]), MAX_STRING_LEN)

    def test_hostile_name_in_artifact_rejected(self):
        # A hostile package name inside the analyzer output rejects the whole
        # artifact at the boundary (SanitizeError is converted to ArtifactError).
        for bad in ["$(id)", "; rm -rf /", "../../../etc/passwd"]:
            with self.assertRaises(ArtifactError):
                validate_artifact(self._base(packages=[{"name": bad}]))

    def test_xss_payload_survives_as_data_only(self):
        # An XSS/prompt-injection string in a cappable text field is NOT rejected
        # here (it is neutralized at the HTML/LLM sink); it must round-trip as
        # inert data, capped, with no field promotion.
        art = self._base(malicious=[{"name": "lodash",
                                     "title": "<img src=x onerror=alert(1)>"}])
        out = validate_artifact(art)
        self.assertEqual(out["malicious"][0]["title"], "<img src=x onerror=alert(1)>")

    def test_non_dict_rejected(self):
        for bad in [None, [], "str", 5]:
            with self.assertRaises(ArtifactError):
                validate_artifact(bad)


if __name__ == "__main__":
    unittest.main()
