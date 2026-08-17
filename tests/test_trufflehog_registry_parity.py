"""The two source registries must agree.

`scanners/trufflehog_scan/sources.py` builds the command line;
`webapp/src/lib/trufflehogSources.ts` renders the form and gates the Start
button. They live in different languages and different images, so nothing but a
test stops them drifting — and drift is silent in both directions:

  * a field only in TS is stored in the profile and never passed to the binary;
  * a field only in Python can never be set by an operator;
  * a credential rule that differs means the UI enables Start for a scan the
    orchestrator will refuse (or, worse, disables one that would have worked).

Parsed from the TS source text rather than executed, so this runs in the Python
gate with no Node.
"""

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from trufflehog_scan import sources as reg  # noqa: E402

TS_PATH = REPO_ROOT / "webapp" / "src" / "lib" / "trufflehogSources.ts"


def ts_source() -> str:
    return TS_PATH.read_text()


def ts_source_blocks() -> dict[str, str]:
    """Split TRUFFLEHOG_SOURCES into one text block per source id."""
    text = ts_source()
    start = text.index("export const TRUFFLEHOG_SOURCES")
    end = text.index("export const TRUFFLEHOG_SOURCE_IDS")
    body = text[start:end]

    ids = [m for m in re.finditer(r"^  (\w+): \{$", body, re.M)]
    blocks = {}
    for i, m in enumerate(ids):
        stop = ids[i + 1].start() if i + 1 < len(ids) else len(body)
        blocks[m.group(1)] = body[m.start():stop]
    return blocks


def ts_fields(block: str) -> list[str]:
    return re.findall(r"\{\s*key: '(\w+)'", block)


def ts_credentials(block: str) -> list[str]:
    return re.findall(r"CRED\.(\w+)", block)


class TestSourceParity(unittest.TestCase):
    def setUp(self):
        self.blocks = ts_source_blocks()

    def test_the_same_sources_exist_on_both_sides(self):
        self.assertEqual(sorted(self.blocks), sorted(reg.SOURCES))

    def test_each_source_has_the_same_fields(self):
        for source_id, src in reg.SOURCES.items():
            py = sorted(f.key for f in src.fields)
            ts = sorted(ts_fields(self.blocks[source_id]))
            self.assertEqual(
                py, ts,
                f"{source_id}: python has {set(py) - set(ts)} extra, "
                f"TS has {set(ts) - set(py)} extra",
            )

    def test_each_source_declares_the_same_asset_label(self):
        for source_id, src in reg.SOURCES.items():
            block = self.blocks[source_id]
            match = re.search(r"assetLabel: '(\w+)'", block)
            self.assertIsNotNone(match, f"{source_id} has no assetLabel in TS")
            self.assertEqual(match.group(1), src.asset_label, source_id)

    def test_each_source_declares_the_same_asset_kind(self):
        for source_id, src in reg.SOURCES.items():
            match = re.search(r"assetKind: '(\w+)'", self.blocks[source_id])
            self.assertIsNotNone(match, f"{source_id} has no assetKind in TS")
            self.assertEqual(match.group(1), src.asset_kind, source_id)

    def test_each_source_uses_the_same_credential_settings_keys(self):
        ts_cred_map = dict(re.findall(r"^  (\w+): \{ settingsKey: '(\w+)'", ts_source(), re.M))
        for source_id, src in reg.SOURCES.items():
            py = sorted(c.settings_key for c in src.credentials)
            ts = sorted(ts_cred_map[name] for name in ts_credentials(self.blocks[source_id]))
            self.assertEqual(py, ts, f"{source_id} credential mismatch")

    def test_optional_within_source_flags_match(self):
        ts_optional = {
            key for key, opt in re.findall(
                r"^  \w+: \{ settingsKey: '(\w+)'.*?(optional: true)?\s*\},$",
                ts_source(), re.M)
            if opt
        }
        py_optional = {c.settings_key for c in reg.ALL_CREDENTIALS if c.optional_within_source}
        self.assertEqual(py_optional, ts_optional)

    def test_field_types_match(self):
        for source_id, src in reg.SOURCES.items():
            ts_typed = dict(re.findall(r"\{\s*key: '(\w+)', type: '(\w+)'", self.blocks[source_id]))
            for f in src.fields:
                self.assertIn(f.key, ts_typed, f"{source_id}.{f.key} missing a TS type")
                self.assertEqual(
                    ts_typed[f.key], f.type,
                    f"{source_id}.{f.key}: python says {f.type}, TS says {ts_typed[f.key]}",
                )

    def test_exclude_paths_keeps_its_per_source_type(self):
        """The footgun this parity test exists for: --exclude-paths takes a FILE
        of regexes on the git family and an inline CSV on docker. One shared
        'excludePaths' helper would build a broken command for one of them."""
        for source_id in ("git", "github", "gitlab", "filesystem"):
            self.assertEqual(reg.SOURCES[source_id].field("excludePaths").type, "pathfile")
            self.assertIn("{ key: 'excludePaths', type: 'pathfile'", self.blocks[source_id])
        self.assertEqual(reg.SOURCES["docker"].field("excludePaths").type, "csv")
        self.assertIn("{ key: 'excludePaths', type: 'csv'", self.blocks["docker"])

    def test_filesystem_roots_match(self):
        text = ts_source()
        block = text[text.index("TRUFFLEHOG_FILESYSTEM_ROOTS = ["):]
        block = block[:block.index("]")]
        ts_roots = re.findall(r"\{ value: '(\w+)'", block)
        self.assertEqual(sorted(ts_roots), sorted(reg.FILESYSTEM_ROOTS))

    def test_client_only_fields_match(self):
        """A field marked client-side is never passed to the binary. Marked on
        one side only means either a flag TruffleHog does not have, or an option
        that silently does nothing."""
        for source_id, src in reg.SOURCES.items():
            py = sorted(f.key for f in src.fields if f.client)
            block = self.blocks[source_id]
            ts = sorted(re.findall(r"\{\s*key: '(\w+)'[^}]*?client: true", block))
            self.assertEqual(py, ts, f"{source_id} client-field mismatch")

    def test_no_field_key_can_hold_a_credential(self):
        cred_keys = {c.settings_key.lower() for c in reg.ALL_CREDENTIALS}
        for source_id, block in self.blocks.items():
            for key in ts_fields(block):
                self.assertNotIn(key.lower(), cred_keys)
                # A field named like a secret is the mistake this guards.
                self.assertNotRegex(
                    key, r"(?i)(token|password|secret|apikey)$",
                    f"{source_id}.{key} looks like a credential; those belong on UserSettings",
                )


class TestCredentialGateParity(unittest.TestCase):
    """The `credentialRequired` rules decide whether Start is enabled. If the two
    sides disagree, the UI offers a scan the orchestrator refuses at dispatch."""

    CASES = [
        ("github", {}, True),
        ("github_experimental", {}, True),
        ("gitlab", {}, True),
        ("postman", {}, True),
        ("circleci", {}, True),
        ("travisci", {}, True),
        ("docker", {"images": ["nginx:1.25"]}, False),
        ("docker", {"namespace": "acme"}, True),
        ("docker", {"images": ["a"], "includePrivate": True}, True),
        ("s3", {}, True),
        ("s3", {"cloudEnvironment": True}, False),
        ("gcs", {"projectId": "p"}, True),
        ("gcs", {"withoutAuth": True}, False),
        ("gcs", {"cloudEnvironment": True}, False),
        ("git", {"uri": "https://example.com/a.git"}, False),
        ("git", {"uri": "ssh://git@example.com/a.git"}, True),
        ("jenkins", {}, False),
        ("elasticsearch", {}, False),
        ("huggingface", {}, False),
        ("filesystem", {}, False),
    ]

    def test_python_side_matches_the_documented_matrix(self):
        for source_id, config, expected in self.CASES:
            self.assertEqual(
                reg.credential_required(source_id, config), expected,
                f"{source_id} {config}",
            )

    def test_ts_implements_the_same_rules(self):
        """Structural check of the TS function against the same matrix. Reading
        the source keeps this in the Python gate; the vitest suite exercises the
        function itself."""
        text = ts_source()
        fn = text[text.index("export function trufflehogCredentialRequired"):]
        fn = fn[:fn.index("\n}")]
        always = {"github", "github_experimental", "gitlab", "postman", "circleci", "travisci"}
        for source_id in always:
            self.assertIn(f"'{source_id}'", fn, f"{source_id} missing from the always-required list")
        self.assertIn("cfg.namespace", fn)
        self.assertIn("cfg.includePrivate", fn)
        self.assertIn("cfg.cloudEnvironment", fn)
        self.assertIn("cfg.withoutAuth", fn)
        self.assertIn("ssh://", fn)


if __name__ == "__main__":
    unittest.main()
