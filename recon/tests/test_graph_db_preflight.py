"""Issue #169 - unit tests for the graph_db bind-mount preflight.

When the orchestrator binds the wrong host path over /app/graph_db, Docker
auto-creates an EMPTY directory and mounts it over the copy baked into the scan
image. Python then imports `graph_db` as an empty NAMESPACE package (a package
object with `__path__` but no `__file__`) and the scan dies later with the
opaque `cannot import name 'Neo4jClient' from 'graph_db' (unknown location)`.

These tests build that exact condition on disk (a directory with no
`__init__.py`) rather than mocking it, so they fail if the namespace-package
signal ever stops being the thing that distinguishes a bad mount.

Run with: python -m pytest recon/tests/test_graph_db_preflight.py -v
"""
import os
import sys
import shutil
import tempfile
import unittest
from unittest.mock import patch

_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_project_root = os.path.dirname(_recon_dir)
for _p in (_project_root, _recon_dir):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.graph_db_preflight import (  # noqa: E402
    check_graph_db,
    require_graph_db,
    warn_if_graph_db_unusable,
)

_REAL_GRAPH_DB = os.path.join(_project_root, "graph_db")


class _FakeGraphDb:
    """Put a synthetic `graph_db` at the FRONT of sys.path and force a re-import.

    `flavour`:
      empty_dir  - directory, no __init__.py  -> namespace package (the bug)
      absent     - nothing at all             -> ImportError
      broken     - __init__.py that imports a module that does not exist
      good       - __init__.py exporting a Neo4jClient
    """

    def __init__(self, flavour):
        self.flavour = flavour

    def __enter__(self):
        self.tmp = tempfile.mkdtemp(prefix="gdb-preflight-")
        pkg = os.path.join(self.tmp, "graph_db")
        if self.flavour != "absent":
            os.makedirs(pkg)
        if self.flavour == "broken":
            with open(os.path.join(pkg, "__init__.py"), "w") as f:
                f.write("from .nope import Neo4jClient\n")
        elif self.flavour == "good":
            with open(os.path.join(pkg, "__init__.py"), "w") as f:
                f.write("class Neo4jClient:\n    pass\n")

        self._saved_path = list(sys.path)
        self._saved_modules = {k: v for k, v in sys.modules.items()
                               if k == "graph_db" or k.startswith("graph_db.")}
        for k in self._saved_modules:
            del sys.modules[k]
        # 'absent' must not fall through to the repo's real graph_db.
        sys.path[:] = ([self.tmp] +
                       [p for p in sys.path
                        if os.path.abspath(p or ".") != os.path.abspath(_project_root)])
        sys.path_importer_cache.clear()
        return self

    def __exit__(self, *exc):
        sys.path[:] = self._saved_path
        for k in [k for k in sys.modules
                  if k == "graph_db" or k.startswith("graph_db.")]:
            del sys.modules[k]
        sys.modules.update(self._saved_modules)
        sys.path_importer_cache.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)
        return False


class TestCheckGraphDb(unittest.TestCase):
    def test_empty_mount_is_detected_and_named(self):
        """The exact issue #169 condition."""
        with _FakeGraphDb("empty_dir"):
            ok, message = check_graph_db()
        self.assertFalse(ok)
        self.assertIn("EMPTY", message)
        # The message must tell the operator what to do on the HOST.
        self.assertIn("./graph_db:/app/graph_db:ro", message)
        self.assertIn("recon-orchestrator", message)

    def test_empty_mount_would_otherwise_raise_the_reported_importerror(self):
        """Proves the fixture reproduces the real failure, not an approximation."""
        with _FakeGraphDb("empty_dir"):
            with self.assertRaises(ImportError) as cm:
                from graph_db import Neo4jClient  # noqa: F401
        self.assertIn("cannot import name 'Neo4jClient'", str(cm.exception))
        self.assertIn("unknown location", str(cm.exception))

    def test_absent_package_is_reported(self):
        with _FakeGraphDb("absent"):
            ok, message = check_graph_db()
        self.assertFalse(ok)
        self.assertIn("not importable", message)

    def test_present_but_broken_package_is_reported(self):
        with _FakeGraphDb("broken"):
            ok, message = check_graph_db()
        self.assertFalse(ok)
        self.assertIn("Neo4jClient", message)
        # Distinct from the empty-mount diagnosis: do not send the operator to
        # docker-compose when the mount is fine and a dependency is missing.
        self.assertNotIn("EMPTY", message)

    def test_good_package_passes_with_no_message(self):
        with _FakeGraphDb("good"):
            ok, message = check_graph_db()
        self.assertTrue(ok)
        self.assertEqual(message, "")

    def test_never_raises(self):
        for flavour in ("empty_dir", "absent", "broken", "good"):
            with self.subTest(flavour=flavour), _FakeGraphDb(flavour):
                check_graph_db()

    @unittest.skipUnless(os.path.isfile(os.path.join(_REAL_GRAPH_DB, "__init__.py")),
                         "repo graph_db not present")
    def test_repo_graph_db_is_not_a_namespace_package(self):
        """Guards the packaging half: graph_db must keep a real __init__.py."""
        import importlib.util
        spec = importlib.util.find_spec("graph_db") if "graph_db" in sys.modules else None
        del spec  # only the on-disk fact matters here
        self.assertTrue(os.path.isfile(os.path.join(_REAL_GRAPH_DB, "__init__.py")))


class TestRequireGraphDb(unittest.TestCase):
    def test_exits_nonzero_on_empty_mount(self):
        with _FakeGraphDb("empty_dir"):
            with self.assertRaises(SystemExit) as cm:
                require_graph_db("Partial Recon")
        self.assertEqual(cm.exception.code, 1)

    def test_returns_quietly_when_healthy(self):
        with _FakeGraphDb("good"):
            with patch("builtins.print") as p:
                require_graph_db("Partial Recon")
        p.assert_not_called()

    def test_failure_message_is_printed_with_context(self):
        with _FakeGraphDb("empty_dir"):
            with patch("builtins.print") as p:
                with self.assertRaises(SystemExit):
                    require_graph_db("Partial Recon")
        out = " ".join(str(c.args[0]) for c in p.call_args_list)
        self.assertIn("Partial Recon", out)
        self.assertIn("preflight FAILED", out)


class TestWarnIfGraphDbUnusable(unittest.TestCase):
    def test_full_recon_warns_loudly_but_does_not_exit(self):
        with _FakeGraphDb("empty_dir"):
            with patch("builtins.print") as p:
                ok = warn_if_graph_db_unusable("Pipeline")
        self.assertFalse(ok)
        out = " ".join(str(c.args[0]) for c in p.call_args_list)
        self.assertIn("NO results will reach the graph", out)

    def test_silent_when_healthy(self):
        with _FakeGraphDb("good"):
            with patch("builtins.print") as p:
                ok = warn_if_graph_db_unusable("Pipeline")
        self.assertTrue(ok)
        p.assert_not_called()


if __name__ == "__main__":
    unittest.main()
