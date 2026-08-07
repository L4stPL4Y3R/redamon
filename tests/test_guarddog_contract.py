"""Cross-layer CONTRACT for the L3 GuardDog dispatch lane.

    agent (supply_chain_tools.py)
      -> webapp (api/internal/supply-chain/guarddog/route.ts)
        -> orchestrator (models.py GuarddogRequest/Result + container_manager)

Each hop is a separate file in a separate service that is deployed and tested
independently, so nothing but this test ties their JSON field names together. A
rename on one side (e.g. issues -> issue_count) would otherwise pass every
per-layer test and silently break the lane at runtime. This asserts the request
triple and the result quadruple are identical end to end.

Pure source inspection (ast + regex): no imports, no pydantic, no docker, no
network - safe to run anywhere.

Run: python -m unittest tests.test_guarddog_contract
"""

import ast
import os
import re
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REQUEST_FIELDS = {"ecosystem", "name", "version"}
RESULT_FIELDS = {"issues", "rules_fired", "errors", "error"}
ECOSYSTEMS = {"npm", "pypi", "go", "crates", "rubygems", "github_action", "extension"}


def _read(*parts):
    with open(os.path.join(_REPO, *parts)) as fh:
        return fh.read()


def _pydantic_fields(source, classname):
    """Annotated field names of a BaseModel class, via AST."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == classname:
            return {n.target.id for n in node.body
                    if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)}
    raise AssertionError("class {} not found".format(classname))


class OrchestratorModelContract(unittest.TestCase):
    def setUp(self):
        self.models = _read("recon_orchestrator", "models.py")

    def test_request_model_is_the_agreed_triple(self):
        self.assertEqual(_pydantic_fields(self.models, "GuarddogRequest"), REQUEST_FIELDS)

    def test_result_model_is_the_agreed_quadruple(self):
        self.assertEqual(_pydantic_fields(self.models, "GuarddogResult"), RESULT_FIELDS)


class OrchestratorReturnContract(unittest.TestCase):
    """run_guarddog_package must return every RESULT_FIELDS key on EVERY path,
    or GuarddogResult(**result) raises / drops data."""
    def setUp(self):
        self.cm = _read("recon_orchestrator", "container_manager.py")

    def test_method_exists(self):
        self.assertIn("def run_guarddog_package", self.cm)

    def test_every_return_dict_carries_all_result_fields(self):
        # AST, not regex: return dicts contain nested {} (e.g. `or {}`) that a
        # brace regex would truncate. Walk the function's `return {..}` literals.
        tree = ast.parse(self.cm)
        fn = next((n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "run_guarddog_package"), None)
        self.assertIsNotNone(fn, "run_guarddog_package not found")
        dict_returns = [n.value for n in ast.walk(fn)
                        if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict)]
        self.assertGreaterEqual(len(dict_returns), 3, "expected several return dicts")
        for d in dict_returns:
            keys = {k.value for k in d.keys if isinstance(k, ast.Constant)}
            self.assertEqual(
                keys, RESULT_FIELDS,
                "a run_guarddog_package return dict is missing result fields: "
                "{}".format(RESULT_FIELDS - keys))


class AgentToolContract(unittest.TestCase):
    def setUp(self):
        self.tool = _read("agentic", "supply_chain_tools.py")

    def test_posts_exactly_the_request_triple(self):
        m = re.search(r"json=\{(.*?)\}", self.tool, re.S)
        self.assertIsNotNone(m)
        keys = set(re.findall(r"[\"'](\w+)[\"']\s*:", m.group(1)))
        self.assertEqual(keys, REQUEST_FIELDS)

    def test_reads_only_result_fields_from_the_response(self):
        read = set(re.findall(r"data\.get\([\"'](\w+)[\"']", self.tool))
        self.assertTrue(read, "tool reads no fields?")
        self.assertTrue(
            read <= RESULT_FIELDS,
            "agent reads response keys the result model does not define: "
            "{}".format(read - RESULT_FIELDS))

    def test_ecosystems_match(self):
        m = re.search(r"_ECOSYSTEMS\s*=\s*\{(.*?)\}", self.tool, re.S)
        self.assertIsNotNone(m)
        ecos = set(re.findall(r"[\"'](\w+)[\"']", m.group(1)))
        self.assertEqual(ecos, ECOSYSTEMS)

    def test_endpoint_path_matches_the_webapp_route(self):
        self.assertIn("/api/internal/supply-chain/guarddog", self.tool)


class WebappRouteContract(unittest.TestCase):
    def setUp(self):
        self.route = _read("webapp", "src", "app", "api", "internal",
                           "supply-chain", "guarddog", "route.ts")

    def test_forwards_exactly_the_request_triple(self):
        m = re.search(r"JSON\.stringify\(\{(.*?)\}\)", self.route, re.S)
        self.assertIsNotNone(m)
        keys = set(re.findall(r"\b(ecosystem|name|version)\b", m.group(1)))
        self.assertEqual(keys, REQUEST_FIELDS)

    def test_ecosystems_match(self):
        m = re.search(r"ECOSYSTEMS\s*=\s*new Set\(\[(.*?)\]\)", self.route, re.S)
        self.assertIsNotNone(m)
        ecos = set(re.findall(r"[\"'](\w+)[\"']", m.group(1)))
        self.assertEqual(ecos, ECOSYSTEMS)

    def test_targets_the_orchestrator_guarddog_endpoint(self):
        self.assertIn("/supply-chain/guarddog", self.route)


class CharsetGateParity(unittest.TestCase):
    """All three layers must forbid a leading '-' (flag smuggle) identically."""
    def _leading_class(self, pattern):
        # The bracket class immediately after the ^ anchor.
        m = re.match(r"\^\[([^\]]*)\]", pattern)
        return m.group(1) if m else None

    def test_all_three_gates_share_one_leading_char_class(self):
        tool = _read("agentic", "supply_chain_tools.py")
        cm = _read("recon_orchestrator", "container_manager.py")
        route = _read("webapp", "src", "app", "api", "internal",
                      "supply-chain", "guarddog", "route.ts")
        pats = {
            "agent": re.search(r"_SAFE\s*=\s*re\.compile\(r[\"'](.*?)[\"']\)", tool).group(1),
            "orchestrator": re.search(r"_GUARDDOG_SAFE\s*=\s*re\.compile\(r[\"'](.*?)[\"']\)", cm).group(1),
            "webapp": re.search(r"SAFE\s*=\s*/(.*?)/", route).group(1),
        }
        classes = {name: self._leading_class(p) for name, p in pats.items()}
        # Identical across layers, and exactly the alnum-or-@ set (no leading '-').
        for name, cls in classes.items():
            self.assertEqual(cls, "A-Za-z0-9@",
                             "{} leading char class drifted: {!r}".format(name, cls))

    def test_python_gates_actually_reject_a_leading_dash(self):
        # Behavioural, not just textual: compile the two Python patterns and prove
        # they reject "--help" / "-rf" but accept a scoped npm name.
        tool = _read("agentic", "supply_chain_tools.py")
        cm = _read("recon_orchestrator", "container_manager.py")
        for src, var in ((tool, r"_SAFE\s*=\s*re\.compile\(r[\"'](.*?)[\"']\)"),
                         (cm, r"_GUARDDOG_SAFE\s*=\s*re\.compile\(r[\"'](.*?)[\"']\)")):
            rx = re.compile(re.search(var, src).group(1))
            self.assertIsNone(rx.match("--help"))
            self.assertIsNone(rx.match("-rf"))
            self.assertIsNotNone(rx.match("@angular/core"))
            self.assertIsNotNone(rx.match("event-stream"))  # internal dash is fine


if __name__ == "__main__":
    unittest.main()
