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
# The lane has a SECOND response shape: when the memory governor refuses to admit
# the analyzer container, the orchestrator raises HTTPException(409, detail=<typed
# limit payload>), which FastAPI serialises as {"detail": {...}} - not a
# GuarddogResult. The agent must be able to read it to tell a TRANSIENT refusal
# ("retry when a scan finishes") from a real failure, so `detail` is legitimate,
# but only on the error branch (asserted below).
ERROR_ENVELOPE_FIELDS = {"detail"}
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


class RefusalPayloadContract(unittest.TestCase):
    """The lane has a second response shape and it crosses the same three
    services: the ledger builds the payload, FastAPI wraps it as {"detail": ...},
    and the agent reads fields out of it to decide whether to retry. Nothing else
    ties those names together, so a rename in AdmissionResult.payload() would
    leave the agent silently reading None and reporting the wrong cause."""

    def setUp(self):
        self.ledger = _read("recon_orchestrator", "admission_ledger.py")
        self.tool = _read("agentic", "supply_chain_tools.py")

    def _payload_keys(self):
        """Keys of the dict AdmissionResult.payload() returns, via AST."""
        tree = ast.parse(self.ledger)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "payload":
                ret = next(n for n in ast.walk(node)
                           if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict))
                return {k.value for k in ret.value.keys if isinstance(k, ast.Constant)}
        raise AssertionError("AdmissionResult.payload() not found")

    def test_agent_only_reads_fields_the_ledger_actually_emits(self):
        emitted = self._payload_keys()
        # Fields the agent pulls off the nested limit dict.
        read = set(re.findall(r"limit\.get\([\"'](\w+)[\"']", self.tool))
        self.assertTrue(read, "agent reads no fields off the limit payload?")
        self.assertTrue(read <= emitted,
                        "agent reads limit fields the ledger never emits: "
                        "{}".format(read - emitted))

    def test_the_limit_type_values_the_agent_branches_on_are_real(self):
        # The agent picks its wording from limitType; both values must exist.
        for value in ("hard", "ram"):
            self.assertIn('limit_type="{}"'.format(value), self.ledger,
                          "agent branches on a limitType the ledger never sets")

    def test_orchestrator_returns_the_payload_on_the_guarddog_route(self):
        api = _read("recon_orchestrator", "api.py")
        guarddog = api[api.find("def supply_chain_guarddog"):][:1200]
        self.assertIn("_value_error_http", guarddog,
                      "guarddog route does not map AdmissionError to the typed 409")
        self.assertIn("e.result.payload()", api)

    def test_webapp_passes_the_status_code_through(self):
        route = _read("webapp", "src", "app", "api", "internal", "supply-chain",
                      "guarddog", "route.ts")
        self.assertIn("status: response.status", route,
                      "webapp flattens the orchestrator status; a 409 would reach "
                      "the agent as 200 and read as a result")


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
        allowed = RESULT_FIELDS | ERROR_ENVELOPE_FIELDS
        self.assertTrue(
            read <= allowed,
            "agent reads response keys neither the result model nor the error "
            "envelope defines: {}".format(read - allowed))

    def test_error_envelope_is_read_only_on_the_refusal_branch(self):
        """`detail` must not leak into the success path: there it would silently
        read a key GuarddogResult does not define. Guarded by requiring the 409
        status check to appear before any `detail` read."""
        for field in ERROR_ENVELOPE_FIELDS:
            idx = self.tool.find('data.get("{}")'.format(field))
            if idx < 0:
                continue
            guard = self.tool.find("status_code == 409")
            self.assertGreater(guard, -1, "no 409 branch guards the error envelope")
            self.assertLess(guard, idx, "{} is read before the 409 check".format(field))

    def test_refusal_is_surfaced_as_retryable(self):
        """A memory refusal is TRANSIENT. Told only 'HTTP 409' an agent concludes
        the tool is broken and stops using it; it must also be told the package
        was NOT analysed, so a refusal never reads as a clean verdict."""
        self.assertIn("status_code == 409", self.tool)
        window = self.tool[self.tool.find("status_code == 409"):][:800]
        self.assertRegex(window, r"(?i)retry")
        self.assertRegex(window, r"(?i)not (be )?(analyzed|analysed)")

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
