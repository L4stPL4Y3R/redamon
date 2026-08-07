"""Every tool the kali MCP servers expose must be in SYSTEM_MCP_TOOL_NAMES.

The regression this guards against, seen live 2026-08-07: execute_osv_scanner
and execute_guarddog were defined with @mcp.tool() in network_recon_server.py
AND advertised to the LLM by the prompt tool table, but were absent from
tools.SYSTEM_MCP_TOOL_NAMES. register_mcp_tools() filters any tool not in a
user manifest UNLESS it is a system tool, so both were silently dropped
("Skipped registering 2 MCP tool(s) not declared in any manifest") while the
model kept planning with them - every call returned "Tool 'X' not found".

The two lists are edited in different files (mcp/servers/*.py vs agentic/
tools.py), so nothing but this test ties them together. It parses the servers
with AST (no import of the server deps needed) and fails on any @mcp.tool()
name missing from the allowlist.

Run: python tests/test_system_mcp_tool_coverage.py
"""

import ast
import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))


def _servers_dir():
    """mcp/servers as mounted in the agent test container (/mcp) or in the repo."""
    for cand in (Path("/mcp/servers"),
                 _AGENTIC_DIR.parent / "mcp" / "servers"):
        if cand.is_dir():
            return cand
    return None


def _mcp_tool_defs(py_file):
    """Names of every function decorated with @mcp.tool() in one server file."""
    tree = ast.parse(py_file.read_text(), filename=str(py_file))
    names = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            # matches @mcp.tool() and @mcp.tool
            call = dec.func if isinstance(dec, ast.Call) else dec
            if (isinstance(call, ast.Attribute) and call.attr == "tool"
                    and isinstance(call.value, ast.Name) and call.value.id == "mcp"):
                names.append(node.name)
    return names


class SystemMcpToolCoverageTests(unittest.TestCase):

    def setUp(self):
        self.servers = _servers_dir()
        if self.servers is None:
            self.skipTest("mcp/servers not mounted (host run without /mcp)")

    def _all_server_tools(self):
        found = {}
        for py in sorted(self.servers.glob("*.py")):
            for name in _mcp_tool_defs(py):
                found[name] = py.name
        return found

    def test_every_server_tool_is_in_the_allowlist(self):
        from tools import SYSTEM_MCP_TOOL_NAMES
        server_tools = self._all_server_tools()
        self.assertTrue(server_tools, "parsed zero @mcp.tool() defs - parser broken?")
        missing = {n: f for n, f in server_tools.items()
                   if n not in SYSTEM_MCP_TOOL_NAMES}
        self.assertEqual(missing, {},
                         "system MCP tools missing from tools.SYSTEM_MCP_TOOL_NAMES "
                         "(they will be silently dropped at registration): "
                         + ", ".join("{} ({})".format(n, f) for n, f in missing.items()))

    def test_osv_scanner_is_a_covered_kali_mcp_tool(self):
        """Named explicitly so the exact 2026-08-07 regression (a Kali MCP tool
        advertised but not in the allowlist -> silently dropped) can never recur
        even if the AST parser above is ever weakened. execute_osv_scanner is
        passive/offline and legitimately lives in Kali."""
        from tools import SYSTEM_MCP_TOOL_NAMES
        self.assertIn("execute_osv_scanner", SYSTEM_MCP_TOOL_NAMES)

    def test_guarddog_is_NOT_a_kali_mcp_tool(self):
        """execute_guarddog dispatches the attacker-tarball analyzer, which needs
        the Docker socket the least-trusted Kali worker must never hold. It is an
        AGENT-NATIVE tool on the webapp->orchestrator lane, so it must NOT be a
        Kali MCP server tool nor in the MCP allowlist."""
        from tools import SYSTEM_MCP_TOOL_NAMES
        self.assertNotIn("execute_guarddog", SYSTEM_MCP_TOOL_NAMES)
        self.assertNotIn("execute_guarddog", self._all_server_tools(),
                         "execute_guarddog is still defined as a Kali @mcp.tool()")

    def test_guarddog_is_registered_as_an_agent_native_tool(self):
        """The counterpart guard: it must be discoverable where it now lives."""
        from supply_chain_tools import build_supply_chain_tools
        self.assertIn("execute_guarddog", build_supply_chain_tools())


if __name__ == "__main__":
    unittest.main()
