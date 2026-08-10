"""Unit tests for the Neo4j connection wrapper (graph.py), driver mocked."""
import os
import unittest
from unittest.mock import MagicMock, patch

import graph


class TestVerifyConnection(unittest.TestCase):
    def test_true_when_query_returns_one(self):
        driver = MagicMock()
        session = driver.session.return_value.__enter__.return_value
        session.run.return_value.single.return_value = {"ok": 1}
        self.assertTrue(graph.verify_connection(driver))

    def test_false_on_exception(self):
        driver = MagicMock()
        driver.session.side_effect = RuntimeError("unreachable")
        self.assertFalse(graph.verify_connection(driver))


class TestMakeDriver(unittest.TestCase):
    def test_reads_env_and_builds_driver(self):
        with patch.dict(os.environ, {
            "NEO4J_URI": "bolt://example:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "secret",
        }), patch.object(graph, "GraphDatabase") as gdb:
            graph.make_driver()
            gdb.driver.assert_called_once_with("bolt://example:7687", auth=("neo4j", "secret"))

    def test_explicit_args_override_env(self):
        with patch.object(graph, "GraphDatabase") as gdb:
            graph.make_driver(uri="bolt://x:1", user="u", password="p")
            gdb.driver.assert_called_once_with("bolt://x:1", auth=("u", "p"))

    def test_graph_session_closes_owned_driver(self):
        fake_driver = MagicMock()
        with patch.object(graph, "make_driver", return_value=fake_driver):
            with graph.graph_session() as s:
                self.assertIsNotNone(s)
        fake_driver.close.assert_called_once()

    def test_graph_session_does_not_close_borrowed_driver(self):
        borrowed = MagicMock()
        with graph.graph_session(driver=borrowed):
            pass
        borrowed.close.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
