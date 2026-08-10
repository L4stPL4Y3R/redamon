"""Neo4j connection for the AI Attack Surface spine.

Uses the bare `neo4j` driver (env-configured) rather than the full graph_db
mixin stack: the spine writes a small, fixed set of node/edge shapes that already
exist in the schema, so it stays self-contained and trivially testable. The
Cypher mirrors the conventions used by ai_surface_recon (tenant keys user_id +
project_id, HAS_VULNERABILITY linkage with BaseURL->Subdomain->Domain fallback).
"""
from __future__ import annotations

import logging
import os
from contextlib import contextmanager

from neo4j import GraphDatabase

logger = logging.getLogger("ai-attack-surface")


def make_driver(uri: str | None = None, user: str | None = None, password: str | None = None):
    uri = uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = user or os.environ.get("NEO4J_USER", "neo4j")
    password = password or os.environ.get("NEO4J_PASSWORD", "")
    return GraphDatabase.driver(uri, auth=(user, password))


@contextmanager
def graph_session(driver=None):
    """Yield a session, owning the driver if we created it."""
    own = driver is None
    driver = driver or make_driver()
    try:
        with driver.session() as session:
            yield session
    finally:
        if own:
            driver.close()


def verify_connection(driver) -> bool:
    try:
        with driver.session() as session:
            return session.run("RETURN 1 AS ok").single()["ok"] == 1
    except Exception as e:
        logger.error(f"Neo4j connection failed: {e}")
        return False
