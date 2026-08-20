"""
BaseMixin: Neo4j connection lifecycle and project-level data cleanup.

Provides:
- Driver initialization and context manager support
- Schema initialization (called once at startup)
- clear_project_data: wipe all data for a project
- clear_gvm_data: selective GVM data cleanup
"""

import os
from pathlib import Path

from neo4j import GraphDatabase
from dotenv import load_dotenv

from graph_db.schema import (init_schema, GLOBAL_REFERENCE_LABELS,
                            NON_RECON_LABELS, NON_RECON_SOURCES)

# Load environment variables from local .env file
load_dotenv(Path(__file__).parent.parent / ".env")

#: `n:CVE OR n:MitreData OR n:Capec`, built once from the schema's own list so a
#: label added there is covered here too.
_REFERENCE_LABEL_PREDICATE = " OR ".join(
    f"n:`{label}`" for label in GLOBAL_REFERENCE_LABELS)
_REFERENCE_LABEL_PREDICATE_X = " OR ".join(
    f"x:`{label}`" for label in GLOBAL_REFERENCE_LABELS)

#: Longest path inside the reference catalogue itself:
#: CVE -> MitreData -> Capec. The orphan sweep looks this far for a
#: non-reference anchor, so a node deeper in a longer chain would be kept
#: rather than wrongly deleted.
_REFERENCE_CHAIN_DEPTH = 3

#: Every label a recon clear must leave standing: the other scanners' own, plus
#: the global reference nodes.
_PRESERVED_LABEL_PREDICATE = " OR ".join(
    f"n:`{label}`" for label in tuple(NON_RECON_LABELS) + tuple(GLOBAL_REFERENCE_LABELS))


class BaseMixin:
    def _sweep_orphan_reference_nodes(self, session) -> int:
        """Delete global reference nodes nothing points at any more.

        The reference labels are deliberately excluded from every project-scoped
        delete: one CVE node is shared by every project that finds it, so
        removing it with a project would take the other projects' links down too
        (observed live: 4 CVEs stamped with one project, linked from a second).

        Excluding them alone would leak, so this is the other half: a node no
        project can reach any more is safe to drop, and the next scan re-MERGEs
        it from its own feed.

        REACHABILITY, not degree. "No relationships at all" never becomes true,
        because the catalogue is internally linked as
        `CVE -[:HAS_CWE]-> MitreData -[:HAS_CAPEC]-> Capec`: an unreferenced CVE
        still holds its CWE, and that CWE still holds its CAPEC, so a
        degree-zero test kept all three forever. Nor is "no non-reference
        NEIGHBOUR" enough — that would delete a MitreData whose CVE is still
        live. The test is therefore whether any non-reference node sits within
        the chain's depth.
        """
        try:
            record = session.run(
                f"""
                MATCH (n) WHERE ({_REFERENCE_LABEL_PREDICATE})
                  AND NOT EXISTS {{
                    MATCH (n)-[*1..{_REFERENCE_CHAIN_DEPTH}]-(x)
                    WHERE NOT ({_REFERENCE_LABEL_PREDICATE_X})
                  }}
                DETACH DELETE n
                RETURN count(n) AS deleted
                """
            ).single()
            return record["deleted"] if record else 0
        except Exception as e:
            print(f"[!][graph-db] reference-node orphan sweep failed: {e}")
            return 0

    def __init__(self, uri=None, user=None, password=None):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER")
        self.password = password or os.getenv("NEO4J_PASSWORD")
        self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        with self.driver.session() as session:
            init_schema(session)

    def close(self):
        self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def verify_connection(self):
        """Verify the connection to Neo4j is working."""
        try:
            with self.driver.session() as session:
                result = session.run("RETURN 1 AS test")
                return result.single()["test"] == 1
        except Exception as e:
            print(f"[!][graph-db] Neo4j connection failed: {e}")
            return False

    def clear_project_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete all nodes and relationships for a specific project.

        This should be called before re-running a recon scan to ensure
        old data is removed and replaced with fresh results.

        Args:
            user_id: User identifier
            project_id: Project identifier

        Returns:
            dict with counts of deleted nodes and relationships
        """
        stats = {"nodes_deleted": 0, "relationships_deleted": 0,
                 "reference_nodes_swept": 0}

        with self.driver.session() as session:
            # Delete all nodes and relationships for this project
            # DETACH DELETE removes the node and all its relationships
            result = session.run(
                f"""
                MATCH (n)
                WHERE n.user_id = $user_id AND n.project_id = $project_id
                  AND NOT ({_REFERENCE_LABEL_PREDICATE})
                DETACH DELETE n
                RETURN count(n) as deleted_count
                """,
                user_id=user_id, project_id=project_id
            )
            record = result.single()
            if record:
                stats["nodes_deleted"] = record["deleted_count"]

            stats["reference_nodes_swept"] = self._sweep_orphan_reference_nodes(session)

            print(f"[*][graph-db] Cleared project data: {stats['nodes_deleted']} nodes deleted")

        return stats

    def clear_recon_data(self, user_id: str, project_id: str) -> dict:
        """Delete the RECON pipeline's own nodes for a project, and nothing else.

        Recon re-runs used to call `clear_project_data`, a bare
        `MATCH (n) WHERE n.user_id AND n.project_id DETACH DELETE n`. That is
        every node in the project, so a recon scan silently deleted the GitHub
        Secret Hunt, the Secret Multiscanner findings, the supply-chain packages
        (1638 OSV vulnerabilities on this box alone), the GVM results and the
        agent's attack chains. Every other scanner had already been given a
        scoped clear; recon was the last one still wiping the lot.

        Two exclusions, because ownership shows up two ways:
          - by LABEL, for the subsystems with labels of their own
            (`NON_RECON_LABELS`), and
          - by SOURCE, for the labels recon shares — Vulnerability above all,
            which GVM, the supply-chain scanner and the AI attack-surface
            scanner all write into (`NON_RECON_SOURCES`).

        Technology is kept whenever GVM has also detected it: recon re-MERGEs the
        node on the next pass anyway, and deleting it here would orphan the GVM
        vulnerabilities hanging off it. That mirrors clear_gvm_data, which strips
        GVM's enrichment off a shared Technology rather than deleting it.
        """
        stats = {"nodes_deleted": 0, "reference_nodes_swept": 0}

        with self.driver.session() as session:
            result = session.run(
                f"""
                MATCH (n)
                WHERE n.user_id = $uid AND n.project_id = $pid
                  AND NOT ({_PRESERVED_LABEL_PREDICATE})
                  AND NOT coalesce(n.source, '') IN $keep_sources
                  AND coalesce(n.ai_attack_synthetic, false) = false
                  AND NOT (n:Technology AND coalesce(n.detected_by, '') CONTAINS 'gvm')
                DETACH DELETE n
                RETURN count(n) AS deleted
                """,
                uid=user_id, pid=project_id, keep_sources=list(NON_RECON_SOURCES)
            )
            record = result.single()
            if record:
                stats["nodes_deleted"] = record["deleted"]

            stats["reference_nodes_swept"] = self._sweep_orphan_reference_nodes(session)

            print(f"[*][graph-db] Cleared recon data: {stats['nodes_deleted']} nodes "
                  f"deleted (other scanners' findings preserved)")

        return stats

    def clear_gvm_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete only GVM-specific nodes and relationships for a project.

        Preserves all recon data (Domain, Subdomain, IP, Port, BaseURL,
        Endpoint, Parameter, Service, etc.). Only removes:
        - Vulnerability nodes with source='gvm'
        - GVM-only CVE nodes (not shared with recon)
        - GVM-only Technology nodes (detected_by='gvm')
        - GVM enrichments on shared Technology nodes (CPE data)
        - USES_TECHNOLOGY relationships with detected_by='gvm'
        - Domain node GVM metadata properties

        Args:
            user_id: User identifier
            project_id: Project identifier

        Returns:
            dict with counts of deleted/cleaned items
        """
        stats = {
            "vulnerabilities_deleted": 0,
            "cves_deleted": 0,
            "technologies_deleted": 0,
            "technologies_cleaned": 0,
            "traceroutes_deleted": 0,
            "certificates_deleted": 0,
            "exploits_gvm_deleted": 0,
            "relationships_deleted": 0,
        }

        with self.driver.session() as session:
            # 1. Delete GVM Vulnerability nodes (and all their relationships)
            result = session.run(
                """
                MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
                WHERE v.source = 'gvm'
                DETACH DELETE v
                RETURN count(v) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["vulnerabilities_deleted"] = record["deleted"]

            # 1b. Delete Traceroute nodes
            result = session.run(
                """
                MATCH (tr:Traceroute {user_id: $uid, project_id: $pid})
                DETACH DELETE tr
                RETURN count(tr) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["traceroutes_deleted"] = record["deleted"]

            # 1c. Delete GVM-sourced Certificate nodes (preserve recon/httpx certificates)
            result = session.run(
                """
                MATCH (c:Certificate {user_id: $uid, project_id: $pid})
                WHERE c.source = 'gvm'
                DETACH DELETE c
                RETURN count(c) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["certificates_deleted"] = record["deleted"]

            # 1d. Delete ExploitGvm nodes
            result = session.run(
                """
                MATCH (e:ExploitGvm {user_id: $uid, project_id: $pid})
                DETACH DELETE e
                RETURN count(e) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["exploits_gvm_deleted"] = record["deleted"]

            # 2. CVE is a GLOBAL reference node shared by every project that
            #    finds it, so it cannot be deleted by project. Removing the
            #    ExploitGvm nodes above already dropped this scan's
            #    EXPLOITED_CVE edges; the sweep collects only the CVEs that are
            #    now referenced by nothing at all, in any project.
            stats["cves_deleted"] = self._sweep_orphan_reference_nodes(session)

            # 3. Delete GVM-only Technology nodes (detected_by exactly 'gvm')
            result = session.run(
                """
                MATCH (t:Technology {user_id: $uid, project_id: $pid})
                WHERE t.detected_by = 'gvm'
                DETACH DELETE t
                RETURN count(t) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["technologies_deleted"] = record["deleted"]

            # 4. Clean shared Technology nodes (strip GVM enrichment)
            result = session.run(
                """
                MATCH (t:Technology {user_id: $uid, project_id: $pid})
                WHERE t.detected_by CONTAINS ',gvm'
                SET t.detected_by = replace(t.detected_by, ',gvm', ''),
                    t.cpe = null, t.cpe_vendor = null, t.cpe_product = null
                RETURN count(t) as cleaned
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["technologies_cleaned"] = record["cleaned"]

            # 5. Delete GVM USES_TECHNOLOGY relationships (Port→Tech and IP→Tech)
            result = session.run(
                """
                MATCH ({user_id: $uid, project_id: $pid})-[r:USES_TECHNOLOGY]->()
                WHERE r.detected_by = 'gvm'
                DELETE r
                RETURN count(r) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["relationships_deleted"] = record["deleted"]

            # 6. Clear Domain node GVM metadata properties
            session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                WHERE d.gvm_scan_timestamp IS NOT NULL
                REMOVE d.gvm_scan_timestamp, d.gvm_total_vulnerabilities,
                       d.gvm_critical, d.gvm_high, d.gvm_medium, d.gvm_low
                """,
                uid=user_id, pid=project_id
            )

            total = (stats["vulnerabilities_deleted"] + stats["cves_deleted"] +
                     stats["technologies_deleted"] + stats["traceroutes_deleted"] +
                     stats["certificates_deleted"] + stats["exploits_gvm_deleted"] +
                     stats["relationships_deleted"])
            print(f"[*][graph-db] Cleared GVM data: {total} items removed, "
                  f"{stats['technologies_cleaned']} shared technologies cleaned")

        return stats
