"""
GraphQL Scan Graph DB Mixin

Contains methods for updating Neo4j graph with GraphQL security scan results.
Separated from recon_mixin.py for better organization.
"""

from typing import Dict, List, Optional
from datetime import datetime


class GraphQLMixin:
    """Mixin for updating graph with GraphQL scan results."""

    def update_graph_from_graphql_scan(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update Neo4j graph with results from GraphQL security scan.

        Enriches existing Endpoint nodes with GraphQL properties and creates
        Vulnerability nodes for discovered GraphQL-specific vulnerabilities.

        Args:
            recon_data: GraphQL scan result dict from run_graphql_scan()
            user_id: Tenant user ID
            project_id: Tenant project ID

        Returns:
            Stats dict with counts of nodes/relationships created/updated
        """
        stats = {
            "endpoints_enriched": 0,
            "vulnerabilities_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        # Extract GraphQL scan data
        graphql_data = recon_data.get("graphql_scan", {})
        if not graphql_data:
            stats["errors"].append("No graphql_scan data found in recon_data")
            return stats

        endpoints_data = graphql_data.get("endpoints", {})
        vulnerabilities = graphql_data.get("vulnerabilities", [])

        with self.driver.session() as session:
            # Process endpoints - enrich existing Endpoint nodes with GraphQL properties
            for endpoint_url, endpoint_info in endpoints_data.items():
                if not endpoint_info.get("tested", False):
                    continue

                try:
                    # Parse endpoint URL to get path and baseurl
                    from urllib.parse import urlparse
                    parsed = urlparse(endpoint_url)
                    path = parsed.path or "/"
                    baseurl = f"{parsed.scheme}://{parsed.netloc}"

                    # Build GraphQL enrichment properties
                    graphql_props = {
                        "is_graphql": True,
                        "graphql_introspection_enabled": endpoint_info.get("introspection_enabled", False),
                        "graphql_schema_extracted": endpoint_info.get("schema_extracted", False),
                        "source": "graphql_scan",
                        "updated_at": datetime.now().isoformat()
                    }

                    # Add optional properties if present
                    if endpoint_info.get("mutations_count", 0) > 0:
                        operations = endpoint_info.get("operations", {})
                        mutations = operations.get("mutations", [])
                        if mutations:
                            graphql_props["graphql_mutations"] = mutations[:50]  # Limit array size

                    if endpoint_info.get("queries_count", 0) > 0:
                        operations = endpoint_info.get("operations", {})
                        queries = operations.get("queries", [])
                        if queries:
                            graphql_props["graphql_queries"] = queries[:50]  # Limit array size

                    if endpoint_info.get("schema_hash"):
                        graphql_props["graphql_schema_hash"] = endpoint_info["schema_hash"]

                    # Update existing Endpoint node with GraphQL properties
                    # Using MERGE to handle case where Endpoint might not exist yet
                    result = session.run(
                        """
                        MERGE (e:Endpoint {
                            path: $path,
                            method: 'POST',
                            baseurl: $baseurl,
                            user_id: $user_id,
                            project_id: $project_id
                        })
                        SET e += $props
                        RETURN e.path as path, e.is_graphql as was_graphql
                        """,
                        path=path,
                        baseurl=baseurl,
                        user_id=user_id,
                        project_id=project_id,
                        props=graphql_props
                    )

                    record = result.single()
                    if record:
                        stats["endpoints_enriched"] += 1

                except Exception as e:
                    stats["errors"].append(f"Failed to enrich endpoint {endpoint_url}: {str(e)}")

            # Process vulnerabilities
            vuln_id_mapping = {}  # Map generated IDs to Neo4j IDs

            for vuln in vulnerabilities:
                try:
                    endpoint_url = vuln.get("endpoint", "")
                    vuln_type = vuln.get("vulnerability_type", "")
                    severity = vuln.get("severity", "info")

                    if not endpoint_url or not vuln_type:
                        continue

                    # Parse endpoint URL
                    parsed = urlparse(endpoint_url)
                    path = parsed.path or "/"
                    baseurl = f"{parsed.scheme}://{parsed.netloc}"

                    # Generate unique vulnerability ID
                    vuln_id = f"graphql_{vuln_type}_{baseurl}_{path}".replace(":", "_").replace("/", "_").replace(".", "_")

                    # Create vulnerability properties
                    vuln_props = {
                        "id": vuln_id,
                        "vulnerability_id": vuln_id,
                        "vulnerability_type": vuln_type,
                        "severity": severity,
                        "title": vuln.get("title", f"GraphQL {vuln_type}"),
                        "description": vuln.get("description", ""),
                        "source": "graphql_scan",
                        "user_id": user_id,
                        "project_id": project_id,
                        "discovered_at": vuln.get("discovered_at", datetime.now().isoformat()),
                        "created_at": datetime.now().isoformat()
                    }

                    # Add evidence if present
                    evidence = vuln.get("evidence", {})
                    if evidence:
                        # Store evidence as JSON string for Neo4j compatibility
                        import json
                        vuln_props["evidence"] = json.dumps(evidence, default=str)

                    # Create Vulnerability node
                    result = session.run(
                        """
                        MERGE (v:Vulnerability {
                            id: $id,
                            user_id: $user_id,
                            project_id: $project_id
                        })
                        SET v += $props
                        RETURN v.id as id
                        """,
                        id=vuln_id,
                        user_id=user_id,
                        project_id=project_id,
                        props=vuln_props
                    )

                    record = result.single()
                    if record:
                        stats["vulnerabilities_created"] += 1
                        vuln_id_mapping[vuln_id] = record["id"]

                    # Create relationship to Endpoint
                    result = session.run(
                        """
                        MATCH (v:Vulnerability {
                            id: $vuln_id,
                            user_id: $user_id,
                            project_id: $project_id
                        })
                        MATCH (e:Endpoint {
                            path: $path,
                            method: 'POST',
                            baseurl: $baseurl,
                            user_id: $user_id,
                            project_id: $project_id
                        })
                        MERGE (v)-[:AFFECTS_ENDPOINT]->(e)
                        """,
                        vuln_id=vuln_id,
                        path=path,
                        baseurl=baseurl,
                        user_id=user_id,
                        project_id=project_id
                    )
                    stats["relationships_created"] += 1

                    # If introspection vulnerability, check for sensitive fields
                    if vuln_type == "graphql_introspection_enabled":
                        sensitive_fields = evidence.get("sensitive_fields", [])
                        if sensitive_fields:
                            # Create additional high severity finding for sensitive data exposure
                            sensitive_vuln_id = f"{vuln_id}_sensitive_data"
                            sensitive_props = vuln_props.copy()
                            sensitive_props.update({
                                "id": sensitive_vuln_id,
                                "vulnerability_id": sensitive_vuln_id,
                                "vulnerability_type": "graphql_sensitive_data_exposure",
                                "severity": "high",
                                "title": "GraphQL Schema Exposes Sensitive Fields",
                                "description": f"Introspection reveals sensitive fields: {', '.join(sensitive_fields[:10])}"
                            })

                            result = session.run(
                                """
                                MERGE (v:Vulnerability {
                                    id: $id,
                                    user_id: $user_id,
                                    project_id: $project_id
                                })
                                SET v += $props
                                RETURN v.id as id
                                """,
                                id=sensitive_vuln_id,
                                user_id=user_id,
                                project_id=project_id,
                                props=sensitive_props
                            )

                            if result.single():
                                stats["vulnerabilities_created"] += 1

                                # Link to endpoint
                                session.run(
                                    """
                                    MATCH (v:Vulnerability {
                                        id: $vuln_id,
                                        user_id: $user_id,
                                        project_id: $project_id
                                    })
                                    MATCH (e:Endpoint {
                                        path: $path,
                                        method: 'POST',
                                        baseurl: $baseurl,
                                        user_id: $user_id,
                                        project_id: $project_id
                                    })
                                    MERGE (v)-[:AFFECTS_ENDPOINT]->(e)
                                    """,
                                    vuln_id=sensitive_vuln_id,
                                    path=path,
                                    baseurl=baseurl,
                                    user_id=user_id,
                                    project_id=project_id
                                )
                                stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Failed to create vulnerability {vuln.get('vulnerability_type', 'unknown')}: {str(e)}")

            # Log results
            print(f"[+][graph-db] GraphQL scan: {stats['endpoints_enriched']} endpoints enriched")
            print(f"[+][graph-db] GraphQL scan: {stats['vulnerabilities_created']} vulnerabilities created")
            print(f"[+][graph-db] GraphQL scan: {stats['relationships_created']} relationships created")

            if stats["errors"]:
                print(f"[!][graph-db] GraphQL scan: {len(stats['errors'])} errors occurred")
                for error in stats["errors"][:5]:  # Show first 5 errors
                    print(f"[!][graph-db] {error}")

        return stats