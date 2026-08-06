"""Supply-chain graph writer (plan Phase 2/4 graph model).

Writes the two node types shared by BOTH L1 (standalone repo/SBOM scan) and L2
(live-target recon harvest), so a repo scan and a live scan of the same project
dedup automatically:

  Package            - a discovered dependency. MERGE key (purl, user_id, project_id).
  MalPackageFinding  - a verdict about a package. MERGE key (finding_id, user_id,
                       project_id) where finding_id = sha256(purl:advisory)[:16].

Relationships:
  (GithubRepository|BaseURL)-[:DEPENDS_ON]->(Package)   (L1 uses the repo, L2 the BaseURL)
  (Package)-[:FLAGGED_AS]->(MalPackageFinding)

Rules (plan section 4):
  - All writes MERGE (ON CREATE SET first_seen; unconditional SET last_seen).
  - Only OSV MAL- hits are verdict=malicious. CVE-/GHSA- (vulnerable) are NOT
    written as MalPackageFinding here; they stay in the raw JSON output. GuardDog
    hits are verdict=suspicious.
  - Tenant isolation: every MERGE key includes user_id + project_id (S10).

The caller passes an ALREADY-VALIDATED artifact (see
supply_chain_common.security.validate_artifact); this writer never sees raw
tool bytes.
"""

import hashlib


def _finding_id(purl, advisory):
    raw = "{}:{}".format(purl or "", advisory or "")
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


class SupplyChainMixin:
    """Mixin adding supply-chain graph writes to the Neo4jClient."""

    def update_graph_from_supply_chain(self, data, user_id, project_id, *,
                                       anchor_label=None, anchor_key=None,
                                       anchor_value=None):
        """MERGE Package + MalPackageFinding nodes from a validated artifact.

        anchor_label: "GithubRepository" (L1 repo), "BaseURL" (L2 live target),
                      or None (e.g. an uploaded SBOM has no graph parent). When
                      None, packages/findings are still created, just without a
                      DEPENDS_ON edge.
        anchor_key:   the anchor node's identity property ("id" or "url").
        anchor_value: its value. The DEPENDS_ON edge is created only when the
                      anchor node already exists (we never invent target nodes).

        Returns a stats dict.
        """
        has_anchor = anchor_label is not None
        if has_anchor and anchor_label not in ("GithubRepository", "BaseURL"):
            raise ValueError("unsupported anchor_label: {}".format(anchor_label))
        # L2-4: anchor_key is string-interpolated into the Cypher (labels/keys
        # can't be parameterized), so whitelist it too, not just anchor_label.
        if has_anchor and anchor_key not in ("id", "url"):
            raise ValueError("unsupported anchor_key: {}".format(anchor_key))
        if has_anchor and anchor_value is None:
            raise ValueError("anchor_value required with anchor_label")

        stats = {"packages_merged": 0, "malicious_merged": 0,
                 "suspicious_merged": 0, "relationships_created": 0,
                 "errors": []}

        packages = data.get("packages") or []
        # Map both malicious (OSV MAL-) and suspicious (GuardDog) into findings.
        findings = []
        for m in data.get("malicious") or []:
            findings.append(("malicious", "osv", m.get("advisory_id"), m))
        for s in data.get("suspicious") or []:
            findings.append(("suspicious", "guarddog", s.get("rule"), s))

        with self.driver.session() as session:
            for pkg in packages:
                purl = pkg.get("purl")
                if not purl:
                    continue
                try:
                    session.run(
                        """
                        MERGE (p:Package {purl: $purl, user_id: $uid, project_id: $pid})
                        ON CREATE SET p.first_seen = datetime()
                        SET p.ecosystem = $ecosystem, p.name = $name,
                            p.version = $version, p.source = $source,
                            p.last_seen = datetime()
                        """,
                        purl=purl, uid=user_id, pid=project_id,
                        ecosystem=pkg.get("ecosystem"), name=pkg.get("name"),
                        version=pkg.get("version"), source=pkg.get("source"),
                    )
                    stats["packages_merged"] += 1
                except Exception as exc:  # keep going; one bad row is not fatal
                    stats["errors"].append("package {}: {}".format(purl, exc))
                    continue

                # DEPENDS_ON edge: only when an anchor is given AND it already
                # exists (an uploaded SBOM has no anchor -> packages float).
                if not has_anchor:
                    continue
                try:
                    res = session.run(
                        """
                        MATCH (a:%s {%s: $anchor_value, user_id: $uid, project_id: $pid})
                        MATCH (p:Package {purl: $purl, user_id: $uid, project_id: $pid})
                        MERGE (a)-[:DEPENDS_ON]->(p)
                        RETURN count(*) AS c
                        """ % (anchor_label, anchor_key),
                        anchor_value=anchor_value, purl=purl,
                        uid=user_id, pid=project_id,
                    )
                    rec = res.single()
                    if rec and rec.get("c"):
                        stats["relationships_created"] += 1
                except Exception as exc:
                    stats["errors"].append("depends_on {}: {}".format(purl, exc))

            for verdict, source_tool, advisory, f in findings:
                purl = f.get("purl")
                if not purl:
                    # A finding without a purl (e.g. GuardDog by name) still needs
                    # a package to attach to; build a name-only purl fallback.
                    name = f.get("name")
                    eco = f.get("ecosystem")
                    if name and eco:
                        purl = "pkg:{}/{}".format(eco, name)
                    else:
                        continue
                fid = _finding_id(purl, advisory)
                try:
                    # MERGE (not MATCH) the Package so a finding whose package is
                    # not in `packages` (e.g. a GuardDog name-only hit) still
                    # attaches instead of leaving an orphaned MalPackageFinding.
                    # Existing packages keep their richer props; only a brand-new
                    # one is seeded from the finding's fields.
                    session.run(
                        """
                        MERGE (mf:MalPackageFinding {finding_id: $fid, user_id: $uid, project_id: $pid})
                        ON CREATE SET mf.first_seen = datetime()
                        SET mf.verdict = $verdict, mf.source_tool = $source_tool,
                            mf.advisory_id = $advisory, mf.severity = $severity,
                            mf.confidence = $confidence, mf.title = $title,
                            mf.detail = $detail, mf.last_seen = datetime()
                        WITH mf
                        MERGE (p:Package {purl: $purl, user_id: $uid, project_id: $pid})
                        ON CREATE SET p.first_seen = datetime(), p.name = $pname,
                                      p.ecosystem = $peco, p.source = 'finding'
                        SET p.last_seen = datetime()
                        MERGE (p)-[:FLAGGED_AS]->(mf)
                        """,
                        fid=fid, uid=user_id, pid=project_id, purl=purl,
                        pname=f.get("name"), peco=f.get("ecosystem"),
                        verdict=verdict, source_tool=source_tool,
                        advisory=advisory, severity=f.get("severity"),
                        confidence=f.get("confidence") or verdict,
                        title=f.get("title") or f.get("message") or advisory,
                        detail=f.get("detail") or f.get("message") or "",
                    )
                    if verdict == "malicious":
                        stats["malicious_merged"] += 1
                    else:
                        stats["suspicious_merged"] += 1
                except Exception as exc:
                    stats["errors"].append("finding {}: {}".format(fid, exc))

        return stats

    def update_graph_from_supply_chain_recon(self, combined_result, user_id, project_id):
        """L2 pipeline graph-write entry point (matches the _graph_update_bg
        signature). Reads combined_result['supply_chain_recon'] {artifact,
        base_urls} and MERGEs, anchoring packages to each target BaseURL that
        already exists. Falls back to a floating write when no BaseURL is known.
        """
        block = (combined_result or {}).get("supply_chain_recon") or {}
        artifact = block.get("artifact")
        if not artifact:
            return {"skipped": "no supply_chain_recon artifact"}
        base_urls = block.get("base_urls") or []

        if not base_urls:
            return self.update_graph_from_supply_chain(artifact, user_id, project_id)

        agg = {"packages_merged": 0, "malicious_merged": 0,
               "suspicious_merged": 0, "relationships_created": 0, "errors": []}
        for url in base_urls:
            stats = self.update_graph_from_supply_chain(
                artifact, user_id, project_id,
                anchor_label="BaseURL", anchor_key="url", anchor_value=url)
            for k in ("packages_merged", "malicious_merged", "suspicious_merged",
                      "relationships_created"):
                agg[k] += stats.get(k, 0)
            agg["errors"].extend(stats.get("errors", []))
        return agg
