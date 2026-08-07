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


# A finding's title is what the graph viewer shows as the node NAME (it has no
# `name` property, so webapp/src/app/api/graph/format.ts falls back to `title`).
# It must stay a short label.
_MAX_TITLE = 120


def _finding_title(finding, advisory):
    """Short, human label for a finding node.

    The advisory/rule id is preferred over the message because GuardDog
    findings carry NO title and their `message` is the full evidence dump - for
    npm `metadata_mismatch` that is a multi-line manifest diff over a thousand
    characters long, which then became the node's displayed name. The evidence
    still ships, in `detail`.
    """
    explicit = (finding.get("title") or "").strip()
    if explicit and len(explicit) <= _MAX_TITLE and "\n" not in explicit:
        return explicit
    if advisory:
        return advisory
    if explicit:
        # No advisory to fall back to: use the first line, truncated.
        first = explicit.splitlines()[0].strip()
        return first[:_MAX_TITLE - 1] + "…" if len(first) > _MAX_TITLE else first
    message = (finding.get("message") or "").strip()
    if message:
        first = message.splitlines()[0].strip()
        return first[:_MAX_TITLE - 1] + "…" if len(first) > _MAX_TITLE else first
    return "finding"


# The Vulnerability node's severity enum is critical|high|medium|low|info -
# there is no "unknown". An ungraded advisory lands at info so it does not
# inflate the alert stream.
_GRAPH_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _vuln_severity(value):
    v = (value or "").strip().lower()
    return v if v in _GRAPH_SEVERITIES else "info"


# Evidence strength per harvest source, used to stop a weaker sighting from
# overwriting a stronger one on the shared Package node (L1 and L2 dedup by
# purl into ONE node, by design).
#
# The ordering is about REACHABILITY, not tool quality: something observed
# being served by the live target is stronger evidence than something read out
# of a manifest a human uploaded. A lockfile can list a dependency that is
# never shipped to a browser; retire.js matching bytes the target actually
# served cannot.
#
#   40  live target, name AND version   (retire.js, wappalyzer)
#   30  live target, name only          (source maps, JS imports)
#   10  manifest / SBOM                 (osv, lockfile, sbom, dir)
#    0  synthesised to hang a finding on (has no discovery evidence at all)
_SOURCE_RANK = {
    "retirejs": 40,
    "wappalyzer": 40,
    "sourcemap": 30,
    "import": 30,
    "osv": 10,
    "sbom": 10,
    "lockfile": 10,
    "dir": 10,
    "finding": 0,
}
# An unrecognised source sits with the manifest tier: strong enough to replace
# a placeholder, never strong enough to erase live-target evidence.
_DEFAULT_SOURCE_RANK = 10


def _overridable_sources(source):
    """Sources a package discovered via `source` is allowed to overwrite.

    Equal rank is included so a re-scan by the same source refreshes normally.
    A source not in the table is left alone rather than clobbered - unknown
    provenance is still provenance.
    """
    rank = _SOURCE_RANK.get(source, _DEFAULT_SOURCE_RANK)
    return [name for name, r in _SOURCE_RANK.items() if r <= rank]


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
        if has_anchor and anchor_label not in ("GithubRepository", "BaseURL", "SbomDocument"):
            raise ValueError("unsupported anchor_label: {}".format(anchor_label))
        # L2-4: anchor_key is string-interpolated into the Cypher (labels/keys
        # can't be parameterized), so whitelist it too, not just anchor_label.
        if has_anchor and anchor_key not in ("id", "url"):
            raise ValueError("unsupported anchor_key: {}".format(anchor_key))
        if has_anchor and anchor_value is None:
            raise ValueError("anchor_value required with anchor_label")

        stats = {"packages_merged": 0, "malicious_merged": 0,
                 "suspicious_merged": 0, "vulnerabilities_merged": 0,
                 "relationships_created": 0, "errors": []}

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
                            p.version = $version,
                            p.source = CASE
                                WHEN p.source IS NULL OR p.source IN $overridable
                                THEN $source ELSE p.source END,
                            p.source_path = coalesce($source_path, p.source_path),
                            p.last_seen = datetime()
                        """,
                        purl=purl, uid=user_id, pid=project_id,
                        ecosystem=pkg.get("ecosystem"), name=pkg.get("name"),
                        version=pkg.get("version"), source=pkg.get("source"),
                        # L1 and L2 dedup into ONE node per purl (intentional),
                        # but `source` was SET unconditionally, so whichever
                        # scan ran last won. Upload a package-lock.json after a
                        # recon scan and lodash@4.17.4 - which retire.js read
                        # out of the bytes the target actually served - started
                        # claiming it came from a file someone uploaded.
                        #
                        # That field answers "is this dependency really being
                        # served, or did it just appear in a manifest?", which
                        # is the difference between a reachable finding and a
                        # theoretical one. So a WEAKER source may no longer
                        # overwrite a stronger one; see _overridable_sources.
                        overridable=_overridable_sources(pkg.get("source")),
                        # Which manifest inside a scanned tree the package came
                        # from - the only way to tell, on an L1 repo scan that
                        # walked 12 lockfiles, WHICH one carries the malware.
                        # coalesce so a later L2 sighting (no path) cannot erase
                        # what the repo scan established.
                        source_path=pkg.get("source_path"),
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
                            mf.detail = $detail, mf.soft_error = $soft_error,
                            mf.aliases = $aliases, mf.last_seen = datetime()
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
                        title=_finding_title(f, advisory),
                        # THE difference between "GuardDog analysed this and
                        # found nothing bad" and "GuardDog never ran". The flag
                        # exists in the artifact for exactly that reason; not
                        # persisting it made every soft error read, in the UI,
                        # as an ordinary low-severity suspicious finding.
                        soft_error=bool(f.get("soft_error")),
                        # OSV alias ids (a MAL- advisory often also has a GHSA-).
                        aliases=[str(a) for a in (f.get("aliases") or [])][:50],
                        # None, not "": an absent detail should be an absent
                        # property, not an empty string that reads as present.
                        detail=f.get("detail") or f.get("message") or None,
                    )
                    if verdict == "malicious":
                        stats["malicious_merged"] += 1
                    else:
                        stats["suspicious_merged"] += 1
                except Exception as exc:
                    stats["errors"].append("finding {}: {}".format(fid, exc))

            # ---- CVE/GHSA -> the EXISTING Vulnerability model --------------
            # These are known-vulnerable, NOT malicious, so they must never become
            # MalPackageFinding. They used to go nowhere at all: a package with 9
            # advisories rendered as a clean node while the JSON artifact listed
            # them. Reuse the Vulnerability node (no new label), exactly as the
            # cache-poisoning and takeover modules do.
            for vul in data.get("vulnerable") or []:
                purl = vul.get("purl")
                advisory = vul.get("advisory_id")
                if not purl or not advisory:
                    continue
                try:
                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $advisory, user_id: $uid, project_id: $pid})
                        ON CREATE SET v.first_seen = datetime()
                        SET v.source = 'osv',
                            v.name = $name,
                            v.description = $description,
                            v.severity = $severity,
                            v.cvss_metrics = $cvss,
                            v.updated_at = datetime()
                        WITH v
                        MERGE (p:Package {purl: $purl, user_id: $uid, project_id: $pid})
                        ON CREATE SET p.first_seen = datetime(), p.name = $pname,
                                      p.ecosystem = $peco, p.source = 'finding'
                        SET p.last_seen = datetime()
                        MERGE (p)-[:HAS_VULNERABILITY]->(v)
                        """,
                        advisory=advisory, uid=user_id, pid=project_id, purl=purl,
                        name=vul.get("title") or advisory,
                        description=vul.get("detail") or vul.get("title") or "",
                        # The graph enum has no "unknown"; an advisory we cannot
                        # grade lands at info so it stays out of the alert stream
                        # rather than inflating it (same convention the takeover
                        # module uses for manual_review).
                        severity=_vuln_severity(vul.get("severity")),
                        cvss=vul.get("cvss_vector"),
                        pname=vul.get("name"), peco=vul.get("ecosystem"),
                    )
                    stats["vulnerabilities_merged"] += 1
                except Exception as exc:
                    stats["errors"].append("vulnerability {}: {}".format(advisory, exc))

        return stats

    def _link_anchor_to_domain(self, session, user_id, project_id, label, node_id, rel):
        """Attach an L1 anchor to the project's Domain, the graph's root.

        Anchoring packages to a file or a repository stopped them from floating
        INDIVIDUALLY, but left the anchor itself parentless - so the whole L1
        scan hung in the view as one detached island, exactly what a GitHub
        Secret Hunt avoids by linking `Domain -[:HAS_GITHUB_HUNT]-> GithubHunt`.
        This is that same link for the supply-chain anchors.

        `label` and `rel` are internal constants, never caller/user input, so
        interpolating them into the query is safe (Cypher cannot parameterise a
        label or a relationship type).

        Returns True when a Domain existed to link to. A project with no Domain
        node yet is NOT an error and must not fail the scan: the graph write is
        still correct, the anchor simply stays a root until recon creates one.
        We never invent a Domain here - fabricating a target the operator never
        scanned would be worse than a detached node.
        """
        try:
            rec = session.run(
                """
                MATCH (dom:Domain {{user_id: $uid, project_id: $pid}})
                MATCH (n:{label} {{id: $nid}})
                MERGE (dom)-[:{rel}]->(n)
                RETURN count(*) AS linked
                """.format(label=label, rel=rel),
                uid=user_id, pid=project_id, nid=node_id).single()
            linked = bool(rec and rec["linked"])
            if not linked:
                print("[!][graph-db] no Domain for user_id={} project_id={}; "
                      "{} stays a graph root".format(user_id, project_id, label))
            return linked
        except Exception as exc:
            print("[!][graph-db] could not link {} to Domain: {}".format(label, exc))
            return False

    def ensure_github_repository(self, user_id, project_id, repo_slug):
        """MERGE the GithubRepository anchor for an L1 repo scan, return its id.

        update_graph_from_supply_chain only MATCHes an anchor (it must never
        invent a target node), so a repo that no other scan has seen would
        leave every package floating. A repository the operator explicitly
        pointed the scanner at is not an invented node, so creating it here is
        correct - and it is the SAME id format the GitHub secret hunter uses,
        so scanning a repo both ways attaches to one node instead of two.
        """
        repo_id = "github-repo-{}-{}-{}".format(user_id, project_id, repo_slug)
        with self.driver.session() as session:
            session.run(
                """
                MERGE (gr:GithubRepository {id: $id})
                ON CREATE SET gr.first_seen = datetime()
                SET gr.name = $name, gr.user_id = $uid, gr.project_id = $pid,
                    gr.updated_at = datetime()
                """,
                id=repo_id, name=repo_slug, uid=user_id, pid=project_id)
            self._link_anchor_to_domain(session, user_id, project_id,
                                        "GithubRepository", repo_id, "HAS_REPOSITORY")
        return repo_id

    def ensure_sbom_document(self, user_id, project_id, filename):
        """MERGE the SbomDocument anchor for an UPLOADED SBOM/lockfile.

        Without it the packages from an upload had no parent at all and sat in
        the graph as an island - a Package plus its Vulnerabilities, reachable
        from nothing. That contradicts the schema's own rule (GRAPH.SCHEMA.md,
        "No Isolated Nodes") and it is visibly odd next to a repo scan, which
        anchors to GithubRepository.

        An uploaded file has no target to hang off, so the file ITSELF is the
        parent: it is what the operator supplied and what the packages were
        read out of. It also recovers information that was previously lost -
        every upload collapsed into an indistinguishable pile of source='osv'
        packages, with no way to tell which file contributed which.
        """
        doc_id = "sbom-{}-{}-{}".format(user_id, project_id, filename)
        with self.driver.session() as session:
            session.run(
                """
                MERGE (d:SbomDocument {id: $id})
                ON CREATE SET d.first_seen = datetime()
                SET d.name = $name, d.user_id = $uid, d.project_id = $pid,
                    d.updated_at = datetime()
                """,
                id=doc_id, name=filename, uid=user_id, pid=project_id)
            self._link_anchor_to_domain(session, user_id, project_id,
                                        "SbomDocument", doc_id, "HAS_SBOM_DOCUMENT")
        return doc_id

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

        # Write the NODES once, then attach the per-BaseURL edges.
        #
        # This used to call update_graph_from_supply_chain once per BaseURL,
        # which re-wrote the ENTIRE artifact every time. A scan with 122
        # packages and 2 BaseURLs issued ~500 Cypher round-trips where ~250
        # were needed, and reported packages_merged=244 for 122 actual nodes -
        # the counts a reader trusts were simply wrong. A target with 10
        # BaseURLs (multiple ports/subdomains is normal) paid 10x.
        #
        # The data was never wrong - MERGE is idempotent - so this is about
        # cost and about the numbers meaning what they say.
        stats = self.update_graph_from_supply_chain(artifact, user_id, project_id)
        stats["relationships_created"] = 0

        purls = [p["purl"] for p in (artifact.get("packages") or []) if p.get("purl")]
        if purls:
            for url in base_urls:
                try:
                    stats["relationships_created"] += self._anchor_packages_to(
                        "BaseURL", "url", url, purls, user_id, project_id)
                except Exception as exc:
                    stats["errors"].append("depends_on {}: {}".format(url, exc))
        return stats

    def _anchor_packages_to(self, anchor_label, anchor_key, anchor_value,
                            purls, user_id, project_id):
        """MERGE DEPENDS_ON from one anchor to many packages in ONE query.

        UNWIND rather than a query per package: this is the only part that has
        to repeat per BaseURL, so it is the part worth batching.

        The anchor is MATCHed, never created - inventing a BaseURL the scan did
        not actually observe would put a fabricated target in the graph.
        """
        if anchor_label not in ("GithubRepository", "BaseURL", "SbomDocument"):
            raise ValueError("unsupported anchor_label: {}".format(anchor_label))
        if anchor_key not in ("id", "url"):
            raise ValueError("unsupported anchor_key: {}".format(anchor_key))

        with self.driver.session() as session:
            res = session.run(
                """
                MATCH (a:%s {%s: $anchor_value, user_id: $uid, project_id: $pid})
                UNWIND $purls AS purl
                MATCH (p:Package {purl: purl, user_id: $uid, project_id: $pid})
                MERGE (a)-[:DEPENDS_ON]->(p)
                RETURN count(*) AS c
                """ % (anchor_label, anchor_key),
                anchor_value=anchor_value, purls=purls,
                uid=user_id, pid=project_id)
            rec = res.single()
            return (rec and rec.get("c")) or 0
