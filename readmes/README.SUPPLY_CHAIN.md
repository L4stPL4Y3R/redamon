# Supply-Chain / Malicious-Package Detection

RedAmon detects **known-malicious** (MAL-) and **known-vulnerable** (CVE/GHSA)
software packages in a target's dependency surface, fully **offline** against a
local copy of the [OSV](https://osv.dev) database. Three layers share one engine.

## The three layers

| Layer | Name | What it is | Trigger |
|---|---|---|---|
| **L3** | Agent tools | On-demand MCP tools the AI agent calls mid-engagement | `execute_osv_scanner`, `execute_guarddog` |
| **L1** | Supply-Chain Scan | Standalone audit of an uploaded SBOM / lockfile | Other Scans modal / project settings |
| **L2** | Supply-Chain Recon | Black-box harvest of a live target's served packages | Recon pipeline (GROUP 5.5) or partial recon |

## Tools (pinned)

| Tool | Role | Version |
|---|---|---|
| **OSV-Scanner** | Verdict engine: is this package MAL- (malicious) or CVE/GHSA (vulnerable)? | v2.4.0 |
| **GuardDog** | Behavioural analysis (install hooks, obfuscation, exfil, typosquat) | v3.0.1 |
| **retire.js** | Black-box JS library+version harvest (L2, v2) | v5.4.3 |

A vulnerability id starting with `MAL-` is a **terminal malicious verdict**. `CVE-`
/ `GHSA-` ids are ordinary known-vulnerable findings and are NOT written as
malicious. A GuardDog hit is always **suspicious**, never malicious.

## Offline OSV database

The verdict path makes **zero network calls**. A shared Docker volume
`redamon-osv-db` holds the OSV database, populated lazily per-ecosystem:

```
./redamon.sh supply-chain-sync npm          # ~208 MB, first run only
./redamon.sh supply-chain-sync npm PyPI Go   # add more ecosystems
```

- Uses `osv-scanner --offline --download-offline-databases` via a seed manifest
  per ecosystem (layout-independent). Refreshes at most once / 24h.
- **Offline scanning uses `--offline`** (NOT `--offline-vulnerabilities`, which
  does not load the local DB in v2.4.0) plus the env var
  `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`.
- The sync runs as root and makes the DB tree world-readable so the non-root,
  read-only scan containers can load it.
- NOT downloaded at install time; the container images are eager, the data lazy.

## Security posture: the DIRTY / CLEAN split

This feature pulls attacker-authored code and text INWARD, so it is split:

- **DIRTY zone** (`redamon-supply-chain-analyzer`): processes untrusted bytes
  (tarballs, target-served JS, manifests/SBOMs). Spawned like `codefix_sandbox`:
  `cap_drop=ALL`, `read_only` rootfs + tmpfs, non-root, mem/pids/cpu caps,
  **holds NO secrets** (no Neo4j / Internal / GitHub token), network-isolated
  (OSV path zero-egress; GuardDog registry-egress is opt-in and fails closed).
- **CLEAN zone** (the recon / `supply_chain_scan` container): holds Neo4j creds,
  writes the graph, but reads ONLY a **schema-validated JSON artifact**
  (`validate_artifact`), never a raw tarball or target byte.

Every attacker-controlled name passes `sanitize_name` (strict charset allowlist)
before any subprocess or filename (S6/S7). Every byte L2 fetches goes through the
existing SSRF guard (`is_url_safe_to_probe`); L2 harvest makes no new fetches at
all (it parses data JS-recon already downloaded). Report fields are HTML-escaped;
LLM-facing strings are `wrap_untrusted`-wrapped. No package manager is ever run
(the NO-INSTALL invariant, enforced by a CI grep test).

The `redamon-supply-chain-analyzer` and `redamon-supply-chain` images and the
`redamon-osv-db` volume are on the docker-broker allowlist.

## Graph model

Two node types, shared by L1 + L2 (so a repo scan and a live scan dedup):

- **`Package`** - a discovered dependency. Merge key `(purl, user_id, project_id)`.
- **`MalPackageFinding`** - a verdict. Merge key `(finding_id, user_id, project_id)`
  where `finding_id = sha256(purl:advisory)[:16]`; `verdict` is `malicious`
  (OSV MAL-) or `suspicious` (GuardDog).

Relationships: `(GithubRepository|BaseURL)-[:DEPENDS_ON]->(Package)` and
`(Package)-[:FLAGGED_AS]->(MalPackageFinding)`. All writes MERGE (tenant-scoped).

## Using it

- **L3 (agent):** ask the agent to check a package. `execute_osv_scanner
  "pkg:npm/lodash@4.17.21"` (or a lockfile/SBOM path) is passive+offline.
  `execute_guarddog "npm <name>"` is DANGEROUS (downloads the tarball, dispatches
  to the analyzer) and is off unless the tool is enabled for the phase.
- **L1 (Other Scans):** in a project, open Supply Chain settings, upload an SBOM
  / lockfile, then start the scan from the Other Scans modal. Writes
  Package/MalPackageFinding nodes.
- **L2 (recon):** enable "Supply-Chain Recon" in project settings; it runs in the
  recon pipeline after JS Recon, or standalone via partial recon (`SupplyChainRecon`).

## v1 scope / deferred to v2

- L1 v1 input is an uploaded **SBOM / lockfile** (static, offline). GitHub-repo
  cloning + GuardDog deep analysis (which need the DIRTY analyzer's clone/tarball
  handling) are v2.
- L2 v1 harvests via source-map mining + imports + technology->purl and verdicts
  offline. retire.js deep harvest of served JS + GuardDog dispatch are v2.
  NOTE: source-map / import mining yields package NAMES without versions, and
  osv-scanner cannot match a version-specific advisory (MAL/CVE) without a
  version. So verdicts come primarily from the version-bearing sources
  (wappalyzer technologies, and retire.js in v2); versionless packages are still
  recorded as `Package` nodes for inventory. Advisories that affect all versions
  can match versionless.

## Key files

- `supply_chain_common/` - shared runners/parsers (osv/guarddog/retire), `purl`,
  `security` (sanitize + `validate_artifact`), `artifact`, `osv_db_sync`.
- `supply_chain_analyzer/` - the DIRTY image + entrypoint.
- `supply_chain_scan/` - the L1 CLEAN writer.
- `recon/helpers/supply_chain/harvest.py` + `recon/main_recon_modules/supply_chain_recon.py` - L2.
- `graph_db/mixins/supply_chain_mixin.py` - the graph writer.
- `mcp/servers/network_recon_server.py` - the L3 tools.
