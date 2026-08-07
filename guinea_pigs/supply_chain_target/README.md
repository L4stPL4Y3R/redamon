# `supply_chain_target` — RedAmon guinea pig for Supply-Chain recon (L2)

A deterministic, dependency-free HTTP target that fires **every branch** of the
L2 supply-chain harvest chain exactly once, with a known expected outcome.

L2 is the layer described in [README.SUPPLY_CHAIN.md](../../readmes/README.SUPPLY_CHAIN.md#layer-l2--recon-pipeline-module):
against a live target with **no manifest**, it reconstructs the served npm
package set, verdicts it offline against the OSV database, and MERGEs
`Package` + `MalPackageFinding` nodes anchored to the target's `BaseURL`.

Every expectation in [expected_results.yaml](expected_results.yaml) was
**observed** by running the production functions against this target
(`run_dry_run.sh`), not predicted.

## Why this target is NOT on 127.0.0.1

Unlike [`ai_surface_target`](../ai_surface_target/), this guinea pig sits on
`192.88.99.10`, on its own docker bridge.

L2's harvest is fed by `js_recon`, which is **Python** and routes every JS URL
and every source-map URL through `is_url_safe_to_probe()`
([ip_filter.py:51](../../recon/main_recon_modules/ip_filter.py#L51)). That guard
fails closed on any non-routable address. A loopback target yields zero
downloaded JS, zero source maps, and an empty harvest.

`ai_surface_target` gets away with `network_mode: host` because `port_scan` and
`http_probe` are Go binaries that never see this Python guard.

Every documentation range is rejected too — Python's `ipaddress` reports
`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `198.18.0.0/15` as
`is_private`. **`192.88.99.0/24`** is the deprecated 6to4 relay anycast prefix
(RFC 7526): Python reports it as global, so the guard passes and the E2E run
exercises the real production path **with the SSRF control intact**. Docker
installs a local route; nothing leaves the host, and the prefix is unrouted on
the real internet.

## Architecture

```
                       ┌──────────────────────────────────────┐
                       │  supply-chain-target  192.88.99.10   │
                       │  (stdlib http.server, ~55 MB)        │
                       │                                      │
   PATH A ◄────────────┤  index.html <script src=...>         │
   versions            │  X-Powered-By: Express               │
                       │                                      │
   PATH B ◄────────────┤  /assets/app.7f3c2a.js  + .map     │
   names only          │  /assets/deep-vendor.js  + .map     │
                       └──────────────────────────────────────┘
                                        │
        httpx -td ──► "Axios:1.14.1", "jQuery:3.4.1", "Lodash", …
        js_recon ──► source_maps[].source_files[:100]
                                        │
                          harvest_packages()  ── dedup by name, versioned wins
                                        │
                          to_cyclonedx → osv-scanner --offline
                                        │
                    MAL- ──► MalPackageFinding      CVE/GHSA ──► JSON only
                                        │
                    BaseURL ─DEPENDS_ON→ Package ─FLAGGED_AS→ finding
```

## The two harvest paths

**Path A — technologies → purl.** The *only* version-bearing source in the
pipeline. httpx's wappalyzergo reads `<script src>` paths and response headers
and emits `"Name:Version"` strings; `harvest.py` maps the display name through
the fixed `_TECH_NPM_ALIASES` table. Anything not in that table is dropped, so
no purls get invented.

**Path B — source-map mining.** Names only, never versions. `js_recon` follows
`//# sourceMappingURL`, and `harvest.py` mines `node_modules/(@scope/)?<pkg>`
out of `sources[:100]`.

## Endpoint → feature map

### Path A: `/` (index.html) + response headers

| Served | httpx emits | Harvested | Proves |
|---|---|---|---|
| `<script src="/axios@1.14.1/axios.min.js">` | `Axios:1.14.1` | `pkg:npm/axios@1.14.1` | **MALICIOUS.** OSV `MAL-2026-2307` is live for axios 1.14.1 → the one `MalPackageFinding` |
| `<script src="/js/jquery-3.4.1.min.js">` | `jQuery:3.4.1` | `pkg:npm/jquery@3.4.1` | **Vulnerable-but-not-a-node.** 2 GHSAs land in JSON, zero graph nodes |
| `<script src="/js/vue-2.6.10.min.js">` | `Vue.js:2.6.10` | `pkg:npm/vue@2.6.10` | second vulnerable-only package |
| `<script src="/js/bootstrap-5.3.3.min.js">` | `Bootstrap:5.3.3` | `pkg:npm/bootstrap@5.3.3` | **Clean + versioned**: a package with a version and no findings |
| `<script src="/js/lodash.custom.js">` | `Lodash` | `pkg:npm/lodash` | **Versionless**: inventory only, cannot be OSV-verdicted |
| `<script src="/js/moment.min.js">` | `Moment.js` | `pkg:npm/moment` | second versionless alias |
| `X-Powered-By: Express` | `Express` | `pkg:npm/express` | alias via a **header**, not a script path |
| `Server: nginx/1.18.0` + `<meta generator="WordPress 6.1">` | `Nginx:1.18.0`, `WordPress:6.1`, `PHP`, `MySQL`, `Node.js` | *(nothing)* | **non-alias techs are dropped** — no invented purls, including versioned ones |

### Path B: `/assets/app.7f3c2a.js.map` (10 sources)

| Source entry | Harvested | Proves |
|---|---|---|
| `./src/index.js`, `./src/components/App.jsx` | *(nothing)* | non-package paths yield nothing |
| `./node_modules/left-pad/index.js` | `pkg:npm/left-pad` | plain unscoped extraction |
| `./node_modules/is-odd/index.js` | `pkg:npm/is-odd` | second unscoped package |
| `./node_modules/@babel/runtime/helpers/typeof.js` | `pkg:npm/%40babel/runtime` | **scoped package**: `@` url-encoded to `%40` |
| `./node_modules/axios/lib/core/Axios.js` | *(loses to `axios@1.14.1`)* | **version-preferring dedup** |
| `./node_modules/../../etc/passwd` | *(rejected)* | `sanitize_name` blocks `..` traversal |
| `./node_modules/-rf/index.js` | *(rejected)* | blocks leading `-` (CLI-flag injection) |
| `./node_modules/evil;whoami/index.js` | *(rejected)* | blocks shell metacharacters |
| ``./node_modules/back`tick`/index.js`` | *(rejected)* | blocks backticks |

### Path B: `/assets/deep-vendor.js.map` (120 sources)

| Index | Source entry | Harvested | Proves |
|---|---|---|---|
| 0 | `./node_modules/outer-pkg/node_modules/inner-pkg/index.js` | **both** `outer-pkg` and `inner-pkg` | nested `node_modules` (regex uses `findall`) |
| 1–98 | `./node_modules/filler-NNN/index.js` | 98 packages | pads the boundary to a known index |
| 99 | `./node_modules/within-cap-edge/index.js` | `pkg:npm/within-cap-edge` | last entry surviving `source_files[:100]` |
| 100 | `./node_modules/beyond-cap-pkg/index.js` | *(absent)* | **the cap holds** |
| 101–119 | `./node_modules/also-beyond-NN/index.js` | *(absent)* | cap holds under volume |

### Deep behavioural analysis (GuardDog)

Opt-in via `supplyChainReconDeepAnalysisEnabled`. It runs **only over packages
the offline OSV pass already flagged**, never the whole set, because it
downloads real tarballs from the public registry. GuardDog runs inside the
hardened dirty analyzer, spawned through the broker socket the recon container
already holds.

That gate means the reachable set here is exactly the three flagged packages,
and each one proves a different branch:

| Package | GuardDog result | Proves |
|---|---|---|
| `jquery@3.4.1` | 4 rules, incl. `threat-runtime-obfuscation-general` | the happy path, **and** severity mapping: `obfuscation` → `medium`, `capability-*` → `low` |
| `vue@2.6.10` | 3 rules, all `capability-*` | a second package, all-low severities |
| `axios@1.14.1` | `errors["download-package"]` | **the soft-error path.** npm unpublished the malicious release, so the tarball is gone. GuardDog returns `issues: 0`; that must become a `soft_error` finding and **never** a silent clean |

Also asserted:

- every suspicious finding carries `source_tool=guarddog` and `verdict=suspicious`
- **no** GuardDog finding ever claims `verdict=malicious` (only an OSV `MAL-` hit is)
- findings attach to the **versioned** `Package` node — no `pkg:npm/jquery`
  duplicate alongside `pkg:npm/jquery@3.4.1`

Fast loop:

```bash
SC_DEEP=1 ./run_dry_run.sh      # ~3 min: downloads 3 tarballs from npm
```

Expected: `packages=111 malicious=1 vulnerable=31 suspicious=8` and
`deep analysis: scanned=3 suspicious=7 soft_errors=1`.

### Graph-layer features

| Feature | Assertion |
|---|---|
| `Package` MERGE on `(purl, user_id, project_id)` | no duplicate purl |
| `MalPackageFinding` MERGE on `(finding_id, …)` | exactly 1 malicious finding |
| `FLAGGED_AS` | finding attaches to `pkg:npm/axios@1.14.1`, no orphans |
| `DEPENDS_ON` anchoring | every `Package` reachable from `BaseURL {url:"http://192.88.99.10"}` |
| enrich vs duplicate | re-scan keeps `first_seen`, advances `last_seen` |
| tenant isolation (S10) | another `project_id` sees 0 packages |

## Running it

```bash
# 1. Bring the target up
cd guinea_pigs/supply_chain_target
docker compose up -d --build
curl -s http://192.88.99.10/robots.txt

# 2. Fast inner loop: run the REAL harvest chain, no app needed (~30 s)
./run_dry_run.sh
#    -> prints packages / malicious / vulnerable, writes .dryrun/dryrun_artifact.json

# 3. Full E2E: in the webapp, create a project with target http://192.88.99.10,
#    enable JS Recon + Supply-Chain Recon, run a full recon scan.

# 4. Assert the graph
./run_validation.sh <USER_ID> <PROJECT_ID>
```

Exit code 0 from `run_validation.sh` means every L2 feature is proven.

Two things the validator deliberately does **not** let you get away with:

- **It aborts on an empty graph.** Roughly half the checks are negative
  controls ("this purl must be absent"), and those all pass vacuously if the
  scan never ran. Rather than report a healthy-looking partial score, it exits
  1 with a checklist.
- **Cross-tenant isolation is only partly provable from one project.** It
  asserts what is falsifiable from a single run (no `Package` or
  `MalPackageFinding` may lack `user_id`/`project_id`) and reports, without
  asserting, whether another tenant holds the same purls. For a positive
  isolation proof, scan this target from a second project and confirm the two
  package sets do not cross.

### Project settings required

| Setting | Value |
|---|---|
| `jsReconEnabled` | `true` (L2 consumes its output; off by default) |
| `jsReconSourceMaps` | `true` (default) |
| `supplyChainReconEnabled` | `true` (off by default) |
| `supplyChainReconEcosystems` | `npm` (default) |
| `supplyChainReconDeepAnalysisEnabled` | `true` only to exercise GuardDog (downloads real tarballs) |
| `jsReconDependencyCheck` | `false` — otherwise it queries npm for all 111 harvested names |

The offline OSV database must be populated, or the scan fails loudly rather
than reporting a false clean:

```bash
./redamon.sh supply-chain-sync npm
```

## Known limits of this harness

These are properties of L2 as it stands, not gaps in the target:

- **Exactly one malicious verdict is reachable.** `_TECH_NPM_ALIASES` has 14
  entries, and `axios` is the only one with a live OSV `MAL-` advisory.
  `react` has `MAL-2024-2929`, but it is **withdrawn**, and osv-scanner
  correctly ignores withdrawn advisories. Multi-finding behaviour has to be
  tested through L1 with an uploaded SBOM.
- **Import mining is untestable end to end.** `mine_import_packages` exists but
  `run_supply_chain_recon` never passes `js_contents`, so the pipeline never
  calls it. Unit tests only.
- **Partial recon cannot produce any verdict.**
  [partial_recon_modules/supply_chain.py](../../recon/partial_recon_modules/supply_chain.py#L93)
  seeds an empty `http_probe`, so Path A never runs, so there are no versions
  to match, and packages float with no `DEPENDS_ON` anchor. Running the
  standalone tool against this target is expected to yield source-map inventory
  only.

## Cleanup

```bash
cd guinea_pigs/supply_chain_target
docker compose down
rm -rf .dryrun
```

> These targets are intentionally shaped to trigger malicious-package verdicts.
> Run only on a local/trusted Docker host.
