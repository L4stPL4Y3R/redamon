#!/usr/bin/env python3
"""RedAmon - Supply-Chain Scan (L1 "Other Scans") entry point.

Runs a standalone supply-chain audit of an operator-uploaded SBOM / lockfile
against the OFFLINE OSV database, writes Package / MalPackageFinding graph nodes,
and saves a JSON artifact. This is the CLEAN writer: it holds Neo4j creds but
only ever runs a static, no-install, offline osv-scanner pass (plan S1).

Env (set by the orchestrator):
    PROJECT_ID, USER_ID, WEBAPP_API_URL,
    SUPPLY_CHAIN_UPLOADS_DIR (default /data/supply-chain-uploads),
    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY (default /osv-db),
    SUPPLY_CHAIN_OUTPUT_DIR (default /app/supply_chain_scan/output)
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

PROJECT_ID = os.environ.get("PROJECT_ID", "")
USER_ID = os.environ.get("USER_ID", "")

try:
    from supply_chain_scan.project_settings import get_setting, load_project_settings
    from supply_chain_scan.supply_chain_runner import SupplyChainRunner
except ImportError:
    from project_settings import get_setting, load_project_settings
    from supply_chain_runner import SupplyChainRunner


def run_supply_chain_scan(project_id: str) -> dict:
    enabled = get_setting("SUPPLY_CHAIN_ENABLED", False)
    sbom_file = get_setting("SUPPLY_CHAIN_SBOM_FILE", "")
    ecosystems_raw = get_setting("SUPPLY_CHAIN_ECOSYSTEMS", "")
    ecosystems = [e.strip() for e in (ecosystems_raw or "").split(",") if e.strip()]

    uploads_dir = os.environ.get("SUPPLY_CHAIN_UPLOADS_DIR", "/data/supply-chain-uploads")
    db_path = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "/osv-db")
    output_dir = os.environ.get("SUPPLY_CHAIN_OUTPUT_DIR",
                                str(Path(__file__).parent / "output"))

    print("\n" + "=" * 70)
    print("           RedAmon - Supply-Chain Scan (L1)")
    print("=" * 70)
    print(f"  Input file:     {sbom_file or '(not set)'}")
    print(f"  Ecosystems:     {', '.join(ecosystems) or '(all)'}")
    print(f"  OSV DB:         {db_path}")
    print("=" * 70 + "\n")

    if not sbom_file:
        print("[!] ERROR: no SBOM/lockfile configured (upload one in Other Scans -> Supply Chain)")
        return {"error": "no input file configured"}

    runner = SupplyChainRunner(
        uploads_dir=uploads_dir, sbom_file=sbom_file, db_path=db_path,
        project_id=project_id, ecosystems=ecosystems)
    artifact = runner.run()

    print("\n" + "=" * 70)
    print("                    SCAN SUMMARY")
    print("=" * 70)
    print(f"  Packages:       {runner.stats['packages']}")
    print(f"  MALICIOUS:      {runner.stats['malicious']}")
    print(f"  Vulnerable:     {runner.stats['vulnerable']}")
    if artifact.get("errors"):
        print(f"  Errors:         {artifact['errors']}")
    print("=" * 70 + "\n")

    # Save the artifact.
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, f"supply_chain_{project_id}.json")
    with open(out_file, "w") as fh:
        json.dump({
            "project_id": project_id,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "input_file": sbom_file,
            "artifact": artifact,
        }, fh, indent=2)
    print(f"[+] Saved artifact to {out_file}")

    # Write the graph (CLEAN writer holds Neo4j creds). Anchor is None: an
    # uploaded SBOM has no repo/URL parent, so packages float (plan Phase 2a).
    try:
        from graph_db import Neo4jClient

        with Neo4jClient() as client:
            if client.verify_connection():
                gstats = client.update_graph_from_supply_chain(
                    artifact, USER_ID, project_id)
                print(f"[+] Graph updated: {gstats}")
            else:
                print("[!] Could not connect to Neo4j - skipping graph update")
    except ImportError:
        print("[!] Neo4j client not available - skipping graph update")
    except Exception as e:
        print(f"[!] Graph update failed (non-fatal): {e}")

    return {
        "input_file": sbom_file,
        "statistics": runner.stats,
        "output_file": out_file,
    }


def main() -> int:
    if not PROJECT_ID:
        print("[!] ERROR: PROJECT_ID environment variable not set")
        return 1

    load_project_settings(PROJECT_ID)
    start = datetime.now()
    try:
        results = run_supply_chain_scan(project_id=PROJECT_ID)
        if "error" in results:
            print(f"\n[!] Scan failed: {results['error']}")
            return 1
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        raise

    print(f"\n[*] Total scan time: {(datetime.now() - start).total_seconds():.2f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
