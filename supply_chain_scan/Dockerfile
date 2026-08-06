# RedAmon Supply-Chain Scan (L1 CLEAN writer)
# ============================================
# Holds Neo4j creds and writes Package/MalPackageFinding graph nodes. Runs ONLY a
# static, no-install, OFFLINE osv-scanner pass on an operator-uploaded SBOM/lockfile
# (plan S1). It never clones a repo, downloads a tarball, or runs a package
# manager. graph_db and supply_chain_common are volume-mounted at spawn time (like
# trufflehog mounts graph_db); the offline OSV DB is mounted read-only at /osv-db.

# osv-scanner v2.4.0 needs Go >= 1.26.4; build it here and COPY the binary.
FROM golang:1-bookworm AS osv-builder
RUN GOBIN=/out go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.4.0

FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=osv-builder /out/osv-scanner /usr/local/bin/osv-scanner

COPY supply_chain_scan/requirements.txt /app/supply_chain_scan/requirements.txt
RUN pip install --no-cache-dir -r /app/supply_chain_scan/requirements.txt

COPY supply_chain_scan/ /app/supply_chain_scan/

# graph_db + supply_chain_common are bind-mounted at /app/graph_db and
# /app/supply_chain_common by the orchestrator spawn (not baked here).

ENV PROJECT_ID="" USER_ID="" WEBAPP_API_URL=""

CMD ["python", "/app/supply_chain_scan/main.py"]
