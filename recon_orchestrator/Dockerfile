FROM python:3.11-slim

WORKDIR /app

# Install Docker CLI for container management and curl for healthcheck
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    docker.io \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Pre-create the shared capture-spool mount point, world-writable. This image is
# the first mounter of the `capture_spool` named volume (compose starts the
# orchestrator by default; the capture profile does not), and Docker copies a
# directory's mode onto a still-EMPTY named volume. Without this the volume is
# born root:root 0755 and the non-root capture-proxy / traffic-ingest containers
# cannot create their spool subdirs (issue #159). _ensure_spool_shared() in api.py
# is the runtime backstop that also repairs already-broken volumes.
RUN mkdir -p /spool && chmod 0777 /spool

# Copy application code
COPY *.py ./
# Shipped memory profile (per-scan-type envelopes). Compose bind-mounts the source
# dir over /app anyway, but baking it in keeps the image correct on its own; the
# host-specific resource_profile.json is gitignored and layers on top at runtime.
COPY resource_profile.default.json ./

# Run the FastAPI application
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8010"]
