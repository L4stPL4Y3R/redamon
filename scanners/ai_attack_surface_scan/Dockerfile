# =============================================================================
# RedAmon AI Attack Surface Scanner — Python Container
# =============================================================================
# One image, PER-TOOL VIRTUALENVS. The attack tools' dependencies conflict and
# cannot share one environment (garak needs datasets<4.0; pyrit needs >=4.8.0;
# promptfoo is Node.js). So the shared spine (neo4j driver + main/target_loader/
# safety/normalizer) runs in the BASE interpreter, and each tool gets its own
# venv. Each adapter invokes its tool via that venv's interpreter as a subprocess.
# =============================================================================

FROM python:3.12-slim

LABEL maintainer="RedAmon Project"
LABEL description="AI Attack Surface deterministic offensive scanner for RedAmon"

WORKDIR /app

# Build tools some tool wheels need at install time. (Kept in the image; a future
# optimization could strip build-essential after the venvs are built to slim it.)
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential curl \
    && rm -rf /var/lib/apt/lists/*

# --- Base (shared spine): just the Neo4j driver ---
COPY scanners/ai_attack_surface_scan/requirements.txt /tmp/base-requirements.txt
RUN pip install --no-cache-dir -r /tmp/base-requirements.txt

# --- Per-tool venvs (isolated, conflicting deps) ---
COPY scanners/ai_attack_surface_scan/adapters/garak/requirements.txt /tmp/garak-requirements.txt
RUN python -m venv /opt/venv-garak \
    && /opt/venv-garak/bin/pip install --no-cache-dir -U pip \
    && /opt/venv-garak/bin/pip install --no-cache-dir -r /tmp/garak-requirements.txt

COPY scanners/ai_attack_surface_scan/adapters/pyrit/requirements.txt /tmp/pyrit-requirements.txt
# pyrit pulls base2048, which ships no arm64/aarch64 wheel and compiles a small
# Rust extension from source. Provide a Rust toolchain ONLY for this build and
# remove it in the same layer so the image stays slim (on amd64 a prebuilt wheel
# exists and the toolchain simply goes unused).
RUN python -m venv /opt/venv-pyrit \
    && /opt/venv-pyrit/bin/pip install --no-cache-dir -U pip \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && . "$HOME/.cargo/env" \
    && /opt/venv-pyrit/bin/pip install --no-cache-dir -r /tmp/pyrit-requirements.txt \
    && rustup self uninstall -y

COPY scanners/ai_attack_surface_scan/adapters/giskard/requirements.txt /tmp/giskard-requirements.txt
RUN python -m venv /opt/venv-giskard \
    && /opt/venv-giskard/bin/pip install --no-cache-dir -U pip \
    && /opt/venv-giskard/bin/pip install --no-cache-dir -r /tmp/giskard-requirements.txt

# --- promptfoo (Node CLI; NOT a venv) ---
# First non-Python tool. Install Node 22 + the pinned promptfoo. The dataset-based
# red-team plugins (our defaults) pull their payloads from HuggingFace
# (datasets-server) at scan time -- promptfoo does NOT persist that dataset to a
# disk cache, so there is nothing to pre-warm into the image; the scan container
# live-fetches at runtime (it is spawned on the host network and has the egress).
# Grading is forced to the local Ollama, so there is zero egress to OpenAI or
# promptfoo-cloud (see adapters/promptfoo/TOOL_API.md §8).
ENV PROMPTFOO_VERSION=0.121.17
ENV PROMPTFOO_BIN=promptfoo
ENV PROMPTFOO_DISABLE_TELEMETRY=true \
    PROMPTFOO_DISABLE_UPDATE=true \
    PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g "promptfoo@${PROMPTFOO_VERSION}" \
    && rm -rf /var/lib/apt/lists/* /root/.npm

# Base-interpreter extra: PyYAML lets the promptfoo adapter parse promptfoo's
# generated redteam test file (always YAML) so it can apply the local encoding
# strategies offline (adapters/promptfoo/local_strategies.py). Kept as its own
# late layer so it reuses the heavy venv/npm cache above instead of busting it.
RUN pip install --no-cache-dir "PyYAML>=6.0"

# Copy the scanner (spine + adapters). The runner scripts are invoked by their
# tool's venv; the spine runs in the base interpreter.
COPY scanners/ai_attack_surface_scan/ ./ai_attack_surface_scan/

RUN mkdir -p ai_attack_surface_scan/output

# Per-tool interpreter paths (adapters default to these; overridable for dev).
ENV GARAK_PYTHON=/opt/venv-garak/bin/python
ENV PYRIT_PYTHON=/opt/venv-pyrit/bin/python
ENV GISKARD_PYTHON=/opt/venv-giskard/bin/python
ENV PYTHONPATH=/app/ai_attack_surface_scan
ENV PYTHONUNBUFFERED=1

CMD ["python", "ai_attack_surface_scan/main.py"]
