# =============================================================================
# RedAmon - Web Cache Vulnerability Scanner (WCVS) image
# =============================================================================
# Builds Hackmanit's WCVS (https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner)
# from source. There is no official prebuilt image on a registry, so RedAmon
# builds a local image tagged `redamon-wcvs:latest` and runs it docker-in-docker
# from the recon container (see recon/cache_scan/wcvs_runner.py).
#
# Build:  docker compose --profile tools build wcvs
# Run:    docker run --rm --net=host redamon-wcvs /wcvs -u https://example.com -gr
#
# Pin WCVS_REF to a release tag/commit for reproducible builds.
# -----------------------------------------------------------------------------
FROM golang:1.23-bookworm AS builder

ARG WCVS_REF=master
RUN git clone https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner.git /src \
    && cd /src \
    && git checkout "${WCVS_REF}" \
    && CGO_ENABLED=0 go build -o /wcvs .

# -----------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Binary at /wcvs (matches upstream), wordlists relative to WORKDIR so WCVS
# finds its default header/parameter lists without -hw/-pw flags.
COPY --from=builder /wcvs /wcvs
COPY --from=builder /src/wordlists /app/wordlists

ENTRYPOINT ["/wcvs"]
