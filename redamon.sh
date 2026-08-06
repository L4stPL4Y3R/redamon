#!/usr/bin/env bash
# =============================================================================
# RedAmon CLI - Simplified installation, update, and lifecycle management
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_FILE="$SCRIPT_DIR/VERSION"
GVM_FLAG_FILE="$SCRIPT_DIR/.gvm-enabled"
KBASE_FLAG_FILE="$SCRIPT_DIR/.kbase-enabled"
KBASE_DISABLED_FLAG_FILE="$SCRIPT_DIR/.kbase-disabled"
LEGACY_SKIPKBASE_FLAG_FILE="$SCRIPT_DIR/.skipkbase"

# Service lists
CORE_SERVICES="postgres neo4j docker-broker recon-orchestrator kali-sandbox agent webapp"
# Build-only images run on demand (NOT long-running services). All live under the
# compose `tools` profile and the redamon-* tag namespace. ai-attack-surface is the
# AI Attack Surface scanner (garak/pyrit/giskard/promptfoo). wcvs is the Web Cache
# Vulnerability Scanner, run docker-in-docker by the recon container for the web
# cache poisoning module.
TOOL_IMAGES="redamon-recon:latest redamon-vuln-scanner:latest redamon-github-hunter:latest redamon-trufflehog:latest redamon-baddns:latest redamon-ai-attack-surface:latest redamon-codefix-sandbox:latest redamon-wcvs:latest"
DEV_COMPOSE="-f docker-compose.yml -f docker-compose.dev.yml"

# Orchestrator-spawned containers that docker compose does NOT manage (they are
# created at runtime via the Docker API, so `compose down` leaves them behind and
# they must be wiped explicitly):
#   - AI Attack Surface scan containers:  redamon-ai-attack-<proj>-<run>
#   - On-demand local LLM (Ollama) judge/attacker:  redamon-local-llm
#   - CodeFix build sandboxes (T6/E10):  redamon-codefix-<job>
# Orchestrator-spawned, NON-compose-managed containers (repeated name filters are
# OR'd by docker ps). Includes the capture proxy + ingest pair: they are spawned by
# the orchestrator with restart:unless-stopped and live in the "capture" profile, so
# `docker compose down` (no --profile capture) would NOT stop them and they would
# leak past down/clean/purge — and hold the capture_* volumes purge tries to drop.
SPAWNED_CONTAINER_NAME_FILTERS=(--filter "name=redamon-ai-attack-" --filter "name=redamon-local-llm" --filter "name=redamon-codefix-" --filter "name=redamon-capture-proxy" --filter "name=redamon-traffic-ingest")
# The on-demand local LLM image (pulled at runtime, not built) + its models volume.
LOCAL_LLM_IMAGE="${LOCAL_LLM_IMAGE:-ollama/ollama:latest}"
LOCAL_LLM_VOLUME="${LOCAL_LLM_VOLUME:-redamon_llm_models}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

print_banner() {
    echo -e "${RED}${BOLD}"
    echo "  ____          _    _                         "
    echo " |  _ \\ ___  __| |  / \\   _ __ ___   ___  _ __"
    echo " | |_) / _ \\/ _\` | / _ \\ | '_ \` _ \\ / _ \\| '_ \\ "
    echo " |  _ <  __/ (_| |/ ___ \\| | | | | | (_) | | | |"
    echo " |_| \\_\\___|\\__,_/_/   \\_\\_| |_| |_|\\___/|_| |_|"
    echo -e "${NC}"
}

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }

# Read a `KEY=value` line from an env file and print the value (empty if the key
# or file is absent). CRITICAL: this must NEVER return non-zero. Callers assign
# its output as `x="$(_env_get ...)"` under `set -euo pipefail`, where a bare
# `grep` that finds nothing exits 1, `pipefail` propagates it, and `set -e` then
# aborts the whole script mid-assignment with no error message. That is exactly
# what made `./redamon.sh install` die silently right after generating the auth
# tokens on a FRESH install (#157): the new `.env` has no POSTGRES_DB line, so
# the TRAFFIC_INGEST_DATABASE_URL grep failed and killed the install before a
# single container was built. The trailing `|| true` pins the exit status to 0.
_env_get() {
    local key="$1" file="${2:-$SCRIPT_DIR/.env}"
    [ -f "$file" ] || return 0
    grep -E "^${key}=" "$file" 2>/dev/null | head -1 | cut -d= -f2- || true
}

# ---------------------------------------------------------------------------
# Adaptive build parallelism (memory-safe Docker builds)
# ---------------------------------------------------------------------------
# The Next.js `webapp` image build peaks at several GB of RAM. Building it in
# parallel with the heavy `agent` image (pip install + large layer export) has
# OOM-killed the webapp build on low-memory hosts ("Killed" / exit code 137).
# Two-layer mitigation, applied to EVERY `docker compose build` in this script
# via compose_build():
#   Layer 1: always build `webapp` on its own first. Once built its layers are
#            cached, so it never compiles concurrently with another image.
#   Layer 2: cap COMPOSE_PARALLEL_LIMIT for the remaining images based on the
#            memory/CPU actually available to the Docker BUILD ENGINE.
#
# Cross-platform: on macOS/Windows the Docker Desktop builder runs inside a Linux
# VM whose memory is capped independently of host RAM, so reading host RAM would
# be misleading. `docker info` reports the engine's real limits and is correct on
# Linux, macOS and Windows alike; host probing (/proc, sysctl) is only a fallback.
#
# Override: REDAMON_BUILD_PARALLEL=N forces the limit (N>=1), =0 leaves it
# unbounded. webapp isolation always applies regardless of the override.

BUILD_MEM_MB=0
BUILD_NCPU=1
BUILD_RES_SOURCE="unknown"

# Query a single `docker info` field, guarding against a wedged daemon. `timeout`
# is not present on stock macOS, so use it only when available.
_docker_info_field() {
    local field="$1" out=""
    if command -v timeout >/dev/null 2>&1; then
        out="$(timeout 8 docker info --format "{{.$field}}" 2>/dev/null)" || out=""
    else
        out="$(docker info --format "{{.$field}}" 2>/dev/null)" || out=""
    fi
    printf '%s' "$out"
}

# Populate BUILD_MEM_MB / BUILD_NCPU / BUILD_RES_SOURCE.
detect_build_resources() {
    local mem_bytes ncpu

    # Primary source: the Docker engine's own view (VM-aware on Mac/Windows).
    mem_bytes="$(_docker_info_field MemTotal)"
    ncpu="$(_docker_info_field NCPU)"
    mem_bytes="${mem_bytes//[^0-9]/}"
    ncpu="${ncpu//[^0-9]/}"

    if [[ -n "$mem_bytes" && "$mem_bytes" -gt 0 ]]; then
        BUILD_MEM_MB=$(( mem_bytes / 1048576 ))
        BUILD_RES_SOURCE="docker info"
    else
        # Fallback: probe the host OS directly.
        case "$(uname -s 2>/dev/null || echo unknown)" in
            Darwin)
                mem_bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
                mem_bytes="${mem_bytes//[^0-9]/}"
                if [[ -n "$mem_bytes" && "$mem_bytes" -gt 0 ]]; then
                    BUILD_MEM_MB=$(( mem_bytes / 1048576 ))
                fi
                BUILD_RES_SOURCE="sysctl (host)"
                ;;
            *)  # Linux, WSL2, Git Bash/MSYS all expose /proc/meminfo
                if [[ -r /proc/meminfo ]]; then
                    local mem_kb
                    mem_kb="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)"
                    mem_kb="${mem_kb//[^0-9]/}"
                    if [[ -n "$mem_kb" && "$mem_kb" -gt 0 ]]; then
                        BUILD_MEM_MB=$(( mem_kb / 1024 ))
                    fi
                    BUILD_RES_SOURCE="/proc/meminfo (host)"
                fi
                ;;
        esac
    fi

    # CPU count: docker info value, else nproc, else sysctl, else 1.
    if [[ -z "$ncpu" || "$ncpu" -lt 1 ]]; then
        if command -v nproc >/dev/null 2>&1; then
            ncpu="$(nproc 2>/dev/null || echo 1)"
        elif [[ "$(uname -s 2>/dev/null || echo unknown)" == "Darwin" ]]; then
            ncpu="$(sysctl -n hw.logicalcpu 2>/dev/null || echo 1)"
        else
            ncpu=1
        fi
        ncpu="${ncpu//[^0-9]/}"
    fi
    if [[ -z "$ncpu" || "$ncpu" -lt 1 ]]; then ncpu=1; fi
    BUILD_NCPU="$ncpu"
}

# Echo the chosen COMPOSE_PARALLEL_LIMIT. "0" means "leave unbounded".
# Assumes detect_build_resources() has already run.
pick_parallelism() {
    # Explicit override wins and skips heuristics entirely.
    if [[ -n "${REDAMON_BUILD_PARALLEL:-}" ]]; then
        local ov="${REDAMON_BUILD_PARALLEL//[^0-9]/}"
        if [[ -z "$ov" ]]; then ov=1; fi
        printf '%s' "$ov"
        return
    fi

    # Could not detect memory -> be conservative (serial).
    if [[ "$BUILD_MEM_MB" -le 0 ]]; then
        printf '1'
        return
    fi

    # Reserve headroom for the OS plus RedAmon containers that stay running
    # during `update` (neo4j/postgres/agent), and budget ~2GB per concurrent
    # heavy build.
    local reserve=2560 per_build=2048 usable mem_bound parallel
    usable=$(( BUILD_MEM_MB - reserve ))
    if [[ "$usable" -lt "$per_build" ]]; then
        mem_bound=1
    else
        mem_bound=$(( usable / per_build ))
    fi

    parallel="$mem_bound"
    if [[ "$BUILD_NCPU" -lt "$parallel" ]]; then parallel="$BUILD_NCPU"; fi
    if [[ "$parallel" -lt 1 ]]; then parallel=1; fi
    if [[ "$parallel" -gt 6 ]]; then parallel=6; fi
    printf '%s' "$parallel"
}

# Warn when the engine has so little memory that even the isolated webapp build
# may OOM -- no scheduling can fix that, the user must grant more memory.
maybe_warn_low_memory() {
    if [[ "$BUILD_MEM_MB" -gt 0 && "$BUILD_MEM_MB" -lt 5120 ]]; then
        warn "Low build memory: ~$(( BUILD_MEM_MB / 1024 ))GB available to Docker (source: ${BUILD_RES_SOURCE}); the webapp build may still run out of memory."
        case "$(uname -s 2>/dev/null || echo unknown)" in
            Darwin|MINGW*|MSYS*|CYGWIN*)
                warn "  Increase it in Docker Desktop > Settings > Resources > Memory (6GB+ recommended), then re-run."
                ;;
            *)
                if grep -qi microsoft /proc/version 2>/dev/null; then
                    warn "  On WSL2, raise memory via %UserProfile%\\.wslconfig ([wsl2] memory=6GB), run 'wsl --shutdown', then re-run."
                else
                    warn "  Consider adding swap: sudo fallocate -l 8G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile"
                fi
                ;;
        esac
    fi
}

# =============================================================================
# Memory governor (Part 4): startup RAM gate + adaptive per-service cap export.
# Both reuse detect_build_resources() (docker info / /proc / sysctl) so the
# figures match the rest of this script. Sizes accept g/m/k suffixes or bytes.
# =============================================================================

# Convert a Docker-style size ("2g","2048m","1073741824") to whole MB. Empty on
# invalid input. Plain numbers are bytes (matches resource_governor.parse_size).
_size_to_mb() {
    local v="${1:-}"
    v="$(printf '%s' "$v" | tr 'A-Z' 'a-z' | tr -d ' ')"
    [[ -z "$v" ]] && { printf ''; return; }
    v="${v%b}"                              # tolerate trailing 'b' (e.g. 512mb)
    local unit="" num="$v"
    case "$v" in
        *k) unit=k; num="${v%k}" ;;
        *m) unit=m; num="${v%m}" ;;
        *g) unit=g; num="${v%g}" ;;
        *t) unit=t; num="${v%t}" ;;
    esac
    # Allow a decimal (e.g. 1.5g, 0.5g); plain number = bytes.
    [[ "$num" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf ''; return; }
    # awk keeps the fraction ('1.5g' -> 1536), which pure bash integer math loses.
    awk -v n="$num" -v u="$unit" 'BEGIN{
        m = (u=="k")?1024 : (u=="m")?1048576 : (u=="g")?1073741824 : (u=="t")?1099511627776 : 1;
        printf "%d", int(n*m/1048576);
    }'
}

# Refuse to start when the host/VM can't hold the always-on core services, with
# a clear message, instead of failing mysteriously later. Returns 1 to abort.
# Override with REDAMON_SKIP_RAM_GATE=1 or REDAMON_MIN_RAM_MB=<mb>.
preflight_ram_gate() {
    [[ "${REDAMON_SKIP_RAM_GATE:-}" == "1" ]] && return 0
    detect_build_resources
    local required_mb baseline_mb headroom_mb
    if [[ -n "${REDAMON_MIN_RAM_MB:-}" ]]; then
        required_mb="${REDAMON_MIN_RAM_MB//[^0-9]/}"
    else
        baseline_mb="$(_size_to_mb "${SERVICE_BASELINE_MEM:-6g}")"; [[ -z "$baseline_mb" ]] && baseline_mb=6144
        headroom_mb="$(_size_to_mb "${OS_HEADROOM_MEM:-2g}")";      [[ -z "$headroom_mb" ]] && headroom_mb=2048
        required_mb=$(( baseline_mb + headroom_mb ))
    fi
    [[ -z "$required_mb" || "$required_mb" -le 0 ]] && return 0
    # ~512MB slack: docker-info MemTotal on a physical 8GB host reads ~7.7GB
    # (kernel/reserved), which should still pass an 8GB requirement.
    local threshold=$(( required_mb - 512 ))
    [[ "$threshold" -lt 0 ]] && threshold="$required_mb"
    if [[ "${BUILD_MEM_MB:-0}" -gt 0 && "$BUILD_MEM_MB" -lt "$threshold" ]]; then
        error "Insufficient memory for RedAmon core services: ~$(( BUILD_MEM_MB / 1024 ))GB available to Docker (source: ${BUILD_RES_SOURCE}), need ~$(( required_mb / 1024 ))GB."
        error "Free up memory, raise the Docker VM memory, or set REDAMON_SKIP_RAM_GATE=1 to override."
        return 1
    fi
    return 0
}

# Export a clamped "<mb>m" cap for VAR unless the user already set it.
_export_clamped_cap() {
    local var="$1" val="$2" floor="$3" ceil="$4"
    [[ -n "${!var:-}" ]] && return 0          # respect explicit override
    [[ "$val" -lt "$floor" ]] && val="$floor"
    [[ "$val" -gt "$ceil" ]] && val="$ceil"
    export "$var=${val}m"
}

# Export a CPU cap of min(compose default, detected cores) for VAR, unless the
# operator pinned it. Skips when the core count is unknown, leaving the compose
# default in place.
_export_cpu_cap() {
    local var="$1" default="$2" n="${BUILD_NCPU:-0}"
    [[ -n "${!var:-}" ]] && return 0                 # shell/env override wins
    # A pin in .env must win too: compose gives the shell environment priority
    # over .env, so exporting here would silently override the operator's value.
    [[ -r "$SCRIPT_DIR/.env" ]] && grep -q "^[[:space:]]*${var}=" "$SCRIPT_DIR/.env" && return 0
    [[ "$n" -lt 1 ]] && return 0
    [[ "$default" -gt "$n" ]] && default="$n"
    export "$var=$default"
}

# #163: docker-compose.yml carries generous `cpus:` defaults sized for a
# workstation (neo4j 8, kali 10, agent 8). The Docker daemon REJECTS any cpus
# value above the host core count -- "range of CPUs is from 0.01 to 4.00, as
# there are only 4 CPUs available" -- so on a 4-vCPU VM every `docker compose
# up` died before the stack came up. Clamp each cap to the detected core count.
# `cpus:` is a limit, not a reservation, so clamping loses nothing: the core
# count was already the real ceiling. Keep these defaults in sync with
# docker-compose.yml and deploy/single-host/deploy.sh's cap_cpus block.
export_cpu_caps() {
    [[ -z "${BUILD_NCPU:-}" ]] && detect_build_resources
    _export_cpu_cap POSTGRES_CPUS 4
    _export_cpu_cap NEO4J_CPUS 8
    _export_cpu_cap KALI_CPUS 10
    _export_cpu_cap RECON_ORCHESTRATOR_CPUS 4
    _export_cpu_cap AGENT_CPUS 8
    _export_cpu_cap WEBAPP_CPUS 4
    _export_cpu_cap DOCKER_BROKER_CPUS 2
}

# Derive per-service memory caps from detected RAM and export them so
# docker-compose.yml `${VAR:-default}` picks them up. Always-on services get a
# static generous cap sized to the host (Part 4). No-op if RAM undetectable.
export_resource_caps() {
    detect_build_resources
    # CPU caps first: unlike the memory caps they do not depend on RAM
    # detection, so they must be applied before the undetectable-RAM bail-out.
    export_cpu_caps
    [[ "${BUILD_MEM_MB:-0}" -le 0 ]] && return 0
    local t="$BUILD_MEM_MB"
    # neo4j: the container mem_limit MUST exceed heap + pagecache or the JVM gets
    # OOM-killed. Derive NEO4J_MEM from the (clamped) heap+pagecache plus JVM
    # overhead headroom (metaspace, threads, direct buffers), never an
    # independent fraction that could land below heap+pagecache.
    local heap_mb pc_mb neo_mb eff_heap eff_pc
    heap_mb=$(( t * 15 / 100 )); [[ "$heap_mb" -lt 512 ]] && heap_mb=512; [[ "$heap_mb" -gt 4096 ]] && heap_mb=4096
    pc_mb=$(( t * 10 / 100 ));   [[ "$pc_mb"   -lt 512 ]] && pc_mb=512;   [[ "$pc_mb"   -gt 4096 ]] && pc_mb=4096
    # Derive the container limit from the EFFECTIVE heap/pagecache (a user's
    # NEO4J_HEAP override wins), or it could land below the JVM heap -> OOM at boot.
    eff_heap="$(_size_to_mb "${NEO4J_HEAP:-${heap_mb}m}")"; [[ -z "$eff_heap" ]] && eff_heap="$heap_mb"
    eff_pc="$(_size_to_mb "${NEO4J_PAGECACHE:-${pc_mb}m}")"; [[ -z "$eff_pc" ]] && eff_pc="$pc_mb"
    neo_mb=$(( eff_heap + eff_pc + 1024 ))
    [[ -z "${NEO4J_HEAP:-}" ]]      && export NEO4J_HEAP="${heap_mb}m"
    [[ -z "${NEO4J_PAGECACHE:-}" ]] && export NEO4J_PAGECACHE="${pc_mb}m"
    [[ -z "${NEO4J_MEM:-}" ]]       && export NEO4J_MEM="${neo_mb}m"
    _export_clamped_cap AGENT_MEM         $(( t * 12 / 100 )) 1024 4096
    _export_clamped_cap GVMD_MEM          $(( t * 12 / 100 )) 1024 3072
    _export_clamped_cap RECON_ORCHESTRATOR_MEM $(( t * 5 / 100 )) 512 2048
    _export_clamped_cap WEBAPP_MEM        $(( t * 6 / 100 )) 512  2048
    _export_clamped_cap POSTGRES_MEM      $(( t * 6 / 100 )) 512  2048
    _export_clamped_cap KALI_MEM          $(( t * 6 / 100 )) 512  2048
}

# Optional one-time compressed-RAM (zram) swap cushion so brief memory overshoots
# degrade gracefully (swap to compressed RAM) instead of OOM-killing. Linux-native
# host only; a NO-OP on macOS/Windows (Docker Desktop's VM manages its own swap)
# and when REDAMON_ENABLE_ZRAM != 1. Best-effort: never fatal, never interactive.
setup_zram() {
    [[ "${REDAMON_ENABLE_ZRAM:-}" == "1" ]] || return 0

    # Docker Desktop / WSL2 / mac: cannot add zram to the host VM from here.
    case "$(uname -s 2>/dev/null || echo unknown)" in
        Linux) ;;
        *) info "zram: skipped (not a native Linux host)"; return 0 ;;
    esac
    if grep -qi microsoft /proc/version 2>/dev/null; then
        info "zram: skipped (WSL2 manages its own memory)"; return 0
    fi
    # Already have zram swap active? Leave it.
    if swapon --show=NAME --noheadings 2>/dev/null | grep -q zram; then
        info "zram: already active"; return 0
    fi
    if ! command -v zramctl >/dev/null 2>&1; then
        warn "zram: zramctl not found; skipping (install util-linux/zram-tools to enable)"; return 0
    fi

    detect_build_resources
    local size="${REDAMON_ZRAM_SIZE:-}"
    if [[ -z "$size" ]]; then
        if [[ "${BUILD_MEM_MB:-0}" -le 0 ]]; then
            warn "zram: cannot size (RAM undetectable); set REDAMON_ZRAM_SIZE to enable"; return 0
        fi
        # Default: half of detected RAM, clamped to [512M, 8G].
        local half=$(( BUILD_MEM_MB / 2 ))
        [[ "$half" -gt 8192 ]] && half=8192
        [[ "$half" -lt 512 ]] && half=512
        size="${half}M"
    fi

    # Requires root; use sudo non-interactively so we never hang on a password.
    local SUDO=""
    if [[ "$(id -u)" != "0" ]]; then
        if sudo -n true 2>/dev/null; then SUDO="sudo -n"; else
            warn "zram: needs root and passwordless sudo is unavailable; skipping"; return 0
        fi
    fi

    local dev
    if dev="$($SUDO zramctl --find --size "$size" --algorithm zstd 2>/dev/null)" && [[ -n "$dev" ]]; then
        if $SUDO mkswap "$dev" >/dev/null 2>&1 && $SUDO swapon --priority 100 "$dev" 2>/dev/null; then
            success "zram: enabled ${size} compressed swap on ${dev}"
        else
            warn "zram: failed to enable swap on ${dev}; cleaning up"
            $SUDO zramctl --reset "$dev" 2>/dev/null || true
        fi
    else
        warn "zram: could not allocate a zram device; skipping"
    fi
    return 0
}

# Memory-safe replacement for `docker compose ... build ...`. Pass exactly the
# args that would follow `docker compose`, e.g.:
#   compose_build --profile tools build
#   compose_build --profile tools build recon vuln-scanner
#   compose_build build recon-orchestrator kali-sandbox agent webapp docker-broker
compose_build() {
    detect_build_resources
    local parallel; parallel="$(pick_parallelism)"

    # Find the service names (positional args after the `build` subcommand).
    local seen_build=false svc has_webapp=false svc_count=0
    for svc in "$@"; do
        if [[ "$seen_build" == false ]]; then
            if [[ "$svc" == "build" ]]; then seen_build=true; fi
            continue
        fi
        case "$svc" in
            -*) continue ;;   # skip build flags (--no-cache, --pull, ...)
        esac
        svc_count=$(( svc_count + 1 ))
        if [[ "$svc" == "webapp" ]]; then has_webapp=true; fi
    done

    # A build with no explicit service list builds everything -> webapp included.
    local isolate_webapp=false
    if [[ "$has_webapp" == true || "$svc_count" -eq 0 ]]; then
        isolate_webapp=true
    fi

    info "Docker build resources: ~$(( BUILD_MEM_MB / 1024 ))GB RAM / ${BUILD_NCPU} CPU (${BUILD_RES_SOURCE}); parallelism=${parallel}"
    maybe_warn_low_memory

    # Layer 1: build the RAM-heavy webapp on its own first.
    if [[ "$isolate_webapp" == true ]]; then
        info "Building webapp in isolation first (prevents out-of-memory during parallel build)..."
        docker compose build webapp
    fi

    # Layer 2: build the (remaining) images with a capped parallel limit. If
    # webapp was in the set it is now cached, so re-passing it is a no-op.
    if [[ -n "$parallel" && "$parallel" -ge 1 ]]; then
        COMPOSE_PARALLEL_LIMIT="$parallel" docker compose "$@"
    else
        docker compose "$@"   # REDAMON_BUILD_PARALLEL=0 -> unbounded
    fi
}

# Best-effort POST to the orchestrator capture-proxy/start (idempotent reconcile:
# removes any stale instance, (re)spawns proxy + ingest on the current image using
# the orchestrator's .env-derived runtime knobs). Returns non-zero if there is no
# ORCHESTRATOR_API_KEY or the orchestrator is unreachable.
_capture_start_post() {
    local env_file="$SCRIPT_DIR/.env" okey="" port=""
    okey="$(_env_get ORCHESTRATOR_API_KEY "$env_file")"
    port="$(_env_get RECON_ORCH_PORT "$env_file")"
    port="${port:-8010}"
    [ -z "$okey" ] && return 1
    curl -fsS -X POST "http://127.0.0.1:${port}/capture-proxy/start" \
        -H "X-Orchestrator-Key: ${okey}" -H 'Content-Type: application/json' \
        -o /dev/null 2>/dev/null
}

# True (0) if the HTTP Traffic Capture master switch is on for any user. The proxy
# is a global singleton, so one enabled operator means it should run.
_capture_master_switch_on() {
    local v
    v="$(docker compose exec -T postgres psql -U redamon -d redamon -tAc \
        "SELECT bool_or(capture_proxy_enabled) FROM user_settings;" 2>/dev/null | tr -d '[:space:]')"
    [ "$v" = "t" ]
}

# If the capture proxy is currently running, ask the orchestrator to recreate it so
# a freshly-rebuilt redamon-capture-proxy:latest actually goes live — a running
# container otherwise keeps the OLD image (security fixes to the addon / egress /
# ingest / redaction would NOT apply until the next Settings toggle). Best-effort.
# A UI-customised port/scope reverts to the .env defaults until the next Settings save.
_reconcile_capture_if_running() {
    docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-capture-proxy$' || return 0
    info "Refreshing the running capture proxy onto the rebuilt image..."
    if _capture_start_post; then
        success "Capture proxy refreshed onto the new image."
    else
        warn "Could not refresh the running capture proxy (no ORCHESTRATOR_API_KEY or orchestrator unreachable); toggle HTTP Traffic Capture off/on in Settings to apply the update."
    fi
}

# The capture proxy + ingest are orchestrator-spawned (NOT compose-managed), so a
# stack restart / `up` leaves them down and nothing restarts them — recon then runs
# DIRECT ("capture degraded") and silently captures nothing. If the master switch is
# on, reconcile them here so capture survives a restart. Idempotent + best-effort;
# retries briefly while the just-started orchestrator becomes reachable.
ensure_capture_proxy_running() {
    _capture_master_switch_on || return 0
    docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-capture-proxy$' && return 0
    info "HTTP Traffic Capture is enabled — starting the capture proxy..."
    local i
    for i in 1 2 3 4 5 6 7 8; do
        if _capture_start_post; then success "Capture proxy started."; return 0; fi
        sleep 3
    done
    warn "HTTP Traffic Capture is on but the capture proxy could not be started (orchestrator not ready or ORCHESTRATOR_API_KEY missing). Re-run ./redamon.sh up, or toggle it in Settings."
}

get_version() {
    if [[ -f "$VERSION_FILE" ]]; then
        cat "$VERSION_FILE" | tr -d '[:space:]'
    else
        echo "unknown"
    fi
}

is_gvm_enabled() {
    [[ -f "$GVM_FLAG_FILE" ]]
}

is_kbase_enabled() {
    [[ -f "$KBASE_FLAG_FILE" ]]
}

# One-time migration from the legacy `.skipkbase` flag (RedAmon <=4.9.3) to the
# new explicit flag pair (`.kbase-enabled` / `.kbase-disabled`). cmd_install
# always writes one of the two markers so the user's explicit choice is sticky
# across `clean` (which keeps KB data on disk). Behavior per case:
#   - .kbase-enabled or .kbase-disabled exists → already migrated → no-op
#   - .skipkbase exists                        → legacy default install (KB off) → convert to .kbase-disabled
#   - no markers, FAISS index on disk          → legacy --kbase install (KB on)  → create .kbase-enabled
#   - no markers, no data                      → fresh clone → create .kbase-disabled (README default)
# Called from every command except cmd_install (which sets the markers explicitly).
_migrate_legacy_kbase_flag() {
    if [[ -f "$KBASE_FLAG_FILE" || -f "$KBASE_DISABLED_FLAG_FILE" ]]; then
        rm -f "$LEGACY_SKIPKBASE_FLAG_FILE"
        return
    fi
    if [[ -f "$LEGACY_SKIPKBASE_FLAG_FILE" ]]; then
        rm -f "$LEGACY_SKIPKBASE_FLAG_FILE"
        touch "$KBASE_DISABLED_FLAG_FILE"
        return
    fi
    if [[ -s "$SCRIPT_DIR/knowledge_base/data/index.faiss" ]]; then
        touch "$KBASE_FLAG_FILE"
    else
        touch "$KBASE_DISABLED_FLAG_FILE"
    fi
}

check_prerequisites() {
    local missing=0

    if ! command -v docker &>/dev/null; then
        error "Docker is not installed. See: https://docs.docker.com/get-docker/"
        missing=1
    fi

    if ! docker compose version &>/dev/null; then
        error "Docker Compose v2 is not installed. See: https://docs.docker.com/compose/install/"
        missing=1
    fi

    if ! command -v git &>/dev/null; then
        error "Git is not installed."
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
}

export_version() {
    export REDAMON_VERSION
    REDAMON_VERSION="$(get_version)"
}

ensure_auth_secrets() {
    local env_file="$SCRIPT_DIR/.env"
    touch "$env_file"
    if ! grep -q '^AUTH_SECRET=' "$env_file" 2>/dev/null; then
        echo "AUTH_SECRET=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated AUTH_SECRET"
    fi
    if ! grep -q '^INTERNAL_API_KEY=' "$env_file" 2>/dev/null; then
        echo "INTERNAL_API_KEY=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated INTERNAL_API_KEY"
    fi
    # S3/E6: least-privilege token injected into scan containers INSTEAD of the
    # master INTERNAL_API_KEY. Scoped (webapp) to settings/projects GET + agent
    # /llm/*; cannot mint admins or harvest LLM-provider keys.
    if ! grep -q '^SCANNER_API_KEY=' "$env_file" 2>/dev/null; then
        echo "SCANNER_API_KEY=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated SCANNER_API_KEY"
    fi
    if ! grep -q '^ORCHESTRATOR_API_KEY=' "$env_file" 2>/dev/null; then
        echo "ORCHESTRATOR_API_KEY=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated ORCHESTRATOR_API_KEY"
    fi
    # Shared bearer token the agent presents to the Kali MCP servers and the
    # servers validate on every inbound SSE request (STRIDE S10 defense-in-depth).
    # Stateless (not baked into any volume), so append-if-absent is safe.
    if ! grep -q '^MCP_AUTH_TOKEN=' "$env_file" 2>/dev/null; then
        echo "MCP_AUTH_TOKEN=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated MCP_AUTH_TOKEN"
    fi
    # Dedicated secret the webapp uses to sign short-lived agent-WebSocket tickets
    # and the agent verifies on the /ws/agent init frame (STRIDE S6). Kept SEPARATE
    # from AUTH_SECRET so an agent compromise cannot forge login cookies. Stateless.
    if ! grep -q '^AGENT_WS_TICKET_SECRET=' "$env_file" 2>/dev/null; then
        echo "AGENT_WS_TICKET_SECRET=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated AGENT_WS_TICKET_SECRET"
    fi
    # Inbound token the tunnel-manager (:8015) validates on config pushes, and the
    # webapp presents when pushing tunnel config (STRIDE I19/S14). Inbound-validation
    # only (same category as MCP_AUTH_TOKEN), so the worker holding it does not
    # violate the "worker holds no secrets" rule. Stateless.
    if ! grep -q '^TUNNEL_AUTH_TOKEN=' "$env_file" 2>/dev/null; then
        echo "TUNNEL_AUTH_TOKEN=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated TUNNEL_AUTH_TOKEN"
    fi
    # Scoped INSERT-only DSN for the HTTP-traffic-capture ingest worker. This is the
    # SINGLE SOURCE OF TRUTH for the traffic_ingest password: the webapp entrypoint
    # (scripts/apply-ingest-role.mjs) provisions the matching Postgres role from it
    # on every boot, and the orchestrator hands it to the spawned ingest container.
    # Without it the ingest gets an EMPTY DSN and every captured request is silently
    # dropped. Append-if-absent + hex password (URL/SQL-safe, no encoding needed).
    if ! grep -q '^TRAFFIC_INGEST_DATABASE_URL=' "$env_file" 2>/dev/null; then
        local _ti_db
        _ti_db="$(_env_get POSTGRES_DB "$env_file")"
        _ti_db="${_ti_db:-redamon}"
        echo "TRAFFIC_INGEST_DATABASE_URL=postgresql://traffic_ingest:$(openssl rand -hex 32)@postgres:5432/${_ti_db}" >> "$env_file"
        info "Generated TRAFFIC_INGEST_DATABASE_URL (capture ingest role)"
    fi
}

# Compose project name (used to resolve the data-volume names). Must match
# docker compose's own derivation or ensure_db_secrets would mis-detect a fresh
# vs existing install and could regenerate a password against a live DB.
# Precedence mirrors compose: exported COMPOSE_PROJECT_NAME, then the same var in
# .env, then the sanitised working-directory basename.
compose_project_name() {
    if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
        echo "$COMPOSE_PROJECT_NAME"
        return
    fi
    local env_file="$SCRIPT_DIR/.env"
    if [ -f "$env_file" ]; then
        local from_env
        from_env="$(_env_get COMPOSE_PROJECT_NAME "$env_file")"
        if [ -n "$from_env" ]; then
            echo "$from_env"
            return
        fi
    fi
    basename "$SCRIPT_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-'
}

# True (0) if the named docker volume for THIS project already exists.
_data_volume_exists() {
    local suffix="$1"   # e.g. postgres_data
    local project; project="$(compose_project_name)"
    docker volume inspect "${project}_${suffix}" >/dev/null 2>&1
}

# Rotate the LIVE Postgres password from <old> to <new> using the old creds.
# Returns 0 on success, non-zero on failure (wrong old password / DB down), so
# the caller can decide NOT to write .env (avoiding a split-brain). Isolated in
# its own function so the shell test harness can stub docker() around it.
_rotate_postgres_password() {
    local old="$1" new="$2"
    local user db
    user="$(_env_get POSTGRES_USER)"
    db="$(_env_get POSTGRES_DB)"
    user="${user:-redamon}"
    db="${db:-redamon}"
    docker exec -e "PGPASSWORD=${old}" redamon-postgres \
        psql -U "$user" -d "$db" -v ON_ERROR_STOP=1 \
        -c "ALTER USER \"${user}\" WITH PASSWORD '${new}';" >/dev/null 2>&1
}

# Rotate the LIVE Neo4j password from <old> to <new>. neo4j:5.26-community only
# supports the SELF-SERVICE form (ALTER CURRENT USER ... FROM ... TO ...); the
# admin form (ALTER USER neo4j SET PASSWORD) is Enterprise-only and is rejected
# on Community. On an already-initialised volume Neo4j ignores NEO4J_AUTH, so
# this cypher-shell rotation is the only effective path. Returns 0 on success.
_rotate_neo4j_password() {
    local old="$1" new="$2"
    docker exec redamon-neo4j \
        cypher-shell -u neo4j -p "$old" \
        "ALTER CURRENT USER SET PASSWORD FROM '${old}' TO '${new}';" >/dev/null 2>&1
}

# True iff `password` authenticates against the running Neo4j.
_neo4j_auth_ok() {
    docker exec redamon-neo4j cypher-shell -u neo4j -p "$1" 'RETURN 1;' >/dev/null 2>&1
}

# S13 / #160: the password Neo4j baked into its volume at first init is the ONLY
# one that works; NEO4J_AUTH is ignored once the volume exists. A .env value that
# was hand-set (the #155 work-around) or left over from a stale volume can disagree
# with it, and ensure_db_secrets trusts a pinned .env without checking -- so the
# mismatch only surfaces LATER as a cryptic `AuthenticationRateLimit` in the recon
# pipeline. Here we VERIFY the pinned password and auto-reconcile: clear any auth
# rate-limit (repeated wrong-password attempts lock out even the correct one), then
# rotate the volume TO the .env value using a known old password. If we cannot, we
# stop with rotate-or-wipe steps instead of handing over a silently-broken stack.
# Best-effort + fail-safe: if Neo4j will not come up we return 0 (never block a start
# on this check). Returns 1 only on a confirmed, un-reconcilable mismatch.
_reconcile_neo4j_password() {
    local envpw="$1"
    [[ -z "$envpw" ]] && return 0

    # Need Neo4j running to probe. .env already carries the password so the
    # fail-closed compose `:?` resolves; start it idempotently if it is down.
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-neo4j$'; then
        docker compose up -d neo4j >/dev/null 2>&1 || return 0
    fi
    _kb_wait_neo4j >/dev/null 2>&1 || return 0   # cannot verify -> do not block

    _neo4j_auth_ok "$envpw" && return 0

    warn "Neo4j did not accept NEO4J_PASSWORD from .env; clearing any auth rate-limit..."
    docker restart redamon-neo4j >/dev/null 2>&1
    _kb_wait_neo4j >/dev/null 2>&1 || true
    if _neo4j_auth_ok "$envpw"; then
        success "Neo4j auth OK after clearing the rate-limit."
        return 0
    fi

    # Genuine mismatch: try known old passwords, rotate the volume to the .env value.
    local cand
    for cand in "$(_env_get NEO4J_PASSWORD_OLD)" changeme123; do
        [[ -z "$cand" ]] && continue
        if _neo4j_auth_ok "$cand"; then
            info "Neo4j volume password differs from .env; rotating it to match .env..."
            if _rotate_neo4j_password "$cand" "$envpw" && _neo4j_auth_ok "$envpw"; then
                success "Reconciled: Neo4j now uses NEO4J_PASSWORD from .env."
                return 0
            fi
        fi
    done
    return 1
}

# Harden the datastore passwords (STRIDE S13/S1). The passwords are baked into
# the postgres/neo4j data volumes at FIRST init, so on a FRESH install (volume
# absent) we auto-generate before the volume is created. On an EXISTING install
# still on the compose default we now ROTATE in place: ALTER the live DB with the
# old (default) creds FIRST, and only on success write the new value to .env, so
# .env and the volume never disagree. If the ALTER fails we fall back to the old
# warn-only behaviour (fail-safe: never a locked-out DB).
# Uses url/shell-safe hex so DATABASE_URL and NEO4J_AUTH need no escaping.
# S13: rotation ALTERs the LIVE DB, so the DB container must be RUNNING. On a
# STOPPED default-cred stack (the reboot -> `up` path, or `down && update`) the DB
# is down AND the fail-closed compose `${VAR:?}` refuses to start it because .env
# has no password yet -- a chicken-and-egg that would abort `up`/`update`/`dev`
# with a cryptic "required variable ... is missing a value". This brings the
# needed DB(s) up with their OLD default creds (exported ONLY for this one call so
# the `:?` interpolation resolves; an already-initialised volume ignores the
# value), so the subsequent ALTER can run and ensure_db_secrets can pin the new
# value. Best-effort: on any failure ensure_db_secrets falls back to warn-only.
_start_dbs_for_rotation_if_needed() {
    local env_file="$SCRIPT_DIR/.env"
    local svcs=() need=false
    if ! grep -q '^POSTGRES_PASSWORD=' "$env_file" 2>/dev/null \
         && _data_volume_exists postgres_data \
         && ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-postgres$'; then
        svcs+=(postgres); need=true
    fi
    if ! grep -q '^NEO4J_PASSWORD=' "$env_file" 2>/dev/null \
         && _data_volume_exists neo4j_data \
         && ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-neo4j$'; then
        svcs+=(neo4j); need=true
    fi
    [[ "$need" == false ]] && return 0

    info "Starting ${svcs[*]} on current default creds so S13 can rotate the password..."
    # compose interpolates the WHOLE file, so BOTH `:?` vars must resolve even to
    # start one service; supply both defaults for this single command only. These
    # match the compose defaults and the `specs` below; an init'd volume ignores
    # them, so the container comes up on the volume's real (default) password.
    if ! POSTGRES_PASSWORD=redamon_secret NEO4J_PASSWORD=changeme123 \
            docker compose up -d "${svcs[@]}" >/dev/null 2>&1; then
        warn "Could not start ${svcs[*]} for rotation; falling back to warn-only fail-safe."
        return 0
    fi
    local c waited
    for c in "${svcs[@]}"; do
        waited=0
        while [[ $waited -lt 60 ]]; do
            [[ "$(docker inspect --format='{{.State.Health.Status}}' "redamon-$c" 2>/dev/null || echo x)" == "healthy" ]] && break
            sleep 2; waited=$((waited + 2))
        done
    done
}

ensure_db_secrets() {
    local env_file="$SCRIPT_DIR/.env"
    touch "$env_file"

    # If a default-cred volume needs rotating but its DB is down, bring it up
    # first (see helper) so the live ALTER below can run. No-op on fresh installs
    # (no volume) and on already-pinned / already-running stacks.
    _start_dbs_for_rotation_if_needed

    # (var, volume suffix, compose default, rotate-fn) tuples.
    local specs=(
        "POSTGRES_PASSWORD:postgres_data:redamon_secret:_rotate_postgres_password"
        "NEO4J_PASSWORD:neo4j_data:changeme123:_rotate_neo4j_password"
    )

    local project; project="$(compose_project_name)"
    local spec var suffix default rotate_fn old new
    # Vars we could NOT establish because a data volume exists but rotation off
    # the default failed. Collected here so we can STOP with one actionable
    # message instead of silently leaving .env without a password (#155).
    local -a unresolved=()
    for spec in "${specs[@]}"; do
        var="$(echo "$spec" | cut -d: -f1)"
        suffix="$(echo "$spec" | cut -d: -f2)"
        default="$(echo "$spec" | cut -d: -f3)"
        rotate_fn="$(echo "$spec" | cut -d: -f4)"

        # Operator/prior-run already pinned it in .env. Respect the value, but for
        # Neo4j VERIFY it actually matches the volume and reconcile if not (#160): a
        # hand-set password that disagrees with the baked-in volume password
        # otherwise fails later with a cryptic AuthenticationRateLimit. On a
        # confirmed, un-reconcilable mismatch, fall through to the actionable stop.
        if grep -q "^${var}=" "$env_file" 2>/dev/null; then
            if [[ "$var" == "NEO4J_PASSWORD" ]] && _data_volume_exists "$suffix" \
               && ! _reconcile_neo4j_password "$(_env_get NEO4J_PASSWORD)"; then
                unresolved+=("${var}=${project}_${suffix}")
            fi
            continue
        fi

        if _data_volume_exists "$suffix"; then
            # Existing DB, initialised with the weak compose default. Rotate the
            # LIVE password using the old default, THEN write the new .env value.
            old="$default"
            new="$(openssl rand -hex 24)"
            info "Rotating ${var} on the existing ${suffix} volume (off the default '${default}')..."
            if "$rotate_fn" "$old" "$new"; then
                echo "${var}=${new}" >> "$env_file"
                info "Rotated ${var} on the live database and pinned it in .env."
            else
                # Rotation failed: DO NOT write .env (a mismatch would lock out
                # consumers / split-brain). But we also must NOT leave .env
                # without the value and press on — the fail-closed compose
                # `${VAR:?}` guard would then abort a later `up`/`update` with a
                # cryptic interpolation error (issue #155). Record it and stop
                # loudly below with remediation steps. The volume is untouched.
                warn "${var} rotation FAILED (wrong old password, or the database is not up)."
                unresolved+=("${var}=${project}_${suffix}")
            fi
        else
            # Fresh install — generate before the DB volume is created so it
            # initialises with the strong value across all consumers.
            echo "${var}=$(openssl rand -hex 24)" >> "$env_file"
            info "Generated strong ${var} (fresh install)"
        fi
    done

    # #155: at least one required DB password could not be set because a stale
    # data volume exists that we could not rotate off the compose default. This
    # is common on re-clone / re-install over Docker volumes that survive repo
    # deletion (e.g. WSL2 + Docker Desktop). Stop here with concrete remediation
    # rather than hand the operator an unstartable stack + a cryptic compose
    # error. Nothing has been destroyed; the volumes are left exactly as they are.
    if (( ${#unresolved[@]} > 0 )); then
        local u vols=() var_names=()
        for u in "${unresolved[@]}"; do
            var_names+=("${u%%=*}")
            vols+=("${u#*=}")
        done
        error "Cannot configure the database password(s): ${var_names[*]}"
        error "A data volume already exists for each, but it was not initialised"
        error "with RedAmon's default credentials, so the password could not be set"
        error "automatically. RedAmon will not start without these (STRIDE S13)."
        echo "" >&2
        echo "  Leftover volume(s): ${vols[*]}" >&2
        echo "" >&2
        echo "  Choose ONE fix, then re-run the same command:" >&2
        echo "" >&2
        echo "  A) The data is disposable (fresh setup / leftover from a prior run)." >&2
        echo "     Remove the stale volume(s) so RedAmon can re-initialise cleanly:" >&2
        echo "         docker volume rm ${vols[*]}" >&2
        echo "" >&2
        echo "  B) You need the data in those volumes: pin each volume's CURRENT" >&2
        echo "     password explicitly in .env (RedAmon then respects it as-is):" >&2
        local vn
        for vn in "${var_names[@]}"; do
            echo "         echo '${vn}=<the volume's existing password>' >> .env" >&2
        done
        echo "" >&2
        exit 1
    fi
}

# S11: minimum admin-password length enforced at creation and reset.
MIN_ADMIN_PASSWORD_LEN=12
_password_strong_enough() {
    local pw="$1"
    [[ ${#pw} -ge $MIN_ADMIN_PASSWORD_LEN ]]
}

# Poll the webapp health endpoint until it answers. Returns 0 once healthy, 1 if
# it never came up within the budget. Default ~3 min (90 * 2s): a heavy first
# boot (--gvm starts the OpenVAS/gvmd feed-sync alongside the webapp and can
# saturate a small VM's CPU/IO for a while) legitimately needs longer than the
# old 60s, which was silently skipping admin creation (issue #156).
_wait_for_webapp() {
    local retries=0 max="${1:-90}"
    while ! docker compose exec -T webapp wget -q --spider http://127.0.0.1:3000/api/health 2>/dev/null; do
        retries=$((retries + 1))
        [[ $retries -ge $max ]] && return 1
        sleep 2
    done
    return 0
}

# True (0) if at least one admin (role=admin with a password) exists.
_admin_exists() {
    local has_admin
    has_admin=$(docker compose exec -T webapp node scripts/check-admin.mjs 2>/dev/null | tr -d '[:space:]')
    [[ -n "$has_admin" && "$has_admin" != "0" ]]
}

# Collect the admin details and upsert via create-admin.mjs. Non-interactive when
# ADMIN_NAME/ADMIN_EMAIL/ADMIN_PASSWORD are all present in the environment (mirrors
# the single-host deploy path); otherwise prompts on the controlling terminal.
# create-admin.mjs upserts on email: a matching email RESETS that admin's
# password, a new email adds another admin — so re-running is safe.
_prompt_and_create_admin() {
    local a_name="${ADMIN_NAME:-}" a_email="${ADMIN_EMAIL:-}" a_pass="${ADMIN_PASSWORD:-}" a_pass2=""
    if [[ -n "$a_name" && -n "$a_email" && -n "$a_pass" ]]; then
        info "Using ADMIN_NAME / ADMIN_EMAIL / ADMIN_PASSWORD from the environment (non-interactive)."
        # S11: enforce the minimum password length here too.
        if ! _password_strong_enough "$a_pass"; then
            error "ADMIN_PASSWORD too short (minimum ${MIN_ADMIN_PASSWORD_LEN} characters)."
            exit 1
        fi
    else
        read -rp "  Admin name: " a_name </dev/tty
        read -rp "  Admin email: " a_email </dev/tty
        while true; do
            read -srp "  Admin password: " a_pass </dev/tty
            echo ""
            read -srp "  Confirm password: " a_pass2 </dev/tty
            echo ""
            if [[ "$a_pass" != "$a_pass2" ]]; then
                warn "Passwords do not match. Try again."
                continue
            fi
            # S11: reject a weak admin password (min length) instead of warning.
            if ! _password_strong_enough "$a_pass"; then
                warn "Password too short (minimum ${MIN_ADMIN_PASSWORD_LEN} characters). Try again."
                continue
            fi
            break
        done
    fi
    docker compose exec -T \
        -e "ADMIN_NAME=$a_name" \
        -e "ADMIN_EMAIL=$a_email" \
        -e "ADMIN_PASSWORD=$a_pass" \
        webapp node scripts/create-admin.mjs
    success "Admin user ready."
    echo ""
}

ensure_admin() {
    if ! _wait_for_webapp; then
        # Do NOT dead-end: point the operator at the standalone recovery command
        # so a slow first boot never leaves them unable to log in (issue #156).
        warn "Webapp is not responding yet -- skipping the automatic admin setup."
        warn "Once it is up (check './redamon.sh status'), create the admin with:"
        warn "    ./redamon.sh create-admin"
        return
    fi

    if ! _admin_exists; then
        echo ""
        warn "No admin user found. Let's create one."
        echo ""
        _prompt_and_create_admin
    fi
}

# Standalone admin (re)creation — the reliable path when the automatic prompt was
# skipped (slow first boot) or the admin password was lost. Safe to re-run: it
# upserts on email (matching email resets the password; new email adds an admin).
cmd_create_admin() {
    print_banner
    check_prerequisites
    if ! _wait_for_webapp 150; then   # ~5 min: this is an explicit, user-driven call
        error "Webapp is not responding at http://localhost:3000/api/health."
        error "Start the stack first ('./redamon.sh up'), then re-run './redamon.sh create-admin'."
        exit 1
    fi
    if _admin_exists; then
        warn "An admin user already exists."
        warn "Continuing will ADD a new admin, or RESET the password if you reuse an existing admin's email."
    else
        info "No admin user found yet — let's create one."
    fi
    echo ""
    _prompt_and_create_admin
}

cmd_reset_password() {
    echo ""
    read -rp "  User email: " EMAIL </dev/tty
    read -srp "  New password: " NEW_PASS </dev/tty
    echo ""
    read -srp "  Confirm password: " CONFIRM </dev/tty
    echo ""

    if [[ "$NEW_PASS" != "$CONFIRM" ]]; then
        error "Passwords do not match."
        exit 1
    fi

    # S11: enforce a minimum password strength on reset too.
    if ! _password_strong_enough "$NEW_PASS"; then
        error "Password too short (minimum ${MIN_ADMIN_PASSWORD_LEN} characters)."
        exit 1
    fi

    docker compose exec -T \
        -e "RESET_EMAIL=$EMAIL" \
        -e "RESET_PASSWORD=$NEW_PASS" \
        webapp node scripts/reset-password.mjs
    success "Password updated."
    echo ""
}

# Wipe the orchestrator-spawned, non-compose-managed containers (AI Attack Surface
# scan containers + the on-demand local LLM). Safe to call anytime — a no-op when
# none are present. Must run BEFORE `compose down --volumes` so the local-llm
# container releases the models volume and it can actually be removed.
remove_spawned_containers() {
    local ids
    ids=$(docker ps -aq "${SPAWNED_CONTAINER_NAME_FILTERS[@]}" 2>/dev/null || true)
    if [[ -n "$ids" ]]; then
        info "Removing orchestrator-spawned AI containers (scan + local LLM)..."
        # shellcheck disable=SC2086
        docker rm -f $ids >/dev/null 2>&1 || true
    fi
}

remove_redamon_images() {
    # Remove locally-built redamon images
    docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep '^redamon-' \
        | xargs -r docker rmi 2>/dev/null || true

    # Remove GVM / Greenbone images
    docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep 'registry.community.greenbone.net' \
        | xargs -r docker rmi 2>/dev/null || true

    # Remove ProjectDiscovery + recon tool images (pulled at runtime by entrypoint)
    local runtime_images=(
        "projectdiscovery/naabu"
        "projectdiscovery/httpx"
        "projectdiscovery/katana"
        "projectdiscovery/nuclei"
        "projectdiscovery/subfinder"
        "projectdiscovery/dnsx"
        "projectdiscovery/uncover"
        "sxcurity/gau"
        "caffix/amass"
        "frost19k/puredns"
        "jauderho/hakrawler"
        "trufflesecurity/trufflehog"
        # On-demand local LLM (Ollama) for the AI Attack Surface judge/attacker —
        # pulled at runtime by the orchestrator, not built.
        "$LOCAL_LLM_IMAGE"
    )
    for img in "${runtime_images[@]}"; do
        docker rmi "$img" 2>/dev/null || true
    done
}

pull_gvm_images() {
    # GVM images are large (~250MB each) and can fail with "unexpected EOF"
    # due to a known Docker+Go 1.24 bug (moby/moby#49513) and Greenbone
    # registry instability. Pull individually with retries.
    local max_retries=5
    local gvm_services
    gvm_services=$(docker compose config --services 2>/dev/null | grep '^gvm-')

    if [[ -z "$gvm_services" ]]; then
        return 0
    fi

    # Skip pull if all GVM images already exist locally (pass force=true to override)
    local force="${1:-false}"
    if [[ "$force" != "true" ]]; then
        local need_pull=false
        local compose_json
        compose_json=$(docker compose config --format json 2>/dev/null)
        for svc in $gvm_services gvmd; do
            local img
            img=$(echo "$compose_json" | jq -r ".services.\"$svc\".image // empty")
            if [[ -n "$img" ]] && ! docker image inspect "$img" &>/dev/null; then
                need_pull=true
                break
            fi
        done
        if [[ "$need_pull" == "false" ]]; then
            info "GVM images already present locally, skipping pull."
            return 0
        fi
    fi

    info "Pulling GVM images (with retry)..."
    local failed=()
    for svc in $gvm_services; do
        local attempt=1
        while [[ $attempt -le $max_retries ]]; do
            if docker compose pull "$svc" 2>/dev/null; then
                break
            fi
            if [[ $attempt -lt $max_retries ]]; then
                warn "Pull failed for $svc (attempt $attempt/$max_retries), retrying..."
                sleep 5
            fi
            ((attempt++))
        done
        if [[ $attempt -gt $max_retries ]]; then
            failed+=("$svc")
        fi
    done

    # Also pull gvmd separately (no gvm- prefix)
    local attempt=1
    while [[ $attempt -le $max_retries ]]; do
        if docker compose pull gvmd 2>/dev/null; then
            break
        fi
        if [[ $attempt -lt $max_retries ]]; then
            warn "Pull failed for gvmd (attempt $attempt/$max_retries), retrying..."
            sleep 3
        fi
        ((attempt++))
    done
    if [[ $attempt -gt $max_retries ]]; then
        failed+=(gvmd)
    fi

    if [[ ${#failed[@]} -gt 0 ]]; then
        error "Failed to pull after $max_retries attempts: ${failed[*]}"
        echo ""
        echo -e "  ${YELLOW}This is often caused by a Docker+Go 1.24 bug (moby/moby#49513).${NC}"
        echo -e "  ${YELLOW}Try: echo '{\"max-concurrent-downloads\":1}' | sudo tee /etc/docker/daemon.json${NC}"
        echo -e "  ${YELLOW}Then: sudo systemctl restart docker && ./redamon.sh up${NC}"
        exit 1
    fi
    success "All GVM images pulled successfully."
}

# ---------------------------------------------------------------------------
# Knowledge Base helpers
# ---------------------------------------------------------------------------

KB_CONFIG_YAML="$SCRIPT_DIR/knowledge_base/kb_config.yaml"

# Read a value from kb_config.yaml. Dotted paths are supported for nested
# keys. Falls back to $2 if the file, key, or python is unavailable.
#   $1: dotted key path (e.g. "runtime.mode" or "KB_ENABLED")
#   $2: fallback value
_kb_yaml_get() {
    local key="$1"
    local fallback="$2"
    python3 -c "
import sys, yaml
try:
    with open('$KB_CONFIG_YAML') as f:
        cfg = yaml.safe_load(f) or {}
    value = cfg
    for k in '$key'.split('.'):
        value = value[k]
    if isinstance(value, bool):
        print('true' if value else 'false')
    else:
        print(value)
except Exception:
    print('$fallback')
" 2>/dev/null || echo "$fallback"
}

# Feature gate mirroring is_gvm_enabled(). Single source of truth: the
# `.kbase-enabled` flag file, written by `install --kbase`. The README contract
# is that KB is opt-in — default install has no KB.
is_kb_enabled() {
    is_kbase_enabled
}

# Export KB-related env vars so downstream processes (docker compose, make)
# see a value that matches the flag file. Called from every cmd_* that
# shells out to docker compose. Always exports — the flag is authoritative,
# any pre-existing $KB_ENABLED in the environment is overwritten so direct
# `KB_ENABLED=true docker compose up` shenanigans can't lie to the agent
# when the image was built without KB deps.
_kb_export_env() {
    if is_kbase_enabled; then
        export KB_ENABLED="true"
        export SKIP_KB="false"
    else
        export KB_ENABLED="false"
        export SKIP_KB="true"
    fi
}

# Wait for the Neo4j container to become healthy. Starts it if not running.
# Returns 0 on success, 1 on timeout.
# Every Knowledge Base `make` goes through here so it inherits the REAL Neo4j
# credentials from .env (redamon.sh does not source .env), instead of the Makefile's
# insecure `changeme123` fallback which fails auth on any rotated/custom-password DB
# (#160 / the `kb stats` failure). An env var (even empty) defeats the Makefile's
# `?=` default, so this is authoritative.
_kb_make() {
    NEO4J_PASSWORD="$(_env_get NEO4J_PASSWORD)" \
        make -C knowledge_base "$@"
}

_kb_wait_neo4j() {
    if ! docker ps --format '{{.Names}}' | grep -q '^redamon-neo4j$'; then
        info "Neo4j not running — starting it..."
        docker compose up -d neo4j
    fi

    info "Waiting for Neo4j to become healthy..."
    local waited=0
    local max_wait=60
    while [[ $waited -lt $max_wait ]]; do
        local health
        health=$(docker inspect --format='{{.State.Health.Status}}' \
                   redamon-neo4j 2>/dev/null || echo "unknown")
        if [[ "$health" == "healthy" ]]; then
            success "Neo4j is healthy"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done

    error "Neo4j did not become healthy within ${max_wait}s"
    error "Check: docker logs redamon-neo4j"
    return 1
}

# Check if the agent container has a CUDA-capable GPU available.
_kb_has_gpu() {
    docker exec redamon-agent python -c \
        "import torch; exit(0 if torch.cuda.is_available() else 1)" &>/dev/null
}

# Check if .env has an embedding API configured and ready to use.
_kb_has_api_key() {
    local env_file="$SCRIPT_DIR/.env"
    [[ -f "$env_file" ]] || return 1
    local use_api key
    use_api=$(grep -E '^KB_EMBEDDING_USE_API=' "$env_file" 2>/dev/null \
              | cut -d= -f2 | tr -d '"' | tr -d "'")
    key=$(grep -E '^KB_EMBEDDING_API_KEY=' "$env_file" 2>/dev/null \
          | cut -d= -f2 | tr -d '"' | tr -d "'")
    [[ "$use_api" == "true" && -n "$key" ]]
}

# Detect the best ingestion profile and show terminal feedback.
# Prints the chosen profile name to stdout. Shows an interactive
# prompt on CPU-only systems asking the user whether to run full
# ingestion or quick-start with fewer sources.
_kb_choose_profile() {
    if _kb_has_api_key; then
        local base_url
        base_url=$(grep -E '^KB_EMBEDDING_API_BASE_URL=' "$SCRIPT_DIR/.env" \
                   | cut -d= -f2 | tr -d '"' | tr -d "'")
        info "KB Embedding: API mode (${base_url:-https://api.openai.com/v1})" >&2
        info "Ingesting all lite sources via API embeddings..." >&2
        echo "lite"
        return
    fi

    if _kb_has_gpu; then
        info "KB Embedding: GPU detected" >&2
        info "Ingesting all lite sources with GPU acceleration..." >&2
        echo "lite"
        return
    fi

    # CPU-only with existing FAISS data: skip the interactive prompt.
    # The manifest dedup will skip unchanged chunks anyway, so a re-run
    # finishes in seconds. To upgrade the profile, use:
    #   ./redamon.sh kb build lite
    #
    # Note: FAISS files are created by Docker (root-owned, mode 600), so
    # we cannot read their contents as a normal user. Use -s (non-zero size)
    # instead of trying to parse the JSON.
    local faiss_index="$SCRIPT_DIR/knowledge_base/data/index.faiss"
    if [[ -s "$faiss_index" ]]; then
        info "KB Embedding: CPU mode (FAISS index exists, refreshing unchanged chunks)" >&2
        echo "cpu-lite"
        return
    fi

    # First-time CPU-only: show explanation and let user choose
    echo ""                                                            >&2
    echo "==========================================================" >&2
    echo "  Knowledge Base -- Embedding Configuration"                 >&2
    echo "==========================================================" >&2
    echo ""                                                            >&2
    echo "  No GPU and no embedding API key detected."                 >&2
    echo "  The KB needs to convert security datasets into vector"     >&2
    echo "  embeddings. On CPU this is slow for large datasets."       >&2
    echo ""                                                            >&2
    echo "  Source          Chunks    Est. time on CPU"                 >&2
    echo "  --------------- --------- ----------------"                >&2
    echo "  tool_docs            ~35   ~2 min"                         >&2
    echo "  gtfobins            ~400   ~7 min"                         >&2
    echo "  lolbas              ~450   ~7 min"                         >&2
    echo "  owasp               ~880   ~35 min"                        >&2
    echo "  exploitdb        ~45,000   ~3 hours"                       >&2
    echo ""                                                            >&2
    echo "  Option 1: Quick start (~15 min)"                           >&2
    echo "    Ingest tool_docs + gtfobins + lolbas only."              >&2
    echo "    You can add owasp/exploitdb later."                      >&2
    echo ""                                                            >&2
    echo "  Option 2: Full ingestion (~4 hours)"                       >&2
    echo "    Ingest all 5 sources now. Go grab a coffee."             >&2
    echo ""                                                            >&2
    echo "  Tip: To skip this wait in the future, configure an"        >&2
    echo "  embedding API in .env (see .env.example):"                 >&2
    echo "    KB_EMBEDDING_USE_API=true"                                >&2
    echo "    KB_EMBEDDING_API_KEY=sk-..."                              >&2
    echo "    KB_EMBEDDING_API_BASE_URL=  (leave empty for OpenAI)"    >&2
    echo "  With an API, full ingestion takes ~2-3 minutes."           >&2
    echo ""                                                            >&2
    echo "==========================================================" >&2
    echo ""                                                            >&2

    read -rp "  Run full ingestion now? [y/N] " full_ingest </dev/tty

    if [[ "$full_ingest" =~ ^[Yy]$ ]]; then
        info "Full ingestion selected. This will take a while..." >&2
        echo "lite"
    else
        info "Quick start selected (tool_docs + gtfobins + lolbas)" >&2
        echo "cpu-lite"
    fi
}

# Internal: run `make kb-build-<profile>` with Neo4j health check first.
# Fails gracefully -- callers decide whether to treat failure as fatal.
_kb_bootstrap() {
    local profile="${1:-lite}"
    _kb_export_env
    _kb_wait_neo4j || return 1
    info "Bootstrapping Knowledge Base (profile=${profile})..."
    _kb_make "kb-build-${profile}" MODE=docker
}

# Status helpers: read KB and Tavily state directly from disk/env without
# requiring Python deps, running containers, or Neo4j connections. These
# should always succeed (or return a safe fallback) so `./redamon.sh status`
# works in any state.

# Count FAISS vectors by reading chunk_ids.json directly. No Python dep
# required — uses python3's stdlib json module, which is always present.
# Returns "0" if the file is missing or unreadable.
_kb_get_faiss_count() {
    local chunk_ids="$SCRIPT_DIR/knowledge_base/data/chunk_ids.json"
    if [[ ! -f "$chunk_ids" ]]; then
        echo "0"
        return
    fi
    python3 -c "
import json, sys
try:
    with open('$chunk_ids') as f:
        data = json.load(f)
    print(len(data) if isinstance(data, list) else 0)
except Exception:
    print('0')
" 2>/dev/null || echo "0"
}

# Count Neo4j KBChunk nodes via cypher-shell inside the neo4j container.
# Returns "0" if the container isn't running, "unknown" if the query fails.
_kb_get_neo4j_count() {
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-neo4j$'; then
        echo "0"
        return
    fi
    # S13: after rotation the live password is in .env, NOT changeme123 and NOT in
    # this shell's env (redamon.sh does not source .env). Read .env first so the
    # `status` / `kb stats` KB count still authenticates on a rotated DB; fall back
    # to the env var, then the fresh-install default.
    local pass
    pass="$(_env_get NEO4J_PASSWORD)"
    pass="${pass:-${NEO4J_PASSWORD}}"
    local user="${NEO4J_USER:-neo4j}"
    local count
    count=$(docker exec redamon-neo4j cypher-shell \
        -u "$user" -p "$pass" --format plain \
        "MATCH (c:KBChunk) RETURN count(c) AS total" 2>/dev/null \
        | tail -n 1 | tr -d '[:space:]"' || true)
    # Validate it's a non-negative integer; fall back to unknown otherwise
    if [[ "$count" =~ ^[0-9]+$ ]]; then
        echo "$count"
    else
        echo "unknown"
    fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_install() {
    local gvm_mode="false"
    local kbase_mode="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --gvm)   gvm_mode="true" ;;
            --kbase) kbase_mode="true" ;;
            *) error "Unknown flag: $1"; exit 1 ;;
        esac
        shift
    done

    print_banner
    check_prerequisites

    local version
    version="$(get_version)"
    info "Installing RedAmon v${version}..."
    if [[ "$gvm_mode" == "true" ]]; then
        info "Mode: Full stack (with GVM/OpenVAS)"
        touch "$GVM_FLAG_FILE"
    else
        info "Mode: Core services (without GVM/OpenVAS)"
        rm -f "$GVM_FLAG_FILE"
    fi
    # KB is OPT-IN at install time. The install always writes ONE of the two
    # markers (.kbase-enabled or .kbase-disabled) so the user's explicit choice
    # is sticky — `clean` keeps KB data on disk, and without an explicit
    # "disabled" marker the migration heuristic would later see leftover FAISS
    # data and re-enable KB. The legacy `.skipkbase` flag is removed.
    rm -f "$LEGACY_SKIPKBASE_FLAG_FILE"
    if [[ "$kbase_mode" == "true" ]]; then
        info "Mode: Including Knowledge Base (--kbase)"
        touch "$KBASE_FLAG_FILE"
        rm -f "$KBASE_DISABLED_FLAG_FILE"
    else
        info "Mode: Skipping Knowledge Base (default; pass --kbase to enable)"
        rm -f "$KBASE_FLAG_FILE"
        touch "$KBASE_DISABLED_FLAG_FILE"
    fi
    _kb_export_env
    echo ""

    # Export version for docker build arg
    export_version

    # Generate auth secrets if not present
    ensure_auth_secrets
    ensure_db_secrets

    # Build all images (tools + core services + the on-demand capture proxy).
    # The capture-proxy / traffic-ingest pair lives in the "capture" profile and is
    # spawned on demand by the orchestrator (never by `up`), but its image
    # (redamon-capture-proxy:latest) must still EXIST or the first Settings toggle
    # fails with an image-not-found pull error. Building it here — alongside tools —
    # guarantees a fresh install can start capture without any extra step.
    info "Building all images (this may take a while on first run)..."
    compose_build --profile tools --profile capture build

    # Pull GVM images with retry (large images, unreliable registry)
    if [[ "$gvm_mode" == "true" ]]; then
        pull_gvm_images
    fi

    # Start services (force-recreate ensures compose changes like command: are applied)
    info "Starting services..."
    if [[ "$gvm_mode" == "true" ]]; then
        docker compose up -d --force-recreate
    else
        # shellcheck disable=SC2086
        docker compose up -d --force-recreate $CORE_SERVICES
    fi

    # Show "ready" banner before the KB prompt so the user knows the app
    # is already usable (they can Ctrl+C the KB question and start working).
    echo ""
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo -e "  ${GREEN}${BOLD}  RedAmon v${version} is ready!${NC}"
    echo -e "  ${GREEN}${BOLD}  Open ${CYAN}http://localhost:3000${GREEN}${BOLD} in your browser${NC}"
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo ""

    # Ensure an admin user exists (prompts if none found)
    ensure_admin

    # HTTP Traffic Capture: start the orchestrator-spawned proxy if the master
    # switch is on (it is not compose-managed, so `up`/restart won't bring it back).
    ensure_capture_proxy_running

    # Bootstrap the Knowledge Base if enabled (reads KB_ENABLED from kb_config.yaml).
    # Install always runs a fresh bootstrap -- first-time setup populates FAISS +
    # Neo4j from committed caches. Graceful failure: if bootstrap fails
    # (network, missing deps, etc.) the agent still starts with an empty KB
    # and the user gets a clear retry command.
    if is_kb_enabled; then
        echo ""
        local kb_profile
        kb_profile=$(_kb_choose_profile)

        if _kb_bootstrap "$kb_profile"; then
            success "Knowledge Base ready (profile: ${kb_profile})"
        else
            warn "KB bootstrap failed -- agent will start with an empty KB"
            warn "Retry with: ./redamon.sh kb build ${kb_profile}"
        fi
    else
        info "KB_ENABLED=false -- skipping Knowledge Base bootstrap"
    fi

    echo ""
    echo -e "  ${CYAN}Status:${NC}  ./redamon.sh status"
    echo ""
    echo -e "  ${YELLOW}If RedAmon is useful to you, a GitHub star helps others find the project:${NC}"
    echo -e "  ${CYAN}https://github.com/samugit83/redamon${NC}"
    echo ""
    if [[ "$gvm_mode" == "true" ]]; then
        warn "GVM/OpenVAS feed sync takes ~30 minutes on first run."
        echo -e "  ${CYAN}GVM credentials:${NC} admin / admin"
    fi
}

cmd_update() {
    _migrate_legacy_kbase_flag
    _kb_export_env

    print_banner
    check_prerequisites

    local old_version
    old_version="$(get_version)"
    info "Current version: v${old_version}"
    info "Checking for updates..."
    echo ""

    # Save current HEAD
    local old_head new_head
    if [[ -n "${REDAMON_UPDATE_FROM:-}" ]]; then
        # We were re-exec'd by our previous self after the pull (see below). Reuse
        # the recorded pre-pull HEAD and do NOT pull again — just run the rebuild
        # logic from the freshly-pulled (newer) script.
        old_head="$REDAMON_UPDATE_FROM"
        new_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"
    else
        old_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

        # Pull latest (try upstream tracking branch first, then origin/master)
        if ! git -C "$SCRIPT_DIR" pull --ff-only 2>/dev/null; then
            if ! git -C "$SCRIPT_DIR" pull --ff-only origin master 2>/dev/null; then
                error "Could not pull updates. You may have local changes."
                echo ""
                echo "  Try one of:"
                echo "    git stash && ./redamon.sh update && git stash pop"
                echo "    git commit -am 'local changes' && ./redamon.sh update"
                exit 1
            fi
        fi

        new_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

        if [[ "$old_head" == "$new_head" ]]; then
            success "Already up to date (v$(get_version))."
            return
        fi

        # Self-heal across versions: re-exec the freshly-pulled script so the
        # update logic from the version being INSTALLED runs (it may know about
        # services or build rules this older copy does not — e.g. a new service
        # added in the target release). Guarded by REDAMON_UPDATE_FROM so we do
        # not pull or loop again.
        export REDAMON_UPDATE_FROM="$old_head"
        exec bash "$SCRIPT_DIR/redamon.sh" update
    fi

    local new_version
    new_version="$(get_version)"
    info "Updating v${old_version} -> v${new_version}"
    echo ""

    # Detect what changed
    local changed_files
    changed_files="$(git -C "$SCRIPT_DIR" diff --name-only "$old_head" "$new_head")"

    # Map changed paths to services
    local rebuild_core=()
    local rebuild_tools=()
    local rebuild_all=false

    if echo "$changed_files" | grep -q "^docker-compose\.yml$"; then
        rebuild_all=true
    fi

    # Track services that need restart only (volume-mounted source code changes)
    local restart_only=()

    if [[ "$rebuild_all" == "true" ]]; then
        info "docker-compose.yml changed -- rebuilding core service images"
        rebuild_core=(recon-orchestrator kali-sandbox agent webapp docker-broker)
    else
        # webapp: always needs rebuild (no volume mount in production)
        if echo "$changed_files" | grep -q "^webapp/"; then
            rebuild_core+=(webapp)
        fi

        # recon-orchestrator: rebuild only if Dockerfile/requirements changed, else restart
        if echo "$changed_files" | grep -q "^recon_orchestrator/\(Dockerfile\|requirements\)"; then
            rebuild_core+=(recon-orchestrator)
        elif echo "$changed_files" | grep -q "^recon_orchestrator/"; then
            restart_only+=(recon-orchestrator)
        fi

        # kali-sandbox: rebuild only if Dockerfile/entrypoint changed, else restart
        if echo "$changed_files" | grep -q "^mcp/kali-sandbox/\(Dockerfile\|entrypoint\)"; then
            rebuild_core+=(kali-sandbox)
        elif echo "$changed_files" | grep -q "^mcp/"; then
            restart_only+=(kali-sandbox)
        fi

        # agent: always rebuild when agentic/ changes — source code is baked into
        # the image (no volume mount for ./agentic:/app), so restart alone won't
        # pick up .py changes.
        if echo "$changed_files" | grep -q "^agentic/"; then
            rebuild_core+=(agent)
        elif echo "$changed_files" | grep -qE "^(knowledge_base|graph_db)/"; then
            rebuild_core+=(agent)
        fi

        # docker-broker: the Docker-socket filtering proxy. Rebuild when its
        # source changes (it builds from ./docker_broker, no volume mount).
        if echo "$changed_files" | grep -q "^docker_broker/"; then
            rebuild_core+=(docker-broker)
        fi
    fi

    # Tool-profile images build ONLY from their own source dirs — a docker-compose.yml
    # change never alters their content. So rebuild a tool image ONLY when its source
    # actually changed, even under rebuild_all. This avoids spuriously rebuilding heavy
    # / fragile tool images (e.g. ai-attack-surface, whose pyrit deps need a Rust
    # toolchain on arm64) on an unrelated compose change.
    if echo "$changed_files" | grep -q "^recon/"; then
        rebuild_tools+=(recon)
    fi
    # wcvs: the Web Cache Vulnerability Scanner image (web cache poisoning module),
    # run docker-in-docker by the recon container. Build-only; rebuild when its
    # Dockerfile (or pinned WCVS_REF) changes.
    if echo "$changed_files" | grep -q "^wcvs/"; then
        rebuild_tools+=(wcvs)
    fi
    if echo "$changed_files" | grep -q "^gvm_scan/"; then
        rebuild_tools+=(vuln-scanner)
    fi
    if echo "$changed_files" | grep -q "^github_secret_hunt/"; then
        rebuild_tools+=(github-secret-hunter)
    fi
    if echo "$changed_files" | grep -q "^trufflehog_scan/"; then
        rebuild_tools+=(trufflehog-scanner)
    fi
    if echo "$changed_files" | grep -q "^baddns_scan/"; then
        rebuild_tools+=(baddns-scanner)
    fi
    # ai-attack-surface: heavy build-only image (Node + promptfoo + per-tool venvs).
    # The adapter .py files are volume-mounted into the scan container at spawn
    # (hot-reload, no rebuild); ONLY the baked-in toolchain — the Dockerfile or any
    # requirements file — needs a rebuild.
    if echo "$changed_files" | grep -qE "^ai_attack_surface_scan/(Dockerfile|.*requirements)"; then
        rebuild_tools+=(ai-attack-surface)
    fi
    # codefix-sandbox: the isolated CodeFix build sandbox (T6/E10). Build-only
    # image; rebuild when anything in its build context changes.
    if echo "$changed_files" | grep -q "^codefix_sandbox/"; then
        rebuild_tools+=(codefix-sandbox)
    fi
    # capture-proxy / traffic-ingest (HTTP Traffic Capture): both share the
    # redamon-capture-proxy:latest image, built from capture_proxy/. It is in the
    # "capture" profile — never started by `up`, but SPAWNED on demand by the
    # orchestrator, which just runs the image (no on-demand build; capture_proxy/ is
    # not mounted into the orchestrator). So `update` MUST rebuild it here or the
    # proxy would keep serving stale capture/ingest/redaction/egress code. Handled
    # separately from rebuild_tools because it needs its own profile flag to build.
    local rebuild_capture=false
    if echo "$changed_files" | grep -q "^capture_proxy/"; then
        rebuild_capture=true
    fi

    # Export version for build arg
    export_version

    # Generate auth/db secrets BEFORE recreating any container. A release may add
    # new inbound secrets (e.g. AGENT_WS_TICKET_SECRET for S6, TUNNEL_AUTH_TOKEN
    # for I19/S14); if the recreate below runs before they exist in .env, the
    # containers start with empty values and those protections FAIL OPEN until the
    # next recreate. Generating first guarantees a single `update` fully enforces.
    # Both are idempotent (append-if-absent), so this is a no-op once present.
    ensure_auth_secrets
    ensure_db_secrets

    # Rebuild tool-profile images. A tool image is build-only (not a running core
    # service), so a failure here must NOT abort the rest of the update (core
    # services, broker, auth key). Warn and continue; the existing tool image keeps
    # working until its build is fixed.
    if [[ ${#rebuild_tools[@]} -gt 0 ]]; then
        info "Rebuilding tool images: ${rebuild_tools[*]}"
        if ! compose_build --profile tools build "${rebuild_tools[@]}"; then
            warn "One or more tool images failed to build (${rebuild_tools[*]}); continuing with the core update. Re-run the build later: docker compose --profile tools build ${rebuild_tools[*]}"
        fi
    fi

    # Rebuild the capture-proxy image if its source changed, then refresh a running
    # proxy onto it. Build-only + best-effort: a failure must not abort the update.
    if [[ "$rebuild_capture" == "true" ]]; then
        info "Rebuilding capture proxy image (redamon-capture-proxy:latest)..."
        if ! compose_build --profile capture build capture-proxy; then
            warn "capture-proxy image failed to build; the existing image keeps working. Re-run later: docker compose --profile capture build capture-proxy"
        else
            _reconcile_capture_if_running
        fi
    fi

    # Rebuild core service images
    if [[ ${#rebuild_core[@]} -gt 0 ]]; then
        info "Rebuilding service images: ${rebuild_core[*]}"
        compose_build build "${rebuild_core[@]}"
    fi

    # Clean up dangling images left by rebuilds
    if [[ ${#rebuild_core[@]} -gt 0 || ${#rebuild_tools[@]} -gt 0 ]]; then
        docker image prune -f >/dev/null 2>&1 || true
    fi

    # Restart rebuilt core services (tool images are build-only, not running).
    # When docker-compose.yml changed (rebuild_all), recreate ALL core services so
    # compose-level changes — e.g. the memory-governor mem_limits + neo4j heap —
    # reach the NON-rebuilt ones too (neo4j, postgres). A per-service --no-deps loop
    # would skip those. export_resource_caps first so the adaptive per-service caps
    # are applied, matching `up`.
    if [[ "$rebuild_all" == "true" ]]; then
        info "Recreating core services to apply docker-compose.yml changes..."
        export_resource_caps
        # shellcheck disable=SC2086
        docker compose up -d $CORE_SERVICES
    elif [[ ${#rebuild_core[@]} -gt 0 ]]; then
        info "Restarting rebuilt services..."
        for svc in "${rebuild_core[@]}"; do
            docker compose up -d --no-deps "$svc"
        done
    fi

    # Recreate GVM containers when docker-compose.yml changed (picks up command/image/volume changes)
    if [[ "$rebuild_all" == "true" ]] && is_gvm_enabled; then
        info "Recreating GVM containers to apply compose changes..."
        pull_gvm_images true
        docker compose up -d --force-recreate gvm-redis gvm-postgres gvmd gvm-ospd
    fi

    # Restart services with volume-mounted code changes (no rebuild needed)
    if [[ ${#restart_only[@]} -gt 0 ]]; then
        info "Restarting services for code changes: ${restart_only[*]}"
        docker compose restart "${restart_only[@]}"
    fi

    echo ""
    success "Updated to v${new_version}!"
    if [[ ${#rebuild_core[@]} -gt 0 || ${#rebuild_tools[@]} -gt 0 ]]; then
        local rebuilt_list="${rebuild_core[*]:+${rebuild_core[*]} }${rebuild_tools[*]}"
        echo -e "  ${CYAN}Rebuilt:${NC}  ${rebuilt_list}"
    fi
    if [[ ${#restart_only[@]} -gt 0 ]]; then
        echo -e "  ${CYAN}Restarted:${NC} ${restart_only[*]}"
    fi
    if [[ ${#rebuild_core[@]} -eq 0 && ${#rebuild_tools[@]} -eq 0 && ${#restart_only[@]} -eq 0 ]]; then
        info "No container images or source code needed updating."
    fi
    echo -e "  ${CYAN}Webapp:${NC}  http://localhost:3000"
    echo ""

    # Auth/db secrets are generated earlier (before the container recreate) so
    # newly-added inbound secrets take effect on this same update — see above.

    # Ensure an admin user exists (prompts if none found)
    ensure_admin

    # HTTP Traffic Capture: restore the proxy if the master switch is on (a stack
    # recreate during update leaves the orchestrator-spawned pair down).
    ensure_capture_proxy_running
}

# Populate the offline OSV database volume (supply-chain feature). Lazy and
# per-ecosystem: never downloaded at install time, only on explicit request or
# first scan. Mirrors the GVM-pull step. Runs osv-scanner's own download inside
# the analyzer image, writing into the read-only-everywhere-else osv_db volume.
cmd_supply_chain_sync() {
    local ecos="${*:-npm}"
    local analyzer_img="redamon-supply-chain-analyzer:latest"
    export_version
    if ! docker image inspect "$analyzer_img" &>/dev/null; then
        info "Supply-chain analyzer image not found, building it (first time only)..."
        if ! compose_build --profile tools build supply-chain-analyzer; then
            error "Could not build $analyzer_img. Build the tool images first: ./redamon.sh update"
            exit 1
        fi
    fi
    docker volume inspect redamon-osv-db &>/dev/null || docker volume create redamon-osv-db >/dev/null
    info "Syncing offline OSV database (ecosystems: $ecos). First npm sync is ~208 MB."
    if docker run --rm \
        -v redamon-osv-db:/osv-db \
        -e OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osv-db \
        --entrypoint python3 \
        "$analyzer_img" \
        -m supply_chain_common.osv_db_sync --db-path /osv-db --ecosystems "$ecos"; then
        success "OSV database sync complete."
    else
        error "OSV database sync failed."
        exit 1
    fi
}

ensure_tool_images() {
    local missing=false
    for img in $TOOL_IMAGES; do
        if ! docker image inspect "$img" &>/dev/null; then
            missing=true
            break
        fi
    done
    if [[ "$missing" == "true" ]]; then
        info "Tool images not found, building them (first time only)..."
        export_version
        compose_build --profile tools build
        success "Tool images built."
    fi
}

cmd_up_dev() {
    _migrate_legacy_kbase_flag
    _kb_export_env

    local gvm_flag="false"
    if is_gvm_enabled; then
        gvm_flag="true"
    fi

    ensure_tool_images
    ensure_auth_secrets
    ensure_db_secrets

    info "Starting RedAmon in DEV mode (GVM: ${gvm_flag})..."

    if [[ "$gvm_flag" == "true" ]]; then
        pull_gvm_images
        # shellcheck disable=SC2086
        docker compose $DEV_COMPOSE up -d
    else
        # shellcheck disable=SC2086
        docker compose $DEV_COMPOSE up -d $CORE_SERVICES
    fi

    # Show "ready" banner before the KB prompt so the user knows the app
    # is already usable (they can Ctrl+C the KB question and start working).
    echo ""
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo -e "  ${GREEN}${BOLD}  RedAmon DEV is ready!${NC}"
    echo -e "  ${GREEN}${BOLD}  Open ${CYAN}http://localhost:3000${GREEN}${BOLD} in your browser (hot-reload)${NC}"
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo ""

    # Ensure an admin user exists (prompts if none found)
    ensure_admin

    # HTTP Traffic Capture: start the orchestrator-spawned proxy if the master
    # switch is on (it is not compose-managed, so `up`/restart won't bring it back).
    ensure_capture_proxy_running

    # Refresh the Knowledge Base if enabled (behavior B -- always run ingest,
    # trust manifest dedup). Same rationale as cmd_up. Dev mode still benefits
    # from fresh KB on restart.
    if is_kb_enabled; then
        echo ""
        local kb_profile
        kb_profile=$(_kb_choose_profile)

        if _kb_bootstrap "$kb_profile"; then
            success "Knowledge Base ready (profile: ${kb_profile})"
        else
            warn "KB refresh failed -- agent will start with the existing KB state"
            warn "Retry with: ./redamon.sh kb build ${kb_profile}"
        fi
    fi
}

cmd_up() {
    _migrate_legacy_kbase_flag
    _kb_export_env

    local gvm_mode="false"
    if is_gvm_enabled; then
        gvm_mode="true"
    fi

    # Memory governor (Part 4): refuse to start if the host can't hold the core
    # services, and export adaptive per-service memory caps for docker-compose.
    if ! preflight_ram_gate; then
        exit 1
    fi
    export_resource_caps
    setup_zram   # optional one-time compressed-swap cushion (REDAMON_ENABLE_ZRAM=1)

    ensure_tool_images
    ensure_auth_secrets
    ensure_db_secrets

    info "Starting RedAmon (GVM: ${gvm_mode})..."

    # Pull GVM images with retry (large images, unreliable registry)
    if [[ "$gvm_mode" == "true" ]]; then
        pull_gvm_images
    fi

    if [[ "$gvm_mode" == "true" ]]; then
        docker compose up -d
    else
        # shellcheck disable=SC2086
        docker compose up -d $CORE_SERVICES
    fi

    # Show "ready" banner before the KB prompt so the user knows the app
    # is already usable (they can Ctrl+C the KB question and start working).
    echo ""
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo -e "  ${GREEN}${BOLD}  RedAmon is ready!${NC}"
    echo -e "  ${GREEN}${BOLD}  Open ${CYAN}http://localhost:3000${GREEN}${BOLD} in your browser${NC}"
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo ""

    # Ensure an admin user exists (prompts if none found)
    ensure_admin

    # HTTP Traffic Capture: start the orchestrator-spawned proxy if the master
    # switch is on (it is not compose-managed, so `up`/restart won't bring it back).
    ensure_capture_proxy_running

    # Refresh the Knowledge Base if enabled. Behavior B: always run the ingest
    # pipeline on up. The two-layer dedup (file hashes + manifest) skips
    # unchanged work, and NVD uses the `since` mechanism for incremental
    # updates -- so a routine restart is ~20-30s even though it touches the
    # network. First-ever up is ~2-3 min (full NVD fetch + embedding).
    # Fresh-clone scenario: no FAISS on disk -> full bootstrap.
    if is_kb_enabled; then
        echo ""
        local kb_profile
        kb_profile=$(_kb_choose_profile)

        if _kb_bootstrap "$kb_profile"; then
            success "Knowledge Base ready (profile: ${kb_profile})"
        else
            warn "KB refresh failed -- agent will start with the existing KB state"
            warn "Retry with: ./redamon.sh kb build ${kb_profile}"
        fi
    fi
}

cmd_down() {
    info "Stopping RedAmon..."
    # The on-demand LLM + any in-flight AI scan containers are orchestrator-spawned
    # (not compose-managed), so stop them too — otherwise the local LLM keeps
    # holding RAM after `down`.
    remove_spawned_containers
    docker compose down
    success "All services stopped. Volumes and images preserved."
}

cmd_clean() {
    warn "This will remove all RedAmon containers and images."
    warn "Your data (databases, reports, scan results) will be preserved in Docker volumes."
    echo ""
    read -rp "Continue? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "Cancelled."
        return
    fi

    info "Stopping containers..."
    remove_spawned_containers
    docker compose --profile tools down

    info "Removing RedAmon images..."
    remove_redamon_images
    docker image prune -f >/dev/null 2>&1 || true

    success "All RedAmon containers and images removed. Volumes preserved."
    echo ""
    info "To reinstall: ./redamon.sh install"
}

cmd_purge() {
    echo ""
    warn "This will PERMANENTLY DELETE:"
    warn "  - All RedAmon containers and images"
    warn "  - ALL DATA: PostgreSQL, Neo4j, GVM feeds, reports, scan results"
    warn "  - Host-side KB index state (FAISS index, manifest, last-ingest marker)"
    warn "  - KB dedup state (.manifest.json, .file_hashes.json)"
    warn "  - Downloaded source files under knowledge_base/data/cache are PRESERVED"
    echo ""
    echo -e "${RED}${BOLD}This action cannot be undone.${NC}"
    echo ""
    read -rp "Type 'yes' to confirm: " confirm
    if [[ "$confirm" != "yes" ]]; then
        info "Cancelled."
        return
    fi

    info "Stopping containers and removing volumes..."
    # Remove orchestrator-spawned containers FIRST: the on-demand local LLM holds
    # the models volume, so `down --volumes` can't remove it until that container
    # is gone.
    remove_spawned_containers
    docker compose --profile tools down --volumes --remove-orphans
    # `compose down --volumes` only removes volumes attached to the services it
    # actually loaded, so several always survive and a "purge" silently keeps
    # data: capture_* (the proxy/ingest are orchestrator-spawned, not compose
    # services), the webapp dev caches (webapp_next_cache / webapp_node_modules
    # live in docker-compose.dev.yml, unknown to a plain `compose`), and
    # profile-gated volumes like kb_data. Sweep EVERY remaining <project>_*
    # volume by name so purge truly leaves nothing behind.
    local _proj; _proj="$(compose_project_name)"
    docker volume ls --format '{{.Name}}' 2>/dev/null \
        | grep -E "^${_proj}_" \
        | xargs -r docker volume rm >/dev/null 2>&1 || true
    # Belt-and-suspenders: explicitly drop the local-LLM models volume in case it
    # was created outside the compose lifecycle (its name is not <project>_-prefixed).
    docker volume rm "$LOCAL_LLM_VOLUME" >/dev/null 2>&1 || true
    # The CodeFix sandbox network is created at runtime by the orchestrator (no
    # compose service is attached), so `compose down` never removes it.
    docker network rm redamon-codefix-net >/dev/null 2>&1 || true

    info "Removing RedAmon images..."
    remove_redamon_images
    docker image prune -f >/dev/null 2>&1 || true

    # Host-side KB state files that must be wiped in lockstep with the
    # Neo4j volume. Leaving these behind after a purge causes a
    # split-brain on reinstall: Neo4j is empty but FAISS still has
    # stale vectors, and the dedup layers still think every chunk is
    # already ingested, so the bootstrap build becomes a no-op and
    # Neo4j stays empty.
    #
    # The on-disk content under knowledge_base/data/cache (tarballs,
    # CSVs, YAML templates, markdown) is deliberately preserved —
    # those are ~30+ MB of downloaded source files that don't need to
    # be re-fetched from GitHub/GitLab/NVD on every reinstall. What we
    # DO wipe are the dedup sidecars that model "what Neo4j already
    # has":
    #   - .manifest.json          (chunk-level hash dedup, Layer 2)
    #   - .file_hashes.json       (file-level hash dedup, Layer 1)
    # These live inside data/cache but are state, not content.
    info "Removing host-side KB index state..."
    # These files are created by Docker (root-owned), so normal rm may fail.
    # Try without sudo first; escalate only if needed.
    local kb_files=(
        "$SCRIPT_DIR/knowledge_base/data/index.faiss"
        "$SCRIPT_DIR/knowledge_base/data/chunk_ids.json"
        "$SCRIPT_DIR/knowledge_base/data/index.faiss.manifest.json"
        "$SCRIPT_DIR/knowledge_base/data/.last_ingest"
    )
    if ! rm -f "${kb_files[@]}" 2>/dev/null; then
        warn "Root-owned files detected, elevating with sudo..."
        # Non-fatal: a sudo-less / non-interactive run must not abort purge here
        # and leave the later volume/flag cleanup undone. Worst case these stale
        # FAISS files remain, which only matters if KB is later re-enabled.
        sudo rm -f "${kb_files[@]}" || warn "Could not remove root-owned KB index files; remove manually: sudo rm -f ${kb_files[*]}"
    fi

    info "Removing host-side KB dedup state (manifest + file hashes)..."
    if ! rm -f "$SCRIPT_DIR/knowledge_base/data/cache/.manifest.json" 2>/dev/null; then
        sudo rm -f "$SCRIPT_DIR/knowledge_base/data/cache/.manifest.json" \
            || warn "Could not remove root-owned KB manifest; remove manually with sudo."
    fi
    # Wipe every per-source .file_hashes.json without touching the
    # downloaded content alongside it. -print is for operator feedback.
    if [[ -d "$SCRIPT_DIR/knowledge_base/data/cache" ]]; then
        if ! find "$SCRIPT_DIR/knowledge_base/data/cache" \
            -type f -name '.file_hashes.json' -print -delete \
            2>/dev/null; then
            sudo find "$SCRIPT_DIR/knowledge_base/data/cache" \
                -type f -name '.file_hashes.json' -print -delete \
                2>/dev/null || true
        fi
    fi

    rm -f "$GVM_FLAG_FILE"
    rm -f "$KBASE_FLAG_FILE"
    rm -f "$KBASE_DISABLED_FLAG_FILE"
    rm -f "$LEGACY_SKIPKBASE_FLAG_FILE"
    success "Full cleanup complete. All RedAmon data and images have been removed."
    echo ""
    info "To reinstall: ./redamon.sh install"
}

cmd_status() {
    _migrate_legacy_kbase_flag

    local version
    version="$(get_version)"

    print_banner
    echo -e "  ${CYAN}Version:${NC}       v${version}"

    # GVM feature gate
    if is_gvm_enabled; then
        echo -e "  ${CYAN}GVM_ENABLED:${NC}   ${GREEN}true${NC}"
    else
        echo -e "  ${CYAN}GVM_ENABLED:${NC}   false"
    fi

    # KB feature gate (from kb_config.yaml / env var)
    if is_kb_enabled; then
        echo -e "  ${CYAN}KB_ENABLED:${NC}    ${GREEN}true${NC}"
    else
        echo -e "  ${CYAN}KB_ENABLED:${NC}    false"
    fi

    # KB data state — always shown, independent of KB_ENABLED
    local faiss_count neo4j_count kb_state
    faiss_count=$(_kb_get_faiss_count)
    neo4j_count=$(_kb_get_neo4j_count)

    if [[ "$faiss_count" == "0" && "$neo4j_count" == "0" ]]; then
        kb_state="${YELLOW}empty${NC}"
    elif [[ "$faiss_count" == "unknown" || "$neo4j_count" == "unknown" ]]; then
        kb_state="${YELLOW}unknown${NC}"
    elif [[ "$faiss_count" == "0" || "$neo4j_count" == "0" ]]; then
        kb_state="${YELLOW}partial${NC}"
    else
        kb_state="${GREEN}populated${NC}"
    fi
    echo -e "  ${CYAN}KB:${NC}            ${kb_state} (FAISS: ${faiss_count} vectors; NEO4J: ${neo4j_count} chunks)"

    echo ""

    # Container list — filter to redamon containers only. Keeps the header
    # row and any container whose name starts with "redamon-".
    docker compose ps | grep -E '^(NAME|redamon-)' || {
        # grep returns non-zero if no lines match (no containers running).
        # Fall back to plain ps so the user still sees the "no services" message.
        docker compose ps
    }

    # Orchestrator-spawned AI containers (NOT compose-managed, so absent above):
    # the on-demand local LLM + any in-flight AI Attack Surface scan containers.
    local spawned
    spawned=$(docker ps "${SPAWNED_CONTAINER_NAME_FILTERS[@]}" \
                --format '    {{.Names}}  ({{.Status}})' 2>/dev/null || true)
    if [[ -n "$spawned" ]]; then
        echo ""
        echo -e "  ${CYAN}AI Attack Surface (on-demand, orchestrator-spawned):${NC}"
        echo "$spawned"
    fi
}

# ---------------------------------------------------------------------------
# Knowledge Base commands
# ---------------------------------------------------------------------------

cmd_kb_build() {
    local profile="${1:-lite}"
    case "$profile" in
        cpu-lite|lite|standard|full) ;;
        *)
            error "Unknown KB profile: $profile"
            echo "Usage: ./redamon.sh kb build [lite|standard|full]"
            exit 1
            ;;
    esac

    print_banner
    info "Building Knowledge Base (profile=${profile})"
    echo ""

    _kb_export_env
    _kb_wait_neo4j || exit 1

    info "Running ingestion pipeline..."
    if ! _kb_make "kb-build-${profile}" MODE=docker; then
        error "KB build failed"
        exit 1
    fi

    echo ""
    success "Knowledge Base built successfully"
    _kb_make kb-stats MODE=docker
}

cmd_kb_update() {
    local source="${1:-}"

    print_banner
    _kb_export_env
    _kb_wait_neo4j || exit 1

    if [[ -n "$source" ]]; then
        case "$source" in
            nvd|exploitdb|nuclei|gtfobins|lolbas|owasp|tools) ;;
            *)
                error "Unknown KB source: $source"
                echo "Valid sources: nvd, exploitdb, nuclei, gtfobins, lolbas, owasp, tools"
                exit 1
                ;;
        esac
        info "Updating KB source: ${source}"
        if ! _kb_make "kb-update-${source}" MODE=docker; then
            error "KB update failed for ${source}"
            exit 1
        fi
    else
        info "Updating all KB sources (incremental)"
        local failed=()
        for src in nvd exploitdb nuclei gtfobins lolbas owasp tools; do
            echo ""
            info "→ ${src}"
            _kb_make "kb-update-${src}" MODE=docker || failed+=("$src")
        done
        if [[ ${#failed[@]} -gt 0 ]]; then
            echo ""
            warn "Some sources failed to update: ${failed[*]}"
        fi
    fi

    echo ""
    success "Knowledge Base update complete"
    _kb_make kb-stats MODE=docker
}

cmd_kb_rebuild() {
    local profile="${1:-standard}"
    case "$profile" in
        cpu-lite|lite|standard|full) ;;
        *)
            error "Invalid profile '$profile'. Use cpu-lite, lite, standard, or full."
            echo "Usage: ./redamon.sh kb rebuild [cpu-lite|lite|standard|full]"
            exit 1
            ;;
    esac

    print_banner
    warn "This will WIPE and rebuild the entire Knowledge Base."
    info "Profile: $profile"
    echo ""

    _kb_export_env
    _kb_wait_neo4j || exit 1

    info "Rebuilding Knowledge Base from scratch..."
    if ! _kb_make "kb-rebuild-${profile}" MODE=docker; then
        error "KB rebuild failed"
        exit 1
    fi

    echo ""
    success "Knowledge Base rebuilt"
    _kb_make kb-stats MODE=docker
}

cmd_kb_stats() {
    _kb_export_env
    _kb_wait_neo4j || exit 1
    _kb_make kb-stats MODE=docker
}

cmd_kb_help() {
    echo -e "${BOLD}Usage:${NC} ./redamon.sh kb <command> [args]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}build [profile]${NC}    Build KB — profile: lite (default) | standard | full"
    echo -e "  ${GREEN}update [source]${NC}    Update KB — all sources, or one: nvd|exploitdb|nuclei|gtfobins|lolbas|owasp|tools"
    echo -e "  ${GREEN}rebuild${NC}            Wipe and rebuild (standard profile)"
    echo -e "  ${GREEN}stats${NC}              Show FAISS + Neo4j chunk counts"
    echo -e "  ${GREEN}help${NC}               Show this help"
    echo ""
    echo -e "${BOLD}Profiles:${NC}"
    echo "  lite      tool_docs + metasploit + gtfobins + lolbas + owasp + exploitdb + NVD (90 days)"
    echo "  standard  same sources as lite + NVD (2 years)"
    echo "  full      standard + Nuclei (requires redamon-kali container running)"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./redamon.sh kb build             # Build lite KB (default)"
    echo "  ./redamon.sh kb build standard    # Build with 2 years of NVD"
    echo "  ./redamon.sh kb rebuild           # Wipe + rebuild standard (default)"
    echo "  ./redamon.sh kb rebuild lite      # Wipe + rebuild lite profile"
    echo "  ./redamon.sh kb rebuild full      # Wipe + rebuild full profile (incl. nuclei)"
    echo "  ./redamon.sh kb update nvd        # Incremental NVD refresh"
    echo "  ./redamon.sh kb update            # Update all sources"
    echo "  ./redamon.sh kb stats             # See what's in the KB"
    echo ""
}

cmd_help() {
    print_banner
    echo -e "${BOLD}Usage:${NC} ./redamon.sh <command> [options]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}install${NC}              Build and start RedAmon (no GVM, no Knowledge Base)"
    echo -e "  ${GREEN}install --gvm${NC}        Build and start RedAmon (with GVM/OpenVAS)"
    echo -e "  ${GREEN}install --kbase${NC}      Build with Knowledge Base (~4.4 GB heavier, local KB enabled)"
    echo -e "  ${GREEN}update${NC}           Pull latest version and smart-rebuild changed services"
    echo -e "  ${GREEN}up${NC}               Start services"
    echo -e "  ${GREEN}up dev${NC}           Start in dev mode (hot-reload, auto-detects GVM mode)"
    echo -e "  ${GREEN}down${NC}             Stop services (preserves data)"
    echo -e "  ${GREEN}clean${NC}            Remove containers and images (keeps data)"
    echo -e "  ${GREEN}purge${NC}            Remove everything including all data"
    echo -e "  ${GREEN}status${NC}           Show running services, version, GVM, and KB state"
    echo -e "  ${GREEN}create-admin${NC}     Create the admin login (or reset it); use if no prompt appeared at install"
    echo -e "  ${GREEN}reset-password${NC}   Reset an existing user's password"
    echo -e "  ${GREEN}kb <command>${NC}     Knowledge Base management (build/update/rebuild/stats)"
    echo -e "  ${GREEN}supply-chain-sync [ecos]${NC}  Populate the offline OSV DB (default: npm; e.g. 'npm PyPI Go')"
    echo -e "  ${GREEN}help${NC}             Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./redamon.sh install               # First-time setup (lightweight: no GVM, no KB)"
    echo "  ./redamon.sh install --kbase       # First-time setup with local Knowledge Base"
    echo "  ./redamon.sh install --gvm         # First-time setup with GVM/OpenVAS"
    echo "  ./redamon.sh install --gvm --kbase # First-time setup with everything"
    echo "  ./redamon.sh update           # Update to latest version"
    echo "  ./redamon.sh up               # Start after reboot"
    echo "  ./redamon.sh up dev           # Dev mode with hot-reload (auto-detects GVM)"
    echo "  ./redamon.sh create-admin     # Create the admin login (or reset it)"
    echo "  ./redamon.sh reset-password   # Reset a user's password"
    echo "  ./redamon.sh kb build lite    # Build Knowledge Base"
    echo "  ./redamon.sh kb update        # Refresh all KB sources"
    echo "  ./redamon.sh kb stats         # Show KB chunk counts"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Dispatch only when executed directly. When the script is sourced (e.g. by the
# test suite in tests/redamon_build_test.sh) this guard prevents the cd and the
# command dispatch from running, so the helper functions can be loaded and unit-
# tested in isolation.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
cd "$SCRIPT_DIR"

# #163: clamp the per-service `cpus:` caps to the host's core count for EVERY
# command that can touch Docker. Done here rather than inside each command
# because `install`, `update` and the password/KB helpers all reach
# `docker compose up` by different routes, and any one of them exceeding the
# core count aborts the whole `up`. `help` is excluded so it stays offline.
case "${1:-help}" in
    help|--help|-h) ;;
    *) export_cpu_caps ;;
esac

case "${1:-help}" in
    install) shift; cmd_install "$@" ;;
    update)  cmd_update ;;
    up)
        if [[ "${2:-}" == "dev" ]]; then
            cmd_up_dev
        else
            cmd_up
        fi
        ;;
    down)    cmd_down ;;
    clean)   cmd_clean ;;
    purge)   cmd_purge ;;
    status)  cmd_status ;;
    kb)
        shift
        case "${1:-help}" in
            build)   shift; cmd_kb_build   "${1:-lite}" ;;
            update)  shift; cmd_kb_update  "${1:-}" ;;
            rebuild) shift; cmd_kb_rebuild "${1:-standard}" ;;
            stats)   cmd_kb_stats ;;
            help|--help|-h|"") cmd_kb_help ;;
            *)
                error "Unknown kb command: $1"
                cmd_kb_help
                exit 1
                ;;
        esac
        ;;
    reset-password) cmd_reset_password ;;
    create-admin)   cmd_create_admin ;;
    supply-chain-sync) shift; cmd_supply_chain_sync "$@" ;;
    help|--help|-h) cmd_help ;;
    *)
        error "Unknown command: $1"
        cmd_help
        exit 1
        ;;
esac
fi
