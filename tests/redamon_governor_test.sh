#!/usr/bin/env bash
# =============================================================================
# Unit tests for the memory-governor bash helpers in redamon.sh:
#   _size_to_mb / preflight_ram_gate / allocate_memory (the proportional
#   allocator: weights, tiers, floors, burst, blast bound) / export_cpu_caps
# Run:  bash tests/redamon_governor_test.sh
# detect_build_resources is stubbed so the gate/export logic is deterministic and
# needs no real Docker daemon.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e   # redamon.sh turns on `set -e`; relax it so a non-zero return under test
         # (e.g. the gate returning 1) does not abort the harness.

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()   { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }

# Silence info/warn/error output from the functions under test.
info()  { :; }; warn() { :; }; error() { :; }; success() { :; }

echo "== _size_to_mb =="
eq "2g -> 2048"        "$(_size_to_mb 2g)"        "2048"
eq "512m -> 512"       "$(_size_to_mb 512m)"      "512"
eq "512mb -> 512"      "$(_size_to_mb 512mb)"     "512"
eq "2G upper -> 2048"  "$(_size_to_mb 2G)"        "2048"
eq "1GB bytes -> 1024" "$(_size_to_mb 1073741824)" "1024"
eq "2048 bytes -> 0MB" "$(_size_to_mb 2048)"      "0"
eq "1.5g -> 1536"      "$(_size_to_mb 1.5g)"      "1536"
eq "0.5g -> 512"       "$(_size_to_mb 0.5g)"      "512"
eq "6.5g -> 6656"      "$(_size_to_mb 6.5g)"      "6656"
eq "empty -> empty"    "$(_size_to_mb '')"        ""
eq "garbage -> empty"  "$(_size_to_mb abc)"       ""

echo "== preflight_ram_gate =="
# Stub detected RAM.
STUB_MEM=0
detect_build_resources() { BUILD_MEM_MB="$STUB_MEM"; BUILD_RES_SOURCE="stub"; BUILD_NCPU=4; }

STUB_MEM=4096; unset REDAMON_MIN_RAM_MB REDAMON_SKIP_RAM_GATE SERVICE_BASELINE_MEM OS_HEADROOM_MEM
preflight_ram_gate; eq "4GB host fails default 8GB gate" "$?" "1"

STUB_MEM=16384
preflight_ram_gate; eq "16GB host passes gate" "$?" "0"

STUB_MEM=7700   # physical 8GB host reads ~7.7GB via docker info -> should pass (tolerance)
preflight_ram_gate; eq "8GB host (7700MB) passes via tolerance" "$?" "0"

STUB_MEM=4096; REDAMON_SKIP_RAM_GATE=1
preflight_ram_gate; eq "skip flag overrides" "$?" "0"
unset REDAMON_SKIP_RAM_GATE

STUB_MEM=10240; REDAMON_MIN_RAM_MB=12288
preflight_ram_gate; eq "explicit MIN_RAM_MB enforced" "$?" "1"
unset REDAMON_MIN_RAM_MB

STUB_MEM=0   # undetectable -> do not block
preflight_ram_gate; eq "undetectable RAM does not block" "$?" "0"

STUB_MEM=5120; SERVICE_BASELINE_MEM=2g; OS_HEADROOM_MEM=1g  # required 3072
preflight_ram_gate; eq "custom baseline+headroom passes" "$?" "0"
unset SERVICE_BASELINE_MEM OS_HEADROOM_MEM

echo "== allocate_memory: the proportional allocator =="
# The whole point of this suite: EVERY limit must be a percentage of the host's
# RAM. A fixed number reappearing here is a regression, and `no cap repeats
# across two host sizes` below is the test that catches it.

MEM_VARS=(NEO4J_HEAP NEO4J_PAGECACHE NEO4J_MEM AGENT_MEM GVMD_MEM KB_REFRESH_MEM
          RECON_ORCHESTRATOR_MEM WEBAPP_MEM POSTGRES_MEM KALI_MEM CAPTURE_PROXY_MEM
          DOCKER_BROKER_MEM TRAFFIC_INGEST_MEM OS_HEADROOM_MEM SERVICE_BASELINE_MEM)

# Isolate from the repo's real .env: an operator pin there would otherwise make
# the allocator (correctly) skip the export and fail these assertions.
MEM_TMP="$(mktemp -d)"
_REAL_SCRIPT_DIR="$SCRIPT_DIR"
SCRIPT_DIR="$MEM_TMP"
WANT_GVM=0; WANT_KB=0
is_gvm_enabled()   { [[ "$WANT_GVM" == "1" ]]; }
is_kbase_enabled() { [[ "$WANT_KB"  == "1" ]]; }

# Deterministic burst: the swap probe must not make the suite host-dependent.
export BURST_FACTOR=1.75

alloc_at() {   # alloc_at <MB> [gvm] [kb]  -> populates the *_MEM vars
    unset "${MEM_VARS[@]}"
    STUB_MEM="$1"; WANT_GVM="${2:-0}"; WANT_KB="${3:-0}"
    allocate_memory
}
sum_alloc() { local s=0 m; for m in "${_ALLOC_MB[@]}"; do s=$(( s + m )); done; printf '%s' "$s"; }
mb() { printf '%s' "${1%m}"; }

# --- weights renormalise per profile, so enabling one shrinks everyone else
# --- rather than over-committing the host.
for combo in "0 0 base" "1 0 +gvm" "0 1 +kb" "1 1 +gvm+kb"; do
    read -r g k label <<< "$combo"
    alloc_at 16384 "$g" "$k"
    tot="$(sum_alloc)"
    if [[ "$tot" -gt 0 && "$tot" -le $(( _ALLOC_SERVICES_MB * 200 / 100 )) ]]; then
        ok "weights normalise ($label)"
    else
        bad "weights normalise ($label)" "$tot" "<= 2x services pool"
    fi
done

# --- the core invariants, at every host size we support and well beyond.
SIZES=(8192 16384 32768 65536 131072 524288)
for t in "${SIZES[@]}"; do
    # Fair shares (no burst) must never exceed the guaranteed services budget.
    BURST_FACTOR=1.0 alloc_at "$t"
    tot="$(sum_alloc)"
    if [[ "$tot" -le $(( _ALLOC_SERVICES_MB + 16 )) ]]; then
        ok "${t}MB: sum(fair shares) <= services pool"
    else
        bad "${t}MB: sum(fair shares) <= services pool" "$tot" "<= $_ALLOC_SERVICES_MB"
    fi

    # Budget identity: nothing is invented or lost.
    if [[ $(( _ALLOC_OS_MB + _ALLOC_SERVICES_MB + _ALLOC_SCAN_MB )) -le "$t" ]]; then
        ok "${t}MB: os + services + scan_pool <= MemTotal"
    else
        bad "${t}MB: os + services + scan_pool <= MemTotal" \
            "$(( _ALLOC_OS_MB + _ALLOC_SERVICES_MB + _ALLOC_SCAN_MB ))" "<= $t"
    fi

    # Worst case at the default burst: everything peaking at once still fits.
    BURST_FACTOR=1.75 alloc_at "$t"
    tot="$(sum_alloc)"
    if [[ $(( tot + _ALLOC_OS_MB )) -le "$t" ]]; then
        ok "${t}MB: burst 1.75 worst case fits without swap"
    else
        bad "${t}MB: burst 1.75 worst case fits without swap" "$(( tot + _ALLOC_OS_MB ))" "<= $t"
    fi

    # neo4j's container limit must exceed heap + page cache or the JVM is
    # OOM-killed at boot. (Regression: this caught a real bug before.)
    h="$(mb "$NEO4J_HEAP")"; p="$(mb "$NEO4J_PAGECACHE")"; m="$(mb "$NEO4J_MEM")"
    if [[ "$m" -gt $(( h + p )) ]]; then
        ok "${t}MB: NEO4J_MEM > heap + pagecache"
    else
        bad "${t}MB: NEO4J_MEM > heap + pagecache" "$m" "> $(( h + p ))"
    fi

    # Floors are for infeasible hosts only; they must never bind on a supported one.
    if [[ "$_ALLOC_FEASIBLE" == "1" ]]; then
        ok "${t}MB: feasible (floors do not bind)"
    else
        bad "${t}MB: feasible (floors do not bind)" "infeasible" "feasible"
    fi
done

# --- THE anti-hardcoding test: a value that does not move with the host is a
# --- fixed cap by definition. Every var must differ across two host sizes.
BURST_FACTOR=1.75 alloc_at 16384
declare -a SMALL_VALS=()
for v in "${MEM_VARS[@]}"; do SMALL_VALS+=("${!v:-}"); done
BURST_FACTOR=1.75 alloc_at 65536
i=0; frozen=""
for v in "${MEM_VARS[@]}"; do
    [[ -n "${SMALL_VALS[$i]}" && "${SMALL_VALS[$i]}" == "${!v:-}" ]] && frozen="$frozen $v=${!v}"
    i=$(( i + 1 ))
done
if [[ -z "$frozen" ]]; then
    ok "no cap is identical on a 16GB and a 64GB host (nothing is hardcoded)"
else
    bad "no cap is identical on a 16GB and a 64GB host" "frozen:$frozen" "all scale"
fi

# --- scaling is genuinely proportional: 4x the RAM, ~4x the cap.
BURST_FACTOR=1.75 alloc_at 16384; w16="$(mb "$WEBAPP_MEM")"
BURST_FACTOR=1.75 alloc_at 65536; w64="$(mb "$WEBAPP_MEM")"
if [[ "$w64" -ge $(( w16 * 39 / 10 )) && "$w64" -le $(( w16 * 41 / 10 )) ]]; then
    ok "WEBAPP_MEM scales ~4x when RAM goes 16GB -> 64GB"
else
    bad "WEBAPP_MEM scales ~4x when RAM goes 16GB -> 64GB" "$w16 -> $w64" "~4x"
fi

# --- infeasible hosts are REFUSED, not silently over-committed.
alloc_at 4096; eq "4GB host is infeasible (rc)" "$?" "1"
eq "4GB host flagged infeasible" "$_ALLOC_FEASIBLE" "0"
alloc_at 8192 1 1; eq "8GB + GVM + KB is infeasible (rc)" "$?" "1"
alloc_at 8192 0 0; eq "8GB base is feasible (rc)" "$?" "0"

# --- reserved vs burst: neo4j/postgres really allocate, so they are NEVER
# --- multiplied; the ceiling-type services are.
BURST_FACTOR=1.0  alloc_at 16384; neo_1="$(mb "$NEO4J_MEM")"; web_1="$(mb "$WEBAPP_MEM")"
BURST_FACTOR=2.5  alloc_at 16384; neo_25="$(mb "$NEO4J_MEM")"; web_25="$(mb "$WEBAPP_MEM")"
eq "neo4j (reserved) ignores BURST_FACTOR" "$neo_1" "$neo_25"
if [[ "$web_25" -gt "$web_1" ]]; then ok "webapp (burst) grows with BURST_FACTOR"
else bad "webapp (burst) grows with BURST_FACTOR" "$web_1 -> $web_25" "larger"; fi

# --- idempotence: same host, same answer.
BURST_FACTOR=1.75 alloc_at 16384; first="$(sum_alloc)"
BURST_FACTOR=1.75 alloc_at 16384; eq "allocation is idempotent" "$(sum_alloc)" "$first"

# --- per-service weight override changes only that service's SHARE.
BURST_FACTOR=1.75 alloc_at 16384; base_web="$(mb "$WEBAPP_MEM")"; base_kali="$(mb "$KALI_MEM")"
REDAMON_WEIGHT_WEBAPP=400 BURST_FACTOR=1.75 alloc_at 16384
if [[ "$(mb "$WEBAPP_MEM")" -gt "$base_web" && "$(mb "$KALI_MEM")" -lt "$base_kali" ]]; then
    ok "REDAMON_WEIGHT_WEBAPP raises webapp and renormalises the rest down"
else
    bad "REDAMON_WEIGHT_WEBAPP renormalises" "web $base_web->$(mb "$WEBAPP_MEM") kali $base_kali->$(mb "$KALI_MEM")" "web up, kali down"
fi
unset REDAMON_WEIGHT_WEBAPP

# --- blast bound: a pathological weight cannot hand one service the whole host.
REDAMON_WEIGHT_WEBAPP=100000 BURST_FACTOR=2.5 alloc_at 16384
if [[ "$(mb "$WEBAPP_MEM")" -le $(( 16384 * 55 / 100 )) ]]; then
    ok "blast bound caps a runaway weight at 55% of the host"
else
    bad "blast bound caps a runaway weight" "$(mb "$WEBAPP_MEM")" "<= $(( 16384 * 55 / 100 ))"
fi
unset REDAMON_WEIGHT_WEBAPP

# --- the scan governor is fed from the SAME computation (no second guess).
BURST_FACTOR=1.75 alloc_at 16384
eq "OS_HEADROOM_MEM = computed os_reserve"       "$OS_HEADROOM_MEM"      "${_ALLOC_OS_MB}m"
eq "SERVICE_BASELINE_MEM = services pool"        "$SERVICE_BASELINE_MEM" "${_ALLOC_SERVICES_MB}m"
# The orchestrator computes scan_pool = total - headroom - baseline; that must
# reproduce our scan_pool exactly, or the two governors disagree again.
if [[ $(( 16384 - _ALLOC_OS_MB - _ALLOC_SERVICES_MB )) -eq "$_ALLOC_SCAN_MB" ]]; then
    ok "orchestrator's scan_pool formula reproduces ours exactly"
else
    bad "orchestrator's scan_pool formula reproduces ours" \
        "$(( 16384 - _ALLOC_OS_MB - _ALLOC_SERVICES_MB ))" "$_ALLOC_SCAN_MB"
fi

echo "== operator pins are never overwritten =="
# The bug this suite exists to prevent: redamon.sh does not source .env, so
# exporting a computed value silently overrode a hand-pinned one on every `up`
# (compose gives the shell environment priority over .env).
alloc_at 16384; unpinned_web="$WEBAPP_MEM"

# Each of these models a FRESH `./redamon.sh up`. Within one process the
# allocator deliberately does not mistake its own earlier exports for operator
# pins (otherwise cmd_update's second pass would own nothing and write an empty
# managed block), so the marker has to be cleared to simulate a new run.
# tests/redamon_env_block_test.sh covers the same ground with real subprocesses.
fresh_process() { _MEM_SELF_EXPORTED=" "; unset "${MEM_VARS[@]}"; }

fresh_process; WEBAPP_MEM="9g"; STUB_MEM=16384; allocate_memory
eq "a shell pin survives" "$WEBAPP_MEM" "9g"

fresh_process
printf 'WEBAPP_MEM=7g\n' > "$MEM_TMP/.env"
STUB_MEM=16384; allocate_memory
eq "a .env pin is not overridden (left unset for compose)" "${WEBAPP_MEM:-<unset>}" "<unset>"
if [[ -n "${AGENT_MEM:-}" ]]; then ok "an unpinned service is still computed"
else bad "an unpinned service is still computed" "<unset>" "a size"; fi

# A bare `VAR=` in .env is a PLACEHOLDER (that is how .env.example ships every
# knob), not a pin. Reading it as one would leave compose with an empty
# mem_limit and the stack would refuse to start.
fresh_process
printf 'WEBAPP_MEM=\n' > "$MEM_TMP/.env"
STUB_MEM=16384; allocate_memory
eq "an empty .env placeholder is not a pin" "$WEBAPP_MEM" "$unpinned_web"

# A value INSIDE the managed block is ours, not a pin: it must be recomputed.
fresh_process
{ printf '%s\n' "$_MEM_BLOCK_BEGIN"; printf 'WEBAPP_MEM=1m\n'; printf '%s\n' "$_MEM_BLOCK_END"; } > "$MEM_TMP/.env"
STUB_MEM=16384; allocate_memory
eq "a value inside the managed block is recomputed" "$WEBAPP_MEM" "$unpinned_web"
rm -f "$MEM_TMP/.env"

# Repeated passes in ONE process (cmd_update recreates the core services after a
# rebuild) must keep owning their vars, or the managed block is written empty.
fresh_process; STUB_MEM=16384; allocate_memory; own1=${#_ALLOC_OWNED[@]}
STUB_MEM=16384; allocate_memory
eq "a second pass in the same process still owns every var" "${#_ALLOC_OWNED[@]}" "$own1"

# --- a host whose RAM cannot be read must FAIL OPEN, never block.
alloc_at 0; eq "undetectable RAM does not fail" "$?" "0"

echo "== knobs set in .env are honoured (redamon.sh does NOT source .env) =="
# BUG: every tuning knob was read from the SHELL environment only. .env.example
# documents them, so an operator setting SERVICES_PCT=70 in .env saw no effect
# and no explanation -- the same silent-inertness this whole feature exists to
# remove. Percentages, the burst factor and per-service weights must all resolve
# from .env.
fresh_process
cat > "$MEM_TMP/.env" <<'ENVKNOBS'
OS_RESERVE_PCT=12
SERVICES_PCT=42
BURST_FACTOR=2.0
BLAST_PCT=80
REDAMON_WEIGHT_WEBAPP=400
ENVKNOBS
unset BURST_FACTOR
eq "OS_RESERVE_PCT read from .env" "$(_pct_env OS_RESERVE_PCT 8 1 50)"   "12"
eq "SERVICES_PCT read from .env"   "$(_pct_env SERVICES_PCT 65 10 95)"   "42"
eq "BLAST_PCT read from .env"      "$(_pct_env BLAST_PCT 55 20 90)"      "80"
eq "BURST_FACTOR read from .env"   "$(BUILD_MEM_MB=16384 _burst_pct)"    "200"
STUB_MEM=16384; allocate_memory
for i in "${!_ALLOC_NAMES[@]}"; do
    [[ "${_ALLOC_NAMES[$i]}" == "WEBAPP" ]] && \
        eq "REDAMON_WEIGHT_WEBAPP read from .env" "${_ALLOC_WEIGHTS[$i]}" "400"
done
# The shell environment must still win over .env.
eq "a shell value overrides .env" "$(SERVICES_PCT=77 _pct_env SERVICES_PCT 65 10 95)" "77"
# Out-of-range and garbage fall back to the default rather than corrupting the split.
printf 'SERVICES_PCT=999\n' > "$MEM_TMP/.env"
eq "an out-of-range .env value falls back" "$(_pct_env SERVICES_PCT 65 10 95)" "65"
printf 'SERVICES_PCT=abc\n' > "$MEM_TMP/.env"
eq "a garbage .env value falls back"       "$(_pct_env SERVICES_PCT 65 10 95)" "65"
rm -f "$MEM_TMP/.env"
export BURST_FACTOR=1.75

echo "== hardening regressions =="
# BUG: burst 2.5 used to be unlocked by the mere PRESENCE of swap. Measured
# across 8G..128G, burst 2.5 over-commits by ~21% of RAM, so a 64 MB zram device
# would have licensed a multi-GB over-commit and a simultaneous peak would OOM
# the host rather than page.
_swap_total_mb() { printf '%s' "${STUB_SWAP_MB:-0}"; }
unset BURST_FACTOR
STUB_MEM=16384
STUB_SWAP_MB=64    ; eq "a token 64MB swap does NOT unlock burst 2.5"  "$(BUILD_MEM_MB=16384 _burst_pct)" "175"
STUB_SWAP_MB=2048  ; eq "an undersized 2GB swap does NOT unlock 2.5"   "$(BUILD_MEM_MB=16384 _burst_pct)" "175"
STUB_SWAP_MB=4096  ; eq "a 4GB swap (25% of 16GB) unlocks burst 2.5"   "$(BUILD_MEM_MB=16384 _burst_pct)" "250"
STUB_SWAP_MB=0     ; eq "no swap keeps the conservative 1.75"          "$(BUILD_MEM_MB=16384 _burst_pct)" "175"
# The threshold is a PERCENTAGE, so it tracks the host rather than a fixed size.
STUB_SWAP_MB=4096  ; eq "the same 4GB swap is too small for a 64GB host" "$(BUILD_MEM_MB=65536 _burst_pct)" "175"
STUB_SWAP_MB=16384 ; eq "16GB swap unlocks 2.5 on a 64GB host"          "$(BUILD_MEM_MB=65536 _burst_pct)" "250"
STUB_SWAP_MB=64    ; eq "BURST_SWAP_MIN_PCT can be relaxed by an operator" \
    "$(BURST_SWAP_MIN_PCT=1 BUILD_MEM_MB=6400 _burst_pct)" "250"
eq "an explicit BURST_FACTOR still overrides the swap probe" \
    "$(BURST_FACTOR=2.5 STUB_SWAP_MB=0 BUILD_MEM_MB=16384 _burst_pct)" "250"
unset STUB_SWAP_MB
export BURST_FACTOR=1.75

# BUG (guard, was already safe): if every weight is rejected as non-numeric the
# fair shares are all 0 and the floor-redistribution pass has nobody to take from.
# No service may be left below the minimum its software needs to boot.
fresh_process
REDAMON_WEIGHT_NEO4J=x REDAMON_WEIGHT_POSTGRES=x REDAMON_WEIGHT_AGENT=x REDAMON_WEIGHT_WEBAPP=x \
REDAMON_WEIGHT_KALI=x REDAMON_WEIGHT_RECON_ORCHESTRATOR=x REDAMON_WEIGHT_CAPTURE_PROXY=x \
REDAMON_WEIGHT_DOCKER_BROKER=x REDAMON_WEIGHT_TRAFFIC_INGEST=x STUB_MEM=16384 allocate_memory
below=0
for i in "${!_ALLOC_MB[@]}"; do
    [[ "${_ALLOC_MB[$i]}" -lt "${_ALLOC_FLOORS[$i]}" ]] && below=$(( below + 1 ))
done
eq "all-invalid weights still leave every service at or above its floor" "$below" "0"
if [[ "$(mb "$WEBAPP_MEM")" -gt 0 && "$(mb "$NEO4J_MEM")" -gt 0 ]]; then
    ok "all-invalid weights never yield a 0-byte mem_limit"
else
    bad "all-invalid weights never yield a 0-byte mem_limit" "$WEBAPP_MEM/$NEO4J_MEM" "> 0"
fi

rm -rf "$MEM_TMP"
SCRIPT_DIR="$_REAL_SCRIPT_DIR"
unset BURST_FACTOR
STUB_MEM=32000

echo "== export_cpu_caps (#163) =="
CPU_VARS=(POSTGRES_CPUS NEO4J_CPUS KALI_CPUS RECON_ORCHESTRATOR_CPUS AGENT_CPUS WEBAPP_CPUS DOCKER_BROKER_CPUS)
# Isolate from the repo's real .env (an operator pin there must not skew the test).
CPU_TMP="$(mktemp -d)"; trap 'rm -rf "$CPU_TMP"' EXIT
SCRIPT_DIR="$CPU_TMP"
reset_cpu_stub() { unset "${CPU_VARS[@]}" BUILD_NCPU; STUB_NCPU="$1"; }
detect_build_resources() { BUILD_MEM_MB="$STUB_MEM"; BUILD_RES_SOURCE="stub"; BUILD_NCPU="$STUB_NCPU"; }

# The reported failure: a 4-vCPU VM. Every cap must land <= 4 or the daemon
# rejects `up` with "range of CPUs is from 0.01 to 4.00".
reset_cpu_stub 4; export_cpu_caps
eq "4 cores: NEO4J_CPUS 8 -> 4"  "$NEO4J_CPUS" "4"
eq "4 cores: KALI_CPUS 10 -> 4"  "$KALI_CPUS"  "4"
eq "4 cores: AGENT_CPUS 8 -> 4"  "$AGENT_CPUS" "4"
eq "4 cores: POSTGRES_CPUS kept" "$POSTGRES_CPUS" "4"
eq "4 cores: BROKER_CPUS kept"   "$DOCKER_BROKER_CPUS" "2"
over=""
for v in "${CPU_VARS[@]}"; do [[ "${!v}" -gt 4 ]] && over="$over $v=${!v}"; done
if [[ -z "$over" ]]; then ok "no cap exceeds host cores"; else bad "no cap exceeds host cores" "$over" "<=4"; fi

# Roomy host: the generous compose defaults must survive untouched.
reset_cpu_stub 16; export_cpu_caps
eq "16 cores: NEO4J_CPUS stays 8" "$NEO4J_CPUS" "8"
eq "16 cores: KALI_CPUS stays 10" "$KALI_CPUS"  "10"

# Single-core host: everything collapses to 1, never to 0 (0 would mean unlimited).
reset_cpu_stub 1; export_cpu_caps
eq "1 core: NEO4J_CPUS -> 1"  "$NEO4J_CPUS" "1"
eq "1 core: BROKER_CPUS -> 1" "$DOCKER_BROKER_CPUS" "1"

# Undetectable core count -> export nothing, leave the compose defaults alone.
reset_cpu_stub 0; export_cpu_caps
eq "0 cores: NEO4J_CPUS unset" "${NEO4J_CPUS:-unset}" "unset"

# An explicit shell override always wins over the clamp.
reset_cpu_stub 4; NEO4J_CPUS=2; export_cpu_caps
eq "shell override kept" "$NEO4J_CPUS" "2"

# A pin in .env must win too: compose ranks the shell environment ABOVE .env, so
# exporting a clamp here would silently override the operator's pinned value.
reset_cpu_stub 4; printf 'NEO4J_CPUS=3\n' > "$CPU_TMP/.env"; export_cpu_caps
eq ".env pin left to compose" "${NEO4J_CPUS:-unset}" "unset"
eq ".env pin does not block others" "$KALI_CPUS" "4"
rm -f "$CPU_TMP/.env"

# export_resource_caps must apply the CPU clamp even when RAM is undetectable
# (the memory branch bails out early; the CPU branch must not ride along).
reset_cpu_stub 4; STUB_MEM=0; export_resource_caps
eq "CPU clamp survives undetectable RAM" "$KALI_CPUS" "4"
unset "${CPU_VARS[@]}"; STUB_MEM=32000

echo "== setup_zram guards =="
# Default off -> pure no-op (returns 0, does nothing).
unset REDAMON_ENABLE_ZRAM
setup_zram; eq "disabled by default -> no-op" "$?" "0"

# Enabled but stub uname to non-Linux -> skips cleanly.
REDAMON_ENABLE_ZRAM=1
uname() { echo "Darwin"; }
setup_zram; eq "non-Linux host -> skip ok" "$?" "0"
unset -f uname
unset REDAMON_ENABLE_ZRAM

echo
echo "RESULT: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
