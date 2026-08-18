#!/usr/bin/env bash
# =============================================================================
# Structural tests for the GVM stack's compose wiring (issue #174).
#
# Two defects lived here, and both are invisible to a first `up`:
#
#   1. gvm-postgres-init was a SIBLING one-shot that deleted
#      /var/run/postgresql/.s.PGSQL.5432 from the volume it shared with a running
#      Postgres. On a repeat `docker compose up -d` compose leaves an already-
#      running service alone but still re-runs an exited one-shot, so it deleted
#      the LIVE socket: gvmd lost its database and crash-looped for hours while
#      Postgres still reported healthy. The cleanup now lives inside
#      gvm-postgres' own entrypoint, where it cannot race anything.
#
#   2. The feed loaders had no restart policy, so ONE SIGKILL (exit 137) left
#      gvm-ospd - gated on the loader via service_completed_successfully - never
#      created at all. The stack then had no scanner, and every scan task sat at
#      0% until its 4h timeout.
#
# Hermetic: `docker compose config` only, no daemon needed for the parse (the
# suite self-skips if compose or python3 is unavailable). The live behavioural
# proof is tests/gvm_socket_race_live.sh.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP  python3 unavailable (GVM compose structure)"
    exit 0
fi

echo "== the stale-lock cleanup cannot race a live Postgres =="

# Parsed from the source file, not from `docker compose config`: the point is
# what ships, and it must hold whether or not a daemon is reachable.
read -r -d '' PY <<'PYEOF'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
services = doc.get("services") or {}
mode = sys.argv[2]

def entrypoint(name):
    ep = (services.get(name) or {}).get("entrypoint") or ""
    return ep if isinstance(ep, str) else " ".join(str(x) for x in ep)

if mode == "socket-deleters":
    # Every service that both mounts the shared psql socket volume AND removes
    # the socket file. Only gvm-postgres itself may do that.
    out = []
    for name, svc in services.items():
        vols = " ".join(str(v) for v in (svc.get("volumes") or []))
        if "gvm_psql_socket" not in vols:
            continue
        body = entrypoint(name) + " " + " ".join(str(c) for c in (svc.get("command") or []))
        if ".s.PGSQL.5432" in body and "rm " in body:
            out.append(name)
    print(" ".join(sorted(out)))
elif mode == "pg-entrypoint":
    print(entrypoint("gvm-postgres").replace("\n", " "))
elif mode == "init-present":
    print("yes" if "gvm-postgres-init" in services else "no")
elif mode == "loader-restarts":
    # Services capped by the shared GVM_DATA_MEM knob = the one-shot feed loaders.
    out = []
    for name, svc in sorted(services.items()):
        if "GVM_DATA_MEM" in str(svc.get("mem_limit", "")):
            out.append("%s=%s" % (name, svc.get("restart", "<none>")))
    print(" ".join(out))
elif mode == "loader-count":
    print(sum(1 for svc in services.values() if "GVM_DATA_MEM" in str(svc.get("mem_limit", ""))))
elif mode == "ospd-gate":
    dep = (services.get("gvm-ospd") or {}).get("depends_on") or {}
    print(dep.get("gvm-vt", {}).get("condition", "<none>"))
PYEOF

run_py() { python3 -c "$PY" "$COMPOSE_FILE" "$1" 2>/dev/null; }

if ! python3 -c "import yaml" >/dev/null 2>&1; then
    echo "  SKIP  pyyaml unavailable (GVM compose structure)"
    exit 0
fi

eq "no sibling container deletes the shared Postgres socket" \
   "$(run_py socket-deleters)" "gvm-postgres"

eq "the one-shot gvm-postgres-init is gone" "$(run_py init-present)" "no"

pg_ep="$(run_py pg-entrypoint)"
case "$pg_ep" in
    *".s.PGSQL.5432"*) ok "gvm-postgres cleans its own stale socket at startup" ;;
    *) bad "gvm-postgres cleans its own stale socket at startup" "$pg_ep" "an rm of .s.PGSQL.5432" ;;
esac
case "$pg_ep" in
    *"exec /usr/local/bin/entrypoint"*) ok "gvm-postgres still hands off to the image entrypoint" ;;
    *) bad "gvm-postgres still hands off to the image entrypoint" "$pg_ep" "exec /usr/local/bin/entrypoint" ;;
esac
# The glob keeps working when the image's Postgres major version moves on.
case "$pg_ep" in
    *"/var/lib/postgresql/*/main/postmaster.pid"*) ok "the postmaster.pid path is version-agnostic" ;;
    *) bad "the postmaster.pid path is version-agnostic" "$pg_ep" "a /*/main/ glob" ;;
esac

echo "== a killed feed loader retries instead of removing the scanner =="

restarts="$(run_py loader-restarts)"
missing=""
for entry in $restarts; do
    case "$entry" in
        *"=on-failure"*) ;;
        *) missing="$missing ${entry%%=*}" ;;
    esac
done
if [[ -z "$missing" && -n "$restarts" ]]; then
    ok "every GVM feed loader restarts on failure"
else
    bad "every GVM feed loader restarts on failure" "no policy:${missing:- <none parsed>}" "on-failure"
fi

# gvm-ospd is gated on the loader COMPLETING, which is exactly why a loader that
# dies without retrying takes the scanner out of the stack.
eq "gvm-ospd is gated on the VT loader completing" "$(run_py ospd-gate)" "service_completed_successfully"

echo "== the governor's loader count matches the compose file =="

# GVM_DATA_MEM caps N containers from ONE variable, so redamon.sh divides the
# group share by that count. If the two drift, every loader is mis-sized.
declared="$(grep -E '^_GVM_DATA_CONTAINERS=' "$REPO_ROOT/redamon.sh" | head -1 | cut -d= -f2)"
eq "_GVM_DATA_CONTAINERS matches the capped services" "$declared" "$(run_py loader-count)"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
