#!/usr/bin/env bash
# =============================================================================
# T3 — deploy source-mutation integrity + app-config passthrough.
#
# HISTORY: this suite used to verify that deploy.sh's deploy-time `git apply`
# patches were sha256-pinned and fatal-on-failure. That mechanism is GONE
# (d2d743fb): the last patch, which injected NEXT_PUBLIC_AGENT_WS_URL into
# webapp/Dockerfile, was folded into the base Dockerfile as a first-class build
# ARG. The suite kept asserting a pinned sha for a deleted file and had been red
# ever since.
#
# The invariant worth guarding is the STRONGER one that replaced it: deploy.sh
# must never mutate repo source on the host at all. A deploy-time edit dirties
# the checkout, which breaks `redamon.sh update`'s `git pull --ff-only` on the
# next run — the exact failure the patch removal was meant to end.
#
# Second half: operator app-config that deploy.sh must forward. redamon.sh reads
# these from the server-side .env, so a knob missing from ANY of the three
# plumbing points (defaults / deploy.env export list / seed) is silently inert
# on a deployed host while working perfectly in a local install.
#
# Run: bash tests/deploy_patch_integrity_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$REPO_ROOT/tooling/deploy/single-host/deploy.sh"
DEPLOY_ENV_EXAMPLE="$REPO_ROOT/tooling/deploy/single-host/.env.example"
COMPOSE="$REPO_ROOT/docker-compose.yml"
PATCH_DIR="$REPO_ROOT/tooling/deploy/single-host/patches"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

echo "== the deploy-time patch mechanism is gone, not merely unused =="
[ ! -d "$PATCH_DIR" ] && pass "tooling/deploy/single-host/patches/ removed" || fail "patches/ is back (deploy must not mutate source)"
if grep -qE 'apply_one|git apply|patch -p[0-9]' "$DEPLOY"; then
  fail "deploy.sh applies a source patch on the host (dirties the checkout, breaks pull --ff-only)"
else
  pass "deploy.sh never patches repo source"
fi
# `sed -i` against the app .env is legitimate (that is the seed() helper); against
# tracked source is not. Guard the tracked paths specifically.
if grep -qE "sed -i[^\n]*(webapp/|agentic/|recon/|docker-compose\.yml)" "$DEPLOY"; then
  fail "deploy.sh sed -i's tracked source"
else
  pass "no in-place edit of tracked source"
fi

echo "== the folded patch is a first-class build ARG instead =="
if grep -q '^ARG NEXT_PUBLIC_AGENT_WS_URL' "$REPO_ROOT/webapp/Dockerfile" \
   && grep -q '^ENV NEXT_PUBLIC_AGENT_WS_URL' "$REPO_ROOT/webapp/Dockerfile"; then
  pass "webapp/Dockerfile declares the WS-URL ARG+ENV"
else
  fail "webapp/Dockerfile lost the NEXT_PUBLIC_AGENT_WS_URL ARG (prod builds would bake localhost:8090)"
fi
if grep -q 'NEXT_PUBLIC_AGENT_WS_URL' "$REPO_ROOT/tooling/deploy/single-host/compose/docker-compose.prod.yml"; then
  pass "prod overlay passes the WS URL as a build arg"
else
  fail "prod overlay no longer supplies NEXT_PUBLIC_AGENT_WS_URL"
fi

echo "== operator app-config reaches the server .env (all three plumbing points) =="
# Every key here is read by the app from the server-side .env. deploy.sh needs it
# (1) defaulted so `set -u` cannot kill the run, (2) in build_deploy_env's export
# list so it crosses the SSH boundary, (3) seeded into the app .env on the host.
for k in NVD_API_KEY TUNNELS_ENABLED \
         OSV_DB_AUTO_REFRESH OSV_DB_ECOSYSTEMS OSV_DB_TTL_SECONDS OSV_DB_REFRESH_TIMEOUT; do
  miss=""
  # Defaults are packed several per line (`: "${A:=}"; : "${B:=}"`), so this
  # cannot anchor at ^.
  grep -qE ": \"\\\$\{${k}:=" "$DEPLOY"         || miss="${miss} default"
  awk -v k="$k" '/^build_deploy_env\(\)/,/^}/ { if ($0 ~ k) found=1 } END { exit !found }' "$DEPLOY" \
                                                || miss="${miss} deploy.env-export"
  grep -qE "^seed ${k} " "$DEPLOY"              || miss="${miss} seed"
  [ -z "$miss" ] && pass "$k plumbed (default + export + seed)" || fail "$k missing:${miss}"
done

echo "== the OSV knobs are documented where an operator will look =="
for k in OSV_DB_AUTO_REFRESH OSV_DB_ECOSYSTEMS; do
  grep -q "$k" "$DEPLOY_ENV_EXAMPLE" && pass "$k in deploy .env.example" || fail "$k undocumented in deploy .env.example"
done

echo "== orchestrator knobs are wired in compose (it has NO env_file) =="
# recon-orchestrator gets a variable ONLY if it is listed in its compose
# environment block. A knob documented in .env.example but absent here is inert:
# the operator sets it, nothing happens, and nothing says why.
for k in OSV_DB_AUTO_REFRESH OSV_DB_ECOSYSTEMS OSV_DB_TTL_SECONDS OSV_DB_REFRESH_TIMEOUT \
         SUPPLY_CHAIN_ANALYZER_MEM SUPPLY_CHAIN_ANALYZER_PIDS SUPPLY_CHAIN_ANALYZER_NANOCPUS; do
  grep -qE "^ +${k}: \\\$\{${k}" "$COMPOSE" && pass "$k wired into compose" || fail "$k not wired into compose (inert in .env)"
done

echo
echo "-----------------------------------------"
printf 'Deploy source-integrity suite: \033[0;32m%d passed\033[0m, ' "$PASS"
if [[ $FAIL -gt 0 ]]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; else printf '%d failed\n' "$FAIL"; fi
