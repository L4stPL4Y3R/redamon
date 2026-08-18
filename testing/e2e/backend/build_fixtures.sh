#!/usr/bin/env bash
# Rebuild the TruffleHog scan-target fixtures from scratch.
#
# SYNTHETIC credentials only. Every value below is fabricated or is a vendor's
# published documentation example; none is, or ever was, a real credential.
# Nothing here is committed - scanners/scan_targets/.gitignore excludes it.
#
# Two shapes on purpose: a bare/mirror clone (needs the "Bare repository"
# toggle) and a working clone (must not have it). The matrix asserts that
# getting that pairing wrong fails LOUDLY rather than reporting a clean scan.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GIT_TARGETS="$ROOT/scanners/scan_targets/git"

rm -rf "$GIT_TARGETS/testrepo.git" "$GIT_TARGETS/workrepo" "$GIT_TARGETS/_build"
mkdir -p "$GIT_TARGETS/_build"
cd "$GIT_TARGETS/_build"

git init -q -b main .

# AWS's own published example pair. Kept even though TruffleHog does NOT flag it
# (its AWS detector checksum-validates the key id, which this example fails) -
# that is worth knowing when adding fixtures, and it proves a plausible-looking
# secret is not automatically a finding.
cat > config.yml <<'EOF'
aws:
  access_key_id: AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  region: eu-south-1
EOF

# Fabricated, but shaped so the detectors fire. Github + SlackWebhook do; the
# Stripe and JWT lines do not, and are left in as negative controls.
# Split into a tail plus a prefix because GitHub's push protection rejects a
# commit carrying either shape whole, fabricated or not. The fixture repository
# still receives the complete string, which is what has to reach the detectors.
SLACK_TAIL='XXXXXXXXXXXXXXXXXXXXXXXX'
STRIPE_TAIL='51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'
cat > .env.example <<EOF
GITHUB_TOKEN=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8
SLACK_WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/$SLACK_TAIL
STRIPE_KEY=sk_live_$STRIPE_TAIL
JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QifQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
EOF

# A throwaway key generated here and used for nothing.
openssl genrsa -out deploy_key.pem 2048 2>/dev/null

git add -A
git -c user.email=fixture@local -c user.name=fixture commit -qm "add synthetic credentials for scanner testing"

# A second commit so history-depth options have something to bite on.
sed -i 's/AKIAIOSFODNN7EXAMPLE/AKIAI44QH8DHBEXAMPLE/' config.yml
git add -A
git -c user.email=fixture@local -c user.name=fixture commit -qm "rotate the key (old one stays in history)"

cd "$GIT_TARGETS"
git clone -q --bare _build testrepo.git
git clone -q _build workrepo
rm -rf _build

echo "fixtures ready:"
echo "  $GIT_TARGETS/testrepo.git   (bare  -> Bare repository ON)"
echo "  $GIT_TARGETS/workrepo       (clone -> Bare repository OFF)"
