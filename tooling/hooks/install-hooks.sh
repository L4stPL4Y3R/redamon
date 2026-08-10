#!/usr/bin/env bash
#
# install-hooks.sh - propagate the tracked hooks in hooks/ into .git/hooks/.
#
# .git/hooks/ is not committed and does not survive a clone, so every clone runs
# this once:  ./tooling/hooks/install-hooks.sh
#
# Idempotent. An existing hook we did not write is backed up to <hook>.local.bak
# rather than clobbered.
#
set -u

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd))"
SRC="$REPO_ROOT/tooling/hooks"
DEST="$(git -C "$REPO_ROOT" rev-parse --git-path hooks 2>/dev/null || echo "$REPO_ROOT/.git/hooks")"
MARKER="tooling/hooks/install-hooks.sh"     # string every managed hook contains, for ownership detection

mkdir -p "$DEST"
installed=0
for src in "$SRC"/*; do
  name="$(basename "$src")"
  case "$name" in
    install-hooks.sh|*.md) continue ;;      # not themselves hooks
  esac
  dest="$DEST/$name"
  if [ -f "$dest" ] && ! grep -qF "$MARKER" "$dest" 2>/dev/null; then
    cp "$dest" "$dest.local.bak"
    echo "backed up existing $name -> $name.local.bak"
  fi
  cp "$src" "$dest"
  chmod +x "$dest"
  echo "installed: $name -> ${dest}"
  installed=$((installed+1))
done

echo "done: $installed hook(s) installed into $DEST"
