#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
mkdir -p "$root/.git/hooks"
for name in commit-msg prepare-commit-msg; do
  cp "$root/.githooks/$name" "$root/.git/hooks/$name"
  chmod +x "$root/.git/hooks/$name" "$root/.githooks/$name" "$root/.githooks/strip-injected-coauthor"
done
echo "Installed commit-msg and prepare-commit-msg (strip injected Cursor co-author trailers)."
