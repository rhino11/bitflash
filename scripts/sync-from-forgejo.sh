#!/usr/bin/env bash
# Fast-forward (or merge) GitHub CI mirror main from Forgejo source of truth.
set -euo pipefail

FORGEJO_URL="${FORGEJO_URL:-https://git.bitflash.network/bitflash/bitflash.git}"
REMOTE_NAME="${REMOTE_NAME:-forgejo}"

cd "$(dirname "$0")/.."

if ! git remote get-url "$REMOTE_NAME" >/dev/null 2>&1; then
  git remote add "$REMOTE_NAME" "$FORGEJO_URL"
fi

git fetch "$REMOTE_NAME" --tags --force
git checkout main
git pull --ff-only origin main 2>/dev/null || true

# Prefer fast-forward from forgejo/main; fall back to merge for local CI-only commits.
if git merge-base --is-ancestor HEAD "$REMOTE_NAME/main"; then
  git merge --ff-only "$REMOTE_NAME/main"
elif git merge-base --is-ancestor "$REMOTE_NAME/main" HEAD; then
  echo "Already contains $REMOTE_NAME/main; nothing to sync."
else
  git merge --no-edit "$REMOTE_NAME/main"
fi

echo "HEAD=$(git rev-parse --short HEAD) $(git log -1 --format=%s)"
echo "Push with: git push origin main && git push origin --tags"
