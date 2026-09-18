#!/usr/bin/env bash
# Fast-forward (or merge) GitHub CI mirror main from Forgejo source of truth.
set -euo pipefail

FORGEJO_URL="${FORGEJO_URL:-https://git.bitflash.network/bitflash/bitflash.git}"
REMOTE_NAME="${REMOTE_NAME:-forgejo}"

cd "$(dirname "$0")/.."

if ! git remote get-url "$REMOTE_NAME" >/dev/null 2>&1; then
  git remote add "$REMOTE_NAME" "$FORGEJO_URL"
fi

# Forgejo is SoT for release tags; force updates when tags move upstream.
git fetch "$REMOTE_NAME" --tags --force
git checkout main
git pull --ff-only origin main 2>/dev/null || true

# Prefer fast-forward from forgejo/main; fall back to merge for local CI-only commits.
if git merge-base --is-ancestor HEAD "$REMOTE_NAME/main"; then
  git merge --ff-only "$REMOTE_NAME/main"
elif git merge-base --is-ancestor "$REMOTE_NAME/main" HEAD; then
  echo "Already contains $REMOTE_NAME/main; nothing to sync."
else
  # Diverged histories (CI overlay on GitHub vs Forgejo SoT): prefer Forgejo on
  # content conflicts, then restore the mirror-only `make ci` target if dropped.
  git merge -X theirs --no-edit "$REMOTE_NAME/main"
fi

if ! grep -qE '^ci:' Makefile; then
  # Keep local parity with .github/workflows/ci.yml (Linux job).
  python3 - <<'PY'
from pathlib import Path
p = Path("Makefile")
text = p.read_text(encoding="utf-8")
needle = "fuzz-script-smoke: deps-linux\n\t$(MAKE) -C src -f Makefile fuzz-script-smoke\n"
block = (
    needle
    + "\n"
    + "# Local parity with .github/workflows/ci.yml (Linux job). Run before opening a PR.\n"
    + "ci: deps-linux\n"
    + "\t$(MAKE) tests\n"
    + "\tpython3 tests/scripts/test_bitflash_tools.py\n"
    + "\t$(MAKE) fuzz-net-message-smoke\n"
    + "\t$(MAKE) fuzz-script-smoke\n"
)
if needle not in text:
    raise SystemExit("Makefile missing fuzz-script-smoke anchor; cannot restore ci target")
if "ci: deps-linux" not in text:
    text = text.replace(needle, block, 1)
    text = text.replace(
        "fuzz-net-message-smoke fuzz-script-smoke checksums",
        "fuzz-net-message-smoke fuzz-script-smoke ci checksums",
        1,
    )
    p.write_text(text, encoding="utf-8")
    print("Restored Makefile ci: target")
PY
  if git diff --quiet -- Makefile; then
    :
  else
    git add Makefile
    git commit -m "ci: restore make ci target after Forgejo sync"
  fi
fi

echo "HEAD=$(git rev-parse --short HEAD) $(git log -1 --format=%s)"
echo "Push with: git push origin main && git push origin --tags --force"
