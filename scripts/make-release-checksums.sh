#!/usr/bin/env bash
set -euo pipefail

sign=0
key=""

usage() {
  cat <<'EOF'
Usage: scripts/make-release-checksums.sh [--sign] [--local-user KEYID]

Creates SHA256SUMS for release assets in the current directory:
  Bitflash-*-windows.zip
  Bitflash-*-x86_64.AppImage
  bitflash-node-*-x86_64

With --sign, also creates SHA256SUMS.asc as a detached ASCII-armored GPG
signature. Upload both files with the release assets.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --sign) sign=1 ;;
    --local-user)
      [ "$#" -ge 2 ] || { echo "--local-user needs a key id" >&2; exit 2; }
      key="$2"
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if command -v sha256sum >/dev/null 2>&1; then
  sha_cmd=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  sha_cmd=(shasum -a 256)
else
  echo "missing required command: sha256sum or shasum" >&2
  exit 1
fi

assets=()
for pattern in \
  "Bitflash-*-windows.zip" \
  "Bitflash-*-x86_64.AppImage" \
  "bitflash-node-*-x86_64"
do
  for file in $pattern; do
    [ -e "$file" ] || continue
    assets+=("$file")
  done
done

if [ "${#assets[@]}" -eq 0 ]; then
  echo "no release assets found in $(pwd)" >&2
  exit 1
fi

printf '%s\n' "${assets[@]}" | LC_ALL=C sort | while IFS= read -r file; do
  "${sha_cmd[@]}" "$file"
done > SHA256SUMS

echo "Wrote SHA256SUMS"

if [ "$sign" -eq 1 ]; then
  if ! command -v gpg >/dev/null 2>&1; then
    echo "missing required command: gpg" >&2
    exit 1
  fi
  gpg_args=(--armor --detach-sign --output SHA256SUMS.asc)
  if [ -n "$key" ]; then
    gpg_args+=(--local-user "$key")
  fi
  gpg "${gpg_args[@]}" SHA256SUMS
  echo "Wrote SHA256SUMS.asc"
fi
