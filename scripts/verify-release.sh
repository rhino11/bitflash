#!/usr/bin/env bash
set -euo pipefail

repo="Bitflash-sh/bitflash"
tag="${1:-latest}"
require_signature=0

usage() {
  cat <<'EOF'
Usage: scripts/verify-release.sh [tag|latest] [--require-signature]

Downloads the release checksum file and every asset named in it, then verifies:
  1. SHA256SUMS.asc, if present, against SHA256SUMS with gpg.
  2. SHA256SUMS against the downloaded assets.

Use --require-signature for release audits. Without it, older releases that
ship only SHA256SUMS are checked for integrity and reported as unsigned.
EOF
}

for arg in "${@:2}"; do
  case "$arg" in
    --require-signature) require_signature=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$tag" = "-h" ] || [ "$tag" = "--help" ]; then
  usage
  exit 0
fi

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need sed
need awk

if command -v sha256sum >/dev/null 2>&1; then
  sha_check=(sha256sum -c SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  sha_check=(shasum -a 256 -c SHA256SUMS)
else
  echo "missing required command: sha256sum or shasum" >&2
  exit 1
fi

download() {
  local url="$1"
  local out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$out"
  else
    echo "missing required command: curl or wget" >&2
    exit 1
  fi
}

if [ "$tag" = "latest" ]; then
  tag="$(download "https://api.github.com/repos/$repo/releases/latest" - |
    sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
    head -1)"
  if [ -z "$tag" ]; then
    echo "could not resolve latest release tag" >&2
    exit 1
  fi
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/bitflash-release-verify.XXXXXX")"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

base_url="https://github.com/$repo/releases/download/$tag"

echo "Verifying Bitflash $tag"
echo "Working directory: $workdir"
cd "$workdir"

download "$base_url/SHA256SUMS" SHA256SUMS

if download "$base_url/SHA256SUMS.asc" SHA256SUMS.asc 2>/dev/null; then
  if ! command -v gpg >/dev/null 2>&1; then
    echo "SHA256SUMS.asc exists, but gpg is not installed" >&2
    exit 1
  fi
  gpg --verify SHA256SUMS.asc SHA256SUMS
  echo "Signature OK"
else
  if [ "$require_signature" -eq 1 ]; then
    echo "release does not publish SHA256SUMS.asc" >&2
    exit 1
  fi
  echo "WARNING: no SHA256SUMS.asc found; checking hashes only"
fi

awk '{print $2}' SHA256SUMS | while IFS= read -r file; do
  file="${file#\*}"
  file="${file#./}"
  [ -z "$file" ] && continue
  case "$file" in
    */*|..*) echo "refusing unexpected checksum path: $file" >&2; exit 1 ;;
  esac
  echo "Downloading $file"
  download "$base_url/$file" "$file"
done

"${sha_check[@]}"
echo "Release assets OK"
