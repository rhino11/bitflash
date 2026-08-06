#!/usr/bin/env bash
set -euo pipefail

# Verifies a Bitflash release: the checksum file's signature against a pinned
# key, then the assets against the checksums.
#
# The signing key is embedded below, not fetched. That is the whole point of a
# pinned key: the trust anchor ships with this script (in git), so it does not
# depend on the same server that serves the release. A server that is
# compromised can swap the binaries and the checksums, but it cannot forge a
# signature by this key.

host="https://releases.bitflash.network"
require_signature=0

# The Bitflash release signing key. Verification requires this exact key --
# gpg's own "good signature" is not enough, because a good signature by *some*
# key proves nothing. See issue #138.
RELEASE_KEY_FP="910A2B4CCA879E81FB4B2AEA1D4A53D3B78AA4B8"
read -r -d '' RELEASE_KEY <<'KEY' || true
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEanSOmRYJKwYBBAHaRw8BAQdAXj24i2BYUcAmOpoXwjE4ZTynHsifCZ+niwQK
HqO0nMa0UEJpdGZsYXNoIFJlbGVhc2VzIChiaXRmbGFzaC5uZXR3b3JrIHJlbGVh
c2Ugc2lnbmluZykgPHJlbGVhc2VzQGJpdGZsYXNoLm5ldHdvcms+iJAEExYKADgW
IQSRCitMyoeegftLKuodSlPTt4qkuAUCanSOmQIbAwULCQgHAgYVCgkICwIEFgID
AQIeAQIXgAAKCRAdSlPTt4qkuIi9AP96X3OcstiCTTgKOr16Vhds3LyuZ19q3Apq
4KAcNuOUMAD+NqgJ1CqkLGPXfZLCtYBCRHXNYWxMMEk+ViLcRtdLMg4=
=mxic
-----END PGP PUBLIC KEY BLOCK-----
KEY

usage() {
  cat <<'EOF'
Usage: scripts/verify-release.sh [tag|latest] [--require-signature]

Downloads the release checksum file and every asset named in it, then verifies:
  1. SHA256SUMS.asc against SHA256SUMS, requiring the pinned Bitflash release
     key (fingerprint 910A 2B4C CA87 9E81 FB4B 2AEA 1D4A 53D3 B78A A4B8).
  2. SHA256SUMS against the downloaded assets.

Releases from before signing was introduced ship only SHA256SUMS; without
--require-signature those are checked for integrity and reported as unsigned.
EOF
}

tag="${1:-latest}"
for arg in "${@:2}"; do
  case "$arg" in
    --require-signature) require_signature=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $arg" >&2; usage >&2; exit 2 ;;
  esac
done
if [ "$tag" = "-h" ] || [ "$tag" = "--help" ]; then usage; exit 0; fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }
need sed
need awk

if command -v sha256sum >/dev/null 2>&1; then
  sha_check=(sha256sum -c SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  sha_check=(shasum -a 256 -c SHA256SUMS)
else
  echo "missing required command: sha256sum or shasum" >&2; exit 1
fi

download() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -q "$1" -O "$2"
  else echo "missing required command: curl or wget" >&2; exit 1; fi
}

if [ "$tag" = "latest" ]; then
  tag="$(download "$host/latest.txt" - 2>/dev/null | tr -d '[:space:]' || true)"
  [ -n "$tag" ] || { echo "could not resolve the latest release tag from $host/latest.txt" >&2; exit 1; }
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/bitflash-release-verify.XXXXXX")"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

base_url="$host/$tag"
echo "Verifying Bitflash $tag"
echo "Working directory: $workdir"
cd "$workdir"

download "$base_url/SHA256SUMS" SHA256SUMS

if download "$base_url/SHA256SUMS.asc" SHA256SUMS.asc 2>/dev/null; then
  need gpg
  # Verify in a throwaway keyring holding ONLY the pinned key, and require that
  # the signature validates against it with the pinned fingerprint. This is the
  # difference between "signed" and "signed by Bitflash".
  keyring="$workdir/keyring"
  mkdir -p "$keyring"; chmod 700 "$keyring"
  printf '%s\n' "$RELEASE_KEY" | GNUPGHOME="$keyring" gpg --batch --quiet --import 2>/dev/null
  status="$(GNUPGHOME="$keyring" gpg --batch --status-fd=1 --verify SHA256SUMS.asc SHA256SUMS 2>/dev/null || true)"
  if printf '%s' "$status" | grep -q "VALIDSIG.*$RELEASE_KEY_FP"; then
    echo "Signature OK -- signed by the pinned Bitflash release key"
  else
    echo "SIGNATURE REJECTED: not a valid signature by the pinned release key" >&2
    echo "  expected key: $RELEASE_KEY_FP" >&2
    exit 1
  fi
else
  if [ "$require_signature" -eq 1 ]; then
    echo "release does not publish SHA256SUMS.asc" >&2; exit 1
  fi
  echo "WARNING: no SHA256SUMS.asc found; checking hashes only (unsigned release)"
fi

awk '{print $2}' SHA256SUMS | while IFS= read -r file; do
  file="${file#\*}"; file="${file#./}"
  [ -z "$file" ] && continue
  case "$file" in */*|..*) echo "refusing unexpected checksum path: $file" >&2; exit 1 ;; esac
  echo "Downloading $file"
  download "$base_url/$file" "$file"
done

"${sha_check[@]}"
echo "Release assets OK"
