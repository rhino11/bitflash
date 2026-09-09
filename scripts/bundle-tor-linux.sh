#!/usr/bin/env bash
set -euo pipefail

# Copies the Linux Tor Expert Bundle into <dest>/tor so an AppImage (or any
# self-contained Linux build) can start managed Tor and reach it through
# pluggable transports without a system Tor install. The bundle ships a single
# lyrebird binary that serves both obfs4 and snowflake, which is exactly what
# src/tor.cpp looks for under tor/pluggable_transports/.
#
# Usage: scripts/bundle-tor-linux.sh <dest-dir>
#   creates <dest-dir>/tor/{tor, pluggable_transports/lyrebird, ...}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEST="${1:-}"
if [ -z "$DEST" ]; then
  echo "usage: scripts/bundle-tor-linux.sh <dest-dir>" >&2
  exit 2
fi

TOR_VERSION="${TOR_VERSION:-15.0.19}"
TOR_ARCHIVE_NAME="tor-expert-bundle-linux-x86_64-${TOR_VERSION}.tar.gz"
TOR_URL="${TOR_URL:-https://archive.torproject.org/tor-package-archive/torbrowser/${TOR_VERSION}/${TOR_ARCHIVE_NAME}}"
TOR_SHA256="${TOR_SHA256:-5a8f19f5f119b5fa2a8fd799a3a532e3236ad36164241800d6302e32f0e1c2a9}"
TOR_ASC_URL="${TOR_ASC_URL:-${TOR_URL}.asc}"
TOR_SIGNING_KEY_FINGERPRINT="${TOR_SIGNING_KEY_FINGERPRINT:-EF6E286DDA85EA2A4BA7DE684E2C6E8793298290}"
TOR_VERIFY_GPG="${TOR_VERIFY_GPG:-auto}"
CACHE_DIR="${CACHE_DIR:-$ROOT/.cache}"
ARCHIVE="${TOR_ARCHIVE:-$CACHE_DIR/$TOR_ARCHIVE_NAME}"
ASC_FILE="${TOR_ASC:-$ARCHIVE.asc}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need sha256sum
need tar

download() {
  local url="$1"
  local out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -L --fail --output "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$out" "$url"
  else
    echo "missing required command: curl or wget" >&2
    exit 1
  fi
}

case "$TOR_VERIFY_GPG" in
  auto|required|off) ;;
  *) echo "TOR_VERIFY_GPG must be auto, required, or off" >&2; exit 2 ;;
esac

mkdir -p "$CACHE_DIR"
if [ ! -f "$ARCHIVE" ]; then
  download "$TOR_URL" "$ARCHIVE"
fi

got="$(sha256sum "$ARCHIVE" | awk '{print tolower($1)}')"
want="$(printf '%s' "$TOR_SHA256" | tr 'A-F' 'a-f')"
if [ "$got" != "$want" ]; then
  echo "Tor archive SHA256 mismatch" >&2
  echo "  expected: $want" >&2
  echo "       got: $got" >&2
  exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/bitflash-tor-linux.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

if [ "$TOR_VERIFY_GPG" != "off" ]; then
  if command -v gpg >/dev/null 2>&1; then
    if [ ! -f "$ASC_FILE" ]; then
      download "$TOR_ASC_URL" "$ASC_FILE"
    fi
    gnupg_home="$tmp/gnupg"
    mkdir -p "$gnupg_home"
    chmod 0700 "$gnupg_home"
    gpg --homedir "$gnupg_home" --batch --auto-key-locate nodefault,wkd,keyserver \
      --locate-keys torbrowser@torproject.org >/dev/null 2>&1 || {
        if [ "$TOR_VERIFY_GPG" = "required" ]; then
          echo "could not import Tor Browser Developers signing key" >&2
          exit 1
        fi
        echo "WARNING: skipped Tor GPG signature verification; signing key import failed" >&2
      }
    if gpg --homedir "$gnupg_home" --batch --with-colons --fingerprint "$TOR_SIGNING_KEY_FINGERPRINT" \
        2>/dev/null | grep -q "^fpr:::::::::${TOR_SIGNING_KEY_FINGERPRINT}:"; then
      gpg --homedir "$gnupg_home" --batch --verify "$ASC_FILE" "$ARCHIVE" >/dev/null 2>&1 || {
        echo "Tor archive GPG signature verification failed" >&2
        exit 1
      }
      echo "Tor archive GPG signature verified against ${TOR_SIGNING_KEY_FINGERPRINT}"
    elif [ "$TOR_VERIFY_GPG" = "required" ]; then
      echo "Tor signing key fingerprint mismatch" >&2
      exit 1
    else
      echo "WARNING: skipped Tor GPG signature verification; signing key fingerprint was not available" >&2
    fi
  elif [ "$TOR_VERIFY_GPG" = "required" ]; then
    echo "missing required command for TOR_VERIFY_GPG=required: gpg" >&2
    exit 1
  else
    echo "WARNING: gpg not found; relying on pinned SHA256 only" >&2
  fi
fi

mkdir -p "$tmp/extract"
tar -xzf "$ARCHIVE" -C "$tmp/extract"

if [ ! -f "$tmp/extract/tor/tor" ]; then
  echo "Tor archive did not contain tor/tor" >&2
  exit 1
fi
if [ ! -f "$tmp/extract/tor/pluggable_transports/lyrebird" ]; then
  echo "Tor archive did not contain tor/pluggable_transports/lyrebird" >&2
  exit 1
fi

mkdir -p "$DEST"
rm -rf "$DEST/tor"
mkdir -p "$DEST/tor"
cp -R "$tmp/extract/tor/." "$DEST/tor/"
if [ -d "$tmp/extract/data" ]; then
  mkdir -p "$DEST/tor/data-defaults"
  cp -R "$tmp/extract/data/." "$DEST/tor/data-defaults/"
fi

# access(X_OK) is how src/tor.cpp locates tor and the transports, so the copied
# binaries must stay executable.
chmod 0755 "$DEST/tor/tor" 2>/dev/null || true
if [ -d "$DEST/tor/pluggable_transports" ]; then
  find "$DEST/tor/pluggable_transports" -maxdepth 1 -type f \
    \( -name lyrebird -o -name conjure-client -o -name obfs4proxy -o -name snowflake-client \) \
    -exec chmod 0755 {} + 2>/dev/null || true
fi

echo "Bundled Tor Expert Bundle ${TOR_VERSION} (linux) into $DEST/tor"
