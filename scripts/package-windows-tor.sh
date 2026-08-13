#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(sed -n 's/^VERSION[[:space:]]*:= *//p' "$ROOT/Makefile" | head -1)}"

TOR_VERSION="${TOR_VERSION:-15.0.19}"
TOR_ARCHIVE_NAME="tor-expert-bundle-windows-x86_64-${TOR_VERSION}.tar.gz"
TOR_URL="${TOR_URL:-https://archive.torproject.org/tor-package-archive/torbrowser/${TOR_VERSION}/${TOR_ARCHIVE_NAME}}"
TOR_SHA256="${TOR_SHA256:-6AC067402C7B4A3DC37887ED3754B3914B67FDC220C966190683E9CCF91ABF0F}"

BUNDLE_DIR="${BUNDLE_DIR:-$ROOT/Bitflash-${VERSION}-windows}"
OUT_ZIP="${OUT_ZIP:-$ROOT/Bitflash-${VERSION}-windows-with-tor.zip}"
CACHE_DIR="${CACHE_DIR:-$ROOT/.cache}"
ARCHIVE="${TOR_ARCHIVE:-$CACHE_DIR/$TOR_ARCHIVE_NAME}"

usage() {
  cat <<EOF
Usage: scripts/package-windows-tor.sh

Creates Bitflash-${VERSION}-windows-with-tor.zip from an existing
Bitflash-${VERSION}-windows/ release directory.

Environment overrides:
  VERSION       Bitflash release version, default read from Makefile
  TOR_VERSION   Tor Expert Bundle version, default ${TOR_VERSION}
  TOR_URL       Download URL, default official Tor archive URL
  TOR_SHA256    Expected archive SHA256
  TOR_ARCHIVE   Use an existing archive instead of downloading
  BUNDLE_DIR    Existing unpacked Windows release directory
  OUT_ZIP       Output zip path
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need sha256sum
need tar
need zip

if [ ! -d "$BUNDLE_DIR" ]; then
  echo "missing Windows release directory: $BUNDLE_DIR" >&2
  echo "run 'make windows' first, or set BUNDLE_DIR" >&2
  exit 1
fi
if [ ! -f "$BUNDLE_DIR/Bitflash.exe" ]; then
  echo "missing Bitflash.exe in $BUNDLE_DIR" >&2
  exit 1
fi
BUNDLE_PARENT="$(cd "$(dirname "$BUNDLE_DIR")" && pwd)"
BUNDLE_NAME="$(basename "$BUNDLE_DIR")"
OUT_PARENT="$(mkdir -p "$(dirname "$OUT_ZIP")" && cd "$(dirname "$OUT_ZIP")" && pwd)"
OUT_NAME="$(basename "$OUT_ZIP")"
OUT_ZIP_ABS="$OUT_PARENT/$OUT_NAME"

mkdir -p "$CACHE_DIR"
if [ ! -f "$ARCHIVE" ]; then
  if command -v curl >/dev/null 2>&1; then
    curl -L --fail --output "$ARCHIVE" "$TOR_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$ARCHIVE" "$TOR_URL"
  else
    echo "missing required command: curl or wget" >&2
    exit 1
  fi
fi

got="$(sha256sum "$ARCHIVE" | awk '{print tolower($1)}')"
want="$(printf '%s' "$TOR_SHA256" | tr 'A-F' 'a-f')"
if [ "$got" != "$want" ]; then
  echo "Tor archive SHA256 mismatch" >&2
  echo "  expected: $want" >&2
  echo "       got: $got" >&2
  exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/bitflash-tor-package.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/extract"
tar -xzf "$ARCHIVE" -C "$tmp/extract"

if [ ! -f "$tmp/extract/tor/tor.exe" ]; then
  echo "Tor archive did not contain tor/tor.exe" >&2
  exit 1
fi

rm -rf "$BUNDLE_DIR/tor"
mkdir -p "$BUNDLE_DIR/tor"
cp -R "$tmp/extract/tor/." "$BUNDLE_DIR/tor/"
if [ -d "$tmp/extract/docs" ]; then
  mkdir -p "$BUNDLE_DIR/tor/docs"
  cp -R "$tmp/extract/docs/." "$BUNDLE_DIR/tor/docs/"
fi
if [ -d "$tmp/extract/data" ]; then
  mkdir -p "$BUNDLE_DIR/tor/data-defaults"
  cp -R "$tmp/extract/data/." "$BUNDLE_DIR/tor/data-defaults/"
fi

cat > "$BUNDLE_DIR/TOR-EXPERT-BUNDLE.txt" <<EOF
Bitflash managed Tor bundle

This Windows package includes the Tor Expert Bundle so -managedtor can start
Tor without requiring a separate Tor install.

Tor Expert Bundle: ${TOR_VERSION}
Archive URL: ${TOR_URL}
Archive SHA256: ${TOR_SHA256}

Bitflash uses tor/tor.exe from this package. Runtime state, hidden-service keys,
and control authentication cookies are written under the user's Bitflash data
directory, not inside this release directory.
EOF

rm -f "$OUT_ZIP_ABS"
(
  cd "$BUNDLE_PARENT"
  zip -qr "$OUT_ZIP_ABS" "$BUNDLE_NAME"
)

echo "Bundled Tor Expert Bundle ${TOR_VERSION}"
echo "Built: $OUT_ZIP_ABS"
