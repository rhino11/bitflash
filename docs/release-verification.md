# Release Verification

Bitflash releases publish binaries and a `SHA256SUMS` file. The checksum file
proves that the file you downloaded matches the file the release page names.
A detached signature, `SHA256SUMS.asc`, proves that the checksum file itself was
signed by the Bitflash release key.

That gives users two separate checks:

1. `gpg --verify SHA256SUMS.asc SHA256SUMS` — who signed the checksums.
2. `sha256sum -c SHA256SUMS` — the binaries against those checksums.

But the first check is only worth something if you require a **specific** key.
A good signature by *some* key proves nothing; anyone can make one.

## The release signing key

```text
fingerprint  910A 2B4C CA87 9E81 FB4B  2AEA 1D4A 53D3 B78A A4B8
uid          Bitflash Releases (bitflash.network release signing)
             <releases@bitflash.network>
```

The public key is published at
`https://releases.bitflash.network/bitflash-release-key.asc` and embedded in
`scripts/verify-release.sh`, so the tool's trust anchor lives in this
repository rather than on the server it verifies.

## User check

From a shell with `curl` or `wget`, `sha256sum` and `gpg`:

```bash
scripts/verify-release.sh latest
```

The public release host should expose latest-file aliases for convenience:

```text
https://releases.bitflash.network/SHA256SUMS
https://releases.bitflash.network/SHA256SUMS.asc
```

Those aliases must point at the current versioned directory. They do not replace
signature verification; they only make the common manual path shorter.

For a specific release:

```bash
scripts/verify-release.sh v1.2.15
```

The script downloads the release, imports the pinned key into a throwaway
keyring, and **refuses anything that is not a valid signature by the key above**
before checking the hashes. Releases from before signing was introduced ship
only `SHA256SUMS`; without `--require-signature` those are checked for integrity
and reported as unsigned.

By hand, if you would rather not run the script:

```bash
curl -O https://releases.bitflash.network/bitflash-release-key.asc
gpg --import bitflash-release-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS   # must name the fingerprint above
sha256sum -c SHA256SUMS
```

## Maintainer flow

The signing key lives on a dedicated location, not in the build tree. After
building the release assets in the repository root, write and sign the
checksums:

```bash
sha256sum Bitflash-*.zip Bitflash-*.AppImage bitflash-node-* > SHA256SUMS
gpg --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
```

Publish, alongside the assets, `SHA256SUMS` and `SHA256SUMS.asc`, and update
`latest.txt` on the releases host to the new tag. Keep using the same key; if it
is ever rotated, announce the new fingerprint clearly and update the embedded
key in `verify-release.sh`.

For Windows releases with managed Tor built in, run `make windows-tor`. It
creates `Bitflash-*-windows-with-tor.zip` by downloading the Tor Expert Bundle,
checking the pinned SHA256 in `scripts/package-windows-tor.sh`, and placing
`tor/tor.exe` next to `Bitflash.exe`. Include that zip in `SHA256SUMS` like any
other release asset.

## Why this matters

`SHA256SUMS` alone protects against a broken download, but not against someone
replacing both a binary and the checksum file. Signing `SHA256SUMS`, and
requiring a pinned key, means an attacker must also hold the release signing key
to make the replacement verify. Serving from bitflash.network makes this the
guarantee that matters: without a pinned key, "trust the site" is the only
thing standing behind a download.

This is not reproducible builds yet. It is the smaller, immediate step that
makes every release asset auditable before anyone runs it.
