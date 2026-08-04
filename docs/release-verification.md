# Release Verification

Bitflash releases publish binaries and a `SHA256SUMS` file. The checksum file
proves that the file you downloaded matches the file the release page names.
A detached signature, `SHA256SUMS.asc`, proves that the checksum file itself was
signed by a trusted release key.

That gives users two separate checks:

1. `gpg --verify SHA256SUMS.asc SHA256SUMS` checks who signed the checksums.
2. `sha256sum -c SHA256SUMS` checks the binaries against those checksums.

## User Check

From a shell with `curl` or `wget` and `sha256sum`:

```bash
scripts/verify-release.sh latest
```

For a specific release:

```bash
scripts/verify-release.sh v1.2.13
```

For release audits, require the signature:

```bash
scripts/verify-release.sh v1.2.13 --require-signature
```

Older releases may not have `SHA256SUMS.asc`. In that case the script warns and
still checks file integrity. New release audits should use `--require-signature`.

## Maintainer Flow

After building release assets in the repository root:

```bash
scripts/make-release-checksums.sh --sign --local-user RELEASE_KEY_ID
```

Upload all built assets plus:

```text
SHA256SUMS
SHA256SUMS.asc
```

Keep the private signing key offline or on a dedicated release machine. Publish
the public key fingerprint in the release notes and keep using the same key for
future releases unless there is a clearly announced rotation.

## Why This Matters

`SHA256SUMS` alone protects against a broken download, but not against someone
replacing both a binary and the checksum file. Signing `SHA256SUMS` means an
attacker must also have the release signing key to make the replacement verify.

This is not reproducible builds yet. It is the smaller, immediate step that
makes every release asset auditable by users before they run it.
