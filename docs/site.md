# Public Site Contract

The public Bitflash sites are generated from this repository. If a deployed
page and the source disagree, the deployed page is stale.

## Canonical Navigation

Every public page should use the same top navigation:

| label | target |
|---|---|
| home | `https://bitflash.network/` |
| code | `https://git.bitflash.network/bitflash/bitflash` |
| docs | `https://docs.bitflash.network/` |
| downloads | `https://releases.bitflash.network/` |
| explorer | `https://explorer.bitflash.network/` |
| status | `https://status.bitflash.network/` |

The `code` link intentionally points at the repository, not the Forgejo
instance root. A visitor choosing "code" wants the source tree.

## Documentation Pages To Publish

The docs index should expose these source files:

| page | source | why it matters |
|---|---|---|
| Manual | `README.md` | run, mine, recover, operate |
| Key derivation and address format | `docs/derivation.md` | independent wallet recovery |
| Release verification | `docs/release-verification.md` | pinned signing-key flow |
| Dependencies | `docs/dependencies.md` | pinned secp256k1/RandomX supply chain |
| Rendezvous and .btf addressing | `docs/rendezvous.md` | network design and caveats |
| Tor mode | `docs/tor.md` | `-tor`, `-socks`, onion relay operation |
| Fair launch verifier | `docs/fair-launch.md` | no-premine launch audit |
| UTXO set commitment | `docs/utxo-commitment.md` | deterministic supply/root audit |
| UTXO inclusion proofs | `docs/utxo-proofs.md` | proof for one unspent output |
| Mining calculator | `docs/mining-calculator.md` | local WhatToMine-style estimates |
| Public pool directory | `docs/pool-directory.md` | `pool_status.json`, `pools.json`, ranking |

## Release Mirror Aliases

Each release remains under its versioned directory:

```text
https://releases.bitflash.network/v1.2.18/SHA256SUMS
https://releases.bitflash.network/v1.2.18/SHA256SUMS.asc
```

The release root should also alias the latest files:

```text
https://releases.bitflash.network/SHA256SUMS
https://releases.bitflash.network/SHA256SUMS.asc
https://releases.bitflash.network/Bitflash-latest-windows.zip
https://releases.bitflash.network/Bitflash-latest-x86_64.AppImage
https://releases.bitflash.network/bitflash-node-latest-x86_64
```

The aliases are convenience only. Verification must still require the pinned
release key documented in `docs/release-verification.md`.

## Static Explorer

`scripts/build-explorer.py` writes a static explorer with no backend:

```text
index.html
style.css
explorer.js
logo.png
blocks.json
block/<height>.json
```

Serve it with a strict content policy:

```text
default-src 'none';
img-src 'self';
style-src 'self';
script-src 'self';
connect-src 'self';
base-uri 'none';
form-action 'none';
frame-ancestors 'none';
```

The viewer must never use `innerHTML` for chain data. A malicious transaction
must be rendered as text, not interpreted as markup.

## Cache Policy

Recommended defaults:

| path | cache |
|---|---|
| HTML pages | `public, max-age=0, must-revalidate` |
| `status.json` | `no-store` |
| `blocks.json`, `block/*.json` | `public, max-age=0, must-revalidate` |
| release assets | `public, max-age=14400, must-revalidate` |
| `SHA256SUMS`, signatures, keys | `public, max-age=0, must-revalidate` |

## Security Headers

Recommended for all static pages:

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: interest-cohort=(), geolocation=(), camera=(), microphone=()
```

Forgejo has its own application headers and should not blindly inherit the
static-site CSP.
