# Build Dependencies

Bitflash links consensus-adjacent cryptographic and proof-of-work code from
external repositories. Fresh builds must not follow upstream `master` silently:
a changed upstream branch can break reproducible builds or change behavior in
code that every node relies on.

The top-level `Makefile` pins source dependencies by full commit hash:

| dependency | repository | pinned commit |
|---|---|---|
| libsecp256k1 | https://github.com/bitcoin-core/secp256k1 | `7fecac74aed8e1fd9078380d67dd04663705c989` |
| RandomX | https://github.com/tevador/RandomX | `1e9d4b2df63fa6edf46b06789486e23c0fcaa55a` |

When updating either dependency, rebuild from a clean dependency directory and
run the full selftest suite before opening the PR. The PR should explain why the
dependency changed and whether the update can affect consensus, addresses,
signatures, proof-of-work validation, or mining.
