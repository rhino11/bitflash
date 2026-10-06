# CI architecture (engine)

## Source of truth vs this mirror

| Role | Location |
|------|----------|
| **Source of truth** | https://github.com/bitflash-network/bitflash |
| **This repo** | https://github.com/rhino11/bitflash (legacy CI mirror; do not sync) |

Forgejo (`git.bitflash.network`) is gone. The scheduled **Sync from Forgejo**
workflow was disabled and removed — it only produced failing notifications.

Develop and open PRs against **bitflash-network/bitflash**. Prefer CI there
(`.github/workflows/ci.yml` / `make ci`). This `rhino11/bitflash` tree may lag;
do not treat it as upstream.

Do **not** treat https://github.com/bitflash-coin/bitflash-core as upstream; it
is an unrelated, lagging history.

## What CI gated here

- Linux: `make tests` (includes `-selftest=wallet-encrypt` and the rest of the
  headless suite), Python tool regressions, net-message and script fuzz smokes
- Windows: MSYS2 UCRT64 selftests

## Security findings vs CI

| Finding class | In `make ci` / Actions? |
|---------------|-------------------------|
| Wallet encrypt / selftests (e.g. UP-001) | **Yes** |
| Hardening (RELRO/canary), SAST, `ws://` policy | **Not yet** — add steps when patching |
