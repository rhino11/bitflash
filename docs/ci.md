# CI architecture (engine)

## Source of truth vs CI host

| Role | Location |
|------|----------|
| **Source of truth** | https://git.bitflash.network/bitflash/bitflash (Forgejo) |
| **CI host (GitHub Actions)** | https://github.com/rhino11/bitflash |

Forgejo Actions are **not** enabled on the upstream host (`has_actions: false`).
This GitHub repo is a **CI mirror**: same history and tags, runners that can
execute the existing GitHub Actions workflow.

Do **not** treat https://github.com/bitflash-coin/bitflash-core as upstream; it
is an unrelated, lagging history.

## Official pattern

1. Develop and open PRs against Forgejo when contributing to the node.
2. Until Forgejo Actions exist, verify on GitHub via this mirror:
   - Workflow: `.github/workflows/ci.yml`
   - Local parity: `make ci` (deps + `make tests` + Python tools + fuzz smokes)
3. Keep the mirror synced from Forgejo (`sync-from-forgejo` workflow or
   `scripts/sync-from-forgejo.sh`).

## What CI gates today

- Linux: `make tests` (includes `-selftest=wallet-encrypt` and the rest of the
  headless suite), Python tool regressions, net-message and script fuzz smokes
- Windows: MSYS2 UCRT64 selftests

## Security findings vs CI

| Finding class | In `make ci` / Actions? |
|---------------|-------------------------|
| Wallet encrypt / selftests (e.g. UP-001) | **Yes** |
| Hardening (RELRO/canary), SAST, `ws://` policy | **Not yet** — add steps when patching |

## Sync

```bash
./scripts/sync-from-forgejo.sh
# or: Actions → "Sync from Forgejo" → Run workflow
```
