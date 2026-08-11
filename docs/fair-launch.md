# Bitflash fair-launch verifier

Bitflash ships a deterministic fair-launch audit script:

```bash
python3 scripts/verify-fair-launch.py --max-blocks 1000 --out bitflash-fair-launch-report.json --json
```

The verifier reads `blk*.dat` directly from the local Bitflash data directory.
It does not use Berkeley DB, does not call the node binary, and does not need
network access.

The report proves the launch baseline that can be checked from the chain:

- the genesis block hash matches the source constant;
- the genesis merkle root matches the source constant;
- the genesis transaction is a single coinbase transaction;
- the genesis output total is exactly `50.00000000 BTF`;
- the scanned block range and mined coinbase total are reproducible.

For machines that do not have a synced data directory yet, the source constants
can be checked without disk blocks:

```bash
python3 scripts/verify-fair-launch.py --reconstruct-genesis
```

## Deterministic output

Use `--json` or `--out` for canonical JSON. The JSON is written with sorted
keys, fixed separators, ASCII escaping, and one trailing newline. It deliberately
does not include local paths or wall-clock generation time, so two auditors
scanning the same block range produce the same bytes.

That makes the report shareable:

```bash
python3 scripts/verify-fair-launch.py --max-blocks 1000 --out report.json --json
sha256sum report.json
```

If another auditor runs the same command against the same chain prefix, the
`sha256sum` should match.

## OpenTimestamps

OpenTimestamps is optional and external. It anchors the report in Bitcoin
without adding any bridge or dependency to Bitflash consensus.

After generating a canonical JSON report:

```bash
ots stamp report.json
ots verify report.json.ots
```

The `.ots` file proves that the exact report bytes existed no later than the
Bitcoin block that confirms the timestamp.

## What this does not claim

This is not a retroactive genesis commitment. The Bitflash genesis block already
exists, so adding a new on-chain commitment to genesis would create a different
chain. This verifier instead audits the launch state that is already on-chain
and makes the result reproducible and timestampable.

It also does not prove real-world miner identity. It proves the genesis state,
the absence of non-coinbase premine in genesis, and the deterministic coinbase
totals over the scanned prefix.
