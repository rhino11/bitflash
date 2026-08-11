# Bitflash UTXO-set commitment

`scripts/verify-utxo-set.py` reconstructs a deterministic commitment to the
current UTXO set from local `blk*.dat` files.

This is intentionally not a consensus rule yet. It is an audit tool: independent
operators can run it against the same chain prefix and compare the resulting
root and canonical JSON hash.

```bash
python3 scripts/verify-utxo-set.py --max-blocks 1000 --out utxo-report.json --json
```

Use `--max-blocks 0` or omit the option to scan every available block file:

```bash
python3 scripts/verify-utxo-set.py --out utxo-report.json --json
```

## What It Verifies

The verifier:

- parses Bitflash block files directly;
- reconstructs the best chain rooted at the Bitflash genesis block;
- ignores side blocks that may also be present in `blk*.dat`;
- verifies every scanned block merkle root;
- applies spends and creates outputs in deterministic order;
- reports current UTXO count, current supply, mined coinbase total, fees, and
  historical duplicate-output overwrites;
- computes a deterministic UTXO root.

## Commitment Algorithm

The UTXO map is keyed by:

```text
txid:vout
```

Keys are sorted lexicographically. Each leaf is:

```text
SHA256("BTFUTXO1|" || outpoint || "|" || value_satoshis || "|" ||
       script_pub_key_hex || "|" || created_height || "|" || created_txid)
```

The tree is then reduced pairwise. If a level has an odd number of hashes, the
last hash is duplicated. Each parent is:

```text
SHA256("BTFNODE1|" || left_hash || right_hash)
```

The final hash is the UTXO-set root.

## Inclusion Proofs

After a root has been computed, `scripts/prove-utxo.py` can create a compact
inclusion proof for one unspent output:

```bash
python3 scripts/prove-utxo.py TXID:VOUT --out utxo-proof.json --json
python3 scripts/verify-utxo-proof.py utxo-proof.json
```

The verifier does not need local block files. It recomputes the target leaf,
walks the sibling path, and compares the result with the expected root. See
[UTXO inclusion proofs](utxo-proofs.md).

## Deterministic Output

`--json` and `--out` write canonical JSON with sorted keys, fixed separators,
ASCII escaping, and one trailing newline. It contains no local path and no
generation timestamp, so two auditors scanning the same chain prefix should
produce byte-identical reports.

```bash
python3 scripts/verify-utxo-set.py --out utxo-report.json --json
sha256sum utxo-report.json
```

## OpenTimestamps

The canonical JSON can be timestamped in Bitcoin without adding any dependency
to Bitflash consensus:

```bash
ots stamp utxo-report.json
ots verify utxo-report.json.ots
```

## Historical Duplicates

Bitflash inherited early Bitcoin behavior around duplicate transaction IDs.
The verifier reports duplicate-output overwrites as warnings and uses
last-write-wins semantics for the UTXO map, matching the legacy index model.
Those warnings are part of the report so auditors can see the historical debt
instead of relying on a polished summary.

## Future Consensus Path

This tool is the low-risk first step toward consensus commitments. A future
hard-fork design can commit this root, or a Utreexo-style accumulator root, in
coinbase or block headers after a fixed activation height. Until then this
script provides reproducible supply and state commitments without changing what
nodes accept.
