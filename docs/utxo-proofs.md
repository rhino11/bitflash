# Bitflash UTXO inclusion proofs

`scripts/prove-utxo.py` creates a deterministic inclusion proof for one
currently unspent output. `scripts/verify-utxo-proof.py` verifies that proof
against the UTXO root produced by `scripts/verify-utxo-set.py`.

This is intentionally outside consensus. It turns the audit root into something
useful for a specific coin without changing what nodes accept.

## Create A Proof

Use an unspent output in `txid:vout` form:

```bash
python3 scripts/prove-utxo.py TXID:VOUT --out utxo-proof.json --json
```

The proof contains:

- the target UTXO;
- its sorted leaf index;
- the leaf hash;
- the Merkle sibling path;
- the UTXO root and chain tip used to create it.

It does not contain the full UTXO set.

## Verify A Proof

Verify against the root embedded in the proof:

```bash
python3 scripts/verify-utxo-proof.py utxo-proof.json
```

Or verify against a root copied from another machine, dashboard, block explorer,
or future node export:

```bash
python3 scripts/verify-utxo-proof.py utxo-proof.json \
  --root ROOT_FROM_REPORT_OR_EXPORT
```

The verifier does not need local `blk*.dat` files. It only needs the proof and
the expected root.

## Scope

This first proof format supports inclusion only. Absence and range proofs are
left for a later design because they require a more careful commitment scheme
and are easier to get subtly wrong.

The proof uses the exact same leaf and node domains as the UTXO commitment:

```text
BTFUTXO1
BTFNODE1
```

That keeps the verifier language-neutral and gives future implementations a
small, stable target.
