#!/usr/bin/env python3
"""Create a Bitflash UTXO inclusion proof from local blk*.dat files.

The proof is deliberately outside consensus. It proves that one txid:vout is
included in the deterministic UTXO root produced by verify-utxo-set.py.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import bitflash_chain as chain

SCHEMA = "bitflash-utxo-inclusion-proof-1"


def canonical_bytes(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def split_outpoint(outpoint):
    parts = outpoint.split(":")
    if len(parts) != 2 or len(parts[0]) != 64:
        raise SystemExit("outpoint must be txid:vout")
    try:
        vout = int(parts[1], 10)
    except ValueError:
        raise SystemExit("vout must be a decimal integer")
    if vout < 0:
        raise SystemExit("vout must not be negative")
    return parts[0].lower(), vout


def build_merkle_proof(keys, leaf_hashes, index):
    current_index = index
    layer = list(leaf_hashes)
    proof = []
    level = 0
    while len(layer) > 1:
        if current_index % 2 == 0:
            sibling_index = current_index + 1
            duplicated = sibling_index >= len(layer)
            sibling = layer[current_index] if duplicated else layer[sibling_index]
            side = "right"
        else:
            sibling_index = current_index - 1
            duplicated = False
            sibling = layer[sibling_index]
            side = "left"
        proof.append({
            "level": level,
            "side": side,
            "hash": sibling.hex(),
            "duplicated": duplicated,
        })

        next_layer = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            next_layer.append(hashlib.sha256(chain.UTXO_NODE_DOMAIN + left + right).digest())
        layer = next_layer
        current_index //= 2
        level += 1
    return proof, layer[0].hex()


def build_proof(args):
    txid, vout = split_outpoint(args.outpoint)
    outpoint = "%s:%d" % (txid, vout)

    raw_blocks = chain.read_blocks(args.datadir, args.max_blocks)
    if not raw_blocks:
        raise SystemExit("no Bitflash blocks found in %s" % args.datadir)
    try:
        blocks = chain.select_main_chain(raw_blocks)
        state = chain.apply_blocks(blocks, strict_duplicates=args.strict_duplicates)
    except chain.ParseError as e:
        raise SystemExit(str(e))
    utxos = state["utxos"]
    stats = state["stats"]
    if outpoint not in utxos:
        raise SystemExit("outpoint is not unspent in the scanned chain: %s" % outpoint)

    keys = sorted(utxos)
    leaf_hashes = [chain.utxo_leaf_hash(k, utxos[k]) for k in keys]
    index = keys.index(outpoint)
    proof_path, root = build_merkle_proof(keys, leaf_hashes, index)
    direct_root = chain.utxo_root(utxos)
    if root != direct_root:
        raise SystemExit("internal proof root mismatch")

    tip = blocks[-1]
    utxo = utxos[outpoint]
    report = {
        "schema": SCHEMA,
        "deterministic": True,
        "chain": {
            "name": "Bitflash",
            "ticker": "BTF",
            "message_start_hex": chain.MAGIC.hex(),
            "coin": chain.COIN,
        },
        "commitment": {
            "algorithm": "sorted-outpoint-merkle-sha256",
            "leaf_domain": chain.UTXO_LEAF_DOMAIN,
            "node_domain": chain.UTXO_NODE_DOMAIN_TAG,
            "root": root,
            "leaf_count": len(keys),
        },
        "target": {
            "outpoint": outpoint,
            "txid": txid,
            "vout": vout,
            "leaf_index": index,
            "leaf_hash": leaf_hashes[index].hex(),
            "utxo": utxo,
        },
        "proof": proof_path,
        "scanned": {
            "raw_block_count": len(raw_blocks),
            "side_blocks_ignored": len(raw_blocks) - len(blocks),
            "main_chain_block_count": len(blocks),
            "first_height": 0,
            "last_height": len(blocks) - 1,
            "tip_hash": tip["hash"],
            "tip_time": tip["time"],
            "tip_time_utc": tip["time_utc"],
        },
        "warnings": {
            "legacy_duplicate_output_overwrites": len(stats["duplicate_outputs"]),
        },
        "verdict": "UTXO_INCLUSION_PROOF_CREATED",
    }
    return report


def print_text(proof):
    data_hash = hashlib.sha256(canonical_bytes(proof)).hexdigest()
    target = proof["target"]
    utxo = target["utxo"]
    print("Bitflash UTXO inclusion proof")
    print("schema: %s" % proof["schema"])
    print("canonical proof sha256: %s" % data_hash)
    print()
    print("Target")
    print("  outpoint: %s" % target["outpoint"])
    print("  value:    %s BTF" % utxo["value_btf"])
    print("  height:   %d" % utxo["created_height"])
    print("  index:    %d of %d" % (target["leaf_index"], proof["commitment"]["leaf_count"]))
    print()
    print("Commitment")
    print("  root:     %s" % proof["commitment"]["root"])
    print("  path:     %d sibling hashes" % len(proof["proof"]))
    print("  tip:      %s" % proof["scanned"]["tip_hash"])
    print()
    print("Verdict: %s" % proof["verdict"])


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("outpoint", help="unspent output to prove, as txid:vout")
    ap.add_argument("--datadir", default=chain.default_datadir(), help="Bitflash data directory")
    ap.add_argument("--max-blocks", type=int, default=0,
                    help="number of blocks to scan; 0 means all block files")
    ap.add_argument("--strict-duplicates", action="store_true",
                    help="fail instead of using legacy last-write-wins duplicate output handling")
    ap.add_argument("--json", action="store_true", help="print canonical JSON")
    ap.add_argument("--out", help="write canonical JSON proof to this path")
    args = ap.parse_args(argv)

    proof = build_proof(args)
    data = canonical_bytes(proof)
    if args.out:
        Path(args.out).write_bytes(data)
    if args.json:
        sys.stdout.buffer.write(data)
    else:
        print_text(proof)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
