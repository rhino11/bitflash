#!/usr/bin/env python3
"""Verify a Bitflash UTXO inclusion proof against a UTXO root."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import bitflash_chain as chain

SCHEMA = "bitflash-utxo-inclusion-proof-1"
LEAF_DOMAIN = "BTFUTXO1"
NODE_DOMAIN = b"BTFNODE1|"


def canonical_bytes(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def load_proof(path):
    try:
        return json.loads(Path(path).read_text(encoding="ascii"))
    except Exception as e:
        raise SystemExit("could not read proof: %s" % e)


def verify(proof, expected_root=None):
    failures = []
    if proof.get("schema") != SCHEMA:
        failures.append("unexpected schema")
    commitment = proof.get("commitment", {})
    if commitment.get("algorithm") != "sorted-outpoint-merkle-sha256":
        failures.append("unexpected commitment algorithm")
    if commitment.get("leaf_domain") != LEAF_DOMAIN:
        failures.append("unexpected leaf domain")
    if commitment.get("node_domain") != "BTFNODE1":
        failures.append("unexpected node domain")

    target = proof.get("target", {})
    outpoint = target.get("outpoint", "")
    utxo = target.get("utxo", {})
    if outpoint != "%s:%s" % (target.get("txid"), target.get("vout")):
        failures.append("target outpoint does not match txid:vout")

    try:
        current = chain.utxo_leaf_hash(outpoint, utxo)
        leaf_ok = target.get("leaf_hash") == current.hex()
    except Exception as e:
        failures.append("could not hash target leaf: %s" % e)
        current = b"\x00" * 32
        leaf_ok = False

    if not leaf_ok:
        failures.append("target leaf hash mismatch")

    for i, step in enumerate(proof.get("proof", [])):
        try:
            sibling = bytes.fromhex(step["hash"])
        except Exception:
            failures.append("bad sibling hash at proof level %d" % i)
            sibling = b"\x00" * 32
        if len(sibling) != 32:
            failures.append("bad sibling hash length at proof level %d" % i)
        side = step.get("side")
        if side == "right":
            current = chain.sha256(NODE_DOMAIN + current + sibling)
        elif side == "left":
            current = chain.sha256(NODE_DOMAIN + sibling + current)
        else:
            failures.append("bad sibling side at proof level %d" % i)

    computed_root = current.hex()
    root = expected_root or commitment.get("root")
    if computed_root != root:
        failures.append("computed root does not match expected root")

    return {
        "schema": "bitflash-utxo-proof-verification-1",
        "deterministic": True,
        "target": {
            "outpoint": outpoint,
            "value_satoshis": utxo.get("value_satoshis"),
            "value_btf": utxo.get("value_btf"),
            "created_height": utxo.get("created_height"),
        },
        "commitment": {
            "expected_root": root,
            "computed_root": computed_root,
            "leaf_hash": target.get("leaf_hash"),
            "path_length": len(proof.get("proof", [])),
        },
        "checks": {
            "schema_is_supported": proof.get("schema") == SCHEMA,
            "leaf_hash_matches_target": leaf_ok,
            "root_matches": computed_root == root,
        },
        "failures": failures,
        "verdict": "UTXO_PROOF_VERIFIED" if not failures else "UTXO_PROOF_FAILED",
    }


def print_text(result):
    data_hash = hashlib.sha256(canonical_bytes(result)).hexdigest()
    print("Bitflash UTXO proof verifier")
    print("schema: %s" % result["schema"])
    print("canonical verification sha256: %s" % data_hash)
    print()
    print("Target")
    print("  outpoint: %s" % result["target"]["outpoint"])
    print("  value:    %s BTF" % result["target"]["value_btf"])
    print("  height:   %s" % result["target"]["created_height"])
    print()
    print("Commitment")
    print("  expected: %s" % result["commitment"]["expected_root"])
    print("  computed: %s" % result["commitment"]["computed_root"])
    print("  path:     %d sibling hashes" % result["commitment"]["path_length"])
    print()
    print("Checks")
    for key in sorted(result["checks"]):
        print("  %s %s" % ("OK  " if result["checks"][key] else "FAIL", key))
    if result["failures"]:
        print()
        print("Failures")
        for failure in result["failures"]:
            print("  - %s" % failure)
    print()
    print("Verdict: %s" % result["verdict"])


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("proof", help="canonical JSON proof from prove-utxo.py")
    ap.add_argument("--root", help="expected UTXO root; defaults to root embedded in proof")
    ap.add_argument("--json", action="store_true", help="print canonical JSON")
    args = ap.parse_args(argv)

    result = verify(load_proof(args.proof), args.root)
    data = canonical_bytes(result)
    if args.json:
        sys.stdout.buffer.write(data)
    else:
        print_text(result)
    return 0 if result["verdict"] == "UTXO_PROOF_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
