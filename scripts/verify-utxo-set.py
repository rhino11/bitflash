#!/usr/bin/env python3
"""Build a deterministic Bitflash UTXO-set commitment from local blk*.dat."""

import argparse
import hashlib
import sys
from pathlib import Path

import bitflash_chain as chain


def build_report(raw_blocks, include_utxos=False, strict_duplicates=False):
    blocks = chain.select_main_chain(raw_blocks)
    state = chain.apply_blocks(blocks, strict_duplicates=strict_duplicates)
    utxos = state["utxos"]
    stats = state["stats"]
    tip = blocks[-1]
    root = chain.utxo_root(utxos)
    checks = {
        "genesis_hash_matches_source": blocks[0]["hash"] == chain.GENESIS_HASH,
        "genesis_merkle_matches_source": blocks[0]["merkle_root"] == chain.GENESIS_MERKLE,
        "all_scanned_merkle_roots_match": all(b["computed_merkle_root"] == b["merkle_root"] for b in blocks),
        "no_missing_spends": len(stats["missing_spends"]) == 0,
    }
    warnings = {
        "legacy_duplicate_output_overwrites": len(stats["duplicate_outputs"]),
    }
    report = {
        "schema": "bitflash-utxo-set-commitment-1",
        "deterministic": True,
        "chain": {
            "name": "Bitflash",
            "ticker": "BTF",
            "message_start_hex": chain.MAGIC.hex(),
            "coin": chain.COIN,
        },
        "commitment": {
            "algorithm": "sorted-outpoint-merkle-sha256",
            "leaf_domain": "BTFUTXO1",
            "node_domain": "BTFNODE1",
            "root": root,
        },
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
        "stats": stats,
        "checks": checks,
        "warnings": warnings,
        "verdict": "UTXO_COMMITMENT_VERIFIED" if all(checks.values()) else "CHECKS_FAILED",
    }
    if include_utxos:
        report["utxos"] = {k: utxos[k] for k in sorted(utxos)}
    return report


def print_text(report):
    data_hash = hashlib.sha256(chain.canonical_bytes(report)).hexdigest()
    print("Bitflash UTXO-set commitment verifier")
    print("schema: %s" % report["schema"])
    print("canonical report sha256: %s" % data_hash)
    print()
    print("Commitment")
    print("  root:   %s" % report["commitment"]["root"])
    print("  algo:   %s" % report["commitment"]["algorithm"])
    print()
    print("Scanned")
    print("  main chain blocks: %d" % report["scanned"]["main_chain_block_count"])
    print("  raw disk blocks:   %d" % report["scanned"]["raw_block_count"])
    print("  side ignored:      %d" % report["scanned"]["side_blocks_ignored"])
    print("  height: %d..%d" % (report["scanned"]["first_height"], report["scanned"]["last_height"]))
    print("  tip:    %s" % report["scanned"]["tip_hash"])
    print()
    print("Supply")
    print("  utxos:  %d" % report["stats"]["utxo_count"])
    print("  supply: %s BTF" % report["stats"]["total_unspent_btf"])
    print("  mined:  %s BTF" % report["stats"]["total_coinbase_btf"])
    print("  delta:  %s BTF" % report["stats"]["coinbase_minus_unspent_btf"])
    print("  fees:   %s BTF" % report["stats"]["total_fees_btf"])
    if report["warnings"]["legacy_duplicate_output_overwrites"]:
        print("  legacy duplicate overwrites: %d" % report["warnings"]["legacy_duplicate_output_overwrites"])
    print()
    print("Checks")
    for key in sorted(report["checks"]):
        print("  %s %s" % ("OK  " if report["checks"][key] else "FAIL", key))
    print()
    print("Verdict: %s" % report["verdict"])
    print()
    print("OpenTimestamps")
    print("  canonical JSON can be stamped later with: ots stamp <report.json>")


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--datadir", default=chain.default_datadir(), help="Bitflash data directory")
    ap.add_argument("--max-blocks", type=int, default=0,
                    help="number of blocks to scan; 0 means all block files")
    ap.add_argument("--include-utxos", action="store_true",
                    help="include the full sorted UTXO map in JSON output")
    ap.add_argument("--strict-duplicates", action="store_true",
                    help="fail instead of using legacy last-write-wins duplicate output handling")
    ap.add_argument("--json", action="store_true", help="print canonical JSON")
    ap.add_argument("--out", help="write canonical JSON to this path")
    args = ap.parse_args(argv)

    blocks = chain.read_blocks(args.datadir, args.max_blocks)
    if not blocks:
        raise SystemExit("no Bitflash blocks found in %s" % args.datadir)
    try:
        report = build_report(blocks, include_utxos=args.include_utxos,
                              strict_duplicates=args.strict_duplicates)
    except chain.ParseError as e:
        raise SystemExit(str(e))
    data = chain.canonical_bytes(report)
    if args.out:
        Path(args.out).write_bytes(data)
    if args.json:
        sys.stdout.buffer.write(data)
    else:
        print_text(report)
    return 0 if report["verdict"] == "UTXO_COMMITMENT_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
