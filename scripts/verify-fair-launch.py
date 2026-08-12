#!/usr/bin/env python3
"""Produce a deterministic Bitflash fair-launch audit report."""

import argparse
import hashlib
import sys
from pathlib import Path

import bitflash_chain as chain


def build_report(blocks, source_mode):
    genesis = blocks[0]
    launch_outputs = genesis["transactions"][0]["vout"] if genesis["transactions"] else []
    coinbase_outputs = []
    total_mined = 0
    non_coinbase_txs = 0

    for height, block in enumerate(blocks):
        if not block["transactions"]:
            continue
        cb = block["transactions"][0]
        if chain.is_coinbase(cb):
            amount = sum(out["value_satoshis"] for out in cb["vout"])
            total_mined += amount
            coinbase_outputs.append({
                "height": height,
                "block_hash": block["hash"],
                "coinbase_txid": cb["txid"],
                "value_satoshis": amount,
                "value_btf": chain.format_money(amount),
                "outputs": cb["vout"],
            })
        non_coinbase_txs += sum(1 for tx in block["transactions"] if not chain.is_coinbase(tx))

    checks = {
        "genesis_hash_matches_source": genesis["hash"] == chain.GENESIS_HASH,
        "genesis_merkle_matches_source": genesis["merkle_root"] == chain.GENESIS_MERKLE,
        "computed_merkle_matches_header": genesis["computed_merkle_root"] == genesis["merkle_root"],
        "genesis_has_single_transaction": genesis["tx_count"] == 1,
        "genesis_transaction_is_coinbase": bool(genesis["transactions"] and chain.is_coinbase(genesis["transactions"][0])),
        "genesis_supply_is_50_btf": sum(out["value_satoshis"] for out in launch_outputs) == 50 * chain.COIN,
    }

    report = {
        "schema": "bitflash-fair-launch-report-1",
        "deterministic": True,
        "source_mode": source_mode,
        "chain": {
            "name": "Bitflash",
            "ticker": "BTF",
            "message_start_hex": chain.MAGIC.hex(),
            "coin": chain.COIN,
        },
        "source_constants": {
            "genesis_hash": chain.GENESIS_HASH,
            "genesis_merkle_root": chain.GENESIS_MERKLE,
            "genesis_time": chain.GENESIS_TIME,
            "genesis_time_utc": chain.utc(chain.GENESIS_TIME),
            "genesis_bits": "0x%08x" % chain.GENESIS_BITS,
            "genesis_nonce": chain.GENESIS_NONCE,
            "genesis_message": chain.GENESIS_TEXT,
        },
        "scanned": {
            "block_count": len(blocks),
            "first_height": 0,
            "last_height": len(blocks) - 1,
            "non_coinbase_transactions": non_coinbase_txs,
            "total_coinbase_satoshis": total_mined,
            "total_coinbase_btf": chain.format_money(total_mined),
        },
        "genesis": {
            "hash": genesis["hash"],
            "merkle_root": genesis["merkle_root"],
            "computed_merkle_root": genesis["computed_merkle_root"],
            "time": genesis["time"],
            "time_utc": genesis["time_utc"],
            "bits": genesis["bits"],
            "nonce": genesis["nonce"],
            "tx_count": genesis["tx_count"],
            "coinbase_txid": genesis["transactions"][0]["txid"] if genesis["transactions"] else "",
            "outputs": launch_outputs,
        },
        "coinbase_outputs": coinbase_outputs,
        "checks": checks,
        "verdict": "FAIR_LAUNCH_BASELINE_VERIFIED" if all(checks.values()) else "CHECKS_FAILED",
        "external_timestamping": {
            "status": "not_embedded",
            "recommended": "OpenTimestamps",
            "instructions": [
                "Save the canonical JSON report.",
                "Run: ots stamp bitflash-fair-launch-report.json",
                "Later verify with: ots verify bitflash-fair-launch-report.json.ots",
            ],
        },
    }
    report["attestation_payload_sha256"] = hashlib.sha256(chain.canonical_bytes(report)).hexdigest()
    return report


def print_text(report):
    checks = report["checks"]
    print("Bitflash fair-launch verifier")
    print("schema: %s" % report["schema"])
    print("source: %s" % report["source_mode"])
    print("attestation payload sha256: %s" % report["attestation_payload_sha256"])
    print()
    print("Genesis")
    print("  hash:    %s" % report["genesis"]["hash"])
    print("  merkle:  %s" % report["genesis"]["merkle_root"])
    print("  time:    %s" % report["genesis"]["time_utc"])
    print("  txs:     %d" % report["genesis"]["tx_count"])
    print("  supply:  %s BTF" % chain.format_money(sum(o["value_satoshis"] for o in report["genesis"]["outputs"])))
    print()
    print("Scanned")
    print("  blocks:  %d" % report["scanned"]["block_count"])
    print("  height:  %d..%d" % (report["scanned"]["first_height"], report["scanned"]["last_height"]))
    print("  minted:  %s BTF" % report["scanned"]["total_coinbase_btf"])
    print("  normal transactions in range: %d" % report["scanned"]["non_coinbase_transactions"])
    print()
    print("Checks")
    for key in sorted(checks):
        print("  %s %s" % ("OK  " if checks[key] else "FAIL", key))
    print()
    print("Verdict: %s" % report["verdict"])
    print()
    print("OpenTimestamps")
    print("  canonical JSON can be stamped later with: ots stamp <report.json>")


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--datadir", default=chain.default_datadir(), help="Bitflash data directory")
    ap.add_argument("--max-blocks", type=int, default=100, help="number of blocks to scan from blk*.dat")
    ap.add_argument("--json", action="store_true", help="print canonical JSON")
    ap.add_argument("--out", help="write canonical JSON to this path")
    ap.add_argument("--reconstruct-genesis", action="store_true",
                    help="do not read disk; reconstruct only the genesis block from source constants")
    args = ap.parse_args(argv)

    if args.reconstruct_genesis:
        blocks = [chain.reconstructed_genesis()]
        source_mode = "reconstructed-genesis"
    else:
        blocks = chain.read_blocks(args.datadir, args.max_blocks)
        if not blocks:
            raise SystemExit("no Bitflash blocks found in %s; use --reconstruct-genesis for a source-only check" % args.datadir)
        source_mode = "local-block-files"

    try:
        report = build_report(blocks, source_mode)
    except chain.ParseError as e:
        raise SystemExit(str(e))
    data = chain.canonical_bytes(report)

    if args.out:
        Path(args.out).write_bytes(data)
    if args.json:
        sys.stdout.buffer.write(data)
    else:
        print_text(report)
    return 0 if report["verdict"] == "FAIR_LAUNCH_BASELINE_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
