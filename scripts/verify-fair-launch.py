#!/usr/bin/env python3
"""Produce a deterministic Bitflash fair-launch audit report.

This verifier is intentionally self-contained. It parses Bitflash block files
directly, without Berkeley DB, without the node binary, and without network
access. The canonical JSON output is stable for the same inputs and can be
timestamped later with OpenTimestamps or any other external notary.
"""

import argparse
import datetime as _dt
import hashlib
import json
import os
import struct
import sys
from pathlib import Path


MAGIC = bytes([0xBF, 0x20, 0x5C, 0xFD])
COIN = 100_000_000
GENESIS_HASH = "5bd7cb255d814e48cebcdfb72da4dc87b34bd774227f8ceb546c5640f4bdc169"
GENESIS_MERKLE = "1a45b4482532abb29b10e234d3f13132230525a339ecea91658ffa675a5b1325"
GENESIS_TIME = 1_753_315_200
GENESIS_BITS = 0x1F0FFFFF
GENESIS_NONCE = 3141
GENESIS_TEXT = "Bitflash 24/Jul/2026 Fair launch: one CPU one vote, no premine"


class ParseError(Exception):
    pass


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ParseError("unexpected end of data")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def i32(self):
        return struct.unpack("<i", self.take(4))[0]

    def i64(self):
        return struct.unpack("<q", self.take(8))[0]


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash_hex(serialized):
    return sha256d(serialized)[::-1].hex()


def compact_size(r):
    first = r.u8()
    if first < 253:
        return first
    if first == 253:
        return struct.unpack("<H", r.take(2))[0]
    if first == 254:
        return r.u32()
    return struct.unpack("<Q", r.take(8))[0]


def read_varbytes(r):
    return r.take(compact_size(r))


def ser_compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def ser_varbytes(b):
    return ser_compact_size(len(b)) + b


def ser_tx(tx):
    out = bytearray()
    out += struct.pack("<i", tx["version"])
    out += ser_compact_size(len(tx["vin"]))
    for txin in tx["vin"]:
        out += bytes.fromhex(txin["prevout_hash"])[::-1]
        out += struct.pack("<I", txin["prevout_n"])
        out += ser_varbytes(bytes.fromhex(txin["script_sig_hex"]))
        out += struct.pack("<I", txin["sequence"])
    out += ser_compact_size(len(tx["vout"]))
    for txout in tx["vout"]:
        out += struct.pack("<q", txout["value_satoshis"])
        out += ser_varbytes(bytes.fromhex(txout["script_pub_key_hex"]))
    out += struct.pack("<I", tx["lock_time"])
    return bytes(out)


def parse_tx(r):
    start = r.pos
    tx = {"version": r.i32(), "vin": [], "vout": [], "lock_time": 0}
    for _ in range(compact_size(r)):
        prev_hash = r.take(32)[::-1].hex()
        prev_n = r.u32()
        script = read_varbytes(r).hex()
        sequence = r.u32()
        tx["vin"].append({
            "prevout_hash": prev_hash,
            "prevout_n": prev_n,
            "script_sig_hex": script,
            "sequence": sequence,
        })
    for _ in range(compact_size(r)):
        value = r.i64()
        script = read_varbytes(r).hex()
        tx["vout"].append({
            "value_satoshis": value,
            "value_btf": format_money(value),
            "script_pub_key_hex": script,
        })
    tx["lock_time"] = r.u32()
    raw = r.data[start:r.pos]
    tx["txid"] = hash_hex(raw)
    return tx


def merkle_root(txids):
    if not txids:
        return "0" * 64
    layer = [bytes.fromhex(x)[::-1] for x in txids]
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            nxt.append(sha256d(left + right))
        layer = nxt
    return layer[0][::-1].hex()


def parse_block(payload, file_name="", offset=0):
    r = Reader(payload)
    header = r.take(80)
    version, = struct.unpack("<i", header[0:4])
    prev = header[4:36][::-1].hex()
    merkle = header[36:68][::-1].hex()
    ntime, bits, nonce = struct.unpack("<III", header[68:80])
    txs = [parse_tx(r) for _ in range(compact_size(r))]
    if r.pos != len(payload):
        raise ParseError("trailing bytes inside block")
    txids = [tx["txid"] for tx in txs]
    return {
        "hash": hash_hex(header),
        "version": version,
        "previous_hash": prev,
        "merkle_root": merkle,
        "computed_merkle_root": merkle_root(txids),
        "time": ntime,
        "time_utc": utc(ntime),
        "bits": "0x%08x" % bits,
        "nonce": nonce,
        "tx_count": len(txs),
        "transactions": txs,
        "source_file": file_name,
        "source_offset": offset,
    }


def iter_block_files(datadir):
    for path in sorted(Path(datadir).glob("blk*.dat")):
        yield path


def read_blocks(datadir, limit):
    blocks = []
    for path in iter_block_files(datadir):
        data = path.read_bytes()
        pos = 0
        while True:
            idx = data.find(MAGIC, pos)
            if idx < 0:
                break
            if idx + 8 > len(data):
                break
            size = struct.unpack("<I", data[idx + 4:idx + 8])[0]
            start = idx + 8
            end = start + size
            if end > len(data):
                break
            blocks.append(parse_block(data[start:end], path.name, start))
            if limit and len(blocks) >= limit:
                return blocks
            pos = end
    return blocks


def genesis_transaction():
    script_sig = (
        bytes.fromhex("04ffff001d")
        + b"\x01\x04"
        + bytes([len(GENESIS_TEXT)])
        + GENESIS_TEXT.encode("ascii")
    )
    pubkey_num = bytes.fromhex(
        "5f1df16b2b704c8a578d0bbaf74d385cde12c11ee50455f3c438ef4c3fbcf649"
        "b6de611feae06279a60939e028a8d65c10b73071a6f16719274855feb0fd8a6704"
    )
    # The genesis source uses CScript << CBigNum("0x..."), and CBigNum::getvch()
    # returns the minimal little-endian script number representation.
    script_pub_key = bytes([65]) + pubkey_num[::-1] + b"\xac"
    tx = {
        "version": 1,
        "vin": [{
            "prevout_hash": "0" * 64,
            "prevout_n": 0xFFFFFFFF,
            "script_sig_hex": script_sig.hex(),
            "sequence": 0xFFFFFFFF,
        }],
        "vout": [{
            "value_satoshis": 50 * COIN,
            "value_btf": format_money(50 * COIN),
            "script_pub_key_hex": script_pub_key.hex(),
        }],
        "lock_time": 0,
    }
    tx["txid"] = hash_hex(ser_tx(tx))
    return tx


def reconstructed_genesis():
    tx = genesis_transaction()
    header = (
        struct.pack("<i", 1)
        + bytes(32)
        + bytes.fromhex(tx["txid"])[::-1]
        + struct.pack("<III", GENESIS_TIME, GENESIS_BITS, GENESIS_NONCE)
    )
    return {
        "hash": hash_hex(header),
        "version": 1,
        "previous_hash": "0" * 64,
        "merkle_root": tx["txid"],
        "computed_merkle_root": tx["txid"],
        "time": GENESIS_TIME,
        "time_utc": utc(GENESIS_TIME),
        "bits": "0x%08x" % GENESIS_BITS,
        "nonce": GENESIS_NONCE,
        "tx_count": 1,
        "transactions": [tx],
        "source_file": "reconstructed-from-source-constants",
        "source_offset": 0,
    }


def format_money(value):
    sign = "-" if value < 0 else ""
    value = abs(value)
    return "%s%d.%08d" % (sign, value // COIN, value % COIN)


def utc(ts):
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_datadir():
    if os.name == "nt" and os.environ.get("APPDATA"):
        return os.path.join(os.environ["APPDATA"], "Bitflash")
    if os.environ.get("HOME"):
        return os.path.join(os.environ["HOME"], ".bitflash")
    return "."


def is_coinbase(tx):
    return (
        len(tx["vin"]) == 1
        and tx["vin"][0]["prevout_hash"] == "0" * 64
        and tx["vin"][0]["prevout_n"] == 0xFFFFFFFF
    )


def canonical_bytes(report):
    return (json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


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
        if is_coinbase(cb):
            amount = sum(out["value_satoshis"] for out in cb["vout"])
            total_mined += amount
            coinbase_outputs.append({
                "height": height,
                "block_hash": block["hash"],
                "coinbase_txid": cb["txid"],
                "value_satoshis": amount,
                "value_btf": format_money(amount),
                "outputs": cb["vout"],
            })
        non_coinbase_txs += sum(1 for tx in block["transactions"] if not is_coinbase(tx))

    checks = {
        "genesis_hash_matches_source": genesis["hash"] == GENESIS_HASH,
        "genesis_merkle_matches_source": genesis["merkle_root"] == GENESIS_MERKLE,
        "computed_merkle_matches_header": genesis["computed_merkle_root"] == genesis["merkle_root"],
        "genesis_has_single_transaction": genesis["tx_count"] == 1,
        "genesis_transaction_is_coinbase": bool(genesis["transactions"] and is_coinbase(genesis["transactions"][0])),
        "genesis_supply_is_50_btf": sum(out["value_satoshis"] for out in launch_outputs) == 50 * COIN,
    }

    report = {
        "schema": "bitflash-fair-launch-report-1",
        "deterministic": True,
        "source_mode": source_mode,
        "chain": {
            "name": "Bitflash",
            "ticker": "BTF",
            "message_start_hex": MAGIC.hex(),
            "coin": COIN,
        },
        "source_constants": {
            "genesis_hash": GENESIS_HASH,
            "genesis_merkle_root": GENESIS_MERKLE,
            "genesis_time": GENESIS_TIME,
            "genesis_time_utc": utc(GENESIS_TIME),
            "genesis_bits": "0x%08x" % GENESIS_BITS,
            "genesis_nonce": GENESIS_NONCE,
            "genesis_message": GENESIS_TEXT,
        },
        "scanned": {
            "block_count": len(blocks),
            "first_height": 0,
            "last_height": len(blocks) - 1,
            "non_coinbase_transactions": non_coinbase_txs,
            "total_coinbase_satoshis": total_mined,
            "total_coinbase_btf": format_money(total_mined),
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
    report["attestation_payload_sha256"] = hashlib.sha256(canonical_bytes(report)).hexdigest()
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
    print("  supply:  %s BTF" % format_money(sum(o["value_satoshis"] for o in report["genesis"]["outputs"])))
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
    ap.add_argument("--datadir", default=default_datadir(), help="Bitflash data directory")
    ap.add_argument("--max-blocks", type=int, default=100, help="number of blocks to scan from blk*.dat")
    ap.add_argument("--json", action="store_true", help="print canonical JSON")
    ap.add_argument("--out", help="write canonical JSON to this path")
    ap.add_argument("--reconstruct-genesis", action="store_true",
                    help="do not read disk; reconstruct only the genesis block from source constants")
    args = ap.parse_args(argv)

    if args.reconstruct_genesis:
        blocks = [reconstructed_genesis()]
        source_mode = "reconstructed-genesis"
        datadir = ""
    else:
        datadir = Path(args.datadir)
        blocks = read_blocks(datadir, args.max_blocks)
        if not blocks:
            raise SystemExit("no Bitflash blocks found in %s; use --reconstruct-genesis for a source-only check" % datadir)
        source_mode = "local-block-files"

    report = build_report(blocks, source_mode)
    data = canonical_bytes(report)

    if args.out:
        Path(args.out).write_bytes(data)
    if args.json:
        sys.stdout.buffer.write(data)
    else:
        print_text(report)
    return 0 if report["verdict"] == "FAIR_LAUNCH_BASELINE_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
