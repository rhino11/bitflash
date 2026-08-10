#!/usr/bin/env python3
"""Build a deterministic Bitflash UTXO-set commitment from local blk*.dat.

This is deliberately outside consensus. It lets auditors reconstruct the chain
state from disk blocks and compare the same canonical UTXO root independently.
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


def sha256(data):
    return hashlib.sha256(data).digest()


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
    tx = {"version": r.i32(), "vin": [], "vout": [], "lock_time": 0}
    for _ in range(compact_size(r)):
        tx["vin"].append({
            "prevout_hash": r.take(32)[::-1].hex(),
            "prevout_n": r.u32(),
            "script_sig_hex": read_varbytes(r).hex(),
            "sequence": r.u32(),
        })
    for _ in range(compact_size(r)):
        value = r.i64()
        tx["vout"].append({
            "value_satoshis": value,
            "value_btf": format_money(value),
            "script_pub_key_hex": read_varbytes(r).hex(),
        })
    tx["lock_time"] = r.u32()
    tx["txid"] = hash_hex(ser_tx(tx))
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


def read_blocks(datadir, max_blocks):
    blocks = []
    for path in sorted(Path(datadir).glob("blk*.dat")):
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
            if max_blocks and len(blocks) >= max_blocks:
                return blocks
            pos = end
    return blocks


def select_main_chain(blocks):
    by_hash = {}
    for block in blocks:
        by_hash.setdefault(block["hash"], block)
    if GENESIS_HASH not in by_hash:
        raise ParseError("genesis block not found in block files")

    children = {}
    for block in by_hash.values():
        children.setdefault(block["previous_hash"], []).append(block)
    for v in children.values():
        v.sort(key=lambda b: (b["hash"], b["source_file"], b["source_offset"]))

    best = []
    stack = [(by_hash[GENESIS_HASH], [by_hash[GENESIS_HASH]])]
    while stack:
        block, path = stack.pop()
        if len(path) > len(best) or (len(path) == len(best) and block["hash"] < best[-1]["hash"]):
            best = path
        for child in children.get(block["hash"], []):
            stack.append((child, path + [child]))
    return best


def is_coinbase(tx):
    return (
        len(tx["vin"]) == 1
        and tx["vin"][0]["prevout_hash"] == "0" * 64
        and tx["vin"][0]["prevout_n"] == 0xFFFFFFFF
    )


def utxo_leaf_hash(outpoint, utxo):
    # Text fields are length-delimited by separators and all variable data is
    # hex or decimal ASCII. That keeps the commitment language-neutral.
    payload = "|".join([
        "BTFUTXO1",
        outpoint,
        str(utxo["value_satoshis"]),
        utxo["script_pub_key_hex"],
        str(utxo["created_height"]),
        utxo["created_txid"],
    ]).encode("ascii")
    return sha256(payload)


def utxo_root(utxos):
    leaves = [utxo_leaf_hash(k, utxos[k]) for k in sorted(utxos)]
    if not leaves:
        return sha256(b"BTFUTXO1|empty").hex()
    layer = leaves
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            nxt.append(sha256(b"BTFNODE1|" + left + right))
        layer = nxt
    return layer[0].hex()


def apply_blocks(blocks):
    utxos = {}
    spent = 0
    missing_spends = []
    duplicate_outputs = []
    total_coinbase = 0
    total_fees = 0
    normal_txs = 0

    for height, block in enumerate(blocks):
        if block["computed_merkle_root"] != block["merkle_root"]:
            raise ParseError("bad merkle root at height %d" % height)
        for tx_index, tx in enumerate(block["transactions"]):
            coinbase = is_coinbase(tx)
            input_value = 0
            output_value = sum(out["value_satoshis"] for out in tx["vout"])
            if coinbase:
                total_coinbase += output_value
            else:
                normal_txs += 1
                for txin in tx["vin"]:
                    prev = "%s:%d" % (txin["prevout_hash"], txin["prevout_n"])
                    prev_utxo = utxos.pop(prev, None)
                    if prev_utxo is None:
                        missing_spends.append({
                            "height": height,
                            "txid": tx["txid"],
                            "missing_outpoint": prev,
                        })
                    else:
                        spent += prev_utxo["value_satoshis"]
                        input_value += prev_utxo["value_satoshis"]
                if input_value >= output_value:
                    total_fees += input_value - output_value
            for n, out in enumerate(tx["vout"]):
                key = "%s:%d" % (tx["txid"], n)
                if key in utxos:
                    duplicate_outputs.append({"height": height, "outpoint": key})
                utxos[key] = {
                    "txid": tx["txid"],
                    "vout": n,
                    "value_satoshis": out["value_satoshis"],
                    "value_btf": out["value_btf"],
                    "script_pub_key_hex": out["script_pub_key_hex"],
                    "created_height": height,
                    "created_block_hash": block["hash"],
                    "created_txid": tx["txid"],
                    "coinbase": coinbase,
                }

    total_unspent = sum(u["value_satoshis"] for u in utxos.values())
    return {
        "utxos": utxos,
        "stats": {
            "utxo_count": len(utxos),
            "spent_outputs": spent,
            "total_unspent_satoshis": total_unspent,
            "total_unspent_btf": format_money(total_unspent),
            "total_coinbase_satoshis": total_coinbase,
            "total_coinbase_btf": format_money(total_coinbase),
            "coinbase_minus_unspent_satoshis": total_coinbase - total_unspent,
            "coinbase_minus_unspent_btf": format_money(total_coinbase - total_unspent),
            "total_fees_satoshis": total_fees,
            "total_fees_btf": format_money(total_fees),
            "normal_transactions": normal_txs,
            "missing_spends": missing_spends,
            "duplicate_outputs": duplicate_outputs,
        },
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


def canonical_bytes(report):
    return (json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def build_report(raw_blocks, include_utxos=False):
    blocks = select_main_chain(raw_blocks)
    state = apply_blocks(blocks)
    utxos = state["utxos"]
    stats = state["stats"]
    tip = blocks[-1]
    root = utxo_root(utxos)
    checks = {
        "genesis_hash_matches_source": blocks[0]["hash"] == GENESIS_HASH,
        "genesis_merkle_matches_source": blocks[0]["merkle_root"] == GENESIS_MERKLE,
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
            "message_start_hex": MAGIC.hex(),
            "coin": COIN,
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
    data_hash = hashlib.sha256(canonical_bytes(report)).hexdigest()
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
    ap.add_argument("--datadir", default=default_datadir(), help="Bitflash data directory")
    ap.add_argument("--max-blocks", type=int, default=0,
                    help="number of blocks to scan; 0 means all block files")
    ap.add_argument("--include-utxos", action="store_true",
                    help="include the full sorted UTXO map in JSON output")
    ap.add_argument("--json", action="store_true", help="print canonical JSON")
    ap.add_argument("--out", help="write canonical JSON to this path")
    args = ap.parse_args(argv)

    blocks = read_blocks(args.datadir, args.max_blocks)
    if not blocks:
        raise SystemExit("no Bitflash blocks found in %s" % args.datadir)
    report = build_report(blocks, include_utxos=args.include_utxos)
    data = canonical_bytes(report)
    if args.out:
        Path(args.out).write_bytes(data)
    if args.json:
        sys.stdout.buffer.write(data)
    else:
        print_text(report)
    return 0 if report["verdict"] == "UTXO_COMMITMENT_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
