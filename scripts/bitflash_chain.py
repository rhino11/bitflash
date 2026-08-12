#!/usr/bin/env python3
"""Shared Bitflash block/chain parser for deterministic audit tools."""

import datetime as _dt
import hashlib
import json
import mmap
import os
import struct
from pathlib import Path


MAGIC = bytes([0xBF, 0x20, 0x5C, 0xFD])
MAX_BLOCK_PAYLOAD = 32 * 1024 * 1024
UTXO_LEAF_DOMAIN = "BTFUTXO1"
UTXO_NODE_DOMAIN_TAG = "BTFNODE1"
UTXO_NODE_DOMAIN = (UTXO_NODE_DOMAIN_TAG + "|").encode("ascii")
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
    start = r.pos
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
        "size": len(payload),
    }


def iter_block_files(datadir):
    for path in sorted(Path(datadir).glob("blk*.dat")):
        yield path


def iter_blocks_from_file(path):
    path = Path(path)
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        if file_size == 0:
            return
        f.seek(0)
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            pos = 0
            while True:
                offset = mm.find(MAGIC, pos)
                if offset < 0 or offset + 8 > file_size:
                    break
                size = struct.unpack("<I", mm[offset + 4:offset + 8])[0]
                payload_offset = offset + 8
                end = payload_offset + size
                if size == 0 or size > MAX_BLOCK_PAYLOAD or end > file_size:
                    pos = offset + 1
                    continue
                payload = mm[payload_offset:end]
                try:
                    yield parse_block(payload, path.name, payload_offset)
                except ParseError:
                    pos = offset + 1
                    continue
                pos = end
        finally:
            mm.close()


def read_blocks_from_files(paths, max_blocks=0):
    blocks = []
    for path in paths:
        for block in iter_blocks_from_file(path):
            blocks.append(block)
            if max_blocks and len(blocks) >= max_blocks:
                return blocks
    return blocks


def read_blocks(datadir, max_blocks=0):
    return read_blocks_from_files(iter_block_files(datadir), max_blocks)


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
    payload = "|".join([
        UTXO_LEAF_DOMAIN,
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
            nxt.append(sha256(UTXO_NODE_DOMAIN + left + right))
        layer = nxt
    return layer[0].hex()


def apply_blocks(blocks, strict_duplicates=False):
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
        for tx in block["transactions"]:
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
                    if strict_duplicates:
                        raise ParseError("duplicate output at height %d: %s" % (height, key))
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
        "size": 80 + len(ser_compact_size(1)) + len(ser_tx(tx)),
    }


def ser_block(block):
    header = (
        struct.pack("<i", block["version"])
        + bytes.fromhex(block["previous_hash"])[::-1]
        + bytes.fromhex(block["merkle_root"])[::-1]
        + struct.pack("<III", block["time"], int(block["bits"], 16), block["nonce"])
    )
    txs = block["transactions"]
    return header + ser_compact_size(len(txs)) + b"".join(ser_tx(tx) for tx in txs)


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
