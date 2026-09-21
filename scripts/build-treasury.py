#!/usr/bin/env python3
"""The treasury ledger, read from the chain.

Scans the local blk*.dat files for every output that pays the treasury's
multisig script and every input that spends one, and writes one JSON file:
the balance, what came in and from what kind of transaction, what went out
and where, block by block. This is what bitflash.network/treasury shows, and
what anyone can regenerate from their own node to check that the page tells
the truth:

    build-treasury.py --datadir ~/.bitflash --script <hex> treasury.json
    build-treasury.py --datadir ~/.bitflash --script <hex> --verify treasury.json

The script hex is `gettreasuryinfo` -> script.hex, or docs/treasury.md. With
--verify, the file is compared against the chain instead of written, and the
exit code says whether they agree (the page can be an older tip; every
movement it lists must still be on the chain, and the balance at its tip
must match).
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import bitflash_chain as chain

TESTNET_MAGIC = bytes([0xCE, 0xE2, 0xC0, 0xFF])
TESTNET_GENESIS_HASH = "a9d11c6d697bcb7aea0653bc088b12dcf9f44e732df205162cf085fd9d9963eb"

ADDRESS_VERSION = 25
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    v = bytes([ADDRESS_VERSION]) + payload
    v += chain.sha256d(v)[:4]
    n = int.from_bytes(v, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = B58[r] + s
    for byte in v:
        if byte == 0:
            s = "1" + s
        else:
            break
    return s


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def describe_output(spk_hex, treasury_hex):
    """Where an output goes, for the spend side of the ledger."""
    if spk_hex == treasury_hex:
        return {"type": "treasury"}
    spk = bytes.fromhex(spk_hex)
    if len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xA9 and spk[2] == 0x14 and spk[23] == 0x88 and spk[24] == 0xAC:
        return {"type": "p2pkh", "address": b58check(spk[3:23])}
    if len(spk) == 67 and spk[0] == 0x41 and spk[-1] == 0xAC:
        return {"type": "p2pk", "address": b58check(hash160(spk[1:66]))}
    if len(spk) == 35 and spk[0] == 0x21 and spk[-1] == 0xAC:
        return {"type": "p2pk", "address": b58check(hash160(spk[1:34]))}
    if spk and spk[0] == 0x6A:
        return {"type": "op_return"}
    if spk and spk[-1] == 0xAE:
        return {"type": "multisig"}
    return {"type": "other"}


def parse_script(hex_script):
    """The treasury script must be a bare m-of-n; returns (m, n, [pubkeys hex])."""
    try:
        s = bytes.fromhex(hex_script)
    except ValueError:
        raise SystemExit("--script: not hex")
    if len(s) < 3 or s[-1] != 0xAE or not (0x51 <= s[0] <= 0x60) or not (0x51 <= s[-2] <= 0x60):
        raise SystemExit("--script: not a bare m-of-n multisig")
    m, n = s[0] - 0x50, s[-2] - 0x50
    keys = []
    i = 1
    while i < len(s) - 2:
        ln = s[i]
        if ln not in (33, 65) or i + 1 + ln > len(s) - 2:
            raise SystemExit("--script: a push in it is not a public key")
        keys.append(s[i + 1:i + 1 + ln].hex())
        i += 1 + ln
    if len(keys) != n or m < 1 or m > n:
        raise SystemExit("--script: key count does not match n")
    return m, n, keys


def scan(blocks, treasury_hex):
    """Every movement of the treasury, in chain order, and the open outputs."""
    utxos = {}      # outpoint -> value
    movements = []
    received = spent = 0
    by_kind = {"coinbase": 0, "transfer": 0}
    for height, block in enumerate(blocks):
        for tx in block["transactions"]:
            coinbase = chain.is_coinbase(tx)
            # spends first: a transaction may take from the treasury and pay
            # part of it back (change), and the ledger shows both
            if not coinbase:
                taken = 0
                for txin in tx["vin"]:
                    key = "%s:%d" % (txin["prevout_hash"], txin["prevout_n"])
                    v = utxos.pop(key, None)
                    if v is not None:
                        taken += v
                if taken:
                    outs = []
                    back = 0
                    for out in tx["vout"]:
                        d = describe_output(out["script_pub_key_hex"], treasury_hex)
                        if d["type"] == "treasury":
                            back += out["value_satoshis"]
                            continue
                        d["value"] = out["value_satoshis"]
                        outs.append(d)
                    net = taken - back
                    spent += net
                    movements.append({
                        "kind": "spend",
                        "height": height,
                        "time": block["time"],
                        "txid": tx["txid"],
                        "amount": -net,
                        "to": outs,
                    })
            for n, out in enumerate(tx["vout"]):
                if out["script_pub_key_hex"] != treasury_hex:
                    continue
                v = out["value_satoshis"]
                utxos["%s:%d" % (tx["txid"], n)] = v
                kind = "coinbase" if coinbase else "transfer"
                # change of a spend is not income; the spend above already
                # netted it out
                if not coinbase and any(mv["txid"] == tx["txid"] and mv["kind"] == "spend" for mv in movements[-1:]):
                    continue
                received += v
                by_kind[kind] += v
                movements.append({
                    "kind": kind,
                    "height": height,
                    "time": block["time"],
                    "txid": tx["txid"],
                    "vout": n,
                    "amount": v,
                })
    return movements, utxos, received, spent, by_kind


def build(args):
    if args.testnet:
        chain.MAGIC = TESTNET_MAGIC
        chain.GENESIS_HASH = TESTNET_GENESIS_HASH
    m, n, keys = parse_script(args.script)
    blocks = chain.read_blocks(args.datadir, 0)
    try:
        main = chain.select_main_chain(blocks)
    except chain.ParseError as e:
        raise SystemExit(str(e))
    movements, utxos, received, spent, by_kind = scan(main, args.script)
    if args.notes:
        # {txid: "why"}: the reason next to a spend, or a name next to a
        # contribution that asked for one. Kept by hand, never on the chain.
        notes = json.load(open(args.notes, encoding="utf-8"))
        for mv in movements:
            if mv["txid"] in notes:
                mv["note"] = str(notes[mv["txid"]])[:200]
    balance = sum(utxos.values())
    assert balance == received - spent, (balance, received, spent)
    tip = main[-1]
    return {
        "network": "bitflash-testnet" if args.testnet else "bitflash",
        "script": args.script,
        "required": m,
        "keys": keys,
        "tipHeight": len(main) - 1,
        "tipHash": tip["hash"],
        "tipTime": tip["time"],
        "generatedAt": int(time.time()),
        "balance": balance,
        "received": received,
        "spent": spent,
        "receivedByKind": by_kind,
        "utxoCount": len(utxos),
        "goal": int(round(args.goal * chain.COIN)) if args.goal else None,
        "movements": movements,
    }


def verify(args, path):
    """The page's file against this node's chain."""
    mine = build(args)
    theirs = json.load(open(path, encoding="utf-8"))
    problems = []
    for k in ("network", "script", "required", "keys"):
        if theirs.get(k) != mine[k]:
            problems.append("%s differs: page %r, chain %r" % (k, theirs.get(k), mine[k]))
    th = theirs.get("tipHeight", -1)
    if th > mine["tipHeight"]:
        problems.append("the page is at height %d, this node only at %d: let it sync" % (th, mine["tipHeight"]))
    else:
        mine_up_to = [mv for mv in mine["movements"] if mv["height"] <= th]
        theirs_mv = theirs.get("movements", [])
        if len(mine_up_to) != len(theirs_mv):
            problems.append("%d movements on the page, %d on the chain up to height %d" % (len(theirs_mv), len(mine_up_to), th))
        for a, b in zip(theirs_mv, mine_up_to):
            for k in ("kind", "height", "txid", "amount"):
                if a.get(k) != b.get(k):
                    problems.append("movement at height %s differs on %s: page %r, chain %r" % (a.get("height"), k, a.get(k), b.get(k)))
                    break
        bal = sum(mv["amount"] for mv in mine_up_to)
        if theirs.get("balance") != bal:
            problems.append("balance at height %d: page %s, chain %s" % (th, theirs.get("balance"), bal))
    if problems:
        print("MISMATCH")
        for p in problems:
            print("  " + p)
        return 1
    print("ok: %s agrees with this node's chain up to height %d: balance %s BTF, %d movements"
          % (path, th, chain.format_money(theirs.get("balance", 0)), len(theirs.get("movements", []))))
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--datadir", default=chain.default_datadir(), help="Bitflash data directory containing blk*.dat")
    ap.add_argument("--script", required=True, help="the treasury output script, hex (gettreasuryinfo -> script.hex)")
    ap.add_argument("--testnet", action="store_true", help="the data directory holds the test chain")
    ap.add_argument("--goal", type=float, default=0.0, help="the goal, in BTF, written into the file for the page to show")
    ap.add_argument("--notes", default=None, help="JSON file {txid: note}: reasons for spends, names for donors who asked")
    ap.add_argument("--verify", action="store_true", help="check FILE against the chain instead of writing it")
    ap.add_argument("file", help="the JSON file to write (or, with --verify, to check)")
    args = ap.parse_args(argv)
    if args.verify:
        return verify(args, args.file)
    report = build(args)
    tmp = args.file + ".tmp"
    with open(tmp, "w", encoding="ascii") as f:
        json.dump(report, f, sort_keys=True, separators=(",", ":"))
        f.write("\n")
    os.replace(tmp, args.file)
    print("treasury at height %d: balance %s BTF (%s in, %s out), %d movements -> %s"
          % (report["tipHeight"], chain.format_money(report["balance"]), chain.format_money(report["received"]),
             chain.format_money(report["spent"]), len(report["movements"]), args.file))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
