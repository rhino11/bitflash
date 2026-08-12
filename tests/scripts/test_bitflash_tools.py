#!/usr/bin/env python3
"""Regression tests for deterministic Bitflash Python tooling."""

import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
FIXTURES = ROOT / "tests" / "fixtures" / "chain-tools"
sys.path.insert(0, str(SCRIPTS))

import bitflash_chain as chain  # noqa: E402


def run(args, **kwargs):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable] + [str(a) for a in args],
        cwd=str(ROOT),
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs
    )


def write_block_file(path, blocks):
    with Path(path).open("wb") as f:
        f.write(b"noise")
        f.write(chain.MAGIC)
        f.write(struct.pack("<I", chain.MAX_BLOCK_PAYLOAD + 1))
        f.write(b"still-noise")
        for block in blocks:
            payload = chain.ser_block(block)
            f.write(chain.MAGIC)
            f.write(struct.pack("<I", len(payload)))
            f.write(payload)


def p2pkh_script(byte):
    return "76a914%s88ac" % (bytes([byte]) * 20).hex()


def make_tx(vin, vout):
    tx = {
        "version": 1,
        "vin": vin,
        "vout": vout,
        "lock_time": 0,
    }
    tx["txid"] = chain.hash_hex(chain.ser_tx(tx))
    return tx


def make_coinbase(label, script_byte, value=50 * chain.COIN):
    return make_tx(
        [{
            "prevout_hash": "0" * 64,
            "prevout_n": 0xFFFFFFFF,
            "script_sig_hex": label.encode("ascii").hex(),
            "sequence": 0xFFFFFFFF,
        }],
        [{
            "value_satoshis": value,
            "value_btf": chain.format_money(value),
            "script_pub_key_hex": p2pkh_script(script_byte),
        }],
    )


def make_spend(prev_txid, prev_n, outputs, label):
    return make_tx(
        [{
            "prevout_hash": prev_txid,
            "prevout_n": prev_n,
            "script_sig_hex": label.encode("ascii").hex(),
            "sequence": 0xFFFFFFFF,
        }],
        [{
            "value_satoshis": value,
            "value_btf": chain.format_money(value),
            "script_pub_key_hex": p2pkh_script(script_byte),
        } for value, script_byte in outputs],
    )


def make_block(prev_hash, txs, ntime, nonce):
    merkle = chain.merkle_root([tx["txid"] for tx in txs])
    header = (
        struct.pack("<i", 1)
        + bytes.fromhex(prev_hash)[::-1]
        + bytes.fromhex(merkle)[::-1]
        + struct.pack("<III", ntime, chain.GENESIS_BITS, nonce)
    )
    block = {
        "hash": chain.hash_hex(header),
        "version": 1,
        "previous_hash": prev_hash,
        "merkle_root": merkle,
        "computed_merkle_root": merkle,
        "time": ntime,
        "time_utc": chain.utc(ntime),
        "bits": "0x%08x" % chain.GENESIS_BITS,
        "nonce": nonce,
        "tx_count": len(txs),
        "transactions": txs,
        "source_file": "synthetic",
        "source_offset": 0,
        "size": 80 + len(chain.ser_compact_size(len(txs))) + sum(len(chain.ser_tx(tx)) for tx in txs),
    }
    return block


def fixture_chain():
    genesis = chain.reconstructed_genesis()
    spend1 = make_spend(
        chain.GENESIS_MERKLE,
        0,
        [(30 * chain.COIN, 0x22), (19 * chain.COIN, 0x33)],
        "spend genesis with 1 BTF fee",
    )
    block1 = make_block(
        genesis["hash"],
        [make_coinbase("fixture coinbase 1", 0x11), spend1],
        chain.GENESIS_TIME + 120,
        4001,
    )
    spend2 = make_spend(
        spend1["txid"],
        0,
        [(12 * chain.COIN, 0x44), (17 * chain.COIN + 50_000_000, 0x55)],
        "split spend with 0.5 BTF fee",
    )
    block2 = make_block(
        block1["hash"],
        [make_coinbase("fixture coinbase 2", 0x66), spend2],
        chain.GENESIS_TIME + 240,
        4002,
    )
    return [genesis, block1, block2], {
        "genesis_outpoint": "%s:0" % chain.GENESIS_MERKLE,
        "first_spend_txid": spend1["txid"],
        "proof_outpoint": "%s:1" % spend2["txid"],
    }


def compare_golden(name, actual, update):
    path = FIXTURES / name
    if update:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(actual)
        return
    # The tools promise canonical LF-terminated JSON. On Windows checkouts a
    # fixture may still appear as CRLF in the working tree; normalize only line
    # endings so content, field order and compact serialization still drift-test.
    expected = path.read_bytes().replace(b"\r\n", b"\n")
    if actual.replace(b"\r\n", b"\n") != expected:
        raise AssertionError("golden mismatch: %s" % name)


def assert_true(cond, msg):
    if not cond:
        raise AssertionError(msg)


def run_genesis_smoke():
    genesis = chain.reconstructed_genesis()
    outpoint = "%s:0" % chain.GENESIS_MERKLE

    with tempfile.TemporaryDirectory(prefix="bitflash-tool-tests-") as tmp:
        tmp = Path(tmp)
        datadir = tmp / "datadir"
        datadir.mkdir()
        blk1 = datadir / "blk0001.dat"
        blk2 = datadir / "blk0002.dat"
        write_block_file(blk1, [genesis])
        blk2.write_bytes(b"")

        fair = run([SCRIPTS / "verify-fair-launch.py", "--datadir", datadir,
                    "--max-blocks", "1", "--json"]).stdout
        fair_report = json.loads(fair)
        assert_true(fair_report["verdict"] == "FAIR_LAUNCH_BASELINE_VERIFIED",
                    "fair launch verifier failed synthetic genesis")

        utxo = run([SCRIPTS / "verify-utxo-set.py", "--datadir", datadir,
                    "--json"]).stdout
        utxo_report = json.loads(utxo)
        assert_true(utxo_report["verdict"] == "UTXO_COMMITMENT_VERIFIED",
                    "UTXO verifier failed synthetic genesis")

        proof_path = tmp / "proof.json"
        run([SCRIPTS / "prove-utxo.py", outpoint, "--datadir", datadir,
             "--out", proof_path, "--json"])
        proof_check = run([SCRIPTS / "verify-utxo-proof.py", proof_path,
                           "--root", utxo_report["commitment"]["root"], "--json"]).stdout
        proof_report = json.loads(proof_check)
        assert_true(proof_report["verdict"] == "UTXO_PROOF_VERIFIED",
                    "UTXO proof verifier rejected synthetic proof")

        explorer_dir = tmp / "explorer"
        run([SCRIPTS / "build-explorer.py", blk1, blk2, explorer_dir])
        blocks = json.loads((explorer_dir / "blocks.json").read_text(encoding="ascii"))
        assert_true(blocks["tipHeight"] == 0 and blocks["count"] == 1,
                    "explorer did not build the synthetic chain")
        index_html = (explorer_dir / "index.html").read_text(encoding="utf-8")
        assert_true("innerHTML" not in index_html, "explorer viewer still uses innerHTML")

        try:
            chain.apply_blocks([genesis, genesis], strict_duplicates=True)
        except chain.ParseError:
            pass
        else:
            raise AssertionError("strict duplicate output mode did not fail")


def run_golden_fixture(update):
    blocks, meta = fixture_chain()

    with tempfile.TemporaryDirectory(prefix="bitflash-tool-golden-") as tmp:
        tmp = Path(tmp)
        datadir = tmp / "datadir"
        datadir.mkdir()
        blk1 = datadir / "blk0001.dat"
        blk2 = datadir / "blk0002.dat"
        write_block_file(blk1, blocks[:2])
        write_block_file(blk2, blocks[2:])

        fair = run([SCRIPTS / "verify-fair-launch.py", "--datadir", datadir,
                    "--max-blocks", "3", "--json"]).stdout.encode("ascii")
        compare_golden("fair-launch-report.json", fair, update)
        fair_report = json.loads(fair)
        assert_true(fair_report["scanned"]["non_coinbase_transactions"] == 2,
                    "fair-launch fixture did not count normal transactions")

        utxo = run([SCRIPTS / "verify-utxo-set.py", "--datadir", datadir,
                    "--include-utxos", "--strict-duplicates", "--json"]).stdout.encode("ascii")
        compare_golden("utxo-report.json", utxo, update)
        utxo_report = json.loads(utxo)
        assert_true(utxo_report["stats"]["normal_transactions"] == 2,
                    "UTXO fixture did not apply normal transactions")
        assert_true(utxo_report["stats"]["total_fees_btf"] == "1.50000000",
                    "UTXO fixture fee total changed")
        assert_true(meta["genesis_outpoint"] not in utxo_report["utxos"],
                    "spent genesis output still appears in the UTXO map")

        proof_path = tmp / "fixture-proof.json"
        proof = run([SCRIPTS / "prove-utxo.py", meta["proof_outpoint"],
                     "--datadir", datadir, "--strict-duplicates",
                     "--out", proof_path, "--json"]).stdout.encode("ascii")
        compare_golden("utxo-proof.json", proof, update)

        proof_check = run([SCRIPTS / "verify-utxo-proof.py", proof_path,
                           "--root", utxo_report["commitment"]["root"], "--json"]).stdout.encode("ascii")
        compare_golden("utxo-proof-verification.json", proof_check, update)
        proof_report = json.loads(proof_check)
        assert_true(proof_report["verdict"] == "UTXO_PROOF_VERIFIED",
                    "fixture UTXO proof did not verify")

        explorer_dir = tmp / "explorer"
        run([SCRIPTS / "build-explorer.py", blk1, blk2, explorer_dir])
        compare_golden("explorer-blocks.json",
                       (explorer_dir / "blocks.json").read_bytes(), update)
        detail = json.loads((explorer_dir / "block" / "1.json").read_text(encoding="ascii"))
        assert_true(len(detail["txs"]) == 2,
                    "explorer fixture block did not include the normal transaction")


def main():
    update = "--update-goldens" in sys.argv[1:]
    run_genesis_smoke()
    run_golden_fixture(update)
    print("Bitflash script tool regressions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
