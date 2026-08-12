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


def assert_true(cond, msg):
    if not cond:
        raise AssertionError(msg)


def main():
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

    print("Bitflash script tool regressions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
