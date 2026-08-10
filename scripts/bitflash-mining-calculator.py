#!/usr/bin/env python3
"""Estimate Bitflash mining rewards and electricity cost.

This is a local WhatToMine-style calculator for Bitflash. It does not fetch
prices, does not talk to the node, and does not affect consensus.
"""

import argparse
import json
import math
import sys


HASHES_AT_DIFF_1 = 4096.0
DEFAULT_BLOCK_TIME = 120.0
DEFAULT_BLOCK_REWARD = 50.0


UNITS = {
    "h": 1.0,
    "h/s": 1.0,
    "hs": 1.0,
    "kh": 1_000.0,
    "kh/s": 1_000.0,
    "khs": 1_000.0,
    "mh": 1_000_000.0,
    "mh/s": 1_000_000.0,
    "mhs": 1_000_000.0,
    "gh": 1_000_000_000.0,
    "gh/s": 1_000_000_000.0,
    "ghs": 1_000_000_000.0,
}


def parse_hashrate(value, unit):
    try:
        n = float(value)
    except ValueError:
        raise SystemExit("invalid hashrate: %s" % value)
    mul = UNITS.get(unit.lower())
    if mul is None:
        raise SystemExit("unknown hashrate unit: %s" % unit)
    if n < 0:
        raise SystemExit("hashrate must not be negative")
    return n * mul


def fmt_hashrate(hps):
    units = [("GH/s", 1_000_000_000.0), ("MH/s", 1_000_000.0), ("kH/s", 1_000.0), ("H/s", 1.0)]
    for name, div in units:
        if hps >= div:
            return "%.4g %s" % (hps / div, name)
    return "%.4g H/s" % hps


def fmt_money(x):
    return "%.8f" % x


def estimate(args):
    miner_hps = parse_hashrate(args.hashrate, args.hashrate_unit)
    if args.network_hashrate is not None:
        network_hps = parse_hashrate(args.network_hashrate, args.network_hashrate_unit)
        difficulty = network_hps * args.block_time / HASHES_AT_DIFF_1
        network_source = "network_hashrate"
    else:
        if args.difficulty is None:
            raise SystemExit("provide either --network-hashrate or --difficulty")
        difficulty = float(args.difficulty)
        if difficulty <= 0:
            raise SystemExit("difficulty must be positive")
        network_hps = difficulty * HASHES_AT_DIFF_1 / args.block_time
        network_source = "difficulty"

    if network_hps <= 0:
        raise SystemExit("network hashrate must be positive")

    block_reward = float(args.block_reward)
    block_time = float(args.block_time)
    pool_fee_percent = float(args.pool_fee)
    price = float(args.price)
    watts = float(args.watts)
    kwh_cost = float(args.kwh_cost)
    if block_reward < 0 or block_time <= 0 or pool_fee_percent < 0 or price < 0 or watts < 0 or kwh_cost < 0:
        raise SystemExit("numeric inputs must be non-negative; block time must be positive")

    share = miner_hps / network_hps
    blocks_per_day = 86400.0 / block_time
    gross_btf_day = blocks_per_day * block_reward * share
    net_btf_day = gross_btf_day * max(0.0, 1.0 - pool_fee_percent / 100.0)
    revenue_day = net_btf_day * price
    cost_day = watts / 1000.0 * 24.0 * kwh_cost
    profit_day = revenue_day - cost_day
    expected_seconds_per_block = math.inf if miner_hps <= 0 else difficulty * HASHES_AT_DIFF_1 / miner_hps

    periods = {
        "hour": 1.0 / 24.0,
        "day": 1.0,
        "week": 7.0,
        "month_30d": 30.0,
    }
    rows = {}
    for name, days in periods.items():
        rows[name] = {
            "btf": net_btf_day * days,
            "revenue": revenue_day * days,
            "electricity_cost": cost_day * days,
            "profit": profit_day * days,
        }

    return {
        "schema": "bitflash-mining-calculator-1",
        "network_source": network_source,
        "inputs": {
            "miner_hashrate_hps": miner_hps,
            "miner_hashrate": fmt_hashrate(miner_hps),
            "network_hashrate_hps": network_hps,
            "network_hashrate": fmt_hashrate(network_hps),
            "difficulty": difficulty,
            "block_time_seconds": block_time,
            "block_reward_btf": block_reward,
            "pool_fee_percent": pool_fee_percent,
            "price_per_btf": price,
            "power_watts": watts,
            "electricity_per_kwh": kwh_cost,
        },
        "estimates": {
            "miner_network_share": share,
            "blocks_per_day": blocks_per_day,
            "expected_time_to_solo_block_seconds": expected_seconds_per_block,
            "expected_time_to_solo_block_hours": expected_seconds_per_block / 3600.0,
            "gross_btf_per_day": gross_btf_day,
            "net_btf_per_day": net_btf_day,
            "periods": rows,
        },
    }


def print_text(result):
    i = result["inputs"]
    e = result["estimates"]
    print("Bitflash mining calculator")
    print("schema: %s" % result["schema"])
    print()
    print("Network")
    print("  source:      %s" % result["network_source"])
    print("  hashrate:    %s" % i["network_hashrate"])
    print("  difficulty:  %.8f" % i["difficulty"])
    print("  block time:  %.0fs" % i["block_time_seconds"])
    print("  reward:      %s BTF" % fmt_money(i["block_reward_btf"]))
    print()
    print("Miner")
    print("  hashrate:    %s" % i["miner_hashrate"])
    print("  share:       %.8f%%" % (e["miner_network_share"] * 100.0))
    if math.isinf(e["expected_time_to_solo_block_seconds"]):
        print("  solo block:  never")
    else:
        print("  solo block:  %.2f hours expected average" % e["expected_time_to_solo_block_hours"])
    print()
    print("Economics")
    print("  price:       $%.8f / BTF" % i["price_per_btf"])
    print("  power:       %.2f W" % i["power_watts"])
    print("  kWh cost:    $%.4f" % i["electricity_per_kwh"])
    print("  pool fee:    %.2f%%" % i["pool_fee_percent"])
    print()
    print("Estimated rewards")
    print("  %-9s %16s %12s %12s %12s" % ("period", "BTF", "revenue", "power", "profit"))
    for name in ["hour", "day", "week", "month_30d"]:
        row = e["periods"][name]
        print("  %-9s %16s $%11.4f $%11.4f $%11.4f" % (
            name,
            fmt_money(row["btf"]),
            row["revenue"],
            row["electricity_cost"],
            row["profit"],
        ))
    print()
    print("Note: this is an expectation, not a promise. Solo mining variance can be huge.")


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hashrate", required=True, help="miner hashrate number")
    ap.add_argument("--hashrate-unit", default="kh/s", choices=sorted(UNITS), help="miner hashrate unit")
    ap.add_argument("--network-hashrate", help="network hashrate number")
    ap.add_argument("--network-hashrate-unit", default="kh/s", choices=sorted(UNITS), help="network hashrate unit")
    ap.add_argument("--difficulty", type=float, help="Bitflash difficulty; diff 1 expects 4096 hashes")
    ap.add_argument("--block-time", type=float, default=DEFAULT_BLOCK_TIME, help="target block time in seconds")
    ap.add_argument("--block-reward", type=float, default=DEFAULT_BLOCK_REWARD, help="block reward in BTF")
    ap.add_argument("--pool-fee", type=float, default=0.0, help="pool fee percent")
    ap.add_argument("--price", type=float, default=0.0, help="price per BTF in USD or your chosen fiat unit")
    ap.add_argument("--watts", type=float, default=0.0, help="miner or whole-system power in watts")
    ap.add_argument("--kwh-cost", type=float, default=0.0, help="electricity cost per kWh")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args(argv)

    result = estimate(args)
    if args.json:
        print(json.dumps(result, sort_keys=True, indent=2))
    else:
        print_text(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
