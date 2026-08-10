# Bitflash mining calculator

`scripts/bitflash-mining-calculator.py` is a local WhatToMine-style calculator
for Bitflash.

It does not fetch market prices, does not talk to exchanges, and does not
change consensus. Price is a manual input until Bitflash has a reliable public
market.

## Examples

Estimate from network hashrate:

```bash
python3 scripts/bitflash-mining-calculator.py \
  --hashrate 21 --hashrate-unit kh/s \
  --network-hashrate 1.56 --network-hashrate-unit mh/s \
  --watts 140 --kwh-cost 0.10 \
  --price 0.001 --pool-fee 1
```

Estimate from Bitflash difficulty:

```bash
python3 scripts/bitflash-mining-calculator.py \
  --hashrate 21 --hashrate-unit kh/s \
  --difficulty 45600 \
  --watts 140 --kwh-cost 0.10
```

Machine-readable output:

```bash
python3 scripts/bitflash-mining-calculator.py \
  --hashrate 21 --hashrate-unit kh/s \
  --network-hashrate 1.56 --network-hashrate-unit mh/s \
  --json
```

## Bitflash Difficulty Scale

Bitflash does not use Bitcoin's SHA256 difficulty-1 constant for pool shares.
The chain's easiest RandomX target is `bnProofOfWorkLimit = ~uint256(0) >> 12`,
so difficulty 1 expects about `4096` hashes.

The calculator uses:

```text
network_hashrate = difficulty * 4096 / block_time_seconds
```

At the default two-minute block target:

```text
network_hashrate = difficulty * 4096 / 120
```

If you already know network hashrate, pass `--network-hashrate` directly and
the script derives the equivalent Bitflash difficulty for display.

## Reward Estimate

The expected daily reward is:

```text
blocks_per_day = 86400 / block_time_seconds
miner_share = miner_hashrate / network_hashrate
gross_btf_per_day = blocks_per_day * block_reward * miner_share
net_btf_per_day = gross_btf_per_day * (1 - pool_fee_percent / 100)
```

Electricity is:

```text
electricity_per_day = watts / 1000 * 24 * kwh_cost
```

This is an expectation, not a promise. Solo mining variance can be very large,
especially when the miner has a small share of the network.

## Future Website Use

The script is intentionally standalone so the same math can later back a
website widget or status dashboard. Until a public price exists, a website
calculator should keep price as a manual field and label fiat profit as
speculative.
