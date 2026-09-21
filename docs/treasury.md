# The treasury

A community fund for one purpose -- the first exchange listing -- held in a
bare 2-of-3 multisig on the chain, with its balance and every movement read
from the blocks at [bitflash.network/treasury](https://bitflash.network/treasury).
This page is the charter: what the fund is, who holds the keys, the rules
they signed, and how to check all of it without trusting any of them.

## What it is

Bitflash has no company and no premine. An exchange listing costs money the
project does not have, so the people who mine and hold BTF pay for it, into an
output that no one person can spend:

```
2 <key1> <key2> <key3> 3 OP_CHECKMULTISIG
```

That shape has been valid on this chain since genesis; nothing in consensus
changed for it. The three public keys are compiled into the node
(`src/treasury.cpp`), printed by `gettreasuryinfo`, shown on the page, and
listed below. Four copies from four places: if any two disagree, something is
wrong, and anyone can see it.

It is not an investment and owes no one anything. A contribution is a
donation to a piece of free software, with one difference from the usual
kind: you can watch it, block by block, and see that it was not taken.

## Where the money comes from

Three ways, all opt-in, none in consensus. A node that has never heard of the
treasury relays its outputs like any other multisig.

| way | how | what it does |
|---|---|---|
| donation | *Send Coins* → *Donate to the Bitflash treasury*; `donate <amount>`; `sendtoaddress treasury <amount>`; `{"treasury": amount}` in `createrawtransaction` | one output to the script |
| solo miner's share | `-treasuryshare=PCT` (0-50), or the slider under *Options → Solo* | the coinbase gets a second output of that percent; the block is worth exactly what it was |
| pool fee | `-poolfeeto=treasury`, or the checkbox next to the fee under *Options → Operator* | the operator's cut of each round is paid to the script with the miners' payouts, recorded and recovered like theirs |

`gettreasuryinfo` shows what this node is configured to do. The word
`treasury` is understood wherever an address is taken, so no one has to paste
a script.

## Rules of spending

1. **Only the stated goal.** Nothing leaves for anything the page does not
   name as the current goal. When the goal is paid, the next one is written
   there before a satoshi moves toward it.
2. **Announced first, seven days ahead.** Exchange, amount, destination
   address and invoice are posted on the Discord and in the page's ledger
   before anyone signs.
3. **Two named holders sign,** and the announcement says which two.
4. **Never to a holder.** No key holder's own address is ever a destination,
   including as change.
5. **Everything shows up on the page,** in the block it lands in, with its
   reason next to it.
6. **Not refundable.** A donation is a donation. If the goal is never reached
   the coins stay where they are, visible, until it is.
7. **A holder who goes quiet** for 90 days is replaced: the other two sign a
   move to a new 2-of-3, announced like any spend, and this file changes with
   it.

What the rules cannot do is stop two holders from colluding. That is why they
are three named people in different places and not the founder twice, and
why every spend is announced before it is signed: a spend that was not
announced is one everyone sees for what it is.

## Who holds the keys

Mainnet: **not configured yet.** `MAINNET_KEYS` in `src/treasury.cpp` is
empty, `gettreasuryinfo` says `configured: false`, and every path that would
pay the treasury refuses. The keys go in the day the three holders have
generated them on machines of their own (`getnewaddress`, then
`validateaddress` for the public key) and their names are in this table:

| key | holder | where |
|---|---|---|
| 1 | the founder | Brazil |
| 2 | to be named: a community member, not the founder | |
| 3 | to be named: a community member, not the founder, another country | |

Testnet is configured, with test keys: one in the bench wallet, one in the 202
test node, one made with openssl and kept outside any wallet. Test coins only.

A holder is a person people can reach, who keeps the key on a machine of
their own, holds none of the coins, and signs with `signrawtransaction`. This
file is signed with the release key when the holders are named
(`docs/treasury.md.asc`), so the table cannot be changed without the key that
signs releases.

## Spending, step by step

Any holder builds the transaction; two sign; anyone sends. The previous
outputs are in the page's `treasury.json` (`txid`, `vout`) and the script hex
is `gettreasuryinfo` → `script.hex`.

```
createrawtransaction [{"txid":"<in>","vout":n}] {"B<exchange>": 1000, "treasury": 234.99}
signrawtransaction <hex> [{"txid":"<in>","vout":n,"scriptPubKey":"<script hex>"}]
    -> complete: false                                            (holder 1)
signrawtransaction <hex-from-holder-1> [{...same prevtx...}]
    -> complete: true                                             (holder 2)
sendrawtransaction <hex>
```

Change goes back to `treasury` (rule 4). A holder without a Bitflash wallet
for the key passes it as the third argument, 64 hex characters, used for that
call and not stored. `docs/multisig.md` has the whole raw-transaction RPC.

Proven on testnet 2026-09-21: 7.5 BTF donated by `donate`, 2.25 by
`sendtoaddress treasury`, 5 BTF per block from a solo miner on
`-treasuryshare=10` (block 6915 onward: coinbase 45 to the miner, 5 to the
script), and 7.49 BTF spent from the script with key 1 (bench wallet) and key
3 (openssl, passed to `signrawtransaction`), all on the page's ledger.

## Verify it yourself

The page is a reading of the chain that any node can repeat.

```
# the script and the keys, from a node 1.2.29 or later
gettreasuryinfo

# the same keys, from the source
grep -A3 MAINNET_KEYS src/treasury.cpp

# the ledger the page shows, against your own block files
curl -O https://status.bitflash.network/treasury.json
python3 scripts/build-treasury.py --datadir ~/.bitflash --script <script hex> --verify treasury.json
# ok: treasury.json agrees with this node's chain up to height N: balance X BTF, M movements
```

`build-treasury.py` without `--verify` writes that file from your own chain,
which is exactly what the status daemon does every block for the page. The
notes next to movements (the reason for a spend, a name a donor asked for)
are the one thing not on the chain; they are kept by hand in a file the
script merges in, and they never change a number.

## What runs where

- **Node** (`src/treasury.h`, `src/treasury.cpp`): the keys per network,
  `treasury::Script()`, `IsTreasury()`, `ShareOf()`; `-treasuryshare`,
  `-poolfeeto`; the coinbase split in `CreateNewBlock`; the pool round's
  `treasury` recipient in `QueuePayouts`; `donate`, `gettreasuryinfo`, and
  the word `treasury` in `ScriptForAddress`; the *Send Coins* button and the
  two *Options* controls. `-selftest=treasury` (20 checks).
- **Ledger** (`scripts/build-treasury.py`): scans `blk*.dat`, writes or
  verifies `treasury.json`. On the 202, `treasury-refresh.service` runs it
  when the block file changes and the status daemon serves the result at
  `/treasury.json` (`--publish`), cross-origin, no cache.
- **Page** (site repository, `crates/site/src/treasury.rs` and
  `treasury.js`): the charter and the slots the script fills every 30 s.
- **Explorer**: labels the treasury's outputs `treasury` (`--treasury <hex>`)
  and opens a block from `#block/N`, which is where the ledger's rows link.
