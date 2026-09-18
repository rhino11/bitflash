# Consensus rules v2

Bitflash forked Bitcoin 0.1.0, and 0.1.0 is where Satoshi's own hardening of
2010 had not happened yet. Rules v2 brings the consensus rules Bitcoin adopted
after that, in one switch, by block time — the same shape as
[PoW v2](pow-v2.md), and on mainnet the same moment, so a node updates once.

| network | block time | UTC |
|---|---|---|
| mainnet | `1789992000` | 2026-09-21 12:00:00 |
| testnet | `1789570800` | 2026-09-16 15:00:00 |

Every rule below is stricter than what it replaces: a block valid under v2 is
valid under the old rules, never the reverse. A node still on the old rules
accepts blocks a v2 node rejects, which is why every node has to be on this
code before the switch. Nothing on either chain before the switch changes
validity; the existing chain syncs unchanged.

## Signatures: strict DER, low S

Before: a signature was whatever OpenSSL's parser would accept, and how much
that is has changed between OpenSSL versions. Two nodes linked against
different versions could disagree on whether a block was valid — that is what
split Bitcoin in July 2015 (BIP66 was the fix). And every ECDSA signature has a
twin, `S' = n − S`, that verifies against the same key and hash; anyone
relaying a transaction could swap them and change its txid in flight.

From the switch, a signature must be exactly:

```
0x30 [total] 0x02 [len R] [R] 0x02 [len S] [S] [hashtype]
```

with R and S positive and minimally encoded, and `S ≤ n/2`. The check is byte
by byte, not a parser's opinion. The wallet has produced low-S signatures since
1.2.26 regardless of the switch; a low-S signature was always valid.

## Coinbase carries the height (BIP34); no unspent duplicate txids (BIP30)

Two coinbases that pay the same key the same amount are byte-identical, so the
second has the txid of the first — and its index entry overwrote the first's,
taking the first's unspent outputs with it. From the switch the coinbase
scriptSig must begin with the block height, serialized as the script
interpreter serializes numbers, which makes every coinbase distinct. Both
miners in this tree (solo and pool) have written it that way since before the
switch. And a transaction whose txid already exists in the index with an
unspent output is refused outright.

## The retarget window measures what it divides by

Difficulty is recomputed every 30 blocks from how long the last 30 took. The
0.1.0 code walked back 29 blocks, so it measured 29 intervals and divided by
30 — the block on the boundary was counted by neither window. That gap is the
lever of the time-warp attack, and with a 30-block window it is a
proportionally larger lever than Bitcoin's. From the switch the window is the
full 30.

## Not consensus, in effect since 1.2.26

**Peers may nudge the clock, not set it.** The node keeps a median of the time
offsets its peers report and adds it to its own clock. 0.1.0 had no bound on
that median. Past 70 minutes it is now dropped, with a warning: a node that
far from its peers has a clock to fix, and a node whose peers can set its time
can be handed blocks it must reject and shown a fork as the best chain.

**Relay policy.** A transaction is held and passed on only if it is under
100 kB, its scriptSigs are pushes of a sane length, and its outputs are one of
the two scripts this network has ever used — pay-to-pubkey-hash or
pay-to-pubkey. The pool holds at most 5,000 transactions; past that only one
paying the base fee gets in. None of this is consensus: a block may still
carry anything the rules above allow.

## Checked by

`bitflash -selftest=rules-v2`: the wallet's signatures (200 of 200 low S and
strict DER), the high-S twin accepted by ECDSA and by the old rules and refused
by v2, two malformed DER shapes, the coinbase prefix with and without the
height, a synthetic chain whose boundary interval only the v2 window sees, the
four non-standard shapes the relay policy refuses, and five peers five hours
ahead moving the clock by nothing.
