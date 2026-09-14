# Proof of work v2

Bitflash's proof of work is RandomX with the reference parameters (the ones
Monero uses, `rx/0` in miner terms). What changed in v2 is the *input* RandomX
hashes and the *key* it is initialized with. Both changed for one reason:
ordinary RandomX miners — XMRig, SRBMiner and their relatives — could not mine
v1, and the public pool had been telling people they could.

## Why

A RandomX miner is handed a *blob* by the pool, writes its nonce at **byte 39**
of that blob, hashes the whole blob, and initializes RandomX from a 32-byte
**`seed_hash`** the job carries. That is the entire protocol on the miner's
side; it does not know or care what the blob means.

v1 hashed the 80-byte block header as serialized, nonce at byte 76, keyed by
the 36-byte string `Bitflash/RandomX/v1/one-cpu-one-vote`. Byte 39 of that
header is inside the merkle root, so a miner's nonce corrupted the block; and a
36-byte key cannot be expressed as a `seed_hash`. No job could be built that
such a miner would hash the way the chain checks.

## What

Selected by the block's `nTime`, so that the hash function of a header is a
function of the header alone — `CheckBlock`, orphan handling, the miners and
the pool all decide from the same four bytes:

| | v1 | v2 |
|---|---|---|
| applies to | `nTime` < switch | `nTime` ≥ switch |
| input | header, 80 bytes, as serialized | 83 bytes, below |
| key | `"Bitflash/RandomX/v1/one-cpu-one-vote"` | SHA-256 of that string, 32 bytes |
| nonce at | 76 | 39 |

The v2 input is the same header with the nonce moved:

```
offset  size  field
 0       4    nVersion
 4      32    hashPrevBlock
36       3    zero
39       4    nNonce          <- where RandomX miners write
43      32    hashMerkleRoot
75       4    nTime
79       4    nBits
```

Every header field is covered exactly once; the three zero bytes are what it
takes to land the nonce at 39. The block on the wire, on disk and in
`GetHash()` is unchanged — only what goes into RandomX is laid out differently.

The v2 key, in hex, is what a pool sends as `seed_hash`:

```
sha256("Bitflash/RandomX/v1/one-cpu-one-vote")
```

`bitflash -selftest=pow-v2` prints nothing secret, but it does verify that a
RandomX VM built from that seed alone reproduces the consensus hash of a v2
input — which is all a third-party miner ever has.

## Switch times

| network | block time | UTC |
|---|---|---|
| mainnet | `1789992000` | 2026-09-21 12:00:00 |
| testnet | `1789419600` | 2026-09-14 21:00:00 |

A node on older code rejects every block after its network's switch as
"RandomX proof-of-work does not match nBits" and stops following the chain. A
node on this code accepts both sides and keeps one RandomX cache per version,
allocated on first use; after the switch the v1 cache is only ever needed to
verify old blocks during a fresh sync.

## What a pool sends

Bitflash's pool (`-operator`) speaks two stratum dialects on the same port.
Bitflash's own worker (`-participant`) uses the Bitcoin one, unchanged. A
miner that opens with `login` is answered in the CryptoNote one:

```json
{"id":1,"jsonrpc":"2.0","error":null,"result":{"id":"<session>","status":"OK",
 "job":{"blob":"<83 bytes hex, nonce zeroed>","job_id":"…",
        "target":"<top 64 bits of the share target, little-endian hex>",
        "algo":"rx/0","height":N,"seed_hash":"<v2 key hex>"}}}
```

New work arrives as `{"jsonrpc":"2.0","method":"job","params":{…}}`; the share
target lives in the job, so there is no `set_difficulty`. `submit` carries
`job_id`, `nonce` (the four bytes at blob offset 39, hex, in order) and
`result` (the 32-byte hash). The pool recomputes the hash; if the miner's
differs, the reply says *hash does not match* rather than *low difficulty
share*, because that is the symptom of a wrong key or layout and the user
should not go looking at their difficulty.

Before the switch, `login` is refused with an error object whose message names
the activation time. XMRig prints it and retries.

## Running your own pool for RandomX miners

Nothing beyond `-operator`. Miners on the clearnet reach it through a stratum
bridge (`-stratumbridge=POOL.btf -stratumbridgebind=0.0.0.0`) or any other
TCP-to-Tor relay pointed at the pool's onion, port p2p+1.
