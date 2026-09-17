# Multisig and pay-to-script-hash (ahead of rules v3)

1.2.28 ships the tools for multisig before the consensus rule that most of
them will lean on. What works today, what waits for the switch, and how to use
it.

## What works now: bare multisig

An output of the shape `m <key1> ... <keyn> n OP_CHECKMULTISIG` has been valid
on this chain since genesis -- `OP_CHECKMULTISIG` is in the 0.1.0 interpreter.
From 1.2.28 nodes also relay it (up to three keys) and the wallet can build,
sign and co-sign it. It has no address form, so it is paid to by raw
transaction, with the script itself as the output key.

A 2-of-3 between three parties, each holding one key:

```
# each party: a key of their own
getnewaddress                       -> B...
validateaddress B...                -> (this wallet's key; give the others its hex public key)

# anyone: the script and its hash
createmultisig 2 ["B...", "04ab...", "04cd..."]
  -> {"address": "C...", "redeemScript": "5241...53ae"}

# fund it (bare multisig, by raw transaction; the C address itself is not payable yet)
listunspent
createrawtransaction [{"txid":"...","vout":0}] {"script:5241...53ae": 1.0, "Bchange...": 48.99}
signrawtransaction <hex>
sendrawtransaction <hex>

# spend it: party 1 signs, hands the hex to party 2, who completes and sends
createrawtransaction [{"txid":"<funding>","vout":1}] {"Bdest...": 0.99}
signrawtransaction <hex>                     -> {"complete": false, ...}   (party 1)
signrawtransaction <hex-from-party-1>        -> {"complete": true,  ...}   (party 2)
sendrawtransaction <hex>
```

`signrawtransaction` keeps the signatures already in the transaction and adds
what the wallet's keys can add; the result is in key order, which is what
`OP_CHECKMULTISIG` demands. A party without a Bitflash wallet for the key can
pass it as 64 hex characters in the third argument; it is used for that call
and not stored. If the previous output is not known to the node (not in the
chain or the memory pool), give it in the second argument as
`[{"txid","vout","scriptPubKey"}]`.

Proven on testnet 2026-09-17: 1 BTF into a 2-of-3 (one key in the bench
wallet, two outside), spent with the wallet's half plus one outside key,
0.99 back, both transactions mined (heights 4343 and 4346).

## What waits: pay-to-script-hash

`createmultisig` and `addmultisigaddress` also give a `C...` address: the
Hash160 of the redeem script, the BIP16 form. Paying to it is refused --
`sendtoaddress`, `createrawtransaction`, and the relay policy all say no --
until the rules v3 switch, because before it an output of that shape is
spendable by anyone who presents the script, signatures or not. The wallet
already stores redeem scripts (`addmultisigaddress`), recognizes such outputs
as its own, and signs them against the redeem script, so the day the rule is
live nothing else needs to change. `validateaddress C...` reports `active`.

The rules v3 switch (P2SH, CLTV, CSV, sigops inside redeem scripts) is not
scheduled yet; `RULES_V3_TIME_MAINNET`/`_TESTNET` read 0 in `consensus.h`.

## RPC reference

| call | does |
|---|---|
| `createmultisig nrequired ["key",...]` | redeem script and C address; nothing stored. Keys: hex public keys, or B addresses whose key this wallet holds |
| `addmultisigaddress nrequired ["key",...] ["label"]` | same, and stores the redeem script in the wallet |
| `decodescript hex` | type, addresses, `reqSigs`, and the C address the script would have |
| `validateaddress addr` | `isscript`; for a C address whose script is held: `script`, `hex`, `addresses`, `sigsrequired`, `active` |
| `listunspent [minconf] [maxconf] [["addr",...]]` | outputs this wallet can spend, with `scriptPubKey` and `redeemScript` where held |
| `createrawtransaction [{"txid","vout"},...] {"addr"\|"script:hex": amount}` | unsigned transaction, hex |
| `decoderawtransaction hex` | the transaction as JSON |
| `getrawtransaction txid [verbose]` | from the memory pool or the chain |
| `signrawtransaction hex [prevtxs] [privkeys]` | signs what it can, merges with what is there; `complete` |
| `sendrawtransaction hex` | into the memory pool and to peers |

Amounts are in BTF. The fee is whatever the inputs exceed the outputs by;
`createrawtransaction` does not add change for you.

## Checked by

`-selftest=multisig` (36 checks): the four shapes and three malformed ones, the
C address round trip and the key-hash decoder refusing it, IsMine for 2-of-2
held and 2-of-3 not, the relay policy (three keys yes, four no, script hash
no, three signatures fit), a 2-of-3 signed by one wallet, signed in two halves
and combined, halves out of key order put right, and a script-hash spend
signed against the redeem script that today's rule accepts with the script
alone and the rules v3 check refuses.
