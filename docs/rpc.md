# JSON-RPC

The interface an exchange, a payment processor or a block explorer integrates a
coin through. It is shaped like `bitcoind`'s — same method names, same
arguments, same result fields — so an integration written for any
Bitcoin-derived coin works here unchanged.

Bitcoin 0.1.0 had no RPC; it arrived in 0.3.x and this tree never inherited it.
Until 1.2.23 there was no way for anybody else's software to run a Bitflash
wallet: no deposit address per user, no way to notice a deposit had landed, no
way to pay a withdrawal.

## Starting it

Nothing listens unless both credentials are given:

```bash
bitflash-node -nogui -datadir=/var/lib/bitflash \
  -rpcuser=exchange -rpcpassword='a long random string, sixteen characters at least'
```

- Binds **127.0.0.1 only**. There is no option to bind wider, on purpose: the
  daemon runs on the machine that talks to it, and a wallet that spends on
  command should not be reachable from the network.
- Port `8432` on mainnet, `18432` on testnet, or `-rpcport=N`.
- Every request needs HTTP Basic credentials. A wrong password gets `401` and a
  quarter-second pause, and the comparison is constant-time.
- `-rpcpassword` shorter than sixteen characters is refused.
- `-rpcpassword=@FILE` reads the secret from a file, so it never appears in
  the process list. Prefer it on any machine other people can log into.

## Calling it

JSON-RPC 1.0 over HTTP `POST /`. Batches (a JSON array of requests) are
accepted and answered in order.

```bash
curl -u exchange:SECRET -H 'Content-Type: application/json' \
  -d '{"id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:8432/
```

```json
{"id":1,"result":31770,"error":null}
```

Errors come back as `{"code":-1,"message":"..."}` in `error`, with `result`
null.

## Methods

| method | arguments | returns |
|---|---|---|
| `getinfo` | — | version, protocol, `blocks`, `connections`, `balance`, `testnet`, `walletlocked` |
| `getblockcount` | — | height of the best chain |
| `getblockhash` | `height` | block hash at that height |
| `getblock` | `hash` | height, confirmations, time, merkle root, `tx` (txids), prev/next hash |
| `getnewaddress` | — | a fresh receiving address, one per call |
| `validateaddress` | `address` | `isvalid`, and `ismine` when it is |
| `getbalance` | `[minconf=1]` | spendable balance, excluding immature mining rewards |
| `sendtoaddress` | `address`, `amount` | txid of the transaction it created and broadcast |
| `gettransaction` | `txid` | amount, confirmations, block, `details` per output |
| `listtransactions` | `[count=10]` | the last `count` wallet transactions, oldest first |
| `listsinceblock` | `[blockhash]` | every wallet transaction in blocks after that one, plus unconfirmed, and `lastblock` |

`amount` and `balance` are BTF as JSON numbers. `sendtoaddress` accepts the
amount as a number or as a string.

## The loop an exchange runs

1. `getnewaddress` once per user, stored against the account.
2. `listsinceblock <last seen block>` on a timer. Credit each `receive` entry
   once `confirmations` reaches the number you trust; store the returned
   `lastblock` and pass it next time.
3. `sendtoaddress` for withdrawals; keep the txid and confirm it with
   `gettransaction`.

`details[].category` tells the kinds apart: `receive`, `send`, and for mining
rewards `immature` until they can be spent and `generate` after. An exchange
should not credit `immature`.

Change is never listed. In a transaction this wallet funded, its own outputs
are change, not receipts, and they do not appear under `receive` -- so summing
the `receive` entries to credit deposits is safe. The transaction's `amount` is
still the wallet's net, change included.

Addresses from `getnewaddress` come from the HD key pool and are covered by the
wallet's recovery phrase. A wallet restored from its phrase gets every deposit
address it ever handed out.

## Confirmations to trust

Blocks arrive every two minutes and the retarget is every thirty, so the chain
reacts fast to hashrate arriving or leaving. Ten confirmations is twenty
minutes; that is a reasonable floor for a young network. Coinbase maturity is
120 blocks.

## What it does not do

No `walletpassphrase` — if the wallet is encrypted, start the node with the
passphrase and the RPC spends from the unlocked wallet. No `listunspent`, no raw
transaction building, no `importprivkey`. Those can be added when somebody
needs them; the set above is what every exchange integration actually calls.
