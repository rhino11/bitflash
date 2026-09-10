# Bitflash Storage Inventory

This document records the Berkeley DB surface that still exists in Bitflash.
It is a migration map, not a promise that all stores should move at once.

The immediate priority is `wallet.dat`: it holds spend authority and recovery
metadata. `blkindex.dat` can be rebuilt from block files, so it is important for
startup correctness but less dangerous than wallet storage.

## Berkeley DB Environment

All `CDB` stores use one Berkeley DB environment rooted at:

```text
<datadir>/database/
```

The environment creates log files such as:

```text
database/log.0000000001
```

Those logs are part of the legacy BDB risk model. They are not user-facing
wallet files, but they can contain historical records while the environment is
live. Wallet encryption already rewrites `wallet.dat` and purges BDB environment
logs after the encrypted file is installed.

## Common Records

Every `CDB` file can carry:

| Key | Value | Purpose |
|---|---|---|
| `"version"` | `int` | Database format version written when a DB is opened in create mode. |

Keys and values are serialized with the existing `CDataStream` format. A future
SQLite migration must preserve byte-for-byte value semantics until a higher
level schema migration is intentionally introduced.

## `wallet.dat`

`wallet.dat` is accessed through `CWalletDB`.
Read-only tooling should go through `ScanWalletRecords()` instead of opening a
Berkeley DB cursor directly. That keeps migration checks, audits, and future
backends behind one record-stream boundary. Wallet rewrite code should also use
that boundary when it needs to copy existing records into a newly written
wallet file.

| Key shape | Value | Secret? | Meaning |
|---|---|---:|---|
| `("name", address)` | `string` | No | Address book label. |
| `("tx", txid)` | `CWalletTx` | No | Wallet transaction state, including spend flags and metadata. |
| `("key", pubkey)` | `CPrivKey` | Yes | Plain private key record for unencrypted wallets or old backups. |
| `"defaultkey"` | `vector<unsigned char>` | No | Default public key shown by the wallet. |
| `"hdmaster"` | `vector<unsigned char>` | Yes | Plain BIP32 master private key material. |
| `"hdchaincode"` | `vector<unsigned char>` | Yes | Plain BIP32 chain code. |
| `"hdnext"` | `unsigned int` | No | Legacy deterministic derivation next index. |
| `"hdschema"` | `int` | No | Deterministic derivation schema (`legacy` or `bip44`). |
| `"hdcointype"` | `unsigned int` | No | BIP44 coin type. Bitflash is `4346950`. |
| `"hdreceivenext"` | `unsigned int` | No | BIP44 external receive-chain next index. |
| `"hdchangenext"` | `unsigned int` | No | BIP44 internal change-chain next index. |
| `("mkey", id)` | `CWalletMasterKey` | Sensitive | Encrypted wallet master-key metadata. |
| `("ckey", pubkey)` | `vector<unsigned char>` | Yes | Private key encrypted under the wallet master key. |
| `"cryptedhdmaster"` | `vector<unsigned char>` | Yes | Encrypted BIP32 master private key material. |
| `"cryptedhdchaincode"` | `vector<unsigned char>` | Yes | Encrypted BIP32 chain code. |
| `"walletminversion"` | `int` | No | Minimum wallet format version required to open this wallet safely. |
| `("pool", index)` | `vector<unsigned char>` | No | Public key reserved in the key pool. The private key lives in `key`/`ckey`. |
| `("setting", name)` | typed setting value | Usually no | Wallet/UI settings such as mining mode, fees, and backup timestamps. |

### Wallet Migration Rules

A future wallet backend must keep these properties:

1. Unknown future wallet formats fail closed with a clear message.
2. Encrypted wallets must encrypt private keys and HD seed material.
3. A locked encrypted wallet may expose public keys and balances, but not
   private keys or decrypted HD seed material.
4. `-backupwallet` must produce a wallet file that opens in a different datadir
   without copying `database/`, and must not leave a half-written final backup
   path if the copy or install step fails.
5. `-recoveryaudit` must distinguish:
   - no recovery phrase installed;
   - recovery phrase present;
   - recovery phrase encrypted and locked, requiring unlock before coverage can
     be audited.

## SQLite Wallet Store

Since v1.2.20 SQLite is the default wallet backend. It is a byte-preserving
record store, not a new wallet format -- the same serialized `CDataStream` bytes
`wallet.dat` uses:

```sql
CREATE TABLE wallet_records (
  key BLOB PRIMARY KEY NOT NULL,
  value BLOB NOT NULL
);
PRAGMA user_version=1;
```

A fresh data directory starts on `wallet.sqlite`. An existing `wallet.dat` keeps
running on Berkeley DB until it is converted: the GUI offers a one-click
conversion on first run, and `-walletbackend=sqlite` / `-walletbackend=bdb`
(recorded in a plain-text `wallet-backend` marker file in the datadir) select a
backend explicitly. Conversion never modifies `wallet.dat`; it stays as a
fallback, and the change takes effect on restart.

Every wallet operation runs on either backend: read, write, erase, key-pool and
HD-seed writes (the two halves of the seed bracketed in one SQLite transaction),
`-backupwallet` (checkpoint then copy the self-contained file), `-encryptwallet`
(an atomic rebuild-and-swap in one transaction), and the `-walletstorageaudit` /
`-walletstoragecheck` diagnostics, which read the active backend's file.

The migration tooling remains available for scripted use. `-walletsqliteexport=FILE`
streams every raw `wallet.dat` record through `ScanWalletRecords()` into a SQLite
file in one transaction, refusing to overwrite. `-walletsqliteverify=FILE`
compares the two streams and prints only counts. `-walletsqliteloadcheck=FILE`
parses an export with the same record types the loader uses.
`-walletsqliterestore=FILE` rebuilds a `wallet.dat` from an export in an empty
data directory. Failed exports and restores remove their incomplete output.

## `blkindex.dat`

`blkindex.dat` is accessed through `CTxDB`.

| Key shape | Value | Rebuildable? | Meaning |
|---|---|---:|---|
| `("tx", txid)` | `CTxIndex` | Yes | Transaction disk position and spent-output index state. |
| `("owner", hash160, CDiskTxPos)` | `int height` | Yes | Legacy owner transaction index cursor range. |
| `("blockindex", blockhash)` | `CDiskBlockIndex` | Yes | Block index entry. |
| `"hashBestChain"` | `uint256` | Yes | Current best-chain tip hash. |

`blkindex.dat` can be rebuilt from `blk*.dat` plus consensus validation. A
future migration may therefore prefer a rebuild path over a byte-preserving
conversion path.

## Other Legacy Stores

| File | Class | Records | Current risk |
|---|---|---|---|
| `reviews.dat` | `CReviewDB` | `("user", hash)`, `("reviews", hash)` | Legacy market/review storage. Not part of wallet safety. |
| `market.dat` | `CMarketDB` | No explicit typed records in current wrappers. | Legacy market storage shell. |

The old IP address database (`addr.dat`) has been removed. Peer discovery is
handled by Nostr, `.btf`, and direct onion peers.

## Migration Order (shipped in v1.2.20)

1. Storage self-tests were added around Berkeley DB behavior first.
2. The SQLite backend landed behind an explicit flag, then behind a
   `wallet-backend` marker and a GUI conversion wizard.
3. BDB-to-SQLite migration is a one-way copy that leaves `wallet.dat` as a backup.
4. SQLite became the default for new wallets only after cross-version restore,
   encryption, backup, and recovery-audit tests passed -- and a live coin-proof
   of receive, spend, restart, and encrypt on real mainnet funds.
5. Treat `blkindex.dat` separately; it is safer to rebuild than to migrate under
   pressure.
