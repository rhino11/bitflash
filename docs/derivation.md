# Key derivation and address format

This document exists so that a Bitflash wallet can be rebuilt **without this
software**. If the project stops, the binaries are lost, or you simply do not
trust them, the twelve words plus what is written here are enough to recover
your private keys with ordinary cryptographic tools.

Everything below is verified by `docs/verify-derivation.py`, a self-contained
script that implements this document from scratch — no Bitflash code, no
libraries beyond Python's standard library — and checks that it reproduces the
addresses the wallet produces. If the two ever disagree, this document is wrong
and the script will say so.

## Addresses

An address is the Base58Check encoding of a version byte followed by
`RIPEMD160(SHA256(public key))`.

| | |
|---|---|
| curve | secp256k1 |
| public key encoding | **uncompressed**, 65 bytes, `0x04 ‖ X ‖ Y` |
| address version byte | **25** (`0x19`), which is why addresses begin with `B` |
| checksum | first 4 bytes of `SHA256(SHA256(payload))`, appended before Base58 |

The public key is uncompressed. This matters more than anything else here: the
same private key hashed in compressed form gives a completely different, valid
looking address that holds nothing. Bitflash descends from Bitcoin 0.1.0, which
predates compressed keys.

Outputs paying an address use the usual script:

```
OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
```

Mined coins and payments made directly to a public key use the older form
`<pubkey> OP_CHECKSIG`. A wallet scanning the chain must recognise both.

## From twelve words to a master key

Standard BIP-39 and BIP-32, with no modifications:

1. **Seed.** `PBKDF2-HMAC-SHA512(password = mnemonic, salt = "mnemonic" + passphrase, iterations = 2048, length = 64 bytes)`. Bitflash always uses an empty passphrase, so the salt is the literal string `mnemonic`.
2. **Master key.** `I = HMAC-SHA512(key = "Bitcoin seed", data = seed)`. The master private key is `I[0..32]`, the master chain code is `I[32..64]`.

Child derivation is BIP-32 `CKDpriv`, hardened and non-hardened as usual.

## Two layouts

A wallet records which layout it uses in `wallet.dat` under the key `hdschema`.
Wallets created before that field existed are treated as legacy.

### Legacy (`hdschema` absent or 1)

```
m/i'
```

Hardened children of the master key, one flat sequence. Index 0 is the wallet's
default receiving address; the key pool and change take the following indices.

Used by every wallet created before BIP-44 support existed, and kept forever:
those phrases must keep working.

### BIP-44 (`hdschema` = 2)

```
m/44'/4346950'/0'/0/i      external chain (receiving)
m/44'/4346950'/0'/1/i      internal chain (change)
```

Coin type **4346950** is `0x425446`, the ASCII bytes `BTF`. It is
[registered for Bitflash under the symbol BITFLASH](https://github.com/satoshilabs/slips/blob/master/slip-0044.md).
The account level is fixed at `0'`; Bitflash does not expose multiple accounts.

A wallet restored from a phrase scans **both** layouts, because the words alone
do not say which one produced them.

## Test vectors

Using the public BIP-39 test mnemonic:

```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

### Legacy

| path | address |
|---|---|
| `m/0'` | `BHJNmVvkVv59fgn7gmgP78BtciQi2HY8Hy` |
| `m/1'` | `B5qh9opG8sH8Mv9k2xzHoTeSUd9BkT6XEZ` |
| `m/2'` | `BCNH8uGyvkiz3uXjhA9iiF27PWAaTStNin` |
| `m/3'` | `BC1QNaXuTPGDgLZy53PghZMHEmZcp5GLgD` |

### BIP-44 external chain

| path | address |
|---|---|
| `m/44'/4346950'/0'/0/0` | `BF1ukigB1afmqxH64gJymPwUqFBrRqWbrb` |
| `m/44'/4346950'/0'/0/1` | `BACY8pcuCapNQr897eRHroNrgN38GSsEzV` |
| `m/44'/4346950'/0'/0/2` | `BMzkMN2k1phNBqy8RPb4Pv1i2QpwsWkKPa` |
| `m/44'/4346950'/0'/0/3` | `BNPZ8U6FHXr9Ererk8psyM2RqEVtF6sfBQ` |

Check them yourself:

```
python docs/verify-derivation.py
```

Both tables were produced by the wallet — the legacy one by the v1.2.15 binary,
which only knows that layout — and then reproduced independently by the script.

## What this document does not give you

Deriving the keys is not the same as spending. To move recovered coins you still
need a node that knows the network: the chain, the peer protocol, and the
transaction format. This document is about **not losing the keys**, which is the
part that cannot be reconstructed later by reading source code that no longer
exists anywhere.

Note also that `wallet.dat` stores private keys unencrypted. A recovery phrase
protects you against losing the file; it does not protect the file. Anyone who
can read it can spend the coins.
