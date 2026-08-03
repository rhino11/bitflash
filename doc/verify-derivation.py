#!/usr/bin/env python3
"""Check doc/derivation.md against the addresses the wallet really produces.

This implements the document and nothing else: BIP-39 to seed, BIP-32 to child
keys, uncompressed secp256k1 public keys, and Base58Check with version byte 25.
It shares no code with Bitflash and needs nothing outside the standard library,
so agreement between the two is evidence that the document is enough to recover
a wallet without this project's software.

    python doc/verify-derivation.py

Exits non-zero if any address disagrees.
"""

import hashlib
import hmac
import sys

MNEMONIC = ("abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about")
COIN_TYPE = 4346950          # 0x425446, the ASCII bytes "BTF"
ADDRESS_VERSION = 25         # 0x19, so addresses start with "B"
HARDENED = 0x80000000

LEGACY = [
    "BHJNmVvkVv59fgn7gmgP78BtciQi2HY8Hy",
    "B5qh9opG8sH8Mv9k2xzHoTeSUd9BkT6XEZ",
    "BCNH8uGyvkiz3uXjhA9iiF27PWAaTStNin",
    "BC1QNaXuTPGDgLZy53PghZMHEmZcp5GLgD",
]

BIP44_EXTERNAL = [
    "BF1ukigB1afmqxH64gJymPwUqFBrRqWbrb",
    "BACY8pcuCapNQr897eRHroNrgN38GSsEzV",
    "BMzkMN2k1phNBqy8RPb4Pv1i2QpwsWkKPa",
    "BNPZ8U6FHXr9Ererk8psyM2RqEVtF6sfBQ",
]

# ---- secp256k1, plain and slow on purpose: it should be readable ------------

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], P - 2, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], P - 2, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return (x, (lam * (p[0] - x) - p[1]) % P)


def point_mul(k, p=G):
    result = None
    while k:
        if k & 1:
            result = point_add(result, p)
        p = point_add(p, p)
        k >>= 1
    return result


def pub_uncompressed(point):
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def pub_compressed(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


# ---- encoding --------------------------------------------------------------

def base58check(payload):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = alphabet[rem] + out
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + out


def address(privkey):
    pub = pub_uncompressed(point_mul(privkey))
    h160 = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
    return base58check(bytes([ADDRESS_VERSION]) + h160)


# ---- BIP-39 and BIP-32 -----------------------------------------------------

def master_from_mnemonic(mnemonic, passphrase=""):
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"),
                               ("mnemonic" + passphrase).encode("utf-8"),
                               2048, 64)
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return int.from_bytes(i[:32], "big"), i[32:]


def ckd_priv(key, chain, index):
    if index >= HARDENED:
        data = b"\x00" + key.to_bytes(32, "big")
    else:
        data = pub_compressed(point_mul(key))
    i = hmac.new(chain, data + index.to_bytes(4, "big"), hashlib.sha512).digest()
    return (int.from_bytes(i[:32], "big") + key) % N, i[32:]


def derive(path):
    key, chain = master_from_mnemonic(MNEMONIC)
    for index in path:
        key, chain = ckd_priv(key, chain, index)
    return key


# ---- the check -------------------------------------------------------------

def main():
    failures = 0

    print("legacy   m/i'")
    for i, expected in enumerate(LEGACY):
        got = address(derive([i + HARDENED]))
        ok = got == expected
        failures += 0 if ok else 1
        print("  m/%d'  %s %s" % (i, got, "ok" if ok else
                                  "MISMATCH, wallet says " + expected))

    print()
    print("bip-44   m/44'/%d'/0'/0/i" % COIN_TYPE)
    for i, expected in enumerate(BIP44_EXTERNAL):
        got = address(derive([44 + HARDENED, COIN_TYPE + HARDENED,
                              0 + HARDENED, 0, i]))
        ok = got == expected
        failures += 0 if ok else 1
        print("  .../%d  %s %s" % (i, got, "ok" if ok else
                                   "MISMATCH, wallet says " + expected))

    print()
    if failures:
        print("%d address(es) disagree -- doc/derivation.md is wrong" % failures)
        return 1
    print("all addresses match: the document reproduces the wallet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
