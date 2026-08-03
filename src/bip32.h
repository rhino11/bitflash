// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// BIP39/BIP32 primitives for deterministic wallet work.
//
// This module is deliberately independent from wallet.dat and GUI code. It is
// the auditable foundation: mnemonic generation/validation, seed derivation,
// and private child derivation over secp256k1.

#ifndef BITFLASH_BIP32_H
#define BITFLASH_BIP32_H

#include <string>
#include <vector>

namespace bitflash
{

static const unsigned int BIP32_HARDENED = 0x80000000U;

struct BIP32PrivateNode
{
    std::vector<unsigned char> privateKey; // 32-byte scalar
    std::vector<unsigned char> chainCode;  // 32 bytes
};

bool BIP39EntropyToMnemonic(const std::vector<unsigned char>& entropy,
                            std::string& mnemonicOut,
                            std::string& errorOut);

bool BIP39GenerateMnemonic(std::string& mnemonicOut,
                           std::string& errorOut,
                           unsigned int entropyBytes = 16);

bool BIP39ValidateMnemonic(const std::string& mnemonic,
                           std::string& normalizedOut,
                           std::string& errorOut);

bool BIP39MnemonicToSeed(const std::string& mnemonic,
                         const std::string& passphrase,
                         std::vector<unsigned char>& seedOut,
                         std::string& errorOut);

bool BIP32MasterFromSeed(const std::vector<unsigned char>& seed,
                         BIP32PrivateNode& nodeOut,
                         std::string& errorOut);

bool BIP32DeriveChild(const BIP32PrivateNode& parent,
                      unsigned int childNumber,
                      BIP32PrivateNode& childOut,
                      std::string& errorOut);

bool BIP32DerivePath(const BIP32PrivateNode& root,
                     const std::vector<unsigned int>& path,
                     BIP32PrivateNode& nodeOut,
                     std::string& errorOut);

bool BIP32DeriveHardenedChild(const BIP32PrivateNode& parent,
                              unsigned int childIndex,
                              BIP32PrivateNode& childOut,
                              std::string& errorOut);

} // namespace bitflash

#endif
