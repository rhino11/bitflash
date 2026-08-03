// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "bip32.h"
#include "bip39_english.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>
#include <sstream>

namespace bitflash
{

static bool IsSupportedEntropySize(size_t n)
{
    return n == 16 || n == 20 || n == 24 || n == 28 || n == 32;
}

static bool GetBit(const unsigned char* data, size_t bit)
{
    return (data[bit / 8] >> (7 - (bit % 8))) & 1;
}

static void AppendBits(std::vector<bool>& out, const unsigned char* data,
                       size_t nBits)
{
    for (size_t i = 0; i < nBits; i++)
        out.push_back(GetBit(data, i));
}

static std::string NormalizeMnemonic(const std::string& in)
{
    std::string out;
    bool inSpace = true;
    for (unsigned char c : in)
    {
        if (std::isspace(c))
        {
            if (!inSpace)
                out.push_back(' ');
            inSpace = true;
        }
        else
        {
            out.push_back((char)std::tolower(c));
            inSpace = false;
        }
    }
    if (!out.empty() && out.back() == ' ')
        out.pop_back();
    return out;
}

static std::vector<std::string> SplitWords(const std::string& phrase)
{
    std::vector<std::string> words;
    std::istringstream in(phrase);
    std::string word;
    while (in >> word)
        words.push_back(word);
    return words;
}

static const std::map<std::string, int>& WordIndex()
{
    static std::map<std::string, int> m;
    if (m.empty())
    {
        for (int i = 0; i < 2048; i++)
            m[BIP39_ENGLISH_WORDS[i]] = i;
    }
    return m;
}

static bool IsValidPrivateKey(const std::vector<unsigned char>& key)
{
    if (key.size() != 32)
        return false;
    bool fNonZero = false;
    for (unsigned char c : key)
        fNonZero = fNonZero || c != 0;
    if (!fNonZero)
        return false;

    bool ok = false;
    BIGNUM* bn = BN_bin2bn(&key[0], 32, NULL);
    BIGNUM* order = BN_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (bn && order && group && EC_GROUP_get_order(group, order, NULL))
        ok = BN_cmp(bn, order) < 0;
    BN_free(bn);
    BN_free(order);
    EC_GROUP_free(group);
    return ok;
}

static bool HmacSha512(const unsigned char* key, int keyLen,
                       const unsigned char* data, size_t dataLen,
                       unsigned char out[64])
{
    unsigned int len = 64;
    return HMAC(EVP_sha512(), key, keyLen, data, dataLen, out, &len) != NULL &&
           len == 64;
}

static bool PrivateKeyToCompressedPubKey(const std::vector<unsigned char>& privateKey,
                                         unsigned char out[33],
                                         std::string& errorOut)
{
    if (!IsValidPrivateKey(privateKey))
    {
        errorOut = "private key is invalid";
        return false;
    }

    BIGNUM* bn = BN_bin2bn(&privateKey[0], 32, NULL);
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* pub = group ? EC_POINT_new(group) : NULL;

    bool ok = false;
    if (bn && ctx && group && pub &&
        EC_POINT_mul(group, pub, bn, NULL, NULL, ctx))
    {
        size_t n = EC_POINT_point2oct(group, pub, POINT_CONVERSION_COMPRESSED,
                                      out, 33, ctx);
        ok = n == 33;
    }

    BN_free(bn);
    BN_CTX_free(ctx);
    EC_POINT_free(pub);
    EC_GROUP_free(group);

    if (!ok)
    {
        errorOut = "could not serialize parent public key";
        return false;
    }
    return true;
}

bool BIP39EntropyToMnemonic(const std::vector<unsigned char>& entropy,
                            std::string& mnemonicOut,
                            std::string& errorOut)
{
    mnemonicOut.clear();
    errorOut.clear();
    if (!IsSupportedEntropySize(entropy.size()))
    {
        errorOut = "entropy must be 128, 160, 192, 224, or 256 bits";
        return false;
    }

    unsigned char checksum[SHA256_DIGEST_LENGTH];
    SHA256(&entropy[0], entropy.size(), checksum);

    const size_t entropyBits = entropy.size() * 8;
    const size_t checksumBits = entropyBits / 32;

    std::vector<bool> bits;
    bits.reserve(entropyBits + checksumBits);
    AppendBits(bits, &entropy[0], entropyBits);
    AppendBits(bits, checksum, checksumBits);

    const size_t words = bits.size() / 11;
    for (size_t i = 0; i < words; i++)
    {
        int idx = 0;
        for (int j = 0; j < 11; j++)
            idx = (idx << 1) | (bits[i * 11 + j] ? 1 : 0);
        if (i != 0)
            mnemonicOut += " ";
        mnemonicOut += BIP39_ENGLISH_WORDS[idx];
    }
    return true;
}

bool BIP39GenerateMnemonic(std::string& mnemonicOut,
                           std::string& errorOut,
                           unsigned int entropyBytes)
{
    mnemonicOut.clear();
    errorOut.clear();
    if (!IsSupportedEntropySize(entropyBytes))
    {
        errorOut = "entropy must be 16, 20, 24, 28, or 32 bytes";
        return false;
    }

    std::vector<unsigned char> entropy(entropyBytes);
    if (RAND_bytes(&entropy[0], entropy.size()) != 1)
    {
        errorOut = "RAND_bytes failed";
        return false;
    }
    bool ok = BIP39EntropyToMnemonic(entropy, mnemonicOut, errorOut);
    OPENSSL_cleanse(&entropy[0], entropy.size());
    return ok;
}

bool BIP39ValidateMnemonic(const std::string& mnemonic,
                           std::string& normalizedOut,
                           std::string& errorOut)
{
    normalizedOut = NormalizeMnemonic(mnemonic);
    errorOut.clear();
    std::vector<std::string> words = SplitWords(normalizedOut);
    const size_t nWords = words.size();
    if (nWords != 12 && nWords != 15 && nWords != 18 && nWords != 21 && nWords != 24)
    {
        errorOut = "mnemonic must contain 12, 15, 18, 21, or 24 words";
        return false;
    }

    const std::map<std::string, int>& index = WordIndex();
    std::vector<bool> bits;
    bits.reserve(nWords * 11);
    for (const std::string& word : words)
    {
        std::map<std::string, int>::const_iterator mi = index.find(word);
        if (mi == index.end())
        {
            errorOut = "mnemonic contains a word outside the BIP39 English list";
            return false;
        }
        int value = mi->second;
        for (int i = 10; i >= 0; i--)
            bits.push_back(((value >> i) & 1) != 0);
    }

    const size_t totalBits = bits.size();
    const size_t entropyBits = totalBits * 32 / 33;
    const size_t checksumBits = totalBits - entropyBits;
    std::vector<unsigned char> entropy(entropyBits / 8, 0);
    for (size_t i = 0; i < entropyBits; i++)
        if (bits[i])
            entropy[i / 8] |= (unsigned char)(1 << (7 - (i % 8)));

    unsigned char checksum[SHA256_DIGEST_LENGTH];
    SHA256(&entropy[0], entropy.size(), checksum);
    for (size_t i = 0; i < checksumBits; i++)
    {
        if (bits[entropyBits + i] != GetBit(checksum, i))
        {
            errorOut = "mnemonic checksum failed";
            return false;
        }
    }
    return true;
}

bool BIP39MnemonicToSeed(const std::string& mnemonic,
                         const std::string& passphrase,
                         std::vector<unsigned char>& seedOut,
                         std::string& errorOut)
{
    seedOut.assign(64, 0);
    std::string normalized;
    if (!BIP39ValidateMnemonic(mnemonic, normalized, errorOut))
    {
        seedOut.clear();
        return false;
    }

    const std::string salt = "mnemonic" + passphrase;
    if (!PKCS5_PBKDF2_HMAC(normalized.c_str(), normalized.size(),
                           (const unsigned char*)salt.data(), salt.size(),
                           2048, EVP_sha512(), 64, &seedOut[0]))
    {
        seedOut.clear();
        errorOut = "PBKDF2-HMAC-SHA512 failed";
        return false;
    }
    return true;
}

bool BIP32MasterFromSeed(const std::vector<unsigned char>& seed,
                         BIP32PrivateNode& nodeOut,
                         std::string& errorOut)
{
    nodeOut.privateKey.clear();
    nodeOut.chainCode.clear();
    errorOut.clear();
    if (seed.size() < 16 || seed.size() > 64)
    {
        errorOut = "BIP32 seed must be between 128 and 512 bits";
        return false;
    }

    unsigned char I[64];
    static const unsigned char key[] = "Bitcoin seed";
    if (!HmacSha512(key, sizeof(key) - 1, &seed[0], seed.size(), I))
    {
        errorOut = "HMAC-SHA512 failed";
        return false;
    }

    nodeOut.privateKey.assign(I, I + 32);
    nodeOut.chainCode.assign(I + 32, I + 64);
    OPENSSL_cleanse(I, sizeof(I));

    if (!IsValidPrivateKey(nodeOut.privateKey))
    {
        nodeOut.privateKey.clear();
        nodeOut.chainCode.clear();
        errorOut = "BIP32 master key is invalid";
        return false;
    }
    return true;
}

bool BIP32DeriveChild(const BIP32PrivateNode& parent,
                      unsigned int childNumber,
                      BIP32PrivateNode& childOut,
                      std::string& errorOut)
{
    childOut.privateKey.clear();
    childOut.chainCode.clear();
    errorOut.clear();
    if (!IsValidPrivateKey(parent.privateKey) || parent.chainCode.size() != 32)
    {
        errorOut = "parent private key or chain code is invalid";
        return false;
    }
    unsigned char data[37];
    if (childNumber & BIP32_HARDENED)
    {
        data[0] = 0x00;
        memcpy(data + 1, &parent.privateKey[0], 32);
    }
    else
    {
        if (!PrivateKeyToCompressedPubKey(parent.privateKey, data, errorOut))
            return false;
    }
    data[33] = (unsigned char)((childNumber >> 24) & 0xff);
    data[34] = (unsigned char)((childNumber >> 16) & 0xff);
    data[35] = (unsigned char)((childNumber >> 8) & 0xff);
    data[36] = (unsigned char)(childNumber & 0xff);

    unsigned char I[64];
    if (!HmacSha512(&parent.chainCode[0], 32, data, sizeof(data), I))
    {
        OPENSSL_cleanse(data, sizeof(data));
        errorOut = "HMAC-SHA512 failed";
        return false;
    }
    OPENSSL_cleanse(data, sizeof(data));

    std::vector<unsigned char> IL(I, I + 32);
    childOut.chainCode.assign(I + 32, I + 64);
    OPENSSL_cleanse(I, sizeof(I));

    BIGNUM* bnIL = BN_bin2bn(&IL[0], 32, NULL);
    BIGNUM* bnParent = BN_bin2bn(&parent.privateKey[0], 32, NULL);
    BIGNUM* bnOrder = BN_new();
    BIGNUM* bnChild = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);

    bool ok = false;
    if (bnIL && bnParent && bnOrder && bnChild && ctx && group &&
        EC_GROUP_get_order(group, bnOrder, NULL) &&
        BN_cmp(bnIL, bnOrder) < 0 &&
        BN_mod_add(bnChild, bnIL, bnParent, bnOrder, ctx) &&
        !BN_is_zero(bnChild))
    {
        childOut.privateKey.assign(32, 0);
        int n = BN_num_bytes(bnChild);
        BN_bn2bin(bnChild, &childOut.privateKey[32 - n]);
        ok = true;
    }

    BN_free(bnIL);
    BN_free(bnParent);
    BN_free(bnOrder);
    BN_free(bnChild);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    OPENSSL_cleanse(&IL[0], IL.size());

    if (!ok)
    {
        childOut.privateKey.clear();
        childOut.chainCode.clear();
        errorOut = "BIP32 child derivation produced an invalid key";
        return false;
    }
    return true;
}

bool BIP32DerivePath(const BIP32PrivateNode& root,
                     const std::vector<unsigned int>& path,
                     BIP32PrivateNode& nodeOut,
                     std::string& errorOut)
{
    nodeOut.privateKey.clear();
    nodeOut.chainCode.clear();
    errorOut.clear();
    if (!IsValidPrivateKey(root.privateKey) || root.chainCode.size() != 32)
    {
        errorOut = "root private key or chain code is invalid";
        return false;
    }

    BIP32PrivateNode cur = root;
    for (size_t i = 0; i < path.size(); i++)
    {
        BIP32PrivateNode next;
        if (!BIP32DeriveChild(cur, path[i], next, errorOut))
            return false;
        cur = next;
    }
    nodeOut = cur;
    return true;
}

bool BIP32DeriveHardenedChild(const BIP32PrivateNode& parent,
                              unsigned int childIndex,
                              BIP32PrivateNode& childOut,
                              std::string& errorOut)
{
    if (childIndex >= BIP32_HARDENED)
    {
        errorOut = "child index must be non-hardened; hardening is applied here";
        return false;
    }
    return BIP32DeriveChild(parent, childIndex | BIP32_HARDENED, childOut, errorOut);
}

} // namespace bitflash
