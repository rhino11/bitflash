// Standalone tests for BIP39/BIP32 primitives.
//
// Build:
//   g++ -std=gnu++14 test_bip32.cpp bip32.cpp -lssl -lcrypto -o test_bip32

#include "bip32.h"

#include <openssl/sha.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace bitflash;

static int g_fail = 0;

#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } \
} while (0)

static int HexDigit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static std::vector<unsigned char> FromHex(const std::string& s)
{
    std::vector<unsigned char> out;
    if (s.size() % 2 != 0)
        return out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2)
    {
        int hi = HexDigit(s[i]);
        int lo = HexDigit(s[i + 1]);
        if (hi < 0 || lo < 0)
            return std::vector<unsigned char>();
        out.push_back((unsigned char)((hi << 4) | lo));
    }
    return out;
}

static std::string ToHex(const std::vector<unsigned char>& v)
{
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (unsigned char c : v)
    {
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0x0f]);
    }
    return out;
}

static bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& out)
{
    static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    out.clear();

    std::vector<unsigned char> b256(str.size() * 733 / 1000 + 1);
    for (char c : str)
    {
        const char* p = strchr(pszBase58, c);
        if (!p)
            return false;
        int carry = (int)(p - pszBase58);
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin();
             it != b256.rend(); ++it)
        {
            carry += 58 * (*it);
            *it = (unsigned char)(carry & 0xff);
            carry >>= 8;
        }
        if (carry != 0)
            return false;
    }

    size_t zeros = 0;
    while (zeros < str.size() && str[zeros] == '1')
        zeros++;
    std::vector<unsigned char>::iterator it = b256.begin();
    while (it != b256.end() && *it == 0)
        ++it;

    std::vector<unsigned char> full;
    full.assign(zeros, 0);
    while (it != b256.end())
        full.push_back(*it++);
    if (full.size() < 4)
        return false;

    std::vector<unsigned char> payload(full.begin(), full.end() - 4);
    unsigned char h1[SHA256_DIGEST_LENGTH];
    unsigned char h2[SHA256_DIGEST_LENGTH];
    SHA256(&payload[0], payload.size(), h1);
    SHA256(h1, sizeof(h1), h2);
    if (memcmp(h2, &full[full.size() - 4], 4) != 0)
        return false;

    out = payload;
    return true;
}

static bool DecodeXPrvNode(const std::string& xprv, BIP32PrivateNode& nodeOut)
{
    nodeOut.privateKey.clear();
    nodeOut.chainCode.clear();

    std::vector<unsigned char> payload;
    if (!DecodeBase58Check(xprv, payload))
        return false;
    if (payload.size() != 78)
        return false;
    if (payload[0] != 0x04 || payload[1] != 0x88 ||
        payload[2] != 0xad || payload[3] != 0xe4)
        return false;
    if (payload[45] != 0x00)
        return false;

    nodeOut.chainCode.assign(payload.begin() + 13, payload.begin() + 45);
    nodeOut.privateKey.assign(payload.begin() + 46, payload.end());
    return true;
}

int main()
{
    std::string err;

    printf("bip39_entropy_to_mnemonic\n");
    {
        std::vector<unsigned char> entropy(16, 0);
        std::string mnemonic;
        CHECK(BIP39EntropyToMnemonic(entropy, mnemonic, err), "zero entropy encodes");
        CHECK(mnemonic ==
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
              "matches BIP39 vector");
    }

    printf("bip39_validation\n");
    {
        std::string normalized;
        CHECK(BIP39ValidateMnemonic(
              "  Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ",
              normalized, err),
              "valid phrase normalizes");
        CHECK(normalized ==
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
              "normalized text matches");
        CHECK(!BIP39ValidateMnemonic(
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
              normalized, err),
              "bad checksum rejected");
    }

    printf("bip39_seed\n");
    {
        std::vector<unsigned char> seed;
        const std::string mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        CHECK(BIP39MnemonicToSeed(mnemonic, "TREZOR", seed, err), "mnemonic derives seed");
        CHECK(ToHex(seed) ==
              "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
              "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
              "matches BIP39 seed vector");
    }

    printf("bip32_master\n");
    {
        std::vector<unsigned char> seed = FromHex("000102030405060708090a0b0c0d0e0f");
        BIP32PrivateNode master;
        CHECK(BIP32MasterFromSeed(seed, master, err), "master key derives");
        CHECK(ToHex(master.privateKey) ==
              "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
              "matches BIP32 master private key");
        CHECK(ToHex(master.chainCode) ==
              "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
              "matches BIP32 master chain code");

        BIP32PrivateNode childA, childB;
        CHECK(BIP32DeriveHardenedChild(master, 0, childA, err), "hardened child derives");
        CHECK(BIP32DeriveHardenedChild(master, 0, childB, err), "hardened child re-derives");
        CHECK(childA.privateKey == childB.privateKey &&
              childA.chainCode == childB.chainCode,
              "same child path is deterministic");
        CHECK(childA.privateKey != master.privateKey &&
              childA.chainCode != master.chainCode,
              "child differs from parent");
        CHECK(!BIP32DeriveHardenedChild(master, 0x80000000U, childA, err),
              "pre-hardened index rejected");
    }

    printf("bip32_paths\n");
    {
        std::vector<unsigned char> seed = FromHex("000102030405060708090a0b0c0d0e0f");
        BIP32PrivateNode master;
        CHECK(BIP32MasterFromSeed(seed, master, err), "path test master derives");

        struct PathVector
        {
            const char* name;
            std::vector<unsigned int> path;
            const char* xprv;
        };

        std::vector<PathVector> vectors;
        vectors.push_back({"m",
            {},
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"});
        vectors.push_back({"m/0'",
            {0 | BIP32_HARDENED},
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"});
        vectors.push_back({"m/0'/1",
            {0 | BIP32_HARDENED, 1},
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"});
        vectors.push_back({"m/0'/1/2'",
            {0 | BIP32_HARDENED, 1, 2 | BIP32_HARDENED},
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"});
        vectors.push_back({"m/0'/1/2'/2",
            {0 | BIP32_HARDENED, 1, 2 | BIP32_HARDENED, 2},
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"});
        vectors.push_back({"m/0'/1/2'/2/1000000000",
            {0 | BIP32_HARDENED, 1, 2 | BIP32_HARDENED, 2, 1000000000},
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"});

        for (const PathVector& v : vectors)
        {
            BIP32PrivateNode actual;
            BIP32PrivateNode expected;
            std::string label = std::string("derives ") + v.name;
            CHECK(BIP32DerivePath(master, v.path, actual, err), label.c_str());
            label = std::string("decodes vector ") + v.name;
            CHECK(DecodeXPrvNode(v.xprv, expected), label.c_str());
            label = std::string("matches vector ") + v.name;
            CHECK(actual.privateKey == expected.privateKey &&
                  actual.chainCode == expected.chainCode, label.c_str());
        }
    }

    printf("\n%s (%d failures)\n",
           g_fail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", g_fail);
    return g_fail == 0 ? 0 : 1;
}
