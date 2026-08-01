// Standalone tests for BIP39/BIP32 primitives.
//
// Build:
//   g++ -std=gnu++14 test_bip32.cpp bip32.cpp -lssl -lcrypto -o test_bip32

#include "bip32.h"

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

    printf("\n%s (%d failures)\n",
           g_fail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", g_fail);
    return g_fail == 0 ? 0 : 1;
}
