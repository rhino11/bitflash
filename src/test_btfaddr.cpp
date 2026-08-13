// Standalone tests for btfaddr (ported from Itzal hidden.rs tests).
// Build (UCRT64):
//   g++ -std=gnu++14 -DSECP256K1_STATIC -I../deps/include test_btfaddr.cpp btfaddr.cpp \
//       -L../deps/lib -lsecp256k1 -lssl -lcrypto -o test_btfaddr.exe

#include "btfaddr.h"
#include <openssl/rand.h>
#define SECP256K1_STATIC
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <nlohmann/json.hpp>
#include <cstdio>
#include <cstring>
#include <string>

using json = nlohmann::json;

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } } while(0)

static std::string ToUpper(const std::string& s)
{
    std::string r = s;
    for (char& c : r) c = (char)toupper((unsigned char)c);
    return r;
}

int main()
{
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char seed[32]; RAND_bytes(seed, 32); secp256k1_context_randomize(ctx, seed);

    printf("base32_roundtrips\n");
    {
        std::vector<std::vector<unsigned char>> cases;
        std::string txt = "hello btf shadow 0123456789";
        cases.push_back(std::vector<unsigned char>(txt.begin(), txt.end()));
        cases.push_back(std::vector<unsigned char>(34, 0x00));
        cases.push_back(std::vector<unsigned char>(34, 0xff));
        for (auto& data : cases)
        {
            std::string enc = btf::Base32Encode(data.data(), data.size());
            std::vector<unsigned char> dec;
            bool ok = btf::Base32Decode(enc, dec);
            // decode may include trailing partial byte handling; compare the meaningful prefix
            CHECK(ok && dec.size() >= data.size() &&
                  memcmp(dec.data(), data.data(), data.size()) == 0, "roundtrip");
        }
    }

    printf("address_roundtrips_and_is_lowercase_hostname\n");
    {
        unsigned char pk[32]; memset(pk, 7, 32);
        std::string a = btf::Address(pk);
        CHECK(a.size() > 4 && a.compare(a.size()-4, 4, ".btf") == 0, "ends with .btf");
        CHECK(btf::IsBtf(a), "IsBtf true");
        std::string label = a.substr(0, a.size()-4);
        bool lc = true;
        for (unsigned char c : label)
            if (!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7'))) lc = false;
        CHECK(lc, "label is lowercase base32 hostname");
        unsigned char out[32];
        CHECK(btf::ParseAddress(a, out) && memcmp(out, pk, 32) == 0, "parse round-trips");
        CHECK(btf::ParseAddress(ToUpper(a), out) && memcmp(out, pk, 32) == 0, "parse case-insensitive");
    }

    printf("rejects_tampered_address\n");
    {
        unsigned char pk[32]; memset(pk, 9, 32);
        std::string a = btf::Address(pk);
        std::string t = a;
        t[0] = (t[0] == 'a') ? 'b' : 'a';
        unsigned char out[32];
        CHECK(!(btf::ParseAddress(t, out) && memcmp(out, pk, 32) == 0), "tampered address rejected");
    }

    printf("rejects_non_btf\n");
    {
        unsigned char out[32];
        CHECK(!btf::IsBtf("example.com"), "example.com not btf");
        CHECK(!btf::ParseAddress("example.com", out), "parse example.com fails");
        CHECK(!btf::ParseAddress("not-base-32-!!!.btf", out), "parse invalid base32 fails");
    }

    const std::string ENC_HEX = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const std::string ONION = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion:8433";

    // helper: fresh keypair -> (seckey, xonly pubkey)
    auto newKey = [&](unsigned char sk[32], unsigned char pk[32]) {
        do { RAND_bytes(sk, 32); } while (!secp256k1_ec_seckey_verify(ctx, sk));
        secp256k1_keypair kp; secp256k1_keypair_create(ctx, &kp, sk);
        secp256k1_xonly_pubkey xp; secp256k1_keypair_xonly_pub(ctx, &xp, NULL, &kp);
        secp256k1_xonly_pubkey_serialize(ctx, pk, &xp);
    };

    printf("descriptor_signs_and_self_certifies\n");
    {
        unsigned char sk[32], pk[32]; newKey(sk, pk);
        std::string d = btf::SignDescriptor(ctx, sk, ENC_HEX, "meeting-node-abc", 1000);
        CHECK(!d.empty(), "sign produced descriptor");
        btf::Descriptor got;
        CHECK(btf::VerifyDescriptor(ctx, d, pk, got), "own key verifies");
        CHECK(got.meeting_node == "meeting-node-abc" && got.enc == ENC_HEX && got.created == 1000, "fields match");
        unsigned char sk2[32], pk2[32]; newKey(sk2, pk2);
        btf::Descriptor bad;
        CHECK(!btf::VerifyDescriptor(ctx, d, pk2, bad), "different key rejected");
    }

    printf("descriptor_signs_optional_onion_endpoint\n");
    {
        unsigned char sk[32], pk[32]; newKey(sk, pk);
        std::string d = btf::SignDescriptor(ctx, sk, ENC_HEX, "meeting-node-abc", 1000, ONION);
        CHECK(!d.empty(), "sign produced onion descriptor");
        btf::Descriptor got;
        CHECK(btf::VerifyDescriptor(ctx, d, pk, got), "onion descriptor verifies");
        CHECK(got.meeting_node == "meeting-node-abc" && got.enc == ENC_HEX &&
              got.created == 1000 && got.onion == ONION, "onion fields match");
    }

    printf("descriptor_rejects_tampering\n");
    {
        unsigned char sk[32], pk[32]; newKey(sk, pk);
        std::string d = btf::SignDescriptor(ctx, sk, ENC_HEX, "node-1", 5);
        json j = json::parse(d); j["meeting_node"] = "evil-node";
        btf::Descriptor o;
        CHECK(!btf::VerifyDescriptor(ctx, j.dump(), pk, o), "tampered meeting_node rejected");
        json j2 = json::parse(d); j2["enc"] = "00000000000000000000000000000000000000000000000000000000deadbeef";
        CHECK(!btf::VerifyDescriptor(ctx, j2.dump(), pk, o), "tampered enc rejected");

        std::string d3 = btf::SignDescriptor(ctx, sk, ENC_HEX, "node-1", 5, ONION);
        json j3 = json::parse(d3);
        j3["onion"] = "bcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde.onion:8433";
        CHECK(btf::VerifyDescriptor(ctx, j3.dump(), pk, o) && o.onion.empty(),
              "tampered onion ignored rather than trusted");
        json j4 = json::parse(d3);
        j4["sig3"] = std::string(128, '0');
        CHECK(btf::VerifyDescriptor(ctx, j4.dump(), pk, o) && o.onion.empty(),
              "bad onion signature ignored rather than trusted");
    }

    printf("full_resolve_chain_from_address\n");
    {
        unsigned char sk[32], pk[32]; newKey(sk, pk);
        std::string addr = btf::Address(pk);
        unsigned char resolved[32];
        CHECK(btf::ParseAddress(addr, resolved), "address parses");
        std::string d = btf::SignDescriptor(ctx, sk, ENC_HEX, "meeting", 1);
        btf::Descriptor o;
        CHECK(btf::VerifyDescriptor(ctx, d, resolved, o), "descriptor verifies under resolved key");
    }

    // Show a sample address so we can eyeball the format
    {
        unsigned char sk[32], pk[32]; newKey(sk, pk);
        printf("\nsample .btf address:\n  %s\n", btf::Address(pk).c_str());
    }

    printf("\n%s (%d failures)\n", g_fail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", g_fail);
    secp256k1_context_destroy(ctx);
    return g_fail == 0 ? 0 : 1;
}
