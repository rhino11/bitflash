// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Bitflash `.btf` self-certifying addresses + service descriptors.
// Ported from the Itzal hidden.rs design. See btfaddr.h.

#include "btfaddr.h"

#include <openssl/sha.h>
// See the note in nostr.cpp: the makefiles pass -DSECP256K1_STATIC too.
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <nlohmann/json.hpp>

#include <cstring>
#include <algorithm>
#include <cctype>

using json = nlohmann::json;

namespace btf
{

const char* TLD = ".btf";

static const char* B32 = "abcdefghijklmnopqrstuvwxyz234567";

std::string Base32Encode(const unsigned char* data, size_t n)
{
    std::string out;
    out.reserve(n * 8 / 5 + 1);
    uint64_t buf = 0;
    uint32_t bits = 0;
    for (size_t i = 0; i < n; i++)
    {
        buf = (buf << 8) | data[i];
        bits += 8;
        while (bits >= 5)
        {
            bits -= 5;
            out.push_back(B32[(buf >> bits) & 0x1f]);
        }
        buf &= (bits == 0) ? 0 : ((1ULL << bits) - 1);
    }
    if (bits > 0)
        out.push_back(B32[(buf << (5 - bits)) & 0x1f]);
    return out;
}

bool Base32Decode(const std::string& s, std::vector<unsigned char>& out)
{
    out.clear();
    out.reserve(s.size() * 5 / 8);
    uint64_t buf = 0;
    uint32_t bits = 0;
    for (unsigned char c : s)
    {
        uint64_t val;
        if (c >= 'a' && c <= 'z')      val = c - 'a';
        else if (c >= 'A' && c <= 'Z') val = c - 'A';
        else if (c >= '2' && c <= '7') val = c - '2' + 26;
        else return false;
        buf = (buf << 5) | val;
        bits += 5;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back((unsigned char)((buf >> bits) & 0xff));
        }
        buf &= (bits == 0) ? 0 : ((1ULL << bits) - 1);
    }
    return true;
}

static std::string ToLowerTrim(const std::string& in)
{
    std::string s = in;
    // trim whitespace
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) return std::string();
    s = s.substr(a, b - a + 1);
    // strip trailing dots (fully-qualified hostname form)
    while (!s.empty() && s.back() == '.') s.pop_back();
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// Two-byte checksum, domain-separated so it can't collide with any other hash use.
static void Checksum(const unsigned char pubkey[32], unsigned char out[2])
{
    static const char* DS = ".btf-checksum-v1";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char*)DS, strlen(DS));
    SHA256_Update(&ctx, pubkey, 32);
    unsigned char d[32];
    SHA256_Final(d, &ctx);
    out[0] = d[0];
    out[1] = d[1];
}

std::string Address(const unsigned char pubkey[32])
{
    unsigned char raw[34];
    memcpy(raw, pubkey, 32);
    Checksum(pubkey, raw + 32);
    return Base32Encode(raw, 34) + TLD;
}

bool IsBtf(const std::string& host)
{
    std::string s = ToLowerTrim(host);
    std::string tld = TLD;
    if (s.size() < tld.size()) return false;
    return s.compare(s.size() - tld.size(), tld.size(), tld) == 0;
}

bool ParseAddress(const std::string& addr, unsigned char pubkeyOut[32])
{
    std::string s = ToLowerTrim(addr);
    std::string tld = TLD;
    if (s.size() < tld.size()) return false;
    if (s.compare(s.size() - tld.size(), tld.size(), tld) != 0) return false;
    std::string label = s.substr(0, s.size() - tld.size());

    std::vector<unsigned char> raw;
    if (!Base32Decode(label, raw)) return false;
    if (raw.size() < 34) return false;

    unsigned char pk[32];
    memcpy(pk, &raw[0], 32);
    unsigned char sum[2];
    Checksum(pk, sum);
    if (raw[32] != sum[0] || raw[33] != sum[1]) return false;

    memcpy(pubkeyOut, pk, 32);
    return true;
}


// ---- descriptor ------------------------------------------------------------

static std::string HexEncode(const unsigned char* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += h[p[i] >> 4]; s += h[p[i] & 0xf]; }
    return s;
}

static bool HexDecode(const std::string& s, unsigned char* out, size_t n)
{
    if (s.size() != n * 2) return false;
    for (size_t i = 0; i < n; i++)
    {
        unsigned int b;
        if (sscanf(s.c_str() + i * 2, "%2x", &b) != 1) return false;
        out[i] = (unsigned char)b;
    }
    return true;
}

// Digest signed over the descriptor fields (domain-separated).
static void DescriptorDigest(const unsigned char pubkey[32], const std::string& enc,
                             const std::string& meeting_node, uint64_t created,
                             unsigned char out[32])
{
    static const char* DS = ".btf-descriptor-v2";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char*)DS, strlen(DS));
    SHA256_Update(&ctx, pubkey, 32);
    SHA256_Update(&ctx, (const unsigned char*)enc.data(), enc.size());
    SHA256_Update(&ctx, (const unsigned char*)meeting_node.data(), meeting_node.size());
    unsigned char be[8];
    for (int i = 0; i < 8; i++) be[i] = (unsigned char)((created >> (8 * (7 - i))) & 0xff);
    SHA256_Update(&ctx, be, 8);
    SHA256_Final(out, &ctx);
}

std::string SignDescriptor(void* ctxv, const unsigned char seckey[32],
                           const std::string& enc, const std::string& meeting_node,
                           uint64_t created)
{
    secp256k1_context* ctx = (secp256k1_context*)ctxv;
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey)) return std::string();
    secp256k1_xonly_pubkey xpub;
    if (!secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, &kp)) return std::string();
    unsigned char pubkey[32];
    secp256k1_xonly_pubkey_serialize(ctx, pubkey, &xpub);

    unsigned char digest[32];
    DescriptorDigest(pubkey, enc, meeting_node, created, digest);

    unsigned char sig[64];
    // Deterministic signature (NULL aux_rand), matching Itzal's no-aux-rand signing.
    if (!secp256k1_schnorrsig_sign32(ctx, sig, digest, &kp, NULL)) return std::string();

    json v = json::object();
    v["v"]            = 2;
    v["pubkey"]       = HexEncode(pubkey, 32);
    v["enc"]          = enc;
    v["meeting_node"] = meeting_node;
    v["created"]      = created;
    v["sig"]          = HexEncode(sig, 64);
    return v.dump();
}

bool VerifyDescriptor(void* ctxv, const std::string& jsonStr,
                      const unsigned char expect_pubkey[32], Descriptor& out)
{
    secp256k1_context* ctx = (secp256k1_context*)ctxv;
    // Descriptors arrive from untrusted peers (via Nostr relays). Guard the whole
    // parse: a malformed or wrong-typed field must be rejected, never throw.
    try
    {
        json v = json::parse(jsonStr);
        if (!v.is_object()) return false;
        if (!v.contains("pubkey") || !v.contains("enc") || !v.contains("meeting_node")
            || !v.contains("created") || !v.contains("sig")) return false;
        // Reject wrong field types before extracting (json::get would otherwise throw).
        if (!v["pubkey"].is_string() || !v["enc"].is_string() ||
            !v["meeting_node"].is_string() || !v["sig"].is_string() ||
            !v["created"].is_number_unsigned()) return false;

        unsigned char pubkey[32];
        if (!HexDecode(v["pubkey"].get<std::string>(), pubkey, 32)) return false;
        if (memcmp(pubkey, expect_pubkey, 32) != 0) return false; // descriptor is for a different key

        std::string enc          = v["enc"].get<std::string>();
        std::string meeting_node = v["meeting_node"].get<std::string>();
        uint64_t    created      = v["created"].get<uint64_t>();

        unsigned char sig[64];
        if (!HexDecode(v["sig"].get<std::string>(), sig, 64)) return false;

        unsigned char digest[32];
        DescriptorDigest(expect_pubkey, enc, meeting_node, created, digest);

        secp256k1_xonly_pubkey xpub;
        if (!secp256k1_xonly_pubkey_parse(ctx, &xpub, expect_pubkey)) return false;
        if (!secp256k1_schnorrsig_verify(ctx, sig, digest, 32, &xpub)) return false;

        memcpy(out.pubkey, expect_pubkey, 32);
        out.enc = enc;
        out.meeting_node = meeting_node;
        out.created = created;
        return true;
    }
    catch (...)
    {
        return false; // malformed / wrong-typed descriptor -> reject, don't crash
    }
}

} // namespace btf
