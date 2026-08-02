// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Peer discovery over Nostr relays. See nostr.h.

#include "headers.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
// We link libsecp256k1 statically (without this the header assumes DLL import).
// Both makefiles also pass -DSECP256K1_STATIC; the guard keeps that from
// warning while leaving this file correct if built without the flag.
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>

// util.h redefines snprintf as a macro (2009 MSVC compat); this breaks
// nlohmann/json, which calls std::snprintf. Undo the macro just here.
#ifdef snprintf
#undef snprintf
#endif
#include <nlohmann/json.hpp>

#include "btfaddr.h"
#include "btfchan.h"

using json = nlohmann::json;

// Bitflash rendezvous descriptor: parameterized-replaceable Nostr event so each
// node keeps exactly one current descriptor (keyed by author pubkey).
static const int   BTF_DESC_KIND = 38501;
// "-2" scopes the 2026 stable relaunch: new nodes discover only each other, and
// the abandoned test .btf descriptors lingering on the relays become invisible.
static const char* BTF_DESC_DTAG = "btf-descriptor-2";

// Relay auto-discovery: a relay operator announces their relay as an addressable
// event (kind 38502) so every node learns it automatically -- no manual
// seed-list edit, no maintainer approval. Volunteer relays just work.
static const int    BTF_RELAY_KIND = 38502;
static const char*  BTF_RELAY_DTAG = "btf-relay-2";
static const size_t BTF_MAX_DISCOVERED_RELAYS = 50; // anti-spam cap

// Pool announcements carry the operator's .btf address, fee, and live stats.
static const int   BTF_POOL_KIND = 38503;
static const char* BTF_POOL_DTAG  = "btf-pool-2";
static const int64 BTF_POOL_MAX_AGE = 3 * 60; // seconds

// Anonymous auto-discovery: how many peers to keep connected via .btf rendezvous
// before we stop dialing more, and how many new dials to attempt per cycle.
// Target outbound peer count. With ~100 known .btf peers on the network,
// an Erdos-Renyi random graph stays connected with overwhelming probability
// once average degree exceeds ln(N) (~4.6 here); 24 is ~5x past that
// threshold, so this is plenty *provided* selection isn't fully correlated
// across nodes -- see the diversity slice in ConnectDiscoveredBtfPeers.
static const unsigned int BTF_TARGET_CONN   = 24;
static const int          BTF_DIALS_PER_PASS = 12;  // try more peers per Nostr cycle

// Nostr descriptor freshness cutoff: skip peers whose descriptor hasn't been
// refreshed in this many seconds. Stale descriptors mean the node isn't running.
static const int64 BTF_PEER_MAX_AGE = 3 * 60 * 60; // 3 hours

// Other nodes' .btf addresses learned from their descriptors on the relays.
// Maps address -> descriptor created_at timestamp (Unix seconds).
static map<string, int64> g_btfPeers;
static CCriticalSection   cs_btfPeers;

// Public discovery relays. Tunable.
//
// Picked for: free/public (no NIP-42 auth or payment wall), track record of
// high uptime, and *infrastructure* diversity, not just different hostnames.
// relay.damus.io, relay.snort.social and relay.primal.net are all fronted by
// Cloudflare -- different operators, same upstream, so a Cloudflare-side
// incident (or a Cloudflare IP range getting rate-limited/blocked on some
// network) can take out several of them at once even though they look like
// independent relays. Kept only one Cloudflare-fronted relay (damus.io, the
// most established) and filled the rest with relays on different hosts
// (Hetzner, various independents) so no single upstream provider is a
// single point of failure for peer discovery. 7 relays lands inside the
// commonly recommended 5-10 range for redundancy without keeping an
// excessive number of persistent sockets open per node.
const char* pszNostrRelays[] = {
    "wss://relay.damus.io",
    "wss://nos.lol",
    // Was relay.nostr.band, which went down and stayed down (2026-07-31:
    // resolves, refuses TCP on 443, from several networks). Replaced with a
    // relay on a different upstream again -- 206.245.132.32, neither
    // Cloudflare nor Hetzner, which the rest of this list already leans on.
    "wss://nostr.bitcoiner.social",
    "wss://nostr21.com",
    "wss://offchain.pub",
    "wss://nostr.mom",
    "wss://relay.primal.net",
};
const int nNostrRelays = ARRAYLEN(pszNostrRelays);

// Rendezvous meeting relay this node registers at (ThreadBtfAccept in net.cpp)
// and advertises in its .btf descriptor. Seed default; /rvrelay overrides.
// Seed rendezvous relays. More entries = more resilience: the node fails over
// between them (see ThreadBtfAccept), so DDoSing one relay IP can't take the
// network down. /rvrelay overrides this list with a single entry.
vector<string> vBtfMeetingRelays = {
    "92.246.128.180:8434",  // Sao Paulo, BR
    "31.44.4.249:8434",     // New Jersey, US
    "90.156.222.107:8434",  // Almaty, KZ
};
string strBtfActiveRelay;
static CCriticalSection cs_activeRelay;

// Only the rendezvous we actually registered at (BtfSetActiveRelay, called from
// ThreadBtfAccept once registration succeeds). Empty until then, on purpose: it
// used to fall back to vBtfMeetingRelays[0], and since ThreadNostrSeed and
// ThreadBtfAccept start in parallel (net.cpp), that fallback is what got
// published at boot -- a descriptor telling peers to dial a relay we were not
// registered at. When that first seed was down, every peer that read the
// descriptor burned a dial on a dead rendezvous.
string BtfActiveRelay()
{
    CRITICAL_BLOCK(cs_activeRelay)
        return strBtfActiveRelay;
    return "";
}

void BtfSetActiveRelay(const string& relay)
{
    CRITICAL_BLOCK(cs_activeRelay)
        strBtfActiveRelay = relay;
}

// A relay this node advertises on Nostr for others to discover (/announcerelay).
string strBtfAnnounceRelay;
// Relays learned from other operators' Nostr announcements.
static set<string> g_discoveredRelays;
static CCriticalSection cs_discoveredRelays;

// Live pool announcements discovered from the relays.
static map<string, BtfPoolAnnouncement> g_discoveredPools;
static CCriticalSection cs_discoveredPools;

// Basic sanity: "host:port" with a numeric 1..65535 port and a plausible host.
static bool LooksLikeRelay(const string& r)
{
    size_t colon = r.rfind(':');
    if (colon == string::npos || colon == 0 || colon + 1 >= r.size())
        return false;
    if (r.size() > 100)
        return false;
    for (size_t i = colon + 1; i < r.size(); i++)
        if (!isdigit((unsigned char)r[i]))
            return false;
    int port = atoi(r.c_str() + colon + 1);
    if (port <= 0 || port > 65535)
        return false;
    // host: allow letters, digits, dot, dash, colon (IPv6 not supported yet)
    for (size_t i = 0; i < colon; i++)
    {
        char c = r[i];
        if (!(isalnum((unsigned char)c) || c == '.' || c == '-'))
            return false;
    }
    return true;
}

// Every relay to try: curated seeds first (reliable bootstrap), then the ones
// discovered from Nostr announcements (volunteer relays).
vector<string> BtfAllRelays()
{
    vector<string> all = vBtfMeetingRelays;
    CRITICAL_BLOCK(cs_discoveredRelays)
        foreach(const string& r, g_discoveredRelays)
            if (find(all.begin(), all.end(), r) == all.end())
                all.push_back(r);
    return all;
}


//
// Utilities
//
static string HexEncode(const unsigned char* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++)
    {
        s += h[p[i] >> 4];
        s += h[p[i] & 0xf];
    }
    return s;
}

static bool HexDecode(const string& s, unsigned char* out, size_t n)
{
    if (s.size() != n * 2)
        return false;
    for (size_t i = 0; i < n; i++)
    {
        unsigned int b;
        if (sscanf(s.c_str() + i * 2, "%2x", &b) != 1)
            return false;
        out[i] = (unsigned char)b;
    }
    return true;
}

static string Base64Encode(const unsigned char* p, size_t n)
{
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string s;
    for (size_t i = 0; i < n; i += 3)
    {
        unsigned int b = p[i] << 16;
        if (i + 1 < n) b |= p[i + 1] << 8;
        if (i + 2 < n) b |= p[i + 2];
        s += tbl[(b >> 18) & 0x3f];
        s += tbl[(b >> 12) & 0x3f];
        s += (i + 1 < n) ? tbl[(b >> 6) & 0x3f] : '=';
        s += (i + 2 < n) ? tbl[b & 0x3f] : '=';
    }
    return s;
}


//
// Node Nostr key -- secp256k1 x-only (BIP340), persisted in <appdir>/nostr.key
//
class CNostrKey
{
public:
    secp256k1_context* ctx;
    secp256k1_keypair  keypair;
    unsigned char      seckey[32];   // node's secp256k1 secret (for descriptor signing)
    unsigned char      xonly[32];    // node's x-only pubkey (also its .btf identity)
    unsigned char      enc_pk[32];   // node's x25519 public key (echan `enc` field)
    unsigned char      enc_sk[32];   // node's x25519 secret key
    bool               fValid;

    CNostrKey() : ctx(NULL), fValid(false) {}

    ~CNostrKey()
    {
        if (ctx) secp256k1_context_destroy(ctx);
    }

    // Load or generate a 32-byte key persisted as hex in <appdir>/<name>.
    static void LoadOrGenSecp(secp256k1_context* ctx, const string& file, unsigned char sk[32])
    {
        FILE* f = fopen(file.c_str(), "rb");
        string strHex;
        if (f) { char buf[65] = {0}; fread(buf, 1, 64, f); fclose(f); strHex = buf; }
        if (!HexDecode(strHex, sk, 32) || !secp256k1_ec_seckey_verify(ctx, sk))
        {
            do { RAND_bytes(sk, sizeof(unsigned char) * 32); } while (!secp256k1_ec_seckey_verify(ctx, sk));
            FILE* fw = fopen(file.c_str(), "wb");
            if (fw) { string h = HexEncode(sk, 32); fwrite(h.c_str(), 1, h.size(), fw); fclose(fw); }
        }
    }

    bool Init()
    {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (!ctx)
            return false;
        unsigned char seed[32];
        RAND_bytes(seed, sizeof(seed));
        secp256k1_context_randomize(ctx, seed);

        LoadOrGenSecp(ctx, GetAppDir() + "/nostr.key", seckey);

        if (!secp256k1_keypair_create(ctx, &keypair, seckey))
            return false;
        secp256k1_xonly_pubkey xpub;
        if (!secp256k1_keypair_xonly_pub(ctx, &xpub, NULL, &keypair))
            return false;
        secp256k1_xonly_pubkey_serialize(ctx, xonly, &xpub);

        // x25519 encryption keypair for the end-to-end channel, persisted separately.
        btf::ChanInit();
        string strEncFile = GetAppDir() + "/btf_enc.key";
        FILE* fe = fopen(strEncFile.c_str(), "rb");
        bool fLoaded = false;
        if (fe)
        {
            char buf[65] = {0};
            if (fread(buf, 1, 64, fe) == 64 && HexDecode(string(buf), enc_sk, 32))
                fLoaded = true;
            fclose(fe);
        }
        if (fLoaded)
        {
            // Derive the public key from the stored secret (stable identity).
            btf::ChanPublicFromSecret(enc_pk, enc_sk);
        }
        else
        {
            btf::ChanKeypair(enc_pk, enc_sk);
            FILE* few = fopen(strEncFile.c_str(), "wb");
            if (few) { string h = HexEncode(enc_sk, 32); fwrite(h.c_str(), 1, h.size(), few); fclose(few); }
        }

        fValid = true;
        return true;
    }

    string PubKeyHex() const { return HexEncode(xonly, 32); }
    string EncPubHex() const { return HexEncode(enc_pk, 32); }
    string BtfAddress() const { return btf::Address(xonly); }

    bool SignId(const unsigned char id[32], string& sigHexOut)
    {
        unsigned char sig[64];
        unsigned char aux[32];
        RAND_bytes(aux, sizeof(aux));
        if (!secp256k1_schnorrsig_sign32(ctx, sig, id, &keypair, aux))
            return false;
        sigHexOut = HexEncode(sig, 64);
        return true;
    }
};

// The node's single Nostr/.btf identity, shared by the seeding thread here and
// the rendezvous transport in net.cpp. Lazily initialized under a lock; the
// secp256k1 context is immutable after Init, so concurrent use is safe.
static CNostrKey g_nostrKey;
static CCriticalSection cs_nostrKey;

static bool EnsureNostrKey()
{
    CRITICAL_BLOCK(cs_nostrKey)
        if (!g_nostrKey.fValid)
            g_nostrKey.Init();
    return g_nostrKey.fValid;
}

bool BtfGetIdentity(unsigned char pubkey[32], unsigned char enc_sk[32])
{
    if (!EnsureNostrKey())
        return false;
    memcpy(pubkey, g_nostrKey.xonly, 32);
    memcpy(enc_sk, g_nostrKey.enc_sk, 32);
    return true;
}

std::string BtfLocalAddress()
{
    if (!EnsureNostrKey())
        return "";
    return g_nostrKey.BtfAddress();
}

// This node's own descriptor, signed and self-certifying -- the same blob
// PublishDescriptor puts on Nostr, but handed straight to a peer instead.
//
// Reads strBtfActiveRelay directly rather than going through BtfActiveRelay():
// only a rendezvous we actually registered at is worth announcing. Handing out
// a meeting node we are not reachable at would make every peer that receives
// it burn a dial, and over peer exchange that mistake travels further than it
// does over Nostr.
std::string BtfLocalDescriptor()
{
    if (!EnsureNostrKey())
        return "";
    string meeting;
    CRITICAL_BLOCK(cs_activeRelay)
        meeting = strBtfActiveRelay;
    if (meeting.empty())
        return "";
    return btf::SignDescriptor(g_nostrKey.ctx, g_nostrKey.seckey,
                               g_nostrKey.EncPubHex(), meeting, (uint64_t)GetTime());
}

// The shared secp256k1 context, so net.cpp can verify descriptors that arrive
// from peers. NULL if the identity could not be loaded.
void* BtfSecpContext()
{
    if (!EnsureNostrKey())
        return NULL;
    return (void*)g_nostrKey.ctx;
}

int GetDiscoveredPeerCount()
{
    int n = 0;
    CRITICAL_BLOCK(cs_btfPeers) { n = (int)g_btfPeers.size(); }
    return n;
}

void BtfGetPoolAnnouncements(std::vector<BtfPoolAnnouncement>& out)
{
    out.clear();
    int64 now = GetTime();
    CRITICAL_BLOCK(cs_discoveredPools)
    {
        for (map<string, BtfPoolAnnouncement>::iterator it = g_discoveredPools.begin(); it != g_discoveredPools.end(); )
        {
            if (it->second.createdAt > 0 && now - it->second.createdAt > BTF_POOL_MAX_AGE)
            {
                it = g_discoveredPools.erase(it);
                continue;
            }
            out.push_back(it->second);
            ++it;
        }
    }
    sort(out.begin(), out.end(), [](const BtfPoolAnnouncement& a, const BtfPoolAnnouncement& b) {
        return a.createdAt > b.createdAt;
    });
}

// Build and sign a Nostr event (NIP-01). Returns the event JSON.
static bool BuildSignedEvent(CNostrKey& key, int kind, const json& tags,
                             const string& content, json& eventOut)
{
    int64 created = GetTime();
    // Canonical serialization for the id: [0,pubkey,created_at,kind,tags,content]
    json ser = json::array({ 0, key.PubKeyHex(), created, kind, tags, content });
    string s = ser.dump();

    unsigned char id[32];
    SHA256((const unsigned char*)s.data(), s.size(), id);

    string sigHex;
    if (!key.SignId(id, sigHex))
        return false;

    eventOut = json::object();
    eventOut["id"]         = HexEncode(id, 32);
    eventOut["pubkey"]     = key.PubKeyHex();
    eventOut["created_at"] = created;
    eventOut["kind"]       = kind;
    eventOut["tags"]       = tags;
    eventOut["content"]    = content;
    eventOut["sig"]        = sigHex;
    return true;
}


//
// Minimal WebSocket client over TLS (wss) or TCP (ws), blocking with timeout.
//
// Ceilings on what a relay may make this node allocate. Nostr events are
// small -- relays themselves usually refuse anything over a few hundred KB --
// so these are generous, and they bound an otherwise attacker-chosen size.
static const uint64 MAX_WS_FRAME   = 1 << 20;  // 1 MiB per frame
static const uint64 MAX_WS_MESSAGE = 4 << 20;  // 4 MiB reassembled

class CWebSocket
{
public:
    SOCKET     hSocket;
    SSL_CTX*   sslctx;
    SSL*       ssl;
    bool       fTls;
    string     recvbuf;

    CWebSocket() : hSocket(INVALID_SOCKET), sslctx(NULL), ssl(NULL), fTls(false) {}
    ~CWebSocket() { Close(); }

    void Close()
    {
        if (ssl)    { SSL_shutdown(ssl); SSL_free(ssl); ssl = NULL; }
        if (sslctx) { SSL_CTX_free(sslctx); sslctx = NULL; }
        if (hSocket != INVALID_SOCKET) { BtfCloseSocket(hSocket); hSocket = INVALID_SOCKET; }
    }

    int RawRead(char* buf, int len)
    {
        if (fTls) return SSL_read(ssl, buf, len);
        return recv(hSocket, buf, len, 0);
    }

    bool RawWrite(const char* buf, int len)
    {
        int off = 0;
        while (off < len)
        {
            int n = fTls ? SSL_write(ssl, buf + off, len - off)
                         : send(hSocket, buf + off, len - off, 0);
            if (n <= 0) return false;
            off += n;
        }
        return true;
    }

    // Connect and perform the WebSocket handshake. url = wss://host[:port]/path
    bool Connect(const string& url, int timeoutSec)
    {
        string u = url;
        int port = 443;
        fTls = true;
        if (u.compare(0, 6, "wss://") == 0) { u = u.substr(6); fTls = true; port = 443; }
        else if (u.compare(0, 5, "ws://") == 0) { u = u.substr(5); fTls = false; port = 80; }
        else return false;

        string host, path = "/";
        size_t slash = u.find('/');
        if (slash != string::npos) { host = u.substr(0, slash); path = u.substr(slash); }
        else host = u;
        size_t colon = host.find(':');
        if (colon != string::npos) { port = atoi(host.substr(colon + 1).c_str()); host = host.substr(0, colon); }

        // Resolve and connect (TCP). AF_UNSPEC so we get both A and AAAA
        // records back and try them in the order the resolver prefers,
        // rather than hard-failing whenever the IPv4 path to a relay is
        // filtered/rate-limited (increasingly common for CDN-fronted
        // relays) while a working IPv6 route exists right there in the
        // same getaddrinfo() result.
        struct addrinfo hints, *res = NULL, *rp = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        char portstr[16]; sprintf(portstr, "%d", port);
        if (getaddrinfo(host.c_str(), portstr, &hints, &res) != 0 || !res)
            return error("Nostr: getaddrinfo %s failed", host.c_str());

        bool fConnected = false;
        for (rp = res; rp != NULL; rp = rp->ai_next)
        {
            hSocket = BtfSocketTag(socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol), SOCK_NOSTR);
            if (hSocket == INVALID_SOCKET)
                continue;

            // Socket receive/send timeout: Windows takes a DWORD of
            // milliseconds; POSIX takes a struct timeval.
#ifdef _WIN32
            DWORD tv = timeoutSec * 1000;
            setsockopt(hSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
            setsockopt(hSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));
#else
            struct timeval tv;
            tv.tv_sec = timeoutSec;
            tv.tv_usec = 0;
            setsockopt(hSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
            setsockopt(hSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));
#endif

            if (connect(hSocket, rp->ai_addr, (int)rp->ai_addrlen) == 0)
            {
                fConnected = true;
                break;
            }

            BtfCloseSocket(hSocket);
            hSocket = INVALID_SOCKET;
        }
        freeaddrinfo(res);

        if (!fConnected)
            return error("Nostr: connect %s:%d failed", host.c_str(), port);

        // TLS
        if (fTls)
        {
            sslctx = SSL_CTX_new(TLS_client_method());
            if (!sslctx) return false;
            ssl = SSL_new(sslctx);
            SSL_set_fd(ssl, (int)hSocket);
            SSL_set_tlsext_host_name(ssl, host.c_str());  // SNI
            if (SSL_connect(ssl) != 1)
                return error("Nostr: TLS handshake with %s failed", host.c_str());
        }

        // WebSocket handshake (HTTP Upgrade)
        unsigned char keybytes[16];
        RAND_bytes(keybytes, sizeof(keybytes));
        string wskey = Base64Encode(keybytes, sizeof(keybytes));
        string req =
            "GET " + path + " HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: " + wskey + "\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n";
        if (!RawWrite(req.data(), (int)req.size()))
            return false;

        // Read the handshake response until \r\n\r\n
        string resp;
        char c;
        while (resp.find("\r\n\r\n") == string::npos)
        {
            int n = RawRead(&c, 1);
            if (n <= 0) return error("Nostr: no handshake response from %s", host.c_str());
            resp += c;
            // Bail out instead of breaking: breaking left the socket parked in
            // the middle of the header block, and since the status line is read
            // first the " 101 " check below still passed -- so the caller got a
            // "connected" socket whose next bytes were leftover HTTP, which the
            // frame parser then read as garbage frames.
            if (resp.size() > 8192)
                return error("Nostr: handshake headers too large from %s", host.c_str());
        }
        if (resp.find(" 101 ") == string::npos)
            return error("Nostr: handshake refused by %s", host.c_str());
        return true;
    }

    // Send a text message (masked frame, as required by the protocol)
    bool SendText(const string& msg)
    {
        string frame;
        frame += (char)0x81; // FIN + opcode texto
        size_t len = msg.size();
        if (len < 126)
            frame += (char)(0x80 | len);
        else if (len <= 0xffff)
        {
            frame += (char)(0x80 | 126);
            frame += (char)((len >> 8) & 0xff);
            frame += (char)(len & 0xff);
        }
        else
        {
            frame += (char)(0x80 | 127);
            for (int i = 7; i >= 0; i--) frame += (char)((len >> (8 * i)) & 0xff);
        }
        unsigned char mask[4];
        RAND_bytes(mask, 4);
        frame.append((char*)mask, 4);
        string masked = msg;
        for (size_t i = 0; i < masked.size(); i++)
            masked[i] ^= mask[i & 3];
        frame += masked;
        return RawWrite(frame.data(), (int)frame.size());
    }

    // Receive the next complete text message. Returns false on error/timeout.
    bool RecvText(string& out)
    {
        out.clear();
        for (;;)
        {
            unsigned char hdr[2];
            if (!ReadN((char*)hdr, 2)) return false;
            bool fin = hdr[0] & 0x80;
            int opcode = hdr[0] & 0x0f;
            bool masked = hdr[1] & 0x80;
            uint64 len = hdr[1] & 0x7f;
            if (len == 126)
            {
                unsigned char e[2];
                if (!ReadN((char*)e, 2)) return false;
                len = (e[0] << 8) | e[1];
            }
            else if (len == 127)
            {
                unsigned char e[8];
                if (!ReadN((char*)e, 8)) return false;
                len = 0;
                for (int i = 0; i < 8; i++) len = (len << 8) | e[i];
            }
            // The length is whatever the relay says it is, and these are public
            // relays the node does not control. Unbounded, a single frame header
            // claiming 2^40 bytes makes the node allocate until it dies -- and
            // reassembly across continuation frames grows without limit even
            // when each frame is small. Cap both, and refuse anything that will
            // not survive the int narrowing ReadN takes.
            if (len > MAX_WS_FRAME) return false;

            unsigned char mask[4] = {0,0,0,0};
            if (masked && !ReadN((char*)mask, 4)) return false;

            string payload;
            payload.resize((size_t)len);
            if (len && !ReadN(&payload[0], (int)len)) return false;
            if (masked)
                for (size_t i = 0; i < payload.size(); i++)
                    payload[i] ^= mask[i & 3];

            if (opcode == 0x8) return false;                 // close
            if (opcode == 0x9) { SendPong(payload); continue; } // ping
            if (opcode == 0xA) continue;                      // pong
            if (out.size() + payload.size() > MAX_WS_MESSAGE) return false;
            out += payload;                                   // text/continuation
            if (fin) return true;
        }
    }

private:
    bool ReadN(char* buf, int n)
    {
        int off = 0;
        while (off < n)
        {
            int r = RawRead(buf + off, n - off);
            if (r <= 0) return false;
            off += r;
        }
        return true;
    }

    void SendPong(const string& payload)
    {
        string frame;
        frame += (char)0x8A;
        frame += (char)(0x80 | (payload.size() & 0x7f));
        unsigned char mask[4]; RAND_bytes(mask, 4);
        frame.append((char*)mask, 4);
        string m = payload;
        for (size_t i = 0; i < m.size(); i++) m[i] ^= mask[i & 3];
        frame += m;
        RawWrite(frame.data(), (int)frame.size());
    }
};


// Persistent relay connections. Public relays (relay.damus.io in particular)
// rate-limit new connections per source IP fairly aggressively. Before this,
// every single operation -- self-test, per-pass seeding, batch descriptor
// resolve, pool announce, pool query -- opened its own fresh CWebSocket,
// meaning a single node could fire a dozen-plus brand-new TCP+TLS+WS
// handshakes at the same 4 relays within any given minute (ThreadNostrSeed's
// own loop plus the separate ThreadBtfPoolAnnouncer thread, each reconnecting
// from scratch every cycle). That's exactly what was showing up as constant
// "handshake refused by relay.damus.io" and "connect ... failed" -- not
// necessarily dead relays, just this node getting rate-limited by its own
// reconnect churn.
//
// Now every relay-touching call reuses one long-lived socket per relay via
// this pool, reconnecting only when a socket actually drops. That cuts fresh
// connections from several per minute down to essentially one per relay for
// the life of the process.
struct RelayConn
{
    CWebSocket ws;
    CCriticalSection cs;   // serializes use of this relay's socket
    bool fConnected;
    RelayConn() : fConnected(false) {}
};
static map<string, RelayConn*> g_relayPool;
static CCriticalSection cs_relayPool;

static RelayConn* GetRelayConn(const string& relay)
{
    CRITICAL_BLOCK(cs_relayPool)
    {
        map<string, RelayConn*>::iterator it = g_relayPool.find(relay);
        if (it != g_relayPool.end())
            return it->second;
        RelayConn* rc = new RelayConn();
        g_relayPool[relay] = rc;
        return rc;
    }
    return NULL; // unreachable
}

// RAII lease on a relay's pooled connection: connects (if not already
// connected) on construction, and on destruction either keeps the socket
// alive for the next caller (if the exchange succeeded) or closes it so the
// next caller reconnects instead of reusing a socket that may be wedged.
// Caller must set fOk = true once its exchange with the relay completed
// cleanly.
class CRelayLease
{
public:
    RelayConn* rc;
    bool fOk;
    bool fJustConnected; // true if this lease had to (re)connect, false if reusing a live socket

    CRelayLease(const string& relay, int timeoutSec) : rc(NULL), fOk(false), fJustConnected(false)
    {
        rc = GetRelayConn(relay);
        rc->cs.Enter();
        if (!rc->fConnected)
        {
            rc->ws.Close();
            rc->fConnected = rc->ws.Connect(relay, timeoutSec);
            fJustConnected = rc->fConnected;
        }
    }
    ~CRelayLease()
    {
        if (!fOk)
        {
            rc->ws.Close();
            rc->fConnected = false;
        }
        rc->cs.Leave();
    }
    bool Connected() const { return rc->fConnected; }
    CWebSocket& Ws() { return rc->ws; }

private:
    CRelayLease(const CRelayLease&);
    CRelayLease& operator=(const CRelayLease&);
};


// Publish this node's self-certifying `.btf` descriptor: "reach me (this key)
// via <meeting_node>, encrypting to my x25519 key <enc>". Signed by the node
// key so only the address's owner can publish it (no hijacking).
static void PublishDescriptor(CWebSocket& ws, CNostrKey& key)
{
    // meeting_node is the rendezvous relay this node's hidden service
    // (ThreadBtfAccept in net.cpp) is registered at -- where clients dial us.
    string meeting_node = BtfActiveRelay();
    if (meeting_node.empty())
    {
        // Not registered anywhere yet. Publishing now would advertise a meeting
        // node we can't be reached at, and peers would waste dials on it. The
        // ThreadNostrSeed loop republishes on every pass, so skipping costs
        // nothing but the delay until ThreadBtfAccept registers.
        LogPrint("nostr", "Nostr: skipping descriptor publish, no rendezvous registered yet\n");
        return;
    }
    string desc = btf::SignDescriptor(key.ctx, key.seckey, key.EncPubHex(),
                                      meeting_node, (uint64_t)GetTime());
    if (desc.empty())
        return;
    json tags = json::array({ json::array({ "d", BTF_DESC_DTAG }) });
    json ev;
    if (BuildSignedEvent(key, BTF_DESC_KIND, tags, desc, ev))
    {
        json pub = json::array({ "EVENT", ev });
        ws.SendText(pub.dump());
    }
}

// Announce our relay (from /announcerelay=host:port) so every node discovers it
// automatically -- volunteer relays join the network with no maintainer step.
static void PublishRelayAnnouncement(CWebSocket& ws, CNostrKey& key)
{
    if (strBtfAnnounceRelay.empty())
        return;
    json tags = json::array({ json::array({ "d", BTF_RELAY_DTAG }) });
    json ev;
    if (BuildSignedEvent(key, BTF_RELAY_KIND, tags, strBtfAnnounceRelay, ev))
    {
        json pub = json::array({ "EVENT", ev });
        ws.SendText(pub.dump());
    }
}

static bool PublishPoolAnnouncementOnRelay(CWebSocket& ws, CNostrKey& key,
                                           const BtfPoolAnnouncement& ann)
{
    if (ann.btfAddress.empty() || ann.poolName.empty())
        return false;

    json content = json::object();
    content["btf"] = ann.btfAddress;
    content["name"] = ann.poolName;
    if (!ann.dashboardUrl.empty())
        content["dashboard_url"] = ann.dashboardUrl;
    content["fee_pct"] = ann.feePercent;
    content["miners"] = ann.connectedMiners;
    content["blocks"] = ann.blocksFound;
    content["hashrate"] = ann.hashRate;

    json tags = json::array({
        json::array({ "d", BTF_POOL_DTAG }),
        json::array({ "t", BTF_POOL_DTAG })
    });
    json ev;
    if (!BuildSignedEvent(key, BTF_POOL_KIND, tags, content.dump(), ev))
        return false;
    json pub = json::array({ "EVENT", ev });
    return ws.SendText(pub.dump());
}

bool BtfPublishPoolAnnouncement(const BtfPoolAnnouncement& ann)
{
    if (!EnsureNostrKey())
        return false;

    bool fPublished = false;
    for (int i = 0; i < nNostrRelays && !fShutdown; i++)
    {
        try
        {
            CRelayLease lease(pszNostrRelays[i], 10);
            if (!lease.Connected())
                continue;
            if (PublishPoolAnnouncementOnRelay(lease.Ws(), g_nostrKey, ann))
                fPublished = lease.fOk = true;
        }
        CATCH_PRINT_EXCEPTION("BtfPublishPoolAnnouncement")
    }
    return fPublished;
}

bool BtfQueryPoolAnnouncement(const std::string& poolBtfAddr, BtfPoolAnnouncement& out)
{
    unsigned char pk[32];
    if (!btf::ParseAddress(poolBtfAddr, pk))
        return false;

    if (!EnsureNostrKey())
        return false;

    int64 bestCreatedAt = 0;
    bool fFound = false;
    for (int i = 0; i < nNostrRelays && !fShutdown; i++)
    {
        try
        {
            CRelayLease lease(pszNostrRelays[i], 10);
            if (!lease.Connected())
                continue;
            CWebSocket& ws = lease.Ws();

            json filter = json::object();
            filter["authors"] = json::array({ HexEncode(pk, 32) });
            filter["kinds"] = json::array({ BTF_POOL_KIND });
            filter["#d"] = json::array({ BTF_POOL_DTAG });
            filter["limit"] = 1;
            json req = json::array({ "REQ", "btf-pool-query", filter });
            if (!ws.SendText(req.dump()))
                continue;

            for (;;)
            {
                string msg;
                if (!ws.RecvText(msg))
                    break;
                json j;
                try { j = json::parse(msg); } catch (...) { continue; }
                if (!j.is_array() || j.empty() || !j[0].is_string()) continue;
                string type = j[0].get<string>();
                if (type == "EVENT" && j.size() >= 3)
                {
                    const json& ev = j[2];
                    if (!ev.contains("content") || !ev["content"].is_string())
                        continue;
                    BtfPoolAnnouncement ann;
                    try
                    {
                        json content = json::parse(ev["content"].get<string>());
                        if (content.contains("btf") && content["btf"].is_string())
                            ann.btfAddress = content["btf"].get<string>();
                        if (content.contains("name") && content["name"].is_string())
                            ann.poolName = content["name"].get<string>();
                        if (content.contains("dashboard_url") && content["dashboard_url"].is_string())
                            ann.dashboardUrl = content["dashboard_url"].get<string>();
                        ann.feePercent = content.value("fee_pct", content.value("fee", 0.0));
                        ann.connectedMiners = content.value("miners", 0);
                        ann.blocksFound = content.value("blocks", 0);
                        ann.hashRate = content.value("hashrate", 0.0);
                        ann.createdAt = ev.value("created_at", (int64)0);
                    }
                    catch (...)
                    {
                        continue;
                    }
                    if (ann.btfAddress == poolBtfAddr && ann.createdAt >= bestCreatedAt)
                    {
                        bestCreatedAt = ann.createdAt;
                        out = ann;
                        fFound = true;
                    }
                }
                else if (type == "EOSE")
                    break;
            }
            lease.fOk = true;
        }
        CATCH_PRINT_EXCEPTION("BtfQueryPoolAnnouncement")
    }

    return fFound;
}

static void HandlePoolAnnouncement(const json& ev)
{
    if (!ev.contains("content") || !ev["content"].is_string())
        return;

    BtfPoolAnnouncement ann;
    try
    {
        json content = json::parse(ev["content"].get<string>());
        if (content.contains("btf") && content["btf"].is_string())
            ann.btfAddress = content["btf"].get<string>();
        else if (content.contains("address") && content["address"].is_string())
            ann.btfAddress = content["address"].get<string>();
        if (content.contains("name") && content["name"].is_string())
            ann.poolName = content["name"].get<string>();
        else if (content.contains("pool_name") && content["pool_name"].is_string())
            ann.poolName = content["pool_name"].get<string>();
        if (content.contains("dashboard_url") && content["dashboard_url"].is_string())
            ann.dashboardUrl = content["dashboard_url"].get<string>();
        else if (content.contains("dashboard") && content["dashboard"].is_string())
            ann.dashboardUrl = content["dashboard"].get<string>();
        ann.feePercent = content.value("fee_pct", content.value("fee", 0.0));
        ann.connectedMiners = content.value("miners", 0);
        ann.blocksFound = content.value("blocks", 0);
        ann.hashRate = content.value("hashrate", 0.0);
        ann.createdAt = ev.value("created_at", (int64)0);
    }
    catch (...)
    {
        return;
    }

    if (ann.btfAddress.empty() || ann.poolName.empty())
        return;

    CRITICAL_BLOCK(cs_discoveredPools)
    {
        map<string, BtfPoolAnnouncement>::iterator it = g_discoveredPools.find(ann.btfAddress);
        if (it == g_discoveredPools.end() || ann.createdAt >= it->second.createdAt)
            g_discoveredPools[ann.btfAddress] = ann;
    }
}

// Resolve a `.btf` address via a relay: fetch the descriptor published by that
// address's key and verify it self-certifies under the decoded pubkey.
static bool ResolveDescriptor(CWebSocket& ws, void* ctx, const string& btfAddr,
                              btf::Descriptor& out)
{
    unsigned char pk[32];
    if (!btf::ParseAddress(btfAddr, pk))
        return false;
    json filter = json::object();
    filter["authors"] = json::array({ HexEncode(pk, 32) });
    filter["kinds"]   = json::array({ BTF_DESC_KIND });
    filter["limit"]   = 1;
    json req = json::array({ "REQ", "btf-resolve", filter });
    if (!ws.SendText(req.dump()))
        return false;
    for (;;)
    {
        string msg;
        if (!ws.RecvText(msg))
            break;
        json j;
        try { j = json::parse(msg); } catch (...) { continue; }
        if (!j.is_array() || j.empty() || !j[0].is_string()) continue;
        string t = j[0].get<string>();
        if (t == "EVENT" && j.size() >= 3)
        {
            const json& ev = j[2];
            if (ev.contains("content") &&
                btf::VerifyDescriptor(ctx, ev["content"].get<string>(), pk, out))
                return true;
        }
        else if (t == "EOSE")
            break;
    }
    return false;
}

// Resolve a `.btf` address into its rendezvous coordinates by querying the
// public discovery relays for the owner's self-certified descriptor. Used by
// ConnectNodeBtf in net.cpp.
bool BtfResolve(const std::string& btfAddr, std::string& meetingHostPort,
                unsigned char enc_pub[32])
{
    if (!EnsureNostrKey())
        return false;
    for (int i = 0; i < nNostrRelays && !fShutdown; i++)
    {
        try
        {
            CRelayLease lease(pszNostrRelays[i], 10);
            if (!lease.Connected())
                continue;
            btf::Descriptor d;
            if (!ResolveDescriptor(lease.Ws(), g_nostrKey.ctx, btfAddr, d))
            {
                lease.fOk = true; // exchange completed, just no match
                continue;
            }
            lease.fOk = true;
            if (d.meeting_node.empty() || d.meeting_node == "rendezvous-pending")
                continue; // descriptor predates the owner's relay config
            if (!HexDecode(d.enc, enc_pub, 32))
                continue;
            meetingHostPort = d.meeting_node;
            return true;
        }
        CATCH_PRINT_EXCEPTION("BtfResolve")
    }
    return false;
}

// Resolve MANY .btf addresses in one pass. A single relay connection carries
// a REQ with every still-unresolved address's pubkey in "authors", instead of
// opening one relay connection per address. This matters because callers like
// ConnectDiscoveredBtfPeers dial many candidates in parallel; without
// batching, each of those dial threads independently walks the same handful
// of public relays on its own, so a pass of N candidates can fire up to
// N * nNostrRelays near-simultaneous connections at the same few relays --
// enough to get rate-limited or have handshakes refused, which then looks
// like "dead peers" even though the descriptors are perfectly resolvable.
bool BtfResolveMany(const std::vector<std::string>& btfAddrs,
                     std::map<std::string, BtfResolvedPeer>& out)
{
    if (!EnsureNostrKey() || btfAddrs.empty())
        return false;

    map<string, string> hexToAddr; // pubkey hex -> .btf addr, for matching events back
    set<string> pending;
    for (const string& a : btfAddrs)
    {
        unsigned char pk[32];
        if (!btf::ParseAddress(a, pk))
            continue;
        hexToAddr[HexEncode(pk, 32)] = a;
        pending.insert(a);
    }
    if (pending.empty())
        return false;

    for (int i = 0; i < nNostrRelays && !fShutdown && !pending.empty(); i++)
    {
        try
        {
            CRelayLease lease(pszNostrRelays[i], 10);
            if (!lease.Connected())
                continue;
            CWebSocket& ws = lease.Ws();

            json authors = json::array();
            for (auto& kv : hexToAddr)
                if (pending.count(kv.second))
                    authors.push_back(kv.first);
            if (authors.empty())
            {
                lease.fOk = true;
                break;
            }

            json filter = json::object();
            filter["authors"] = authors;
            filter["kinds"]   = json::array({ BTF_DESC_KIND });
            filter["limit"]   = (int)authors.size();
            json req = json::array({ "REQ", "btf-resolve-many", filter });
            if (!ws.SendText(req.dump()))
                continue;

            for (;;)
            {
                string msg;
                if (!ws.RecvText(msg))
                    break;
                json j;
                try { j = json::parse(msg); } catch (...) { continue; }
                if (!j.is_array() || j.empty() || !j[0].is_string()) continue;
                string t = j[0].get<string>();
                if (t == "EVENT" && j.size() >= 3)
                {
                    const json& ev = j[2];
                    if (!ev.contains("pubkey") || !ev.contains("content"))
                        continue;
                    string hexpk = ev["pubkey"].get<string>();
                    auto ai = hexToAddr.find(hexpk);
                    if (ai == hexToAddr.end() || !pending.count(ai->second))
                        continue; // not one we're waiting on (or already resolved)

                    unsigned char pk[32];
                    if (!HexDecode(hexpk, pk, 32))
                        continue;
                    btf::Descriptor d;
                    if (!btf::VerifyDescriptor(g_nostrKey.ctx, ev["content"].get<string>(), pk, d))
                        continue;
                    if (d.meeting_node.empty() || d.meeting_node == "rendezvous-pending")
                        continue;
                    BtfResolvedPeer rp;
                    if (!HexDecode(d.enc, rp.enc_pub, 32))
                        continue;
                    rp.meetingHostPort = d.meeting_node;
                    out[ai->second] = rp;
                    pending.erase(ai->second);
                }
                else if (t == "EOSE")
                    break;
            }
            lease.fOk = true;
        }
        CATCH_PRINT_EXCEPTION("BtfResolveMany")
    }
    return !out.empty();
}


// ---- per-relay backoff -----------------------------------------------------
//
// A relay that is down costs the whole discovery loop the full connect timeout,
// every round, forever. relay.nostr.band went down and produced 1092 identical
// error lines on the seed while adding ten seconds to every pass -- and the
// loop is what discovers peers, so a dead relay was slowing down the live ones.
//
// Back off per relay instead: 30s after the first failure, doubling to a
// fifteen-minute ceiling, cleared the moment it answers again. This changes
// only when an attempt happens, never whether discovery is correct.
struct CRelayBackoff
{
    int64 nNextTry;
    int   nFails;
    CRelayBackoff() : nNextTry(0), nFails(0) {}
};
static map<string, CRelayBackoff> mapRelayBackoff;
static CCriticalSection           cs_relayBackoff;

static const int64 RELAY_BACKOFF_BASE_SECS = 30;
static const int64 RELAY_BACKOFF_MAX_SECS  = 15 * 60;

static bool RelayDueForRetry(const string& relay)
{
    CRITICAL_BLOCK(cs_relayBackoff)
    {
        map<string, CRelayBackoff>::iterator it = mapRelayBackoff.find(relay);
        if (it == mapRelayBackoff.end())
            return true;
        return GetTime() >= it->second.nNextTry;
    }
    return true;
}

static void RelayNoteFailure(const string& relay)
{
    CRITICAL_BLOCK(cs_relayBackoff)
    {
        CRelayBackoff& b = mapRelayBackoff[relay];
        b.nFails++;
        int64 nWait = RELAY_BACKOFF_BASE_SECS;
        for (int i = 1; i < b.nFails && nWait < RELAY_BACKOFF_MAX_SECS; i++)
            nWait *= 2;
        if (nWait > RELAY_BACKOFF_MAX_SECS)
            nWait = RELAY_BACKOFF_MAX_SECS;
        b.nNextTry = GetTime() + nWait;
        // Only on the way in, so a relay that stays down says this once per
        // backoff step rather than once per pass.
        LogPrint("nostr", "Nostr: %s unreachable (%d in a row), not retrying for %ds\n",
                 relay.c_str(), b.nFails, (int)nWait);
    }
}

static void RelayNoteSuccess(const string& relay)
{
    CRITICAL_BLOCK(cs_relayBackoff)
    {
        map<string, CRelayBackoff>::iterator it = mapRelayBackoff.find(relay);
        if (it != mapRelayBackoff.end())
        {
            if (it->second.nFails > 0)
                LogPrint("nostr", "Nostr: %s answering again after %d failure(s)\n",
                         relay.c_str(), it->second.nFails);
            mapRelayBackoff.erase(it);
        }
    }
}

// Connect to a relay: publish our .btf descriptor and collect relay data.
static bool SeedFromRelay(CNostrKey& key, const string& relay)
{
    CRelayLease lease(relay, 10);
    if (!lease.Connected())
        return false;
    CWebSocket& ws = lease.Ws();
    if (lease.fJustConnected)
        LogPrint("nostr", "Nostr: connected to %s\n", relay.c_str());

    // Publish our self-certifying .btf descriptor (rendezvous discovery)
    PublishDescriptor(ws, key);

    // If we run a relay, announce it so others discover it automatically
    PublishRelayAnnouncement(ws, key);

    // Discover other nodes' .btf descriptors so we can auto-connect anonymously
    // (no manual /connectbtf). Each node publishes one addressable descriptor
    // (kind 38501, d-tag btf-descriptor); we learn every peer's .btf address by
    // deriving it from the event author. Reachability is verified later, when
    // the rendezvous tunnel boxes to that key's static x25519 key.
    ws.SendText(json::array({ "CLOSE", "bf-sub" }).dump());
    {
        json dfilter = json::object();
        dfilter["kinds"] = json::array({ BTF_DESC_KIND });
        dfilter["#d"]    = json::array({ BTF_DESC_DTAG });
        dfilter["limit"] = 200;
        json dreq = json::array({ "REQ", "btf-disc", dfilter });
        int nPeers = 0;
        if (ws.SendText(dreq.dump()))
        {
            for (;;)
            {
                string msg;
                if (!ws.RecvText(msg))
                    break;
                json j;
                try { j = json::parse(msg); } catch (...) { continue; }
                if (!j.is_array() || j.empty() || !j[0].is_string()) continue;
                string type = j[0].get<string>();
                if (type == "EVENT" && j.size() >= 3)
                {
                    const json& ev = j[2];
                    if (!ev.contains("pubkey") || !ev.contains("kind")) continue;
                    if (ev["kind"].get<int>() != BTF_DESC_KIND) continue;
                    unsigned char pkb[32];
                    if (!HexDecode(ev["pubkey"].get<string>(), pkb, 32)) continue;
                    if (memcmp(pkb, key.xonly, 32) == 0) continue; // not ourselves
                    string peerAddr = btf::Address(pkb);
                    int64 createdAt = ev.value("created_at", (int64)0);
                    bool fNew = false;
                    CRITICAL_BLOCK(cs_btfPeers)
                    {
                        auto it = g_btfPeers.find(peerAddr);
                        if (it == g_btfPeers.end()) { g_btfPeers[peerAddr] = createdAt; fNew = true; }
                        else if (createdAt > it->second)  it->second = createdAt; // refresh
                    }
                    if (fNew && fDebug)
                        LogPrint("nostr", "Nostr: discovered .btf peer %s\n", peerAddr.c_str());
                    if (++nPeers > 500) break;
                }
                else if (type == "EOSE")
                    break;
            }
        }
    }

    // Discover volunteer relays announced by other operators (kind 38502). Nodes
    // add these to their failover list automatically, so anyone can strengthen
    // the network without a maintainer editing the seed list. Bad/dead relays
    // just fail to pair and get skipped -- and a relay is trustless anyway (it
    // only forwards echan ciphertext and can't read or MITM the traffic).
    ws.SendText(json::array({ "CLOSE", "btf-disc" }).dump());
    {
        json rfilter = json::object();
        rfilter["kinds"] = json::array({ BTF_RELAY_KIND });
        rfilter["#d"]    = json::array({ BTF_RELAY_DTAG });
        rfilter["limit"] = 200;
        json rreq = json::array({ "REQ", "btf-relays", rfilter });
        if (ws.SendText(rreq.dump()))
        {
            for (;;)
            {
                string msg;
                if (!ws.RecvText(msg))
                    break;
                json j;
                try { j = json::parse(msg); } catch (...) { continue; }
                if (!j.is_array() || j.empty() || !j[0].is_string()) continue;
                string type = j[0].get<string>();
                if (type == "EVENT" && j.size() >= 3)
                {
                    const json& ev = j[2];
                    if (!ev.contains("content") || !ev.contains("kind")) continue;
                    if (ev["kind"].get<int>() != BTF_RELAY_KIND) continue;
                    string r = ev["content"].get<string>();
                    if (!LooksLikeRelay(r)) continue;
                    bool fNew = false;
                    CRITICAL_BLOCK(cs_discoveredRelays)
                        if (g_discoveredRelays.size() < BTF_MAX_DISCOVERED_RELAYS)
                            fNew = g_discoveredRelays.insert(r).second;
                    if (fNew && fDebug)
                        LogPrint("nostr", "Nostr: discovered relay %s\n", r.c_str());
                }
                else if (type == "EOSE")
                    break;
            }
        }
    }

    // Discover live pool announcements. These are expiring status beacons, not
    // permanent directory entries, so the GUI can show only fresh pools.
    ws.SendText(json::array({ "CLOSE", "btf-pools" }).dump());
    {
        json pfilter = json::object();
        pfilter["kinds"] = json::array({ BTF_POOL_KIND });
        pfilter["#d"]    = json::array({ BTF_POOL_DTAG });
        pfilter["limit"]  = 200;
        json preq = json::array({ "REQ", "btf-pools", pfilter });
        if (ws.SendText(preq.dump()))
        {
            for (;;)
            {
                string msg;
                if (!ws.RecvText(msg))
                    break;
                json j;
                try { j = json::parse(msg); } catch (...) { continue; }
                if (!j.is_array() || j.empty() || !j[0].is_string()) continue;
                string type = j[0].get<string>();
                if (type == "EVENT" && j.size() >= 3)
                    HandlePoolAnnouncement(j[2]);
                else if (type == "EOSE")
                    break;
            }
        }
    }
    lease.fOk = true;
    return true;
}

volatile bool gAnnounceNow = false;

void ThreadBtfPoolAnnouncer(void*)
{
    LogPrint("pool", "ThreadBtfPoolAnnouncer started\n");
    while (!fShutdown)
    {
        if (nMineMode == MINE_OPERATOR && gPoolRunning)
        {
            BtfPoolAnnouncement ann;
            ann.btfAddress = BtfLocalAddress();
            ann.poolName = strPoolName;
            ann.dashboardUrl = strPoolDashboardUrl;
            ann.feePercent = dPoolFeePercent;
            uint64 roundShares = 0;
            double totalHashRate = 0.0;
            GetPoolOperatorStats(ann.connectedMiners, ann.blocksFound, roundShares, totalHashRate);
            ann.hashRate = totalHashRate;
            ann.createdAt = GetTime();
            if (!ann.btfAddress.empty() && !ann.poolName.empty())
                BtfPublishPoolAnnouncement(ann);
        }

        for (int i = 0; i < 60 && !fShutdown && !gAnnounceNow; i++)
            Sleep(1000);
        gAnnounceNow = false;
    }
}


// Per-peer backoff: don't redial a .btf that just failed until this time. Keeps
// dead/stale descriptors (e.g. abandoned test identities that linger on the
// relays) from consuming the whole per-pass dial budget and starving the live
// peers. Backoff grows on repeated failures, capped.
//
// g_btfPeerFails also doubles as the priority signal for dial ordering: a peer
// we've connected to before (present in g_btfPeerEverConnected) is known-good
// and goes first; a peer we've never tried goes next; a peer with a growing
// fail count is known-bad and goes last, worst offenders furthest back. This
// replaces the old behavior where the whole candidate list was shuffled right
// after being sorted by freshness, which made the freshness sort a no-op and
// gave dead peers equal footing with everyone else.
static map<string, int64> g_btfPeerBackoff;   // addr -> next-try time
static map<string, int>   g_btfPeerFails;      // addr -> consecutive failures
static set<string>        g_btfPeerEverConnected; // addr -> has succeeded at least once
static CCriticalSection   cs_btfPeerState;

// Backoff cap for repeatedly-dead peers. The old 15-minute cap meant a
// descriptor that has failed many times in a row cycles back into the dial
// pool just as often as a peer we've never tried, wasting dial budget on
// known-dead addresses every pass. Once a peer has failed enough times to
// be "chronic", stretch the cap much further so it consumes budget far less
// often while still getting retried eventually in case it comes back online.
static const int64 BTF_BACKOFF_CAP_SECS       = 15 * 60;      // 15 min: initial ramp cap
static const int64 BTF_BACKOFF_CAP_SECS_DEAD  = 6 * 60 * 60;  // 6 hr: cap for chronic failures
static const int   BTF_CHRONIC_FAIL_THRESHOLD = 6;            // fails before "chronic" cap kicks in

// Dial the .btf peers discovered on the relays, up to a target connection count.
// Connections are attempted in parallel so a single slow/dead relay doesn't
// stall the entire pass. Each candidate gets its own thread; all threads start
// at once and we wait for them to finish before returning.
static void ConnectDiscoveredBtfPeers()
{
    vector<pair<int64,string>> peersWithAge;
    int nTotal = 0;
    CRITICAL_BLOCK(cs_btfPeers)
    {
        nTotal = g_btfPeers.size();
        for (auto& kv : g_btfPeers)
            peersWithAge.push_back({kv.second, kv.first});
    }
    int64 cutoff = GetTime() - BTF_PEER_MAX_AGE;
    int nFresh = 0;
    vector<pair<int64,string>> fresh; // (createdAt, addr), newest first
    for (auto& p : peersWithAge)
    {
        if (p.first < cutoff)
            continue;
        fresh.push_back(p);
        nFresh++;
    }
    if (!fresh.empty())
        LogPrint("nostr", "Nostr: %d fresh peers, %d stale (of %d total)\n", nFresh, nTotal-nFresh, nTotal);

    // Drop stale peers so we stop retrying dead descriptors until they refresh.
    {
        CRITICAL_BLOCK(cs_btfPeers)
        {
            for (map<string, int64>::iterator it = g_btfPeers.begin(); it != g_btfPeers.end(); )
            {
                if (it->second < cutoff)
                    it = g_btfPeers.erase(it);
                else
                    ++it;
            }
        }
    }

    // Sort newest descriptor first -- recently-active nodes are much more
    // likely to be online right now.
    sort(fresh.begin(), fresh.end(),
         [](const pair<int64,string>& a, const pair<int64,string>& b){ return a.first > b.first; });

    // Reorder into tiers: known-good (succeeded before) first, untried next,
    // known-bad (has a fail count) last -- worst offenders furthest back.
    // Freshness order is preserved *within* each tier, so recency still
    // matters, but a peer we know is dead no longer gets equal footing with
    // a peer we've never tried or one that's worked before.
    vector<string> tierGood, tierUntried, tierBad;
    CRITICAL_BLOCK(cs_btfPeerState)
    {
        for (auto& p : fresh)
        {
            const string& addr = p.second;
            if (g_btfPeerEverConnected.count(addr))
                tierGood.push_back(addr);
            else if (g_btfPeerFails.find(addr) == g_btfPeerFails.end())
                tierUntried.push_back(addr);
            else
                tierBad.push_back(addr);
        }
        // Within known-bad, put fewer-fails peers ahead of chronic offenders.
        sort(tierBad.begin(), tierBad.end(),
             [](const string& a, const string& b){ return g_btfPeerFails[a] < g_btfPeerFails[b]; });
    }

    vector<string> peers;
    peers.reserve(fresh.size());
    peers.insert(peers.end(), tierGood.begin(), tierGood.end());
    peers.insert(peers.end(), tierUntried.begin(), tierUntried.end());
    peers.insert(peers.end(), tierBad.begin(), tierBad.end());

    // Pick candidates for this pass (skip those in backoff, cap at budget).
    //
    // The tiered order above is deliberately biased toward peers we know
    // are good -- that's the right default, since dialing untested/bad
    // peers wastes attempts. But if every node on the network applies the
    // same bias, everyone converges on the same small set of "known good"
    // peers as neighbors: that correlates peer sets across the network,
    // which is exactly what standard random-graph connectivity results
    // assume you avoid. If that shared hub set has a bad day (e.g. one
    // relay outage), many nodes lose the same edges at once instead of
    // losing independent, uncorrelated edges.
    //
    // So: fill most of the pass from the reliable/tiered order, but reserve
    // a slice for peers picked at random from the *entire* fresh pool
    // (not just the front of the sorted list). Same pattern Bitcoin's own
    // peer manager and Kademlia-style DHTs use -- sticky reliable peers
    // plus a random sample, not one or the other.
    int64 now = GetTime();
    int nBudget = (int)BTF_DIALS_PER_PASS;
    {
        int nRoom = (int)BTF_TARGET_CONN - (int)vNodes.size();
        if (nRoom < nBudget) nBudget = nRoom;
    }
    if (nBudget < 0) nBudget = 0;
    int nRandomSlots = (nBudget > 0) ? max(1, nBudget * 3 / 10) : 0;
    int nSortedSlots = nBudget - nRandomSlots;

    vector<string> candidates;
    set<string> setChosen;
    CRITICAL_BLOCK(cs_btfPeerState)
    {
        // Reliability slice: walk the tiered (good -> untried -> bad) order.
        for (const string& addr : peers)
        {
            if ((int)vNodes.size() >= (int)BTF_TARGET_CONN) break;
            if ((int)candidates.size() >= nSortedSlots) break;
            map<string, int64>::iterator bi = g_btfPeerBackoff.find(addr);
            if (bi != g_btfPeerBackoff.end() && now < bi->second)
                continue;
            candidates.push_back(addr);
            setChosen.insert(addr);
        }

        // Diversity slice: random sample from the full fresh pool, so the
        // dial isn't limited to whatever the tiered sort put up front.
        vector<string> pool;
        for (auto& p : fresh)
        {
            const string& addr = p.second;
            if (setChosen.count(addr))
                continue;
            map<string, int64>::iterator bi = g_btfPeerBackoff.find(addr);
            if (bi != g_btfPeerBackoff.end() && now < bi->second)
                continue;
            pool.push_back(addr);
        }
        int nWant = min(nRandomSlots, (int)pool.size());
        for (int i = 0; i < nWant; i++)
        {
            if ((int)vNodes.size() + (int)candidates.size() >= (int)BTF_TARGET_CONN) break;
            if ((int)candidates.size() >= nBudget) break;
            size_t j = i + (size_t)GetRand((uint64)(pool.size() - i));
            std::swap(pool[i], pool[j]);
            candidates.push_back(pool[i]);
            setChosen.insert(pool[i]);
        }
    }

    if (candidates.empty()) return;

    // Resolve every candidate's descriptor in one batched pass (a handful of
    // relay round-trips total, one REQ per relay covering all candidates)
    // instead of each dial thread independently walking the relay list on
    // its own. That per-thread approach meant a 12-candidate pass could fire
    // up to 12 * nNostrRelays near-simultaneous connections at the same
    // handful of public relays -- enough to trip rate limits or get
    // handshakes refused, which then looks exactly like "dead peers" even
    // though the descriptors were perfectly resolvable.
    map<string, BtfResolvedPeer> resolved;
    for (const string& addr : candidates)
        BtfChurnNoteResolveAttempt();
    BtfResolveMany(candidates, resolved);

    // Candidates whose descriptor didn't resolve this pass are recorded as a
    // failure right away (no point spawning a tunnel thread with nothing to
    // dial), same bookkeeping as a failed connect attempt.
    vector<string> toDial;
    CRITICAL_BLOCK(cs_btfPeerState)
    {
        for (const string& addr : candidates)
        {
            if (resolved.count(addr))
            {
                BtfChurnNoteResolveResult(true);
                toDial.push_back(addr);
                continue;
            }
            BtfChurnNoteResolveResult(false);
            int n = ++g_btfPeerFails[addr];
            int64 cap = (n >= BTF_CHRONIC_FAIL_THRESHOLD) ? BTF_BACKOFF_CAP_SECS_DEAD
                                                           : BTF_BACKOFF_CAP_SECS;
            int64 secs = 30;
            for (int k = 1; k < n && secs < cap; k++) secs *= 2;
            if (secs > cap) secs = cap;
            g_btfPeerBackoff[addr] = GetTime() + secs;
        }
    }
    if (toDial.empty()) return;

    // Launch one thread per resolved candidate -- all connect attempts run in
    // parallel, but purely against each peer's own rendezvous meeting node,
    // not the shared Nostr relays, so there's no thundering-herd effect here.
    // Each thread writes its result back via shared state guarded by cs_btfPeerState.
    struct DialCtx { string addr; BtfResolvedPeer rp; };
    vector<DialCtx*> ctxs;
    for (const string& addr : toDial)
    {
        DialCtx* ctx = new DialCtx{addr, resolved[addr]};
        ctxs.push_back(ctx);
        _beginthread([](void* arg) {
            DialCtx* ctx = (DialCtx*)arg;
            string addr = ctx->addr;
            string meeting = ctx->rp.meetingHostPort;
            unsigned char enc_pub[32];
            memcpy(enc_pub, ctx->rp.enc_pub, 32);
            delete ctx;

            CNode* pnode = ConnectNodeBtfResolved(addr, meeting, enc_pub);
            CRITICAL_BLOCK(cs_btfPeerState)
            {
                if (pnode)
                {
                    if (!pnode->fNetworkNode)
                        pnode->fNetworkNode = true;
                    else
                        pnode->Release();
                    g_btfPeerBackoff.erase(addr);
                    g_btfPeerFails.erase(addr);
                    g_btfPeerEverConnected.insert(addr);
                }
                else
                {
                    int n = ++g_btfPeerFails[addr];
                    int64 cap = (n >= BTF_CHRONIC_FAIL_THRESHOLD) ? BTF_BACKOFF_CAP_SECS_DEAD
                                                                   : BTF_BACKOFF_CAP_SECS;
                    int64 secs = 30;
                    for (int k = 1; k < n && secs < cap; k++) secs *= 2;
                    if (secs > cap) secs = cap;
                    g_btfPeerBackoff[addr] = GetTime() + secs;
                }
            }
        }, 0, ctx);
    }

    // Wait long enough for all parallel dials to finish (each has a 10s socket
    // timeout, so 12s gives them all time to resolve).
    for (int i = 0; i < 12 && !fShutdown; i++)
        Sleep(1000);
}


void ThreadNostrSeed(void* parg)
{
    LogPrint("nostr", "ThreadNostrSeed started\n");

    if (!EnsureNostrKey())
    {
        LogPrint("nostr", "Nostr: failed to initialize secp256k1 key\n");
        return;
    }
    CNostrKey& key = g_nostrKey;
    LogPrint("nostr", "Nostr: node pubkey = %s\n", key.PubKeyHex().c_str());
    LogPrint("nostr", "Nostr: node .btf address = %s\n", key.BtfAddress().c_str());

    // The self-test below publishes a real descriptor, and PublishDescriptor now
    // refuses to publish before ThreadBtfAccept has registered a rendezvous. Give
    // registration a bounded head start so the test measures the publish/resolve
    // chain instead of losing the race against it.
    for (int i = 0; i < 60 && !fShutdown && BtfActiveRelay().empty(); i++)
        Sleep(1000);

    // One-time self-test of the rendezvous: publish our descriptor to a relay,
    // then resolve our OWN .btf address back and verify it self-certifies. Proves
    // the .btf publish/resolve/verify chain works against real public relays.
    for (int i = 0; i < nNostrRelays && !fShutdown; i++)
    {
        try
        {
            CRelayLease lease(pszNostrRelays[i], 10);
            if (!lease.Connected()) continue;
            CWebSocket& ws = lease.Ws();
            PublishDescriptor(ws, key);
            Sleep(700); // let the relay store the replaceable event
            btf::Descriptor d;
            if (ResolveDescriptor(ws, key.ctx, key.BtfAddress(), d))
            {
                LogPrint("nostr", "Nostr: .btf self-resolve OK via %s (meeting_node=%s, enc=%s...)\n",
                       pszNostrRelays[i], d.meeting_node.c_str(), d.enc.substr(0, 16).c_str());
                lease.fOk = true;
                break;
            }
            lease.fOk = true;
        }
        CATCH_PRINT_EXCEPTION("btf self-test")
    }

    // OpenSSL is already initialized by the rest of the app; TLS_client_method is enough.
    loop
    {
        for (int i = 0; i < nNostrRelays; i++)
        {
            if (fShutdown) return;
            if (!RelayDueForRetry(pszNostrRelays[i]))
                continue;
            try
            {
                if (SeedFromRelay(key, pszNostrRelays[i]))
                    RelayNoteSuccess(pszNostrRelays[i]);
                else
                    RelayNoteFailure(pszNostrRelays[i]);
            }
            CATCH_PRINT_EXCEPTION("SeedFromRelay")
        }

        // Auto-connect to discovered .btf peers over the rendezvous relay -- the
        // anonymous, CGNAT-friendly replacement for the old IP-based connect. No
        // manual /connectbtf needed: nodes find each other purely via Nostr.
        try
        {
            ConnectDiscoveredBtfPeers();
        }
        CATCH_PRINT_EXCEPTION("ConnectDiscoveredBtfPeers")

        if (nMineMode == MINE_OPERATOR && gPoolRunning)
        {
            BtfPoolAnnouncement ann;
            ann.btfAddress = BtfLocalAddress();
            ann.poolName = strPoolName;
            ann.dashboardUrl = strPoolDashboardUrl;
            ann.feePercent = dPoolFeePercent;
            uint64 roundShares = 0;
            double totalHashRate = 0.0;
            GetPoolOperatorStats(ann.connectedMiners, ann.blocksFound, roundShares, totalHashRate);
            ann.hashRate = totalHashRate;
            ann.createdAt = GetTime();
            if (!ann.btfAddress.empty() && !ann.poolName.empty())
                BtfPublishPoolAnnouncement(ann);
        }

        // Re-discover periodically. Sleep less aggressively when
        // we have no connections yet so we find peers faster on startup.
        int nSleepSecs = vNodes.empty() ? 20 : 60;
        for (int i = 0; i < nSleepSecs && !fShutdown; i++)
            Sleep(1000);
    }
}
