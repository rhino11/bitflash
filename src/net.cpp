// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#pragma push_macro("snprintf")
#undef snprintf
#include <nlohmann/json.hpp>
#pragma pop_macro("snprintf")
#ifdef snprintf
#undef snprintf
#endif
#include "headers.h"
#include <thread>          // hardware_concurrency, for the miner thread count
#ifdef _WIN32
#include <winsock2.h>
#endif
#include <openssl/rand.h>
#include "btfaddr.h"
#include "btftunnel.h"

void ThreadReconnectCachedBtfPeers(void* parg);
void ThreadMessageHandler2(void* parg);
void ThreadSocketHandler2(void* parg);






//
// Global state variables
//
bool fClient = false;
uint64 nLocalServices = (fClient ? 0 : NODE_NETWORK);
CAddress addrLocalHost(0, DEFAULT_PORT, nLocalServices);
unsigned short nListenPort = DEFAULT_PORT; // local P2P port (tunable via /port)
CNode nodeLocalHost(INVALID_SOCKET, CAddress("127.0.0.1", nLocalServices));
CNode* pnodeLocalHost = &nodeLocalHost;
bool fShutdown = false;
array<bool, 10> vfThreadRunning;
vector<CNode*> vNodes;
CCriticalSection cs_vNodes;
map<CInv, CDataStream> mapRelay;
deque<pair<int64, CInv> > vRelayExpiration;
CCriticalSection cs_mapRelay;
map<CInv, int64> mapAlreadyAskedFor;
string strBtfConnect; // .btf peer to keep connected to (from /connectbtf)


bool GetMyExternalIP(unsigned int& ipRet)
{
    // Try several plain-text IP echo services in order.
    // Each returns just the IPv4 address as the first line of the HTTP body.
    struct { const char* host; const char* path; } services[] = {
        { "api4.ipify.org",    "/"          },
        { "icanhazip.com",     "/"          },
        { "ipecho.net",        "/plain"     },
        { "checkip.amazonaws.com", "/"      },
    };

    for (auto& svc : services)
    {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(svc.host, "80", &hints, &res) != 0 || !res)
            continue;

        SOCKET hSocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (hSocket == INVALID_SOCKET) { freeaddrinfo(res); continue; }

        // 5-second timeout so a dead service doesn't stall startup
#ifdef _WIN32
        DWORD tv = 5000;
        setsockopt(hSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(hSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
        struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0;
        setsockopt(hSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(hSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

        if (connect(hSocket, res->ai_addr, (int)res->ai_addrlen) != 0)
        {
            freeaddrinfo(res); closesocket(hSocket); continue;
        }
        freeaddrinfo(res);

        string req = string("GET ") + svc.path + " HTTP/1.0\r\nHost: " + svc.host + "\r\nConnection: close\r\n\r\n";
        send(hSocket, req.c_str(), (int)req.size(), 0);

        // Read response, skip HTTP headers, grab first line of body
        string response;
        char buf[256];
        int n;
        while ((n = recv(hSocket, buf, sizeof(buf)-1, 0)) > 0)
        {
            buf[n] = 0;
            response += buf;
            if (response.size() > 4096) break;
        }
        closesocket(hSocket);

        // Find blank line separating headers from body
        size_t bodyPos = response.find("\r\n\r\n");
        if (bodyPos == string::npos) bodyPos = response.find("\n\n");
        if (bodyPos == string::npos) continue;
        string body = response.substr(bodyPos + (response[bodyPos+2]=='\r' ? 4 : 2));

        // Trim whitespace
        while (!body.empty() && (body.back() == '\n' || body.back() == '\r' || body.back() == ' '))
            body.pop_back();

        // Parse as IP
        CAddress addr(body.c_str());
        if (addr.ip == 0) continue;

        printf("GetMyExternalIP() via %s: %s\n", svc.host, body.c_str());
        ipRet = addr.ip;
        return true;
    }

    return error("GetMyExternalIP() : all services failed\n");
}









void AbandonRequests(void (*fn)(void*, CDataStream&), void* param1)
{
    // If the dialog might get closed before the reply comes back,
    // call this in the destructor so it doesn't get called after it's deleted.
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
        {
            CRITICAL_BLOCK(pnode->cs_mapRequests)
            {
                for (map<uint256, CRequestTracker>::iterator mi = pnode->mapRequests.begin(); mi != pnode->mapRequests.end();)
                {
                    CRequestTracker& tracker = (*mi).second;
                    if (tracker.fn == fn && tracker.param1 == param1)
                        pnode->mapRequests.erase(mi++);
                    else
                        mi++;
                }
            }
        }
    }
}







//
// Subscription methods for the broadcast and subscription system.
// Channel numbers are message numbers, i.e. MSG_TABLE and MSG_PRODUCT.
//
// The subscription system uses a meet-in-the-middle strategy.
// With 100,000 nodes, if senders broadcast to 1000 random nodes and receivers
// subscribe to 1000 random nodes, 99.995% (1 - 0.99^1000) of messages will get through.
//

bool AnySubscribed(unsigned int nChannel)
{
    if (pnodeLocalHost->IsSubscribed(nChannel))
        return true;
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode->IsSubscribed(nChannel))
                return true;
    return false;
}

bool CNode::IsSubscribed(unsigned int nChannel)
{
    if (nChannel >= vfSubscribe.size())
        return false;
    return vfSubscribe[nChannel];
}

void CNode::Subscribe(unsigned int nChannel, unsigned int nHops)
{
    if (nChannel >= vfSubscribe.size())
        return;

    if (!AnySubscribed(nChannel))
    {
        // Relay subscribe
        CRITICAL_BLOCK(cs_vNodes)
            foreach(CNode* pnode, vNodes)
                if (pnode != this)
                    pnode->PushMessage("subscribe", nChannel, nHops);
    }

    vfSubscribe[nChannel] = true;
}

void CNode::CancelSubscribe(unsigned int nChannel)
{
    if (nChannel >= vfSubscribe.size())
        return;

    // Prevent from relaying cancel if wasn't subscribed
    if (!vfSubscribe[nChannel])
        return;
    vfSubscribe[nChannel] = false;

    if (!AnySubscribed(nChannel))
    {
        // Relay subscription cancel
        CRITICAL_BLOCK(cs_vNodes)
            foreach(CNode* pnode, vNodes)
                if (pnode != this)
                    pnode->PushMessage("sub-cancel", nChannel);

        // Clear memory, no longer subscribed
        if (nChannel == MSG_PRODUCT)
            CRITICAL_BLOCK(cs_mapProducts)
                mapProducts.clear();
    }
}









CNode* FindNode(unsigned int ip)
{
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
            if (pnode->addr.ip == ip)
                return (pnode);
    }
    return NULL;
}

// Synthetic marker address for a tunneled `.btf` peer. The real endpoint is
// unknown by design (the tunnel hides it), so tag the CNode with a non-routable
// 10.x.x.x address (fails IsRoutable, so it is never gossiped as a real peer)
// that is stable per identity, keeping FindNode and the duplicate check working.
static CAddress BtfMarkerAddr(const unsigned char b5[5])
{
    unsigned int ip;
    unsigned char b[4] = { 10, b5[0], b5[1], b5[2] };
    memcpy(&ip, b, 4);
    unsigned short port = htons((unsigned short)((b5[3] << 8) | b5[4]));
    return CAddress(ip, port, nLocalServices);
}

// Shared tail: given a peer's pubkey and already-resolved rendezvous
// coordinates, open the tunnel and register the CNode. Used by both
// ConnectNodeBtf (which resolves the descriptor itself) and
// ConnectNodeBtfResolved (which takes an already-resolved descriptor, so it
// makes no Nostr relay calls at all -- see nostr.cpp's BtfResolveMany for why
// that matters when dialing many candidates in parallel).
//
// Peers we have actually reached, remembered across restarts.
//
// Discovery is otherwise entirely dependent on the Nostr relays: a node that
// has been running for hours and knows exactly which peers answer throws all
// of it away on exit, and the next start walks the same ~96%-dead descriptor
// list again. Reconnecting from this file skips the relays completely --
// address, meeting node and encryption key are all we need.
//
static const size_t MAX_CACHED_BTF_PEERS = 50;
static const int64  CACHED_BTF_PEER_TTL  = 7 * 24 * 60 * 60; // a week

struct CachedBtfPeer
{
    string btfAddr;
    string meeting;
    string encHex;
    int64  lastSeen;
    // The peer's own signed descriptor, as it announced itself. Kept verbatim
    // because that signature is what lets us hand this peer on to somebody
    // else: the receiver checks it against the key the address decodes to and
    // never has to take our word for anything. Empty for entries learned
    // before peer exchange existed, or resolved through Nostr -- those are
    // still dialable, just not relayable.
    string desc;
};

static string BtfPeerCachePath() { return GetAppDir() + "/btfpeers.json"; }

static string BytesToHex(const unsigned char* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += h[p[i] >> 4]; s += h[p[i] & 0xf]; }
    return s;
}

static bool HexToBytes(const string& s, unsigned char* out, size_t n)
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

void LoadCachedBtfPeers(vector<CachedBtfPeer>& out)
{
    out.clear();
    FILE* f = fopen(BtfPeerCachePath().c_str(), "r");
    if (!f) return;
    string body;
    char buf[4096];
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0) body.append(buf, r);
    fclose(f);
    try
    {
        nlohmann::json arr = nlohmann::json::parse(body);
        if (!arr.is_array()) return;
        int64 nNow = GetTime();
        for (const auto& o : arr)
        {
            if (!o.is_object()) continue;
            if (!o.contains("btf") || !o["btf"].is_string()) continue;
            if (!o.contains("meeting") || !o["meeting"].is_string()) continue;
            if (!o.contains("enc") || !o["enc"].is_string()) continue;
            CachedBtfPeer p;
            p.btfAddr  = o["btf"].get<string>();
            p.meeting  = o["meeting"].get<string>();
            p.encHex   = o["enc"].get<string>();
            p.lastSeen = o.value("seen", (int64)0);
            if (o.contains("desc") && o["desc"].is_string())
                p.desc = o["desc"].get<string>();
            if (nNow - p.lastSeen > CACHED_BTF_PEER_TTL) continue; // long gone
            out.push_back(p);
        }
    }
    catch (...)
    {
        LogPrint("net", "btfpeers: cache unreadable, starting empty\n");
        out.clear();
    }
}

static CCriticalSection cs_btfPeerCache;

// strDesc is the peer's own signed descriptor when we have it (it announced
// itself over peer exchange), "" when we only resolved it through Nostr. An
// empty one never clears a descriptor already on file: dialing a peer we first
// learned about by exchange must not cost us the ability to pass it on.
static void RememberBtfPeer(const string& strBtfAddr, const string& strMeeting,
                            const unsigned char enc_pub[32],
                            const string& strDesc = string())
{
    CRITICAL_BLOCK(cs_btfPeerCache)
    {
        vector<CachedBtfPeer> peers;
        LoadCachedBtfPeers(peers);

        string strKeepDesc = strDesc;
        for (size_t i = 0; i < peers.size(); i++)
            if (peers[i].btfAddr == strBtfAddr)
            {
                if (strKeepDesc.empty())
                    strKeepDesc = peers[i].desc;
                peers.erase(peers.begin() + i);
                break;
            }

        CachedBtfPeer p;
        p.btfAddr  = strBtfAddr;
        p.meeting  = strMeeting;
        p.encHex   = BytesToHex(enc_pub, 32);
        p.lastSeen = GetTime();
        p.desc     = strKeepDesc;
        peers.insert(peers.begin(), p); // most recent first

        if (peers.size() > MAX_CACHED_BTF_PEERS)
            peers.resize(MAX_CACHED_BTF_PEERS);

        nlohmann::json arr = nlohmann::json::array();
        foreach(const CachedBtfPeer& q, peers)
        {
            nlohmann::json o;
            o["btf"]     = q.btfAddr;
            o["meeting"] = q.meeting;
            o["enc"]     = q.encHex;
            o["seen"]    = q.lastSeen;
            if (!q.desc.empty())
                o["desc"] = q.desc;
            arr.push_back(o);
        }
        FILE* f = fopen(BtfPeerCachePath().c_str(), "w");
        if (f)
        {
            string s = arr.dump(2);
            fwrite(s.c_str(), 1, s.size(), f);
            fclose(f);
        }
    }
}

//
// Compiled-in bootstrap seeds.
//
// A node with no cache has nothing but the Nostr relays, and if those are down,
// blocked or simply slow, a first run has no way into the network at all. Seeds
// are the floor under that: a handful of long-lived peers baked into the binary.
//
// A seed entry is deliberately just an address and an encryption key -- no
// meeting node. The rendezvous relay pairs on the service's public key, and a
// `.btf` address *is* that key, so a client can find a seed by trying the known
// relays in turn. Recording which relay a seed was on would rot the moment it
// failed over, which is the exact failure this project spent a long time
// chasing: advertising a rendezvous somebody is not registered at.
//
// Seeds are ordinary nodes with no special authority. They hand out signed,
// self-certifying descriptors like any peer, so a hostile seed can stall a
// bootstrap but cannot forge a peer or feed a false chain.
//
struct BtfSeed
{
    const char* btfAddr;
    const char* encHex;   // 64 hex chars, the peer's x25519 public key
};

static const BtfSeed pszBtfSeeds[] =
{
    // Dedicated bootstrap node, Almaty. Runs beside a rendezvous relay on the
    // same host, holds no wallet balance and does not mine -- it exists only to
    // answer a first dial. It is trusted for nothing: it serves the same signed
    // descriptors any peer does.
    { "ygffz37jczlmrkzicxok6chobauyratdexc7hfgwzjdabzvb2nkngqy.btf",
      "de8284b9d4effa2132e7981b566c1a297c39c1857d9c128e8ae093ef511d3200" },
};
static const size_t nBtfSeeds = ARRAYLEN(pszBtfSeeds);

// Extra seeds from the command line (/btfseed=ADDRESS:ENCHEX, repeatable).
vector<pair<string, string> > vBtfExtraSeeds;

static int TryBtfSeeds()
{
    vector<pair<string, string> > seeds;
    for (size_t i = 0; i < nBtfSeeds; i++)
        seeds.push_back(make_pair(string(pszBtfSeeds[i].btfAddr),
                                  string(pszBtfSeeds[i].encHex)));
    foreach(const PAIRTYPE(string, string)& s, vBtfExtraSeeds)
        seeds.push_back(s);

    if (seeds.empty())
        return 0;

    vector<string> relays = BtfAllRelays();
    if (relays.empty())
        return 0;

    LogPrint("net", "btfseed: trying %zu seed(s) across %zu relay(s)\n",
             seeds.size(), relays.size());

    int nConnected = 0;
    foreach(const PAIRTYPE(string, string)& s, seeds)
    {
        if (fShutdown) return nConnected;
        unsigned char enc[32];
        if (!HexToBytes(s.second, enc, 32))
        {
            LogPrint("net", "btfseed: %s has a malformed encryption key, skipped\n",
                     s.first.c_str());
            continue;
        }
        // We do not know which relay this seed is registered at, so walk them.
        foreach(const string& strRelay, relays)
        {
            if (fShutdown) return nConnected;
            if (ConnectNodeBtfResolved(s.first, strRelay, enc))
            {
                LogPrint("net", "btfseed: reached %s via %s\n",
                         s.first.c_str(), strRelay.c_str());
                nConnected++;
                break;  // found it; no need to try this seed's other relays
            }
        }
        if (nConnected >= 4)
            break;      // enough of a foothold; the rest comes from discovery
    }
    LogPrint("net", "btfseed: %d seed(s) answered\n", nConnected);
    return nConnected;
}

// Dial everything we reached last time, before the relays have said anything.
void ThreadReconnectCachedBtfPeers(void* parg)
{
    vector<CachedBtfPeer> peers;
    LoadCachedBtfPeers(peers);
    if (peers.empty())
    {
        // First run, or the cache aged out. Seeds are the only way in that does
        // not depend on a relay answering.
        LogPrint("net", "btfpeers: no cache yet, falling back to seeds\n");
        if (TryBtfSeeds() == 0)
            LogPrint("net", "btfpeers: no seed answered, waiting on relay discovery\n");
        return;
    }
    LogPrint("net", "btfpeers: trying %zu remembered peer(s) before discovery\n",
             peers.size());

    int nConnected = 0;
    foreach(const CachedBtfPeer& p, peers)
    {
        if (fShutdown) return;
        unsigned char enc[32];
        if (!HexToBytes(p.encHex, enc, 32)) continue;
        if (ConnectNodeBtfResolved(p.btfAddr, p.meeting, enc))
        {
            nConnected++;
            if (nConnected >= 8) break; // enough to bootstrap; the rest can wait
        }
    }
    LogPrint("net", "btfpeers: %d of %zu remembered peer(s) answered\n",
             nConnected, peers.size());
}

//
// .btf peer exchange
//
// Until now discovery depended entirely on the Nostr relays: two connected
// nodes never told each other who else existed, so a relay outage left a
// running network unable to grow, and a node that found one stale peer had no
// way to learn there was anything better.
//
// What travels here is each peer's own signed descriptor. The receiver checks
// the Schnorr signature against the key the `.btf` address decodes to, so the
// sender is trusted for nothing -- forging an entry would need somebody else's
// secret key. That leaves flooding: valid descriptors for keys the sender
// generated itself. The caps below bound one message, and the cache prefers
// peers that actually answered, so a flood costs a Sybil more than it costs us.
//

void BtfPexCollect(vector<string>& vDescOut)
{
    vDescOut.clear();

    // Ours first -- the node on the other end may know nobody but us.
    string strMine = BtfLocalDescriptor();
    if (!strMine.empty())
        vDescOut.push_back(strMine);

    vector<CachedBtfPeer> peers;
    CRITICAL_BLOCK(cs_btfPeerCache)
        LoadCachedBtfPeers(peers);

    // Most recently seen first: these answered us, they are not names copied
    // off a relay listing.
    foreach(const CachedBtfPeer& p, peers)
    {
        if (vDescOut.size() >= MAX_PEX_DESCRIPTORS) break;
        if (p.desc.empty()) continue;                          // nothing provable to pass on
        if (p.desc.size() > MAX_PEX_DESCRIPTOR_BYTES) continue;
        vDescOut.push_back(p.desc);
    }
}

int BtfPexAccept(const vector<string>& vDesc)
{
    void* ctx = BtfSecpContext();
    if (!ctx)
        return 0;

    string strSelf = BtfLocalAddress();
    int nKept = 0;
    unsigned int nSeen = 0;

    foreach(const string& strDesc, vDesc)
    {
        if (++nSeen > MAX_PEX_DESCRIPTORS) break;
        if (strDesc.empty() || strDesc.size() > MAX_PEX_DESCRIPTOR_BYTES) continue;

        // The descriptor names the key it belongs to, and taking that key from
        // the blob is safe precisely because the signature must verify under
        // it: nobody can produce a valid descriptor for a key they don't hold.
        unsigned char pubkey[32];
        try
        {
            nlohmann::json v = nlohmann::json::parse(strDesc);
            if (!v.is_object() || !v.contains("pubkey") || !v["pubkey"].is_string())
                continue;
            if (!HexToBytes(v["pubkey"].get<string>(), pubkey, 32))
                continue;
        }
        catch (...) { continue; }   // malformed JSON from an untrusted peer

        btf::Descriptor d;
        if (!btf::VerifyDescriptor(ctx, strDesc, pubkey, d))
            continue;

        string strAddr = btf::Address(pubkey);
        if (strAddr.empty() || strAddr == strSelf)
            continue;               // ourselves, nothing to learn

        unsigned char enc[32];
        if (!HexToBytes(d.enc, enc, 32))
            continue;

        RememberBtfPeer(strAddr, d.meeting_node, enc, strDesc);
        nKept++;
    }
    return nKept;
}

static CNode* ConnectNodeBtfTail(const string& strBtfAddr, const unsigned char pk[32],
                                  const string& strMeeting, const unsigned char enc_pub[32])
{
    CAddress addr = BtfMarkerAddr(pk);
    CNode* pnode = FindNode(addr.ip);
    if (pnode)
    {
        pnode->AddRef();
        return pnode;
    }

    size_t colon = strMeeting.rfind(':');
    if (colon == string::npos)
        return NULL;
    string strHost = strMeeting.substr(0, colon);
    int nPort = atoi(strMeeting.substr(colon + 1).c_str());
    if (nPort <= 0 || nPort > 65535)
        return NULL;

    btf_socket_t hSocket = btf::BtfClientTunnel(strHost.c_str(), (unsigned short)nPort, pk, enc_pub);
    if (hSocket == INVALID_SOCKET)
    {
        if (fDebug)
            LogPrint("net", "ConnectNodeBtf: tunnel to %s via %s failed\n", strBtfAddr.c_str(), strMeeting.c_str());
        return NULL;
    }

    if (fDebug)
        LogPrint("net", "connected %s via rendezvous %s\n", strBtfAddr.c_str(), strMeeting.c_str());

    // This one answered -- worth trying first next time we start.
    RememberBtfPeer(strBtfAddr, strMeeting, enc_pub);

    // Add node
    pnode = new CNode(hSocket, addr, false);
    pnode->AddRef();
    CRITICAL_BLOCK(cs_vNodes)
        vNodes.push_back(pnode);
    return pnode;
}

// Connect to a peer by its `.btf` address: resolve the self-certified
// descriptor over Nostr, then tunnel through its meeting node with the
// end-to-end channel. Neither side ever learns the other's IP.
CNode* ConnectNodeBtf(const string& strBtfAddr)
{
    unsigned char pk[32];
    if (!btf::ParseAddress(strBtfAddr, pk))
    {
        LogPrint("net", "ConnectNodeBtf: invalid address %s\n", strBtfAddr.c_str());
        return NULL;
    }
    if (BtfLocalAddress() == strBtfAddr)
        return NULL; // ourselves

    if (fDebug)
        LogPrint("net", "trying %s\n", strBtfAddr.c_str());

    string strMeeting;
    unsigned char enc_pub[32];
    if (!BtfResolve(strBtfAddr, strMeeting, enc_pub))
    {
        if (fDebug)
            LogPrint("net", "ConnectNodeBtf: could not resolve a descriptor for %s\n", strBtfAddr.c_str());
        return NULL;
    }
    return ConnectNodeBtfTail(strBtfAddr, pk, strMeeting, enc_pub);
}

// Same as ConnectNodeBtf, but skips the Nostr resolve step because the caller
// already resolved the descriptor (e.g. via BtfResolveMany, batching many
// addresses into one relay round-trip instead of one relay round-trip per
// address). Makes zero relay connections -- only talks to the peer's
// rendezvous meeting node.
CNode* ConnectNodeBtfResolved(const string& strBtfAddr, const string& strMeeting,
                              const unsigned char enc_pub[32])
{
    unsigned char pk[32];
    if (!btf::ParseAddress(strBtfAddr, pk))
    {
        LogPrint("net", "ConnectNodeBtf: invalid address %s\n", strBtfAddr.c_str());
        return NULL;
    }
    if (BtfLocalAddress() == strBtfAddr)
        return NULL; // ourselves
    return ConnectNodeBtfTail(strBtfAddr, pk, strMeeting, enc_pub);
}

// Anonymous inbound listener (this node's `.btf` hidden service). Registers at
// the meeting relay and blocks until a client dials our address; each pairing
// becomes a normal inbound CNode riding the end-to-end channel, then we
// register again for the next caller.
void ThreadBtfAccept(void* parg)
{
    printf("ThreadBtfAccept started\n");
    unsigned char pk[32];
    unsigned char sk[32];
    while (!BtfGetIdentity(pk, sk))
    {
        if (fShutdown)
            return;
        Sleep(5000);
    }
    size_t iRelay = 0;
    bool fPicked = false;
    loop
    {
        if (fShutdown)
            return;
        // Curated seeds + relays discovered from Nostr announcements.
        vector<string> relays = BtfAllRelays();
        if (relays.empty())
        {
            Sleep(10000); // no meeting relay configured
            continue;
        }
        // Random start spreads nodes across all relays (incl. volunteer ones).
        if (!fPicked)
        {
            iRelay = (size_t)GetRand(relays.size());
            fPicked = true;
        }
        // Stick to the current relay while it works; on failure, fail over to
        // the next one so a DDoS'd/blocked relay IP can't keep us offline.
        string strMeeting = relays[iRelay % relays.size()];
        size_t colon = strMeeting.rfind(':');
        if (colon == string::npos)
        {
            iRelay++;
            Sleep(2000);
            continue;
        }
        string strHost = strMeeting.substr(0, colon);
        int nPort = atoi(strMeeting.substr(colon + 1).c_str());

        // Returns as soon as the relay has us listed -- it does not wait for a
        // dial. That distinction is the whole point: we have to be advertised
        // before anyone can dial us, so registering and waiting cannot be the
        // same call.
        btf::RvSocket rv = btf::RvServiceRegister(strHost.c_str(), (unsigned short)nPort, pk);
        if (fShutdown)
        {
            if (rv != btf::RV_INVALID)
                btf::RvClose(rv);
            return;
        }
        if (rv == btf::RV_INVALID)
        {
            LogPrint("net", "rendezvous: could not register at %s, trying another\n",
                     strMeeting.c_str());
            iRelay++;       // this relay is down/attacked -> try the next one
            Sleep(3000);
            continue;
        }

        // Registered. Advertise THIS relay now, while we are listed and before
        // anybody dials -- a descriptor naming it is what makes a dial possible
        // at all. Keep using it (iRelay unchanged) until it fails.
        BtfSetActiveRelay(strMeeting);
        LogPrint("net", "rendezvous: registered at %s, waiting for a dial\n",
                 strMeeting.c_str());

        // Now wait for someone to arrive -- but not forever. This used to have
        // no bound, and a registration whose path died quietly left the thread
        // parked in recv() with nothing to wake it: the loop never came back
        // here, the node stopped being reachable, and nothing in the log said
        // so. Re-registering every few minutes when nobody has dialled costs
        // one reconnect and removes the whole failure mode.
        if (!btf::RvServiceWaitPaired(rv, BTF_RENDEZVOUS_WAIT_SECS))
        {
            btf::RvClose(rv);
            LogPrint("net", "rendezvous: no dial at %s within %ds (or it dropped us), "
                     "re-registering\n", strMeeting.c_str(), BTF_RENDEZVOUS_WAIT_SECS);
            continue;
        }

        btf_socket_t hSocket = btf::BtfServiceWrap(rv, sk);
        if (hSocket == INVALID_SOCKET)
            continue;

        // The dialer is anonymous (its pubkey never reaches us), so tag the
        // connection with a random marker address.
        unsigned char rnd[5];
        RAND_bytes(rnd, sizeof(rnd));
        CAddress addr = BtfMarkerAddr(rnd);

        LogPrint("net", "accepted .btf connection via rendezvous %s\n", strMeeting.c_str());
        CNode* pnode = new CNode(hSocket, addr, true);
        pnode->AddRef();
        CRITICAL_BLOCK(cs_vNodes)
            vNodes.push_back(pnode);
    }
}

// Keep an outbound connection to a specific `.btf` peer (from /connectbtf) --
// the rendezvous analogue of addnode. Retries until connected, reconnects if
// the tunnel drops.
void ThreadBtfConnect(void* parg)
{
    printf("ThreadBtfConnect started\n");
    string strAddr = *(string*)parg;
    delete (string*)parg;
    loop
    {
        if (fShutdown)
            return;
        try
        {
            CNode* pnode = ConnectNodeBtf(strAddr);
            if (pnode)
            {
                if (!pnode->fNetworkNode)
                    pnode->fNetworkNode = true; // keep the ref from ConnectNodeBtf
                else
                    pnode->Release(); // already pinned; drop the extra ref
            }
        }
        CATCH_PRINT_EXCEPTION("ThreadBtfConnect")
        for (int i = 0; i < 30 && !fShutdown; i++)
            Sleep(1000);
    }
}

void CNode::Disconnect()
{
    LogPrint("net", "disconnecting node %s\n", addr.ToString().c_str());

    closesocket(hSocket);

    // All of a nodes broadcasts and subscriptions are automatically torn down
    // when it goes down, so a node has to stay up to keep its broadcast going.

    CRITICAL_BLOCK(cs_mapProducts)
        for (map<uint256, CProduct>::iterator mi = mapProducts.begin(); mi != mapProducts.end();)
            AdvertRemoveSource(this, MSG_PRODUCT, 0, (*(mi++)).second);

    // Cancel subscriptions
    for (unsigned int nChannel = 0; nChannel < vfSubscribe.size(); nChannel++)
        if (vfSubscribe[nChannel])
            CancelSubscribe(nChannel);
}













void ThreadSocketHandler(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadSocketHandler(parg));

    loop
    {
        vfThreadRunning[0] = true;
        CheckForShutdown(0);
        try
        {
            ThreadSocketHandler2(parg);
        }
        CATCH_PRINT_EXCEPTION("ThreadSocketHandler()")
        vfThreadRunning[0] = false;
        Sleep(5000);
    }
}

void ThreadSocketHandler2(void* parg)
{
    printf("ThreadSocketHandler started\n");
    SOCKET hListenSocket = *(SOCKET*)parg;
    list<CNode*> vNodesDisconnected;
    int nPrevNodeCount = 0;

    loop
    {
        //
        // Disconnect nodes
        //
        CRITICAL_BLOCK(cs_vNodes)
        {
            // Disconnect duplicate connections
            map<unsigned int, CNode*> mapFirst;
            foreach(CNode* pnode, vNodes)
            {
                if (pnode->fDisconnect)
                    continue;
                unsigned int ip = pnode->addr.ip;
                if (mapFirst.count(ip) && addrLocalHost.ip < ip)
                {
                    // In case two nodes connect to each other at once,
                    // the lower ip disconnects its outbound connection
                    CNode* pnodeExtra = mapFirst[ip];

                    if (pnodeExtra->GetRefCount() > (pnodeExtra->fNetworkNode ? 1 : 0))
                        swap(pnodeExtra, pnode);

                    if (pnodeExtra->GetRefCount() <= (pnodeExtra->fNetworkNode ? 1 : 0))
                    {
                        LogPrint("net", "(%d nodes) disconnecting duplicate: %s\n", (int)vNodes.size(), pnodeExtra->addr.ToString().c_str());
                        if (pnodeExtra->fNetworkNode && !pnode->fNetworkNode)
                        {
                            pnode->AddRef();
                            swap(pnodeExtra->fNetworkNode, pnode->fNetworkNode);
                            pnodeExtra->Release();
                        }
                        pnodeExtra->fDisconnect = true;
                    }
                }
                mapFirst[ip] = pnode;
            }

            // Disconnect unused nodes
            vector<CNode*> vNodesCopy = vNodes;
            foreach(CNode* pnode, vNodesCopy)
            {
                if (pnode->ReadyToDisconnect() && pnode->vRecv.empty() && pnode->vSend.empty())
                {
                    // remove from vNodes
                    vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());
                    pnode->Disconnect();

                    // hold in disconnected pool until all refs are released
                    pnode->nReleaseTime = max(pnode->nReleaseTime, GetTime() + 5 * 60);
                    if (pnode->fNetworkNode)
                        pnode->Release();
                    vNodesDisconnected.push_back(pnode);
                }
            }

            // Delete disconnected nodes
            list<CNode*> vNodesDisconnectedCopy = vNodesDisconnected;
            foreach(CNode* pnode, vNodesDisconnectedCopy)
            {
                // wait until threads are done using it
                if (pnode->GetRefCount() <= 0)
                {
                    bool fDelete = false;
                    TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                     TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                      TRY_CRITICAL_BLOCK(pnode->cs_mapRequests)
                       TRY_CRITICAL_BLOCK(pnode->cs_inventory)
                        fDelete = true;
                    if (fDelete)
                    {
                        vNodesDisconnected.remove(pnode);
                        delete pnode;
                    }
                }
            }
        }
        if (vNodes.size() != nPrevNodeCount)
        {
            nPrevNodeCount = vNodes.size();
            MainFrameRepaint();
        }


        //
        // Find which sockets have data to receive
        //
        struct timeval timeout;
        timeout.tv_sec  = 0;
        timeout.tv_usec = 50000; // frequency to poll pnode->vSend

        fd_set fdsetRecv;
        fd_set fdsetSend;
        FD_ZERO(&fdsetRecv);
        FD_ZERO(&fdsetSend);
        SOCKET hSocketMax = 0;
        FD_SET(hListenSocket, &fdsetRecv);
        hSocketMax = max(hSocketMax, hListenSocket);
        CRITICAL_BLOCK(cs_vNodes)
        {
            foreach(CNode* pnode, vNodes)
            {
                FD_SET(pnode->hSocket, &fdsetRecv);
                hSocketMax = max(hSocketMax, pnode->hSocket);
                TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                    if (!pnode->vSend.empty())
                        FD_SET(pnode->hSocket, &fdsetSend);
            }
        }

        vfThreadRunning[0] = false;
        int nSelect = select(hSocketMax + 1, &fdsetRecv, &fdsetSend, NULL, &timeout);
        vfThreadRunning[0] = true;
        CheckForShutdown(0);
        if (nSelect == SOCKET_ERROR)
        {
            int nErr = WSAGetLastError();
            LogPrint("net", "select failed: %d\n", nErr);
            for (int i = 0; i <= hSocketMax; i++)
            {
                FD_SET(i, &fdsetRecv);
                FD_SET(i, &fdsetSend);
            }
            Sleep(timeout.tv_usec/1000);
        }
        RandAddSeed();

        //// debug print
        //foreach(CNode* pnode, vNodes)
        //{
        //    printf("vRecv = %-5d ", pnode->vRecv.size());
        //    printf("vSend = %-5d    ", pnode->vSend.size());
        //}
        //printf("\n");


        //
        // Accept new connections
        //
        if (FD_ISSET(hListenSocket, &fdsetRecv))
        {
            struct sockaddr_in sockaddr;
#ifdef _WIN32
            int len = sizeof(sockaddr);
#else
            socklen_t len = sizeof(sockaddr);
#endif
            SOCKET hSocket = accept(hListenSocket, (struct sockaddr*)&sockaddr, &len);
            CAddress addr(sockaddr);
            if (hSocket == INVALID_SOCKET)
            {
                if (WSAGetLastError() != WSAEWOULDBLOCK)
                    printf("ERROR ThreadSocketHandler accept failed: %d\n", WSAGetLastError());
            }
            else
            {
                LogPrint("net", "accepted connection from %s\n", addr.ToString().c_str());
                CNode* pnode = new CNode(hSocket, addr, true);
                pnode->AddRef();
                CRITICAL_BLOCK(cs_vNodes)
                    vNodes.push_back(pnode);
            }
        }


        //
        // Service each socket
        //
        vector<CNode*> vNodesCopy;
        CRITICAL_BLOCK(cs_vNodes)
            vNodesCopy = vNodes;
        foreach(CNode* pnode, vNodesCopy)
        {
            CheckForShutdown(0);
            SOCKET hSocket = pnode->hSocket;

            //
            // Receive
            //
            if (FD_ISSET(hSocket, &fdsetRecv))
            {
                TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                {
                    CDataStream& vRecv = pnode->vRecv;
                    unsigned int nPos = vRecv.size();

                    // typical socket buffer is 8K-64K
                    const unsigned int nBufSize = 0x10000;
                    vRecv.resize(nPos + nBufSize);
                    int nBytes = recv(hSocket, &vRecv[nPos], nBufSize, 0);
                    vRecv.resize(nPos + max(nBytes, 0));
                    if (nBytes > 0)
                    {
                        pnode->nLastRecv = GetTime();
                    }
                    else if (nBytes == 0)
                    {
                        // socket closed gracefully
                        if (!pnode->fDisconnect)
                            LogPrint("net", "recv: socket closed\n");
                        pnode->fDisconnect = true;
                    }
                    else if (nBytes < 0)
                    {
                        // socket error
                        int nErr = WSAGetLastError();
                        if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                        {
                            if (!pnode->fDisconnect)
                                LogPrint("net", "recv failed: %d\n", nErr);
                            pnode->fDisconnect = true;
                        }
                    }
                }
            }

            //
            // Send
            //
            if (FD_ISSET(hSocket, &fdsetSend))
            {
                TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                {
                    CDataStream& vSend = pnode->vSend;
                    if (!vSend.empty())
                    {
                        int nBytes = send(hSocket, &vSend[0], vSend.size(), 0);
                        if (nBytes > 0)
                        {
                            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
                            pnode->nLastSend = GetTime();
                        }
                        else if (nBytes == 0)
                        {
                            if (pnode->ReadyToDisconnect())
                                pnode->vSend.clear();
                        }
                        else
                        {
                            LogPrint("net", "send error %d\n", nBytes);
                            if (pnode->ReadyToDisconnect())
                                pnode->vSend.clear();
                        }
                    }
                    if (vSend.empty())
                        pnode->nLastSendEmpty = GetTime();
                }
            }

            //
            // Inactivity
            //
            // Dropping the connection is the whole cure: everything above this
            // layer already knows how to reconnect, and a peer we cannot hear
            // is worth exactly as much as no peer at all. Give a new
            // connection a grace period first, or we would cut off peers that
            // are still completing the rendezvous handshake.
            //
            if (GetTime() - pnode->nTimeConnected > BTF_HANDSHAKE_GRACE_SECS)
            {
                if (pnode->nLastRecv == 0 || pnode->nLastSend == 0)
                {
                    LogPrint("net", "socket no message in first %d seconds, recv=%d send=%d\n",
                             BTF_HANDSHAKE_GRACE_SECS, pnode->nLastRecv != 0, pnode->nLastSend != 0);
                    pnode->fDisconnect = true;
                }
                else if (GetTime() - pnode->nLastSend > BTF_SEND_STALL_SECS &&
                         GetTime() - pnode->nLastSendEmpty > BTF_SEND_STALL_SECS)
                {
                    // We have had something queued to send for this long and
                    // none of it has gone out: the socket accepts no more.
                    LogPrint("net", "socket not sending\n");
                    pnode->fDisconnect = true;
                }
                else if (GetTime() - pnode->nLastRecv > BTF_RECV_TIMEOUT_SECS)
                {
                    // The deaf case. Nothing has arrived for many block
                    // intervals while the socket still looks perfectly fine.
                    LogPrint("net", "socket inactivity timeout\n");
                    pnode->fDisconnect = true;
                }
            }
        }


        Sleep(10);
    }
}


















void ThreadMessageHandler(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadMessageHandler(parg));

    loop
    {
        vfThreadRunning[2] = true;
        CheckForShutdown(2);
        try
        {
            ThreadMessageHandler2(parg);
        }
        CATCH_PRINT_EXCEPTION("ThreadMessageHandler()")
        vfThreadRunning[2] = false;
        Sleep(5000);
    }
}

void ThreadMessageHandler2(void* parg)
{
    printf("ThreadMessageHandler started\n");
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    loop
    {
        // Poll the connected nodes for messages
        vector<CNode*> vNodesCopy;
        CRITICAL_BLOCK(cs_vNodes)
            vNodesCopy = vNodes;
        foreach(CNode* pnode, vNodesCopy)
        {
            pnode->AddRef();

            // Receive messages
            TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                ProcessMessages(pnode);

            // Send messages
            TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                SendMessages(pnode);

            pnode->Release();
        }

        // Wait and allow messages to bunch up
        vfThreadRunning[2] = false;
        Sleep(100);
        vfThreadRunning[2] = true;
        CheckForShutdown(2);
    }
}









// Satoshi's "todo: start one thread per processor" stood here since 2009 and is
// what MinerThreadCount() and StartMinerThreads() below finally do -- by way of
// std::thread::hardware_concurrency rather than NUMBER_OF_PROCESSORS, which only
// ever existed on Windows.
//
// Miners share slot 3 of vfThreadRunning, and StopNode waits for every slot to
// go false before the node tears the database down. With one miner that was the
// same thing as "the miner finished"; with several, the first one out would
// announce that everybody had finished while the rest were still hashing and
// still calling ProcessBlock. So count them, and let only the last one leaving
// clear the flag.
static CCriticalSection cs_nMinersRunning;
static int nMinersRunning = 0;

void ThreadBitcoinMiner(void* parg)
{
    int nThreadId = (int)(intptr_t)parg;
    CRITICAL_BLOCK(cs_nMinersRunning)
    {
        nMinersRunning++;
        vfThreadRunning[3] = true;
    }
    try
    {
        bool fRet = BitcoinMiner(nThreadId);
        printf("BitcoinMiner thread %d returned %s\n", nThreadId, fRet ? "true" : "false");
    }
    CATCH_PRINT_EXCEPTION("BitcoinMiner()")
    CRITICAL_BLOCK(cs_nMinersRunning)
    {
        if (--nMinersRunning <= 0)
        {
            nMinersRunning = 0;
            vfThreadRunning[3] = false;
        }
    }
}

// Start the miners. Returns how many actually got off the ground.
int StartMinerThreads()
{
    int nThreads = MinerThreadCount();
    int nStarted = 0;
    for (int i = 0; i < nThreads; i++)
    {
        if (_beginthread(ThreadBitcoinMiner, 0, (void*)(intptr_t)(i + 1)) == (uintptr_t)-1)
            printf("Error: _beginthread(ThreadBitcoinMiner) failed on thread %d\n", i + 1);
        else
            nStarted++;
    }
    // The dataset is one allocation shared by all of them; only the 2 MB
    // scratchpads multiply. Printed because "why is it using 2 GB" is the first
    // question anyone asks.
    printf("Mining with %d thread(s) of %u core(s) -- about %d MB "
           "(~2080 MB shared RandomX dataset + ~2 MB per thread)\n",
           nStarted, std::thread::hardware_concurrency(), 2080 + 2 * nStarted);
    return nStarted;
}











bool StartNode(string& strError)
{
    strError = "";

    // Sockets startup
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR)
    {
        strError = strprintf("Error: TCP/IP socket library failed to start (WSAStartup returned error %d)", ret);
        printf("%s\n", strError.c_str());
        return false;
    }

    // Get local host ip
    char pszHostName[255];
    if (gethostname(pszHostName, 255) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Unable to get IP address of this computer (gethostname returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }
    struct hostent* pHostEnt = gethostbyname(pszHostName);
    if (!pHostEnt)
    {
        strError = strprintf("Error: Unable to get IP address of this computer (gethostbyname returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }
    addrLocalHost = CAddress(*(long*)(pHostEnt->h_addr_list[0]),
                             nListenPort,
                             nLocalServices);
    printf("addrLocalHost = %s\n", addrLocalHost.ToString().c_str());

    // Create socket for listening for incoming connections
    SOCKET hListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming connections (socket returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // Set to nonblocking, incoming connections will also inherit this
    u_long nOne = 1;
    if (ioctlsocket(hListenSocket, FIONBIO, &nOne) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Couldn't set properties on socket for incoming connections (ioctlsocket returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound
    int nRetryLimit = 15;
    struct sockaddr_in sockaddr = addrLocalHost.GetSockAddr();
    if (bind(hListenSocket, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
            strError = strprintf("Error: Unable to bind to port %s on this computer. The program is probably already running.", addrLocalHost.ToString().c_str());
        else
            strError = strprintf("Error: Unable to bind to port %s on this computer (bind returned error %d)", addrLocalHost.ToString().c_str(), nErr);
        printf("%s\n", strError.c_str());
        return false;
    }
    printf("bound to addrLocalHost = %s\n\n", addrLocalHost.ToString().c_str());

    // Listen for incoming connections
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Listening for incoming connections failed (listen returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // Get our external IP in a background thread -- up to 4 HTTP requests with
    // 5s timeouts each could otherwise delay startup by 20s on first run.
    // addrIncoming from a previous session is used immediately as a fallback.
    if (addrIncoming.ip)
        addrLocalHost.ip = addrIncoming.ip;

    _beginthread([](void*) {
        unsigned int ip = addrLocalHost.ip;
        if (GetMyExternalIP(ip)) {
            addrLocalHost.ip = ip;
            addrIncoming = addrLocalHost;
            CWalletDB().WriteSetting("addrIncoming", addrIncoming);
            printf("External IP updated: %s\n", addrLocalHost.ToStringIP().c_str());
        }
    }, 0, NULL);

    // Peers that answered last time, dialled straight away. The relays are the
    // only way to find anyone otherwise, and reaching them plus walking their
    // descriptor list is what makes a restart take minutes.
    if (_beginthread(ThreadReconnectCachedBtfPeers, 0, NULL) == -1)
        printf("Error: _beginthread(ThreadReconnectCachedBtfPeers) failed\n");

    // Peer discovery over Nostr relays (replaces the old IRC seed)
    if (_beginthread(ThreadNostrSeed, 0, NULL) == -1)
        printf("Error: _beginthread(ThreadNostrSeed) failed\n");

    // Anonymous inbound: this node's .btf hidden service, reachable through the
    // meeting relay without exposing our IP or needing a public port.
    if (!vBtfMeetingRelays.empty())
        if (_beginthread(ThreadBtfAccept, 0, NULL) == -1)
            printf("Error: _beginthread(ThreadBtfAccept) failed\n");

    // Anonymous outbound: keep a connection to a specific .btf peer, if asked.
    if (!strBtfConnect.empty())
        if (_beginthread(ThreadBtfConnect, 0, new string(strBtfConnect)) == -1)
            printf("Error: _beginthread(ThreadBtfConnect) failed\n");

    //
    // Start threads
    //
    if (_beginthread(ThreadSocketHandler, 0, new SOCKET(hListenSocket)) == -1)
    {
        strError = "Error: _beginthread(ThreadSocketHandler) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    if (_beginthread(ThreadMessageHandler, 0, NULL) == -1)
    {
        strError = "Error: _beginthread(ThreadMessageHandler) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    return true;
}

bool StopNode()
{
    printf("StopNode()\n");
    fShutdown = true;
    nTransactionsUpdated++;
    while (count(vfThreadRunning.begin(), vfThreadRunning.end(), true))
        Sleep(10);
    Sleep(50);

    // Sockets shutdown
    WSACleanup();
    return true;
}

void CheckForShutdown(int n)
{
    if (fShutdown)
    {
        if (n != -1)
            vfThreadRunning[n] = false;
        _endthread();
    }
}
