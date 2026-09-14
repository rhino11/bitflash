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
#else
#include <poll.h>
#endif
#include <openssl/rand.h>
#include <cerrno>
#include <cstdlib>
#include "btfaddr.h"
#include "proxy.h"
#include "tor.h"

void ThreadReconnectCachedBtfPeers(void* parg);
void ThreadMessageHandler2(void* parg);
void ThreadSocketHandler2(void* parg);

#ifdef _WIN32
typedef WSAPOLLFD BtfPollFd;
static int BtfPoll(BtfPollFd* pfd, unsigned int nfd, int nTimeoutMs)
{
    return WSAPoll(pfd, nfd, nTimeoutMs);
}
#else
typedef struct pollfd BtfPollFd;
static int BtfPoll(BtfPollFd* pfd, unsigned int nfd, int nTimeoutMs)
{
    return poll(pfd, (nfds_t)nfd, nTimeoutMs);
}
#endif






//
// Global state variables
//
static const char pchMainnetMessageStart[4] = { 0xbf, 0x20, 0x5c, 0xfd };
static const char pchTestnetMessageStart[4] = { (char)0xce, (char)0xe2, (char)0xc0, (char)0xff };
static bool fTestNet = false;
char pchMessageStart[4] = { 0xbf, 0x20, 0x5c, 0xfd };
bool fClient = false;
uint64 nLocalServices = (fClient ? 0 : NODE_NETWORK);
CAddress addrLocalHost(0, GetDefaultPort(), nLocalServices);
unsigned short nListenPort = GetDefaultPort(); // local P2P port (tunable via /port)
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
static const int BTF_ONION_CONNECT_TIMEOUT_SECS = 120;

int   nPeersWatched        = 0;
int64 nBlocksReceived      = 0;
int64 nBlocksWithoutParent = 0;
static int64 nNodeStartTime = 0;

static CCriticalSection cs_btfChurn;
static int64 nBtfResolveAttempts = 0;
static int64 nBtfResolveOk = 0;
static int64 nBtfResolveMiss = 0;
static int64 nBtfDialAttempts = 0;
static int64 nBtfDialOk = 0;
static int64 nBtfDialFailed = 0;
static int64 nBtfRegisterOk = 0;
static int64 nBtfRegisterFailed = 0;
static int64 nBtfPairOk = 0;
static int64 nBtfPairFailed = 0;
static int64 nBtfHandshakeNoRecv = 0;
static int64 nBtfHandshakeNoSend = 0;
static int64 nBtfHandshakeSilent = 0;
static string strBtfLastDialFail;
static string strBtfLastHandshakeTimeout;

bool IsTestNet()
{
    return fTestNet;
}

unsigned short GetDefaultPort()
{
    return htons(fTestNet ? TESTNET_PORT : MAINNET_PORT);
}

void SelectNetworkParams(bool fTestNetIn)
{
    if (fTestNet == fTestNetIn)
        return;

    fTestNet = fTestNetIn;
    memcpy(pchMessageStart,
           fTestNet ? pchTestnetMessageStart : pchMainnetMessageStart,
           sizeof(pchMessageStart));
    nListenPort = GetDefaultPort();
    addrLocalHost.port = nListenPort;
}

void BtfChurnNoteResolveAttempt()
{
    CRITICAL_BLOCK(cs_btfChurn)
        nBtfResolveAttempts++;
}

void BtfChurnNoteResolveResult(bool fOk)
{
    CRITICAL_BLOCK(cs_btfChurn)
    {
        if (fOk) nBtfResolveOk++;
        else    nBtfResolveMiss++;
    }
}

void BtfChurnNoteDialAttempt(const string& strBtfAddr, const string& strMeeting)
{
    CRITICAL_BLOCK(cs_btfChurn)
        nBtfDialAttempts++;
    LogPrint("net", "btfchurn: dial attempt addr=%s meeting=%s\n",
             strBtfAddr.c_str(), strMeeting.c_str());
}

void BtfChurnNoteDialResult(const string& strBtfAddr, const string& strMeeting, bool fOk)
{
    CRITICAL_BLOCK(cs_btfChurn)
    {
        if (fOk)
            nBtfDialOk++;
        else
        {
            nBtfDialFailed++;
            strBtfLastDialFail = strBtfAddr + " via " + strMeeting;
        }
    }
    LogPrint("net", "btfchurn: dial %s addr=%s meeting=%s\n",
             fOk ? "ok" : "failed", strBtfAddr.c_str(), strMeeting.c_str());
}

void BtfChurnNoteRegisterResult(const string& strMeeting, bool fOk)
{
    CRITICAL_BLOCK(cs_btfChurn)
    {
        if (fOk) nBtfRegisterOk++;
        else    nBtfRegisterFailed++;
    }
    LogPrint("net", "btfchurn: register %s meeting=%s\n",
             fOk ? "ok" : "failed", strMeeting.c_str());
}

void BtfChurnNotePairResult(const string& strMeeting, bool fOk)
{
    CRITICAL_BLOCK(cs_btfChurn)
    {
        if (fOk) nBtfPairOk++;
        else    nBtfPairFailed++;
    }
    LogPrint("net", "btfchurn: pair %s meeting=%s\n",
             fOk ? "ok" : "timeout-or-drop", strMeeting.c_str());
}

void BtfChurnNoteHandshakeTimeout(const string& strBtfAddr, const string& strMeeting,
                                  bool fRecv, bool fSend)
{
    CRITICAL_BLOCK(cs_btfChurn)
    {
        if (!fRecv && !fSend)
            nBtfHandshakeSilent++;
        else
        {
            if (!fRecv) nBtfHandshakeNoRecv++;
            if (!fSend) nBtfHandshakeNoSend++;
        }
        strBtfLastHandshakeTimeout = strprintf("%s via %s recv=%d send=%d",
                                               strBtfAddr.empty() ? "unknown" : strBtfAddr.c_str(),
                                               strMeeting.empty() ? "unknown" : strMeeting.c_str(),
                                               fRecv, fSend);
    }
}

// --- Socket accounting (implementation lives in sockcount.h) --------------
static const char* pszSockSite[SOCK_SITES] = {
    "external-ip probe", "listen socket", "inbound accept",
    "rendezvous dial", "rendezvous listen", "rendezvous accept",
    "loopback pair listener", "loopback pair app end", "loopback pair pump end",
    "nostr relay", "direct onion peer", "stratum bridge"
};

static string SockAccountingText()
{
    long long nOpened[SOCK_SITES], nClosed[SOCK_SITES], nFailed[SOCK_SITES];
    long long nCollided[SOCK_SITES], nUntagged = 0;
    BtfSockSnapshot(nOpened, nClosed, nFailed, nCollided, &nUntagged);

    long long nUnconn[SOCK_SITES];
    BtfSockLiveUnconnected(nUnconn);

    string str = "\n  sockets by where they were created\n";
    str += "  site                       opened   closed     live  close failed  live unconn\n";
    long long nTotalOpened = 0, nTotalClosed = 0, nTotalFailed = 0, nTotalUnconn = 0;
    for (int i = 0; i < SOCK_SITES; i++)
    {
        nTotalOpened += nOpened[i];
        nTotalClosed += nClosed[i];
        nTotalFailed += nFailed[i];
        nTotalUnconn += nUnconn[i];
        if (nOpened[i] == 0)
            continue;
        str += strprintf("  %-24s %8lld %8lld %8lld %13lld %12lld\n", pszSockSite[i],
                         nOpened[i], nClosed[i], nOpened[i] - nClosed[i], nFailed[i], nUnconn[i]);
    }
    str += strprintf("  %-24s %8s %8lld %8s %13s %12s\n", "closed but never tagged",
                     "-", nUntagged, "-", "-", "-");
    str += strprintf("  %-24s %8lld %8lld %8lld %13lld %12lld\n", "TOTAL",
                     nTotalOpened, nTotalClosed, nTotalOpened - nTotalClosed,
                     nTotalFailed, nTotalUnconn);

    // The live total is what this program believes it is holding. Comparing it
    // against `Get-NetTCPConnection | ? OwningProcess -eq <pid>` needs the note
    // in sockcount.h first: that table lists a wildcard-bound socket twice, so
    // a raw row count always looks larger than this. Count orphans, not rows.
    //
    // "live unconn" is a getpeername on every tagged socket. Anything above 1
    // -- the listening socket -- means this program is holding a socket it
    // never connected, which is the shape the leak hunt was looking for and
    // never found.
    if (nTotalFailed > 0)
    {
        str += "  close failures by code\n";
        for (int i = 0; i < SOCK_SITES; i++)
        {
            if (nFailed[i] == 0)
                continue;
            map<int, long long> mapErr;
            BtfSockCloseErrors(i, mapErr);
            string strCodes;
            for (map<int, long long>::const_iterator mi = mapErr.begin(); mi != mapErr.end(); ++mi)
                strCodes += strprintf("%s%d x%lld", strCodes.empty() ? "" : ", ",
                                      mi->first, mi->second);
            str += strprintf("  %-24s %s\n", pszSockSite[i], strCodes.c_str());
        }
    }

    // A handle number handed out again while a site still claimed it. Windows
    // only reuses a number after the last close, so this says that site's
    // bookkeeping outlived its socket -- and it will close that number again,
    // on somebody else's connection. Any value above zero is a bug with a name
    // attached.
    for (int i = 0; i < SOCK_SITES; i++)
    {
        if (nCollided[i] == 0)
            continue;
        str += strprintf("  handle reused while %s still claimed it: %lld\n",
                         pszSockSite[i], nCollided[i]);
    }
    return str;
}

// Defined further down, next to the counter it reads. The miner keeps its own
// live count -- threads bump it on the way in and on the way out -- which is
// the honest number here: how many are hashing now, not how many were asked to.
static int MinersRunningCount();

// Seconds rendered the way a person reads them off a screen.
static string FormatAge(int64 nSeconds)
{
    if (nSeconds < 0)  return "never";
    if (nSeconds < 60) return strprintf("%llds", (long long)nSeconds);
    if (nSeconds < 3600)
        return strprintf("%lldm%02llds", (long long)(nSeconds / 60), (long long)(nSeconds % 60));
    return strprintf("%lldh%02lldm", (long long)(nSeconds / 3600), (long long)((nSeconds % 3600) / 60));
}

string GetDiagnosticsText()
{
    int64 nNow = GetTime();
    string str;

    int nInbound = 0, nHeld = 0, nDirectOnion = 0, nRendezvous = 0;
    vector<CNode*> vCopy;
    CRITICAL_BLOCK(cs_vNodes)
    {
        vCopy = vNodes;
        nHeld = (int)vNodes.size();
        foreach(CNode* pnode, vNodes)
        {
            if (pnode->fInbound)
                nInbound++;
            if (pnode->strBtfMeeting.find(".onion:") != string::npos)
                nDirectOnion++;
            else if (!pnode->strBtfMeeting.empty())
                nRendezvous++;
        }
    }

    int nMedian = GetPeerMedianHeight();

    str += "Bitflash node diagnostics\n";
    str += strprintf("  network           %s\n", IsTestNet() ? "testnet" : "mainnet");
    str += strprintf("  uptime            %s\n",
                     FormatAge(nNodeStartTime ? nNow - nNodeStartTime : -1).c_str());
    if (nMedian < 0)
        str += strprintf("  height            %d  (no peer has said where it is)\n", nBestHeight);
    else
        str += strprintf("  height            %d  (peers report %d, %s)\n",
                         nBestHeight, nMedian,
                         nBestHeight >= nMedian ? "level or ahead"
                                                : strprintf("behind by %d", nMedian - nBestHeight).c_str());
    str += strprintf("  peers held        %d  (%d inbound, %d outbound)\n",
                     nHeld, nInbound, nHeld - nInbound);

    // The number that would have made the deafness obvious. Anything held but
    // not watched is a socket this node will never read again.
    str += strprintf("  peers watched     %d of %d held by poll%s\n",
                     nPeersWatched, nHeld,
                     nHeld > nPeersWatched ? "   <-- NOT ALL PEERS ARE BEING READ" : "");
    str += strprintf("  managed Tor       %s\n", BtfManagedTorStatus().c_str());

    string strTorMode = "disabled";
    if (BtfManagedTorEnabled())
        strTorMode = "managed";
    else if (BtfTorProxyEnabled())
        strTorMode = "external";
    else if (BtfSocks5ProxyEnabled())
        strTorMode = "socks5";
    string strOnion = BtfLocalOnionEndpoint();
    str += strprintf("  Tor mode          %s\n", strTorMode.c_str());
    str += strprintf("  onion endpoint    %s\n",
                     strOnion.empty() ? "none" : strOnion.c_str());
    str += strprintf("  .btf peers         %d direct onion, %d rendezvous\n",
                     nDirectOnion, nRendezvous);

    if (nBlocksReceived > 0)
        str += strprintf("  blocks received   %lld  (%lld arrived without a parent, %.1f%%)\n",
                         (long long)nBlocksReceived, (long long)nBlocksWithoutParent,
                         100.0 * nBlocksWithoutParent / nBlocksReceived);
    else
        str += "  blocks received   0\n";

    int nMining = MinersRunningCount();
    int nPoWNow = PoWVersionAt(GetAdjustedTime());
    str += strprintf("  proof of work     v%d, %s mode%s\n", nPoWNow,
                     RandomXFastReady(nPoWNow) ? "fast (2 GB dataset)" : "light (256 MB cache)",
                     nMining > 0
                         ? strprintf(", mining on %d thread(s), about %d MB",
                                     nMining,
                                     (RandomXFastReady(nPoWNow) ? 2080 : 256) + 2 * nMining).c_str()
                         : ", not mining");
    if (nPoWNow == 1)
        str += strprintf("  PoW v2 switch     block time %u; RandomX miners (xmrig) from then on\n",
                         PoWV2Time());
    str += strprintf("  large pages       %s\n", RandomXLargePagesStatus());

    str += SockAccountingText();

    int64 nResolveAttempts, nResolveOk, nResolveMiss;
    int64 nDialAttempts, nDialOk, nDialFailed;
    int64 nRegisterOk, nRegisterFailed, nPairOk, nPairFailed;
    int64 nHandshakeNoRecv, nHandshakeNoSend, nHandshakeSilent;
    string strLastDialFail, strLastHandshakeTimeout;
    CRITICAL_BLOCK(cs_btfChurn)
    {
        nResolveAttempts = nBtfResolveAttempts;
        nResolveOk = nBtfResolveOk;
        nResolveMiss = nBtfResolveMiss;
        nDialAttempts = nBtfDialAttempts;
        nDialOk = nBtfDialOk;
        nDialFailed = nBtfDialFailed;
        nRegisterOk = nBtfRegisterOk;
        nRegisterFailed = nBtfRegisterFailed;
        nPairOk = nBtfPairOk;
        nPairFailed = nBtfPairFailed;
        nHandshakeNoRecv = nBtfHandshakeNoRecv;
        nHandshakeNoSend = nBtfHandshakeNoSend;
        nHandshakeSilent = nBtfHandshakeSilent;
        strLastDialFail = strBtfLastDialFail;
        strLastHandshakeTimeout = strBtfLastHandshakeTimeout;
    }
    str += "\n  .btf churn\n";
    str += strprintf("  resolves          %lld attempts, %lld ok, %lld no descriptor\n",
                     (long long)nResolveAttempts, (long long)nResolveOk,
                     (long long)nResolveMiss);
    str += strprintf("  outbound dials    %lld attempts, %lld ok, %lld failed\n",
                     (long long)nDialAttempts, (long long)nDialOk,
                     (long long)nDialFailed);
    str += strprintf("  rendezvous local  register ok/fail %lld/%lld, pair ok/drop %lld/%lld\n",
                     (long long)nRegisterOk, (long long)nRegisterFailed,
                     (long long)nPairOk, (long long)nPairFailed);
    str += strprintf("  handshake grace   silent %lld, no recv %lld, no send %lld\n",
                     (long long)nHandshakeSilent, (long long)nHandshakeNoRecv,
                     (long long)nHandshakeNoSend);
    if (!strLastDialFail.empty())
        str += strprintf("  last dial failure %s\n", strLastDialFail.c_str());
    if (!strLastHandshakeTimeout.empty())
        str += strprintf("  last handshake    %s\n", strLastHandshakeTimeout.c_str());

    str += "\n  peer                          dir  height   last recv   last send   unsent  via\n";
    foreach(CNode* pnode, vCopy)
    {
        int nSendSize = 0;
        TRY_CRITICAL_BLOCK(pnode->cs_vSend)
            nSendSize = (int)pnode->vSend.size();
        string strVia;
        if (!pnode->strBtfMeeting.empty())
            strVia = pnode->strBtfMeeting;
        str += strprintf("  %-28s %-4s %6d  %10s  %10s  %7d  %s\n",
                         pnode->addr.ToString().substr(0, 28).c_str(),
                         pnode->fInbound ? "in" : "out",
                         pnode->nStartingHeight,
                         FormatAge(pnode->nLastRecv ? nNow - pnode->nLastRecv : -1).c_str(),
                         FormatAge(pnode->nLastSend ? nNow - pnode->nLastSend : -1).c_str(),
                         nSendSize,
                         strVia.substr(0, 28).c_str());
    }
    return str;
}


bool GetMyExternalIP(unsigned int& ipRet)
{
    if (BtfSocks5ProxyEnabled())
        return error("GetMyExternalIP() skipped while SOCKS5 proxy is enabled\n");

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

        SOCKET hSocket = BtfSocketTag(socket(res->ai_family, res->ai_socktype, res->ai_protocol), SOCK_EXTIP);
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
            freeaddrinfo(res); BtfCloseSocket(hSocket); continue;
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
        BtfCloseSocket(hSocket);

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

void CNode::PushGetBlocks(CBlockIndex* pindexBegin, uint256 hashEnd)
{
    // Filter out duplicate requests.
    if (pindexBegin == pindexLastGetBlocksBegin && hashEnd == hashLastGetBlocksEnd)
        return;
    pindexLastGetBlocksBegin = pindexBegin;
    hashLastGetBlocksEnd     = hashEnd;

    PushMessage("getblocks", CBlockLocator(pindexBegin), hashEnd);
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
    string onion;
    string encHex;
    int64  lastSeen;
    // The peer's own signed descriptor, as it announced itself. Kept verbatim
    // because that signature is what lets us hand this peer on to somebody
    // else: the receiver checks it against the key the address decodes to and
    // never has to take our word for anything. Empty for entries learned
    // before peer exchange existed, or resolved through Nostr -- those are
    // still dialable, just not relayable.
    string desc;
    // True once a connection to this peer actually succeeded. Only these are
    // handed on to other nodes: a cache entry is otherwise just something we
    // were told, and passing hearsay along is how one node's mixed cache
    // becomes everybody's.
    bool fVerified;
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
            if (o.contains("onion") && o["onion"].is_string())
                btf::NormalizeOnionEndpoint(o["onion"].get<string>(), p.onion);
            p.encHex   = o["enc"].get<string>();
            p.lastSeen = o.value("seen", (int64)0);
            if (o.contains("desc") && o["desc"].is_string())
                p.desc = o["desc"].get<string>();
            p.fVerified = o.value("ok", false);
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

// Look up a peer's cached direct-onion endpoint (host.onion:port) by .btf
// address, from the peers we have actually reached and remembered. Lets a
// caller reach a node it has already seen without a Nostr round-trip -- Nostr
// over Tor often has no exit node, so a cache hit is the reliable path.
bool BtfCachedPeerOnion(const string& strBtfAddr, string& strOnionOut)
{
    strOnionOut.clear();
    vector<CachedBtfPeer> peers;
    CRITICAL_BLOCK(cs_btfPeerCache)
        LoadCachedBtfPeers(peers);
    foreach(const CachedBtfPeer& p, peers)
        if (p.btfAddr == strBtfAddr && !p.onion.empty())
        {
            strOnionOut = p.onion;
            return true;
        }
    return false;
}

// strDesc is the peer's own signed descriptor when we have it (it announced
// itself over peer exchange), "" when we only resolved it through Nostr. An
// empty one never clears a descriptor already on file: dialing a peer we first
// learned about by exchange must not cost us the ability to pass it on.
static void RememberBtfPeer(const string& strBtfAddr, const string& strMeeting,
                            const unsigned char enc_pub[32],
                            const string& strDesc = string(),
                            const string& strOnion = string(),
                            bool fVerified = false)
{
    CRITICAL_BLOCK(cs_btfPeerCache)
    {
        vector<CachedBtfPeer> peers;
        LoadCachedBtfPeers(peers);

        string strKeepDesc = strDesc;
        string strKeepOnion;
        btf::NormalizeOnionEndpoint(strOnion, strKeepOnion);
        for (size_t i = 0; i < peers.size(); i++)
            if (peers[i].btfAddr == strBtfAddr)
            {
                if (strKeepDesc.empty())
                    strKeepDesc = peers[i].desc;
                if (strKeepOnion.empty())
                    strKeepOnion = peers[i].onion;
                // Verified is sticky: a peer that answered once does not become
                // hearsay again because somebody mentioned it afterwards.
                if (peers[i].fVerified)
                    fVerified = true;
                peers.erase(peers.begin() + i);
                break;
            }

        CachedBtfPeer p;
        p.btfAddr  = strBtfAddr;
        p.meeting  = strMeeting;
        p.onion    = strKeepOnion;
        p.encHex   = BytesToHex(enc_pub, 32);
        p.lastSeen = GetTime();
        p.desc     = strKeepDesc;
        p.fVerified = fVerified;
        peers.insert(peers.begin(), p); // most recent first

        if (peers.size() > MAX_CACHED_BTF_PEERS)
            peers.resize(MAX_CACHED_BTF_PEERS);

        nlohmann::json arr = nlohmann::json::array();
        foreach(const CachedBtfPeer& q, peers)
        {
            nlohmann::json o;
            o["btf"]     = q.btfAddr;
            o["meeting"] = q.meeting;
            if (!q.onion.empty())
                o["onion"] = q.onion;
            o["enc"]     = q.encHex;
            o["seen"]    = q.lastSeen;
            if (!q.desc.empty())
                o["desc"] = q.desc;
            if (q.fVerified)
                o["ok"] = true;
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
    const char* onion;    // pinned host.onion:port -- dialled directly, no Nostr
    // No encryption key: a direct onion connection is authenticated by the
    // address itself, so nothing here needs the x25519 key.
};

static const BtfSeed pszBtfSeedsMainnet[] =
{
    // Dedicated bootstrap node reachable at its Tor hidden service. Holds no
    // wallet balance and does not mine -- it exists only to answer a first dial.
    // Trusted for nothing: it serves the same signed, self-certifying descriptors
    // any peer does. The .onion is pinned so a cold start dials it WITHOUT a
    // Nostr resolve -- discovery over Nostr routes through Tor, which often has
    // no exit to reach the Nostr relays, and would leave a fresh node with no way
    // in. (The old Almaty rendezvous seed is retired: this release is onion-only.)
    { "fd5gieenz3oep42siocc7z7ldealvt6iztu3nkekzphc6prwwcs45xi.btf",
      "btjui62nrnc4ysmqkfxkkastvn65mecgf4j6qn2fxll3ayc7lb2vkuid.onion:8443" },
};

static const BtfSeed pszBtfSeedsTestnet[] =
{
    // Testnet bootstrap node. It runs its own genesis and magic bytes, so a
    // mainnet seed would just fail the handshake -- each network pins its own.
    // Same trustless, onion-dialled role as the mainnet seed above.
    { "g27psluzpzwjtrhbdvqmjujffxob5uzbdch6gsf5fitdtb56hswzkpa.btf",
      "jx7aprn2n4amrodshliw7yqlr75yn5i4d45b4fyt4i5qqm3wqtvd4jid.onion:18433" },
};

// Seeds for the active network: a mainnet seed cannot bootstrap a testnet node
// (different genesis/magic) and vice versa, so pick the list by network.
static const BtfSeed* BtfActiveSeeds(size_t& nOut)
{
    if (IsTestNet()) { nOut = ARRAYLEN(pszBtfSeedsTestnet); return pszBtfSeedsTestnet; }
    nOut = ARRAYLEN(pszBtfSeedsMainnet); return pszBtfSeedsMainnet;
}

// Extra seeds from the command line (/btfseed=ADDRESS:ENCHEX, repeatable).
vector<pair<string, string> > vBtfExtraSeeds;

// Explicit listener address (-bindaddr); see the bind site in BindListenPort.
static string g_strBtfBindAddr;
void BtfSetListenBindAddress(const string& strAddr) { g_strBtfBindAddr = strAddr; }
string BtfListenBindAddress() { return g_strBtfBindAddr; }

static int TryBtfSeeds()
{
    int nConnected = 0;
    // A direct onion connection is authenticated by the .btf address itself, so
    // the encryption key is unused on this path; pass a zeroed placeholder.
    unsigned char dummyEnc[32] = { 0 };

    size_t nSeeds = 0;
    const BtfSeed* seeds = BtfActiveSeeds(nSeeds);
    LogPrint("net", "btfseed: trying %zu baked %s seed(s) over onion\n",
             nSeeds, IsTestNet() ? "testnet" : "mainnet");

    // Baked seeds carry a pinned .onion, so dial it directly -- no Nostr resolve.
    // That is the whole point of a cold-start floor: Nostr discovery routes over
    // Tor, which frequently has no exit to reach the Nostr relays, so a fresh
    // node with an empty peer cache must be able to reach the seed without it.
    for (size_t i = 0; i < nSeeds; i++)
    {
        if (fShutdown) return nConnected;
        if (ConnectNodeBtfResolved(seeds[i].btfAddr, "", seeds[i].onion, dummyEnc))
        {
            LogPrint("net", "btfseed: reached %s over onion %s\n",
                     seeds[i].btfAddr, seeds[i].onion);
            if (++nConnected >= 4)
                return nConnected;  // enough; the rest comes from peer exchange
        }
    }

    // Extra seeds from the command line carry only an address, so resolve them
    // over Nostr (best effort -- depends on a working exit).
    foreach(const PAIRTYPE(string, string)& s, vBtfExtraSeeds)
    {
        if (fShutdown) return nConnected;
        if (ConnectNodeBtf(s.first))
        {
            LogPrint("net", "btfseed: reached %s\n", s.first.c_str());
            if (++nConnected >= 4)
                break;
        }
    }
    LogPrint("net", "btfseed: %d seed(s) answered\n", nConnected);
    return nConnected;
}

//
// The .btf connection scheduler.
//
// This used to run once at startup: try the cache, or the seeds if the cache
// was empty, and return. Two failures came out of that shape and both were seen
// on real hardware before they were read in the code.
//
// The first is that a fresh hidden service usually loses its opening dial --
// the service is not published yet and the circuits are cold -- so the one
// attempt the node ever made failed and it sat there with no peers, mining a
// chain nobody else saw, until somebody restarted it.
//
// The second is subtler. Peer exchange verifies a descriptor and hands it to
// RememberBtfPeer, which writes it to the on-disk cache. But the cache was read
// exactly once, at startup, so nothing learned while running was ever dialled;
// the only discovery that worked continuously was Nostr, over a Tor that
// frequently has no exit to reach the relays. A node could learn about a
// hundred peers and connect to none of them.
//
// So the cache is re-read every round, which is what puts peer exchange into
// the scheduler, and seeds are retried whenever the peer count is on the floor
// rather than only when the cache happens to be empty. Every candidate carries
// its own exponential backoff so a dead address costs one dial and then goes
// quiet, and a transient failure is retried instead of being final.
//

static const int   BTF_TARGET_PEERS    = 8;   // stop dialling once we hold this many
static const int   BTF_SEED_FLOOR      = 2;   // below this, seeds are fair game again
static const int   BTF_DIALS_PER_ROUND = 4;   // bounds a round against a big stale cache
static const int64 BTF_ROUND_SECONDS   = 20;
static const int64 BTF_BACKOFF_BASE    = 30;
static const int64 BTF_BACKOFF_MAX     = 15 * 60;

static CCriticalSection cs_btfDialSched;
static map<string, int64> g_btfNextDial;   // address -> earliest next attempt
static map<string, int>   g_btfDialFails;  // address -> consecutive failures

static int CountBtfPeersConnected()
{
    int n = 0;
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (!pnode->strBtfAddr.empty())
                n++;
    return n;
}

static bool BtfAlreadyConnected(const string& strBtfAddr)
{
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode->strBtfAddr == strBtfAddr)
                return true;
    return false;
}

static bool BtfDialDue(const string& strBtfAddr)
{
    CRITICAL_BLOCK(cs_btfDialSched)
    {
        map<string, int64>::iterator it = g_btfNextDial.find(strBtfAddr);
        if (it != g_btfNextDial.end() && GetTime() < it->second)
            return false;
    }
    return true;
}

static void BtfNoteDialResult(const string& strBtfAddr, bool fOk)
{
    CRITICAL_BLOCK(cs_btfDialSched)
    {
        if (fOk)
        {
            g_btfDialFails.erase(strBtfAddr);
            g_btfNextDial.erase(strBtfAddr);
            return;
        }
        int nFails = ++g_btfDialFails[strBtfAddr];
        // Doubling, capped. Jitter keeps a set of nodes that all lost the same
        // peer from coming back at it in lockstep afterwards.
        int64 nWait = BTF_BACKOFF_BASE << min(nFails - 1, 8);
        if (nWait > BTF_BACKOFF_MAX)
            nWait = BTF_BACKOFF_MAX;
        nWait += GetRand(nWait / 4 + 1);
        g_btfNextDial[strBtfAddr] = GetTime() + nWait;
    }
}

// One pass over the remembered peers. Returns how many answered.
static int DialRememberedBtfPeers(int nBudget)
{
    vector<CachedBtfPeer> peers;
    LoadCachedBtfPeers(peers);   // re-read every round: this is the PEX path
    if (peers.empty())
        return 0;

    int nConnected = 0, nTried = 0;
    foreach(const CachedBtfPeer& p, peers)
    {
        if (fShutdown || nTried >= nBudget)
            break;
        if (p.btfAddr == BtfLocalAddress())
            continue;                       // never dial ourselves
        if (BtfAlreadyConnected(p.btfAddr) || !BtfDialDue(p.btfAddr))
            continue;
        unsigned char enc[32];
        if (!HexToBytes(p.encHex, enc, 32))
            continue;
        nTried++;
        bool fOk = ConnectNodeBtfResolved(p.btfAddr, p.meeting, p.onion, enc) != NULL;
        BtfNoteDialResult(p.btfAddr, fOk);
        if (fOk)
            nConnected++;
    }
    if (nTried)
        LogPrint("net", "btfpeers: %d of %d remembered peer(s) answered this round\n",
                 nConnected, nTried);
    return nConnected;
}

void ThreadReconnectCachedBtfPeers(void* parg)
{
    LogPrint("net", "btfpeers: connection scheduler started\n");
    while (!fShutdown)
    {
        int nHave = CountBtfPeersConnected();
        if (nHave < BTF_TARGET_PEERS)
        {
            int nBudget = BTF_DIALS_PER_ROUND;
            nHave += DialRememberedBtfPeers(nBudget);

            // Seeds are not just a cold-start crutch. If the cache is empty, or
            // everything in it is gone, they are the only way back that does not
            // need a Nostr relay to answer.
            if (!fShutdown && nHave < BTF_SEED_FLOOR && BtfDialDue("__seeds__"))
            {
                int nSeeded = TryBtfSeeds();
                BtfNoteDialResult("__seeds__", nSeeded > 0);
                if (nSeeded == 0)
                    LogPrint("net", "btfpeers: no seed answered; will retry with backoff\n");
            }
        }

        for (int64 i = 0; i < BTF_ROUND_SECONDS && !fShutdown; i++)
            Sleep(1000);
    }
    LogPrint("net", "btfpeers: connection scheduler stopped\n");
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

// Does this endpoint plausibly belong to the network this node is on?
//
// Belt and braces beside the namespaced announcements: a node still running an
// older build will keep handing over whatever its cache holds, and the ports are
// the one thing already in the descriptor that says which network a peer meant.
// Mainnet's defaults sit in 8433..8443 (p2p, its pool port, the seed), testnet's
// in 18433..18443. Anything outside both bands is somebody's custom port and is
// left alone -- this rejects what is provably the other network, not everything
// unfamiliar.
static bool BtfEndpointFitsThisNetwork(const string& strOnion)
{
    string::size_type colon = strOnion.rfind(':');
    if (colon == string::npos)
        return true;                       // no port to judge
    int nPort = atoi(strOnion.substr(colon + 1).c_str());
    bool fMainnetBand = (nPort >= 8433 && nPort <= 8443);
    bool fTestnetBand = (nPort >= 18433 && nPort <= 18443);
    if (!fMainnetBand && !fTestnetBand)
        return true;                       // custom port, not ours to judge
    return IsTestNet() ? fTestnetBand : fMainnetBand;
}

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

    // Most recently seen first, and only peers this node actually reached.
    //
    // This used to forward the whole cache, including entries that were only
    // ever heard about. One node with a mixed cache then handed that mix to
    // everyone it met, and the mix spread faster than any of it could be
    // verified: a testnet node's cache filled with mainnet peers it could never
    // handshake, and the reverse. Gossiping only what answered keeps a node's
    // own experience as the thing it vouches for.
    foreach(const CachedBtfPeer& p, peers)
    {
        if (vDescOut.size() >= MAX_PEX_DESCRIPTORS) break;
        if (!p.fVerified) continue;                            // heard about, never reached
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

        if (!BtfEndpointFitsThisNetwork(d.onion))
        {
            LogPrint("net", "btfpeers: dropping %s at %s -- other network\n",
                     strAddr.c_str(), d.onion.c_str());
            continue;
        }

        RememberBtfPeer(strAddr, d.meeting_node, enc, strDesc, d.onion);
        nKept++;
    }
    return nKept;
}

static bool SplitHostPort(const string& strHostPort, string& strHost, unsigned short& nPort)
{
    size_t colon = strHostPort.rfind(':');
    if (colon == string::npos || colon == 0 || colon + 1 >= strHostPort.size())
        return false;
    string port = strHostPort.substr(colon + 1);
    for (size_t i = 0; i < port.size(); i++)
        if (!isdigit((unsigned char)port[i]))
            return false;

    errno = 0;
    char* end = NULL;
    long n = strtol(port.c_str(), &end, 10);
    if (errno == ERANGE || end == NULL || *end != '\0' || n <= 0 || n > 65535)
        return false;

    strHost = strHostPort.substr(0, colon);
    nPort = (unsigned short)n;
    return true;
}

static CNode* ConnectNodeBtfTail(const string& strBtfAddr, const unsigned char pk[32],
                                  const string& strMeeting, const string& strOnion,
                                  const unsigned char enc_pub[32],
                                  const string& strDesc = string())
{
    CAddress addr = BtfMarkerAddr(pk);
    CNode* pnode = FindNode(addr.ip);
    if (pnode)
    {
        pnode->AddRef();
        return pnode;
    }

    string strOnionNorm;
    if (BtfSocks5ProxyEnabled() && btf::NormalizeOnionEndpoint(strOnion, strOnionNorm))
    {
        string strOnionHost;
        unsigned short nOnionPort = 0;
        if (SplitHostPort(strOnionNorm, strOnionHost, nOnionPort))
        {
            BtfChurnNoteDialAttempt(strBtfAddr, strOnionNorm);
            SOCKET hOnionSocket = BtfConnectSocket(strOnionHost, nOnionPort, SOCK_ONION_PEER,
                                                   BTF_ONION_CONNECT_TIMEOUT_SECS);
            if (hOnionSocket != INVALID_SOCKET)
            {
                if (fDebug)
                    LogPrint("net", "connected %s via direct onion %s\n",
                             strBtfAddr.c_str(), strOnionNorm.c_str());
                BtfChurnNoteDialResult(strBtfAddr, strOnionNorm, true);
                RememberBtfPeer(strBtfAddr, strMeeting, enc_pub, strDesc, strOnionNorm, true);

                pnode = new CNode(hOnionSocket, addr, false);
                pnode->strBtfAddr = strBtfAddr;
                pnode->strBtfMeeting = string("onion ") + strOnionNorm;
                pnode->AddRef();
                CRITICAL_BLOCK(cs_vNodes)
                    vNodes.push_back(pnode);
                return pnode;
            }
            if (fDebug)
                LogPrint("net", "ConnectNodeBtf: direct onion to %s at %s failed\n",
                         strBtfAddr.c_str(), strOnionNorm.c_str());
            BtfChurnNoteDialResult(strBtfAddr, strOnionNorm, false);
        }
    }

    // Onion-only. Bitflash no longer dials a rendezvous meeting node: a peer we
    // cannot reach at its .onion is simply unreachable from here. Dropping the
    // relay dial is the whole point -- no VPS chokepoint, no relay code path.
    (void)enc_pub;
    return NULL;
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
    string strOnion;
    unsigned char enc_pub[32];
    BtfChurnNoteResolveAttempt();
    if (!BtfResolve(strBtfAddr, strMeeting, enc_pub, &strOnion))
    {
        BtfChurnNoteResolveResult(false);
        if (fDebug)
            LogPrint("net", "ConnectNodeBtf: could not resolve a descriptor for %s\n", strBtfAddr.c_str());
        return NULL;
    }
    BtfChurnNoteResolveResult(true);
    return ConnectNodeBtfTail(strBtfAddr, pk, strMeeting, strOnion, enc_pub);
}

// Same as ConnectNodeBtf, but skips the Nostr resolve step because the caller
// already resolved the descriptor (e.g. via BtfResolveMany, batching many
// addresses into one relay round-trip instead of one relay round-trip per
// address). Makes zero relay connections -- only talks to the peer's
// rendezvous meeting node.
CNode* ConnectNodeBtfResolved(const string& strBtfAddr, const string& strMeeting,
                              const string& strOnion, const unsigned char enc_pub[32],
                              const string& strDesc)
{
    unsigned char pk[32];
    if (!btf::ParseAddress(strBtfAddr, pk))
    {
        LogPrint("net", "ConnectNodeBtf: invalid address %s\n", strBtfAddr.c_str());
        return NULL;
    }
    if (BtfLocalAddress() == strBtfAddr)
        return NULL; // ourselves

    // The last place to catch a peer from the other network, and the one that
    // covers every way it got here: a cache written by an older build, a Nostr
    // descriptor published under the shared tag before the announcements were
    // namespaced, a peer exchange from a node still running 1.2.20. Dialling it
    // spends a Tor circuit and an outbound slot on a handshake the magic bytes
    // will reject, and the connection sits there at height -1 until it is
    // reaped.
    if (!strOnion.empty() && !BtfEndpointFitsThisNetwork(strOnion))
    {
        LogPrint("net", "ConnectNodeBtf: skipping %s at %s -- other network\n",
                 strBtfAddr.c_str(), strOnion.c_str());
        return NULL;
    }
    return ConnectNodeBtfTail(strBtfAddr, pk, strMeeting, strOnion, enc_pub, strDesc);
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

    // Invalidate before anything else can look at it. This used to close the
    // socket and leave the handle number sitting in the object, so ~CNode
    // closed it a second time and the socket loop kept arming it in the
    // meantime. See the note on ~CNode in net.h.
    BtfCloseSocket(hSocket);
    hSocket = INVALID_SOCKET;

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
                // Wait for the buffers to drain before letting a node go, so a
                // last message still gets out -- but not forever. vSend never
                // drains through a socket whose far end is gone, and a node
                // stuck that way stayed in vNodes for the life of the process,
                // holding its socket and counting as a peer.
                if (!pnode->ReadyToDisconnect())
                    pnode->nDisconnectSince = 0;
                else if (pnode->nDisconnectSince == 0)
                    pnode->nDisconnectSince = GetTime();

                bool fDrained = pnode->vRecv.empty() && pnode->vSend.empty();
                bool fStuck   = pnode->nDisconnectSince != 0 &&
                                GetTime() - pnode->nDisconnectSince > DISCONNECT_DRAIN_SECS;

                if (pnode->ReadyToDisconnect() && (fDrained || fStuck))
                {
                    if (!fDrained)
                        printf("dropping stuck node %s after %d s with %d bytes unsent\n",
                               pnode->addr.ToString().c_str(),
                               (int)(GetTime() - pnode->nDisconnectSince),
                               (int)pnode->vSend.size());
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
        static const int nPollTimeoutMs = 50; // frequency to poll pnode->vSend

        struct NodePollResult
        {
            CNode* pnode;
            SOCKET hSocket;
            bool fRecv;
            bool fSend;
            bool fInvalid;
            NodePollResult(CNode* pnodeIn, SOCKET hSocketIn)
                : pnode(pnodeIn), hSocket(hSocketIn), fRecv(false), fSend(false), fInvalid(false) {}
        };

        vector<BtfPollFd> vPoll;
        vector<NodePollResult> vPollNodes;

        BtfPollFd listenPoll;
        memset(&listenPoll, 0, sizeof(listenPoll));
        listenPoll.fd = hListenSocket;
        listenPoll.events = POLLIN;
        vPoll.push_back(listenPoll);

        CRITICAL_BLOCK(cs_vNodes)
        {
            foreach(CNode* pnode, vNodes)
            {
                // A disconnected node stays in vNodes until its references go.
                // Do not watch a closed handle number: the OS may already have
                // handed it to a different connection.
                if (pnode->hSocket == INVALID_SOCKET)
                    continue;

                BtfPollFd pfd;
                memset(&pfd, 0, sizeof(pfd));
                pfd.fd = pnode->hSocket;
                pfd.events = POLLIN;
                TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                    if (!pnode->vSend.empty())
                        pfd.events |= POLLOUT;
                vPoll.push_back(pfd);
                vPollNodes.push_back(NodePollResult(pnode, pnode->hSocket));
            }
            nPeersWatched = (int)vPollNodes.size();
        }

        // Say the state of the node out loud now and then, so a log pulled off
        // a machine three weeks later still answers "was it hearing anybody".
        {
            static int64 nLastReport = 0;
            // Wound forward on the first pass so the first report lands about a
            // minute in, once peers have had time to connect. A report written
            // at second zero says nothing, and waiting ten minutes for the
            // first one is ten minutes of a log that cannot answer anything.
            if (nLastReport == 0)
                nLastReport = GetTime() - 9 * 60;
            if (GetTime() - nLastReport > 10 * 60)
            {
                nLastReport = GetTime();
                printf("%s\n", GetDiagnosticsText().c_str());
            }
        }

        vfThreadRunning[0] = false;
        int nPoll = BtfPoll(&vPoll[0], (unsigned int)vPoll.size(), nPollTimeoutMs);
        vfThreadRunning[0] = true;
        CheckForShutdown(0);
        if (nPoll == SOCKET_ERROR)
        {
            int nErr = WSAGetLastError();
            LogPrint("net", "poll failed: %d\n", nErr);
            CRITICAL_BLOCK(cs_vNodes)
            {
                foreach(CNode* pnode, vNodes)
                {
                    if (pnode->hSocket == INVALID_SOCKET)
                        continue;
                    int nType = 0;
#ifdef _WIN32
                    int nTypeLen = sizeof(nType);
#else
                    socklen_t nTypeLen = sizeof(nType);
#endif
                    if (getsockopt(pnode->hSocket, SOL_SOCKET, SO_TYPE, (char*)&nType, &nTypeLen) != 0)
                    {
                        printf("dropping node %s: its socket is no longer valid\n",
                               pnode->addr.ToString().c_str());
                        pnode->fDisconnect = true;
                    }
                }
            }
            Sleep(nPollTimeoutMs);
        }
        else
        {
            for (size_t i = 0; i < vPollNodes.size(); i++)
            {
                short revents = vPoll[i + 1].revents; // poll[0] is the listener
                vPollNodes[i].fRecv = (revents & (POLLIN | POLLERR | POLLHUP)) != 0;
                vPollNodes[i].fSend = (revents & POLLOUT) != 0;
                vPollNodes[i].fInvalid = (revents & POLLNVAL) != 0;
            }
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
        if (nPoll != SOCKET_ERROR && (vPoll[0].revents & POLLIN))
        {
            struct sockaddr_in sockaddr;
#ifdef _WIN32
            int len = sizeof(sockaddr);
#else
            socklen_t len = sizeof(sockaddr);
#endif
            SOCKET hSocket = BtfSocketTag(accept(hListenSocket, (struct sockaddr*)&sockaddr, &len), SOCK_ACCEPT);
            CAddress addr(sockaddr);
            if (hSocket == INVALID_SOCKET)
            {
                if (WSAGetLastError() != WSAEWOULDBLOCK)
                    printf("ERROR ThreadSocketHandler accept failed: %d\n", WSAGetLastError());
            }
            else
            {
                // Refuse rather than accept a connection this node cannot
                // watch. Without this the listen socket kept taking peers --
                // it is always watched -- while everything past the
                // limit sat open and unread, which fed on itself: the deafer
                // the node got, the more connections it collected.
                unsigned int nNodes = 0;
                CRITICAL_BLOCK(cs_vNodes)
                    nNodes = (unsigned int)vNodes.size();
                // Also count how many connections this one address already
                // holds. A single IP that keeps opening sockets -- a broken
                // node or a deliberate connection-exhaustion flood -- must not
                // be able to take the whole table, which is what starved the
                // relays.
                //
                // Loopback is exempt. Onion peers reach a managed-Tor node
                // through its local hidden-service listener, so every one of
                // them accepts as 127.0.0.1; capping loopback would cap all
                // inbound onion peers as a single group, which is the opposite
                // of where the network is headed. The global MAX_CONNECTIONS
                // still bounds the total, and the direct-IP flood this defends
                // against never arrives over loopback. (Per-onion-identity
                // limiting, once a peer's identity is known past accept(), is
                // the right tool for onion and is left for later.)
                bool fLoopback = (addr.GetByte(3) == 127);
                unsigned int nFromThisIP = 0;
                if (!fLoopback)
                    CRITICAL_BLOCK(cs_vNodes)
                        for (vector<CNode*>::iterator it = vNodes.begin(); it != vNodes.end(); ++it)
                            if ((*it)->addr.ip == addr.ip)
                                nFromThisIP++;

                if (nNodes >= MAX_CONNECTIONS)
                {
                    LogPrint("net", "refusing connection from %s, already at %u\n",
                             addr.ToString().c_str(), nNodes);
                    BtfCloseSocket(hSocket);
                }
                else if (!fLoopback && nFromThisIP >= MAX_CONNECTIONS_PER_IP)
                {
                    LogPrint("net", "refusing connection from %s, already %u from that address\n",
                             addr.ToString().c_str(), nFromThisIP);
                    BtfCloseSocket(hSocket);
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
        }


        //
        // Service each socket
        //
        for (size_t i = 0; i < vPollNodes.size(); i++)
        {
            CheckForShutdown(0);
            NodePollResult& poll = vPollNodes[i];
            CNode* pnode = poll.pnode;
            SOCKET hSocket = poll.hSocket;

            if (hSocket == INVALID_SOCKET || pnode->hSocket != hSocket)
                continue;

            if (poll.fInvalid)
            {
                LogPrint("net", "poll reported invalid socket for %s\n",
                         pnode->addr.ToString().c_str());
                pnode->fDisconnect = true;
                continue;
            }

            //
            // Receive
            //
            if (poll.fRecv)
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
            if (poll.fSend)
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
                    if (!pnode->strBtfMeeting.empty())
                        BtfChurnNoteHandshakeTimeout(pnode->strBtfAddr, pnode->strBtfMeeting,
                                                     pnode->nLastRecv != 0, pnode->nLastSend != 0);
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

int GetPeerMedianHeight()
{
    vector<int> vHeights;
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode->nStartingHeight >= 0)
                vHeights.push_back(pnode->nStartingHeight);

    if (vHeights.empty())
        return -1;

    sort(vHeights.begin(), vHeights.end());
    return vHeights[vHeights.size() / 2];
}


// Say out loud when we are behind the network.
//
// This is the whole reason the height is in the handshake. Every serious bug
// this node has had looked identical from the outside: running, threads alive,
// nothing in the log, and no blocks arriving. A node that knows where everyone
// else is can say so, and "8 blocks behind for 27 minutes" is a sentence a
// user can act on. Deliberately not behind a debug category -- an operator who
// already suspects trouble is not the one who needs telling.
static void WarnIfBehind()
{
    static int64 nLastWarned;
    static int64 nBehindSince;

    int nPeers = GetPeerMedianHeight();
    if (nPeers < 0 || nBestHeight < 0)
        return;

    // One block of slack: somebody is always mid-relay.
    if (nBestHeight >= nPeers - 1)
    {
        nBehindSince = 0;
        return;
    }

    int64 nNow = GetTime();
    if (nBehindSince == 0)
    {
        nBehindSince = nNow;
        return;
    }

    // Falling briefly behind is ordinary. Staying behind is not.
    if (nNow - nBehindSince < BTF_BEHIND_GRACE_SECS)
        return;
    if (nNow - nLastWarned < BTF_BEHIND_WARN_INTERVAL_SECS)
        return;

    nLastWarned = nNow;
    printf("WARNING: %d blocks behind the network (height %d, peers report %d) for %d minutes\n",
           nPeers - nBestHeight, nBestHeight, nPeers, (int)((nNow - nBehindSince) / 60));
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

        WarnIfBehind();

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

static int MinersRunningCount()
{
    int n = 0;
    CRITICAL_BLOCK(cs_nMinersRunning)
        n = nMinersRunning;
    return n;
}

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
    nNodeStartTime = GetTime();

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
    SOCKET hListenSocket = BtfSocketTag(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), SOCK_LISTEN);
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
    // Where to listen. Managed Tor forwards hidden-service traffic to
    // 127.0.0.1:<port>, so loopback is all an onion-only node ever needs -- and
    // binding wider than that is not merely untidy, it deanonymises the node.
    // Anything that can reach the plain TCP port completes the same handshake a
    // Tor peer does, and peer exchange then hands it this node's signed
    // descriptor, onion included. Whoever dialled the IP now knows which onion
    // it is. So under managed Tor the listener stays on loopback.
    //
    // Tor running on another machine still needs a reachable bind, so -bindaddr
    // takes an explicit address for that case. It has to be asked for by name:
    // the wide bind is exactly the mistake, and it should not be the default
    // anyone gets without choosing it.
    string strBindAddr = BtfListenBindAddress();
    if (!strBindAddr.empty())
    {
        unsigned long nAddr = inet_addr(strBindAddr.c_str());
        if (nAddr == INADDR_NONE)
        {
            strError = strprintf("Error: -bindaddr=%s is not a usable IPv4 address", strBindAddr.c_str());
            printf("%s\n", strError.c_str());
            return false;
        }
        sockaddr.sin_addr.s_addr = nAddr;
        printf("Listening on %s as requested by -bindaddr\n", strBindAddr.c_str());
    }
    else if (BtfManagedTorEnabled())
    {
        sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        printf("Onion-only: P2P listener bound to 127.0.0.1; reachable through the hidden service\n");
    }
    else
    {
        sockaddr.sin_addr.s_addr = INADDR_ANY;
    }
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

    // Anonymous inbound is the Tor hidden service now, not a rendezvous relay:
    // Tor forwards onion connections to our local listener, which accepts them
    // like any other inbound peer. No ThreadBtfAccept, no registration at a
    // meeting relay, no VPS in the path.

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
