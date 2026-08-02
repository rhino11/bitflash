// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

class CMessageHeader;
class CAddress;
class CInv;
class CRequestTracker;
class CNode;
// Defined in main.h, which is included after this file. Only ever used here as
// a pointer, so the forward declaration is enough.
class CBlockIndex;



static const unsigned short DEFAULT_PORT = htons(8433);
static const unsigned int PUBLISH_HOPS = 5;
enum
{
    NODE_NETWORK = (1 << 0),
};






bool GetMyExternalIP(unsigned int& ipRet);
CNode* ConnectNodeBtf(const string& strBtfAddr);
CNode* ConnectNodeBtfResolved(const string& strBtfAddr, const string& strMeeting,
                              const unsigned char enc_pub[32]);
void ThreadBtfAccept(void* parg);
void ThreadBtfConnect(void* parg);
extern string strBtfConnect;
// Bootstrap seeds added at runtime with /btfseed=ADDRESS:ENCHEX (repeatable).
// The compiled-in list lives in net.cpp; these are appended to it.
extern std::vector<std::pair<std::string, std::string> > vBtfExtraSeeds;

// --- .btf peer exchange ---------------------------------------------------
// Peers gossip signed descriptors so discovery survives a relay outage. Both
// caps apply to a single "btfpeers" message; the generic header limit is 256 MB,
// which is no protection at all for something a stranger can send unprompted.
static const unsigned int MAX_PEX_DESCRIPTORS      = 20;
static const unsigned int MAX_PEX_DESCRIPTOR_BYTES = 1024;
// Ignore a peer's exchange more often than this. One announcement per side per
// connection is the intended traffic; anything faster is someone else's idea.
static const int64        PEX_MIN_INTERVAL         = 60;

// How long to sit registered at a rendezvous relay before giving up on this
// attempt and registering again. Bounded because a registration socket that
// goes quiet is indistinguishable, from inside recv(), from one whose path has
// died -- and the second kind never wakes up. Five minutes is short enough
// that a node is unreachable only briefly and long enough that the reconnect
// traffic is nothing: one per relay per five minutes.
static const int          BTF_RENDEZVOUS_WAIT_SECS = 300;

// Registrations this node parks at a rendezvous at once.
//
// Back to one, and it stays at one until every relay in vBtfMeetingRelays runs
// the queue from #113. More than one is what keeps a node reachable while one
// registration is being paired -- but only against a relay that accepts more
// than one. An older relay closes the previous registration whenever the same
// node registers again, so several accept threads pointed at one of those
// evict each other in a loop: thread 2 registers and kills thread 1, thread 3
// kills thread 2, thread 1 sees its socket die and kills thread 3.
//
// #113 called that harmless. It is not. Measured on a node running three
// threads against the un-upgraded New Jersey relay: 189 registrations in about
// fifteen minutes -- roughly twelve a minute -- and not one pairing. The node
// was not merely failing to benefit, it was unreachable through that relay and
// hammering it. A node with one thread does none of this.
//
// The bench that approved #113 could not see it: its harness re-registers by
// design, which is exactly what hides an eviction loop.
//
// Raise this to 3 only when the other two relays are upgraded.
static const int          BTF_ACCEPT_THREADS       = 1;

// Liveness of an established peer connection. BTF_RENDEZVOUS_WAIT_SECS bounds
// the wait for a dial to arrive; these bound the connection that comes out of
// it, which has the same failure mode once it goes quiet.
//
// A healthy peer relays a block inventory roughly every nTargetSpacing (two
// minutes), so silence measured in block intervals is the honest signal.
// Bitcoin used ninety minutes against ten-minute blocks -- nine intervals --
// and the same nine intervals here is eighteen minutes; thirty leaves margin
// for a slow stretch without letting a dead path last an hour.
static const int          BTF_RECV_TIMEOUT_SECS    = 30 * 60;
static const int          BTF_SEND_STALL_SECS      = 10 * 60;
static const int          BTF_HANDSHAKE_GRACE_SECS = 60;

// A serialized object cannot be larger than MAX_SIZE, so no valid network
// message needs the old 256 MB header allowance. Keep the wire cap aligned with
// what the deserializer can accept and bound how long one peer may sit on a
// partial payload after a complete header has arrived.
static const unsigned int MAX_PROTOCOL_MESSAGE_SIZE = MAX_SIZE;
static const int          BTF_INCOMPLETE_MESSAGE_TIMEOUT_SECS = 2 * 60;

// Ceiling on simultaneous connections.
//
// ThreadSocketHandler watches every peer through one select(), and select()
// cannot watch more descriptors than FD_SETSIZE. On Windows FD_SET simply
// stops adding once the set is full -- no error, no log -- so every socket
// past the limit stays open and is never read again. Nothing capped vNodes,
// so a node accepted connections it had no way to service, and because new
// entries go on the end of vNodes it was always the newest connection that
// starved, including the ones dialed to fix connectivity.
//
// Measured on two nodes before this ceiling existed: 277 and 90 CNode objects
// against 93 and 90 live sockets, and a status bar reporting hundreds of
// peers for a node that was really talking to thirty.
//
// 125 is Bitcoin's number and sits far below FD_SETSIZE on both platforms.
static const unsigned int MAX_CONNECTIONS = 125;

// A node marked for disconnect is normally held until its buffers drain, so
// a last message still goes out. But vSend cannot drain through a socket
// whose far end is gone, and that made such a node immortal: it stayed in
// vNodes, kept its socket open, and kept being counted. Force it out after
// this long regardless of what is still buffered.
static const int64        DISCONNECT_DRAIN_SECS    = 60;

// Send a ping after this long with nothing to say, so a peer running the
// inactivity check above does not mistake a quiet node for a dead one. Must
// stay well under BTF_RECV_TIMEOUT_SECS.
static const int          BTF_PING_INTERVAL_SECS   = 10 * 60;

// How long a node must stay behind the network before it says so, and how
// often it repeats itself. Five minutes is two and a half block intervals --
// long enough that ordinary relay lag never trips it.
static const int          BTF_BEHIND_GRACE_SECS         = 5 * 60;
static const int          BTF_BEHIND_WARN_INTERVAL_SECS = 5 * 60;

// --- Self-diagnosis -------------------------------------------------------
//
// A node that has stopped working looks exactly like a node with nothing to
// do. That has cost this project real time more than once: a node deaf to
// most of its peers, a miner allocating one RandomX dataset per thread, a
// third of arriving blocks missing their parent -- each was found from
// outside, by reading the process's sockets or its memory from another
// machine, because the node itself had no way to say so.
//
// These counters exist so it can. Cheap to keep, and they name the failures
// that actually happened rather than the ones that sound impressive.
extern int   nPeersWatched;        // peers in the last select() set
extern int64 nBlocksReceived;      // blocks handed to ProcessBlock
extern int64 nBlocksWithoutParent; // ...of those, how many arrived orphaned

// One report, rendered the same way for the GUI panel and the log, so what a
// user pastes into an issue is what a developer already knows how to read.
string GetDiagnosticsText();

#include "sockcount.h"

// Defined in main.cpp. Declared here because CNode announces it in the version
// message, and net.h is included before main.h.
extern int nBestHeight;

// Median height announced by the peers we are connected to, or -1 while nobody
// has told us anything. Median rather than maximum so one peer claiming an
// absurd height cannot move it.
int GetPeerMedianHeight();

// Lightweight .btf churn accounting. These counters are diagnostics only: they
// let an operator tell stale descriptors, relay pairing failures, and paired
// tunnels that never speak apart before changing behaviour.
void BtfChurnNoteResolveAttempt();
void BtfChurnNoteResolveResult(bool fOk);
void BtfChurnNoteDialAttempt(const string& strBtfAddr, const string& strMeeting);
void BtfChurnNoteDialResult(const string& strBtfAddr, const string& strMeeting, bool fOk);
void BtfChurnNoteRegisterResult(const string& strMeeting, bool fOk);
void BtfChurnNotePairResult(const string& strMeeting, bool fOk);
void BtfChurnNoteHandshakeTimeout(const string& strBtfAddr, const string& strMeeting,
                                  bool fRecv, bool fSend);

// Descriptors to hand a peer: ours first, then peers that answered us.
void BtfPexCollect(std::vector<std::string>& vDescOut);
// Verify descriptors a peer sent and remember the good ones. Returns how many.
int  BtfPexAccept(const std::vector<std::string>& vDesc);
void AbandonRequests(void (*fn)(void*, CDataStream&), void* param1);
bool AnySubscribed(unsigned int nChannel);
void ThreadBitcoinMiner(void* parg);
// Starts MinerThreadCount() miners; returns how many came up.
int  StartMinerThreads();
bool StartNode(string& strError=REF(string()));
bool StopNode();
void CheckForShutdown(int n);









//
// Message header
//  (4) message start
//  (12) command
//  (4) size

// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ascii, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
// Magic bytes unique to the Bitflash network (0xbf = "BF"). Second byte bumped
// to 0x20 for the 2026 stable relaunch so the old test chain can't interfere.
static const char pchMessageStart[4] = { 0xbf, 0x20, 0x5c, 0xfd };

class CMessageHeader
{
public:
    enum { COMMAND_SIZE=12 };
    char pchMessageStart[sizeof(::pchMessageStart)];
    char pchCommand[COMMAND_SIZE];
    unsigned int nMessageSize;

    CMessageHeader()
    {
        memcpy(pchMessageStart, ::pchMessageStart, sizeof(pchMessageStart));
        memset(pchCommand, 0, sizeof(pchCommand));
        pchCommand[1] = 1;
        nMessageSize = -1;
    }

    CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn)
    {
        memcpy(pchMessageStart, ::pchMessageStart, sizeof(pchMessageStart));
        strncpy(pchCommand, pszCommand, COMMAND_SIZE);
        nMessageSize = nMessageSizeIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(FLATDATA(pchMessageStart));
        READWRITE(FLATDATA(pchCommand));
        READWRITE(nMessageSize);
    )

    string GetCommand()
    {
        if (pchCommand[COMMAND_SIZE-1] == 0)
            return string(pchCommand, pchCommand + strlen(pchCommand));
        else
            return string(pchCommand, pchCommand + COMMAND_SIZE);
    }

    bool IsValid()
    {
        // Check start string
        if (memcmp(pchMessageStart, ::pchMessageStart, sizeof(pchMessageStart)) != 0)
            return false;

        // Check the command string for errors
        for (char* p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++)
        {
            if (*p1 == 0)
            {
                // Must be all zeros after the first zero
                for (; p1 < pchCommand + COMMAND_SIZE; p1++)
                    if (*p1 != 0)
                        return false;
            }
            else if (*p1 < ' ' || *p1 > 0x7E)
                return false;
        }

        // Message size
        if (nMessageSize > MAX_PROTOCOL_MESSAGE_SIZE)
        {
            if (LogAcceptsCategory("net")) printf("CMessageHeader::IsValid() : nMessageSize too large %u\n", nMessageSize);
            return false;
        }

        return true;
    }
};






static const unsigned char pchIPv4[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

class CAddress
{
public:
    uint64 nServices;
    unsigned char pchReserved[12];
    unsigned int ip;
    unsigned short port;

    // disk only
    unsigned int nTime;

    // memory only
    unsigned int nLastFailed;

    CAddress()
    {
        nServices = 0;
        memcpy(pchReserved, pchIPv4, sizeof(pchReserved));
        ip = 0;
        port = DEFAULT_PORT;
        nTime = GetAdjustedTime();
        nLastFailed = 0;
    }

    CAddress(unsigned int ipIn, unsigned short portIn, uint64 nServicesIn=0)
    {
        nServices = nServicesIn;
        memcpy(pchReserved, pchIPv4, sizeof(pchReserved));
        ip = ipIn;
        port = portIn;
        nTime = GetAdjustedTime();
        nLastFailed = 0;
    }

    explicit CAddress(const struct sockaddr_in& sockaddr, uint64 nServicesIn=0)
    {
        nServices = nServicesIn;
        memcpy(pchReserved, pchIPv4, sizeof(pchReserved));
        ip = sockaddr.sin_addr.s_addr;
        port = sockaddr.sin_port;
        nTime = GetAdjustedTime();
        nLastFailed = 0;
    }

    explicit CAddress(const char* pszIn, uint64 nServicesIn=0)
    {
        nServices = nServicesIn;
        memcpy(pchReserved, pchIPv4, sizeof(pchReserved));
        ip = 0;
        port = DEFAULT_PORT;
        nTime = GetAdjustedTime();
        nLastFailed = 0;

        char psz[100];
        if (strlen(pszIn) > ARRAYLEN(psz)-1)
            return;
        strcpy(psz, pszIn);
        unsigned int a, b, c, d, e;
        if (sscanf(psz, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &e) < 4)
            return;
        char* pszPort = strchr(psz, ':');
        if (pszPort)
        {
            *pszPort++ = '\0';
            port = htons(atoi(pszPort));
        }
        ip = inet_addr(psz);
    }

    IMPLEMENT_SERIALIZE
    (
        if (nType & SER_DISK)
        {
            READWRITE(nVersion);
            READWRITE(nTime);
        }
        READWRITE(nServices);
        READWRITE(FLATDATA(pchReserved));
        READWRITE(ip);
        READWRITE(port);
    )

    friend inline bool operator==(const CAddress& a, const CAddress& b)
    {
        return (memcmp(a.pchReserved, b.pchReserved, sizeof(a.pchReserved)) == 0 &&
                a.ip   == b.ip &&
                a.port == b.port);
    }

    friend inline bool operator<(const CAddress& a, const CAddress& b)
    {
        int ret = memcmp(a.pchReserved, b.pchReserved, sizeof(a.pchReserved));
        if (ret < 0)
            return true;
        else if (ret == 0)
        {
            if (ntohl(a.ip) < ntohl(b.ip))
                return true;
            else if (a.ip == b.ip)
                return ntohs(a.port) < ntohs(b.port);
        }
        return false;
    }

    vector<unsigned char> GetKey() const
    {
        CDataStream ss;
        ss.reserve(18);
        ss << FLATDATA(pchReserved) << ip << port;

        #if defined(_MSC_VER) && _MSC_VER < 1300
        return vector<unsigned char>((unsigned char*)&ss.begin()[0], (unsigned char*)&ss.end()[0]);
        #else
        return vector<unsigned char>(ss.begin(), ss.end());
        #endif
    }

    struct sockaddr_in GetSockAddr() const
    {
        struct sockaddr_in sockaddr;
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_addr.s_addr = ip;
        sockaddr.sin_port = port;
        return sockaddr;
    }

    bool IsIPv4() const
    {
        return (memcmp(pchReserved, pchIPv4, sizeof(pchIPv4)) == 0);
    }

    bool IsRoutable() const
    {
        return !(GetByte(3) == 10 || (GetByte(3) == 192 && GetByte(2) == 168));
    }

    unsigned char GetByte(int n) const
    {
        return ((unsigned char*)&ip)[3-n];
    }

    string ToStringIPPort() const
    {
        return strprintf("%u.%u.%u.%u:%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0), ntohs(port));
    }

    string ToStringIP() const
    {
        return strprintf("%u.%u.%u.%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0));
    }

    string ToString() const
    {
        return strprintf("%u.%u.%u.%u:%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0), ntohs(port));
        //return strprintf("%u.%u.%u.%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0));
    }

    void print() const
    {
        if (LogAcceptsCategory("net")) printf("CAddress(%s)\n", ToString().c_str());
    }
};







enum
{
    MSG_TX = 1,
    MSG_BLOCK,
    MSG_REVIEW,
    MSG_PRODUCT,
    MSG_TABLE,
};

static const char* ppszTypeName[] =
{
    "ERROR",
    "tx",
    "block",
    "review",
    "product",
    "table",
};

class CInv
{
public:
    int type;
    uint256 hash;

    CInv()
    {
        type = 0;
        hash = 0;
    }

    CInv(int typeIn, const uint256& hashIn)
    {
        type = typeIn;
        hash = hashIn;
    }

    CInv(const string& strType, const uint256& hashIn)
    {
        int i;
        for (i = 1; i < ARRAYLEN(ppszTypeName); i++)
        {
            if (strType == ppszTypeName[i])
            {
                type = i;
                break;
            }
        }
        if (i == ARRAYLEN(ppszTypeName))
            throw std::out_of_range(strprintf("CInv::CInv(string, uint256) : unknown type '%s'", strType.c_str()));
        hash = hashIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(type);
        READWRITE(hash);
    )

    friend inline bool operator<(const CInv& a, const CInv& b)
    {
        return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
    }

    bool IsKnownType() const
    {
        return (type >= 1 && type < ARRAYLEN(ppszTypeName));
    }

    const char* GetCommand() const
    {
        if (!IsKnownType())
            // Was "type=% unknown type": the % swallowed the space as a flag and
            // the u as the conversion, so this read "type= 3nknown type".
            throw std::out_of_range(strprintf("CInv::GetCommand() : type=%d unknown type", type));
        return ppszTypeName[type];
    }

    string ToString() const
    {
        return strprintf("%s %s", GetCommand(), hash.ToString().substr(0,14).c_str());
    }

    void print() const
    {
        if (LogAcceptsCategory("net")) printf("CInv(%s)\n", ToString().c_str());
    }
};





class CRequestTracker
{
public:
    void (*fn)(void*, CDataStream&);
    void* param1;

    explicit CRequestTracker(void (*fnIn)(void*, CDataStream&)=NULL, void* param1In=NULL)
    {
        fn = fnIn;
        param1 = param1In;
    }

    bool IsNull()
    {
        return fn == NULL;
    }
};





extern bool fClient;
extern uint64 nLocalServices;
extern CAddress addrLocalHost;
extern unsigned short nListenPort;
extern CNode* pnodeLocalHost;
extern bool fShutdown;
extern array<bool, 10> vfThreadRunning;
extern vector<CNode*> vNodes;
extern CCriticalSection cs_vNodes;
extern map<CInv, CDataStream> mapRelay;
extern deque<pair<int64, CInv> > vRelayExpiration;
extern CCriticalSection cs_mapRelay;
extern map<CInv, int64> mapAlreadyAskedFor;





class CNode
{
public:
    // socket
    uint64 nServices;
    SOCKET hSocket;
    CDataStream vSend;
    CDataStream vRecv;
    CCriticalSection cs_vSend;
    CCriticalSection cs_vRecv;
    unsigned int nPushPos;
    CAddress addr;
    int nVersion;
    bool fClient;
    bool fInbound;
    bool fNetworkNode;
    bool fDisconnect;
protected:
    int nRefCount;
public:
    int64 nReleaseTime;
    int64 nDisconnectSince;
    map<uint256, CRequestTracker> mapRequests;
    CCriticalSection cs_mapRequests;

    // inventory based relay
    set<CInv> setInventoryKnown;
    set<CInv> setInventoryKnown2;
    vector<CInv> vInventoryToSend;
    CCriticalSection cs_inventory;
    multimap<int64, CInv> mapAskFor;

    // publish and subscription
    vector<char> vfSubscribe;

    // Last "btfpeers" we accepted from this node, to rate-limit the exchange.
    int64 nLastPexRecv;

    // Last getblocks we sent this peer, so we do not ask the same question
    // over and over. See CNode::PushGetBlocks.
    CBlockIndex* pindexLastGetBlocksBegin;
    uint256      hashLastGetBlocksEnd;

    // Liveness. A peer whose network path dies silently -- NAT drops an idle
    // mapping, a relay restarts, a route changes -- never sends FIN, so the
    // socket stays readable-never and the node simply stops hearing from it
    // with no error anywhere. These stamps are the only way to tell that
    // apart from a peer that merely has nothing to say.
    int64 nTimeConnected;
    int64 nLastSend;
    int64 nLastRecv;
    int64 nLastSendEmpty;
    int64 nIncompleteMessageStart;
    unsigned int nIncompleteMessageSize;
    string strIncompleteMessageCommand;
    string strBtfAddr;
    string strBtfMeeting;

    // Height this peer announced in its version message, or -1 if it sent a
    // version message that predates the field. Knowing how far along everyone
    // else is, is the only way a node can tell "in sync" from "not hearing".
    int nStartingHeight;


    CNode(SOCKET hSocketIn, CAddress addrIn, bool fInboundIn=false)
    {
        nServices = 0;
        hSocket = hSocketIn;
        vSend.SetType(SER_NETWORK);
        vRecv.SetType(SER_NETWORK);
        nPushPos = -1;
        addr = addrIn;
        nVersion = 0;
        fClient = false; // set by version message
        fInbound = fInboundIn;
        fNetworkNode = false;
        fDisconnect = false;
        nRefCount = 0;
        nReleaseTime = 0;
        nDisconnectSince = 0;
        nLastPexRecv = 0;
        pindexLastGetBlocksBegin = NULL;
        hashLastGetBlocksEnd = 0;
        nTimeConnected = GetTime();
        nLastSend = 0;
        nLastRecv = 0;
        nLastSendEmpty = GetTime();
        nIncompleteMessageStart = 0;
        nIncompleteMessageSize = 0;
        strIncompleteMessageCommand.clear();
        strBtfAddr.clear();
        strBtfMeeting.clear();
        nStartingHeight = -1;
        vfSubscribe.assign(256, false);

        // Push a version message
        /// when NTP implemented, change to just nTime = GetAdjustedTime()
        int64 nTime = (fInbound ? GetAdjustedTime() : GetTime());
        // nBestHeight goes last so a node that predates it stops reading after
        // addr and treats the rest as trailing bytes, which cost it a log line
        // and nothing else.
        PushMessage("version", VERSION, nLocalServices, nTime, addr, nBestHeight);
    }

    // Disconnect() closes the socket and sets this to INVALID_SOCKET, so by the
    // time a node is deleted there is normally nothing left to do here. It used
    // not to: Disconnect() closed the handle and left the number in place, and
    // this destructor closed that same number a second time -- with a raw
    // closesocket() that the socket accounting never saw, so neither the double
    // close nor the stale claim showed up in any report.
    //
    // A double close is not a harmless no-op. Between the two, the operating
    // system is free to hand that number to a new socket -- this node opens
    // hundreds a minute -- and the second close then takes down a connection
    // that belongs to somebody else, which the log can only report as a peer
    // vanishing for no reason. `dropping node: its socket is no longer valid`
    // is what that looks like from the outside.
    ~CNode()
    {
        if (hSocket != INVALID_SOCKET)
        {
            BtfCloseSocket(hSocket);
            hSocket = INVALID_SOCKET;
        }
    }

private:
    CNode(const CNode&);
    void operator=(const CNode&);
public:


    bool ReadyToDisconnect()
    {
        return fDisconnect || GetRefCount() <= 0;
    }

    int GetRefCount()
    {
        return max(nRefCount, 0) + (GetTime() < nReleaseTime ? 1 : 0);
    }

    void AddRef(int64 nTimeout=0)
    {
        if (nTimeout != 0)
            nReleaseTime = max(nReleaseTime, GetTime() + nTimeout);
        else
            nRefCount++;
    }

    void Release()
    {
        nRefCount--;
    }



    void AddInventoryKnown(const CInv& inv)
    {
        CRITICAL_BLOCK(cs_inventory)
            setInventoryKnown.insert(inv);
    }

    void PushInventory(const CInv& inv)
    {
        CRITICAL_BLOCK(cs_inventory)
            if (!setInventoryKnown.count(inv))
                vInventoryToSend.push_back(inv);
    }

    void AskFor(const CInv& inv)
    {
        // We're using mapAskFor as a priority queue,
        // the key is the earliest time the request can be sent
        int64& nRequestTime = mapAlreadyAskedFor[inv];
        if (LogAcceptsCategory("net")) printf("askfor %s  %lld\n", inv.ToString().c_str(), nRequestTime);

        // Make sure not to reuse time indexes to keep things in the same order
        int64 nNow = (GetTime() - 1) * 1000000;
        static int64 nLastTime;
        nLastTime = nNow = max(nNow, ++nLastTime);

        // Each retry is 2 minutes after the last
        nRequestTime = max(nRequestTime + 2 * 60 * 1000000, nNow);
        mapAskFor.insert(make_pair(nRequestTime, inv));
    }



    void BeginMessage(const char* pszCommand)
    {
        EnterCriticalSection(&cs_vSend);
        if (nPushPos != -1)
            AbortMessage();
        nPushPos = vSend.size();
        vSend << CMessageHeader(pszCommand, 0);
        if (LogAcceptsCategory("net")) printf("sending: %-12s ", pszCommand);
    }

    void AbortMessage()
    {
        if (nPushPos == -1)
            return;
        vSend.resize(nPushPos);
        nPushPos = -1;
        LeaveCriticalSection(&cs_vSend);
        if (LogAcceptsCategory("net")) printf("(aborted)\n");
    }

    void EndMessage()
    {
        extern int nDropMessagesTest;
        if (nDropMessagesTest > 0 && GetRand(nDropMessagesTest) == 0)
        {
            if (LogAcceptsCategory("net")) printf("dropmessages DROPPING SEND MESSAGE\n");
            AbortMessage();
            return;
        }

        if (nPushPos == -1)
            return;

        // Patch in the size
        unsigned int nSize = vSend.size() - nPushPos - sizeof(CMessageHeader);
        memcpy((char*)&vSend[nPushPos] + offsetof(CMessageHeader, nMessageSize), &nSize, sizeof(nSize));

        if (LogAcceptsCategory("net")) printf("(%d bytes)  ", nSize);
        //for (int i = nPushPos+sizeof(CMessageHeader); i < min(vSend.size(), nPushPos+sizeof(CMessageHeader)+20U); i++)
        //    printf("%02x ", vSend[i] & 0xff);
        if (LogAcceptsCategory("net")) printf("\n");

        nPushPos = -1;
        LeaveCriticalSection(&cs_vSend);
    }

    void EndMessageAbortIfEmpty()
    {
        if (nPushPos == -1)
            return;
        int nSize = vSend.size() - nPushPos - sizeof(CMessageHeader);
        if (nSize > 0)
            EndMessage();
        else
            AbortMessage();
    }

    const char* GetMessageCommand() const
    {
        if (nPushPos == -1)
            return "";
        return &vSend[nPushPos] + offsetof(CMessageHeader, pchCommand);
    }




    // Ask this peer to fill in blocks we are missing, but only once per
    // question.
    //
    // Every orphan block fires one of these, and an inv for a block we already
    // hold as an orphan fires another. A node that is missing part of the
    // chain therefore asks the same peer the same thing repeatedly: measured
    // on a production node, 1287 orphan blocks out of 4117 processed, and 97
    // "already have block" from the answers coming back more than once. The
    // duplicate answers create more orphans, which fire more requests.
    //
    // Remembering the last question asked breaks that loop. Same fix Bitcoin
    // made in e2c2648c1.
    // Body lives in net.cpp: it builds a CBlockLocator, which main.h defines,
    // and main.h is included after this file.
    void PushGetBlocks(CBlockIndex* pindexBegin, uint256 hashEnd);

    void PushMessage(const char* pszCommand)
    {
        try
        {
            BeginMessage(pszCommand);
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1>
    void PushMessage(const char* pszCommand, const T1& a1)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4 << a5;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }


    void PushRequest(const char* pszCommand,
                     void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        CRITICAL_BLOCK(cs_mapRequests)
            mapRequests[hashReply] = CRequestTracker(fn, param1);

        PushMessage(pszCommand, hashReply);
    }

    template<typename T1>
    void PushRequest(const char* pszCommand, const T1& a1,
                     void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        CRITICAL_BLOCK(cs_mapRequests)
            mapRequests[hashReply] = CRequestTracker(fn, param1);

        PushMessage(pszCommand, hashReply, a1);
    }

    template<typename T1, typename T2>
    void PushRequest(const char* pszCommand, const T1& a1, const T2& a2,
                     void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        CRITICAL_BLOCK(cs_mapRequests)
            mapRequests[hashReply] = CRequestTracker(fn, param1);

        PushMessage(pszCommand, hashReply, a1, a2);
    }



    bool IsSubscribed(unsigned int nChannel);
    void Subscribe(unsigned int nChannel, unsigned int nHops=0);
    void CancelSubscribe(unsigned int nChannel);
    void Disconnect();
};










inline void RelayInventory(const CInv& inv)
{
    // Put on lists to offer to the other nodes
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            pnode->PushInventory(inv);
}

template<typename T>
void RelayMessage(const CInv& inv, const T& a)
{
    CDataStream ss(SER_NETWORK);
    ss.reserve(10000);
    ss << a;
    RelayMessage(inv, ss);
}

template<>
inline void RelayMessage<>(const CInv& inv, const CDataStream& ss)
{
    CRITICAL_BLOCK(cs_mapRelay)
    {
        // Expire old relay messages
        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < GetTime())
        {
            mapRelay.erase(vRelayExpiration.front().second);
            vRelayExpiration.pop_front();
        }

        // Save original serialized message so newer versions are preserved
        mapRelay[inv] = ss;
        vRelayExpiration.push_back(make_pair(GetTime() + 15 * 60, inv));
    }

    RelayInventory(inv);
}








//
// Templates for the publish and subscription system.
// The object being published as T& obj needs to have:
//   a set<unsigned int> setSources member
//   specializations of AdvertInsert and AdvertErase
// Currently implemented for CTable and CProduct.
//

template<typename T>
void AdvertStartPublish(CNode* pfrom, unsigned int nChannel, unsigned int nHops, T& obj)
{
    // Add to sources
    obj.setSources.insert(pfrom->addr.ip);

    if (!AdvertInsert(obj))
        return;

    // Relay
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode != pfrom && (nHops < PUBLISH_HOPS || pnode->IsSubscribed(nChannel)))
                pnode->PushMessage("publish", nChannel, nHops, obj);
}

template<typename T>
void AdvertStopPublish(CNode* pfrom, unsigned int nChannel, unsigned int nHops, T& obj)
{
    uint256 hash = obj.GetHash();

    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode != pfrom && (nHops < PUBLISH_HOPS || pnode->IsSubscribed(nChannel)))
                pnode->PushMessage("pub-cancel", nChannel, nHops, hash);

    AdvertErase(obj);
}

template<typename T>
void AdvertRemoveSource(CNode* pfrom, unsigned int nChannel, unsigned int nHops, T& obj)
{
    // Remove a source
    obj.setSources.erase(pfrom->addr.ip);

    // If no longer supported by any sources, cancel it
    if (obj.setSources.empty())
        AdvertStopPublish(pfrom, nChannel, nHops, obj);
}
