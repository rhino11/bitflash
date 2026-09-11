// JSON-RPC over HTTP for exchange integration.
//
// Bitcoin 0.1.0 had no RPC; it arrived in 0.3.x and this tree never inherited
// it. Without one there is no way for anybody else's software to run a wallet:
// no deposit address per user, no way to notice a deposit landed, no way to pay
// a withdrawal. Every exchange integration is built on exactly those calls, so
// they are what this file provides -- and only those. The method set is the
// one exchanges actually use, named and shaped the way bitcoind names and
// shapes them, so an integration written for any Bitcoin-derived coin works
// here unchanged.
//
// Exposure is the design constraint. A node on this network goes to some
// trouble not to be reachable in the clear, and a wallet that spends on command
// must not undo that. So: nothing listens unless -rpcuser and -rpcpassword are
// both given, the socket binds loopback and there is no option to bind wider,
// every request carries HTTP Basic credentials, and the comparison is constant
// time. What the exchange runs beside the daemon can talk to it; nothing else.

#include <nlohmann/json.hpp>
#include "headers.h"
#include "btfsock.h"
#include "jsonrpc.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#define rpc_close(s) closesocket(s)
#else
#define rpc_close(s) close(s)
#endif

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// configuration

static string g_rpcUser;
static string g_rpcPassword;
static int    g_rpcPort = 0;

bool JsonRpcConfigure(const string& strUser, const string& strPassword, const string& strPort)
{
    g_rpcUser     = strUser;
    g_rpcPassword = strPassword;

    if (g_rpcUser.empty() && g_rpcPassword.empty())
        return false;                                   // not asked for
    if (g_rpcUser.empty() || g_rpcPassword.empty())
    {
        fprintf(stderr, "JSON-RPC needs both -rpcuser and -rpcpassword; refusing to start it with one\n");
        return false;
    }
    if (g_rpcPassword.size() < 16)
    {
        // A wallet behind a short password on a local port is a wallet behind
        // whatever else runs on that machine. Sixteen is a floor, not advice.
        fprintf(stderr, "JSON-RPC: -rpcpassword must be at least 16 characters\n");
        return false;
    }
    g_rpcPort = strPort.empty() ? (IsTestNet() ? 18432 : 8432) : atoi(strPort.c_str());
    if (g_rpcPort <= 0 || g_rpcPort > 65535)
    {
        fprintf(stderr, "JSON-RPC: -rpcport=%s is not a port\n", strPort.c_str());
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// small helpers

static double ValueFromAmount(int64 n) { return (double)n / (double)COIN; }

static int64 AmountFromValue(const json& v)
{
    // Exchanges send amounts as JSON numbers or as strings; accept both, and
    // go through ParseMoney so "1.5" and 1.5 land on the same satoshi count.
    string s = v.is_string() ? v.get<string>() : strprintf("%.8f", v.get<double>());
    int64 n = 0;
    if (!ParseMoney(s.c_str(), n) || n <= 0)
        throw runtime_error("invalid amount");
    return n;
}

static bool ConstantTimeEqual(const string& a, const string& b)
{
    // Length leaks, but a guess at the length of a password is not a guess at
    // the password. What must not leak is where the first wrong byte is.
    unsigned char diff = (unsigned char)(a.size() != b.size());
    size_t n = min(a.size(), b.size());
    for (size_t i = 0; i < n; i++)
        diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

static string Base64Decode(const string& in)
{
    static const string tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string out;
    int val = 0, bits = -8;
    foreach(unsigned char c, in)
    {
        if (c == '=') break;
        string::size_type p = tbl.find((char)c);
        if (p == string::npos) continue;
        val = (val << 6) + (int)p;
        bits += 6;
        if (bits >= 0)
        {
            out.push_back((char)((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

static CScript ScriptForAddress(const string& strAddr)
{
    uint160 hash160;
    if (!AddressToHash160(strAddr, hash160))
        throw runtime_error("invalid Bitflash address");
    CScript s;
    s << OP_DUP << OP_HASH160 << hash160 << OP_EQUALVERIFY << OP_CHECKSIG;
    return s;
}

static string AddressOfScript(const CScript& scriptPubKey)
{
    uint160 h;
    if (ExtractHash160(scriptPubKey, h))
        return Hash160ToAddress(h);
    // Coinbase outputs pay to a bare public key, the 2009 way, so there is no
    // hash in the script to read off; derive the address from the key instead.
    // Without this every mining reward listed with an empty address.
    vector<unsigned char> vchPubKey;
    if (ExtractPubKey(scriptPubKey, false, vchPubKey))
        return PubKeyToAddress(vchPubKey);
    return "";
}

static bool IsMineAddress(const string& strAddr)
{
    uint160 h;
    if (!AddressToHash160(strAddr, h))
        return false;
    CRITICAL_BLOCK(cs_mapKeys)
        return mapPubKeys.count(h) > 0;
    return false;
}

static CBlockIndex* BlockIndexOf(const uint256& hash)
{
    map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(hash);
    return it == mapBlockIndex.end() ? NULL : it->second;
}

// ---------------------------------------------------------------------------
// the shape exchanges read

// One wallet transaction, the way gettransaction / listtransactions describe
// it: net amount from this wallet's point of view, confirmations, and one
// "details" entry per output that concerns us.
static json WalletTxToJson(const CWalletTx& wtx)
{
    json j;
    int64 nCredit = wtx.GetCredit();
    int64 nDebit  = wtx.GetDebit();
    int nDepth    = wtx.GetDepthInMainChain();

    j["txid"]          = wtx.GetHash().GetHex();
    j["amount"]        = ValueFromAmount(nCredit - nDebit);
    j["confirmations"] = nDepth;
    j["time"]          = (int64)wtx.nTimeReceived;
    j["timereceived"]  = (int64)wtx.nTimeReceived;
    if (nDepth > 0)
    {
        j["blockhash"] = wtx.hashBlock.GetHex();
        CBlockIndex* pindex = BlockIndexOf(wtx.hashBlock);
        if (pindex)
        {
            j["blockindex"] = pindex->nHeight;
            j["blocktime"]  = (int64)pindex->nTime;
        }
    }
    if (wtx.IsCoinBase())
    {
        // Mining reward. An exchange should not credit these until mature, and
        // the category says so; confirmations alone would not.
        j["generated"] = true;
    }

    json details = json::array();
    for (size_t i = 0; i < wtx.vout.size(); i++)
    {
        const CTxOut& out = wtx.vout[i];
        bool fMine = out.IsMine();
        string addr = AddressOfScript(out.scriptPubKey);
        if (nDebit > 0 && !fMine)
        {
            json d;
            d["category"] = "send";
            d["address"]  = addr;
            d["amount"]   = -ValueFromAmount(out.nValue);
            d["vout"]     = (int)i;
            details.push_back(d);
        }
        if (fMine)
        {
            json d;
            d["category"] = wtx.IsCoinBase()
                                ? (wtx.GetBlocksToMaturity() > 0 ? "immature" : "generate")
                                : "receive";
            d["address"]  = addr;
            d["amount"]   = ValueFromAmount(out.nValue);
            d["vout"]     = (int)i;
            details.push_back(d);
        }
    }
    j["details"] = details;
    return j;
}

static json BlockToJson(CBlockIndex* pindex)
{
    CBlock block;
    if (!block.ReadFromDisk(pindex, true))
        throw runtime_error("block not on disk");
    json j;
    j["hash"]          = pindex->GetBlockHash().GetHex();
    j["confirmations"] = nBestHeight - pindex->nHeight + 1;
    j["height"]        = pindex->nHeight;
    j["version"]       = block.nVersion;
    j["merkleroot"]    = block.hashMerkleRoot.GetHex();
    j["time"]          = (int64)block.nTime;
    j["nonce"]         = (int64)block.nNonce;
    j["bits"]          = strprintf("%08x", block.nBits);
    json tx = json::array();
    foreach(const CTransaction& t, block.vtx)
        tx.push_back(t.GetHash().GetHex());
    j["tx"] = tx;
    if (pindex->pprev)
        j["previousblockhash"] = pindex->pprev->GetBlockHash().GetHex();
    if (pindex->pnext)
        j["nextblockhash"] = pindex->pnext->GetBlockHash().GetHex();
    return j;
}

// ---------------------------------------------------------------------------
// methods

typedef json (*RpcMethod)(const json& params);

static json rpc_getinfo(const json&)
{
    json j;
    j["version"]         = BITFLASH_VERSION_STRING;
    j["protocolversion"] = VERSION;
    j["blocks"]          = nBestHeight;
    j["connections"]     = (int)vNodes.size();
    j["testnet"]         = IsTestNet();
    j["balance"]         = ValueFromAmount(GetBalance());
    j["walletlocked"]    = IsWalletLocked();
    return j;
}

static json rpc_getblockcount(const json&)
{
    return nBestHeight;
}

static json rpc_getblockhash(const json& p)
{
    if (p.size() < 1 || !p[0].is_number_integer())
        throw runtime_error("getblockhash <height>");
    int n = p[0].get<int>();
    if (n < 0 || n > nBestHeight)
        throw runtime_error("block height out of range");
    CBlockIndex* pindex = pindexBest;
    while (pindex && pindex->nHeight > n)
        pindex = pindex->pprev;
    if (!pindex)
        throw runtime_error("block not found");
    return pindex->GetBlockHash().GetHex();
}

static json rpc_getblock(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("getblock <hash>");
    CBlockIndex* pindex = BlockIndexOf(uint256(p[0].get<string>()));
    if (!pindex)
        throw runtime_error("block not found");
    return BlockToJson(pindex);
}

static json rpc_getnewaddress(const json&)
{
    // One fresh key per call. That is what an exchange wants from this: a
    // unique deposit address for each of its users.
    return PubKeyToAddress(GenerateNewKey());
}

static json rpc_validateaddress(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("validateaddress <address>");
    string addr = p[0].get<string>();
    uint160 h;
    json j;
    bool fValid = AddressToHash160(addr, h);
    j["isvalid"] = fValid;
    if (fValid)
    {
        j["address"] = addr;
        j["ismine"]  = IsMineAddress(addr);
    }
    return j;
}

static json rpc_getbalance(const json& p)
{
    // GetBalance() counts what the wallet would let you spend now, which
    // already excludes immature coinbase. minconf beyond that is filtered here.
    int nMinConf = (p.size() >= 1 && p[0].is_number_integer()) ? p[0].get<int>() : 1;
    if (nMinConf <= 1)
        return ValueFromAmount(GetBalance());

    int64 nTotal = 0;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = it->second;
            if (!wtx.IsFinal() || wtx.GetDepthInMainChain() < nMinConf)
                continue;
            if (wtx.IsCoinBase() && wtx.GetBlocksToMaturity() > 0)
                continue;
            nTotal += wtx.GetCredit() - wtx.GetDebit();
        }
    }
    return ValueFromAmount(nTotal);
}

static json rpc_sendtoaddress(const json& p)
{
    if (p.size() < 2 || !p[0].is_string())
        throw runtime_error("sendtoaddress <address> <amount>");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    CScript scriptPubKey = ScriptForAddress(p[0].get<string>());
    int64 nValue = AmountFromValue(p[1]);
    CWalletTx wtx;
    if (!SendMoney(scriptPubKey, nValue, wtx))
        throw runtime_error("send failed: insufficient balance once the fee is counted");
    return wtx.GetHash().GetHex();
}

static json rpc_gettransaction(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("gettransaction <txid>");
    uint256 hash(p[0].get<string>());
    CRITICAL_BLOCK(cs_mapWallet)
    {
        map<uint256, CWalletTx>::iterator it = mapWallet.find(hash);
        if (it == mapWallet.end())
            throw runtime_error("transaction not in wallet");
        return WalletTxToJson(it->second);
    }
    throw runtime_error("transaction not in wallet");
}

static json rpc_listtransactions(const json& p)
{
    int nCount = (p.size() >= 1 && p[0].is_number_integer()) ? p[0].get<int>() : 10;
    if (nCount < 0) nCount = 0;

    // Newest last, like bitcoind: the caller reads the tail.
    vector<pair<int64, const CWalletTx*> > v;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
            v.push_back(make_pair((int64)it->second.nTimeReceived, &it->second));
        sort(v.begin(), v.end());
        json out = json::array();
        size_t nStart = v.size() > (size_t)nCount ? v.size() - nCount : 0;
        for (size_t i = nStart; i < v.size(); i++)
            out.push_back(WalletTxToJson(*v[i].second));
        return out;
    }
    return json::array();
}

static json rpc_listsinceblock(const json& p)
{
    // The call exchanges actually poll. Everything that touched the wallet in
    // blocks after the given one, plus everything still unconfirmed, and the
    // hash to pass next time. An empty or unknown hash means "everything".
    int nSinceHeight = -1;
    if (p.size() >= 1 && p[0].is_string() && !p[0].get<string>().empty())
    {
        CBlockIndex* pindex = BlockIndexOf(uint256(p[0].get<string>()));
        if (pindex && pindex->IsInMainChain())
            nSinceHeight = pindex->nHeight;
    }

    json txs = json::array();
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = it->second;
            int nDepth = wtx.GetDepthInMainChain();
            int nHeight = nDepth > 0 ? nBestHeight - nDepth + 1 : -1;
            if (nDepth > 0 && nHeight <= nSinceHeight)
                continue;
            txs.push_back(WalletTxToJson(wtx));
        }
    }
    json j;
    j["transactions"] = txs;
    j["lastblock"]    = hashBestChain.GetHex();
    return j;
}

static json rpc_help(const json&)
{
    return "getinfo getblockcount getblockhash getblock getnewaddress validateaddress "
           "getbalance sendtoaddress gettransaction listtransactions listsinceblock help";
}

struct RpcEntry { const char* name; RpcMethod fn; };
static const RpcEntry kMethods[] = {
    { "getinfo",          rpc_getinfo },
    { "getblockcount",    rpc_getblockcount },
    { "getblockhash",     rpc_getblockhash },
    { "getblock",         rpc_getblock },
    { "getnewaddress",    rpc_getnewaddress },
    { "validateaddress",  rpc_validateaddress },
    { "getbalance",       rpc_getbalance },
    { "sendtoaddress",    rpc_sendtoaddress },
    { "gettransaction",   rpc_gettransaction },
    { "listtransactions", rpc_listtransactions },
    { "listsinceblock",   rpc_listsinceblock },
    { "help",             rpc_help },
};

static json Dispatch(const json& req)
{
    json id = req.contains("id") ? req["id"] : json(nullptr);
    json reply;
    reply["id"] = id;
    try
    {
        if (!req.contains("method") || !req["method"].is_string())
            throw runtime_error("missing method");
        string method = req["method"].get<string>();
        json params = req.contains("params") && req["params"].is_array() ? req["params"] : json::array();

        RpcMethod fn = NULL;
        for (size_t i = 0; i < ARRAYLEN(kMethods); i++)
            if (method == kMethods[i].name) { fn = kMethods[i].fn; break; }
        if (!fn)
            throw runtime_error("method not found");

        // Chain state and wallet state are read together; hold both the whole
        // way through, the same order the rest of the node takes them.
        CRITICAL_BLOCK(cs_main)
        {
            reply["result"] = fn(params);
            reply["error"]  = nullptr;
        }
    }
    catch (const std::exception& e)
    {
        reply["result"] = nullptr;
        reply["error"]  = json{{"code", -1}, {"message", e.what()}};
    }
    return reply;
}

// ---------------------------------------------------------------------------
// http

static bool RecvAll(btf_socket_t s, string& out, int nTimeoutSecs)
{
    // Read headers, then exactly Content-Length bytes of body. No keep-alive:
    // one request, one response, close -- which is how every RPC client that
    // targets bitcoind behaves anyway.
    char buf[4096];
    int64 nStart = GetTime();
    size_t nHeaderEnd = string::npos, nBodyLen = 0;
    while (GetTime() - nStart < nTimeoutSecs)
    {
        int r = recv(s, buf, sizeof(buf), 0);
        if (r <= 0) return false;
        out.append(buf, r);
        if (out.size() > 1 << 20) return false;                  // nobody needs a 1 MB request
        if (nHeaderEnd == string::npos)
        {
            nHeaderEnd = out.find("\r\n\r\n");
            if (nHeaderEnd == string::npos) continue;
            string hdr = out.substr(0, nHeaderEnd);
            string lower = hdr;
            for (size_t i = 0; i < lower.size(); i++) lower[i] = (char)tolower((unsigned char)lower[i]);
            size_t p = lower.find("content-length:");
            if (p != string::npos)
                nBodyLen = (size_t)atoi(hdr.c_str() + p + 15);
        }
        if (out.size() >= nHeaderEnd + 4 + nBodyLen)
            return true;
    }
    return false;
}

static void SendHttp(btf_socket_t s, int nCode, const string& strBody)
{
    const char* pszText = nCode == 200 ? "OK" : nCode == 401 ? "Unauthorized" :
                          nCode == 400 ? "Bad Request" : nCode == 404 ? "Not Found" : "Error";
    string resp = strprintf("HTTP/1.1 %d %s\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: %u\r\n"
                            "Connection: close\r\n"
                            "%s"
                            "\r\n",
                            nCode, pszText, (unsigned)strBody.size(),
                            nCode == 401 ? "WWW-Authenticate: Basic realm=\"bitflash\"\r\n" : "");
    resp += strBody;
    size_t off = 0;
    while (off < resp.size())
    {
        int w = send(s, resp.data() + off, (int)(resp.size() - off), 0);
        if (w <= 0) break;
        off += w;
    }
}

static bool Authorised(const string& strHeaders)
{
    string lower = strHeaders;
    for (size_t i = 0; i < lower.size(); i++) lower[i] = (char)tolower((unsigned char)lower[i]);
    size_t p = lower.find("authorization: basic ");
    if (p == string::npos) return false;
    size_t e = strHeaders.find("\r\n", p);
    string b64 = strHeaders.substr(p + 21, e == string::npos ? string::npos : e - (p + 21));
    while (!b64.empty() && isspace((unsigned char)b64[b64.size()-1])) b64.erase(b64.size()-1);
    return ConstantTimeEqual(Base64Decode(b64), g_rpcUser + ":" + g_rpcPassword);
}

static void HandleConnection(btf_socket_t s)
{
    string req;
    if (!RecvAll(s, req, 30))
    {
        rpc_close(s);
        return;
    }
    size_t nHeaderEnd = req.find("\r\n\r\n");
    string headers = req.substr(0, nHeaderEnd);
    string body    = req.substr(nHeaderEnd + 4);

    if (!Authorised(headers))
    {
        // Same answer whether the user is unknown or the password is wrong,
        // and a pause so a brute force at loopback speed is still slow.
        Sleep(250);
        SendHttp(s, 401, "");
        rpc_close(s);
        return;
    }
    if (headers.compare(0, 5, "POST ") != 0)
    {
        SendHttp(s, 404, "");
        rpc_close(s);
        return;
    }

    json reply;
    try
    {
        json parsed = json::parse(body);
        if (parsed.is_array())
        {
            // Batch: one reply per request, in order.
            reply = json::array();
            foreach(const json& r, parsed)
                reply.push_back(Dispatch(r));
        }
        else
            reply = Dispatch(parsed);
    }
    catch (const std::exception& e)
    {
        reply = json{{"result", nullptr}, {"error", json{{"code", -32700}, {"message", "parse error"}}}, {"id", nullptr}};
    }
    SendHttp(s, 200, reply.dump());
    rpc_close(s);
}

void ThreadJsonRpcServer(void* parg)
{
    btf_socket_t lsock = (btf_socket_t)socket(AF_INET, SOCK_STREAM, 0);
    if (lsock == INVALID_SOCKET)
    {
        printf("JSON-RPC: could not create listener socket\n");
        return;
    }
    int one = 1;
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);      // loopback, and only loopback
    addr.sin_port = htons((unsigned short)g_rpcPort);
    if (bind(lsock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        printf("JSON-RPC: could not bind 127.0.0.1:%d\n", g_rpcPort);
        rpc_close(lsock);
        return;
    }
    if (listen(lsock, 16) != 0)
    {
        printf("JSON-RPC: could not listen on %d\n", g_rpcPort);
        rpc_close(lsock);
        return;
    }
    printf("JSON-RPC listening on 127.0.0.1:%d\n", g_rpcPort);

    while (!fShutdown)
    {
        fd_set fds; FD_ZERO(&fds); FD_SET(lsock, &fds);
        struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
        int r = select((int)lsock + 1, &fds, NULL, NULL, &tv);
        if (r <= 0) continue;
        struct sockaddr_in peer; socklen_t len = sizeof(peer);
        btf_socket_t s = (btf_socket_t)accept(lsock, (struct sockaddr*)&peer, &len);
        if (s == INVALID_SOCKET) continue;
        // Belt and braces on top of the bind: even if something ever changed
        // the bind, a request from off-box is refused here.
        if (peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
        {
            rpc_close(s);
            continue;
        }
        HandleConnection(s);
    }
    rpc_close(lsock);
    printf("JSON-RPC stopped\n");
}
