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
    bool fScript = false;
    if (!DecodeAnyAddress(strAddr, hash160, fScript))
        throw runtime_error("invalid Bitflash address");
    CScript s;
    if (fScript)
    {
        // Until the rules v3 switch a pay-to-script-hash output is spendable
        // by anyone who presents the script, signatures or not. Paying to one
        // before then is giving the money away.
        if (!RulesV3Active(GetAdjustedTime()))
            throw runtime_error(RulesV3Time() == 0
                ? "pay-to-script-hash addresses (C...) are not active on this network yet: the rules v3 switch is not scheduled"
                : strprintf("pay-to-script-hash addresses (C...) activate at block time %u; not before", RulesV3Time()));
        s << OP_HASH160 << hash160 << OP_EQUAL;
        return s;
    }
    s << OP_DUP << OP_HASH160 << hash160 << OP_EQUALVERIFY << OP_CHECKSIG;
    return s;
}

// A public key for multisig construction: hex, or an address whose key this
// wallet holds.
static vector<unsigned char> PubKeyFromParam(const string& str)
{
    if (IsHex(str))
    {
        vector<unsigned char> vch = ParseHex(str);
        if (vch.size() != 65 && vch.size() != 33)
            throw runtime_error("public key must be 65 (or 33) bytes: " + str);
        return vch;
    }
    uint160 h;
    if (!AddressToHash160(str, h))
        throw runtime_error("not a public key and not a Bitflash address: " + str);
    CRITICAL_BLOCK(cs_mapKeys)
    {
        map<uint160, vector<unsigned char> >::iterator mi = mapPubKeys.find(h);
        if (mi == mapPubKeys.end())
            throw runtime_error("this wallet does not hold the key for " + str + "; give the public key in hex");
        return mi->second;
    }
    throw runtime_error("unreachable");
}

static CScript MultisigRedeemScript(const json& p)
{
    if (p.size() < 2 || !p[0].is_number_integer() || !p[1].is_array())
        throw runtime_error("<nrequired> [\"key\",...]");
    int nRequired = p[0].get<int>();
    vector<vector<unsigned char> > keys;
    for (size_t i = 0; i < p[1].size(); i++)
    {
        if (!p[1][i].is_string())
            throw runtime_error("keys must be strings");
        keys.push_back(PubKeyFromParam(p[1][i].get<string>()));
    }
    if (keys.empty() || keys.size() > 16)
        throw runtime_error("between 1 and 16 keys");
    if (nRequired < 1 || nRequired > (int)keys.size())
        throw runtime_error(strprintf("nrequired must be between 1 and %d", (int)keys.size()));
    CScript redeem;
    redeem.SetMultisig(nRequired, keys);
    if (redeem.size() > 520)
        throw runtime_error("redeem script over 520 bytes");
    return redeem;
}

static json ScriptToJson(const CScript& script)
{
    json j;
    j["asm"] = script.ToString();
    j["hex"] = HexStr(script.begin(), script.end(), false);
    txnouttype whichType;
    vector<vector<unsigned char> > vSolutions;
    if (SolverTyped(script, whichType, vSolutions))
    {
        j["type"] = GetTxnOutputType(whichType);
        if (whichType == TX_PUBKEYHASH)
            j["address"] = Hash160ToAddress(uint160(vSolutions[0]));
        else if (whichType == TX_PUBKEY)
            j["address"] = PubKeyToAddress(vSolutions[0]);
        else if (whichType == TX_SCRIPTHASH)
            j["address"] = Hash160ToScriptAddress(uint160(vSolutions[0]));
        else if (whichType == TX_NULL_DATA)
        {
            j["data"] = HexStr(vSolutions[0].begin(), vSolutions[0].end(), false);
        }
        else if (whichType == TX_MULTISIG)
        {
            j["reqSigs"] = (int)vSolutions.front()[0];
            json a = json::array();
            for (size_t i = 1; i + 1 < vSolutions.size(); i++)
                a.push_back(PubKeyToAddress(vSolutions[i]));
            j["addresses"] = a;
        }
    }
    else
        j["type"] = "nonstandard";
    return j;
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
        // An output of ours in a transaction we funded is change, not a
        // receipt. It must not be listed as one: an exchange that sums the
        // "receive" entries to credit deposits would credit its own change
        // every time it paid a withdrawal. Coinbase has no inputs of ours, so
        // it is never mistaken for change.
        if (fMine && (nDebit == 0 || wtx.IsCoinBase()))
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
    int nConnections = 0;
    CRITICAL_BLOCK(cs_vNodes)
        nConnections = (int)vNodes.size();
    j["connections"]     = nConnections;
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
    // One fresh address per call: what an exchange wants is a unique deposit
    // address for each of its users.
    //
    // From the key pool, not GenerateNewKey(). The pool is derived from the HD
    // seed, so an address handed out here is covered by the recovery phrase;
    // GenerateNewKey() makes a random key outside the seed, and an exchange
    // that lost its wallet file would restore from the phrase and find every
    // deposit address it ever gave out missing. That is the difference between
    // an outage and a loss, and it is exactly what -newaddress already gets
    // right on the command line.
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    vector<unsigned char> vchPubKey = GetKeyFromPool();
    if (vchPubKey.empty())
        throw runtime_error("could not draw a key from the wallet");
    return PubKeyToAddress(vchPubKey);
}

static json rpc_validateaddress(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("validateaddress <address>");
    string addr = p[0].get<string>();
    uint160 h;
    bool fScript = false;
    json j;
    bool fValid = DecodeAnyAddress(addr, h, fScript);
    j["isvalid"] = fValid;
    if (fValid)
    {
        j["address"] = addr;
        j["isscript"] = fScript;
        if (fScript)
        {
            CScript redeem;
            bool fHave = GetWalletCScript(h, redeem);
            j["ismine"] = fHave && IsMine(redeem);
            if (fHave)
            {
                json sub = ScriptToJson(redeem);
                j["script"] = sub["type"];
                j["hex"] = sub["hex"];
                if (sub.contains("addresses")) j["addresses"] = sub["addresses"];
                if (sub.contains("reqSigs")) j["sigsrequired"] = sub["reqSigs"];
            }
            j["active"] = RulesV3Active(GetAdjustedTime());
        }
        else
        {
            j["ismine"] = IsMineAddress(addr);
            // The public key, when it is ours: what the other parties of a
            // multisig need from this wallet, and nothing else hands out.
            CRITICAL_BLOCK(cs_mapKeys)
            {
                map<uint160, vector<unsigned char> >::iterator mi = mapPubKeys.find(h);
                if (mi != mapPubKeys.end())
                    j["pubkey"] = HexStr(mi->second.begin(), mi->second.end(), false);
            }
        }
    }
    return j;
}

// createmultisig <nrequired> ["key",...]: the redeem script and its address,
// nothing stored. addmultisigaddress does the same and keeps the script, so
// the wallet recognizes and can sign for outputs paid to it.
static json rpc_createmultisig(const json& p)
{
    CScript redeem = MultisigRedeemScript(p);
    json j;
    j["address"] = Hash160ToScriptAddress(Hash160(redeem));
    j["redeemScript"] = HexStr(redeem.begin(), redeem.end(), false);
    return j;
}

static json rpc_addmultisigaddress(const json& p)
{
    CScript redeem = MultisigRedeemScript(p);
    if (!AddCScript(redeem))
        throw runtime_error("could not store the redeem script in the wallet");
    string strAddr = Hash160ToScriptAddress(Hash160(redeem));
    if (p.size() >= 3 && p[2].is_string() && !p[2].get<string>().empty())
        SetAddressBookName(strAddr, p[2].get<string>());
    return strAddr;
}

static json rpc_decodescript(const json& p)
{
    if (p.size() < 1 || !p[0].is_string() || !IsHex(p[0].get<string>()))
        throw runtime_error("decodescript <hex>");
    vector<unsigned char> vch = ParseHex(p[0].get<string>());
    CScript script(vch.begin(), vch.end());
    json j = ScriptToJson(script);
    j["p2sh"] = Hash160ToScriptAddress(Hash160(script));
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

// ---------------------------------------------------------------------------
// raw transactions: what a multisig needs, since the two (or three) wallets
// that hold the keys pass one half-signed transaction between them

static json TxToJson(const CTransaction& tx)
{
    json j;
    j["txid"] = tx.GetHash().GetHex();
    j["version"] = tx.nVersion;
    j["locktime"] = tx.nLockTime;
    json vin = json::array();
    for (size_t i = 0; i < tx.vin.size(); i++)
    {
        const CTxIn& txin = tx.vin[i];
        json in;
        if (tx.IsCoinBase())
            in["coinbase"] = HexStr(txin.scriptSig.begin(), txin.scriptSig.end(), false);
        else
        {
            in["txid"] = txin.prevout.hash.GetHex();
            in["vout"] = txin.prevout.n;
            json ss;
            ss["asm"] = txin.scriptSig.ToString();
            ss["hex"] = HexStr(txin.scriptSig.begin(), txin.scriptSig.end(), false);
            in["scriptSig"] = ss;
        }
        in["sequence"] = txin.nSequence;
        vin.push_back(in);
    }
    j["vin"] = vin;
    json vout = json::array();
    for (size_t i = 0; i < tx.vout.size(); i++)
    {
        json out;
        out["value"] = ValueFromAmount(tx.vout[i].nValue);
        out["n"] = (int)i;
        out["scriptPubKey"] = ScriptToJson(tx.vout[i].scriptPubKey);
        vout.push_back(out);
    }
    j["vout"] = vout;
    CDataStream ss(SER_NETWORK);
    ss << tx;
    j["hex"] = HexStr(ss.begin(), ss.end(), false);
    return j;
}

static CTransaction TxFromHexParam(const json& v)
{
    if (!v.is_string() || !IsHex(v.get<string>()))
        throw runtime_error("expected a transaction in hex");
    vector<unsigned char> vch = ParseHex(v.get<string>());
    CDataStream ss(vch, SER_NETWORK);
    CTransaction tx;
    try { ss >> tx; }
    catch (std::exception&) { throw runtime_error("transaction does not decode"); }
    return tx;
}

// The transaction an outpoint refers to: memory pool, then the chain.
static bool LookupTransaction(const uint256& hash, CTransaction& txRet)
{
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        map<uint256, CTransaction>::iterator mi = mapTransactions.find(hash);
        if (mi != mapTransactions.end())
        {
            txRet = mi->second;
            return true;
        }
    }
    CTxDB txdb("r");
    return txdb.ReadDiskTx(hash, txRet);
}

// listunspent [minconf=1] [maxconf=9999999] [["address",...]]
// The wallet marks spending per transaction (0.1.0), so an unspent wallet
// transaction's outputs that are ours are the unspent outputs.
static json rpc_listunspent(const json& p)
{
    int nMinDepth = (p.size() >= 1 && p[0].is_number_integer()) ? p[0].get<int>() : 1;
    int nMaxDepth = (p.size() >= 2 && p[1].is_number_integer()) ? p[1].get<int>() : 9999999;
    set<string> setFilter;
    if (p.size() >= 3 && p[2].is_array())
        for (size_t i = 0; i < p[2].size(); i++)
            if (p[2][i].is_string())
                setFilter.insert(p[2][i].get<string>());

    json out = json::array();
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = it->second;
            if (wtx.fSpent || !wtx.IsFinal())
                continue;
            if (wtx.IsCoinBase() && wtx.GetBlocksToMaturity() > 0)
                continue;
            int nDepth = wtx.GetDepthInMainChain();
            if (nDepth < nMinDepth || nDepth > nMaxDepth)
                continue;
            for (size_t n = 0; n < wtx.vout.size(); n++)
            {
                const CTxOut& txout = wtx.vout[n];
                if (!IsMine(txout.scriptPubKey))
                    continue;
                json sj = ScriptToJson(txout.scriptPubKey);
                string strAddr = sj.contains("address") ? sj["address"].get<string>() : "";
                if (!setFilter.empty() && !setFilter.count(strAddr))
                    continue;
                json o;
                o["txid"] = wtx.GetHash().GetHex();
                o["vout"] = (int)n;
                if (!strAddr.empty())
                    o["address"] = strAddr;
                o["scriptPubKey"] = HexStr(txout.scriptPubKey.begin(), txout.scriptPubKey.end(), false);
                if (txout.scriptPubKey.IsPayToScriptHash())
                {
                    CScript redeem;
                    if (GetWalletCScript(uint160(vector<unsigned char>(txout.scriptPubKey.begin() + 2, txout.scriptPubKey.begin() + 22)), redeem))
                        o["redeemScript"] = HexStr(redeem.begin(), redeem.end(), false);
                }
                o["amount"] = ValueFromAmount(txout.nValue);
                o["confirmations"] = nDepth;
                out.push_back(o);
            }
        }
    }
    return out;
}

// createrawtransaction [{"txid":h,"vout":n},...] {"address":amount,...}
// An output key may also be "script:<hex>" for a script that has no address
// form -- a bare multisig, which is what works before the rules v3 switch.
static json rpc_createrawtransaction(const json& p)
{
    if (p.size() < 2 || !p[0].is_array() || !p[1].is_object())
        throw runtime_error("createrawtransaction [{\"txid\":txid,\"vout\":n},...] {address:amount,...}");
    CTransaction tx;
    for (size_t i = 0; i < p[0].size(); i++)
    {
        const json& in = p[0][i];
        if (!in.is_object() || !in.contains("txid") || !in["txid"].is_string() ||
            !in.contains("vout") || !in["vout"].is_number_integer())
            throw runtime_error("each input needs txid and vout");
        int nOut = in["vout"].get<int>();
        if (nOut < 0)
            throw runtime_error("vout must be positive");
        tx.vin.push_back(CTxIn(COutPoint(uint256(in["txid"].get<string>()), nOut)));
    }
    set<string> setSeen;
    for (json::const_iterator it = p[1].begin(); it != p[1].end(); ++it)
    {
        string strKey = it.key();
        if (setSeen.count(strKey))
            throw runtime_error("duplicated output: " + strKey);
        setSeen.insert(strKey);
        CScript scriptPubKey;
        if (strKey.compare(0, 5, "data:") == 0)
        {
            // A burn: OP_RETURN <data>. The amount is what is destroyed.
            string strHex = strKey.substr(5);
            if (!IsHex(strHex) && !strHex.empty())
                throw runtime_error("data: must be followed by hex");
            vector<unsigned char> vch = ParseHex(strHex);
            if (vch.size() > MAX_OP_RETURN_RELAY)
                throw runtime_error(strprintf("data: at most %u bytes", MAX_OP_RETURN_RELAY));
            scriptPubKey << OP_RETURN;
            if (!vch.empty())
                scriptPubKey << vch;
            int64 nBurn = AmountFromValue(it.value());
            if (nBurn < 0)
                throw runtime_error("amount must not be negative");
            tx.vout.push_back(CTxOut(nBurn, scriptPubKey));
            continue;
        }
        if (strKey.compare(0, 7, "script:") == 0)
        {
            string strHex = strKey.substr(7);
            if (!IsHex(strHex))
                throw runtime_error("script: must be followed by hex");
            vector<unsigned char> vch = ParseHex(strHex);
            scriptPubKey = CScript(vch.begin(), vch.end());
            if (scriptPubKey.IsPayToScriptHash() && !RulesV3Active(GetAdjustedTime()))
                throw runtime_error("pay-to-script-hash outputs are not active on this network yet");
        }
        else
            scriptPubKey = ScriptForAddress(strKey);
        int64 nValue = AmountFromValue(it.value());
        if (nValue <= 0)
            throw runtime_error("amount must be positive");
        tx.vout.push_back(CTxOut(nValue, scriptPubKey));
    }
    if (tx.vin.empty() || tx.vout.empty())
        throw runtime_error("a transaction needs at least one input and one output");
    CDataStream ss(SER_NETWORK);
    ss << tx;
    return HexStr(ss.begin(), ss.end(), false);
}

static json rpc_decoderawtransaction(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("decoderawtransaction <hex>");
    return TxToJson(TxFromHexParam(p[0]));
}

static json rpc_getrawtransaction(const json& p)
{
    if (p.size() < 1 || !p[0].is_string())
        throw runtime_error("getrawtransaction <txid> [verbose=0]");
    CTransaction tx;
    if (!LookupTransaction(uint256(p[0].get<string>()), tx))
        throw runtime_error("transaction not found (not in the memory pool and not in the chain)");
    json j = TxToJson(tx);
    bool fVerbose = p.size() >= 2 && ((p[1].is_boolean() && p[1].get<bool>()) || (p[1].is_number_integer() && p[1].get<int>() != 0));
    return fVerbose ? j : j["hex"];
}

// A key handed to signrawtransaction lives in the wallet's key map only for
// the duration of the call, and is never written anywhere.
struct CTemporaryKeys
{
    vector<vector<unsigned char> > vPubKeys;
    ~CTemporaryKeys()
    {
        CRITICAL_BLOCK(cs_mapKeys)
            for (size_t i = 0; i < vPubKeys.size(); i++)
            {
                mapKeys.erase(vPubKeys[i]);
                mapPubKeys.erase(Hash160(vPubKeys[i]));
            }
    }
};

// signrawtransaction <hex> [[{"txid","vout","scriptPubKey","redeemScript"},...]] [["privkey-hex",...]]
// Signs what this wallet's keys (plus any given) can sign, keeps what is
// already signed, and says whether every input now verifies.
static json rpc_signrawtransaction(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("signrawtransaction <hex> [prevtxs] [privkeys]");
    if (IsWalletLocked())
        throw runtime_error("wallet is locked");
    CTransaction tx = TxFromHexParam(p[0]);

    // Previous outputs: given, else looked up
    map<COutPoint, CScript> mapPrevOut;
    map<uint160, CScript> mapRedeem;
    if (p.size() >= 2 && p[1].is_array())
    {
        for (size_t i = 0; i < p[1].size(); i++)
        {
            const json& pv = p[1][i];
            if (!pv.is_object() || !pv.contains("txid") || !pv.contains("vout") || !pv.contains("scriptPubKey"))
                throw runtime_error("each prevtx needs txid, vout and scriptPubKey");
            vector<unsigned char> vch = ParseHex(pv["scriptPubKey"].get<string>());
            mapPrevOut[COutPoint(uint256(pv["txid"].get<string>()), pv["vout"].get<int>())] = CScript(vch.begin(), vch.end());
            if (pv.contains("redeemScript") && pv["redeemScript"].is_string())
            {
                vector<unsigned char> r = ParseHex(pv["redeemScript"].get<string>());
                CScript redeem(r.begin(), r.end());
                mapRedeem[Hash160(redeem)] = redeem;
            }
        }
    }
    CTemporaryKeys tempKeys;
    if (p.size() >= 3 && p[2].is_array())
    {
        for (size_t i = 0; i < p[2].size(); i++)
        {
            if (!p[2][i].is_string() || !IsHex(p[2][i].get<string>()))
                throw runtime_error("private keys are given as 64 hex characters");
            CKey key;
            if (!key.SetSecret(ParseHex(p[2][i].get<string>())))
                throw runtime_error("invalid private key");
            vector<unsigned char> vchPubKey = key.GetPubKey();
            CRITICAL_BLOCK(cs_mapKeys)
            {
                if (!mapKeys.count(vchPubKey))
                {
                    mapKeys[vchPubKey] = key.GetPrivKey();
                    mapPubKeys[Hash160(vchPubKey)] = vchPubKey;
                    tempKeys.vPubKeys.push_back(vchPubKey);
                }
            }
        }
    }
    // Redeem scripts named by the caller are usable for this call
    for (map<uint160, CScript>::iterator it = mapRedeem.begin(); it != mapRedeem.end(); ++it)
        CRITICAL_BLOCK(cs_mapKeys)
            if (!mapScripts.count(it->first))
                mapScripts[it->first] = it->second;

    bool fComplete = true;
    json errors = json::array();
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        CTxIn& txin = tx.vin[i];
        CScript scriptPubKey;
        map<COutPoint, CScript>::iterator mi = mapPrevOut.find(txin.prevout);
        if (mi != mapPrevOut.end())
            scriptPubKey = mi->second;
        else
        {
            CTransaction txPrev;
            if (!LookupTransaction(txin.prevout.hash, txPrev) || txin.prevout.n >= txPrev.vout.size())
            {
                json e; e["vout"] = (int)i; e["error"] = "previous output not found; give it in prevtxs";
                errors.push_back(e);
                fComplete = false;
                continue;
            }
            scriptPubKey = txPrev.vout[txin.prevout.n].scriptPubKey;
        }

        // Sign afresh into a scratch transaction, then merge with what the
        // input already carried
        CScript scriptSigOld = txin.scriptSig;
        CTransaction txScratch = tx;
        txScratch.vin[i].scriptSig.clear();
        CTransaction txFrom;
        txFrom.vout.resize(txin.prevout.n + 1);
        txFrom.vout[txin.prevout.n].scriptPubKey = scriptPubKey;
        // SignSignature checks prevout.hash against txFrom's hash only through
        // VerifySignature; here the outpoint is trusted as given
        CScript scriptSigNew;
        {
            CTransaction txForSig = txScratch;
            uint256 hash;
            if (scriptPubKey.IsPayToScriptHash())
            {
                CScript subscript;
                if (GetWalletCScript(uint160(vector<unsigned char>(scriptPubKey.begin() + 2, scriptPubKey.begin() + 22)), subscript))
                {
                    hash = SignatureHash(subscript, txForSig, i, SIGHASH_ALL);
                    CScript inner;
                    Solver(subscript, hash, SIGHASH_ALL, inner);
                    // merge inner parts (multisig) before appending the script
                    CScript innerOld;
                    {
                        vector<vector<unsigned char> > pushes;
                        CScript::const_iterator pc = scriptSigOld.begin();
                        opcodetype opcode; vector<unsigned char> vch;
                        while (pc < scriptSigOld.end() && scriptSigOld.GetOp(pc, opcode, vch))
                            pushes.push_back(vch);
                        for (size_t k = 0; k + 1 < pushes.size(); k++)
                            innerOld << pushes[k];
                    }
                    CScript merged = CombineMultisig(subscript, txForSig, i, innerOld, inner);
                    scriptSigNew = merged;
                    scriptSigNew << static_cast<vector<unsigned char> >(subscript);
                }
                else
                    scriptSigNew = scriptSigOld;
            }
            else
            {
                hash = SignatureHash(scriptPubKey, txForSig, i, SIGHASH_ALL);
                CScript fresh;
                Solver(scriptPubKey, hash, SIGHASH_ALL, fresh);
                txnouttype whichType;
                vector<vector<unsigned char> > vSolutions;
                if (SolverTyped(scriptPubKey, whichType, vSolutions) && whichType == TX_MULTISIG)
                    scriptSigNew = CombineMultisig(scriptPubKey, txForSig, i, scriptSigOld, fresh);
                else
                    scriptSigNew = fresh.empty() ? scriptSigOld : fresh;
            }
        }
        txin.scriptSig = scriptSigNew;
        if (!VerifyScriptP2SH(txin.scriptSig, scriptPubKey, tx, i))
        {
            fComplete = false;
            json e; e["vout"] = (int)i; e["error"] = "input does not verify yet (more signatures needed, or keys not held)";
            errors.push_back(e);
        }
    }

    // Forget the caller's redeem scripts again unless the wallet had them
    for (map<uint160, CScript>::iterator it = mapRedeem.begin(); it != mapRedeem.end(); ++it)
        CRITICAL_BLOCK(cs_mapKeys)
            if (mapScripts.count(it->first) && !HaveCScript(it->first))
                mapScripts.erase(it->first);

    CDataStream ss(SER_NETWORK);
    ss << tx;
    json j;
    j["hex"] = HexStr(ss.begin(), ss.end(), false);
    j["complete"] = fComplete;
    if (!errors.empty())
        j["errors"] = errors;
    return j;
}

static json rpc_sendrawtransaction(const json& p)
{
    if (p.size() < 1)
        throw runtime_error("sendrawtransaction <hex>");
    CTransaction tx = TxFromHexParam(p[0]);
    uint256 hash = tx.GetHash();
    CDataStream ssTx(SER_NETWORK);
    ssTx << tx;
    CRITICAL_BLOCK(cs_main)
    {
        CTransaction txHave;
        bool fHave = LookupTransaction(hash, txHave);
        if (!fHave)
        {
            bool fMissingInputs = false;
            if (!tx.AcceptTransaction(true, &fMissingInputs))
                throw runtime_error(fMissingInputs ? "transaction rejected: missing inputs"
                                                   : "transaction rejected (invalid, non-standard, or already spent inputs)");
            AddToWalletIfMine(tx, NULL);
        }
        RelayMessage(CInv(MSG_TX, hash), ssTx);
    }
    return hash.GetHex();
}

static json rpc_help(const json&)
{
    return "getinfo getblockcount getblockhash getblock getnewaddress validateaddress "
           "getbalance sendtoaddress gettransaction listtransactions listsinceblock "
           "createmultisig addmultisigaddress decodescript listunspent createrawtransaction "
           "decoderawtransaction getrawtransaction signrawtransaction sendrawtransaction help";
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
    { "createmultisig",   rpc_createmultisig },
    { "addmultisigaddress", rpc_addmultisigaddress },
    { "decodescript",     rpc_decodescript },
    { "listunspent",      rpc_listunspent },
    { "createrawtransaction", rpc_createrawtransaction },
    { "decoderawtransaction", rpc_decoderawtransaction },
    { "getrawtransaction", rpc_getrawtransaction },
    { "signrawtransaction", rpc_signrawtransaction },
    { "sendrawtransaction", rpc_sendrawtransaction },
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
        json params = json::array();
        if (req.contains("params"))
        {
            // Positional only. Silently treating an object as "no params"
            // would turn a caller's typo into a call with defaults -- for
            // sendtoaddress, that is the wrong kind of forgiving.
            if (!req["params"].is_array())
                throw runtime_error("params must be an array");
            params = req["params"];
        }

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
        int w = send(s, resp.data() + off, (int)(resp.size() - off), BTF_SEND_FLAGS);
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
            // Batch: one reply per request, in order. Capped, because every
            // entry takes the chain lock in turn and a single request with
            // thousands of them would hold the node's main lock for as long
            // as it liked.
            if (parsed.size() > 100)
                throw runtime_error("batch too large (max 100)");
            reply = json::array();
            foreach(const json& r, parsed)
                reply.push_back(Dispatch(r));
        }
        else
            reply = Dispatch(parsed);
    }
    catch (const json::parse_error&)
    {
        reply = json{{"result", nullptr}, {"error", json{{"code", -32700}, {"message", "parse error"}}}, {"id", nullptr}};
    }
    catch (const std::exception& e)
    {
        reply = json{{"result", nullptr}, {"error", json{{"code", -32600}, {"message", e.what()}}}, {"id", nullptr}};
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
