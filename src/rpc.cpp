// Copyright (c) 2009 Satoshi Nakamoto / Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Bitflash pool server -- .btf Stratum pool, operator side.
//
// Architecture:
//   PoolEventLoop  -- single thread, owns all miner fds, all job/share/payout
//                     state. No locks needed on any of that data.
//   AcceptOneFn    -- one thread per relay. Blocks on RvServiceRegister +
//                     BtfServiceWrap, pushes finished socket to gReadyQueue.
//   AcceptLoopFn   -- spawns AcceptOneFn threads, re-polls relay list every
//                     60s so dynamically discovered relays get picked up.
//
// GUI-visible state is snapshotted under gStatsMutex every 2s.
// Accept queue handoff uses gReadyMutex (held for microseconds).

#pragma push_macro("snprintf")
#undef snprintf
#include <nlohmann/json.hpp>
#pragma pop_macro("snprintf")

#include "headers.h"
#ifdef snprintf
#undef snprintf
#endif
#include "btftunnel.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <atomic>
#include <mutex>
#include <map>
#include <set>
#include <deque>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>

using json = nlohmann::json;

#ifdef _WIN32
#define sock_close(s)  BtfCloseSocket(s)
#define SEND_FLAGS     0
#else
#define sock_close(s)  BtfCloseSocket(s)
#define SEND_FLAGS     MSG_NOSIGNAL
#endif

volatile bool gPoolRunning = false;

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------
static std::string ToHex(const void* p, size_t n)
{
    const unsigned char* b = (const unsigned char*)p;
    std::string s; s.reserve(n * 2);
    static const char* H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { s += H[b[i] >> 4]; s += H[b[i] & 0xf]; }
    return s;
}

static std::vector<unsigned char> FromHex(const std::string& s)
{
    std::vector<unsigned char> v;
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        auto h = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        v.push_back((unsigned char)((h(s[i]) << 4) | h(s[i + 1])));
    }
    return v;
}

// ---------------------------------------------------------------------------
// Job -- written and read exclusively by the event loop thread
// ---------------------------------------------------------------------------
struct StratumJob {
    std::string jobId;
    CBlock      block;
    uint256     target;  // full block target; share targets are per-miner via vardiff
    int         height;
};
static StratumJob gCurrentJob;
static bool       gHaveJob = false;

// Compute a share target from a Stratum difficulty value.
// Stratum difficulty 1 must correspond to THIS chain's easiest allowed target
// (bnProofOfWorkLimit = ~uint256(0) >> 12, compact 0x1f0fffff), not Bitcoin's
// SHA256 diff-1 target (0x1d00ffff). Those differ by about 2^20 (~1e6x):
// Bitcoin's diff-1 needs ~2^32 hashes/share on average, while this chain's PoW
// floor needs only ~2^12. Using the Bitcoin constant made every miner's
// "difficulty 1" about a million times harder than the chain's own floor, so a
// worker could hash for minutes without ever finding a share -- and vardiff
// never gets the samples it needs to correct course, because no share ever
// comes in for it to measure. Base off the actual chain limit instead so
// difficulty 1 is genuinely easy and vardiff has real data to retarget from.
// Higher difficulty = smaller (harder) target.
static uint256 ShareTargetFromDifficulty(double difficulty)
{
    if (difficulty <= 0.0) difficulty = 1.0;
    static const uint256 diff1 = CBigNum(bnProofOfWorkLimit).getuint256();
    // shareTarget = diff1 / difficulty
    CBigNum bn; bn.setuint256(diff1);
    // Multiply by 2^16 to keep precision, divide, shift back
    bn <<= 16;
    bn /= (uint64)(difficulty * 65536.0);
    uint256 t = bn.getuint256();
    // Cap at all-ones (maximum, easiest possible)
    if (t < diff1 && difficulty < 1.0) t = ~uint256(0);
    return t;
}

// Expected number of hashes to find one share at a given Stratum difficulty,
// on this chain's scale (difficulty 1 == bnProofOfWorkLimit, which needs on
// average 2^12 = 4096 hashes). Used to turn "shares per second" into H/s.
static const double SHARE_HASHES_AT_DIFF_1 = 4096.0;
static double ExpectedHashesForDifficulty(double difficulty)
{
    if (difficulty <= 0.0) difficulty = 1.0;
    return difficulty * SHARE_HASHES_AT_DIFF_1;
}

// Rebuild the current job from the best chain tip.
// Must be called from the event loop thread (or startup, before the loop).
// Returns true on success. Logs the specific failure reason on false.
static bool RebuildJob()
{
    CRITICAL_BLOCK(cs_main)
    {
        if (!pindexBest) {
            LogPrint("pool", "RebuildJob: no chain tip (pindexBest is null)\n");
            return false;
        }

        CBlockIndex* pindexPrev = pindexBest;
        unsigned int nBits = GetNextWorkRequired(pindexPrev);

        // From the pool, so the template's payout key is in wallet.dat before
        // any miner is handed work against it.
        vector<unsigned char> vchPubKey = GetKeyFromPool();
        static std::atomic<uint32_t> sExtra{0};
        uint32_t extraNonce = ++sExtra;

        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vin[0].prevout.SetNull();
        // Height first, for the reason given at the matching line in
        // BitcoinMiner: it is what keeps two coinbases at different heights
        // from ever being byte-identical. This builder was missed when that
        // went in, and it produces real blocks -- a pool operator's template
        // is mined and submitted like any other. #58.
        txNew.vin[0].scriptSig << (pindexPrev ? pindexPrev->nHeight + 1 : 0) << nBits << (CBigNum)extraNonce;
        txNew.vout.resize(1);
        txNew.vout[0].scriptPubKey << vchPubKey << OP_CHECKSIG;

        CBlock block;
        block.vtx.push_back(txNew);

        {
            CTxDB txdb("r");
            CRITICAL_BLOCK(cs_mapTransactions)
            {
                map<uint256, CTxIndex> pool;
                unsigned int sz = 0;
                for (auto& kv : mapTransactions) {
                    CTransaction& tx = kv.second;
                    if (tx.IsCoinBase() || !tx.IsFinal()) continue;
                    int64 nFees = 0;
                    map<uint256, CTxIndex> tmp(pool);
                    if (!tx.ConnectInputs(txdb, tmp, CDiskTxPos(1,1,1), 0, nFees,
                                          false, true, tx.GetMinFee(block.vtx.size() < 100)))
                        continue;
                    pool = tmp;
                    block.vtx.push_back(tx);
                    sz += ::GetSerializeSize(tx, SER_NETWORK);
                    if (sz > MAX_SIZE / 2) break;
                }
            }
        }

        block.vtx[0].vout[0].nValue = block.GetBlockValue(pindexPrev->nHeight + 1, 0);
        block.hashPrevBlock  = pindexPrev->GetBlockHash();
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.nTime = max((unsigned int)(pindexPrev->GetMedianTimePast() + 1),
                          (unsigned int)GetAdjustedTime());
        block.nBits  = nBits;
        block.nNonce = 1;
        // No AddKey here: the pool wrote this key to wallet.dat before it was
        // handed out.

        StratumJob job;
        job.jobId       = ToHex(&extraNonce, 4);
        job.block       = block;
        job.target      = CBigNum().SetCompact(nBits).getuint256();
        job.height      = nBestHeight + 1;

        gCurrentJob = job;
        gHaveJob    = true;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Payouts -- event loop thread only
// ---------------------------------------------------------------------------
struct PendingPayout {
    int                          matureAtHeight;
    std::map<std::string, int64> amounts; // address -> satoshis
};
static std::vector<PendingPayout> gPendingPayouts;

static std::string PayoutFilePath()
{
    return GetAppDir() + "/pending_payouts.json";
}

static void SavePendingPayouts()
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& pp : gPendingPayouts) {
        nlohmann::json obj;
        obj["matureAtHeight"] = pp.matureAtHeight;
        nlohmann::json amounts = nlohmann::json::object();
        for (const auto& kv : pp.amounts)
            amounts[kv.first] = kv.second;
        obj["amounts"] = amounts;
        arr.push_back(obj);
    }
    std::string path = PayoutFilePath();
    FILE* f = fopen(path.c_str(), "w");
    if (f) {
        std::string s = arr.dump(2);
        fwrite(s.c_str(), 1, s.size(), f);
        fclose(f);
    } else {
        LogPrint("payout", "[payout] WARNING: could not write %s\n", path.c_str());
    }
}

static void LoadPendingPayouts()
{
    std::string path = PayoutFilePath();
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return; // no file yet -- first run, nothing to load
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::string s(sz, '\0');
    fread(&s[0], 1, sz, f);
    fclose(f);
    try {
        nlohmann::json arr = nlohmann::json::parse(s);
        for (const auto& obj : arr) {
            PendingPayout pp;
            pp.matureAtHeight = obj["matureAtHeight"].get<int>();
            for (auto it = obj["amounts"].begin(); it != obj["amounts"].end(); ++it)
                pp.amounts[it.key()] = it.value().get<int64>();
            gPendingPayouts.push_back(pp);
        }
        LogPrint("payout", "[payout] loaded %zu pending payout(s) from disk\n",
                 gPendingPayouts.size());
    } catch (const std::exception& e) {
        LogPrint("payout", "[payout] WARNING: failed to parse %s: %s\n",
                 path.c_str(), e.what());
    }
}

// Payouts ready to execute are moved here under gPayoutExecMutex.
// A dedicated thread drains this list so SendMoney (which takes cs_main)
// never runs on the event loop thread and can't stall miner I/O.
static std::vector<PendingPayout> gPayoutExecQueue;
static std::mutex                 gPayoutExecMutex;
static std::atomic<bool>          gPayoutThreadRunning{false};

static void QueuePayouts(int blockHeight,
                         const std::map<std::string, uint64>& shareCount,
                         uint64 total)
{
    if (total == 0) {
        LogPrint("payout", "[payout] block %d: zero shares recorded -- nothing to pay out\n",
                 blockHeight);
        return;
    }

    double feeFrac = dPoolFeePercent / 100.0;
    if (feeFrac < 0.0) feeFrac = 0.0;
    if (feeFrac > 1.0) feeFrac = 1.0;

    // Compute the block subsidy at the height that was just found.
    // We do not include tx fees in miner payout -- those stay in the operator
    // wallet as part of the coinbase, which is the operator's cut on top of feeFrac.
    int64 nSubsidy = 50 * COIN;
    nSubsidy >>= (blockHeight / 210000); // halving schedule
    int64 minerReward = (int64)((double)nSubsidy * (1.0 - feeFrac));

    PendingPayout pp;
    pp.matureAtHeight = blockHeight + COINBASE_MATURITY;

    int skipped = 0;
    int64 burned = 0; // amount owed to miners with bad/empty addresses
    for (auto& kv : shareCount) {
        int64 amount = (int64)(((double)kv.second / (double)total) * (double)minerReward);
        if (amount < CENT) {
            skipped++;
            continue;
        }
        uint160 addrCheck;
        if (kv.first.empty() || !AddressToHash160(kv.first, addrCheck)) {
            // Address was invalid at authorize time (warned then). Their share
            // of the reward cannot be paid -- log the amount so it's visible.
            burned += amount;
            LogPrint("payout", "[payout] WARNING: %s owed to miner with invalid"
                     " address '%s' -- cannot pay out, amount forfeited\n",
                     FormatMoney(amount).c_str(), kv.first.c_str());
            continue;
        }
        pp.amounts[kv.first] = amount;
    }

    gPendingPayouts.push_back(pp);
    SavePendingPayouts();

    int64 operatorCut = nSubsidy - minerReward;
    LogPrint("payout",
             "[payout] block %d: subsidy %s BTF, miners get %s"
             " (fee %.2f%% = %s to operator),"
             " %zu recipients, matures height %d,"
             " %d below dust%s\n",
             blockHeight,
             FormatMoney(nSubsidy).c_str(),
             FormatMoney(minerReward).c_str(),
             dPoolFeePercent,
             FormatMoney(operatorCut).c_str(),
             pp.amounts.size(), pp.matureAtHeight, skipped,
             burned > 0 ? (", " + FormatMoney(burned) + " forfeited (bad address)").c_str()
                        : "");
}

// Called from event loop: move matured entries to the exec queue (fast).
// NOT crash-safe, despite the ordering below looking like it is.
//
// A matured payout is erased from gPendingPayouts, the file is rewritten
// without it, and only then does it reach the exec queue -- which lives in
// memory alone. SavePendingPayouts writes gPendingPayouts and nothing else;
// there is no exec-queue section of the file to recover from. Die anywhere
// between the rewrite and SendMoney and those miners are simply never paid,
// with no record that they were owed anything.
//
// Making this safe needs the payment to be idempotent -- record the txid and
// check the wallet for it on restart -- rather than a reordering, since
// re-queueing blindly would double-pay whoever was already sent to.
static void FlushMaturePayouts()
{
    std::vector<PendingPayout> ready;
    for (auto it = gPendingPayouts.begin(); it != gPendingPayouts.end(); ) {
        if (nBestHeight < it->matureAtHeight) { ++it; continue; }
        LogPrint("payout", "[payout] block height %d matured -- queuing %zu payments\n",
                 it->matureAtHeight, it->amounts.size());
        ready.push_back(*it);   // copy first; erase after save
        ++it;
    }
    if (!ready.empty()) {
        // Erase from pending then save before handing off to exec thread,
        // so the file never contains an entry that is already being sent.
        for (auto it = gPendingPayouts.begin(); it != gPendingPayouts.end(); ) {
            if (nBestHeight >= it->matureAtHeight)
                it = gPendingPayouts.erase(it);
            else
                ++it;
        }
        SavePendingPayouts();
        std::lock_guard<std::mutex> lk(gPayoutExecMutex);
        for (auto& pp : ready)
            gPayoutExecQueue.push_back(std::move(pp));
    }
}

// Payout execution thread: drains gPayoutExecQueue, calls SendMoney.
// Runs independently of the event loop so slow wallet operations
// (SendMoney takes cs_main) never stall miner I/O.
static void PayoutThreadFn(void*)
{
    gPayoutThreadRunning = true;
    LogPrint("payout", "[payout] payout thread started\n");

    while (!fShutdown && gPoolRunning) {
        std::vector<PendingPayout> batch;
        {
            std::lock_guard<std::mutex> lk(gPayoutExecMutex);
            batch.swap(gPayoutExecQueue);
        }

        for (auto& pp : batch) {
            LogPrint("payout", "[payout] executing payments for block matured at %d"
                     " (%zu miners)\n", pp.matureAtHeight, pp.amounts.size());
            for (auto& kv : pp.amounts) {
                uint160 h160;
                if (!AddressToHash160(kv.first, h160)) {
                    // Should not happen -- bad addresses are filtered in QueuePayouts
                    LogPrint("payout", "[payout] SKIPPED bad address '%s'\n",
                             kv.first.c_str());
                    continue;
                }
                CScript sc;
                sc << OP_DUP << OP_HASH160 << h160 << OP_EQUALVERIFY << OP_CHECKSIG;
                CWalletTx wtx;
                wtx.mapValue["comment"] = strprintf("Pool payout height %d",
                                                     pp.matureAtHeight);
                if (SendMoney(sc, kv.second, wtx))
                    LogPrint("payout", "[payout] paid %s to %s\n",
                             FormatMoney(kv.second).c_str(), kv.first.c_str());
                else
                    LogPrint("payout", "[payout] FAILED to pay %s to %s"
                             " (insufficient funds or wallet locked?)\n",
                             FormatMoney(kv.second).c_str(), kv.first.c_str());
            }
        }

        Sleep(500); // check for new work every 500ms
    }

    gPayoutThreadRunning = false;
    LogPrint("payout", "[payout] payout thread stopped\n");
}

// ---------------------------------------------------------------------------
// GUI stats snapshot -- event loop writes, GUI threads read
// ---------------------------------------------------------------------------
struct StatsSnapshot {
    int    authorizedMiners = 0;
    int    blocksFound      = 0;
    uint64 roundShares      = 0;
    double totalHashRate    = 0.0;
};
static StatsSnapshot                   gStats;
static std::vector<PoolWorkerStatView> gWorkerStats;
static std::vector<PendingPayoutView>  gPayoutViews;
static std::mutex                      gStatsMutex;

void GetPoolOperatorStats(int& authorizedMiners, int& blocksFound, uint64& roundShares, double& totalHashRate)
{
    std::lock_guard<std::mutex> lk(gStatsMutex);
    authorizedMiners = gStats.authorizedMiners;
    blocksFound      = gStats.blocksFound;
    roundShares      = gStats.roundShares;
    totalHashRate    = gStats.totalHashRate;
}

void GetPoolWorkerStats(std::vector<PoolWorkerStatView>& out)
{
    std::lock_guard<std::mutex> lk(gStatsMutex);
    out = gWorkerStats;
}

void GetPendingPayouts(std::vector<PendingPayoutView>& out)
{
    std::lock_guard<std::mutex> lk(gStatsMutex);
    out = gPayoutViews;
}

// ---------------------------------------------------------------------------
// Miner state -- event loop thread only
// ---------------------------------------------------------------------------
static std::atomic<uint32_t> gNextExtranonce2{1};

// Vardiff target: aim for one share every VARDIFF_TARGET_SECS seconds per miner.
// After VARDIFF_SHARES_PER_CHECK shares, recalculate and adjust if rate is off
// by more than 50%. Shares are the stable unit; difficulty floats to match.
static const int64  VARDIFF_TARGET_SECS       = 15;  // one share every 15s
static const uint64 VARDIFF_SHARES_PER_CHECK  = 5;   // re-evaluate every 5 shares
static const double VARDIFF_RETARGET_RATIO    = 1.5; // adjust if >50% off target
static const double VARDIFF_MIN               = 0.001;
static const double VARDIFF_MAX               = 1e12;
// If a miner has gone this long since its vardiff window opened with ZERO
// shares, the normal vardiff retarget (which only fires after
// VARDIFF_SHARES_PER_CHECK shares) can never trigger -- it has no samples to
// act on. This is the residual gap the ShareTargetFromDifficulty fix above
// doesn't cover: even with a correctly-easy diff-1 target, a miner stuck in
// RandomX light mode (or otherwise much slower than expected) can go
// indefinitely without a single share, and difficulty would never drop to
// meet it. Force a difficulty cut on a timeout instead of waiting for shares
// that will never come.
static const int64  VARDIFF_STALL_SECS        = 45;  // 3x share target -- reacts faster without false-triggering on normal variance
static const double VARDIFF_STALL_CUT         = 4.0; // divide difficulty by this much

struct Miner {
    btf_socket_t fd;
    bool         authorised    = false;
    std::string  address;
    std::string  worker;
    std::string  readBuf;
    int64        connectTime;
    uint64       sessionShares  = 0;
    uint64       roundShares    = 0;
    uint64       totalShares    = 0;
    int64        lastSeen       = 0;
    uint32_t     extranonce2;

    // Vardiff state
    double       difficulty     = 1.0;   // current share difficulty sent to this miner
    uint256      shareTarget;            // derived from difficulty; what we check against
    int64        vardiffWindowStart = 0; // when the current vardiff window opened
    uint64       vardiffShares  = 0;     // shares found in current window

    // Hashrate estimate -- EWMA of (expected hashes per share at current
    // difficulty) / (seconds since the previous share). We had all the data
    // to compute this (difficulty + share timing) but never actually did,
    // so pool/GUI hashrate always showed as zero/missing.
    int64        lastShareTime  = 0;     // GetTime() of the previous accepted share
    double       hashRate       = 0.0;   // smoothed H/s estimate

    explicit Miner(btf_socket_t f)
        : fd(f), connectTime(GetTime()),
          extranonce2(gNextExtranonce2.fetch_add(1)) {}
};

static std::vector<Miner*> gMiners;

struct FoundBlock { int height; int64 ts; std::string addr; };
static std::deque<FoundBlock> gFoundBlocks;

// ---------------------------------------------------------------------------
// Accept queue -- accept threads push; event loop pops at top of each tick
// ---------------------------------------------------------------------------
static std::vector<btf_socket_t> gReadyQueue;
static std::mutex                gReadyMutex;

static void PushReady(btf_socket_t s)
{
    std::lock_guard<std::mutex> lk(gReadyMutex);
    gReadyQueue.push_back(s);
}

// ---------------------------------------------------------------------------
// I/O helpers -- event loop thread only
// ---------------------------------------------------------------------------

// Blocking send of a complete JSON line. Called only from the event loop so
// no other thread is writing to the same fd concurrently.
static bool SendLine(btf_socket_t fd, const json& j)
{
    std::string s = j.dump() + "\n";
    int off = 0, total = (int)s.size();
    while (off < total) {
        int r = send(fd, s.c_str() + off, total - off, SEND_FLAGS);
        if (r <= 0) return false;
        off += r;
    }
    return true;
}

// Ceilings on what an unauthenticated peer can make the pool operator hold.
// Stratum lines are a few hundred bytes and a real pool this size will not see
// anything near a thousand miners.
static const size_t MAX_STRATUM_LINE = 64 * 1024;
static const size_t MAX_POOL_MINERS  = 1000;

// Non-blocking recv: pull whatever bytes are available now into buf, then
// return one complete line if one is ready. Three outcomes:
//   true  -- line is filled; buf may still contain more lines
//   false, errno EAGAIN/EWOULDBLOCK (or FIONREAD==0) -- no data right now
//   false, r==0 -- clean disconnect; caller must treat fd as dead
// Caller distinguishes disconnect from "not yet" by checking whether
// line.empty() after a false return (line is "" on both paths, so we
// use a separate out-param for the disconnect signal).
static bool RecvLine(btf_socket_t fd, std::string& buf,
                     std::string& line, bool& disconnected)
{
    disconnected = false;
    char tmp[4096];

#ifdef _WIN32
    u_long avail = 0;
    ioctlsocket(fd, FIONREAD, &avail);
    if (avail > 0) {
        int r = recv(fd, tmp, (int)std::min((u_long)(sizeof(tmp)-1), avail), 0);
        if (r > 0)      { tmp[r] = 0; buf += tmp; }
        else if (r == 0){ disconnected = true; return false; }
        // r < 0: WSAEWOULDBLOCK -- fall through with what we have
    }
#else
    {
        int r = recv(fd, tmp, sizeof(tmp) - 1, MSG_DONTWAIT);
        if (r > 0)       { tmp[r] = 0; buf += tmp; }
        else if (r == 0) { disconnected = true; return false; }
        // r < 0: EAGAIN/EWOULDBLOCK -- fall through with what we have
    }
#endif

    // A peer that never sends a newline would otherwise grow this buffer for
    // as long as it keeps writing, and it does not have to authorize first --
    // the read happens before any of that. Stratum lines are a few hundred
    // bytes; anything past the cap is not a slow line, it is a flood.
    if (buf.size() > MAX_STRATUM_LINE) {
        disconnected = true;
        buf.clear();
        return false;
    }

    size_t pos = buf.find('\n');
    if (pos == std::string::npos) return false; // no complete line yet

    line = buf.substr(0, pos);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    buf = buf.substr(pos + 1);
    return true;
}

// ---------------------------------------------------------------------------
// Job helpers
// ---------------------------------------------------------------------------
static CBlock BuildMinerBlock(const StratumJob& job, uint32_t extranonce2)
{
    CBlock blk = job.block;
    blk.vtx[0].vin[0].scriptSig << (CBigNum)extranonce2;
    blk.hashMerkleRoot = blk.BuildMerkleTree();
    return blk;
}

// shareTarget is per-miner (set by vardiff) and passed explicitly so the
// value in p[3] of mining.notify always matches what HandleLine checks on submit.
// This is the single source of truth for share difficulty.
static json MakeNotifyParams(const StratumJob& job, const CBlock& b,
                              const uint256& shareTarget, bool clean)
{
    unsigned char hdr[80];
    memcpy(hdr,    &b.nVersion,       4);
    memcpy(hdr+4,  &b.hashPrevBlock,  32);
    memcpy(hdr+36, &b.hashMerkleRoot, 32);
    memcpy(hdr+68, &b.nTime,          4);
    memcpy(hdr+72, &b.nBits,          4);
    memcpy(hdr+76, &b.nNonce,         4);
    unsigned char tgt[32]; memcpy(tgt, &shareTarget, 32);
    return json::array({job.jobId, ToHex(hdr, 80),
                        b.hashPrevBlock.GetHex(), ToHex(tgt, 32), clean});
}

static void SendJob(Miner* m, bool clean)
{
    if (!gHaveJob) return;
    CBlock mb = BuildMinerBlock(gCurrentJob, m->extranonce2);
    // Use this miner's own shareTarget (set by vardiff) in the notify params.
    // The participant miner reads p[3] as its share target, and HandleLine
    // checks m->shareTarget on submit -- both sides now use the same value.
    json n = {{"id",nullptr},{"method","mining.notify"},
              {"params", MakeNotifyParams(gCurrentJob, mb, m->shareTarget, clean)}};
    if (!SendLine(m->fd, n))
        LogPrint("worker", "[pool->worker] job send FAILED for %s -- miner will be dropped\n",
                 m->address.empty() ? "(not yet authorized)" : m->address.c_str());
}

static void BroadcastJob(bool clean)
{
    if (!gHaveJob) return;
    int sent = 0;
    for (Miner* m : gMiners) {
        if (!m->authorised) continue;
        SendJob(m, clean);
        sent++;
    }
    LogPrint("pool", "[pool] job %s broadcast to %d miner(s)\n",
             gCurrentJob.jobId.c_str(), sent);
}

// ---------------------------------------------------------------------------
// Stratum message handler -- called for each complete line from a miner
// Returns false if the miner should be disconnected immediately.
// ---------------------------------------------------------------------------
static bool HandleLine(Miner* m, const std::string& rawLine,
                       std::map<std::string, uint64>& roundShareCount,
                       uint64& roundShareTotal,
                       int& blocksFoundThisSession)
{
    json req;
    try {
        // Fast pre-parse depth check to prevent stack overflow in json::parse.
        // Legitimate Stratum requests have a depth of at most 4.
        int depth = 0;
        bool in_string = false;
        bool escape = false;
        for (char c : rawLine) {
            if (in_string) {
                if (escape) escape = false;
                else if (c == '\\') escape = true;
                else if (c == '"') in_string = false;
            } else {
                if (c == '"') in_string = true;
                else if (c == '{' || c == '[') {
                    if (++depth > 20) {
                        LogPrint("worker", "[worker] JSON too deeply nested from %s\n",
                                 m->address.empty() ? "(unauth)" : m->address.c_str());
                        return true;
                    }
                } else if (c == '}' || c == ']') {
                    depth--;
                }
            }
        }
        req = json::parse(rawLine);
    }
    catch (...) {
        LogPrint("worker", "[worker] JSON parse error from %s: %.80s\n",
                 m->address.empty() ? "(unauth)" : m->address.c_str(),
                 rawLine.c_str());
        return true; // don't disconnect on bad JSON, just ignore the line
    }

    // value() throws when the document is not an object, and again when a key
    // is present with the wrong type -- "[1,2,3]" and {"method":1} are both
    // valid JSON that parse cleanly and then blow up on the next two lines.
    if (!req.is_object() || (req.contains("method") && !req["method"].is_string())) {
        LogPrint("worker", "[worker] malformed request from %s: %.80s\n",
                 m->address.empty() ? "(unauth)" : m->address.c_str(),
                 rawLine.c_str());
        return true;
    }

    json        id     = req.value("id", json(nullptr));
    std::string method = req.value("method", "");

    // Reply helper: always sends result+error pair as Stratum requires
    auto reply = [&](json result, std::string error = "") {
        json err = error.empty() ? json(nullptr) : json(error);
        if (!SendLine(m->fd, json{{"id",id},{"result",result},{"error",err}}))
            LogPrint("worker", "[pool->worker] reply send FAILED for %s (method=%s)\n",
                     m->address.empty() ? "(unauth)" : m->address.c_str(),
                     method.c_str());
    };

    // ------------------------------------------------------------------
    if (method == "mining.subscribe") {
        std::string sid = ToHex(&m->fd, 4);
        LogPrint("worker", "[worker->pool] subscribe from fd=%d sid=%s\n",
                 (int)m->fd, sid.c_str());
        reply(json::array({json::array({json::array({"mining.notify",sid})}),sid,4}));
        return true;
    }

    // ------------------------------------------------------------------
    if (method == "mining.authorize") {
        // is_array() matters as much as the element checks: indexing a json
        // object with a number throws, and size() on an object returns its key
        // count, so "params":{"a":1} would pass a bare size() test.
        auto& p = req["params"];
        bool fArr = p.is_array();
        m->address = (fArr && p.size() > 0 && p[0].is_string()) ? p[0].get<std::string>() : "";
        m->worker  = (fArr && p.size() > 1 && p[1].is_string()) ? p[1].get<std::string>() : "worker";
        m->lastSeen = GetTime();

        // Validate address before authorising
        uint160 h160; bool validAddr = AddressToHash160(m->address, h160);

        m->authorised = true; // authorise regardless -- shares just won't pay out
        LogPrint("worker", "[worker->pool] authorize address=%s worker=%s addr_valid=%s\n",
                 m->address.c_str(), m->worker.c_str(), validAddr ? "yes" : "NO");

        if (!validAddr)
            LogPrint("worker", "[pool] WARNING: address '%s' is invalid -- "
                     "miner will hash but shares cannot be paid out\n",
                     m->address.c_str());

        reply(true);

        // Initialize vardiff state and send initial difficulty
        m->difficulty       = 1.0;
        m->shareTarget      = ShareTargetFromDifficulty(m->difficulty);
        m->vardiffWindowStart = GetTime();
        m->vardiffShares    = 0;
        LogPrint("worker", "[pool->worker] initial difficulty=%.4f for %s\n",
                 m->difficulty, m->address.c_str());
        if (!SendLine(m->fd, json{{"id",nullptr},{"method","mining.set_difficulty"},
                                  {"params",json::array({m->difficulty})}}))
            LogPrint("worker", "[pool->worker] set_difficulty send FAILED for %s\n",
                     m->address.c_str());

        if (gHaveJob) {
            LogPrint("worker", "[pool->worker] sending job %s to %s\n",
                     gCurrentJob.jobId.c_str(), m->address.c_str());
            SendJob(m, true);
        } else {
            LogPrint("worker", "[pool->worker] no job available yet for %s"
                     " -- will be sent one as soon as the pool builds it\n",
                     m->address.c_str());
        }
        return true;
    }

    // ------------------------------------------------------------------
    if (method == "mining.extranonce.subscribe") { reply(true); return true; }
    if (method == "mining.get_transactions")     { reply(json::array()); return true; }

    // ------------------------------------------------------------------
    if (method == "mining.submit") {
        if (!m->authorised) {
            LogPrint("worker", "[worker->pool] submit from unauthorized miner (fd=%d)\n",
                     (int)m->fd);
            reply(false, "not authorised");
            return true;
        }

        auto& p = req["params"];
        // Check the shape as well as the length: a submit carrying
        // "params":[1,2,3] would otherwise reach get<std::string>() and throw
        // a json::type_error that nothing above catches, taking the pool down
        // with it. Authorising costs an attacker nothing but an address.
        if (!p.is_array() || p.size() < 3 || !p[1].is_string() || !p[2].is_string()) {
            LogPrint("worker", "[worker->pool] submit bad params from %s\n",
                     m->address.c_str());
            reply(false, "bad params");
            return true;
        }

        std::string submitJobId = p[1].get<std::string>();
        std::string nonceHex    = p[2].get<std::string>();

        if (!gHaveJob) {
            LogPrint("worker", "[worker->pool] submit from %s but pool has no current job\n",
                     m->address.c_str());
            reply(false, "stale job");
            return true;
        }
        if (gCurrentJob.jobId != submitJobId) {
            LogPrint("worker", "[worker->pool] submit stale job from %s"
                     " (submitted=%s current=%s)\n",
                     m->address.c_str(), submitJobId.c_str(), gCurrentJob.jobId.c_str());
            reply(false, "stale job");
            return true;
        }

        auto nb = FromHex(nonceHex);
        if (nb.size() < 4) {
            LogPrint("worker", "[worker->pool] submit bad nonce from %s: '%s'\n",
                     m->address.c_str(), nonceHex.c_str());
            reply(false, "bad nonce");
            return true;
        }
        unsigned int nNonce; memcpy(&nNonce, nb.data(), 4);

        // Rebuild this miner's exact block (unique merkle via extranonce2)
        CBlock b = BuildMinerBlock(gCurrentJob, m->extranonce2);
        b.nNonce = nNonce;
        unsigned char hdr[80];
        memcpy(hdr,    &b.nVersion,       4);
        memcpy(hdr+4,  &b.hashPrevBlock,  32);
        memcpy(hdr+36, &b.hashMerkleRoot, 32);
        memcpy(hdr+68, &b.nTime,          4);
        memcpy(hdr+72, &b.nBits,          4);
        memcpy(hdr+76, &b.nNonce,         4);

        uint256 powHash = RandomXPoWHash(hdr, 80);

        // Check against this miner's personal share target (set by vardiff)
        if (powHash > m->shareTarget) {
            LogPrint("worker", "[worker->pool] high-hash from %s"
                     " nonce=%u (difficulty=%.4f)\n",
                     m->address.c_str(), nNonce, m->difficulty);
            reply(false, "high-hash");
            return true;
        }

        // Valid share -- record it
        m->sessionShares++;
        m->roundShares++;
        m->totalShares++;
        m->vardiffShares++;
        int64 shareTime = GetTime();
        m->lastSeen = shareTime;
        roundShareCount[m->address]++;
        roundShareTotal++;

        // Update hashrate estimate: expected hashes for this share divided by
        // the time since the last one, smoothed with an EWMA so a single fast
        // or slow share doesn't make the number jump around.
        if (m->lastShareTime > 0) {
            int64 dt = shareTime - m->lastShareTime;
            if (dt <= 0) dt = 1;
            double inst = ExpectedHashesForDifficulty(m->difficulty) / (double)dt;
            const double alpha = 0.25;
            m->hashRate = (m->hashRate <= 0.0) ? inst
                                                : alpha * inst + (1.0 - alpha) * m->hashRate;
        }
        m->lastShareTime = shareTime;

        LogPrint("worker", "[worker->pool] valid share from %s"
                 " nonce=%u job=%s difficulty=%.4f (session: %llu)\n",
                 m->address.c_str(), nNonce,
                 gCurrentJob.jobId.c_str(), m->difficulty,
                 (unsigned long long)m->sessionShares);
        reply(true);

        // Vardiff: after every VARDIFF_SHARES_PER_CHECK shares, check rate
        if (m->vardiffShares >= VARDIFF_SHARES_PER_CHECK) {
            int64 elapsed = GetTime() - m->vardiffWindowStart;
            if (elapsed <= 0) elapsed = 1;
            double actualSecsPerShare = (double)elapsed / (double)m->vardiffShares;
            double ratio = actualSecsPerShare / (double)VARDIFF_TARGET_SECS;
            // ratio < 1 means shares arriving faster than target (too easy)
            // ratio > 1 means shares arriving slower than target (too hard)
            if (ratio < (1.0 / VARDIFF_RETARGET_RATIO) ||
                ratio > VARDIFF_RETARGET_RATIO) {
                // New difficulty scales inversely with actual share rate
                double newDiff = m->difficulty / ratio;
                if (newDiff < VARDIFF_MIN) newDiff = VARDIFF_MIN;
                if (newDiff > VARDIFF_MAX) newDiff = VARDIFF_MAX;
                // Only apply if the change is meaningful (>10%)
                if (newDiff / m->difficulty > 1.1 || m->difficulty / newDiff > 1.1) {
                    m->difficulty    = newDiff;
                    m->shareTarget   = ShareTargetFromDifficulty(m->difficulty);
                    LogPrint("worker", "[pool] vardiff: %s new difficulty=%.4f"
                             " (%.1fs/share actual vs %ds target)\n",
                             m->address.c_str(), m->difficulty,
                             actualSecsPerShare, (int)VARDIFF_TARGET_SECS);
                    SendLine(m->fd, json{{"id",nullptr},
                                        {"method","mining.set_difficulty"},
                                        {"params",json::array({m->difficulty})}});
                    // set_difficulty alone doesn't change what the worker
                    // actually hashes against -- it only reads its share
                    // target from mining.notify params[3]. Without this, the
                    // new difficulty wouldn't take effect until the next
                    // natural job broadcast (new block, or the 60s trickle
                    // refresh), so push a fresh notify for this miner now.
                    SendJob(m, false);
                }
            }
            // Reset window
            m->vardiffWindowStart = GetTime();
            m->vardiffShares      = 0;
        }

        if (powHash > gCurrentJob.target) return true; // valid share, not a block

        // Full difficulty met -- submit block to the chain
        LogPrint("pool", "[pool] BLOCK CANDIDATE from %s height=%d nNonce=%u -- submitting\n",
                 m->address.c_str(), gCurrentJob.height, nNonce);

        CBlock* pblock = new CBlock(b);
        bool accepted = false;
        CRITICAL_BLOCK(cs_main)
        {
            int heightBefore = nBestHeight;
            if (ProcessBlock(NULL, pblock)) {
                // ProcessBlock returns true for orphans too -- verify the chain
                // actually advanced. If nBestHeight didn't increase, the block
                // was shelved as an orphan (pool was behind the chain tip) and
                // no coinbase was added to the wallet. Do not pay out.
                if (nBestHeight > heightBefore) {
                    accepted = true;
                    LogPrint("pool", "[pool] BLOCK ACCEPTED height=%d by %s\n",
                             gCurrentJob.height, m->address.c_str());
                    gFoundBlocks.push_front({gCurrentJob.height, GetTime(), m->address});
                    if (gFoundBlocks.size() > 50) gFoundBlocks.pop_back();
                    blocksFoundThisSession++;
                    gHaveJob = false; // invalidate job immediately
                } else {
                    LogPrint("pool", "[pool] BLOCK ORPHANED height=%d by %s"
                             " -- pool was behind chain tip, no payout\n",
                             gCurrentJob.height, m->address.c_str());
                    gHaveJob = false; // job is stale regardless
                }
            } else {
                LogPrint("pool", "[pool] BLOCK REJECTED height=%d (ProcessBlock returned false)\n",
                         gCurrentJob.height);
                delete pblock;
            }
        }

        if (accepted) {
            // Snapshot height before RebuildJob() (which increments it)
            int foundHeight = gCurrentJob.height;
            QueuePayouts(foundHeight, roundShareCount, roundShareTotal);
            // Reset round shares
            roundShareCount.clear();
            roundShareTotal = 0;
            for (Miner* mi : gMiners) mi->roundShares = 0;
            // Build and broadcast new job immediately
            if (RebuildJob()) {
                LogPrint("pool", "[pool] new job %s built after block %d\n",
                         gCurrentJob.jobId.c_str(), foundHeight);
                BroadcastJob(true);
            } else {
                LogPrint("pool", "[pool] WARNING: RebuildJob() failed after block %d"
                         " -- miners will wait\n", foundHeight);
            }
        }
        return true;
    }

    // Unknown method -- log it (can reveal miner software quirks)
    LogPrint("worker", "[worker->pool] unknown method '%s' from %s\n",
             method.c_str(),
             m->address.empty() ? "(unauth)" : m->address.c_str());
    reply(nullptr, "unknown method");
    return true;
}

// ---------------------------------------------------------------------------
// Stats refresh -- called every 2s from event loop
// ---------------------------------------------------------------------------
static void RefreshStats(int blocksFoundThisSession, uint64 roundShareTotal)
{
    std::lock_guard<std::mutex> lk(gStatsMutex);

    gStats.authorizedMiners = 0;
    gStats.blocksFound      = blocksFoundThisSession;
    gStats.roundShares      = roundShareTotal;
    gStats.totalHashRate    = 0.0;
    for (Miner* m : gMiners)
        if (m->authorised) gStats.authorizedMiners++;

    gWorkerStats.clear();
    for (Miner* m : gMiners) {
        if (!m->authorised || m->lastSeen <= 0) continue;
        PoolWorkerStatView v;
        v.address     = m->address;
        v.worker      = m->worker;
        v.roundShares = m->roundShares;
        v.totalShares = m->totalShares;
        v.lastSeen    = m->lastSeen;
        v.hashRate    = m->hashRate;
        gWorkerStats.push_back(v);
        gStats.totalHashRate += m->hashRate;
    }
    std::sort(gWorkerStats.begin(), gWorkerStats.end(),
        [](const PoolWorkerStatView& a, const PoolWorkerStatView& b) {
            return a.roundShares != b.roundShares ? a.roundShares > b.roundShares
                                                  : a.lastSeen > b.lastSeen;
        });

    // gPendingPayouts is event-loop-only data (no lock needed here since
    // RefreshStats is always called from the event loop thread).
    gPayoutViews.clear();
    for (const PendingPayout& pp : gPendingPayouts) {
        PendingPayoutView pv;
        pv.matureAtHeight = pp.matureAtHeight;
        pv.recipients     = (int)pp.amounts.size();
        pv.totalAmount    = 0;
        for (auto& kv : pp.amounts) pv.totalAmount += kv.second;
        gPayoutViews.push_back(pv);
    }
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------
static void PoolEventLoop()
{
    int   lastHeight            = -1;
    int64 lastRefresh           = GetTime();
    int64 lastStatsRefresh      = 0;
    int   blocksFoundThisSession = 0;
    int64 noJobSince            = 0;   // 0 = have a job
    bool  warnedNoJob           = false;
    int64 lastNoJobRetry        = 0;   // throttle RebuildJob calls when no tip

    std::map<std::string, uint64> roundShareCount;
    uint64 roundShareTotal = 0;

    static const int64 JOB_REFRESH_SECS  = 60;  // re-stamp nTime periodically
    static const int64 NO_JOB_WARN_SECS  = 15;  // warn after this long with no job
    static const int64 NO_JOB_RETRY_SECS = 5;   // how often to retry RebuildJob

    while (!fShutdown && gPoolRunning) {

        // 1. Drain accept queue
        {
            std::lock_guard<std::mutex> lk(gReadyMutex);
            for (btf_socket_t fd : gReadyQueue) {
                // Connecting costs nothing and every accepted socket carries a
                // read buffer, so an unbounded miner list is an unbounded
                // allocation for whoever runs the pool.
                if (gMiners.size() >= MAX_POOL_MINERS) {
                    LogPrint("worker", "[pool] refusing miner fd=%d --"
                             " already at %zu connections\n",
                             (int)fd, gMiners.size());
                    sock_close(fd);
                    continue;
                }
                gMiners.push_back(new Miner(fd));
                LogPrint("worker", "[pool] miner fd=%d entered event loop"
                         " -- awaiting subscribe/authorize\n", (int)fd);
            }
            gReadyQueue.clear();
        }

        // 2. Detect new block.
        // When our own miner found the block, HandleLine already called
        // RebuildJob() + BroadcastJob(true) and set gHaveJob=true.
        // We still flush mature payouts and update bookkeeping, but skip
        // rebuilding if a fresh job already exists for this height.
        {
            bool newBlock = false;
            CRITICAL_BLOCK(cs_main)
            {
                if (pindexBest && nBestHeight != lastHeight) {
                    lastHeight = nBestHeight;
                    newBlock   = true;
                }
            }
            if (newBlock) {
                FlushMaturePayouts();
                if (!gHaveJob) {
                    // External block (not found by our miners), or HandleLine's
                    // RebuildJob failed. Either way this round is over with no
                    // payout from us, so clear round shares before starting the
                    // next one -- otherwise they'd keep accumulating across
                    // rounds that our own miners didn't win.
                    roundShareCount.clear();
                    roundShareTotal = 0;
                    for (Miner* mi : gMiners) mi->roundShares = 0;

                    // Build and broadcast now.
                    if (RebuildJob()) {
                        LogPrint("pool", "[pool] new block height=%d -- job %s ready,"
                                 " %zu miner(s) connected\n",
                                 lastHeight, gCurrentJob.jobId.c_str(), gMiners.size());
                        BroadcastJob(true);
                    } else {
                        LogPrint("pool", "[pool] new block height=%d but RebuildJob() failed"
                                 " -- miners will wait\n", lastHeight);
                    }
                } else {
                    // HandleLine already built and broadcast for this height.
                    LogPrint("pool", "[pool] new block height=%d -- job already"
                             " broadcast by submit handler\n", lastHeight);
                }
                lastRefresh  = GetTime();
                noJobSince   = 0;
                warnedNoJob  = false;
            }
        }

        // 3. No-job watchdog (throttled: only retry every NO_JOB_RETRY_SECS)
        if (!gHaveJob) {
            int64 now = GetTime();
            if (noJobSince == 0) noJobSince = now;

            if (now - lastNoJobRetry >= NO_JOB_RETRY_SECS) {
                lastNoJobRetry = now;
                if (RebuildJob()) {
                    LogPrint("pool", "[pool] job built after %llds without one\n",
                             (long long)(now - noJobSince));
                    BroadcastJob(false);
                    noJobSince  = 0;
                    warnedNoJob = false;
                    lastRefresh = now;
                } else if (!warnedNoJob && now - noJobSince >= NO_JOB_WARN_SECS) {
                    LogPrint("pool", "[pool] STUCK: no job for %llds -- %s."
                             " Miners are waiting. Will keep retrying every %llds.\n",
                             (long long)(now - noJobSince),
                             pindexBest ? "RebuildJob() keeps failing (check above for why)"
                                        : "no chain tip yet (node still syncing)",
                             (long long)NO_JOB_RETRY_SECS);
                    warnedNoJob = true;
                }
            }
        } else if (GetTime() - lastRefresh >= JOB_REFRESH_SECS) {
            // Periodic nTime refresh -- stale timestamps cause valid hashes to be rejected
            if (RebuildJob()) BroadcastJob(false);
            lastRefresh = GetTime();
        }

        // 3.5. Vardiff stall watchdog -- runs independently of share count.
        // The normal vardiff check in HandleLine only fires once
        // VARDIFF_SHARES_PER_CHECK shares have arrived; a miner that never
        // finds a single share never reaches that check, so it can be stuck
        // at its initial (or last) difficulty forever. Catch that here.
        for (Miner* m : gMiners) {
            if (!m->authorised || m->vardiffShares != 0 || m->vardiffWindowStart <= 0)
                continue;
            int64 stalled = GetTime() - m->vardiffWindowStart;
            if (stalled < VARDIFF_STALL_SECS) continue;

            double newDiff = m->difficulty / VARDIFF_STALL_CUT;
            if (newDiff < VARDIFF_MIN) newDiff = VARDIFF_MIN;

            if (newDiff < m->difficulty) {
                m->difficulty         = newDiff;
                m->shareTarget        = ShareTargetFromDifficulty(m->difficulty);
                m->vardiffWindowStart = GetTime();
                LogPrint("worker", "[pool] vardiff STALL: %s sent zero shares in"
                         " %llds -- forcing difficulty down to %.6f (no share data"
                         " to retarget from normally)\n",
                         m->address.c_str(), (long long)stalled, m->difficulty);
                SendLine(m->fd, json{{"id",nullptr},
                                    {"method","mining.set_difficulty"},
                                    {"params",json::array({m->difficulty})}});
                // Same reasoning as the normal vardiff retarget above: the
                // worker only reads its share target from mining.notify, so
                // push a fresh job now instead of waiting on the next
                // natural broadcast.
                SendJob(m, false);
            } else {
                // Already at the difficulty floor -- this miner's problem isn't
                // difficulty, it's something else (slow hashing, bad connection,
                // stuck RandomX light mode, etc). Log once per stall window so
                // it's visible without spamming.
                LogPrint("worker", "[pool] vardiff STALL: %s still at zero shares"
                         " after %llds at floor difficulty %.6f -- likely a"
                         " hashrate/connectivity problem, not a difficulty problem\n",
                         m->address.c_str(), (long long)stalled, m->difficulty);
                m->vardiffWindowStart = GetTime(); // avoid re-logging every tick
            }
        }

        // 4. Select over miner sockets
        if (!gMiners.empty()) {
            fd_set fds; FD_ZERO(&fds);
            int maxfd = 0;
            for (Miner* m : gMiners) {
                FD_SET(m->fd, &fds);
                if ((int)m->fd > maxfd) maxfd = (int)m->fd;
            }
            struct timeval tv = {0, 50000}; // 50ms
            if (select(maxfd + 1, &fds, NULL, NULL, &tv) > 0) {
                std::vector<Miner*> dead;
                for (Miner* m : gMiners) {
                    if (!FD_ISSET(m->fd, &fds)) continue;
                    std::string line;
                    bool disc = false;
                    // Drain all complete lines buffered for this miner.
                    // HandleLine always returns true; disc signals clean disconnect.
                    // ThreadRPCServer has no handler of its own, so anything
                    // thrown here would reach the top of the thread and
                    // terminate the whole node -- not just the pool. Every
                    // line arrives from an unauthenticated socket.
                    while (RecvLine(m->fd, m->readBuf, line, disc)) {
                        try {
                            HandleLine(m, line, roundShareCount,
                                       roundShareTotal, blocksFoundThisSession);
                        } catch (const std::exception& e) {
                            LogPrint("worker", "[pool] dropping miner %s --"
                                     " exception handling line: %s\n",
                                     m->address.empty() ? "(unauth)" : m->address.c_str(),
                                     e.what());
                            disc = true;
                            break;
                        } catch (...) {
                            LogPrint("worker", "[pool] dropping miner %s --"
                                     " unknown exception handling line\n",
                                     m->address.empty() ? "(unauth)" : m->address.c_str());
                            disc = true;
                            break;
                        }
                    }
                    if (disc) dead.push_back(m);
                }
                for (Miner* m : dead) {
                    LogPrint("worker", "[pool] miner %s disconnected"
                             " (session shares: %llu, round shares: %llu)\n",
                             m->worker.empty() ? "(never authorized)" : m->worker.c_str(),
                             (unsigned long long)m->sessionShares,
                             (unsigned long long)m->roundShares);
                    sock_close(m->fd);
                    gMiners.erase(std::find(gMiners.begin(), gMiners.end(), m));
                    delete m;
                }
            }
        } else {
            Sleep(50);
        }

        // 5. Refresh GUI stats every 2s
        if (GetTime() - lastStatsRefresh >= 2) {
            RefreshStats(blocksFoundThisSession, roundShareTotal);
            lastStatsRefresh = GetTime();
        }
    }

    for (Miner* m : gMiners) { sock_close(m->fd); delete m; }
    gMiners.clear();
}

// ---------------------------------------------------------------------------
// Accept threads
// ---------------------------------------------------------------------------
struct AcceptCtx { unsigned char pk[32]; unsigned char sk[32]; std::string relay; };

// One persistent thread per relay. Loops: register -> wrap -> push -> repeat.
static void AcceptOneFn(void* arg)
{
    AcceptCtx* ctx = (AcceptCtx*)arg;
    unsigned char pk[32], sk[32];
    memcpy(pk, ctx->pk, 32); memcpy(sk, ctx->sk, 32);
    std::string relay = ctx->relay;
    delete ctx;

    size_t colon = relay.rfind(':');
    if (colon == std::string::npos) {
        LogPrint("pool", "[pool] AcceptOneFn: bad relay address '%s'\n", relay.c_str());
        return;
    }
    std::string host = relay.substr(0, colon);
    int         port = atoi(relay.substr(colon + 1).c_str());

    LogPrint("pool", "[pool] accept thread started for relay %s\n", relay.c_str());

    while (!fShutdown && gPoolRunning) {
        // Blocks until a miner connects to us at this relay
        btf::RvSocket rv = btf::RvServiceRegister(host.c_str(), (unsigned short)port, pk);

        if (fShutdown || !gPoolRunning) {
            if (rv != btf::RV_INVALID) btf::RvClose(rv);
            break;
        }
        if (rv == btf::RV_INVALID) {
            LogPrint("pool", "[pool] relay %s: RvServiceRegister failed"
                     " -- backing off 30s before retry\n", relay.c_str());
            for (int i = 0; i < 30 && !fShutdown && gPoolRunning; i++) Sleep(1000);
            continue;
        }

        // Echan handshake -- blocking but fast (local + relay round-trip)
        btf_socket_t fd = btf::BtfServiceWrap(rv, sk);
        if (fd == INVALID_SOCKET) {
            LogPrint("pool", "[pool] relay %s: BtfServiceWrap failed (echan handshake)"
                     " -- miner dropped, will accept next\n", relay.c_str());
            continue;
        }

        LogPrint("worker", "[pool] miner arrived via relay %s -- pushing to event loop\n",
                 relay.c_str());
        PushReady(fd);
        // Loop immediately: register again so the next miner can connect
    }

    LogPrint("pool", "[pool] accept thread stopped for relay %s\n", relay.c_str());
}

// Spawns one AcceptOneFn per relay. Re-polls relay list every 60s to pick up
// newly discovered relays. Uses a set to avoid spawning duplicate threads.
static void AcceptLoopFn(void*)
{
    LogPrint("pool", "[pool] AcceptLoopFn started -- miners can connect via %s\n",
             BtfLocalAddress().c_str());

    // Wait for our identity to be ready
    unsigned char pk[32], sk[32];
    int waitSecs = 0;
    while (!BtfGetIdentity(pk, sk)) {
        if (fShutdown || !gPoolRunning) return;
        if (waitSecs == 0)
            LogPrint("pool", "[pool] waiting for .btf identity...\n");
        waitSecs++;
        Sleep(2000);
    }
    LogPrint("pool", "[pool] .btf identity ready after %ds\n", waitSecs * 2);

    std::set<std::string> spawned; // relays we've already started a thread for

    while (!fShutdown && gPoolRunning) {
        vector<string> relays = BtfAllRelays();
        if (relays.empty()) {
            LogPrint("pool", "[pool] no relays available -- miners cannot connect yet\n");
        } else {
            for (const string& relay : relays) {
                if (spawned.count(relay)) continue; // already running
                AcceptCtx* ctx = new AcceptCtx();
                memcpy(ctx->pk, pk, 32); memcpy(ctx->sk, sk, 32);
                ctx->relay = relay;
                uintptr_t tid = _beginthread(AcceptOneFn, 0, ctx);
                if (tid == (uintptr_t)-1) {
                    delete ctx;
                    LogPrint("pool", "[pool] failed to spawn accept thread for %s\n",
                             relay.c_str());
                } else {
                    spawned.insert(relay);
                    LogPrint("pool", "[pool] accept thread spawned for relay %s"
                             " (%zu total)\n", relay.c_str(), spawned.size());
                }
            }
        }
        // Re-poll every 60s -- newly discovered relays get picked up
        for (int i = 0; i < 60 && !fShutdown && gPoolRunning; i++) Sleep(1000);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
void ThreadRPCServer(void*)
{
    gPoolRunning = true;

    LogPrint("pool", "[pool] ============================================\n");
    LogPrint("pool", "[pool] Pool server starting\n");
    LogPrint("pool", "[pool] .btf address: %s\n", BtfLocalAddress().c_str());
    LogPrint("pool", "[pool] fee: %.2f%%\n", dPoolFeePercent);

    if (RebuildJob()) {
        LogPrint("pool", "[pool] initial job %s seeded at height %d\n",
                 gCurrentJob.jobId.c_str(), nBestHeight + 1);
    } else {
        LogPrint("pool", "[pool] no chain tip yet -- job will build on first block\n");
    }

    LoadPendingPayouts();

    _beginthread(AcceptLoopFn, 0, NULL);
    _beginthread(ThreadBtfPoolAnnouncer, 0, NULL);
    _beginthread(PayoutThreadFn, 0, NULL);

    PoolEventLoop(); // blocks until gPoolRunning = false or fShutdown

    LogPrint("pool", "[pool] pool server stopped\n");
    LogPrint("pool", "[pool] ============================================\n");
    gPoolRunning = false;
}
