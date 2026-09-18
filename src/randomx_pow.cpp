// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// RandomX PoW implementation. See randomx_pow.h.

#include "headers.h"
#include <randomx.h>
#include <openssl/sha.h>
#include <thread>
#include <vector>
#include <mutex>

// v1 key. The v2 key is SHA-256 of this string, computed once at init: 32
// bytes, which is the one size a RandomX miner accepts as seed_hash.
static const char* RANDOMX_KEY_V1 = "Bitflash/RandomX/v1/one-cpu-one-vote";
static unsigned char g_seedV2[32];
static bool          g_fSeedV2 = false;

static const unsigned char* SeedV2()
{
    if (!g_fSeedV2)
    {
        SHA256((const unsigned char*)RANDOMX_KEY_V1, strlen(RANDOMX_KEY_V1), g_seedV2);
        g_fSeedV2 = true;
    }
    return g_seedV2;
}

const unsigned char* PoWSeedV2() { return SeedV2(); }

std::string PoWSeedV2Hex()
{
    const unsigned char* s = SeedV2();
    std::string hex;
    static const char* d = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { hex += d[s[i] >> 4]; hex += d[s[i] & 15]; }
    return hex;
}

unsigned int PoWV2Time()
{
    return IsTestNet() ? POW_V2_TIME_TESTNET : POW_V2_TIME_MAINNET;
}

unsigned int RulesV2Time()
{
    return IsTestNet() ? RULES_V2_TIME_TESTNET : RULES_V2_TIME_MAINNET;
}

bool RulesV2Active(unsigned int nBlockTime)
{
    return nBlockTime >= RulesV2Time();
}

int PoWVersionAt(unsigned int nTime)
{
    return nTime >= PoWV2Time() ? 2 : 1;
}

// Header as serialized:  version 0..3 | prev 4..35 | merkle 36..67 |
//                        time 68..71 | bits 72..75 | nonce 76..79
// v2 input:              version 0..3 | prev 4..35 | zero 36..38 | nonce 39..42 |
//                        merkle 43..74 | time 75..78 | bits 79..82
// Every header field is covered once; the three zero bytes are what it takes
// to land the nonce at 39.
size_t PoWInputV2(const unsigned char* h, unsigned char* out)
{
    memcpy(out,      h,      36);   // version + prev
    memset(out + 36, 0,      3);
    memcpy(out + 39, h + 76, 4);    // nonce
    memcpy(out + 43, h + 36, 32);   // merkle
    memcpy(out + 75, h + 68, 8);    // time + bits
    return POW_INPUT_V2_SIZE;
}

size_t PoWInputFromHeader(const unsigned char* h, unsigned char* out, int* pnVersion)
{
    unsigned int nTime;
    memcpy(&nTime, h + 68, 4);
    int v = PoWVersionAt(nTime);
    if (pnVersion) *pnVersion = v;
    if (v == 2)
        return PoWInputV2(h, out);
    memcpy(out, h, 80);
    return 80;
}

// ---------------------------------------------------------------------------

static randomx_flags   g_flags   = RANDOMX_FLAG_DEFAULT;
static std::mutex      g_csInit;
static bool            g_fInit   = false;

// One of these per PoW version. Allocated on first use.
struct RxKeyState
{
    randomx_cache*   cache     = NULL;
    randomx_dataset* dataset   = NULL;
    randomx_vm*      vmVerify  = NULL;
    CCriticalSection csVerify;
    std::mutex       csDataset;
    bool             fFast     = false;
    bool             fLargeCache   = false;
    bool             fLargeDataset = false;
    bool             fLargeVerify  = false;
};
static RxKeyState g_key[2];   // index = version - 1

static RxKeyState* KeyState(int nVersion)
{
    if (nVersion < 1 || nVersion > 2)
        return NULL;
    return &g_key[nVersion - 1];
}

// RandomX reads a 256 MB cache, a 2 GB dataset and a 2 MB scratchpad per VM
// at random, so most reads miss the TLB on 4 KB pages. 2 MB pages recover
// roughly a tenth of the hash rate.
//
// The pool must be reserved first (vm.nr_hugepages), and RandomX returns NULL
// instead of falling back, so each allocation below retries without the flag.
bool fRandomXLargePages = true;   // cleared by -nolargepages

// How to reserve the large-page pool, for the hint printed when a large-page
// allocation falls back to normal pages. The mechanism is OS-specific.
static const char* LargePagesHint()
{
#ifdef _WIN32
    return "enable the \"Lock pages in memory\" privilege and run elevated";
#else
    return "reserve them with: sysctl vm.nr_hugepages=1280";
#endif
}

static randomx_flags WithLargePages(randomx_flags f)
{
    return (randomx_flags)(f | RANDOMX_FLAG_LARGE_PAGES);
}

// Ask for a cache in large pages, then plain pages. Sets fLargeOut to say
// which one answered.
static randomx_cache* AllocCache(randomx_flags flags, bool& fLargeOut)
{
    fLargeOut = false;
    if (fRandomXLargePages)
    {
        randomx_cache* c = randomx_alloc_cache(WithLargePages(flags));
        if (c)
        {
            fLargeOut = true;
            return c;
        }
    }
    return randomx_alloc_cache(flags);
}

static void InitCacheKey(randomx_cache* cache, int nVersion)
{
    if (nVersion == 2)
        randomx_init_cache(cache, SeedV2(), 32);
    else
        randomx_init_cache(cache, RANDOMX_KEY_V1, strlen(RANDOMX_KEY_V1));
}

bool RandomXInit()
{
    if (g_fInit)
        return true;

    std::lock_guard<std::mutex> lock(g_csInit);
    if (g_fInit)
        return true;

    // Detect the best flags for this CPU (JIT, hardware AES, Argon2).
    g_flags = randomx_get_flags();
    SeedV2();
    g_fInit = true;
    printf("RandomX: flags=%d, v2 seed %s, v2 from %u (%s)\n",
           (int)g_flags, PoWSeedV2Hex().c_str(), PoWV2Time(),
           IsTestNet() ? "testnet" : "mainnet");
    return true;
}

// Cache + verification VM of one version, allocated the first time that
// version is asked for. 256 MB each; a node that runs only after the switch
// and never has to check a v1 block allocates only v2.
static RxKeyState* EnsureKey(int nVersion)
{
    RxKeyState* k = KeyState(nVersion);
    if (!k)
        return NULL;
    if (k->vmVerify)
        return k;
    if (!g_fInit && !RandomXInit())
        return NULL;

    std::lock_guard<std::mutex> lock(g_csInit);
    if (k->vmVerify)
        return k;

    randomx_flags flags = g_flags;
    randomx_cache* cache = AllocCache(flags, k->fLargeCache);
    if (!cache)
    {
        // Try without JIT as a fallback
        flags = RANDOMX_FLAG_DEFAULT;
        cache = AllocCache(flags, k->fLargeCache);
        if (!cache)
        {
            error("RandomX: failed to allocate the v%d cache (256 MB)", nVersion);
            return NULL;
        }
        g_flags = flags;
    }
    InitCacheKey(cache, nVersion);

    // Verification VM in light mode (cache only). The scratchpad is only 2 MB
    // and this VM is created once, but it hashes every block the node ever
    // validates, so it gets the same treatment.
    randomx_vm* vm = NULL;
    if (fRandomXLargePages)
    {
        vm = randomx_create_vm(WithLargePages(flags), cache, NULL);
        k->fLargeVerify = (vm != NULL);
    }
    if (!vm)
        vm = randomx_create_vm(flags, cache, NULL);
    if (!vm)
    {
        randomx_release_cache(cache);
        error("RandomX: failed to create the v%d verification VM", nVersion);
        return NULL;
    }
    k->cache = cache;
    k->vmVerify = vm;
    printf("RandomX: v%d cache ready (256 MB, large pages: %s)\n",
           nVersion, RandomXLargePagesStatus());
    if (fRandomXLargePages && !k->fLargeCache)
        printf("RandomX: large pages unavailable for the cache; %s "
               "for about 10%% more hash rate\n", LargePagesHint());
    return k;
}


const char* RandomXLargePagesStatus()
{
    if (!fRandomXLargePages)
        return "off (-nolargepages)";
    bool fCache = false, fDataset = false, fAny = false;
    for (int i = 0; i < 2; i++)
    {
        fCache   |= g_key[i].fLargeCache;
        fDataset |= g_key[i].fLargeDataset;
        fAny     |= g_key[i].fLargeCache || g_key[i].fLargeVerify;
    }
    if (fCache && fDataset)
        return "cache + dataset";
    if (fCache)
        return "cache only";
    if (fDataset)
        return "dataset only";
    return fAny ? "scratchpad only" : "unavailable";
}


// One dataset per version, once, no matter how many miners ask for it.
//
// Every miner thread calls this at startup. The fFast guard below is only
// set at the very end, after the ~2 GB dataset has been filled, which takes
// tens of seconds -- so without this lock all of them sail past the guard
// together and each allocates its own dataset. Measured in production: a
// 32-core machine logged "initializing ~2 GB dataset" 34 times and committed
// 65 GB of private pages against a startup message promising 2142 MB.
//
// The waste was the mild half. dataset is assigned the moment the memory is
// allocated, before it holds anything, so the last thread to allocate would
// swing the pointer out from under the threads still filling their own. A
// miner could then hash against a dataset another thread had not finished
// writing, producing proof of work that no other node can reproduce.
//
// Holding the lock across the whole initialisation is deliberate: a thread
// that arrives mid-init has nothing useful to do until the dataset exists,
// and blocking is how it waits for exactly that.
bool RandomXInitDataset(int nVersion, int nThreads)
{
    RxKeyState* k = EnsureKey(nVersion);
    if (!k)
        return false;

    std::lock_guard<std::mutex> lock(k->csDataset);
    if (k->fFast)
        return true;

    // Only RANDOMX_FLAG_LARGE_PAGES means anything to randomx_alloc_dataset;
    // the rest of g_flags belongs to the VMs that read it.
    randomx_dataset* ds = NULL;
    if (fRandomXLargePages)
    {
        ds = randomx_alloc_dataset(WithLargePages(RANDOMX_FLAG_DEFAULT));
        k->fLargeDataset = (ds != NULL);
        if (!ds)
            printf("RandomX: large pages unavailable for the 2 GB dataset; %s "
                   "for about 10%% more hash rate\n", LargePagesHint());
    }
    if (!ds)
        ds = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
    if (!ds)
    {
        printf("RandomX: not enough memory for the 2 GB dataset, staying in light mode\n");
        return false;
    }

    unsigned long total = randomx_dataset_item_count();
    if (nThreads < 1) nThreads = 1;
    printf("RandomX: initializing the v%d ~2 GB dataset with %d threads...\n", nVersion, nThreads);

    std::vector<std::thread> workers;
    unsigned long per = total / nThreads;
    randomx_cache* cache = k->cache;
    for (int i = 0; i < nThreads; i++)
    {
        unsigned long start = i * per;
        unsigned long count = (i == nThreads - 1) ? (total - start) : per;
        workers.emplace_back([ds, cache, start, count]() {
            randomx_init_dataset(ds, cache, start, count);
        });
    }
    for (auto& w : workers) w.join();

    k->dataset = ds;
    k->fFast = true;
    printf("RandomX: v%d dataset ready (fast mode active)\n", nVersion);
    return true;
}


bool RandomXFastReady(int nVersion)
{
    RxKeyState* k = KeyState(nVersion);
    return k && k->fFast;
}


uint256 RandomXPoWHash(int nVersion, const void* pData, size_t nSize)
{
    uint256 result = 0;
    RxKeyState* k = EnsureKey(nVersion);
    if (!k)
        return result;
    CRITICAL_BLOCK(k->csVerify)
    {
        unsigned char hash[RANDOMX_HASH_SIZE];
        randomx_calculate_hash(k->vmVerify, pData, nSize, hash);
        memcpy(&result, hash, RANDOMX_HASH_SIZE);
    }
    return result;
}


uint256 PoWHashHeader(const unsigned char* pHeader80)
{
    unsigned char input[POW_INPUT_MAX];
    int v = 1;
    size_t n = PoWInputFromHeader(pHeader80, input, &v);
    return RandomXPoWHash(v, input, n);
}


uint256 PoWHashHeaderWithVM(void* vm, const unsigned char* pHeader80)
{
    unsigned char input[POW_INPUT_MAX];
    size_t n = PoWInputFromHeader(pHeader80, input);
    return RandomXHashWithVM(vm, input, n);
}


void* RandomXCreateMinerVM(int nVersion)
{
    RxKeyState* k = EnsureKey(nVersion);
    if (!k)
        return NULL;

    randomx_flags    flags   = g_flags;
    randomx_cache*   cache   = k->cache;
    randomx_dataset* dataset = NULL;
    if (k->fFast && k->dataset)
    {
        flags   = (randomx_flags)(g_flags | RANDOMX_FLAG_FULL_MEM);
        cache   = NULL;
        dataset = k->dataset;
    }

    // Each thread gets its own 2 MB scratchpad, so the large-page pool can run
    // dry partway through a fleet of miners. Threads that miss out still run.
    if (fRandomXLargePages)
    {
        randomx_vm* vm = randomx_create_vm(WithLargePages(flags), cache, dataset);
        if (vm)
            return vm;
    }
    return randomx_create_vm(flags, cache, dataset);
}


void RandomXDestroyMinerVM(void* vm)
{
    if (vm)
        randomx_destroy_vm((randomx_vm*)vm);
}


uint256 RandomXHashWithVM(void* vm, const void* pData, size_t nSize)
{
    uint256 result = 0;
    if (!vm)
        return result;
    unsigned char hash[RANDOMX_HASH_SIZE];
    randomx_calculate_hash((randomx_vm*)vm, pData, nSize, hash);
    memcpy(&result, hash, RANDOMX_HASH_SIZE);
    return result;
}
