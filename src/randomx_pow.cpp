// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// RandomX PoW implementation. See randomx_pow.h.

#include "headers.h"
#include <randomx.h>
#include <thread>
#include <vector>
#include <mutex>

// Fixed key (seed) that determines the RandomX cache/dataset. Keeping it
// constant avoids per-epoch "reseed" logic; for the CPU+RAM fairness goal
// this is sufficient (RandomX already neutralizes GPU/ASIC by design).
static const char* RANDOMX_KEY = "Bitflash/RandomX/v1/one-cpu-one-vote";

static randomx_flags   g_flags   = RANDOMX_FLAG_DEFAULT;
static randomx_cache*  g_cache   = NULL;
static randomx_dataset* g_dataset = NULL;
static randomx_vm*     g_vmVerify = NULL;
static CCriticalSection g_csVerify;
static std::mutex      g_csInit;
static bool            g_fInit    = false;
static bool            g_fFast    = false;

// RandomX reads a 256 MB cache, a 2 GB dataset and a 2 MB scratchpad per VM
// at random, so most reads miss the TLB on 4 KB pages. 2 MB pages recover
// roughly a tenth of the hash rate.
//
// The pool must be reserved first (vm.nr_hugepages), and RandomX returns NULL
// instead of falling back, so each allocation below retries without the flag.
bool fRandomXLargePages = true;   // cleared by -nolargepages
static bool g_fLargeCache   = false;
static bool g_fLargeDataset = false;
static bool g_fLargeAny     = false;

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


bool RandomXInit()
{
    if (g_fInit)
        return true;

    std::lock_guard<std::mutex> lock(g_csInit);
    if (g_fInit)
        return true;

    // Detect the best flags for this CPU (JIT, hardware AES, Argon2).
    g_flags = randomx_get_flags();

    g_cache = AllocCache(g_flags, g_fLargeCache);
    if (!g_cache)
    {
        // Try without JIT as a fallback
        g_flags = RANDOMX_FLAG_DEFAULT;
        g_cache = AllocCache(g_flags, g_fLargeCache);
        if (!g_cache)
            return error("RandomX: failed to allocate cache (256 MB)");
    }
    randomx_init_cache(g_cache, RANDOMX_KEY, strlen(RANDOMX_KEY));

    // Verification VM in light mode (cache only). The scratchpad is only 2 MB
    // and this VM is created once, but it hashes every block the node ever
    // validates, so it gets the same treatment.
    bool fLargeVerify = false;
    if (fRandomXLargePages)
    {
        g_vmVerify = randomx_create_vm(WithLargePages(g_flags), g_cache, NULL);
        fLargeVerify = (g_vmVerify != NULL);
    }
    if (!g_vmVerify)
        g_vmVerify = randomx_create_vm(g_flags, g_cache, NULL);
    if (!g_vmVerify)
        return error("RandomX: failed to create verification VM");

    g_fLargeAny = g_fLargeCache || fLargeVerify;
    g_fInit = true;
    printf("RandomX: initialized (cache 256 MB, flags=%d, large pages: %s)\n",
           (int)g_flags, RandomXLargePagesStatus());
    if (fRandomXLargePages && !g_fLargeCache)
        printf("RandomX: large pages unavailable for the cache; "
               "reserve them with sysctl vm.nr_hugepages=1280 for about 10%% more hash rate\n");
    return true;
}


const char* RandomXLargePagesStatus()
{
    if (!fRandomXLargePages)
        return "off (-nolargepages)";
    if (g_fLargeCache && g_fLargeDataset)
        return "cache + dataset";
    if (g_fLargeCache)
        return "cache only";
    if (g_fLargeDataset)
        return "dataset only";
    return g_fLargeAny ? "scratchpad only" : "unavailable";
}


// One dataset, once, no matter how many miners ask for it.
//
// Every miner thread calls this at startup. The g_fFast guard below is only
// set at the very end, after the ~2 GB dataset has been filled, which takes
// tens of seconds -- so without this lock all of them sail past the guard
// together and each allocates its own dataset. Measured in production: a
// 32-core machine logged "initializing ~2 GB dataset" 34 times and committed
// 65 GB of private pages against a startup message promising 2142 MB.
//
// The waste was the mild half. g_dataset is assigned the moment the memory is
// allocated, before it holds anything, so the last thread to allocate would
// swing the pointer out from under the threads still filling their own. A
// miner could then hash against a dataset another thread had not finished
// writing, producing proof of work that no other node can reproduce.
//
// Holding the lock across the whole initialisation is deliberate: a thread
// that arrives mid-init has nothing useful to do until the dataset exists,
// and blocking is how it waits for exactly that.
static std::mutex g_csDataset;

bool RandomXInitDataset(int nThreads)
{
    if (!g_fInit && !RandomXInit())
        return false;

    std::lock_guard<std::mutex> lock(g_csDataset);
    if (g_fFast)
        return true;

    // Only RANDOMX_FLAG_LARGE_PAGES means anything to randomx_alloc_dataset;
    // the rest of g_flags belongs to the VMs that read it.
    if (fRandomXLargePages)
    {
        g_dataset = randomx_alloc_dataset(WithLargePages(RANDOMX_FLAG_DEFAULT));
        g_fLargeDataset = (g_dataset != NULL);
        if (!g_dataset)
            printf("RandomX: large pages unavailable for the 2 GB dataset; "
                   "reserve 1280 with sysctl vm.nr_hugepages for about 10%% more hash rate\n");
    }
    if (!g_dataset)
        g_dataset = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
    if (!g_dataset)
    {
        printf("RandomX: not enough memory for the 2 GB dataset, staying in light mode\n");
        return false;
    }

    unsigned long total = randomx_dataset_item_count();
    if (nThreads < 1) nThreads = 1;
    printf("RandomX: initializing ~2 GB dataset with %d threads...\n", nThreads);

    std::vector<std::thread> workers;
    unsigned long per = total / nThreads;
    for (int i = 0; i < nThreads; i++)
    {
        unsigned long start = i * per;
        unsigned long count = (i == nThreads - 1) ? (total - start) : per;
        workers.emplace_back([start, count]() {
            randomx_init_dataset(g_dataset, g_cache, start, count);
        });
    }
    for (auto& w : workers) w.join();

    g_fFast = true;
    printf("RandomX: dataset ready (fast mode active)\n");
    return true;
}


bool RandomXFastReady()
{
    return g_fFast;
}


uint256 RandomXPoWHash(const void* pHeader, size_t nSize)
{
    uint256 result = 0;
    if (!g_fInit && !RandomXInit())
        return result;
    CRITICAL_BLOCK(g_csVerify)
    {
        unsigned char hash[RANDOMX_HASH_SIZE];
        randomx_calculate_hash(g_vmVerify, pHeader, nSize, hash);
        memcpy(&result, hash, RANDOMX_HASH_SIZE);
    }
    return result;
}


void* RandomXCreateMinerVM()
{
    if (!g_fInit && !RandomXInit())
        return NULL;

    randomx_flags   flags   = g_flags;
    randomx_cache*  cache   = g_cache;
    randomx_dataset* dataset = NULL;
    if (g_fFast && g_dataset)
    {
        flags   = (randomx_flags)(g_flags | RANDOMX_FLAG_FULL_MEM);
        cache   = NULL;
        dataset = g_dataset;
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


uint256 RandomXHashWithVM(void* vm, const void* pHeader, size_t nSize)
{
    uint256 result = 0;
    if (!vm)
        return result;
    unsigned char hash[RANDOMX_HASH_SIZE];
    randomx_calculate_hash((randomx_vm*)vm, pHeader, nSize, hash);
    memcpy(&result, hash, RANDOMX_HASH_SIZE);
    return result;
}
