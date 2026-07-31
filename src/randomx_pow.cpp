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
static bool            g_fInit    = false;
static bool            g_fFast    = false;


bool RandomXInit()
{
    if (g_fInit)
        return true;

    // Detect the best flags for this CPU (JIT, hardware AES, Argon2).
    g_flags = randomx_get_flags();

    g_cache = randomx_alloc_cache(g_flags);
    if (!g_cache)
    {
        // Try without JIT as a fallback
        g_flags = RANDOMX_FLAG_DEFAULT;
        g_cache = randomx_alloc_cache(g_flags);
        if (!g_cache)
            return error("RandomX: failed to allocate cache (256 MB)");
    }
    randomx_init_cache(g_cache, RANDOMX_KEY, strlen(RANDOMX_KEY));

    // Verification VM in light mode (cache only)
    g_vmVerify = randomx_create_vm(g_flags, g_cache, NULL);
    if (!g_vmVerify)
        return error("RandomX: failed to create verification VM");

    g_fInit = true;
    printf("RandomX: initialized (cache 256 MB, flags=%d)\n", (int)g_flags);
    return true;
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

    randomx_flags fastFlags = (randomx_flags)(g_flags | RANDOMX_FLAG_FULL_MEM);
    g_dataset = randomx_alloc_dataset(fastFlags);
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
    if (g_fFast && g_dataset)
    {
        randomx_flags fastFlags = (randomx_flags)(g_flags | RANDOMX_FLAG_FULL_MEM);
        return randomx_create_vm(fastFlags, NULL, g_dataset);
    }
    // Light mode: own VM sharing the cache
    return randomx_create_vm(g_flags, g_cache, NULL);
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
