// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Memory-hard Proof of Work (CPU + RAM) via RandomX -- replaces SHA-256d as
// the PoW algorithm. The block IDENTITY hash stays SHA-256d (GetHash),
// preserving all indexing; what changes is the PROOF-OF-WORK hash
// (GetPoWHash), computed with RandomX.
//
// Modes:
//   - Verification (all nodes): 256 MB cache, "light" VM. Cheap.
//   - Mining (optional, fast): ~2 GB dataset, "full" VMs. Fast.
// GPUs and ASICs are neutralized by RandomX's memory cost/latency.

#ifndef BITFLASH_RANDOMX_POW_H
#define BITFLASH_RANDOMX_POW_H

// uint256 comes from uint256.h, already included by headers.h before this file.

// Initialize the cache (256 MB) and the verification VM. Call once at startup.
// Returns false if allocation fails.
bool RandomXInit();

// Allocate and initialize the ~2 GB dataset for fast mining (fast mode),
// using nThreads to speed it up. Idempotent. Returns false on failure (the
// miner then falls back to light mode automatically).
bool RandomXInitDataset(int nThreads);

// PoW hash of an 80-byte header, using the verification VM (thread-safe,
// guarded by a critical section).
uint256 RandomXPoWHash(const void* pHeader, size_t nSize);

// Create a VM for a mining thread (own VM, not shared). Uses the dataset
// (fast) if available, otherwise the cache (light). Release with
// RandomXDestroyMinerVM. Returns NULL on failure.
void* RandomXCreateMinerVM();
void  RandomXDestroyMinerVM(void* vm);

// Compute a PoW hash on an owned mining VM (not guarded).
uint256 RandomXHashWithVM(void* vm, const void* pHeader, size_t nSize);

// True when the 2 GB dataset is ready (fast mode active).
bool RandomXFastReady();

// Ask for large (2 MB) pages for the cache, dataset and scratchpads. Set false
// by -nolargepages. Must be set before the first RandomXInit().
extern bool fRandomXLargePages;

// Which allocations actually got large pages, for the status display.
const char* RandomXLargePagesStatus();

#endif
