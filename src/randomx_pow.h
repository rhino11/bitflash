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
//
// Two versions of the proof of work exist, selected by the block's nTime:
//
//   v1  RandomX over the 80-byte header as serialized, keyed by the string
//       "Bitflash/RandomX/v1/one-cpu-one-vote". Every block before
//       POW_V2_TIME.
//
//   v2  RandomX over an 83-byte input built from the same header with the
//       nonce moved to bytes 39..42, keyed by SHA-256 of the v1 key string.
//       Every block from POW_V2_TIME on.
//
// v2 exists for one reason: ordinary RandomX miners. XMRig and its relatives
// put their nonce at byte 39 of whatever blob the pool hands them, hash the
// whole blob, and take the RandomX key from a 32-byte "seed_hash" in the job.
// v1 put the nonce at byte 76 and used a 36-byte key, so no such miner could
// produce a share the chain would accept -- the public pool announced in
// September 2026 could not actually be mined by the software it named. The
// v2 input is the header the chain already has, laid out where those miners
// expect it, with a key they can be told.

#ifndef BITFLASH_RANDOMX_POW_H
#define BITFLASH_RANDOMX_POW_H

#include <string>

// uint256 comes from uint256.h, already included by headers.h before this file.

// Activation, by block time (nTime), so the hash function of a header is a
// function of the header alone. Mainnet: 2026-09-21 12:00:00 UTC. Testnet:
// 2026-09-14 21:00:00 UTC.
static const unsigned int POW_V2_TIME_MAINNET = 1789992000;
static const unsigned int POW_V2_TIME_TESTNET = 1789419600;
unsigned int PoWV2Time();

// 1 or 2 for a block carrying this nTime.
int PoWVersionAt(unsigned int nTime);

// The v2 input of an 80-byte header, as serialized (nonce at 76). Returns
// its length, POW_INPUT_V2_SIZE. pOut needs POW_INPUT_MAX bytes.
static const size_t POW_INPUT_V2_SIZE = 83;
static const size_t POW_INPUT_MAX     = 83;
static const size_t POW_V2_NONCE_OFFSET = 39;
size_t PoWInputV2(const unsigned char* pHeader80, unsigned char* pOut);

// The PoW input of a header for whichever version its nTime selects.
size_t PoWInputFromHeader(const unsigned char* pHeader80, unsigned char* pOut, int* pnVersion = NULL);

// The 32-byte v2 key, and its hex -- the seed_hash a RandomX miner is given.
const unsigned char* PoWSeedV2();
std::string PoWSeedV2Hex();

// PoW hash of an 80-byte header, version chosen by its nTime, on the shared
// verification VM (thread-safe). This is what consensus checks.
uint256 PoWHashHeader(const unsigned char* pHeader80);

// Same, on an owned mining VM created for the header's version.
uint256 PoWHashHeaderWithVM(void* vm, const unsigned char* pHeader80);

// Initialize flags and the v1/v2 cache + verification VM on demand. Call once
// at startup; the caches themselves are allocated the first time each
// version is asked for, so a node that never sees a v1 block after the
// switch never pays for the v1 cache.
bool RandomXInit();

// Allocate and initialize the ~2 GB dataset of one version for fast mining,
// using nThreads to speed it up. Idempotent per version. Returns false on
// failure (the miner then falls back to light mode automatically).
bool RandomXInitDataset(int nVersion, int nThreads);

// Raw hash on the verification VM of one version. Consensus code should use
// PoWHashHeader; this is for tests and for the pool, which builds its own
// inputs.
uint256 RandomXPoWHash(int nVersion, const void* pData, size_t nSize);

// Create a VM for a mining thread (own VM, not shared) keyed for one version.
// Uses that version's dataset (fast) if ready, otherwise its cache (light).
// Release with RandomXDestroyMinerVM. Returns NULL on failure.
void* RandomXCreateMinerVM(int nVersion);
void  RandomXDestroyMinerVM(void* vm);

// Compute a hash on an owned mining VM (not guarded).
uint256 RandomXHashWithVM(void* vm, const void* pData, size_t nSize);

// True when the 2 GB dataset of that version is ready (fast mode active).
bool RandomXFastReady(int nVersion);

// Ask for large (2 MB) pages for the cache, dataset and scratchpads. Set false
// by -nolargepages. Must be set before the first RandomXInit().
extern bool fRandomXLargePages;

// Which allocations actually got large pages, for the status display.
const char* RandomXLargePagesStatus();

#endif
