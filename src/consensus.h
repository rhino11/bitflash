// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Rules v2: the consensus rules Bitcoin adopted after 0.1.0, applied here
// from one moment, by block time -- the same shape as the PoW v2 switch in
// randomx_pow.h, and on mainnet the same moment, so a node updates once.
//
//   - the coinbase scriptSig starts with the block height (BIP34), and a
//     transaction whose txid already exists unspent is refused (BIP30): two
//     coinbases could otherwise be byte-identical, and the second one
//     overwrote the first's index entry
//   - signatures must be strictly DER-encoded with a low S value (BIP66,
//     BIP62): validation no longer depends on how permissive the linked
//     OpenSSL happens to be -- which is what split Bitcoin in 2015 -- and a
//     third party can no longer change a txid by re-encoding a signature
//   - the difficulty retarget measures the time of nInterval intervals, not
//     nInterval-1 (the off-by-one behind the time-warp attack)
//
// Testnet switches first so the rules run on a live chain before mainnet.

#ifndef BITFLASH_CONSENSUS_H
#define BITFLASH_CONSENSUS_H

// Mainnet: 2026-09-21 12:00:00 UTC, with PoW v2. Testnet: 2026-09-16 15:00:00 UTC.
static const unsigned int RULES_V2_TIME_MAINNET = 1789992000;
static const unsigned int RULES_V2_TIME_TESTNET = 1789570800;

// The most a peer can move this node's clock, in either direction. Beyond
// it the offset is dropped rather than applied: a node whose peers disagree
// with its own clock by more than this has a clock problem, not a peer
// problem, and letting peers set the time is how a node is walked off the
// chain (Bitcoin 0.3.x: 70 minutes).
static const int64 MAX_TIME_ADJUSTMENT = 70 * 60;

unsigned int RulesV2Time();
bool RulesV2Active(unsigned int nBlockTime);

#endif
