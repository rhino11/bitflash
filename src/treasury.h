// Copyright (c) 2026 The Bitflash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
// The Bitflash treasury: one bare 2-of-3 multisig output per network, the
// community fund that pays for an exchange listing and nothing else. The keys
// are in this file on purpose -- the binary, the source, the page and the
// signed charter all name the same three, and anyone can check that they
// agree. No one key spends; docs/treasury.md says who holds which.
//
// Nothing here is consensus. A node that has never heard of the treasury
// carries its outputs like any other multisig.
#ifndef BITFLASH_TREASURY_H
#define BITFLASH_TREASURY_H

#include <string>
#include <vector>

class CScript;

namespace treasury {

// Signatures needed to spend, out of the keys listed.
static const int REQUIRED = 2;

// The largest share of a block a solo miner may direct to the treasury.
static const int SHARE_MAX_PERCENT = 50;

// The public page, where the balance and every movement are shown.
static const char* const PAGE = "https://bitflash.network/treasury";

// True when the running network has a treasury (the keys below are filled).
bool Configured();

// The three public keys, hex, in script order. Empty when not configured.
std::vector<std::string> Keys();

// The output script (bare 2-of-3), or false when not configured.
bool Script(CScript& scriptRet);
std::string ScriptHex();

// True when scriptPubKey is exactly the treasury script.
bool IsTreasury(const CScript& scriptPubKey);

// The part of a block reward directed to the treasury by -treasuryshare;
// 0 when the share is 0, out of range, or the treasury is not configured.
long long ShareOf(long long nBlockValue, int nPercent);

} // namespace treasury

// Solo mining: percent of every block mined here paid to the treasury in the
// coinbase itself (0 = none; at most treasury::SHARE_MAX_PERCENT). Ignored in
// operator (pool) mode, where -poolfeeto=treasury does the same job.
extern int nTreasurySharePercent;

// Operator: the pool fee is paid to the treasury instead of kept.
extern bool fPoolFeeToTreasury;

#endif
