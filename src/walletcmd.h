// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Recovery-phrase commands. Both run against a loaded wallet and then exit;
// neither starts the node.

#ifndef BITFLASH_WALLETCMD_H
#define BITFLASH_WALLETCMD_H

#include <string>

// Create a phrase for a wallet that does not have one, install the seed, and
// show the words once. Refuses if a phrase already exists. Returns 0 on success.
int CmdNewPhrase();

// Install the seed a phrase describes, derive forward looking for used
// addresses, and rescan the chain so their coins appear. Returns 0 on success.
int CmdRestorePhrase(const std::string& strMnemonic, int nMinDepth = 0);

// Called once per batch with how many addresses have been derived so far and
// how many transactions the wallet now holds.
typedef void (*RestoreProgressFn)(void* pArg, int nDerived, int nRecovered);

// The restore itself, shared by the command and the GUI so the two cannot
// drift apart. Returns false without touching the wallet if the chain is not
// loaded or the phrase is not valid.
bool RestoreFromPhrase(const std::string& strMnemonic,
                       int nMinDepth,
                       RestoreProgressFn fnProgress,
                       void* pArg,
                       std::string& strErrorRet,
                       int& nRecoveredRet,
                       int& nDerivedRet);

// Restore scans stop only after the requested depth is reached. BIP44 has more
// than one branch, so the depth has to be satisfied per branch, not by summing
// receive + change + compatibility keys.
bool RestoreScanReachedDepth(int nSchema,
                             unsigned int nReceiveNext,
                             unsigned int nChangeNext,
                             unsigned int nLegacyNext,
                             int nStopDepth);

// Take the next address from the key pool and print it. With a recovery phrase
// installed the address is derived, so the phrase can bring back whatever is
// paid to it.
int CmdNewAddress();

// Diagnostic: print the first nCount addresses this wallet's phrase derives.
int CmdShowDerived(int nCount);

// Diagnostic: print whether the currently spendable wallet balance is covered
// by the installed recovery phrase or still depends on wallet.dat-only keys.
int CmdRecoveryAudit();

// Rewrite wallet.dat so private keys and the HD seed are encrypted with the
// given passphrase. Returns 0 on success and exits without starting the node.
int CmdEncryptWallet(const std::string& strPassphrase);

// Spend, from the command line. Until now the only way to send was the window,
// so a headless node could be paid and could never pay -- it could hold a
// balance it had no way to move. strArg is "ADDRESS,AMOUNT".
int CmdSendTo(const std::string& strArg);

#endif
