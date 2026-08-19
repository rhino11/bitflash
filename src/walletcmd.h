// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Recovery-phrase commands. Both run against a loaded wallet and then exit;
// neither starts the node.

#ifndef BITFLASH_WALLETCMD_H
#define BITFLASH_WALLETCMD_H

#include <map>
#include <string>
#include <vector>

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

// Given the pubkeys derived while scanning a compatibility branch, return the
// next index after the highest one that actually appears in wallet
// transactions. The scan depth can be much larger than this; hdnext must record
// use, not how far a restore looked ahead.
unsigned int WalletLastUsedPubKeyIndexNext(
    const std::map<unsigned int, std::vector<unsigned char> >& mapPubKeysByIndex);

// Take the next address from the key pool and print it. With a recovery phrase
// installed the address is derived, so the phrase can bring back whatever is
// paid to it.
int CmdNewAddress();

// Diagnostic: print the first nCount addresses this wallet's phrase derives.
int CmdShowDerived(int nCount);

// Diagnostic: print whether the currently spendable wallet balance is covered
// by the installed recovery phrase or still depends on wallet.dat-only keys.
int CmdRecoveryAudit();

// Diagnostic: count wallet.dat record types without printing keys,
// addresses, transaction ids, labels, or other wallet values.
int CmdWalletStorageAudit(const std::string& strJsonOut = "");

// Diagnostic: fail closed when wallet.dat contains an internally inconsistent
// or migration-unsafe mix of storage records.
int CmdWalletStorageCheck();

// Copy every raw wallet.dat record into a SQLite key/value store, preserving
// serialized bytes. A migration/scripting tool; it does not change which backend
// the runtime wallet opens.
int CmdWalletSQLiteExport(const std::string& strDest);

// Export the currently-loaded wallet to a SQLite file (shared by the command
// above and the GUI wizard). Returns false with an error on any failure.
bool ExportActiveWalletToSQLite(const std::string& strDest, int& nCopiedRet,
                                std::string& strErrorRet);

// Convert the running Berkeley DB wallet to SQLite and record the backend
// marker so the next start opens it. wallet.dat is left untouched as fallback.
bool DoConvertWalletToSQLite(int& nCopiedRet, std::string& strErrorRet);

// Diagnostic/migration staging: compare a SQLite wallet export with the current
// wallet.dat raw records. Prints counts only, never record keys or values.
int CmdWalletSQLiteVerify(const std::string& strPath);

// Diagnostic/migration staging: rebuild wallet.dat from a SQLite export in an
// empty data directory. Refuses to overwrite an existing wallet.dat.
int CmdWalletSQLiteRestore(const std::string& strPath);

// Diagnostic/migration staging: parse a SQLite wallet export as the runtime
// wallet loader would. Prints counts only, never record keys or values.
int CmdWalletSQLiteLoadCheck(const std::string& strPath);

// Rewrite wallet.dat so private keys and the HD seed are encrypted with the
// given passphrase. Returns 0 on success and exits without starting the node.
int CmdEncryptWallet(const std::string& strPassphrase);

// Spend, from the command line. Until now the only way to send was the window,
// so a headless node could be paid and could never pay -- it could hold a
// balance it had no way to move. strArg is "ADDRESS,AMOUNT".
int CmdSendTo(const std::string& strArg);

#endif
