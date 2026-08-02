// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Recovery-phrase commands, from the command line.
//
// The phrase reaches the person who typed the command and nowhere else. In this
// tree printf is OutputDebugStringF, which writes into the data directory's
// debug.log -- the file we routinely ask users to attach to issues. A wallet's
// twelve words must never go there, so this file takes the real printf and
// AttachTerminal() gives it somewhere to land on Windows.

#include "headers_core.h"
#include "bip32.h"
#include "walletcmd.h"

#undef printf

// How far ahead to look for used addresses when restoring.
//
// A wallet is restored from a phrase alone, so the node has no idea how many
// addresses the old one handed out. It derives forward in batches and stops
// once a whole batch turns up unused. A fixed number would be simpler and wrong
// for exactly this network: a miner burns an address per block, so a node that
// mined for a week is thousands of keys deep, and stopping at a few hundred
// would restore a wallet that looks empty.
static const int RESTORE_BATCH   = 100;
static const int RESTORE_MAX     = 10000;
// The wallet may have a full unused key pool in front of a change address
// created while spending pre-phrase coins. Looking only one empty batch ahead
// can stop just before that change output.
static const int RESTORE_MIN_SCAN = KEYPOOL_SIZE + RESTORE_BATCH;

int CmdNewPhrase()
{
    AttachTerminal();

    if (HaveHDSeed())
    {
        printf("This wallet already has a recovery phrase.\n");
        printf("Creating another would replace it, and coins on addresses derived from\n");
        printf("the current one would no longer come back from the phrase you write down.\n");
        printf("Nothing was changed.\n");
        return 1;
    }

    std::string strMnemonic, strError;
    if (!bitflash::BIP39GenerateMnemonic(strMnemonic, strError))
    {
        fprintf(stderr, "Could not generate a phrase: %s\n", strError.c_str());
        return 1;
    }

    if (!SetHDSeedFromMnemonic(strMnemonic, strError))
    {
        fprintf(stderr, "Could not install the seed: %s\n", strError.c_str());
        return 1;
    }

    // Fill the pool from the new seed straight away, so the addresses this
    // wallet hands out next are ones the phrase can reproduce.
    TopUpKeyPool();

    printf("\n");
    printf("Write these twelve words down, in order, on paper.\n");
    printf("They are the only thing that can rebuild this wallet if the file is lost.\n");
    printf("Anyone who reads them can spend your coins. They are not stored anywhere,\n");
    printf("and this is the only time they will be shown.\n");
    printf("\n");
    printf("    %s\n", strMnemonic.c_str());
    printf("\n");
    printf("Keys already in this wallet are NOT covered by the phrase -- they existed\n");
    printf("before it did. Keep your file backups as well.\n");
    fflush(stdout);
    return 0;
}

bool RestoreFromPhrase(const std::string& strMnemonic,
                       int nMinDepth,
                       RestoreProgressFn fnProgress,
                       void* pArg,
                       std::string& strErrorRet,
                       int& nRecoveredRet,
                       int& nDerivedRet)
{
    strErrorRet.clear();
    nRecoveredRet = 0;
    nDerivedRet   = 0;

    // Refuse before touching the wallet, not after.
    //
    // Without this, a restore on a node that has not synced derives the right
    // keys, scans a chain that is not there, and reports "no transactions were
    // found" -- which reads as "your coins are gone" to the one person least
    // able to argue with it. Measured while testing: a copied data directory
    // whose Berkeley DB environment failed to load left the node at height 0,
    // the scan walked one block, and the message said nothing was found across
    // 600 addresses.
    if (!CanScanWalletTransactions(strErrorRet))
        return false;

    size_t nWalletStart = 0;
    CRITICAL_BLOCK(cs_mapWallet)
        nWalletStart = mapWallet.size();

    if (!SetHDSeedFromMnemonic(strMnemonic, strErrorRet))
        return false;

    // Derive forward in batches, scanning after each, until a whole batch turns
    // up nothing. Every derived key is written to the wallet before the scan,
    // because the scan asks the wallet what belongs to it.
    int nTotalDerived = (int)nHDNext;
    int nStopDepth = max(nMinDepth, RESTORE_MIN_SCAN);
    while (nTotalDerived < RESTORE_MAX)
    {
        // Count wallet transactions, not scan hits.
        //
        // ScanForWalletTransactions reports what it added *or updated*, and it
        // walks the whole chain every time, so a transaction found in the first
        // batch is reported again by every batch after it. Testing this against
        // a real payment produced exactly +1 per batch and a loop that ran to
        // the ceiling, deriving ten thousand addresses to rediscover one coin.
        size_t nWalletBefore = 0;
        CRITICAL_BLOCK(cs_mapWallet)
            nWalletBefore = mapWallet.size();

        std::string strDeriveError;
        for (int i = 0; i < RESTORE_BATCH; i++)
        {
            CKey key;
            if (!DeriveHDKey(nHDNext, key, strDeriveError))
                break;
            if (!AddKey(key))
                break;
            nHDNext++;
            nTotalDerived++;
        }
        CWalletDB().WriteHDNext(nHDNext);

        ScanForWalletTransactions(pindexGenesisBlock);

        size_t nWalletAfter = 0;
        CRITICAL_BLOCK(cs_mapWallet)
            nWalletAfter = mapWallet.size();

        if (fnProgress)
        {
            size_t nRecoveredNow = nWalletAfter > nWalletStart ?
                                   nWalletAfter - nWalletStart : 0;
            fnProgress(pArg, nTotalDerived, (int)nRecoveredNow);
        }

        // A whole batch with nothing in it means far enough -- unless the
        // caller asked to look deeper anyway.
        if (nWalletAfter == nWalletBefore && nTotalDerived >= nStopDepth)
            break;
    }

    // The pool is rebuilt from where derivation stopped, so the next address
    // this wallet hands out is one the phrase can reproduce as well.
    CRITICAL_BLOCK(cs_keyPool)
        mapKeyPool.clear();
    TopUpKeyPool();

    size_t nWalletEnd = 0;
    CRITICAL_BLOCK(cs_mapWallet)
        nWalletEnd = mapWallet.size();
    nRecoveredRet = (int)(nWalletEnd > nWalletStart ?
                          nWalletEnd - nWalletStart : 0);
    nDerivedRet = nTotalDerived;
    return true;
}

static void PrintRestoreProgress(void*, int nDerived, int nRecovered)
{
    printf("  %d addresses checked, %d transaction(s) recovered\n", nDerived, nRecovered);
    fflush(stdout);
}

int CmdRestorePhrase(const std::string& strMnemonic, int nMinDepth)
{
    AttachTerminal();

    printf("Checking the phrase and the chain.\n");
    fflush(stdout);

    std::string strError;
    int nRecovered = 0, nDerived = 0;
    if (!RestoreFromPhrase(strMnemonic, nMinDepth, PrintRestoreProgress, NULL,
                           strError, nRecovered, nDerived))
    {
        fprintf(stderr, "Cannot restore: %s\n", strError.c_str());
        fprintf(stderr, "Nothing was changed.\n");
        return 1;
    }

    printf("\n");
    if (nRecovered > 0)
        printf("Restored: %d transaction(s) across %d derived addresses.\n",
               nRecovered, nDerived);
    else
        printf("No transactions were found for the first %d addresses of that phrase.\n"
               "If you expected coins, check the words and the order.\n", nDerived);
    printf("Start the node normally to see the balance.\n");
    fflush(stdout);
    return 0;
}

int CmdNewAddress()
{
    AttachTerminal();

    std::vector<unsigned char> vchPubKey = GetKeyFromPool();
    if (vchPubKey.empty())
    {
        fprintf(stderr, "Could not get a key from the wallet.\n");
        return 1;
    }

    printf("%s\n", PubKeyToAddress(vchPubKey).c_str());
    if (!HaveHDSeed())
        printf("(this wallet has no recovery phrase, so only a file backup covers this address)\n");
    fflush(stdout);
    return 0;
}

// Diagnostic: print the addresses a phrase produces, so "the restore found
// nothing" can be told apart from "that address was never derived".
int CmdShowDerived(int nCount)
{
    AttachTerminal();

    if (!HaveHDSeed())
    {
        fprintf(stderr, "This wallet has no recovery phrase installed.\n");
        return 1;
    }
    if (nCount <= 0)
        nCount = 20;

    std::string strError;
    for (int i = 0; i < nCount; i++)
    {
        CKey key;
        if (!DeriveHDKey((unsigned int)i, key, strError))
        {
            fprintf(stderr, "derivation failed at %d: %s\n", i, strError.c_str());
            return 1;
        }
        printf("%6d  %s\n", i, PubKeyToAddress(key.GetPubKey()).c_str());
    }
    fflush(stdout);
    return 0;
}
