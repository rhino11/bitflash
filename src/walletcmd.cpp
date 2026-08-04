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
// Quiet batches required before giving up. Three, because the wallet's own
// bookkeeping can leave a gap of two hundred used-nothing indices between one
// used address and the next -- see the note at the stop condition. One was not
// enough and cost a real balance in testing.
static const int RESTORE_QUIET_BATCHES = 3;
// The wallet may have restored once, scanned a few quiet batches, and then
// spent after that. Change starts from wherever that restore stopped, so the
// next real change output can be just beyond the old quiet window. The default
// restore has to look far enough for that ordinary "restore, then spend, then
// restore again" path; explicit -restoredepth can still go deeper.
static const int RESTORE_MIN_SCAN =
    KEYPOOL_SIZE + (RESTORE_QUIET_BATCHES + 1) * RESTORE_BATCH;

bool RestoreScanReachedDepth(int nSchema,
                             unsigned int nReceiveNext,
                             unsigned int nChangeNext,
                             unsigned int nLegacyNext,
                             int nStopDepth)
{
    if (nStopDepth <= 0)
        return true;
    unsigned int nDepth = (unsigned int)nStopDepth;
    if (nSchema == HD_SCHEMA_BIP44)
        return nReceiveNext >= nDepth &&
               nChangeNext >= nDepth &&
               nLegacyNext >= nDepth;
    return nLegacyNext >= nDepth;
}

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
    int nTotalDerived = nHDKeySchema == HD_SCHEMA_BIP44
        ? (int)(nHDReceiveNext + nHDChangeNext)
        : (int)nHDNext;
    int nStopDepth = max(nMinDepth, RESTORE_MIN_SCAN);
    int nQuietBatches = 0;
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
        if (nHDKeySchema == HD_SCHEMA_BIP44)
        {
            for (int i = 0; i < RESTORE_BATCH; i++)
            {
                CKey key;
                if (!DeriveHDKey(nHDReceiveNext, key, strDeriveError))
                    break;
                if (!AddKey(key))
                    break;
                nHDReceiveNext++;
                nTotalDerived++;
            }
            CWalletDB().WriteHDReceiveNext(nHDReceiveNext);

            for (int i = 0; i < RESTORE_BATCH; i++)
            {
                CKey key;
                if (!DeriveHDChangeKey(nHDChangeNext, key, strDeriveError))
                    break;
                if (!AddKey(key))
                    break;
                nHDChangeNext++;
                nTotalDerived++;
            }
            CWalletDB().WriteHDChangeNext(nHDChangeNext);

            int nSavedSchema = nHDKeySchema;
            nHDKeySchema = HD_SCHEMA_LEGACY;
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
            nHDKeySchema = nSavedSchema;
            CWalletDB().WriteHDNext(nHDNext);
        }
        else
        {
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
        }

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

        // Stopping needs more than one quiet batch, because this wallet digs
        // gaps in its own derivation. A restore leaves the receive counter at
        // the depth it scanned, the key pool then derives KEYPOOL_SIZE more,
        // and a later spend can use change after that -- so the address used
        // *after* a restore can sit two hundred indices past the last one used
        // before it, with nothing in between.
        //
        // Measured, on a real wallet with real coin: restore, spend once, and
        // the coins land at indices 201 and 302. Restoring again with the old
        // one-batch rule stopped at 201 and reported a single transaction. The
        // money was derived, covered by the phrase, and invisible.
        if (nWalletAfter == nWalletBefore)
            nQuietBatches++;
        else
            nQuietBatches = 0;
        if (nQuietBatches >= RESTORE_QUIET_BATCHES &&
            RestoreScanReachedDepth(nHDKeySchema,
                                    nHDReceiveNext,
                                    nHDChangeNext,
                                    nHDNext,
                                    nStopDepth))
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

int CmdRecoveryAudit()
{
    AttachTerminal();

    WalletRecoveryAudit audit = GetWalletRecoveryAudit();
    int64 nTotal = audit.nRecoverableCredit + audit.nLegacyCredit;
    int64 nImmatureTotal = audit.nRecoverableImmatureCredit + audit.nLegacyImmatureCredit;

    printf("Wallet recovery audit\n");
    printf("  recovery phrase: %s\n", audit.fHaveSeed ? "present" : "not installed");
    if (audit.fHaveSeed)
    {
        printf("  derivation schema: %s\n", HDKeySchemaName(audit.nSchema).c_str());
        printf("  BIP44 coin type: %u (provisional BITFLASH)\n", audit.nCoinType);
        printf("  derived keys known to this wallet: %u\n", audit.nDerivedKnown);
        printf("  receive/change counters: %u/%u\n",
               audit.nReceiveNext, audit.nChangeNext);
    }
    if (!audit.fDeriveComplete)
        printf("  derivation warning: %s\n", audit.strDeriveError.c_str());
    printf("  total spendable balance:      %s BTF\n", FormatMoney(nTotal).c_str());
    printf("  covered by recovery phrase:   %s BTF (%d transaction(s))\n",
           FormatMoney(audit.nRecoverableCredit).c_str(), audit.nRecoverableTx);
    printf("  wallet.dat-only balance:      %s BTF (%d transaction(s))\n",
           FormatMoney(audit.nLegacyCredit).c_str(), audit.nLegacyTx);
    printf("  immature mining rewards:      %s BTF\n", FormatMoney(nImmatureTotal).c_str());
    printf("    phrase-backed immature:     %s BTF (%d transaction(s))\n",
           FormatMoney(audit.nRecoverableImmatureCredit).c_str(),
           audit.nRecoverableImmatureTx);
    printf("    wallet.dat-only immature:   %s BTF (%d transaction(s))\n",
           FormatMoney(audit.nLegacyImmatureCredit).c_str(),
           audit.nLegacyImmatureTx);

    if (!audit.fHaveSeed)
    {
        printf("\n");
        printf("This wallet has no recovery phrase. A file backup is the only backup.\n");
        fflush(stdout);
        return nTotal + nImmatureTotal > 0 ? 2 : 0;
    }
    if (!audit.fDeriveComplete)
    {
        printf("\n");
        printf("Warning: the audit could not derive every known phrase key, so coverage is incomplete.\n");
        fflush(stdout);
        return 2;
    }
    if (audit.nLegacyCredit > 0 || audit.nLegacyImmatureCredit > 0)
    {
        printf("\n");
        printf("Warning: some coins are on keys the phrase does not reproduce.\n");
        printf("Keep wallet.dat backups until that balance has been moved to a phrase-backed address.\n");
        fflush(stdout);
        return 2;
    }

    printf("\n");
    if (nTotal + nImmatureTotal > 0)
        printf("All known wallet balance is covered by the recovery phrase.\n");
    else
        printf("No wallet balance found yet.\n");
    fflush(stdout);
    return 0;
}

int CmdEncryptWallet(const std::string& strPassphrase)
{
    AttachTerminal();

    string strBackup;
    string strError;
    if (!EncryptWallet(strPassphrase, strBackup, strError))
    {
        fprintf(stderr, "Cannot encrypt wallet: %s\n", strError.c_str());
        fprintf(stderr, "Nothing was changed.\n");
        return 1;
    }

    printf("Wallet encrypted.\n");
    printf("The old unencrypted wallet was moved to:\n");
    printf("  %s\n", strBackup.c_str());
    printf("That backup still contains private keys in plain text. Move it offline or\n");
    printf("delete it after you have a safer backup plan.\n");
    printf("Restart Bitflash before using the wallet again.\n");
    fflush(stdout);

    // The rewritten wallet.dat is clean; the environment's write-ahead logs are
    // not, because every plaintext record this wallet ever wrote passed through
    // them. Closing the environment and dropping the logs is the last step of
    // encrypting, not an optimisation -- our own backup advice is to copy the
    // whole directory, and following it otherwise carries the keys along.
    PurgeDbEnvironmentLogs();
    return 0;
}

// Spend, from the command line.
//
// SendMoney() has been in this tree since 0.1.0 and only the window ever called
// it, so a headless node could be paid and could never pay: it held a balance
// with no way to move it. Found while trying to prove that change from a wallet
// with a recovery phrase lands on a key the phrase can reproduce -- a test that
// needs a spend, and there was no way to make one without a screen.
//
// Deliberately strict, because this moves money and there is nobody to click
// "are you sure": the address must decode, the amount must parse and be
// positive, and anything else refuses before touching the wallet.
int CmdSendTo(const std::string& strArg)
{
    AttachTerminal();

    if (IsWalletLocked())
    {
        fprintf(stderr, "Wallet is encrypted and locked. Start with /walletpassphrase or /walletpassphrase=@FILE to spend.\n");
        return 1;
    }

    std::string::size_type comma = strArg.rfind(',');
    if (comma == std::string::npos)
    {
        fprintf(stderr, "Usage: -sendto=ADDRESS,AMOUNT   (for example -sendto=B7kQ...,1.5)\n");
        return 1;
    }
    std::string strAddr   = strArg.substr(0, comma);
    std::string strAmount = strArg.substr(comma + 1);

    // Trim, so a quoted argument with stray spaces does not silently become an
    // invalid address and send nothing.
    while (!strAddr.empty()   && isspace((unsigned char)strAddr[0]))                strAddr.erase(0, 1);
    while (!strAddr.empty()   && isspace((unsigned char)strAddr[strAddr.size()-1])) strAddr.erase(strAddr.size()-1);
    while (!strAmount.empty() && isspace((unsigned char)strAmount[0]))              strAmount.erase(0, 1);
    while (!strAmount.empty() && isspace((unsigned char)strAmount[strAmount.size()-1])) strAmount.erase(strAmount.size()-1);

    uint160 hash160;
    if (!AddressToHash160(strAddr, hash160))
    {
        fprintf(stderr, "Not a valid address: %s\n", strAddr.c_str());
        return 1;
    }

    int64 nValue = 0;
    if (!ParseMoney(strAmount.c_str(), nValue) || nValue <= 0)
    {
        fprintf(stderr, "Not a valid amount: %s\n", strAmount.c_str());
        return 1;
    }

    std::string strWhy;
    if (!CanScanWalletTransactions(strWhy))
    {
        // Spending needs the chain: without it the wallet cannot tell which of
        // its outputs are still unspent, and a transaction built on that guess
        // is one the network will reject.
        fprintf(stderr, "The block chain is not loaded, so this wallet cannot tell "
                        "which coins it still has. Start the node and let it sync first.\n");
        return 1;
    }

    CScript scriptPubKey;
    scriptPubKey << OP_DUP << OP_HASH160 << hash160 << OP_EQUALVERIFY << OP_CHECKSIG;

    CWalletTx wtx;
    if (!SendMoney(scriptPubKey, nValue, wtx))
    {
        fprintf(stderr, "The transaction was not created. Usually that means the "
                        "balance is too low once the fee is counted.\n");
        return 1;
    }

    printf("Sent %s to %s\n", FormatMoney(nValue).c_str(), strAddr.c_str());
    printf("  transaction %s\n", wtx.GetHash().ToString().c_str());
    printf("  it needs to be relayed and mined before the other side sees it.\n");
    fflush(stdout);
    return 0;
}
