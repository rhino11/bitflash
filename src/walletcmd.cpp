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
#include "wallet_sqlite.h"

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

unsigned int WalletLastUsedPubKeyIndexNext(
    const std::map<unsigned int, std::vector<unsigned char> >& mapPubKeysByIndex)
{
    std::map<std::vector<unsigned char>, unsigned int> mapIndexByPubKey;
    for (std::map<unsigned int, std::vector<unsigned char> >::const_iterator it =
             mapPubKeysByIndex.begin();
         it != mapPubKeysByIndex.end(); ++it)
        mapIndexByPubKey[it->second] = it->first;

    unsigned int nNext = 0;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin();
             it != mapWallet.end(); ++it)
        {
            CWalletTx& wtx = (*it).second;
            for (int i = 0; i < (int)wtx.vout.size(); i++)
            {
                vector<unsigned char> vchPubKey;
                if (!ExtractPubKey(wtx.vout[i].scriptPubKey, false, vchPubKey))
                    continue;
                std::map<std::vector<unsigned char>, unsigned int>::const_iterator mi =
                    mapIndexByPubKey.find(vchPubKey);
                if (mi != mapIndexByPubKey.end() && mi->second + 1 > nNext)
                    nNext = mi->second + 1;
            }
        }
    }
    return nNext;
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
    const bool fRestoreBIP44 = nHDKeySchema == HD_SCHEMA_BIP44;
    unsigned int nLegacyScanNext = nHDNext;
    std::map<unsigned int, vector<unsigned char> > mapLegacyScanPubKeys;
    int nTotalDerived = fRestoreBIP44
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
        if (fRestoreBIP44)
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
                if (!DeriveHDKey(nLegacyScanNext, key, strDeriveError))
                    break;
                if (!AddKey(key))
                    break;
                mapLegacyScanPubKeys[nLegacyScanNext] = key.GetPubKey();
                nLegacyScanNext++;
                nTotalDerived++;
            }
            nHDKeySchema = nSavedSchema;
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

        if (fRestoreBIP44)
        {
            // The legacy branch is scanned only for compatibility with phrases
            // created before BIP44. Persist the last used legacy index + 1, not
            // the lookahead depth. Otherwise a restore with no legacy hits can
            // leave hdnext at RESTORE_MAX and make future compatibility scans
            // look exhausted even though no legacy key was ever used.
            unsigned int nLegacyUsedNext =
                WalletLastUsedPubKeyIndexNext(mapLegacyScanPubKeys);
            if (nLegacyUsedNext != nHDNext)
            {
                nHDNext = nLegacyUsedNext;
                CWalletDB().WriteHDNext(nHDNext);
            }
        }

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
                                    fRestoreBIP44 ? nLegacyScanNext : nHDNext,
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
    if (audit.fHaveSeed)
        printf("  recovery phrase: present\n");
    else if (audit.fSeedEncryptedLocked)
        printf("  recovery phrase: encrypted, unlock wallet to audit\n");
    else
        printf("  recovery phrase: not installed\n");
    if (audit.fHaveSeed)
    {
        printf("  derivation schema: %s\n", HDKeySchemaName(audit.nSchema).c_str());
        printf("  BIP44 coin type: %u (SLIP-0044 BITFLASH)\n", audit.nCoinType);
        printf("  derived keys known to this wallet: %u\n", audit.nDerivedKnown);
        printf("  receive/change counters: %u/%u\n",
               audit.nReceiveNext, audit.nChangeNext);
    }
    if (!audit.fDeriveComplete)
        printf("  derivation warning: %s\n", audit.strDeriveError.c_str());
    printf("  total spendable balance:      %s BTF\n", FormatMoney(nTotal).c_str());
    if (audit.fSeedEncryptedLocked)
    {
        printf("  recovery coverage:            unavailable while wallet is locked\n");
        printf("  immature mining rewards:      %s BTF\n", FormatMoney(nImmatureTotal).c_str());
        printf("\n");
        printf("Unlock the wallet with /walletpassphrase or /walletpassphrase=@FILE to audit phrase coverage.\n");
        fflush(stdout);
        return 2;
    }
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

struct WalletStorageAuditCounts
{
    unsigned int nTotal = 0;
    unsigned int nMalformed = 0;
    unsigned int nUnknown = 0;
    unsigned int nVersion = 0;
    unsigned int nNames = 0;
    unsigned int nTransactions = 0;
    unsigned int nPlainKeys = 0;
    unsigned int nEncryptedKeys = 0;
    unsigned int nMasterKeys = 0;
    unsigned int nDefaultKey = 0;
    unsigned int nPlainHDMaster = 0;
    unsigned int nPlainHDChainCode = 0;
    unsigned int nCryptedHDMaster = 0;
    unsigned int nCryptedHDChainCode = 0;
    unsigned int nWalletMinVersion = 0;
    unsigned int nPool = 0;
    unsigned int nSettings = 0;
    unsigned int nHDNext = 0;
    unsigned int nHDSchema = 0;
    unsigned int nHDCoinType = 0;
    unsigned int nHDReceiveNext = 0;
    unsigned int nHDChangeNext = 0;
};

static std::string HDSeedStorageState(unsigned int nMaster, unsigned int nChain)
{
    if (nMaster == 0 && nChain == 0)
        return "none";
    if (nMaster > 0 && nChain > 0)
        return "complete";
    return "incomplete";
}

static void CountWalletStorageType(const std::string& strType,
                                   WalletStorageAuditCounts& c)
{
    if (strType == "version")
        c.nVersion++;
    else if (strType == "name")
        c.nNames++;
    else if (strType == "tx")
        c.nTransactions++;
    else if (strType == "key")
        c.nPlainKeys++;
    else if (strType == "ckey")
        c.nEncryptedKeys++;
    else if (strType == "mkey")
        c.nMasterKeys++;
    else if (strType == "defaultkey")
        c.nDefaultKey++;
    else if (strType == "hdmaster")
        c.nPlainHDMaster++;
    else if (strType == "hdchaincode")
        c.nPlainHDChainCode++;
    else if (strType == "cryptedhdmaster")
        c.nCryptedHDMaster++;
    else if (strType == "cryptedhdchaincode")
        c.nCryptedHDChainCode++;
    else if (strType == "walletminversion")
        c.nWalletMinVersion++;
    else if (strType == "pool")
        c.nPool++;
    else if (strType == "setting")
        c.nSettings++;
    else if (strType == "hdnext")
        c.nHDNext++;
    else if (strType == "hdschema")
        c.nHDSchema++;
    else if (strType == "hdcointype")
        c.nHDCoinType++;
    else if (strType == "hdreceivenext")
        c.nHDReceiveNext++;
    else if (strType == "hdchangenext")
        c.nHDChangeNext++;
    else
        c.nUnknown++;
}

static bool ReadWalletStorageCounts(WalletStorageAuditCounts& counts,
                                    std::string& strError)
{
    class CWalletStorageCountVisitor : public CWalletRecordVisitor
    {
    public:
        WalletStorageAuditCounts& counts;

        explicit CWalletStorageCountVisitor(WalletStorageAuditCounts& countsIn)
            : counts(countsIn) { }

        bool VisitWalletRecord(const CDataStream& ssKeyIn,
                               const CDataStream& ssValue,
                               std::string& strErrorRet)
        {
            (void)ssValue;
            (void)strErrorRet;
            counts.nTotal++;
            try
            {
                CDataStream ssKey = ssKeyIn;
                std::string strType;
                ssKey >> strType;
                if (ssKey.fail())
                {
                    counts.nMalformed++;
                    return true;
                }
                CountWalletStorageType(strType, counts);
            }
            catch (...)
            {
                counts.nMalformed++;
            }
            return true;
        }
    };

    CWalletStorageCountVisitor visitor(counts);
    return ScanWalletRecords(visitor, strError);
}

static std::string WalletStorageAuditJson(const WalletStorageAuditCounts& counts)
{
    std::string strJson;
    strJson += "{\n";
    strJson += "  \"format\": \"bitflash-wallet-storage-audit-v1\",\n";
    strJson += strprintf("  \"records_total\": %u,\n", counts.nTotal);
    strJson += strprintf("  \"malformed_records\": %u,\n", counts.nMalformed);
    strJson += strprintf("  \"unknown_records\": %u,\n", counts.nUnknown);
    strJson += strprintf("  \"plain_private_keys\": %u,\n", counts.nPlainKeys);
    strJson += strprintf("  \"encrypted_private_keys\": %u,\n", counts.nEncryptedKeys);
    strJson += strprintf("  \"encryption_master_keys\": %u,\n", counts.nMasterKeys);
    strJson += strprintf("  \"default_public_key\": \"%s\",\n",
                          counts.nDefaultKey ? "present" : "none");
    strJson += strprintf("  \"plain_hd_seed\": \"%s\",\n",
                          HDSeedStorageState(counts.nPlainHDMaster,
                                             counts.nPlainHDChainCode).c_str());
    strJson += strprintf("  \"encrypted_hd_seed\": \"%s\",\n",
                          HDSeedStorageState(counts.nCryptedHDMaster,
                                             counts.nCryptedHDChainCode).c_str());
    strJson += strprintf("  \"wallet_minimum_version\": \"%s\",\n",
                          counts.nWalletMinVersion ? "present" : "none");
    strJson += strprintf("  \"keypool_entries\": %u,\n", counts.nPool);
    strJson += strprintf("  \"wallet_transactions\": %u,\n", counts.nTransactions);
    strJson += strprintf("  \"address_book_labels\": %u,\n", counts.nNames);
    strJson += strprintf("  \"settings\": %u,\n", counts.nSettings);
    strJson += strprintf("  \"hd_metadata_records\": %u,\n",
                          counts.nHDNext + counts.nHDSchema + counts.nHDCoinType +
                          counts.nHDReceiveNext + counts.nHDChangeNext);
    strJson += strprintf("  \"database_version_records\": %u\n", counts.nVersion);
    strJson += "}\n";
    return strJson;
}

static bool WriteAuditTextFile(const std::string& strPath,
                               const std::string& strText,
                               std::string& strError)
{
    FILE* pf = fopen(strPath.c_str(), "wb");
    if (!pf)
    {
        strError = "cannot open output file";
        return false;
    }
    size_t nWritten = fwrite(strText.data(), 1, strText.size(), pf);
    bool fCloseOk = fclose(pf) == 0;
    if (nWritten != strText.size() || !fCloseOk)
    {
        strError = "could not write the complete output file";
        return false;
    }
    return true;
}

static void AddWalletStorageFailure(std::vector<std::string>& vFailures,
                                    const std::string& strFailure)
{
    vFailures.push_back(strFailure);
}

static void BuildWalletStorageSanityFailures(const WalletStorageAuditCounts& counts,
                                             std::vector<std::string>& vFailures)
{
    bool fPlainHD = counts.nPlainHDMaster > 0 || counts.nPlainHDChainCode > 0;
    bool fCryptedHD = counts.nCryptedHDMaster > 0 || counts.nCryptedHDChainCode > 0;
    bool fEncryptedRecords = counts.nEncryptedKeys > 0 ||
                             counts.nMasterKeys > 0 ||
                             fCryptedHD;

    if (counts.nMalformed > 0)
        AddWalletStorageFailure(vFailures, "wallet.dat contains malformed records");
    if (counts.nUnknown > 0)
        AddWalletStorageFailure(vFailures, "wallet.dat contains unknown records");
    if ((counts.nPlainHDMaster > 0) != (counts.nPlainHDChainCode > 0))
        AddWalletStorageFailure(vFailures, "plain HD seed is incomplete");
    if ((counts.nCryptedHDMaster > 0) != (counts.nCryptedHDChainCode > 0))
        AddWalletStorageFailure(vFailures, "encrypted HD seed is incomplete");
    if (fPlainHD && fCryptedHD)
        AddWalletStorageFailure(vFailures, "wallet.dat contains both plain and encrypted HD seed records");
    if (counts.nDefaultKey > 1)
        AddWalletStorageFailure(vFailures, "wallet.dat contains more than one default public key record");
    if (counts.nWalletMinVersion > 1)
        AddWalletStorageFailure(vFailures, "wallet.dat contains more than one minimum-version record");

    if (fEncryptedRecords)
    {
        if (counts.nPlainKeys > 0)
            AddWalletStorageFailure(vFailures, "encrypted wallet still contains plain private key records");
        if (fPlainHD)
            AddWalletStorageFailure(vFailures, "encrypted wallet still contains plain HD seed records");
        if (counts.nMasterKeys == 0)
            AddWalletStorageFailure(vFailures, "encrypted wallet has no encryption master key record");
        if (counts.nWalletMinVersion == 0)
            AddWalletStorageFailure(vFailures, "encrypted wallet has no minimum-version record");
    }
}

int CmdWalletStorageCheck()
{
    AttachTerminal();

    WalletStorageAuditCounts counts;
    std::string strError;
    if (!ReadWalletStorageCounts(counts, strError))
    {
        fprintf(stderr, "Cannot check wallet storage: %s\n", strError.c_str());
        return 1;
    }

    std::vector<std::string> vFailures;
    BuildWalletStorageSanityFailures(counts, vFailures);

    printf("Wallet storage sanity check\n");
    printf("  records total:             %u\n", counts.nTotal);
    printf("  encrypted records:         %s\n",
           (counts.nEncryptedKeys || counts.nMasterKeys ||
            counts.nCryptedHDMaster || counts.nCryptedHDChainCode) ? "yes" : "no");
    printf("  plain private keys:        %u\n", counts.nPlainKeys);
    printf("  encrypted private keys:    %u\n", counts.nEncryptedKeys);
    printf("  plain HD seed:             %s\n",
           HDSeedStorageState(counts.nPlainHDMaster,
                              counts.nPlainHDChainCode).c_str());
    printf("  encrypted HD seed:         %s\n",
           HDSeedStorageState(counts.nCryptedHDMaster,
                              counts.nCryptedHDChainCode).c_str());
    if (vFailures.empty())
    {
        printf("  storage sanity:            ok\n");
        fflush(stdout);
        return 0;
    }

    printf("  storage sanity:            failed\n");
    for (std::vector<std::string>::const_iterator it = vFailures.begin();
         it != vFailures.end(); ++it)
        printf("  failure:                   %s\n", it->c_str());
    fflush(stdout);
    return 2;
}

int CmdWalletStorageAudit(const std::string& strJsonOut)
{
    AttachTerminal();

    WalletStorageAuditCounts counts;
    std::string strError;
    if (!ReadWalletStorageCounts(counts, strError))
    {
        fprintf(stderr, "Cannot audit wallet storage: %s\n", strError.c_str());
        return 1;
    }

    if (!strJsonOut.empty())
    {
        std::string strWriteError;
        if (!WriteAuditTextFile(strJsonOut,
                                WalletStorageAuditJson(counts),
                                strWriteError))
        {
            fprintf(stderr, "Cannot write wallet storage audit JSON: %s\n",
                    strWriteError.c_str());
            return 1;
        }
        printf("Wallet storage audit written to %s\n", strJsonOut.c_str());
        fflush(stdout);
        return counts.nMalformed > 0 ? 2 : 0;
    }

    printf("Wallet storage audit\n");
    printf("  records total:             %u\n", counts.nTotal);
    printf("  malformed records:         %u\n", counts.nMalformed);
    printf("  unknown records:           %u\n", counts.nUnknown);
    printf("  plain private keys:        %u\n", counts.nPlainKeys);
    printf("  encrypted private keys:    %u\n", counts.nEncryptedKeys);
    printf("  encryption master keys:    %u\n", counts.nMasterKeys);
    printf("  default public key:        %s\n", counts.nDefaultKey ? "present" : "none");
    printf("  plain HD seed:             %s\n",
           HDSeedStorageState(counts.nPlainHDMaster,
                              counts.nPlainHDChainCode).c_str());
    printf("  encrypted HD seed:         %s\n",
           HDSeedStorageState(counts.nCryptedHDMaster,
                              counts.nCryptedHDChainCode).c_str());
    printf("  wallet minimum version:    %s\n",
           counts.nWalletMinVersion ? "present" : "none");
    printf("  keypool entries:           %u\n", counts.nPool);
    printf("  wallet transactions:       %u\n", counts.nTransactions);
    printf("  address book labels:       %u\n", counts.nNames);
    printf("  settings:                  %u\n", counts.nSettings);
    printf("  HD metadata records:       %u\n",
           counts.nHDNext + counts.nHDSchema + counts.nHDCoinType +
           counts.nHDReceiveNext + counts.nHDChangeNext);
    printf("  database version records:  %u\n", counts.nVersion);
    fflush(stdout);

    if (counts.nMalformed > 0)
        return 2;
    return 0;
}

static vector<unsigned char> DataStreamBytesLocal(const CDataStream& ss)
{
    return vector<unsigned char>(ss.begin(), ss.end());
}

namespace {

static void RemoveSQLiteExportFiles(const string& strPath)
{
    remove(strPath.c_str());
    remove((strPath + "-wal").c_str());
    remove((strPath + "-shm").c_str());
}

static void RemoveFailedRestoreWallet(const string& strWalletPath)
{
    DBFlush(true);
    remove(strWalletPath.c_str());
}

class CWalletSQLiteExportVisitor : public CWalletRecordVisitor
{
public:
    CWalletDBSQLite& db;
    int& nCopied;

    CWalletSQLiteExportVisitor(CWalletDBSQLite& dbIn, int& nCopiedIn)
        : db(dbIn), nCopied(nCopiedIn) { }

    bool VisitWalletRecord(const CDataStream& ssKey,
                           const CDataStream& ssValue,
                           string& strErrorRet)
    {
        if (!db.WriteRecord(DataStreamBytesLocal(ssKey),
                            DataStreamBytesLocal(ssValue),
                            strErrorRet))
            return false;
        nCopied++;
        return true;
    }
};

class CWalletRecordMapVisitor : public CWalletRecordVisitor
{
public:
    std::map<vector<unsigned char>, vector<unsigned char> >& mapRecords;

    explicit CWalletRecordMapVisitor(
        std::map<vector<unsigned char>, vector<unsigned char> >& mapRecordsIn)
        : mapRecords(mapRecordsIn) { }

    bool VisitWalletRecord(const CDataStream& ssKey,
                           const CDataStream& ssValue,
                           string& strErrorRet)
    {
        vector<unsigned char> vchKey = DataStreamBytesLocal(ssKey);
        if (mapRecords.count(vchKey))
        {
            strErrorRet = "duplicate serialized wallet key";
            return false;
        }
        mapRecords[vchKey] = DataStreamBytesLocal(ssValue);
        return true;
    }
};

class CWalletRawRestoreDB : public CWalletDB
{
public:
    CWalletRawRestoreDB(const char* pszMode="cr+", bool fTxn=true)
        : CWalletDB(pszMode, fTxn) { }

    bool WriteRaw(CDataStream ssKey, CDataStream ssValue)
    {
        if (!pdb || ssKey.empty())
            return false;

        Dbt datKey((void*)&ssKey[0], ssKey.size());
        Dbt datValue(ssValue.empty() ? NULL : (void*)&ssValue[0],
                     ssValue.size());
        int ret = pdb->put(GetTxn(), &datKey, &datValue, 0);

        memset(datKey.get_data(), 0, datKey.get_size());
        if (datValue.get_data())
            memset(datValue.get_data(), 0, datValue.get_size());
        return ret == 0;
    }
};

class CWalletSQLiteRestoreVisitor : public CWalletRecordVisitor
{
public:
    CWalletRawRestoreDB& db;
    int& nCopied;

    CWalletSQLiteRestoreVisitor(CWalletRawRestoreDB& dbIn, int& nCopiedIn)
        : db(dbIn), nCopied(nCopiedIn) { }

    bool VisitWalletRecord(const CDataStream& ssKey,
                           const CDataStream& ssValue,
                           string& strErrorRet)
    {
        if (!db.WriteRaw(ssKey, ssValue))
        {
            strErrorRet = "could not write raw wallet record";
            return false;
        }
        nCopied++;
        return true;
    }
};

class CWalletSQLiteLoadCheckVisitor : public CWalletRecordVisitor
{
public:
    int nRecords;
    int nUnknown;
    string strFailure;

    CWalletSQLiteLoadCheckVisitor() : nRecords(0), nUnknown(0) { }

    bool Fail(const string& strMessage, string& strErrorRet)
    {
        strFailure = strMessage;
        strErrorRet = strMessage;
        return false;
    }

    bool VisitWalletRecord(const CDataStream& ssKeyIn,
                           const CDataStream& ssValueIn,
                           string& strErrorRet)
    {
        nRecords++;
        try
        {
            CDataStream ssKey = ssKeyIn;
            CDataStream ssValue = ssValueIn;
            string strType;
            ssKey >> strType;
            if (ssKey.fail())
                return Fail("malformed wallet record key", strErrorRet);

            if (strType == "name")
            {
                string strAddress;
                string strName;
                ssKey >> strAddress;
                ssValue >> strName;
            }
            else if (strType == "tx")
            {
                uint256 hash;
                CWalletTx wtx;
                ssKey >> hash;
                ssValue >> wtx;
            }
            else if (strType == "key")
            {
                vector<unsigned char> vchPubKey;
                CPrivKey vchPrivKey;
                ssKey >> vchPubKey;
                ssValue >> vchPrivKey;
            }
            else if (strType == "mkey")
            {
                unsigned int nID = 0;
                CWalletMasterKey kMasterKey;
                ssKey >> nID;
                ssValue >> kMasterKey;
            }
            else if (strType == "ckey")
            {
                vector<unsigned char> vchPubKey;
                vector<unsigned char> vchCryptedSecret;
                ssKey >> vchPubKey;
                ssValue >> vchCryptedSecret;
            }
            else if (strType == "defaultkey" ||
                     strType == "hdmaster" ||
                     strType == "hdchaincode" ||
                     strType == "cryptedhdmaster" ||
                     strType == "cryptedhdchaincode")
            {
                vector<unsigned char> vch;
                ssValue >> vch;
            }
            else if (strType == "hdnext" ||
                     strType == "hdreceivenext" ||
                     strType == "hdchangenext" ||
                     strType == "hdcointype")
            {
                unsigned int nValue = 0;
                ssValue >> nValue;
            }
            else if (strType == "hdschema")
            {
                int nSchema = 0;
                ssValue >> nSchema;
                if (!ssValue.fail() &&
                    nSchema != HD_SCHEMA_NONE &&
                    nSchema != HD_SCHEMA_LEGACY &&
                    nSchema != HD_SCHEMA_BIP44)
                    return Fail("unsupported deterministic wallet schema",
                                strErrorRet);
            }
            else if (strType == "walletminversion")
            {
                int nMinVersion = 0;
                ssValue >> nMinVersion;
                if (!ssValue.fail() && nMinVersion > WALLET_FORMAT_SUPPORTED)
                    return Fail("unsupported future wallet format", strErrorRet);
            }
            else if (strType == "pool")
            {
                int64 nIndex = 0;
                vector<unsigned char> vchPubKey;
                ssKey >> nIndex;
                ssValue >> vchPubKey;
            }
            else if (strType == "setting")
            {
                string strKey;
                ssKey >> strKey;
                if (strKey == "nTransactionFee")
                {
                    int64 nValue = 0;
                    ssValue >> nValue;
                }
                else if (strKey == "addrIncoming")
                {
                    CAddress addr;
                    ssValue >> addr;
                }
                else if (strKey == "nMineMode")
                {
                    int nValue = 0;
                    ssValue >> nValue;
                }
                else if (strKey == "fGenerateBitcoins")
                {
                    int fValue = 0;
                    ssValue >> fValue;
                }
                else if (strKey == "strParticipantPool")
                {
                    string strValue;
                    ssValue >> strValue;
                }
            }
            else if (strType == "version")
            {
                int nVersion = 0;
                ssValue >> nVersion;
            }
            else
            {
                nUnknown++;
            }

            if (ssKey.fail())
                return Fail("malformed wallet record key", strErrorRet);
            if (ssValue.fail())
                return Fail("malformed wallet record value", strErrorRet);
        }
        catch (const std::exception& e)
        {
            return Fail(strprintf("wallet record parse exception: %s", e.what()),
                        strErrorRet);
        }
        catch (...)
        {
            return Fail("wallet record parse exception", strErrorRet);
        }
        return true;
    }
};

} // namespace

int CmdWalletSQLiteExport(const std::string& strDest)
{
    AttachTerminal();

    if (strDest.empty())
    {
        fprintf(stderr, "Missing SQLite wallet export path.\n");
        return 1;
    }
    if (FileExists(strDest.c_str()))
    {
        fprintf(stderr, "Refusing to overwrite existing SQLite wallet export: %s\n",
                strDest.c_str());
        return 1;
    }

    string strError;
    CWalletDBSQLite db;
    if (!db.Open(strDest, strError))
    {
        RemoveSQLiteExportFiles(strDest);
        fprintf(stderr, "Cannot open SQLite wallet export: %s\n", strError.c_str());
        return 1;
    }
    if (!db.BeginTransaction(strError))
    {
        db.Close();
        RemoveSQLiteExportFiles(strDest);
        fprintf(stderr, "Cannot begin SQLite wallet export: %s\n", strError.c_str());
        return 1;
    }

    int nCopied = 0;
    CWalletSQLiteExportVisitor visitor(db, nCopied);
    if (!ScanWalletRecords(visitor, strError))
    {
        string strRollbackError;
        db.RollbackTransaction(strRollbackError);
        db.Close();
        RemoveSQLiteExportFiles(strDest);
        fprintf(stderr, "Cannot export wallet.dat to SQLite: %s\n", strError.c_str());
        return 1;
    }
    if (!db.CommitTransaction(strError))
    {
        db.Close();
        RemoveSQLiteExportFiles(strDest);
        fprintf(stderr, "Cannot commit SQLite wallet export: %s\n", strError.c_str());
        return 1;
    }
    if (!db.Checkpoint(strError))
    {
        db.Close();
        RemoveSQLiteExportFiles(strDest);
        fprintf(stderr, "Cannot checkpoint SQLite wallet export: %s\n", strError.c_str());
        return 1;
    }

    int nCount = 0;
    if (!db.CountRecords(nCount, strError))
    {
        db.Close();
        RemoveSQLiteExportFiles(strDest);
        fprintf(stderr, "Cannot verify SQLite wallet export count: %s\n",
                strError.c_str());
        return 1;
    }
    if (nCount != nCopied)
    {
        db.Close();
        RemoveSQLiteExportFiles(strDest);
        fprintf(stderr, "SQLite wallet export count mismatch: copied %d, stored %d\n",
                nCopied, nCount);
        return 1;
    }

    printf("SQLite wallet export written to %s\n", strDest.c_str());
    printf("  records copied:            %d\n", nCopied);
    fflush(stdout);
    return 0;
}

int CmdWalletSQLiteVerify(const std::string& strPath)
{
    AttachTerminal();

    if (strPath.empty())
    {
        fprintf(stderr, "Missing SQLite wallet export path.\n");
        return 1;
    }
    if (!FileExists(strPath.c_str()))
    {
        fprintf(stderr, "SQLite wallet export does not exist: %s\n",
                strPath.c_str());
        return 1;
    }

    std::map<vector<unsigned char>, vector<unsigned char> > mapBDB;
    std::map<vector<unsigned char>, vector<unsigned char> > mapSQLite;
    string strError;

    CWalletRecordMapVisitor bdbVisitor(mapBDB);
    if (!ScanWalletRecords(bdbVisitor, strError))
    {
        fprintf(stderr, "Cannot scan wallet.dat records: %s\n", strError.c_str());
        return 1;
    }

    CWalletDBSQLite db;
    if (!db.Open(strPath, strError))
    {
        fprintf(stderr, "Cannot open SQLite wallet export: %s\n", strError.c_str());
        return 1;
    }
    CWalletRecordMapVisitor sqliteVisitor(mapSQLite);
    if (!db.ScanRecords(sqliteVisitor, strError))
    {
        fprintf(stderr, "Cannot scan SQLite wallet export: %s\n", strError.c_str());
        return 1;
    }

    int nMissing = 0;
    int nMismatched = 0;
    for (std::map<vector<unsigned char>, vector<unsigned char> >::const_iterator it =
             mapBDB.begin(); it != mapBDB.end(); ++it)
    {
        std::map<vector<unsigned char>, vector<unsigned char> >::const_iterator sit =
            mapSQLite.find(it->first);
        if (sit == mapSQLite.end())
            nMissing++;
        else if (sit->second != it->second)
            nMismatched++;
    }

    int nExtra = 0;
    for (std::map<vector<unsigned char>, vector<unsigned char> >::const_iterator it =
             mapSQLite.begin(); it != mapSQLite.end(); ++it)
    {
        if (!mapBDB.count(it->first))
            nExtra++;
    }

    printf("SQLite wallet export verification\n");
    printf("  wallet.dat records:        %u\n", (unsigned int)mapBDB.size());
    printf("  SQLite records:            %u\n", (unsigned int)mapSQLite.size());
    printf("  missing records:           %d\n", nMissing);
    printf("  extra records:             %d\n", nExtra);
    printf("  record value mismatches:   %d\n", nMismatched);
    if (nMissing == 0 && nExtra == 0 && nMismatched == 0)
    {
        printf("  verification:              ok\n");
        fflush(stdout);
        return 0;
    }

    printf("  verification:              failed\n");
    fflush(stdout);
    return 2;
}

int CmdWalletSQLiteRestore(const std::string& strPath)
{
    AttachTerminal();

    if (strPath.empty())
    {
        fprintf(stderr, "Missing SQLite wallet export path.\n");
        return 1;
    }
    if (!FileExists(strPath.c_str()))
    {
        fprintf(stderr, "SQLite wallet export does not exist: %s\n",
                strPath.c_str());
        return 1;
    }

    string strWalletPath = GetAppDir() + "/wallet.dat";
    if (FileExists(strWalletPath.c_str()))
    {
        fprintf(stderr, "Refusing to overwrite existing wallet.dat: %s\n",
                strWalletPath.c_str());
        return 1;
    }

    string strError;
    CWalletDBSQLite sqlite;
    if (!sqlite.Open(strPath, strError))
    {
        fprintf(stderr, "Cannot open SQLite wallet export: %s\n", strError.c_str());
        return 1;
    }

    int nSQLiteRecords = 0;
    if (!sqlite.CountRecords(nSQLiteRecords, strError))
    {
        fprintf(stderr, "Cannot count SQLite wallet export records: %s\n",
                strError.c_str());
        return 1;
    }
    if (nSQLiteRecords <= 0)
    {
        fprintf(stderr, "SQLite wallet export contains no records.\n");
        return 2;
    }

    CWalletRawRestoreDB bdb("cr+", true);
    if (!bdb.TxnBegin())
    {
        fprintf(stderr, "Cannot begin Berkeley DB restore transaction.\n");
        return 1;
    }

    int nCopied = 0;
    CWalletSQLiteRestoreVisitor visitor(bdb, nCopied);
    if (!sqlite.ScanRecords(visitor, strError))
    {
        bdb.TxnAbort();
        bdb.Close();
        RemoveFailedRestoreWallet(strWalletPath);
        fprintf(stderr, "Cannot restore SQLite wallet export: %s\n",
                strError.c_str());
        return 1;
    }
    if (nCopied != nSQLiteRecords)
    {
        bdb.TxnAbort();
        bdb.Close();
        RemoveFailedRestoreWallet(strWalletPath);
        fprintf(stderr, "SQLite wallet restore copied %d records, expected %d.\n",
                nCopied, nSQLiteRecords);
        return 2;
    }
    if (!bdb.TxnCommit())
    {
        bdb.Close();
        RemoveFailedRestoreWallet(strWalletPath);
        fprintf(stderr, "Cannot commit Berkeley DB restore transaction.\n");
        return 1;
    }

    printf("SQLite wallet export restored to wallet.dat\n");
    printf("  records restored:          %d\n", nCopied);
    fflush(stdout);
    return 0;
}

int CmdWalletSQLiteLoadCheck(const std::string& strPath)
{
    AttachTerminal();

    if (strPath.empty())
    {
        fprintf(stderr, "Missing SQLite wallet export path.\n");
        return 1;
    }
    if (!FileExists(strPath.c_str()))
    {
        fprintf(stderr, "SQLite wallet export does not exist: %s\n",
                strPath.c_str());
        return 1;
    }

    string strError;
    CWalletDBSQLite sqlite;
    if (!sqlite.Open(strPath, strError))
    {
        fprintf(stderr, "Cannot open SQLite wallet export: %s\n", strError.c_str());
        return 1;
    }

    CWalletSQLiteLoadCheckVisitor visitor;
    if (!sqlite.ScanRecords(visitor, strError))
    {
        printf("SQLite wallet load check\n");
        printf("  records checked:           %d\n", visitor.nRecords);
        printf("  unknown records:           %d\n", visitor.nUnknown);
        printf("  load check:                failed\n");
        printf("  failure:                   %s\n", strError.c_str());
        fflush(stdout);
        return 2;
    }

    printf("SQLite wallet load check\n");
    printf("  records checked:           %d\n", visitor.nRecords);
    printf("  unknown records:           %d\n", visitor.nUnknown);
    printf("  load check:                ok\n");
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
