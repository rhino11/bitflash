// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"






//
// CDB
//

static CCriticalSection cs_db;
static bool fDbEnvInit = false;
DbEnv dbenv(0u);
static map<string, int> mapFileUseCount;

class CDBInit
{
public:
    CDBInit()
    {
    }
    ~CDBInit()
    {
        if (fDbEnvInit)
        {
            try { dbenv.close(0); }
            catch (...) { }
            fDbEnvInit = false;
        }
    }
}
instance_of_cdbinit;


CDB::CDB(const char* pszFile, const char* pszMode, bool fTxn) : pdb(NULL)
{
    int ret;
    if (pszFile == NULL)
        return;

    bool fCreate = strchr(pszMode, 'c');
    bool fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;
    else if (fReadOnly)
        nFlags |= DB_RDONLY;
    if (!fReadOnly || fTxn)
        nFlags |= DB_AUTO_COMMIT;

    CRITICAL_BLOCK(cs_db)
    {
        if (!fDbEnvInit)
        {
            string strAppDir = GetAppDir();
            string strLogDir = strAppDir + "/database";

            // _mkdir returns 0 only when it actually created the directory, so
            // this is also the test for "this environment did not exist until
            // now". See the recovery block after dbenv.open() for why we care.
            bool fFreshEnv = (_mkdir(strLogDir.c_str()) == 0);

            printf("dbenv.open strAppDir=%s\n", strAppDir.c_str());

            dbenv.set_lg_dir(strLogDir.c_str());
            dbenv.set_lg_max(10000000);
            dbenv.set_lk_max_locks(10000);
            dbenv.set_lk_max_objects(10000);
            dbenv.set_errfile(fopen("db.log", "a")); /// debug
            ///dbenv.log_set_config(DB_LOG_AUTO_REMOVE, 1); /// causes corruption
            ret = dbenv.open(strAppDir.c_str(),
                             DB_CREATE     |
                             DB_INIT_LOCK  |
                             DB_INIT_LOG   |
                             DB_INIT_MPOOL |
                             DB_INIT_TXN   |
                             DB_THREAD     |
                             DB_PRIVATE    |
                             DB_RECOVER,
                             0);
            if (ret > 0)
                throw runtime_error(strprintf("CDB() : error %d opening database environment\n", ret));
            fDbEnvInit = true;

            // A Berkeley DB file records, in every page header, a log sequence
            // number belonging to the environment that wrote it. Carried into a
            // different environment those numbers refer to logs that do not
            // exist, and BDB refuses to write: "Db::put: Invalid argument",
            // thrown from a path that used to abort the process.
            //
            // That is what happens when someone backs up wallet.dat on its own.
            // It is the obviously important file, it is the only one people
            // copy, and the environment it is welded to lives in a database/
            // subdirectory nobody has reason to suspect. The file is intact --
            // same bytes, same keys -- and the wallet still will not open.
            // Issue #40 reports exactly this, after the fact.
            //
            // lsn_reset() exists for precisely this migration, so do it for
            // them. A fresh environment beside pre-existing .dat files means
            // those files came from somewhere else; in the normal case the
            // environment is already there and none of this runs.
            if (fFreshEnv)
            {
                static const char* pszBdbFiles[] = { "wallet.dat", "blkindex.dat" };
                for (int i = 0; i < (int)(sizeof(pszBdbFiles)/sizeof(pszBdbFiles[0])); i++)
                {
                    const char* pszName = pszBdbFiles[i];
                    if (!FileExists((strAppDir + "/" + pszName).c_str()))
                        continue;
                    try
                    {
                        if (dbenv.lsn_reset(pszName, 0) == 0)
                            printf("CDB() : adopted %s from another environment "
                                   "(log sequence numbers reset)\n", pszName);
                    }
                    catch (...) { }   // best effort; the open below reports real trouble
                }
            }
        }

        strFile = pszFile;
        ++mapFileUseCount[strFile];
    }

    pdb = new Db(&dbenv, 0);

    ret = pdb->open(NULL,      // Txn pointer
                    pszFile,   // Filename
                    "main",    // Logical db name
                    DB_BTREE,  // Database type
                    nFlags,    // Flags
                    0);

    if (ret > 0)
    {
        delete pdb;
        pdb = NULL;
        CRITICAL_BLOCK(cs_db)
            --mapFileUseCount[strFile];
        strFile = "";
        throw runtime_error(strprintf("CDB() : can't open database file %s, error %d\n", pszFile, ret));
    }

    if (fCreate && !Exists(string("version")))
        WriteVersion(VERSION);

    RandAddSeed();
}

void CDB::Close()
{
    if (!pdb)
        return;
    if (!vTxn.empty())
        vTxn.front()->abort();
    vTxn.clear();
    try { pdb->close(0); } catch (...) { }
    delete pdb;
    pdb = NULL;
    try { dbenv.txn_checkpoint(0, 0, 0); } catch (...) { }

    CRITICAL_BLOCK(cs_db)
        --mapFileUseCount[strFile];

    RandAddSeed();
}

void DBFlush(bool fShutdown)
{
    // Flush log data to the actual data file
    //  on all files that are not in use
    printf("DBFlush(%s)\n", fShutdown ? "true" : "false");
    CRITICAL_BLOCK(cs_db)
    {
        // This runs on the way out. Anything that throws here and is not caught
        // takes the process down before the wallet has been put down cleanly,
        // which is the difference between a portable wallet.dat and one welded
        // to this directory -- the lsn_reset just below is what frees it.
        try { dbenv.txn_checkpoint(0, 0, 0); }
        catch (const std::exception& e)
        { printf("DBFlush() : checkpoint failed: %s\n", e.what()); }

        map<string, int>::iterator mi = mapFileUseCount.begin();
        while (mi != mapFileUseCount.end())
        {
            string strFile = (*mi).first;
            int nRefCount = (*mi).second;
            if (nRefCount == 0)
            {
                try { dbenv.lsn_reset(strFile.c_str(), 0); }
                catch (const std::exception& e)
                { printf("DBFlush() : lsn_reset(%s) failed: %s\n", strFile.c_str(), e.what()); }
                mapFileUseCount.erase(mi++);
            }
            else
                mi++;
        }
        if (fShutdown)
        {
            char** listp;
            if (mapFileUseCount.empty())
                try { dbenv.log_archive(&listp, DB_ARCH_REMOVE); } catch (...) { }
            try { dbenv.close(0); } catch (...) { }
            fDbEnvInit = false;
        }
    }
}






//
// CTxDB
//

bool CTxDB::ReadTxIndex(uint256 hash, CTxIndex& txindex)
{
    assert(!fClient);
    txindex.SetNull();
    return Read(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::UpdateTxIndex(uint256 hash, const CTxIndex& txindex)
{
    assert(!fClient);
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight)
{
    assert(!fClient);

    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction& tx)
{
    assert(!fClient);
    uint256 hash = tx.GetHash();

    return Erase(make_pair(string("tx"), hash));
}

bool CTxDB::ContainsTx(uint256 hash)
{
    assert(!fClient);
    return Exists(make_pair(string("tx"), hash));
}

bool CTxDB::ReadOwnerTxes(uint160 hash160, int nMinHeight, vector<CTransaction>& vtx)
{
    assert(!fClient);
    vtx.clear();

    // Get cursor
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        return false;

    unsigned int fFlags = DB_SET_RANGE;
    loop
    {
        // Read next record
        CDataStream ssKey;
        if (fFlags == DB_SET_RANGE)
            ssKey << string("owner") << hash160 << CDiskTxPos(0, 0, 0);
        CDataStream ssValue;
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
            return false;

        // Unserialize
        string strType;
        uint160 hashItem;
        CDiskTxPos pos;
        ssKey >> strType >> hashItem >> pos;
        int nItemHeight;
        ssValue >> nItemHeight;

        // Read transaction
        if (strType != "owner" || hashItem != hash160)
            break;
        if (nItemHeight >= nMinHeight)
        {
            vtx.resize(vtx.size()+1);
            if (!vtx.back().ReadFromDisk(pos))
                return false;
        }
    }
    return true;
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
    assert(!fClient);
    tx.SetNull();
    if (!ReadTxIndex(hash, txindex))
        return false;
    return (tx.ReadFromDisk(txindex.pos));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}

bool CTxDB::EraseBlockIndex(uint256 hash)
{
    return Erase(make_pair(string("blockindex"), hash));
}

bool CTxDB::ReadHashBestChain(uint256& hashBestChain)
{
    return Read(string("hashBestChain"), hashBestChain);
}

bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(string("hashBestChain"), hashBestChain);
}

CBlockIndex* InsertBlockIndex(uint256 hash)
{
    if (hash == 0)
        return NULL;

    // Return existing
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
    mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool CTxDB::LoadBlockIndex()
{
    // Get cursor
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        return false;

    unsigned int fFlags = DB_SET_RANGE;
    loop
    {
        // Read next record
        CDataStream ssKey;
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("blockindex"), uint256(0));
        CDataStream ssValue;
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
            return false;

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType == "blockindex")
        {
            CDiskBlockIndex diskindex;
            ssValue >> diskindex;

            // Construct block index object
            CBlockIndex* pindexNew = InsertBlockIndex(diskindex.GetBlockHash());
            pindexNew->pprev          = InsertBlockIndex(diskindex.hashPrev);
            pindexNew->pnext          = InsertBlockIndex(diskindex.hashNext);
            pindexNew->nFile          = diskindex.nFile;
            pindexNew->nBlockPos      = diskindex.nBlockPos;
            pindexNew->nHeight        = diskindex.nHeight;
            pindexNew->nVersion       = diskindex.nVersion;
            pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
            pindexNew->nTime          = diskindex.nTime;
            pindexNew->nBits          = diskindex.nBits;
            pindexNew->nNonce         = diskindex.nNonce;

            // Watch for genesis block and best block
            if (pindexGenesisBlock == NULL && diskindex.GetBlockHash() == hashGenesisBlock)
                pindexGenesisBlock = pindexNew;
        }
        else
        {
            break;
        }
    }

    if (!ReadHashBestChain(hashBestChain))
    {
        if (pindexGenesisBlock == NULL)
            return true;
        return error("CTxDB::LoadBlockIndex() : hashBestChain not found\n");
    }

    if (!mapBlockIndex.count(hashBestChain))
        return error("CTxDB::LoadBlockIndex() : blockindex for hashBestChain not found\n");
    pindexBest = mapBlockIndex[hashBestChain];
    nBestHeight = pindexBest->nHeight;
    printf("LoadBlockIndex(): hashBestChain=%s  height=%d\n", hashBestChain.ToString().substr(0,14).c_str(), nBestHeight);

    return true;
}





// Legacy IP-based peer address database (CAddrDB / addr.dat) removed --
// peer discovery is entirely Nostr/.btf-based now.




//
// CReviewDB
//

bool CReviewDB::ReadReviews(uint256 hash, vector<CReview>& vReviews)
{
    vReviews.size(); // msvc workaround, just need to do anything with vReviews
    return Read(make_pair(string("reviews"), hash), vReviews);
}

bool CReviewDB::WriteReviews(uint256 hash, const vector<CReview>& vReviews)
{
    return Write(make_pair(string("reviews"), hash), vReviews);
}







//
// CWalletDB
//

bool CWalletDB::LoadWallet(vector<unsigned char>& vchDefaultKeyRet)
{
    vchDefaultKeyRet.clear();

    // Satoshi's "todo: shouldn't we catch exceptions" sat here since 2009, and
    // it was not a nicety. Nothing on this path caught anything, so a record
    // this build could not read -- a wallet from another platform's Berkeley
    // DB, a truncated file, a field it does not understand -- threw out of
    // LoadWallet, out of main(), into std::terminate and abort(). On Windows
    // that surfaces as STATUS_STACK_BUFFER_OVERRUN (0xC0000409) in
    // ucrtbase.dll: no message, no log line past "Loading wallet...", and a
    // faulting module that has nothing to do with the actual problem.
    //
    // The program knew exactly what had gone wrong and threw the reason away.
    // Now it says so and stops cleanly, which is the difference between "your
    // wallet is unreadable and here is why" and a crash nobody can act on.
    //
    // Deliberately a hard failure rather than skipping the bad record: a
    // partially loaded wallet is worse than one that refuses to open, because
    // the balance looks plausible while keys or transactions are missing.
    string strLastType;
    try
    {
    CRITICAL_BLOCK(cs_mapKeys)
    CRITICAL_BLOCK(cs_mapWallet)
    {
        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return false;

        loop
        {
            // Read next record
            CDataStream ssKey;
            CDataStream ssValue;
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
                return false;

            // Unserialize
            // Taking advantage of the fact that pair serialization
            // is just the two items serialized one after the other
            string strType;
            ssKey >> strType;
            strLastType = strType;
            if (strType == "name")
            {
                string strAddress;
                ssKey >> strAddress;
                ssValue >> mapAddressBook[strAddress];
            }
            else if (strType == "tx")
            {
                uint256 hash;
                ssKey >> hash;
                CWalletTx& wtx = mapWallet[hash];
                ssValue >> wtx;

                if (wtx.GetHash() != hash)
                    printf("Error in wallet.dat, hash mismatch\n");

                //// debug print
                //printf("LoadWallet  %s\n", wtx.GetHash().ToString().c_str());
                //printf(" %12lld  %s  %s  %s\n",
                //    wtx.vout[0].nValue,
                //    DateTimeStr(wtx.nTime).c_str(),
                //    wtx.hashBlock.ToString().substr(0,14).c_str(),
                //    wtx.mapValue["message"].c_str());
            }
            else if (strType == "key")
            {
                vector<unsigned char> vchPubKey;
                ssKey >> vchPubKey;
                CPrivKey vchPrivKey;
                ssValue >> vchPrivKey;

                mapKeys[vchPubKey] = vchPrivKey;
                mapPubKeys[Hash160(vchPubKey)] = vchPubKey;
            }
            else if (strType == "defaultkey")
            {
                ssValue >> vchDefaultKeyRet;
            }
            else if (strType == "setting")  /// or settings or option or options or config?
            {
                string strKey;
                ssKey >> strKey;
                if (strKey == "nTransactionFee")    ssValue >> nTransactionFee;
                if (strKey == "addrIncoming")       ssValue >> addrIncoming;
                // Mining-mode/pool settings (nMineMode, strParticipantPool, strPoolName,
                // strPoolDashboardUrl, dPoolFeePercent, fGenerateBitcoins) are intentionally
                // NOT restored here. They used to be, and LoadWallet() runs after CLI flags
                // are parsed in main_gui.cpp, so a saved value would silently overwrite
                // whatever was just requested on the command line or in a previous Options
                // session -- no error, no log line. That's what caused pool name/address to
                // show correctly in the UI but stay stale in the logs, and mode to change
                // behavior across restarts. Mode/pool config is decided fresh every launch
                // instead: CLI flags if given, otherwise the compiled-in default. Nothing to
                // go stale, nothing to fight over load order.
            }
        }
    }
    }
    catch (const std::exception& e)
    {
        printf("LoadWallet: wallet.dat could not be read. Failed while handling "
               "a '%s' record: %s\n", strLastType.c_str(), e.what());
        printf("LoadWallet: the file was left untouched. A wallet.dat written by "
               "a different platform's Berkeley DB is the usual cause.\n");
        return false;
    }
    catch (...)
    {
        printf("LoadWallet: wallet.dat could not be read. Unknown failure while "
               "handling a '%s' record.\n", strLastType.c_str());
        return false;
    }

    printf("nTransactionFee = %lld\n", nTransactionFee);
    printf("addrIncoming = %s\n", addrIncoming.ToString().c_str());
    printf("nMineMode = %d, strParticipantPool = %s, fGenerateBitcoins = %d (from CLI/default, not wallet.dat)\n",
           nMineMode, strParticipantPool.c_str(), fGenerateBitcoins);
    printf("strPoolName = %s, dPoolFeePercent = %.2f, strPoolDashboardUrl = %s (from CLI/default, not wallet.dat)\n",
           strPoolName.c_str(), dPoolFeePercent, strPoolDashboardUrl.c_str());

    return true;
}

bool LoadWallet()
{
    vector<unsigned char> vchDefaultKey;
    if (!CWalletDB("cr").LoadWallet(vchDefaultKey))
        return false;

    if (mapKeys.count(vchDefaultKey))
    {
        // Set keyUser
        keyUser.SetPubKey(vchDefaultKey);
        keyUser.SetPrivKey(mapKeys[vchDefaultKey]);
    }
    else
    {
        // Create new keyUser and set as default key
        keyUser.MakeNewKey();
        if (!AddKey(keyUser))
            return false;
        if (!SetAddressBookName(PubKeyToAddress(keyUser.GetPubKey()), "Your Address"))
            return false;
        CWalletDB().WriteDefaultKey(keyUser.GetPubKey());
    }

    return true;
}


// Write a copy of wallet.dat that can be opened anywhere.
//
// A plain file copy is not a backup here. Berkeley DB stamps every page with a
// log sequence number tied to the environment that wrote it, so the copy only
// works beside the database/ directory it grew up with -- which is why backing
// up "just wallet.dat", the one file anybody would think to save, produces
// something that will not open. See the recovery block in CDB::CDB and #40.
//
// So: flush outstanding writes, copy, then clear the copy's log sequence
// numbers. What lands on disk is a wallet.dat that stands on its own.
//
// This is still a point-in-time snapshot. Keys are generated as they are
// needed, not derived from a seed, so coins paid to an address created after
// this file was written are not spendable from it. Backing up once is not
// enough, and that is a property of the wallet format rather than of this
// function.
bool BackupWallet(const string& strDest)
{
    if (strDest.empty())
        return error("BackupWallet() : no destination given\n");

    string strSrc = GetAppDir() + "/wallet.dat";
    if (!FileExists(strSrc.c_str()))
        return error("BackupWallet() : %s does not exist\n", strSrc.c_str());

    CRITICAL_BLOCK(cs_db)
    {
        // Committing first, so the copy is not missing the newest records.
        // Both calls can throw, and a failed backup must not take the node
        // down with it.
        try { dbenv.txn_checkpoint(0, 0, 0); }
        catch (const std::exception& e)
        { return error("BackupWallet() : checkpoint failed: %s\n", e.what()); }

        try
        {
            FILE* pfIn = fopen(strSrc.c_str(), "rb");
            if (!pfIn)
                return error("BackupWallet() : cannot read %s\n", strSrc.c_str());
            FILE* pfOut = fopen(strDest.c_str(), "wb");
            if (!pfOut)
            {
                fclose(pfIn);
                return error("BackupWallet() : cannot write %s\n", strDest.c_str());
            }

            char buf[65536];
            size_t n;
            bool fOk = true;
            while ((n = fread(buf, 1, sizeof(buf), pfIn)) > 0)
                if (fwrite(buf, 1, n, pfOut) != n) { fOk = false; break; }
            if (ferror(pfIn))
                fOk = false;
            fclose(pfIn);
            // Flushed and closed before lsn_reset touches it.
            if (fclose(pfOut) != 0)
                fOk = false;

            if (!fOk)
            {
                remove(strDest.c_str());   // half a wallet is worse than none
                return error("BackupWallet() : copy to %s failed\n", strDest.c_str());
            }

            // Without this the copy is welded to this node's database/ dir.
            int ret = dbenv.lsn_reset(strDest.c_str(), 0);
            if (ret != 0)
                printf("BackupWallet() : warning -- lsn_reset returned %d; the copy "
                       "may only open beside this node's database/ directory\n", ret);
        }
        catch (const std::exception& e)
        { return error("BackupWallet() : %s\n", e.what()); }
    }

    printf("BackupWallet() : wrote %s\n", strDest.c_str());
    return true;
}
