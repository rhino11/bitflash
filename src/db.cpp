// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"






//
// CDB
//

// Closes a Berkeley DB cursor however the function exits.
//
// Three functions opened one and none of them ever closed it. Berkeley DB
// requires every cursor to be closed before the handle it came from, and
// ~CDB() calls Close(), which calls pdb->close() inside a catch-all that
// swallows whatever it returns. So the violation was real and silent.
//
// An open cursor also holds read locks. That is what made the first version of
// the startup chain repair (#61) hang: it opened a write transaction beside
// the cursor CTxDB::LoadBlockIndex was still holding, and waited on it forever
// with nothing in any log. The repair had to be moved to the caller.
//
// Each of these functions has several early returns, so a guard is safer than
// remembering to close on every one of them. Same fix Bitcoin made in
// c5c7911da, alongside its zombie-socket and double-close work.
class CAutoCursor
{
public:
    explicit CAutoCursor(Dbc* pcursorIn) : pcursor(pcursorIn) { }
    ~CAutoCursor()
    {
        if (pcursor)
        {
            try { pcursor->close(); }
            catch (...) { }   // closing on the way out must not throw
        }
    }
private:
    Dbc* pcursor;
    CAutoCursor(const CAutoCursor&);
    void operator=(const CAutoCursor&);
};

static CCriticalSection cs_db;
static bool fDbEnvInit = false;

// Why LoadWallet() refused, in words meant for the person who has to act on it.
// Empty unless the reason is one we can name.
string strWalletLoadError;
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

// Close the Berkeley DB environment and delete its write-ahead logs.
//
// Encrypting the wallet rewrites wallet.dat, and that file does come out clean.
// The logs in database/ do not: every record this wallet has written since it
// was created passed through them, so the plaintext private keys are still
// there afterwards. Measured -- wallet.dat held no trace of a known key while
// database/log.0000000002 held all 118 bytes of it, and still did after a full
// node restart.
//
// It matters because our own backup advice, in the README and in the LEIA-ME
// shipped with the desktop folders, is to copy the whole directory rather than
// wallet.dat alone. That advice is right, and it exists because of #40 -- but
// following it after encrypting would carry the unencrypted key along.
//
// log_archive(DB_ARCH_REMOVE) cannot fix this. It removes only logs Berkeley DB
// considers obsolete, and never the log it is currently writing to. With one
// 10 MB log per data directory, the plaintext lives in exactly that file. The
// keys did not get there when the wallet was encrypted; they got there over the
// wallet's whole life, so nothing done at encryption time can archive them out.
//
// So the logs go, after a full flush. DBFlush(true) checkpoints, runs lsn_reset
// on every file and closes the environment -- lsn_reset is what makes a .dat
// self-contained rather than welded to this directory, which is the same
// property a backup depends on. Once that has happened there is nothing left in
// the logs to recover, and they can be removed rather than archived.
//
// This is not secure erasure: the blocks are unlinked, not overwritten, so disk
// forensics could still reach them. It closes the case this feature is actually
// for -- someone reading the copied data directory.
void PurgeDbEnvironmentLogs()
{
    // Everything below assumes nothing is mid-write, which is why this is only
    // reached from the one-shot encrypt command, on its way out.
    DBFlush(true);

    string strDbDir = GetAppDir() + "/database";
    int nRemoved = 0;
    for (int i = 1; i < 1000; i++)
    {
        string strPath = strprintf("%s/log.%010d", strDbDir.c_str(), i);
        if (!FileExists(strPath.c_str()))
            continue;
        if (remove(strPath.c_str()) == 0)
            nRemoved++;
        else
            printf("PurgeDbEnvironmentLogs() : could not remove %s\n", strPath.c_str());
    }
    printf("PurgeDbEnvironmentLogs() : removed %d database log file(s)\n", nRemoved);
}

void DBFlush(bool fShutdown)
{
    // Flush log data to the actual data file
    //  on all files that are not in use
    printf("DBFlush(%s)\n", fShutdown ? "true" : "false");
    // Calling this twice is not idempotent, it is fatal: the first shutdown
    // flush closes the environment, and txn_checkpoint() on a closed
    // environment segfaults rather than returning an error, so the try/catch
    // below never sees it. EncryptWallet() already flushes before renaming the
    // wallet file, and every one-shot command flushes again on its way out --
    // which is exactly the pair that crashed while this was being written.
    if (!fDbEnvInit)
    {
        printf("DBFlush() : environment already closed, nothing to flush\n");
        return;
    }
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
            // listp must be NULL when DB_ARCH_REMOVE is set. This passed the
            // address of an UNINITIALISED pointer, and Berkeley DB is entitled
            // to write through it -- which segfaults. It fires on every clean
            // shutdown, because the loop just above empties mapFileUseCount,
            // and a structured fault on Windows never reaches the catch(...)
            // wrapped around it. Inherited from 0.1.0 and wrong since then.
            //
            // Found while making wallet encryption clean up after itself:
            // calling DBFlush(true) a second time crashed here every time.
            if (mapFileUseCount.empty())
                try { dbenv.log_archive(NULL, DB_ARCH_REMOVE); } catch (...) { }
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
    CAutoCursor cursorGuard(pcursor);

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
    CAutoCursor cursorGuard(pcursor);

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

    // Verify the tail of the best chain, and fall back to the last good block
    // if any of it fails.
    //
    // A node that accepted blocks its current rules would reject -- because it
    // was running an older build, or because the tip it landed on was never
    // valid -- has no way to notice on its own. It keeps the branch, keeps
    // building on it, and keeps mining coins that the rest of the network
    // throws away. The only cure used to be deleting blk*.dat by hand, which
    // requires knowing something is wrong in the first place. That is how a
    // node here once mined a 323-block fork for five days.
    //
    // Checking every block on every start would mean a RandomX hash per block,
    // so only the tail is checked by default. /checkblocks=0 does the lot.
    int nCheckBlocks = nCheckBlocksOnLoad;
    CBlockIndex* pindexFork = NULL;
    int nChecked = 0;
    for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
    {
        if (nCheckBlocks > 0 && nChecked >= nCheckBlocks)
            break;
        nChecked++;
        CBlock block;
        if (!block.ReadFromDisk(pindex->nFile, pindex->nBlockPos, true))
            return error("LoadBlockIndex() : ReadFromDisk failed at height %d", pindex->nHeight);
        if (!block.CheckBlock())
        {
            printf("LoadBlockIndex() : *** bad block at height %d, hash=%s\n",
                   pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,14).c_str());
            // Keep going: an older bad block further back wins, because
            // everything after it has to come off too.
            pindexFork = pindex->pprev;
        }
    }
    printf("LoadBlockIndex(): verified %d block(s)\n", nChecked);

    // The repair itself happens in the caller, after this handle is closed.
    // The cursor above is still open and holds read locks, so a write
    // transaction opened here waits on it forever -- measured: the node came
    // up, printed the diagnosis, and hung with no error anywhere.
    pindexBadChainFork = pindexFork;

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
    // Whether wallet.dat actually carried a mining mode, as opposed to just the
    // ancient fGenerateBitcoins flag. See the reconciliation further down.
    bool fHaveStoredMineMode = false;
    bool fHaveStoredHDCoinType = false;
    vchDefaultKeyRet.clear();
    strWalletLoadError.clear();

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
        CAutoCursor cursorGuard(pcursor);

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
            else if (strType == "mkey")
            {
                unsigned int nID = 0;
                ssKey >> nID;
                CWalletMasterKey kMasterKey;
                ssValue >> kMasterKey;
                mapMasterKeys[nID] = kMasterKey;
                nWalletMasterKeyMaxID = max(nWalletMasterKeyMaxID, nID);
                fWalletEncrypted = true;
                fWalletLocked = true;
            }
            else if (strType == "ckey")
            {
                vector<unsigned char> vchPubKey;
                ssKey >> vchPubKey;
                vector<unsigned char> vchCryptedSecret;
                ssValue >> vchCryptedSecret;
                if (!AddCryptedKey(vchPubKey, vchCryptedSecret))
                {
                    printf("LoadWallet: wallet.dat has an unreadable encrypted key record\n");
                    return false;
                }
            }
            else if (strType == "defaultkey")
            {
                ssValue >> vchDefaultKeyRet;
            }
            else if (strType == "hdmaster")
            {
                ssValue >> vchHDMaster;
            }
            else if (strType == "hdchaincode")
            {
                ssValue >> vchHDChainCode;
            }
            else if (strType == "hdnext")
            {
                ssValue >> nHDNext;
            }
            else if (strType == "hdschema")
            {
                ssValue >> nHDKeySchema;
            }
            else if (strType == "hdcointype")
            {
                ssValue >> nHDCoinType;
                fHaveStoredHDCoinType = true;
            }
            else if (strType == "hdreceivenext")
            {
                ssValue >> nHDReceiveNext;
            }
            else if (strType == "hdchangenext")
            {
                ssValue >> nHDChangeNext;
            }
            else if (strType == "cryptedhdmaster")
            {
                ssValue >> vchCryptedHDMaster;
                fWalletEncrypted = true;
                fWalletLocked = true;
            }
            else if (strType == "cryptedhdchaincode")
            {
                ssValue >> vchCryptedHDChainCode;
                fWalletEncrypted = true;
                fWalletLocked = true;
            }
            else if (strType == "walletminversion")
            {
                int nMinVersion = 0;
                ssValue >> nMinVersion;
                if (nMinVersion > WALLET_FORMAT_SUPPORTED)
                {
                    // Said out loud, not only into debug.log: this is the one
                    // refusal whose whole purpose is to be understood, and the
                    // caller puts it in front of the user.
                    strWalletLoadError = strprintf(
                        "This wallet.dat was written by a newer version of Bitflash "
                        "(wallet format %d; this build understands %d). Upgrade "
                        "Bitflash before opening it.",
                        nMinVersion, WALLET_FORMAT_SUPPORTED);
                    printf("LoadWallet: %s\n", strWalletLoadError.c_str());
                    return false;
                }
            }
            else if (strType == "pool")
            {
                int64 nIndex;
                ssKey >> nIndex;
                vector<unsigned char> vchPubKey;
                ssValue >> vchPubKey;
                mapKeyPool[nIndex] = vchPubKey;
            }
            else if (strType == "setting")  /// or settings or option or options or config?
            {
                string strKey;
                ssKey >> strKey;
                if (strKey == "nTransactionFee")    ssValue >> nTransactionFee;
                if (strKey == "addrIncoming")       ssValue >> addrIncoming;

                // Mining mode is restored, but only when no flag chose one.
                //
                // These settings used to be restored unconditionally. LoadWallet()
                // runs after main_gui.cpp has parsed the command line, so a stored
                // value silently overwrote what had just been asked for -- no error,
                // no log line -- and the fix at the time was to stop restoring them
                // at all. That traded a silent override for a different silent
                // failure: a machine set to mine came back from every restart as a
                // plain relay, looking exactly like one that had been asked to
                // relay. A 32-core miner sat idle for hours that way, and the only
                // evidence was memory usage that never climbed.
                //
                // Precedence is now explicit rather than accidental: a flag wins,
                // and it says so in the log below. Only the two fields that decide
                // whether this node mines are restored, plus the pool address a
                // participant cannot work without.
                if (!fMineModeFromCommandLine)
                {
                    if (strKey == "nMineMode")          { ssValue >> nMineMode; fHaveStoredMineMode = true; }
                    if (strKey == "fGenerateBitcoins")  ssValue >> fGenerateBitcoins;
                    if (strKey == "strParticipantPool") ssValue >> strParticipantPool;
                }
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

    // An encrypted wallet has a seed; it just has not been decrypted yet.
    //
    // The reset in the else branch was written when "no seed in memory after
    // loading" could only mean "this wallet has no seed". With encryption that
    // is no longer true, and taking the else branch here wiped the schema and
    // the derivation counters that had just been read correctly out of the
    // file. Unlocking later restores the seed but nothing restores those, so a
    // BIP44 wallet came back deriving legacy addresses -- different addresses
    // from the ones its own recovery phrase produces, while the audit reported
    // the phrase as covering nothing.
    if (HaveHDSeed() || !vchCryptedHDMaster.empty())
    {
        if (nHDKeySchema == HD_SCHEMA_NONE)
        {
            nHDKeySchema = HD_SCHEMA_LEGACY;
            printf("LoadWallet: deterministic seed has no schema metadata; "
                   "treating it as legacy m/index'\n");
        }
        else if (nHDKeySchema != HD_SCHEMA_LEGACY &&
                 nHDKeySchema != HD_SCHEMA_BIP44)
        {
            printf("LoadWallet: deterministic wallet schema %d (%s) is not "
                   "supported by this build\n",
                   nHDKeySchema, HDKeySchemaName(nHDKeySchema).c_str());
            return false;
        }
        if (!fHaveStoredHDCoinType)
        {
            nHDCoinType = HD_BIP44_COIN_TYPE_BITFLASH_PROVISIONAL;
            printf("LoadWallet: deterministic seed has no BIP44 coin type metadata; "
                   "using provisional Bitflash coin type %u\n", nHDCoinType);
        }
    }
    else
    {
        nHDKeySchema = HD_SCHEMA_NONE;
        nHDNext = 0;
        nHDReceiveNext = 0;
        nHDChangeNext = 0;
        nHDCoinType = HD_BIP44_COIN_TYPE_BITFLASH_PROVISIONAL;
    }

    // fGenerateBitcoins and nMineMode only mean anything together, and a
    // wallet.dat can easily hold one without the other: Bitcoin 0.1.0 already
    // wrote fGenerateBitcoins when mining was toggled, years before this fork
    // had a mode at all. Restoring that lone flag put a node into the one state
    // the miner cannot act on -- generate on, mode relay -- so every miner
    // thread started and returned at the relay guard, and the machine sat there
    // looking like it was mining while hashing nothing. That happened to a
    // 32-core node on the first 1.2.11 start.
    //
    // So the flag is only believed when the mode it belongs to was stored with
    // it, and the pair is made coherent either way.
    if (!fMineModeFromCommandLine)
    {
        if (!fHaveStoredMineMode)
        {
            if (fGenerateBitcoins)
                printf("LoadWallet: ignoring a stored fGenerateBitcoins with no mining mode "
                       "beside it -- it predates this setting and cannot be read on its own\n");
            fGenerateBitcoins = 0;
        }
        else
        {
            fGenerateBitcoins = (nMineMode != MINE_RELAY) ? 1 : 0;
        }
    }

    printf("nTransactionFee = %lld\n", nTransactionFee);
    printf("addrIncoming = %s\n", addrIncoming.ToString().c_str());
    printf("nMineMode = %d, strParticipantPool = %s, fGenerateBitcoins = %d (%s)\n",
           nMineMode, strParticipantPool.c_str(), fGenerateBitcoins,
           fMineModeFromCommandLine ? "from the command line, wallet.dat ignored"
                                    : "remembered from wallet.dat, or the default");
    printf("strPoolName = %s, dPoolFeePercent = %.2f, strPoolDashboardUrl = %s (from CLI/default, not wallet.dat)\n",
           strPoolName.c_str(), dPoolFeePercent, strPoolDashboardUrl.c_str());

    return true;
}

bool LoadWallet()
{
    vector<unsigned char> vchDefaultKey;
    if (!CWalletDB("cr").LoadWallet(vchDefaultKey))
        return false;

    if (!vchDefaultKey.empty() && mapPubKeys.count(Hash160(vchDefaultKey)))
    {
        // Set keyUser
        keyUser.SetPubKey(vchDefaultKey);
        if (mapKeys.count(vchDefaultKey))
            keyUser.SetPrivKey(mapKeys[vchDefaultKey]);
    }
    else if (IsWalletEncrypted())
    {
        printf("LoadWallet: encrypted wallet has no usable default public key. "
               "The file was left untouched.\n");
        return false;
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

    // Recorded here rather than by whoever called, so that a backup taken with
    // /backupwallet counts as much as one taken from the GUI. When the GUI
    // wrote this itself, anyone following the README -- which documents the
    // command line first -- was told forever that they had never backed up.
    // Outside the cs_db block above: this opens the wallet for writing, and
    // there is no reason to do that while holding the database lock.
    try { CWalletDB().WriteSetting("nLastWalletBackup", (int64)GetTime()); }
    catch (...) { }   // the backup is written; failing to note it is not fatal

    printf("BackupWallet() : wrote %s\n", strDest.c_str());
    return true;
}


// ---- plain-text key export/import ------------------------------------------
//
// The last door out. Everything else in this file assumes Berkeley DB will
// cooperate; these two do not. A wallet.dat can be unreadable for reasons that
// have nothing to do with your keys being gone -- a version this build does not
// understand, a file truncated by a bad copy, an environment that cannot be
// recovered -- and until now that meant the coins were unreachable even though
// the secrets were sitting right there. Issue #40 is one person's account of
// exactly that.
//
// The format is deliberately dull: a text file, one key per line, no database,
// no environment, no framing. Anything that can read a line can recover from it.

static int HexDigitValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool ParseHexInto(const string& str, vector<unsigned char>& vchRet)
{
    vchRet.clear();
    if (str.empty() || (str.size() % 2) != 0)
        return false;
    for (size_t i = 0; i < str.size(); i += 2)
    {
        int hi = HexDigitValue(str[i]);
        int lo = HexDigitValue(str[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        vchRet.push_back((unsigned char)((hi << 4) | lo));
    }
    return true;
}

bool DumpWallet(const string& strDest)
{
    if (strDest.empty())
        return error("DumpWallet() : no destination given\n");
    if (IsWalletLocked())
        return error("DumpWallet() : wallet is encrypted and locked; unlock it with /walletpassphrase first\n");

    // Never over an existing file. The whole point is to hold the only copy of
    // something irreplaceable, and a mistyped path must not eat one.
    if (FileExists(strDest.c_str()))
        return error("DumpWallet() : %s already exists -- refusing to overwrite\n",
                     strDest.c_str());

    FILE* pf = fopen(strDest.c_str(), "w");
    if (!pf)
        return error("DumpWallet() : cannot write %s\n", strDest.c_str());
#ifndef _WIN32
    // Before a single key reaches it.
    chmod(strDest.c_str(), S_IRUSR | S_IWUSR);
#endif

    fprintf(pf, "# Bitflash wallet key dump\n");
    fprintf(pf, "# %s\n", DateTimeStr(GetTime()).c_str());
    fprintf(pf, "#\n");
    fprintf(pf, "# THIS FILE CONTAINS PRIVATE KEYS IN PLAIN TEXT.\n");
    fprintf(pf, "# Anyone who reads it can spend these coins. Treat it as cash.\n");
    fprintf(pf, "#\n");
    fprintf(pf, "# One key per line:  <private-key-hex> <address> [label]\n");
    fprintf(pf, "# The key is the DER encoding, hex; restore with -importwallet=FILE.\n");
    fprintf(pf, "#\n");

    vector<vector<unsigned char> > vPubKeys;
    {
        CRITICAL_BLOCK(cs_mapKeys)
        {
            for (map<vector<unsigned char>, CPrivKey>::iterator mi = mapKeys.begin();
                 mi != mapKeys.end(); ++mi)
                vPubKeys.push_back((*mi).first);
            for (map<vector<unsigned char>, vector<unsigned char> >::iterator mi = mapCryptedKeys.begin();
                 mi != mapCryptedKeys.end(); ++mi)
                if (!mapKeys.count((*mi).first))
                    vPubKeys.push_back((*mi).first);
        }
    }

    int nKeys = 0;
    bool fOk = true;
    for (size_t i = 0; i < vPubKeys.size(); i++)
    {
        const vector<unsigned char>& vchPubKey = vPubKeys[i];
        CPrivKey vchPrivKey;
        string strError;
        if (!GetWalletPrivKey(vchPubKey, vchPrivKey, strError))
        {
            fOk = false;
            break;
        }

        string strAddress = PubKeyToAddress(vchPubKey);
        string strLabel;
        map<string, string>::iterator mia = mapAddressBook.find(strAddress);
        if (mia != mapAddressBook.end())
            strLabel = (*mia).second;

        // Labels are user text and could contain a newline, which would forge
        // a second entry on read-back.
        for (size_t j = 0; j < strLabel.size(); j++)
            if (strLabel[j] == '\n' || strLabel[j] == '\r')
                strLabel[j] = ' ';

        if (fprintf(pf, "%s %s %s\n",
                    HexStr(vchPrivKey.begin(), vchPrivKey.end(), false).c_str(),
                    strAddress.c_str(),
                    strLabel.c_str()) < 0)
        { fOk = false; break; }
        nKeys++;
    }

    if (fclose(pf) != 0)
        fOk = false;
    if (!fOk)
    {
        remove(strDest.c_str());
        return error("DumpWallet() : writing %s failed\n", strDest.c_str());
    }

    printf("DumpWallet() : wrote %d key(s) to %s\n", nKeys, strDest.c_str());
    return true;
}

bool ImportWallet(const string& strSrc, int& nAddedRet, int& nSkippedRet)
{
    nAddedRet = 0;
    nSkippedRet = 0;

    FILE* pf = fopen(strSrc.c_str(), "r");
    if (!pf)
        return error("ImportWallet() : cannot read %s\n", strSrc.c_str());

    char buf[8192];
    int nLine = 0;
    int nBad = 0;
    while (fgets(buf, sizeof(buf), pf))
    {
        nLine++;
        string strLine = buf;
        while (!strLine.empty() && (strLine[strLine.size()-1] == '\n' ||
                                    strLine[strLine.size()-1] == '\r'))
            strLine.resize(strLine.size() - 1);
        if (strLine.empty() || strLine[0] == '#')
            continue;

        string strHex = strLine.substr(0, strLine.find(' '));
        vector<unsigned char> vchPrivKey;
        if (!ParseHexInto(strHex, vchPrivKey))
        {
            printf("ImportWallet() : line %d is not a hex key, skipped\n", nLine);
            nBad++;
            continue;
        }

        CKey key;
        // A key this build cannot load is reported and stepped over rather than
        // aborting the run: one damaged line in a salvage file must not cost
        // the reader every other key in it.
        try
        {
            CPrivKey vchSecure(vchPrivKey.begin(), vchPrivKey.end());
            if (!key.SetPrivKey(vchSecure))
            {
                printf("ImportWallet() : line %d is not a usable key, skipped\n", nLine);
                nBad++;
                continue;
            }
        }
        catch (const std::exception& e)
        {
            printf("ImportWallet() : line %d rejected (%s), skipped\n", nLine, e.what());
            nBad++;
            continue;
        }

        if (WalletCanSpendKey(key.GetPubKey()))
        {
            nSkippedRet++;   // already ours; importing twice is not an error
            continue;
        }

        if (!AddKey(key))
        {
            fclose(pf);
            return error("ImportWallet() : failed to store key from line %d\n", nLine);
        }
        nAddedRet++;
    }
    fclose(pf);

    printf("ImportWallet() : %d added, %d already present, %d unreadable\n",
           nAddedRet, nSkippedRet, nBad);

    // Imported keys are only useful once their transactions are noticed, and
    // that scan is a full pass over the chain the node does at startup.
    if (nAddedRet > 0)
        printf("ImportWallet() : restart the node so it can find transactions "
               "belonging to the new keys\n");
    return true;
}


// ---- wallet encryption rewrite -------------------------------------------

class CWalletRewriteDB : public CDB
{
public:
    CWalletRewriteDB(const char* pszFile, const char* pszMode="r+", bool fTxn=false)
        : CDB(pszFile, pszMode, fTxn) { }

    bool WriteRaw(CDataStream ssKey, CDataStream ssValue)
    {
        if (!pdb || ssKey.empty())
            return false;

        Dbt datKey(&ssKey[0], ssKey.size());
        Dbt datValue(ssValue.empty() ? NULL : &ssValue[0], ssValue.size());
        int ret = pdb->put(GetTxn(), &datKey, &datValue, 0);

        memset(datKey.get_data(), 0, datKey.get_size());
        if (datValue.get_data())
            memset(datValue.get_data(), 0, datValue.get_size());
        return ret == 0;
    }

    bool WriteWalletMinVersion(int nVersion)
    {
        return Write(string("walletminversion"), nVersion);
    }

    bool WriteMasterKey(unsigned int nID, const CWalletMasterKey& kMasterKey)
    {
        return Write(make_pair(string("mkey"), nID), kMasterKey, true);
    }

    bool WriteCryptedKey(const vector<unsigned char>& vchPubKey,
                         const vector<unsigned char>& vchCryptedSecret)
    {
        return Write(make_pair(string("ckey"), vchPubKey), vchCryptedSecret, false);
    }

    bool WriteCryptedHDMaster(const vector<unsigned char>& vchCryptedMaster,
                              const vector<unsigned char>& vchCryptedChainCode)
    {
        return Write(string("cryptedhdmaster"), vchCryptedMaster)
            && Write(string("cryptedhdchaincode"), vchCryptedChainCode);
    }

    bool WriteHDNext(unsigned int nNext)
    {
        return Write(string("hdnext"), nNext);
    }

    bool WritePool(int64 nIndex, const vector<unsigned char>& vchPubKey)
    {
        return Write(make_pair(string("pool"), nIndex), vchPubKey);
    }

    bool CopyPublicRecordsTo(CWalletRewriteDB& dbTo, int& nCopiedRet, string& strErrorRet)
    {
        nCopiedRet = 0;
        Dbc* pcursor = GetCursor();
        if (!pcursor)
        {
            strErrorRet = "could not open a wallet cursor";
            return false;
        }

        unsigned int fFlags = DB_NEXT;
        loop
        {
            CDataStream ssKey;
            CDataStream ssValue;
            int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
            if (ret == DB_NOTFOUND)
                break;
            if (ret != 0)
            {
                pcursor->close();
                strErrorRet = strprintf("could not read wallet record: Berkeley DB error %d", ret);
                return false;
            }

            string strType;
            try
            {
                CDataStream ssType = ssKey;
                ssType >> strType;
            }
            catch (...)
            {
                pcursor->close();
                strErrorRet = "wallet.dat has a record whose key type cannot be read";
                return false;
            }

            if (strType == "key" ||
                strType == "pool" ||
                strType == "hdmaster" ||
                strType == "hdchaincode" ||
                strType == "mkey" ||
                strType == "ckey" ||
                strType == "cryptedhdmaster" ||
                strType == "cryptedhdchaincode" ||
                strType == "walletminversion")
                continue;

            if (!dbTo.WriteRaw(ssKey, ssValue))
            {
                pcursor->close();
                strErrorRet = strprintf("could not copy wallet record '%s'", strType.c_str());
                return false;
            }
            nCopiedRet++;
        }

        pcursor->close();
        return true;
    }
};

static string WalletEncryptBackupPath()
{
    string strBase = GetAppDir() + "/wallet.dat.before-encrypt.";
    string strPath = strBase + i64tostr(GetTime()) + ".bak";
    for (int i = 1; FileExists(strPath.c_str()); i++)
        strPath = strBase + i64tostr(GetTime()) + "." + itostr(i) + ".bak";
    return strPath;
}

static bool EncryptPrivateKeyForWallet(const CKeyingMaterial& vchMasterKey,
                                       const vector<unsigned char>& vchPubKey,
                                       const CPrivKey& vchPrivKey,
                                       vector<unsigned char>& vchCryptedRet,
                                       string& strErrorRet)
{
    if (!EncryptSecret(vchMasterKey,
                       vector<unsigned char>(vchPrivKey.begin(), vchPrivKey.end()),
                       WalletKeyIV(vchPubKey), vchCryptedRet))
    {
        strErrorRet = "could not encrypt a private key";
        return false;
    }
    return true;
}

bool EncryptWallet(const string& strPassphrase, string& strBackupRet, string& strErrorRet)
{
    strBackupRet.clear();
    strErrorRet.clear();

    if (IsWalletEncrypted())
    {
        strErrorRet = "wallet is already encrypted";
        return false;
    }
    if (strPassphrase.size() < 8)
    {
        strErrorRet = "passphrase must be at least 8 characters";
        return false;
    }

    map<vector<unsigned char>, CPrivKey> mapPlainKeys;
    vector<unsigned char> vchPlainHDMaster;
    vector<unsigned char> vchPlainHDChainCode;
    unsigned int nHDNextSnapshot = 0;
    {
        CRITICAL_BLOCK(cs_mapKeys)
            mapPlainKeys = mapKeys;
    }
    {
        CRITICAL_BLOCK(cs_keyPool)
        {
            vchPlainHDMaster = vchHDMaster;
            vchPlainHDChainCode = vchHDChainCode;
            nHDNextSnapshot = nHDNext;
        }
    }
    if (mapPlainKeys.empty())
    {
        strErrorRet = "wallet has no private keys to encrypt";
        return false;
    }

    CKeyingMaterial vchMasterKey;
    vchMasterKey.resize(32);
    if (RAND_bytes(&vchMasterKey[0], vchMasterKey.size()) != 1)
    {
        strErrorRet = "could not create a random wallet master key";
        return false;
    }

    CWalletMasterKey kMasterKey;
    if (RAND_bytes(&kMasterKey.vchSalt[0], kMasterKey.vchSalt.size()) != 1)
    {
        strErrorRet = "could not create a wallet encryption salt";
        return false;
    }

    CKeyingMaterial vchPassKey;
    vector<unsigned char> vchPassIV;
    if (!DeriveWalletPassphraseKey(strPassphrase, kMasterKey.vchSalt,
                                   kMasterKey.nDeriveIterations,
                                   vchPassKey, vchPassIV) ||
        !EncryptSecret(vchPassKey,
                       vector<unsigned char>(vchMasterKey.begin(), vchMasterKey.end()),
                       vchPassIV, kMasterKey.vchCryptedKey))
    {
        strErrorRet = "could not encrypt the wallet master key";
        return false;
    }

    vector<pair<vector<unsigned char>, vector<unsigned char> > > vCryptedKeys;
    for (map<vector<unsigned char>, CPrivKey>::const_iterator mi = mapPlainKeys.begin();
         mi != mapPlainKeys.end(); ++mi)
    {
        vector<unsigned char> vchCrypted;
        if (!EncryptPrivateKeyForWallet(vchMasterKey, (*mi).first, (*mi).second,
                                        vchCrypted, strErrorRet))
            return false;
        vCryptedKeys.push_back(make_pair((*mi).first, vchCrypted));
    }

    vector<unsigned char> vchCryptedHDMasterNew;
    vector<unsigned char> vchCryptedHDChainCodeNew;
    if (!vchPlainHDMaster.empty() || !vchPlainHDChainCode.empty())
    {
        if (vchPlainHDMaster.size() != 32 || vchPlainHDChainCode.size() != 32)
        {
            strErrorRet = "wallet has an incomplete HD seed";
            return false;
        }
        if (!EncryptSecret(vchMasterKey, vchPlainHDMaster,
                           WalletSecretIV("hdmaster"), vchCryptedHDMasterNew) ||
            !EncryptSecret(vchMasterKey, vchPlainHDChainCode,
                           WalletSecretIV("hdchaincode"), vchCryptedHDChainCodeNew))
        {
            strErrorRet = "could not encrypt the HD seed";
            return false;
        }
    }

    vector<pair<int64, vector<unsigned char> > > vNewPool;
    vector<pair<vector<unsigned char>, vector<unsigned char> > > vNewPoolKeys;
    unsigned int nHDNextNew = nHDNextSnapshot;
    for (int i = 0; i < KEYPOOL_SIZE; i++)
    {
        CKey key;
        if (!vchPlainHDMaster.empty())
        {
            string strDeriveError;
            if (!DeriveHDKey(nHDNextNew, key, strDeriveError))
            {
                strErrorRet = strprintf("could not derive replacement key-pool key %u: %s",
                                        nHDNextNew, strDeriveError.c_str());
                return false;
            }
            nHDNextNew++;
        }
        else
        {
            key.MakeNewKey();
        }

        vector<unsigned char> vchPubKey = key.GetPubKey();
        if (!mapPlainKeys.count(vchPubKey))
        {
            vector<unsigned char> vchCrypted;
            if (!EncryptPrivateKeyForWallet(vchMasterKey, vchPubKey, key.GetPrivKey(),
                                            vchCrypted, strErrorRet))
                return false;
            vNewPoolKeys.push_back(make_pair(vchPubKey, vchCrypted));
        }
        vNewPool.push_back(make_pair((int64)i + 1, vchPubKey));
    }

    string strTempFile = strprintf("wallet.encrypting.%lld.dat", GetTime());
    string strTempPath = GetAppDir() + "/" + strTempFile;
    remove(strTempPath.c_str());

    int nCopied = 0;
    {
        CWalletRewriteDB dbSource("wallet.dat", "r");
        CWalletRewriteDB dbTarget(strTempFile.c_str(), "c+");
        if (!dbSource.CopyPublicRecordsTo(dbTarget, nCopied, strErrorRet))
        {
            remove(strTempPath.c_str());
            return false;
        }
        if (!dbTarget.WriteWalletMinVersion(WALLET_FORMAT_ENCRYPTED) ||
            !dbTarget.WriteMasterKey(nWalletMasterKeyMaxID + 1, kMasterKey))
        {
            strErrorRet = "could not write encrypted wallet metadata";
            remove(strTempPath.c_str());
            return false;
        }
        for (size_t i = 0; i < vCryptedKeys.size(); i++)
        {
            if (!dbTarget.WriteCryptedKey(vCryptedKeys[i].first, vCryptedKeys[i].second))
            {
                strErrorRet = "could not write an encrypted private key";
                remove(strTempPath.c_str());
                return false;
            }
        }
        for (size_t i = 0; i < vNewPoolKeys.size(); i++)
        {
            if (!dbTarget.WriteCryptedKey(vNewPoolKeys[i].first, vNewPoolKeys[i].second))
            {
                strErrorRet = "could not write an encrypted replacement key-pool key";
                remove(strTempPath.c_str());
                return false;
            }
        }
        if (!vchCryptedHDMasterNew.empty() &&
            !dbTarget.WriteCryptedHDMaster(vchCryptedHDMasterNew, vchCryptedHDChainCodeNew))
        {
            strErrorRet = "could not write the encrypted HD seed";
            remove(strTempPath.c_str());
            return false;
        }
        if (!dbTarget.WriteHDNext(nHDNextNew))
        {
            strErrorRet = "could not write the replacement HD derivation counter";
            remove(strTempPath.c_str());
            return false;
        }
        for (size_t i = 0; i < vNewPool.size(); i++)
        {
            if (!dbTarget.WritePool(vNewPool[i].first, vNewPool[i].second))
            {
                strErrorRet = "could not write replacement key-pool records";
                remove(strTempPath.c_str());
                return false;
            }
        }
    }

    // The source and target handles are closed. Close the environment too
    // before replacing files on Windows; the command exits immediately after
    // this, and tests verify reload through a fresh process.
    DBFlush(true);

    string strWalletPath = GetAppDir() + "/wallet.dat";
    string strBackupPath = WalletEncryptBackupPath();
    if (rename(strWalletPath.c_str(), strBackupPath.c_str()) != 0)
    {
        strErrorRet = strprintf("could not move the original wallet to %s", strBackupPath.c_str());
        remove(strTempPath.c_str());
        return false;
    }
    if (rename(strTempPath.c_str(), strWalletPath.c_str()) != 0)
    {
        rename(strBackupPath.c_str(), strWalletPath.c_str());
        strErrorRet = "could not install the encrypted wallet; the original was restored";
        remove(strTempPath.c_str());
        return false;
    }

    strBackupRet = strBackupPath;
    printf("EncryptWallet() : copied %d public record(s), encrypted %u key(s), "
           "rebuilt %d key-pool entry(s)\n",
           nCopied, (unsigned int)(vCryptedKeys.size() + vNewPoolKeys.size()),
           (int)vNewPool.size());

    // The rewritten wallet.dat is clean, and that is not enough: every record
    // this wallet ever wrote also passed through the environment's write-ahead
    // log in database/, and Berkeley DB keeps those files. Measured on a real
    // wallet -- wallet.dat held no trace of a known private key afterwards,
    // while database/log.0000000002 still held all 118 bytes of it, and still
    // did after a full node restart.
    //
    // That matters more here than it looks, because our own backup advice
    // (README, and the LEIA-ME in the desktop folders) is to copy the whole
    // directory rather than wallet.dat alone -- which is the right advice, and
    // the reason for issue #40. Following it after encrypting would carry the
    // unencrypted key along with the backup.
    //
    // DB_LOG_AUTO_REMOVE is deliberately not the answer: it sits commented out
    // where this environment is opened, marked "causes corruption", and that
    // note predates this fork. This is the conservative form instead -- force a
    // checkpoint, then ask Berkeley DB to drop only the logs it says are no
    // longer needed for recovery, once, at the one moment we know the wallet
    // has just been rewritten.
    return true;
}
