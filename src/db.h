// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include <db_cxx.h>
class CTransaction;
class CTxIndex;
class CDiskBlockIndex;
class CDiskTxPos;
class COutPoint;
class CUser;
class CReview;
class CAddress;
class CWalletTx;

extern map<string, string> mapAddressBook;
extern bool fClient;

// Wallet file format guard. The current wallet stores private keys in plain
// records. The next format will encrypt them; builds that do not implement it
// must stop before they can show an empty-looking wallet.
static const int WALLET_FORMAT_PLAINTEXT = 1;
static const int WALLET_FORMAT_ENCRYPTED = 2;
static const int WALLET_FORMAT_SUPPORTED = WALLET_FORMAT_ENCRYPTED;

class CWalletMasterKey
{
public:
    vector<unsigned char> vchCryptedKey;
    vector<unsigned char> vchSalt;
    unsigned int nDerivationMethod;
    unsigned int nDeriveIterations;

    CWalletMasterKey()
    {
        nDerivationMethod = 0;
        nDeriveIterations = 25000;
        vchSalt.resize(8);
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchCryptedKey);
        READWRITE(vchSalt);
        READWRITE(nDerivationMethod);
        READWRITE(nDeriveIterations);
    )
};


extern DbEnv dbenv;
extern void DBFlush(bool fShutdown);
// Close the environment and delete its logs. Only the encryption command calls
// this: the logs hold the plaintext records the old wallet wrote.
extern void PurgeDbEnvironmentLogs();

// Set by LoadWallet() when it refuses for a reason worth telling the user.
extern string strWalletLoadError;




class CDB
{
protected:
    Db* pdb;
    string strFile;
    vector<DbTxn*> vTxn;

    explicit CDB(const char* pszFile, const char* pszMode="r+", bool fTxn=false);
    ~CDB() { Close(); }
public:
    void Close();
private:
    CDB(const CDB&);
    void operator=(const CDB&);

protected:
    template<typename K, typename T>
    bool Read(const K& key, T& value)
    {
        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Read
        Dbt datValue;
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = pdb->get(GetTxn(), &datKey, &datValue, 0);
        memset(datKey.get_data(), 0, datKey.get_size());
        if (datValue.get_data() == NULL)
            return false;

        // Unserialize value
        CDataStream ssValue((char*)datValue.get_data(), (char*)datValue.get_data() + datValue.get_size(), SER_DISK);
        ssValue >> value;

        // Clear and free memory
        memset(datValue.get_data(), 0, datValue.get_size());
        free(datValue.get_data());
        return (ret == 0);
    }

    template<typename K, typename T>
    bool Write(const K& key, const T& value, bool fOverwrite=true)
    {
        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Value
        CDataStream ssValue(SER_DISK);
        ssValue.reserve(10000);
        ssValue << value;
        Dbt datValue(&ssValue[0], ssValue.size());

        // Write
        int ret = pdb->put(GetTxn(), &datKey, &datValue, (fOverwrite ? 0 : DB_NOOVERWRITE));

        // Clear memory in case it was a private key
        memset(datKey.get_data(), 0, datKey.get_size());
        memset(datValue.get_data(), 0, datValue.get_size());
        return (ret == 0);
    }

    template<typename K>
    bool Erase(const K& key)
    {
        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Erase
        int ret = pdb->del(GetTxn(), &datKey, 0);

        // Clear memory
        memset(datKey.get_data(), 0, datKey.get_size());
        return (ret == 0 || ret == DB_NOTFOUND);
    }

    template<typename K>
    bool Exists(const K& key)
    {
        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Exists
        int ret = pdb->exists(GetTxn(), &datKey, 0);

        // Clear memory
        memset(datKey.get_data(), 0, datKey.get_size());
        return (ret == 0);
    }

    Dbc* GetCursor()
    {
        if (!pdb)
            return NULL;
        Dbc* pcursor = NULL;
        int ret = pdb->cursor(NULL, &pcursor, 0);
        if (ret != 0)
            return NULL;
        return pcursor;
    }

    int ReadAtCursor(Dbc* pcursor, CDataStream& ssKey, CDataStream& ssValue, unsigned int fFlags=DB_NEXT)
    {
        // Read at cursor
        Dbt datKey;
        if (fFlags == DB_SET || fFlags == DB_SET_RANGE || fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE)
        {
            datKey.set_data(&ssKey[0]);
            datKey.set_size(ssKey.size());
        }
        Dbt datValue;
        if (fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE)
        {
            datValue.set_data(&ssValue[0]);
            datValue.set_size(ssValue.size());
        }
        datKey.set_flags(DB_DBT_MALLOC);
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = pcursor->get(&datKey, &datValue, fFlags);
        if (ret != 0)
            return ret;
        else if (datKey.get_data() == NULL || datValue.get_data() == NULL)
            return 99999;

        // Convert to streams
        ssKey.SetType(SER_DISK);
        ssKey.clear();
        ssKey.write((char*)datKey.get_data(), datKey.get_size());
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((char*)datValue.get_data(), datValue.get_size());

        // Clear and free memory
        memset(datKey.get_data(), 0, datKey.get_size());
        memset(datValue.get_data(), 0, datValue.get_size());
        free(datKey.get_data());
        free(datValue.get_data());
        return 0;
    }

    DbTxn* GetTxn()
    {
        if (!vTxn.empty())
            return vTxn.back();
        else
            return NULL;
    }

public:
    bool TxnBegin()
    {
        if (!pdb)
            return false;
        DbTxn* ptxn = NULL;
        int ret = dbenv.txn_begin(GetTxn(), &ptxn, 0);
        if (!ptxn || ret != 0)
            return false;
        vTxn.push_back(ptxn);
        return true;
    }

    bool TxnCommit()
    {
        if (!pdb)
            return false;
        if (vTxn.empty())
            return false;
        int ret = vTxn.back()->commit(0);
        vTxn.pop_back();
        return (ret == 0);
    }

    bool TxnAbort()
    {
        if (!pdb)
            return false;
        if (vTxn.empty())
            return false;
        int ret = vTxn.back()->abort();
        vTxn.pop_back();
        return (ret == 0);
    }

    bool ReadVersion(int& nVersion)
    {
        nVersion = 0;
        return Read(string("version"), nVersion);
    }

    bool WriteVersion(int nVersion)
    {
        return Write(string("version"), nVersion);
    }
};








class CTxDB : public CDB
{
public:
    CTxDB(const char* pszMode="r+", bool fTxn=false) : CDB(!fClient ? "blkindex.dat" : NULL, pszMode, fTxn) { }
private:
    CTxDB(const CTxDB&);
    void operator=(const CTxDB&);
public:
    bool ReadTxIndex(uint256 hash, CTxIndex& txindex);
    bool UpdateTxIndex(uint256 hash, const CTxIndex& txindex);
    bool AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight);
    bool EraseTxIndex(const CTransaction& tx);
    bool ContainsTx(uint256 hash);
    bool ReadOwnerTxes(uint160 hash160, int nHeight, vector<CTransaction>& vtx);
    bool ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(uint256 hash, CTransaction& tx);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx);
    bool WriteBlockIndex(const CDiskBlockIndex& blockindex);
    bool EraseBlockIndex(uint256 hash);
    bool ReadHashBestChain(uint256& hashBestChain);
    bool WriteHashBestChain(uint256 hashBestChain);
    bool LoadBlockIndex();
};





class CReviewDB : public CDB
{
public:
    CReviewDB(const char* pszMode="r+", bool fTxn=false) : CDB("reviews.dat", pszMode, fTxn) { }
private:
    CReviewDB(const CReviewDB&);
    void operator=(const CReviewDB&);
public:
    bool ReadUser(uint256 hash, CUser& user)
    {
        return Read(make_pair(string("user"), hash), user);
    }

    bool WriteUser(uint256 hash, const CUser& user)
    {
        return Write(make_pair(string("user"), hash), user);
    }

    bool ReadReviews(uint256 hash, vector<CReview>& vReviews);
    bool WriteReviews(uint256 hash, const vector<CReview>& vReviews);
};





class CMarketDB : public CDB
{
public:
    CMarketDB(const char* pszMode="r+", bool fTxn=false) : CDB("market.dat", pszMode, fTxn) { }
private:
    CMarketDB(const CMarketDB&);
    void operator=(const CMarketDB&);
};





// Legacy IP-based peer address database (CAddrDB / addr.dat) removed --
// peer discovery is entirely Nostr/.btf-based now.





class CWalletDB : public CDB
{
public:
    CWalletDB(const char* pszMode="r+", bool fTxn=false) : CDB("wallet.dat", pszMode, fTxn) { }
private:
    CWalletDB(const CWalletDB&);
    void operator=(const CWalletDB&);
public:
    bool ReadName(const string& strAddress, string& strName)
    {
        strName = "";
        return Read(make_pair(string("name"), strAddress), strName);
    }

    bool WriteName(const string& strAddress, const string& strName)
    {
        mapAddressBook[strAddress] = strName;
        return Write(make_pair(string("name"), strAddress), strName);
    }

    bool EraseName(const string& strAddress)
    {
        mapAddressBook.erase(strAddress);
        return Erase(make_pair(string("name"), strAddress));
    }

    bool ReadTx(uint256 hash, CWalletTx& wtx)
    {
        return Read(make_pair(string("tx"), hash), wtx);
    }

    bool WriteTx(uint256 hash, const CWalletTx& wtx)
    {
        return Write(make_pair(string("tx"), hash), wtx);
    }

    bool EraseTx(uint256 hash)
    {
        return Erase(make_pair(string("tx"), hash));
    }

    bool ReadKey(const vector<unsigned char>& vchPubKey, CPrivKey& vchPrivKey)
    {
        vchPrivKey.clear();
        return Read(make_pair(string("key"), vchPubKey), vchPrivKey);
    }

    bool WriteKey(const vector<unsigned char>& vchPubKey, const CPrivKey& vchPrivKey)
    {
        return Write(make_pair(string("key"), vchPubKey), vchPrivKey, false);
    }

    bool ReadDefaultKey(vector<unsigned char>& vchPubKey)
    {
        vchPubKey.clear();
        return Read(string("defaultkey"), vchPubKey);
    }

    bool WriteDefaultKey(const vector<unsigned char>& vchPubKey)
    {
        return Write(string("defaultkey"), vchPubKey);
    }

    // --- Deterministic (BIP32) seed ---------------------------------------
    //
    // Stored as the master key and chain code rather than the mnemonic: the
    // twelve words are the user's to write down, and keeping a copy of them in
    // the file they are meant to protect defeats the point of having them.
    //
    // "hdschema" identifies the derivation layout. Wallets created before the
    // field existed are inferred as HD_SCHEMA_LEGACY when a seed is present.
    // "hdnext" is that legacy layout's next child index. The receive/change
    // counters and coin type are reserved for the BIP44 layout that uses
    // separate chains.
    bool ReadHDMaster(vector<unsigned char>& vchMasterRet, vector<unsigned char>& vchChainCodeRet)
    {
        vchMasterRet.clear();
        vchChainCodeRet.clear();
        return Read(string("hdmaster"), vchMasterRet)
            && Read(string("hdchaincode"), vchChainCodeRet);
    }

    bool WriteHDMaster(const vector<unsigned char>& vchMaster, const vector<unsigned char>& vchChainCode)
    {
        return Write(string("hdmaster"), vchMaster)
            && Write(string("hdchaincode"), vchChainCode);
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

    bool WriteHDSchema(int nSchema)
    {
        return Write(string("hdschema"), nSchema);
    }

    bool WriteHDCoinType(unsigned int nCoinType)
    {
        return Write(string("hdcointype"), nCoinType);
    }

    bool WriteHDReceiveNext(unsigned int nNext)
    {
        return Write(string("hdreceivenext"), nNext);
    }

    bool WriteHDChangeNext(unsigned int nNext)
    {
        return Write(string("hdchangenext"), nNext);
    }

    // Keys generated ahead of time and not yet handed out. The private key of
    // each is already stored under its own "key" record by AddKey; a "pool"
    // record only says that this one is still unspoken for.
    bool WritePool(int64 nIndex, const vector<unsigned char>& vchPubKey)
    {
        return Write(make_pair(string("pool"), nIndex), vchPubKey);
    }

    bool ErasePool(int64 nIndex)
    {
        return Erase(make_pair(string("pool"), nIndex));
    }

    template<typename T>
    bool ReadSetting(const string& strKey, T& value)
    {
        return Read(make_pair(string("setting"), strKey), value);
    }

    template<typename T>
    bool WriteSetting(const string& strKey, const T& value)
    {
        return Write(make_pair(string("setting"), strKey), value);
    }

    bool LoadWallet(vector<unsigned char>& vchDefaultKeyRet);
};

bool LoadWallet();

// Writes a wallet.dat that opens on its own, anywhere -- see the definition in
// db.cpp for why a plain file copy does not. Still a point-in-time snapshot:
// keys are made as needed rather than derived from a seed, so coins paid to an
// address created after this call are not spendable from the file it writes.
bool BackupWallet(const string& strDest);

// Plain-text key export/import: no Berkeley DB, no environment, no version
// coupling. What you fall back on when wallet.dat itself will not cooperate.
// DumpWallet refuses to overwrite an existing file and writes owner-only on
// POSIX -- the output holds private keys in the clear.
bool DumpWallet(const string& strDest);
bool ImportWallet(const string& strSrc, int& nAddedRet, int& nSkippedRet);
bool EncryptWallet(const string& strPassphrase, string& strBackupRet, string& strErrorRet);

inline bool SetAddressBookName(const string& strAddress, const string& strName)
{
    return CWalletDB().WriteName(strAddress, strName);
}
