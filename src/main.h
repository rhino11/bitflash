// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

class COutPoint;
class CInPoint;
class CDiskTxPos;
class CCoinBase;
class CTxIn;
class CTxOut;
class CTransaction;
class CBlock;
class CBlockIndex;
class CWalletTx;
class CKeyItem;

// Ceiling on transactions held waiting for a parent that has not arrived.
// They cost a peer nothing to send and are never validated, only stored.
static const unsigned int MAX_ORPHAN_TRANSACTIONS = 100;
// Blocks held waiting for a parent that has not arrived. Orphan transactions
// have had a ceiling since 0.1.0 and orphan blocks never did: one whose parent
// never turns up stays in memory for the life of the process, and a peer can
// send an unlimited number of them by inventing the previous-block hash. They
// are not free either -- each holds a whole block. A production node was
// seeing 1287 of them against 4117 blocks processed.
static const unsigned int MAX_ORPHAN_BLOCKS = 200;
// Signature operations allowed in one block. Size alone does not bound what a
// block costs to validate: every OP_CHECKSIG is an elliptic-curve verification,
// so a block within the size limit could still hold millions of them and take
// the network minutes of CPU to reject. Same value Bitcoin settled on.
static const unsigned int MAX_BLOCK_SIGOPS = 20000;
// Consensus block-size ceiling. MAX_SIZE is the serializer's generic safety
// limit (32 MB), not a block rule. Bitcoin 0.1.0 predated the later 1 MB block
// cap, so this tree inherited no real block-size consensus limit.
static const unsigned int MAX_BLOCK_SIZE = 1000000;
static const int64 COIN = 100000000;
// Total Bitflash emission: identical to Bitcoin (21 million).
// MAX_MONEY guards against the value overflow bug (CVE-2010-5139), which in
// 2010 allowed creating 184 billion coins in a single transaction.
static const int64 MAX_MONEY = 21000000 * COIN;
inline bool MoneyRange(int64 nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
static const int64 CENT = 1000000;
static const int COINBASE_MATURITY = 100;

// Bitflash difficulty floor. The PoW is RandomX (memory-hard), ~1000x slower
// per hash than SHA-256d, so the target is much easier than Bitcoin's to let a
// CPU network start with little hashrate. Difficulty rises on its own (retarget
// toward 10-min blocks) as miners join. This does NOT affect emission
// (21 million, halving every 210,000 blocks). Tunable.
static const CBigNum bnProofOfWorkLimit(~uint256(0) >> 12);






extern CCriticalSection cs_main;
extern map<uint256, CBlockIndex*> mapBlockIndex;
extern uint256 hashGenesisBlock;
extern uint256 hashGenesisMerkleRoot;
extern unsigned int GENESIS_NONCE;
extern CBlockIndex* pindexGenesisBlock;
extern int nBestHeight;
extern uint256 hashBestChain;
extern int nCheckBlocksOnLoad;
extern CBlockIndex* pindexBadChainFork;
extern CBlockIndex* pindexBest;
extern unsigned int nTransactionsUpdated;
extern string strSetDataDir;
extern int nDropMessagesTest;
// Mining mode -- remembered in wallet.dat, but the command line always wins.
// See LoadWallet() in db.cpp for why the precedence has to be explicit.
//   MINE_RELAY (0):       default. Node runs/syncs, never mines, no pool server.
//   MINE_SOLO (1):        mine to own wallet, no pool server
//   MINE_OPERATOR (2):    run pool server, mine to own wallet, distribute to miners
//   MINE_PARTICIPANT (3): connect to external pool, submit shares, receive payouts
#define MINE_RELAY       0
#define MINE_SOLO        1
#define MINE_OPERATOR    2
#define MINE_PARTICIPANT 3
extern int    nMineMode;
// Set by the startup parser when a flag chose the mode. LoadWallet leaves the
// stored mode alone when this is true, so a flag is never silently overruled by
// something a previous session wrote.
extern bool   fMineModeFromCommandLine;
extern string strParticipantPool; // participant: pool .btf address
extern string strPoolName;        // operator: announced pool name
extern string strPoolDashboardUrl; // operator: optional dashboard URL
extern double dPoolFeePercent;     // operator: announced fee percent
extern bool fSoloMineTest; // /solomine: mine without requiring a peer (local test)
// Threads to hash with; 0 = decide from the hardware. Set by /genproclimit.
extern int nMinerThreads;
// Resolves the automatic case into a real count.
int MinerThreadCount();
extern bool gPoolServerRunning;    // GUI/startup state
extern volatile bool gPoolRunning; // runtime pool server loop flag (rpc.cpp)

struct PendingPayoutView
{
    int matureAtHeight;
    int recipients;
    int64 totalAmount;
};

struct PoolWorkerStatView
{
    std::string address;
    std::string worker;
    uint64 totalShares;
    uint64 roundShares;
    int64 lastSeen;
    double hashRate; // estimated H/s, derived from share difficulty + submit rate
};

// Settings
extern int fGenerateBitcoins;
extern int64 nTransactionFee;
extern CAddress addrIncoming;







string GetAppDir();
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");
FILE* AppendBlockFile(unsigned int& nFileRet);
bool AddKey(const CKey& key);
vector<unsigned char> GenerateNewKey();

// --- Wallet encryption ----------------------------------------------------
//
// Plain wallets keep private keys in mapKeys. Encrypted wallets keep public
// keys visible so balances can still be recognized while locked, and decrypt
// private keys only after an unlock passphrase has supplied the master key.
typedef vector<unsigned char, secure_allocator<unsigned char> > CKeyingMaterial;
extern map<vector<unsigned char>, vector<unsigned char> > mapCryptedKeys;
extern map<unsigned int, CWalletMasterKey> mapMasterKeys;
extern unsigned int nWalletMasterKeyMaxID;
extern CKeyingMaterial vWalletMasterKey;
extern vector<unsigned char> vchCryptedHDMaster;
extern vector<unsigned char> vchCryptedHDChainCode;
extern bool fWalletEncrypted;
extern bool fWalletLocked;
bool IsWalletEncrypted();
bool IsWalletLocked();
void LockWallet();
bool UnlockWallet(const string& strPassphrase, string& strErrorRet);
bool DeriveWalletPassphraseKey(const string& strPassphrase,
                               const vector<unsigned char>& vchSalt,
                               unsigned int nDeriveIterations,
                               CKeyingMaterial& vchKeyRet,
                               vector<unsigned char>& vchIVRet);
bool EncryptSecret(const CKeyingMaterial& vchKey,
                   const vector<unsigned char>& vchPlaintext,
                   const vector<unsigned char>& vchIV,
                   vector<unsigned char>& vchCiphertextRet);
bool DecryptSecret(const CKeyingMaterial& vchKey,
                   const vector<unsigned char>& vchCiphertext,
                   const vector<unsigned char>& vchIV,
                   vector<unsigned char>& vchPlaintextRet);
vector<unsigned char> WalletKeyIV(const vector<unsigned char>& vchPubKey);
vector<unsigned char> WalletSecretIV(const string& strLabel);
bool AddCryptedKey(const vector<unsigned char>& vchPubKey,
                   const vector<unsigned char>& vchCryptedSecret);
bool WalletCanSpendKey(const vector<unsigned char>& vchPubKey);
bool GetWalletPrivKey(const vector<unsigned char>& vchPubKey,
                      CPrivKey& vchPrivKeyRet,
                      string& strErrorRet);

// --- Key pool -------------------------------------------------------------
//
// A backup of this wallet only ever contained the keys that existed the moment
// it was taken. Mine a block or take a new address afterwards and the coin
// lands on a key the backup has never heard of -- it is on the chain, and the
// file you carefully put away cannot spend it. The LEIA-ME shipped with a
// warning about this, which is an admission, not a fix.
//
// Keys are now generated a hundred at a time and handed out one by one, so a
// backup covers the next hundred addresses this node will use. It is the same
// answer Bitcoin arrived at, and it is not deterministic derivation (#47) --
// it just buys back the distance between a backup and the next mistake.
static const int KEYPOOL_SIZE = 100;
extern CCriticalSection cs_keyPool;
extern map<int64, vector<unsigned char> > mapKeyPool;

// --- Deterministic wallet (BIP32) -----------------------------------------
//
// When a seed is present today, the key pool is derived from it by the legacy
// Bitflash path -- m/index', hardened, index increasing -- instead of being
// made of random keys. That is what lets a recovery phrase bring a wallet back:
// the same twelve words reproduce the same keys in the same order.
//
// BIP44 uses a different path family and separate receive/change counters.
// The schema fields below let new wallets opt into that without making old
// m/index' coins disappear.
//
// A wallet without a seed keeps working exactly as before. Existing seeded
// wallets keep their recorded schema. A new phrase uses BIP44, but it is still
// created only when the user asks for a phrase and confirms they have written
// it down, because a phrase generated silently is a backup nobody has.
//
// Empty until a seed exists.
extern vector<unsigned char> vchHDMaster;     // 32-byte master private key (IL)
extern vector<unsigned char> vchHDChainCode;  // 32 bytes (IR)
extern unsigned int nHDNext;                  // next child index to derive
static const int HD_SCHEMA_NONE   = 0;
static const int HD_SCHEMA_LEGACY = 1;         // m/index'
static const int HD_SCHEMA_BIP44  = 2;         // m/44'/coin_type'/account'/change/index
static const unsigned int HD_BIP44_PURPOSE = 44;
static const unsigned int HD_BIP44_ACCOUNT = 0;
static const unsigned int HD_BIP44_CHAIN_RECEIVE = 0;
static const unsigned int HD_BIP44_CHAIN_CHANGE = 1;
// Provisional until Bitflash has an official SLIP-0044 assignment.
// Proposed registry row: 4346950 | BITFLASH | Bitflash.
static const unsigned int HD_BIP44_COIN_TYPE_BITFLASH_PROVISIONAL = 4346950;
extern int nHDKeySchema;
extern unsigned int nHDReceiveNext;            // BIP44 external chain
extern unsigned int nHDChangeNext;             // BIP44 internal chain
extern unsigned int nHDCoinType;               // BIP44 coin_type'
inline bool HaveHDSeed() { return vchHDMaster.size() == 32 && vchHDChainCode.size() == 32; }
string HDKeySchemaName(int nSchema);
std::vector<unsigned int> HDLegacyPath(unsigned int nIndex);
std::vector<unsigned int> HDBIP44Path(unsigned int nCoinType,
                                      unsigned int nAccount,
                                      unsigned int nChain,
                                      unsigned int nIndex);

// Install a seed derived from a mnemonic, replacing any existing one. The
// default receiving key is derived immediately, so the next visible address is
// covered by the phrase. Writes to wallet.dat. Returns false and leaves the
// wallet untouched if the phrase is not valid.
bool SetHDSeedFromMnemonic(const string& strMnemonic, string& strErrorRet);

// Derive the receiving child at nIndex for the wallet's active schema and
// return it as a key. Legacy seeded wallets use m/index'. BIP44 wallets use
// m/44'/coin_type'/0'/0/index. Used by the key pool and restore, which needs
// to run ahead of the pool.
bool DeriveHDKey(unsigned int nIndex, CKey& keyRet, string& strErrorRet);
bool DeriveHDChangeKey(unsigned int nIndex, CKey& keyRet, string& strErrorRet);

// Fill the pool back up to KEYPOOL_SIZE. Every key it creates is written to
// wallet.dat before it is offered to anybody.
void TopUpKeyPool();

// Hand out the oldest unused key. Falls back to generating one on the spot if
// the pool cannot be filled, which is exactly what this code did before the
// pool existed -- a wallet that cannot pre-generate should still be able to
// mine.
vector<unsigned char> GetKeyFromPool();
bool AddToWallet(const CWalletTx& wtxIn);
void ReacceptWalletTransactions();
// Walk the chain from pindexStart forward, adding every transaction that pays
// a key this wallet holds. Returns how many were added or updated. Needed by
// anything that puts a key into the wallet after the fact -- an import, a
// restored backup, and later a recovery phrase.
bool CanScanWalletTransactions(string& strErrorRet);
int  ScanForWalletTransactions(CBlockIndex* pindexStart);
// Returns how many wallet transactions the chain corrected.
int  RescanSpentFlags();
void RelayWalletTransactions();
bool LoadBlockIndex(bool fAllowNew=true);
void PrintBlockTree();
void AddOrphanTx(const CDataStream& vMsg);
void EraseOrphanTx(uint256 hash);
void LimitOrphanTx(unsigned int nMaxOrphans);
// Same ceiling idea for orphan blocks, which never had one.
void LimitOrphanBlocks(unsigned int nMaxOrphans);
// nThreadId is 1..N, only for logging: it makes each miner's lines
// distinguishable, which the dedup filter would otherwise collapse into one.
bool BitcoinMiner(int nThreadId = 1);
void ThreadRPCServer(void* parg);  // rpc.cpp -- .btf pool server
void GetParticipantMiningStats(uint64& sharesSent, uint64& sharesAccepted, double& hashRate);
void SetParticipantMiningStatus(const std::string& status);
std::string GetParticipantMiningStatus();
void GetPoolOperatorStats(int& authorizedMiners, int& blocksFound, uint64& roundShares, double& totalHashRate);
void GetPoolWorkerStats(std::vector<PoolWorkerStatView>& out);
void GetPendingPayouts(std::vector<PendingPayoutView>& out);
bool ProcessMessages(CNode* pfrom);
bool ProcessBlock(CNode* pfrom, CBlock* pblock);
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast);
extern CCriticalSection cs_mapTransactions;
bool ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv);
bool SendMessages(CNode* pto);
int64 GetBalance();
struct WalletRecoveryAudit
{
    bool fHaveSeed;
    bool fDeriveComplete;
    int nSchema;
    unsigned int nDerivedKnown;
    unsigned int nReceiveNext;
    unsigned int nChangeNext;
    unsigned int nCoinType;
    int nRecoverableTx;
    int nLegacyTx;
    int nRecoverableImmatureTx;
    int nLegacyImmatureTx;
    int64 nRecoverableCredit;
    int64 nLegacyCredit;
    int64 nRecoverableImmatureCredit;
    int64 nLegacyImmatureCredit;
    string strDeriveError;

    WalletRecoveryAudit()
    {
        fHaveSeed = false;
        fDeriveComplete = true;
        nSchema = HD_SCHEMA_NONE;
        nDerivedKnown = 0;
        nReceiveNext = 0;
        nChangeNext = 0;
        nCoinType = HD_BIP44_COIN_TYPE_BITFLASH_PROVISIONAL;
        nRecoverableTx = 0;
        nLegacyTx = 0;
        nRecoverableImmatureTx = 0;
        nLegacyImmatureTx = 0;
        nRecoverableCredit = 0;
        nLegacyCredit = 0;
        nRecoverableImmatureCredit = 0;
        nLegacyImmatureCredit = 0;
    }
};
WalletRecoveryAudit GetWalletRecoveryAudit();
bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& txNew, int64& nFeeRequiredRet);
bool CommitTransactionSpent(const CWalletTx& wtxNew);
bool SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew);











class CDiskTxPos
{
public:
    unsigned int nFile;
    unsigned int nBlockPos;
    unsigned int nTxPos;

    CDiskTxPos()
    {
        SetNull();
    }

    CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn)
    {
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nTxPos = nTxPosIn;
    }

    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { nFile = -1; nBlockPos = 0; nTxPos = 0; }
    bool IsNull() const { return (nFile == -1); }

    friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return (a.nFile     == b.nFile &&
                a.nBlockPos == b.nBlockPos &&
                a.nTxPos    == b.nTxPos);
    }

    friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return !(a == b);
    }

    string ToString() const
    {
        if (IsNull())
            return strprintf("null");
        else
            return strprintf("(nFile=%d, nBlockPos=%d, nTxPos=%d)", nFile, nBlockPos, nTxPos);
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }
};




class CInPoint
{
public:
    CTransaction* ptx;
    unsigned int n;

    CInPoint() { SetNull(); }
    CInPoint(CTransaction* ptxIn, unsigned int nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = -1; }
    bool IsNull() const { return (ptx == NULL && n == -1); }
};




class COutPoint
{
public:
    uint256 hash;
    unsigned int n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { hash = 0; n = -1; }
    bool IsNull() const { return (hash == 0 && n == -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    string ToString() const
    {
        return strprintf("COutPoint(%s, %d)", hash.ToString().substr(0,6).c_str(), n);
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




//
// An input of a transaction.  It contains the location of the previous
// transaction's output that it claims and a signature that matches the
// output's public key.
//
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    unsigned int nSequence;

    CTxIn()
    {
        nSequence = UINT_MAX;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=UINT_MAX)
    {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=UINT_MAX)
    {
        prevout = COutPoint(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    )

    bool IsFinal() const
    {
        return (nSequence == UINT_MAX);
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    string ToString() const
    {
        string str;
        str += strprintf("CTxIn(");
        str += prevout.ToString();
        if (prevout.IsNull())
            str += strprintf(", coinbase %s", HexStr(scriptSig.begin(), scriptSig.end(), false).c_str());
        else
            str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24).c_str());
        if (nSequence != UINT_MAX)
            str += strprintf(", nSequence=%u", nSequence);
        str += ")";
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }

    bool IsMine() const;
    int64 GetDebit() const;
};




//
// An output of a transaction.  It contains the public key that the next input
// must be able to sign with to claim it.
//
class CTxOut
{
public:
    int64 nValue;
    CScript scriptPubKey;

public:
    CTxOut()
    {
        SetNull();
    }

    CTxOut(int64 nValueIn, CScript scriptPubKeyIn)
    {
        nValue = nValueIn;
        scriptPubKey = scriptPubKeyIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    )

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull()
    {
        return (nValue == -1);
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    bool IsMine() const
    {
        return ::IsMine(scriptPubKey);
    }

    int64 GetCredit() const
    {
        if (IsMine())
            return nValue;
        return 0;
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    string ToString() const
    {
        if (scriptPubKey.size() < 6)
            return "CTxOut(error)";
        return strprintf("CTxOut(nValue=%lld.%08lld, scriptPubKey=%s)", nValue / COIN, nValue % COIN, scriptPubKey.ToString().substr(0,24).c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




//
// The basic transaction that is broadcasted on the network and contained in
// blocks.  A transaction can contain multiple inputs and outputs.
//
class CTransaction
{
public:
    int nVersion;
    vector<CTxIn> vin;
    vector<CTxOut> vout;
    int nLockTime;


    CTransaction()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
    )

    void SetNull()
    {
        nVersion = 1;
        vin.clear();
        vout.clear();
        nLockTime = 0;
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    bool IsFinal() const
    {
        if (nLockTime == 0 || nLockTime < nBestHeight)
            return true;
        foreach(const CTxIn& txin, vin)
            if (!txin.IsFinal())
                return false;
        return true;
    }

    bool IsNewerThan(const CTransaction& old) const
    {
        if (vin.size() != old.vin.size())
            return false;
        for (int i = 0; i < vin.size(); i++)
            if (vin[i].prevout != old.vin[i].prevout)
                return false;

        bool fNewer = false;
        unsigned int nLowest = UINT_MAX;
        for (int i = 0; i < vin.size(); i++)
        {
            if (vin[i].nSequence != old.vin[i].nSequence)
            {
                if (vin[i].nSequence <= nLowest)
                {
                    fNewer = false;
                    nLowest = vin[i].nSequence;
                }
                if (old.vin[i].nSequence < nLowest)
                {
                    fNewer = true;
                    nLowest = old.vin[i].nSequence;
                }
            }
        }
        return fNewer;
    }

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    unsigned int GetSigOpCount() const
    {
        unsigned int n = 0;
        foreach(const CTxIn& txin, vin)
            n += txin.scriptSig.GetSigOpCount();
        foreach(const CTxOut& txout, vout)
            n += txout.scriptPubKey.GetSigOpCount();
        return n;
    }

    bool CheckTransaction() const
    {
        // Basic checks that don't depend on any context
        if (vin.empty() || vout.empty())
            return error("CTransaction::CheckTransaction() : vin or vout empty");

        // Check for negative or overflow output values (CVE-2010-5139)
        int64 nValueOut = 0;
        foreach(const CTxOut& txout, vout)
        {
            if (txout.nValue < 0)
                return error("CTransaction::CheckTransaction() : txout.nValue negative");
            if (txout.nValue > MAX_MONEY)
                return error("CTransaction::CheckTransaction() : txout.nValue too high");
            nValueOut += txout.nValue;
            if (!MoneyRange(nValueOut))
                return error("CTransaction::CheckTransaction() : txout total out of range");
        }

        if (IsCoinBase())
        {
            if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
                return error("CTransaction::CheckTransaction() : coinbase script size");
        }
        else
        {
            foreach(const CTxIn& txin, vin)
                if (txin.prevout.IsNull())
                    return error("CTransaction::CheckTransaction() : prevout is null");
        }

        // Check for duplicate inputs (a tx spending the same output twice)
        set<COutPoint> vInOutPoints;
        foreach(const CTxIn& txin, vin)
        {
            if (vInOutPoints.count(txin.prevout))
                return error("CTransaction::CheckTransaction() : duplicate inputs");
            vInOutPoints.insert(txin.prevout);
        }

        return true;
    }

    bool IsMine() const
    {
        foreach(const CTxOut& txout, vout)
            if (txout.IsMine())
                return true;
        return false;
    }

    int64 GetDebit() const
    {
        int64 nDebit = 0;
        foreach(const CTxIn& txin, vin)
            nDebit += txin.GetDebit();
        return nDebit;
    }

    int64 GetCredit() const
    {
        int64 nCredit = 0;
        foreach(const CTxOut& txout, vout)
            nCredit += txout.GetCredit();
        return nCredit;
    }

    int64 GetValueOut() const
    {
        int64 nValueOut = 0;
        foreach(const CTxOut& txout, vout)
        {
            if (txout.nValue < 0)
                throw runtime_error("CTransaction::GetValueOut() : negative value");
            if (txout.nValue > MAX_MONEY)
                throw runtime_error("CTransaction::GetValueOut() : value too high");
            nValueOut += txout.nValue;
            if (!MoneyRange(nValueOut))
                throw runtime_error("CTransaction::GetValueOut() : total out of range");
        }
        return nValueOut;
    }

    int64 GetMinFee(bool fDiscount=false) const
    {
        unsigned int nBytes = ::GetSerializeSize(*this, SER_NETWORK);
        if (fDiscount && nBytes < 10000)
            return 0;
        return (1 + (int64)nBytes / 1000) * CENT;
    }



    bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL)
    {
        CAutoFile filein = OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb");
        if (!filein)
            return error("CTransaction::ReadFromDisk() : OpenBlockFile failed");

        // Read transaction
        if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
            return error("CTransaction::ReadFromDisk() : fseek failed");
        filein >> *this;

        // Return file pointer
        if (pfileRet)
        {
            if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
                return error("CTransaction::ReadFromDisk() : second fseek failed");
            *pfileRet = filein.release();
        }
        return true;
    }


    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nVersion  == b.nVersion &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }


    string ToString() const
    {
        string str;
        str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%d, vout.size=%d, nLockTime=%u)\n",
            GetHash().ToString().substr(0,6).c_str(),
            nVersion,
            (int)vin.size(),
            (int)vout.size(),
            nLockTime);
        for (int i = 0; i < vin.size(); i++)
            str += "    " + vin[i].ToString() + "\n";
        for (int i = 0; i < vout.size(); i++)
            str += "    " + vout[i].ToString() + "\n";
        return str;
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }



    bool DisconnectInputs(CTxDB& txdb);
    bool ConnectInputs(CTxDB& txdb, map<uint256, CTxIndex>& mapTestPool, CDiskTxPos posThisTx, int nHeight, int64& nFees, bool fBlock, bool fMiner, int64 nMinFee=0);
    bool ClientConnectInputs();

    bool AcceptTransaction(CTxDB& txdb, bool fCheckInputs=true, bool* pfMissingInputs=NULL);

    bool AcceptTransaction(bool fCheckInputs=true, bool* pfMissingInputs=NULL)
    {
        CTxDB txdb("r");
        return AcceptTransaction(txdb, fCheckInputs, pfMissingInputs);
    }

protected:
    bool AddToMemoryPool();
public:
    bool RemoveFromMemoryPool();
};





//
// A transaction with a merkle branch linking it to the block chain
//
class CMerkleTx : public CTransaction
{
public:
    uint256 hashBlock;
    vector<uint256> vMerkleBranch;
    int nIndex;

    // memory only
    mutable bool fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }

    int64 GetCredit() const
    {
        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;
        return CTransaction::GetCredit();
    }

    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    )


    int SetMerkleBranch(const CBlock* pblock=NULL);
    int GetDepthInMainChain() const;
    bool IsInMainChain() const { return GetDepthInMainChain() > 0; }
    int GetBlocksToMaturity() const;
    bool AcceptTransaction(CTxDB& txdb, bool fCheckInputs=true);
    bool AcceptTransaction() { CTxDB txdb("r"); return AcceptTransaction(txdb); }
};




//
// A transaction with a bunch of additional info that only the owner cares
// about.  It includes any unrecorded transactions needed to link it back
// to the block chain.
//
class CWalletTx : public CMerkleTx
{
public:
    vector<CMerkleTx> vtxPrev;
    map<string, string> mapValue;
    vector<pair<string, string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived;  // time received by this node
    char fFromMe;
    char fSpent;
    //// probably need to sign the order info so know it came from payer

    // memory only
    mutable unsigned int nTimeDisplayed;


    CWalletTx()
    {
        Init();
    }

    CWalletTx(const CMerkleTx& txIn) : CMerkleTx(txIn)
    {
        Init();
    }

    CWalletTx(const CTransaction& txIn) : CMerkleTx(txIn)
    {
        Init();
    }

    void Init()
    {
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        fFromMe = false;
        fSpent = false;
        nTimeDisplayed = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CMerkleTx*)this, nType, nVersion, ser_action);
        nVersion = this->nVersion;
        READWRITE(vtxPrev);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);
    )

    bool WriteToDisk()
    {
        return CWalletDB().WriteTx(GetHash(), *this);
    }


    int64 GetTxTime() const;

    void AddSupportingTransactions(CTxDB& txdb);

    bool AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs=true);
    bool AcceptWalletTransaction() { CTxDB txdb("r"); return AcceptWalletTransaction(txdb); }

    void RelayWalletTransaction(CTxDB& txdb);
    void RelayWalletTransaction() { CTxDB txdb("r"); RelayWalletTransaction(txdb); }
};




//
// A txdb record that contains the disk location of a transaction and the
// locations of transactions that spend its outputs.  vSpent is really only
// used as a flag, but having the location is very helpful for debugging.
//
class CTxIndex
{
public:
    CDiskTxPos pos;
    vector<CDiskTxPos> vSpent;

    CTxIndex()
    {
        SetNull();
    }

    CTxIndex(const CDiskTxPos& posIn, unsigned int nOutputs)
    {
        pos = posIn;
        vSpent.resize(nOutputs);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(pos);
        READWRITE(vSpent);
    )

    void SetNull()
    {
        pos.SetNull();
        vSpent.clear();
    }

    bool IsNull()
    {
        return pos.IsNull();
    }

    friend bool operator==(const CTxIndex& a, const CTxIndex& b)
    {
        if (a.pos != b.pos || a.vSpent.size() != b.vSpent.size())
            return false;
        for (int i = 0; i < a.vSpent.size(); i++)
            if (a.vSpent[i] != b.vSpent[i])
                return false;
        return true;
    }

    friend bool operator!=(const CTxIndex& a, const CTxIndex& b)
    {
        return !(a == b);
    }
};





//
// Nodes collect new transactions into a block, hash them into a hash tree,
// and scan through nonce values to make the block's hash satisfy proof-of-work
// requirements.  When they solve the proof-of-work, they broadcast the block
// to everyone and the block is added to the block chain.  The first transaction
// in the block is a special one that creates a new coin owned by the creator
// of the block.
//
// Blocks are appended to blk0001.dat files on disk.  Their location on disk
// is indexed by CBlockIndex objects in memory.
//
class CBlock
{
public:
    // header
    int nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    // network and disk
    vector<CTransaction> vtx;

    // memory only
    mutable vector<uint256> vMerkleTree;


    CBlock()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);

        // ConnectBlock depends on vtx being last so it can calculate offset
        if (!(nType & (SER_GETHASH|SER_BLOCKHEADERONLY)))
            READWRITE(vtx);
        else if (fRead)
            const_cast<CBlock*>(this)->vtx.clear();
    )

    void SetNull()
    {
        nVersion = 1;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        vtx.clear();
        vMerkleTree.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const
    {
        // Block IDENTITY hash (SHA-256d), used for indexing.
        return Hash(BEGIN(nVersion), END(nNonce));
    }

    uint256 GetPoWHash() const
    {
        // Memory-hard PROOF-OF-WORK hash (RandomX) over the 80-byte header.
        // This is the one that must be <= target (nBits).
        return RandomXPoWHash((const void*)BEGIN(nVersion), END(nNonce) - BEGIN(nVersion));
    }

    bool CheckSizeLimits() const
    {
        // The middle test compares a transaction *count* against a *byte*
        // limit. It is inherited from 0.1.0, where the same line compared
        // vtx.size() against MAX_SIZE, and it is inert: the smallest possible
        // transaction serializes to more than sixty bytes, so a block holding
        // over a million of them cannot also weigh under a megabyte.
        //
        // Kept rather than removed. This is consensus code, and a rewrite that
        // reads better is still a rewrite that can change what the network
        // accepts. Written down so the next reader does not have to derive it,
        // or "fix" it into something that does.
        return (!vtx.empty() &&
                vtx.size() <= MAX_BLOCK_SIZE &&
                ::GetSerializeSize(*this, SER_DISK) <= MAX_BLOCK_SIZE);
    }


    uint256 BuildMerkleTree() const
    {
        vMerkleTree.clear();
        foreach(const CTransaction& tx, vtx)
            vMerkleTree.push_back(tx.GetHash());
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            for (int i = 0; i < nSize; i += 2)
            {
                int i2 = min(i+1, nSize-1);
                vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                           BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
            }
            j += nSize;
        }
        return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
    }

    vector<uint256> GetMerkleBranch(int nIndex) const
    {
        if (vMerkleTree.empty())
            BuildMerkleTree();
        vector<uint256> vMerkleBranch;
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            int i = min(nIndex^1, nSize-1);
            vMerkleBranch.push_back(vMerkleTree[j+i]);
            nIndex >>= 1;
            j += nSize;
        }
        return vMerkleBranch;
    }

    static uint256 CheckMerkleBranch(uint256 hash, const vector<uint256>& vMerkleBranch, int nIndex)
    {
        if (nIndex == -1)
            return 0;
        foreach(const uint256& otherside, vMerkleBranch)
        {
            if (nIndex & 1)
                hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
            else
                hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
            nIndex >>= 1;
        }
        return hash;
    }


    bool WriteToDisk(bool fWriteTransactions, unsigned int& nFileRet, unsigned int& nBlockPosRet)
    {
        // Open history file to append
        CAutoFile fileout = AppendBlockFile(nFileRet);
        if (!fileout)
            return error("CBlock::WriteToDisk() : AppendBlockFile failed");
        if (!fWriteTransactions)
            fileout.nType |= SER_BLOCKHEADERONLY;

        // Write index header
        unsigned int nSize = fileout.GetSerializeSize(*this);
        fileout << FLATDATA(pchMessageStart) << nSize;

        // Write block
        nBlockPosRet = ftell(fileout);
        if (nBlockPosRet == -1)
            return error("CBlock::WriteToDisk() : ftell failed");
        fileout << *this;

        return true;
    }

    bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions)
    {
        SetNull();

        // Open history file to read
        CAutoFile filein = OpenBlockFile(nFile, nBlockPos, "rb");
        if (!filein)
            return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
        if (!fReadTransactions)
            filein.nType |= SER_BLOCKHEADERONLY;

        // Read block
        filein >> *this;

        // Check the header
        if (CBigNum().SetCompact(nBits) > bnProofOfWorkLimit)
            return error("CBlock::ReadFromDisk() : nBits errors in block header");
        // NOTE: the proof of work is RandomX (GetPoWHash), validated once by
        // CheckBlock when the block is accepted. Re-checking it on every disk
        // read would be prohibitively slow, and checking the SHA-256d GetHash()
        // here (a leftover from Bitcoin) is simply wrong for a RandomX chain.

        return true;
    }



    void print() const
    {
        printf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%d)\n",
            GetHash().ToString().substr(0,14).c_str(),
            nVersion,
            hashPrevBlock.ToString().substr(0,14).c_str(),
            hashMerkleRoot.ToString().substr(0,6).c_str(),
            nTime, nBits, nNonce,
            (int)vtx.size());
        for (int i = 0; i < vtx.size(); i++)
        {
            printf("  ");
            vtx[i].print();
        }
        printf("  vMerkleTree: ");
        for (int i = 0; i < vMerkleTree.size(); i++)
            printf("%s ", vMerkleTree[i].ToString().substr(0,6).c_str());
        printf("\n");
    }


    int64 GetBlockValue(int nHeight, int64 nFees) const;
    bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    bool ReadFromDisk(const CBlockIndex* blockindex, bool fReadTransactions);
    bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos);
    bool CheckBlock() const;
    bool AcceptBlock();
};






//
// The block chain is a tree shaped structure starting with the
// genesis block at the root, with each block potentially having multiple
// candidates to be the next block.  pprev and pnext link a path through the
// main/longest chain.  A blockindex may have multiple pprev pointing back
// to it, but pnext will only point forward to the longest branch, or will
// be null if the block is not part of the longest chain.
//
class CBlockIndex
{
public:
    const uint256* phashBlock;
    CBlockIndex* pprev;
    CBlockIndex* pnext;
    unsigned int nFile;
    unsigned int nBlockPos;
    int nHeight;

    // block header
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;


    CBlockIndex()
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        nFile = 0;
        nBlockPos = 0;
        nHeight = 0;

        nVersion       = 0;
        hashMerkleRoot = 0;
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;
    }

    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock& block)
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nHeight = 0;

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    bool IsInMainChain() const
    {
        return (pnext || this == pindexBest);
    }

    bool EraseBlockFromDisk()
    {
        // Open history file
        CAutoFile fileout = OpenBlockFile(nFile, nBlockPos, "rb+");
        if (!fileout)
            return false;

        // Overwrite with empty null block
        CBlock block;
        block.SetNull();
        fileout << block;

        return true;
    }

    enum { nMedianTimeSpan=11 };

    int64 GetMedianTimePast() const
    {
        unsigned int pmedian[nMedianTimeSpan];
        unsigned int* pbegin = &pmedian[nMedianTimeSpan];
        unsigned int* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->nTime;

        sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    int64 GetMedianTime() const
    {
        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan/2; i++)
        {
            if (!pindex->pnext)
                return nTime;
            pindex = pindex->pnext;
        }
        return pindex->GetMedianTimePast();
    }



    string ToString() const
    {
        // pprev/pnext are pointers: %08x truncated them to 32 bits on a 64-bit
        // build, so the two fields this line exists to show were unreliable.
        return strprintf("CBlockIndex(nprev=%p, pnext=%p, nFile=%d, nBlockPos=%-6d nHeight=%d, merkle=%s, hashBlock=%s)",
            (void*)pprev, (void*)pnext, nFile, nBlockPos, nHeight,
            hashMerkleRoot.ToString().substr(0,6).c_str(),
            GetBlockHash().ToString().substr(0,14).c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};



//
// Used to marshal pointers into hashes for db storage.
//
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev;
    uint256 hashNext;

    CDiskBlockIndex()
    {
        hashPrev = 0;
        hashNext = 0;
    }

    explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex)
    {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
        hashNext = (pnext ? pnext->GetBlockHash() : 0);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(hashNext);
        READWRITE(nFile);
        READWRITE(nBlockPos);
        READWRITE(nHeight);

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    )

    uint256 GetBlockHash() const
    {
        CBlock block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;
        return block.GetHash();
    }


    string ToString() const
    {
        string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
            GetBlockHash().ToString().c_str(),
            hashPrev.ToString().substr(0,14).c_str(),
            hashNext.ToString().substr(0,14).c_str());
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};








//
// Describes a place in the block chain to another node such that if the
// other node doesn't have the same branch, it can find a recent common trunk.
// The further back it is, the further before the fork it may be.
//
class CBlockLocator
{
protected:
    vector<uint256> vHave;
public:

    CBlockLocator()
    {
    }

    explicit CBlockLocator(const CBlockIndex* pindex)
    {
        Set(pindex);
    }

    explicit CBlockLocator(uint256 hashBlock)
    {
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end())
            Set((*mi).second);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    )

    void Set(const CBlockIndex* pindex)
    {
        vHave.clear();
        int nStep = 1;
        while (pindex)
        {
            vHave.push_back(pindex->GetBlockHash());

            // Exponentially larger steps back
            for (int i = 0; pindex && i < nStep; i++)
                pindex = pindex->pprev;
            if (vHave.size() > 10)
                nStep *= 2;
        }
        vHave.push_back(hashGenesisBlock);
    }

    CBlockIndex* GetBlockIndex()
    {
        // Find the first block the caller has in the main chain
        foreach(const uint256& hash, vHave)
        {
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return pindex;
            }
        }
        return pindexGenesisBlock;
    }

    uint256 GetBlockHash()
    {
        // Find the first block the caller has in the main chain
        foreach(const uint256& hash, vHave)
        {
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return hash;
            }
        }
        return hashGenesisBlock;
    }

    int GetHeight()
    {
        CBlockIndex* pindex = GetBlockIndex();
        if (!pindex)
            return 0;
        return pindex->nHeight;
    }
};












extern map<uint256, CTransaction> mapTransactions;
extern map<uint256, CWalletTx> mapWallet;
extern vector<pair<uint256, bool> > vWalletUpdated;
extern CCriticalSection cs_mapWallet;
extern map<vector<unsigned char>, CPrivKey> mapKeys;
extern map<uint160, vector<unsigned char> > mapPubKeys;
extern CCriticalSection cs_mapKeys;
extern CKey keyUser;
