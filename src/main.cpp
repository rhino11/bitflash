// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#pragma push_macro("snprintf")
#undef snprintf
#include <nlohmann/json.hpp>
#pragma pop_macro("snprintf")
#ifdef snprintf
#undef snprintf
#endif
#include "headers.h"
#include "sha.h"
#include <atomic>
#include <mutex>
#include <thread>
#include "bip32.h"
#include "btfaddr.h"
#include "btftunnel.h"
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif





//
// Global state
//

CCriticalSection cs_main;

map<uint256, CTransaction> mapTransactions;
CCriticalSection cs_mapTransactions;
unsigned int nTransactionsUpdated = 0;
map<COutPoint, CInPoint> mapNextTx;

map<uint256, CBlockIndex*> mapBlockIndex;
// Bitflash genesis -- mined under RandomX PoW on 2026-07-22
// (nTime 1753142400, nBits 0x1f0fffff, RandomX key "Bitflash/RandomX/v1/...")
// Bitflash 2026 stable relaunch genesis (2-min blocks, RandomX). Mined values.
unsigned int GENESIS_NONCE = 3141;
uint256 hashGenesisBlock("0x5bd7cb255d814e48cebcdfb72da4dc87b34bd774227f8ceb546c5640f4bdc169");
uint256 hashGenesisMerkleRoot("0x1a45b4482532abb29b10e234d3f13132230525a339ecea91658ffa675a5b1325");
CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;
uint256 hashBestChain = 0;
// Blocks at the tip to re-verify on startup. 0 means the whole chain. 288 is
// about ten hours at a two-minute target -- far enough back to catch a bad tip,
// short enough that startup does not pay a RandomX hash per block for the whole
// history. /checkblocks=N overrides it.
int nCheckBlocksOnLoad = 288;
// Set by CTxDB::LoadBlockIndex when the tail of the chain fails verification.
// The repair runs in LoadBlockIndex() below, once that read-only handle and its
// cursor are closed.
CBlockIndex* pindexBadChainFork = NULL;
CBlockIndex* pindexBest = NULL;

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;

map<uint256, CDataStream*> mapOrphanTransactions;
multimap<uint256, CDataStream*> mapOrphanTransactionsByPrev;

map<uint256, CWalletTx> mapWallet;
vector<pair<uint256, bool> > vWalletUpdated;
CCriticalSection cs_mapWallet;

map<vector<unsigned char>, CPrivKey> mapKeys;
map<vector<unsigned char>, vector<unsigned char> > mapCryptedKeys;
map<uint160, vector<unsigned char> > mapPubKeys;
map<unsigned int, CWalletMasterKey> mapMasterKeys;
unsigned int nWalletMasterKeyMaxID = 0;
CKeyingMaterial vWalletMasterKey;
vector<unsigned char> vchCryptedHDMaster;
vector<unsigned char> vchCryptedHDChainCode;
bool fWalletEncrypted = false;
bool fWalletLocked = true;
CCriticalSection cs_mapKeys;
CKey keyUser;

string strSetDataDir;
int nDropMessagesTest = 0;
bool fSoloMineTest = false; // /solomine: mine without requiring a peer (local test)

// Settings
int fGenerateBitcoins;
// How many threads to hash with. 0 means "decide from the hardware" -- see
// MinerThreadCount(). This was effectively 1 forever, because Bitcoin 0.1.0
// started exactly one miner thread and nothing here ever changed that. It made
// sense for SHA-256d in 2009; RandomX is built to be fed by every core at once,
// so a 32-core machine was mining at a thirty-second of its capacity and the
// only visible symptom was a suspiciously idle CPU.
int nMinerThreads = 0;
int64 nTransactionFee = 0;
CAddress addrIncoming;
int    nMineMode        = MINE_RELAY;
bool   fMineModeFromCommandLine = false;
string strParticipantPool;           // participant mode: pool .btf address
string strPoolName       = "Bitflash Pool";
string strPoolDashboardUrl;
double dPoolFeePercent   = 0.0;

static std::atomic<uint64> gParticipantSharesSent{0};
static std::atomic<uint64> gParticipantSharesAccepted{0};
static std::atomic<uint64> gParticipantHashes{0};
static std::atomic<uint64> gParticipantHashRateX1000{0};
static std::mutex gParticipantStatusMutex;
static std::string gParticipantStatus;

void SetParticipantMiningStatus(const std::string& status)
{
    // Updates the GUI status string only. Logging is done at each call site
    // with full context; duplicating it here just adds noise to the log.
    std::lock_guard<std::mutex> lk(gParticipantStatusMutex);
    gParticipantStatus = status;
}

std::string GetParticipantMiningStatus()
{
    std::lock_guard<std::mutex> lk(gParticipantStatusMutex);
    return gParticipantStatus;
}

void GetParticipantMiningStats(uint64& sharesSent, uint64& sharesAccepted, double& hashRate)
{
    sharesSent = gParticipantSharesSent.load();
    sharesAccepted = gParticipantSharesAccepted.load();
    hashRate = (double)gParticipantHashRateX1000.load() / 1000.0;
}







//////////////////////////////////////////////////////////////////////////////
//
// mapKeys
//

// Threads to hash with, resolving the automatic case.
//
// Automatic leaves one core to the rest of the node -- accepting blocks,
// talking to peers, serving the GUI -- because a machine that mines perfectly
// while falling behind the chain has won nothing. Anyone who disagrees can say
// so with /genproclimit and get exactly what they ask for.
//
// Memory is not the reason to hold back: the ~2 GB RandomX dataset is shared by
// every thread, and each one adds only its own 2 MB scratchpad. Sixteen threads
// cost about 32 MB more than one.
int MinerThreadCount()
{
    if (nMinerThreads > 0)
        return nMinerThreads;
    unsigned int nCores = std::thread::hardware_concurrency();
    if (nCores <= 1)
        return 1;
    return (int)(nCores - 1);
}

bool AddKey(const CKey& key)
{
    if (IsWalletEncrypted())
    {
        string strError;
        CPrivKey vchPrivKey = key.GetPrivKey();
        vector<unsigned char> vchCryptedSecret;
        if (IsWalletLocked())
            return error("AddKey() : wallet is locked\n");
        if (!EncryptSecret(vWalletMasterKey, vector<unsigned char>(vchPrivKey.begin(), vchPrivKey.end()),
                           WalletKeyIV(key.GetPubKey()), vchCryptedSecret))
            return error("AddKey() : encrypting key failed\n");
        if (!AddCryptedKey(key.GetPubKey(), vchCryptedSecret))
            return false;
        return CWalletDB().WriteCryptedKey(key.GetPubKey(), vchCryptedSecret);
    }

    CRITICAL_BLOCK(cs_mapKeys)
    {
        mapKeys[key.GetPubKey()] = key.GetPrivKey();
        mapPubKeys[Hash160(key.GetPubKey())] = key.GetPubKey();
    }
    return CWalletDB().WriteKey(key.GetPubKey(), key.GetPrivKey());
}

bool IsWalletEncrypted()
{
    return fWalletEncrypted;
}

bool IsWalletLocked()
{
    return fWalletEncrypted && fWalletLocked;
}

void LockWallet()
{
    if (!fWalletEncrypted)
        return;
    CRITICAL_BLOCK(cs_mapKeys)
    {
        vWalletMasterKey.clear();
        if (!vchCryptedHDMaster.empty())
            vchHDMaster.clear();
        if (!vchCryptedHDChainCode.empty())
            vchHDChainCode.clear();
        fWalletLocked = true;
    }
}

bool DeriveWalletPassphraseKey(const string& strPassphrase,
                               const vector<unsigned char>& vchSalt,
                               unsigned int nDeriveIterations,
                               CKeyingMaterial& vchKeyRet,
                               vector<unsigned char>& vchIVRet)
{
    vchKeyRet.clear();
    vchIVRet.clear();
    if (vchSalt.size() != 8 || nDeriveIterations < 1)
        return false;

    unsigned char chKey[32];
    unsigned char chIV[16];
    int n = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &vchSalt[0],
                           (const unsigned char*)strPassphrase.data(),
                           (int)strPassphrase.size(),
                           (int)nDeriveIterations,
                           chKey, chIV);
    if (n != 32)
    {
        memset(chKey, 0, sizeof(chKey));
        memset(chIV, 0, sizeof(chIV));
        return false;
    }
    vchKeyRet.assign(chKey, chKey + sizeof(chKey));
    vchIVRet.assign(chIV, chIV + sizeof(chIV));
    memset(chKey, 0, sizeof(chKey));
    memset(chIV, 0, sizeof(chIV));
    return true;
}

bool EncryptSecret(const CKeyingMaterial& vchKey,
                   const vector<unsigned char>& vchPlaintext,
                   const vector<unsigned char>& vchIV,
                   vector<unsigned char>& vchCiphertextRet)
{
    vchCiphertextRet.clear();
    if (vchKey.size() != 32 || vchIV.size() != 16)
        return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    bool fOk = false;
    int nLen = 0;
    int nFinal = 0;
    vector<unsigned char> vchOut(vchPlaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, &vchKey[0], &vchIV[0]) &&
        EVP_EncryptUpdate(ctx, &vchOut[0], &nLen,
                          vchPlaintext.empty() ? NULL : &vchPlaintext[0],
                          (int)vchPlaintext.size()) &&
        EVP_EncryptFinal_ex(ctx, &vchOut[0] + nLen, &nFinal))
    {
        vchOut.resize(nLen + nFinal);
        vchCiphertextRet.swap(vchOut);
        fOk = true;
    }
    EVP_CIPHER_CTX_free(ctx);
    return fOk;
}

bool DecryptSecret(const CKeyingMaterial& vchKey,
                   const vector<unsigned char>& vchCiphertext,
                   const vector<unsigned char>& vchIV,
                   vector<unsigned char>& vchPlaintextRet)
{
    vchPlaintextRet.clear();
    if (vchKey.size() != 32 || vchIV.size() != 16 || vchCiphertext.empty())
        return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    bool fOk = false;
    int nLen = 0;
    int nFinal = 0;
    vector<unsigned char> vchOut(vchCiphertext.size());
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, &vchKey[0], &vchIV[0]) &&
        EVP_DecryptUpdate(ctx, &vchOut[0], &nLen, &vchCiphertext[0],
                          (int)vchCiphertext.size()) &&
        EVP_DecryptFinal_ex(ctx, &vchOut[0] + nLen, &nFinal))
    {
        vchOut.resize(nLen + nFinal);
        vchPlaintextRet.swap(vchOut);
        fOk = true;
    }
    EVP_CIPHER_CTX_free(ctx);
    return fOk;
}

vector<unsigned char> WalletKeyIV(const vector<unsigned char>& vchPubKey)
{
    uint256 hash = Hash(vchPubKey.begin(), vchPubKey.end());
    vector<unsigned char> vchIV(16);
    memcpy(&vchIV[0], hash.begin(), vchIV.size());
    return vchIV;
}

vector<unsigned char> WalletSecretIV(const string& strLabel)
{
    uint256 hash = Hash(strLabel.begin(), strLabel.end());
    vector<unsigned char> vchIV(16);
    memcpy(&vchIV[0], hash.begin(), vchIV.size());
    return vchIV;
}

bool AddCryptedKey(const vector<unsigned char>& vchPubKey,
                   const vector<unsigned char>& vchCryptedSecret)
{
    if (vchPubKey.empty() || vchCryptedSecret.empty())
        return false;
    CRITICAL_BLOCK(cs_mapKeys)
    {
        fWalletEncrypted = true;
        mapCryptedKeys[vchPubKey] = vchCryptedSecret;
        mapPubKeys[Hash160(vchPubKey)] = vchPubKey;
    }
    return true;
}

bool WalletCanSpendKey(const vector<unsigned char>& vchPubKey)
{
    CRITICAL_BLOCK(cs_mapKeys)
        return mapKeys.count(vchPubKey) > 0 || mapCryptedKeys.count(vchPubKey) > 0;
    return false;
}

bool GetWalletPrivKey(const vector<unsigned char>& vchPubKey,
                      CPrivKey& vchPrivKeyRet,
                      string& strErrorRet)
{
    vchPrivKeyRet.clear();
    CRITICAL_BLOCK(cs_mapKeys)
    {
        map<vector<unsigned char>, CPrivKey>::iterator mi = mapKeys.find(vchPubKey);
        if (mi != mapKeys.end())
        {
            vchPrivKeyRet = (*mi).second;
            return true;
        }

        map<vector<unsigned char>, vector<unsigned char> >::iterator mci = mapCryptedKeys.find(vchPubKey);
        if (mci == mapCryptedKeys.end())
        {
            strErrorRet = "private key not found";
            return false;
        }
        if (IsWalletLocked())
        {
            strErrorRet = "wallet is locked";
            return false;
        }

        vector<unsigned char> vchPlaintext;
        if (!DecryptSecret(vWalletMasterKey, (*mci).second, WalletKeyIV(vchPubKey), vchPlaintext))
        {
            strErrorRet = "could not decrypt private key";
            return false;
        }

        CPrivKey vchPrivKey(vchPlaintext.begin(), vchPlaintext.end());
        CKey key;
        if (!key.SetPrivKey(vchPrivKey) || key.GetPubKey() != vchPubKey)
        {
            strErrorRet = "decrypted private key does not match its public key";
            return false;
        }
        vchPrivKeyRet = vchPrivKey;
        return true;
    }
    return false;
}

bool UnlockWallet(const string& strPassphrase, string& strErrorRet)
{
    strErrorRet.clear();
    if (!IsWalletEncrypted())
        return true;

    CRITICAL_BLOCK(cs_mapKeys)
    {
        for (map<unsigned int, CWalletMasterKey>::iterator mi = mapMasterKeys.begin();
             mi != mapMasterKeys.end(); ++mi)
        {
            const CWalletMasterKey& kMasterKey = (*mi).second;
            CKeyingMaterial vchPassKey;
            vector<unsigned char> vchPassIV;
            if (!DeriveWalletPassphraseKey(strPassphrase, kMasterKey.vchSalt,
                                           kMasterKey.nDeriveIterations,
                                           vchPassKey, vchPassIV))
                continue;

            vector<unsigned char> vchMasterPlain;
            if (!DecryptSecret(vchPassKey, kMasterKey.vchCryptedKey,
                               vchPassIV, vchMasterPlain))
                continue;
            if (vchMasterPlain.size() != 32)
                continue;

            CKeyingMaterial vchCandidate(vchMasterPlain.begin(), vchMasterPlain.end());
            bool fValid = mapCryptedKeys.empty();
            for (map<vector<unsigned char>, vector<unsigned char> >::iterator mci = mapCryptedKeys.begin();
                 mci != mapCryptedKeys.end(); ++mci)
            {
                vector<unsigned char> vchPlaintext;
                if (!DecryptSecret(vchCandidate, (*mci).second, WalletKeyIV((*mci).first), vchPlaintext))
                    break;
                CPrivKey vchPrivKey(vchPlaintext.begin(), vchPlaintext.end());
                CKey key;
                if (key.SetPrivKey(vchPrivKey) && key.GetPubKey() == (*mci).first)
                    fValid = true;
                break;
            }
            if (fValid)
            {
                vWalletMasterKey = vchCandidate;
                if (!vchCryptedHDMaster.empty())
                {
                    vector<unsigned char> vchPlainHDMaster;
                    if (!DecryptSecret(vWalletMasterKey, vchCryptedHDMaster,
                                       WalletSecretIV("hdmaster"), vchPlainHDMaster) ||
                        vchPlainHDMaster.size() != 32)
                    {
                        strErrorRet = "could not decrypt HD master key";
                        return false;
                    }
                    vchHDMaster = vchPlainHDMaster;
                }
                if (!vchCryptedHDChainCode.empty())
                {
                    vector<unsigned char> vchPlainHDChainCode;
                    if (!DecryptSecret(vWalletMasterKey, vchCryptedHDChainCode,
                                       WalletSecretIV("hdchaincode"), vchPlainHDChainCode) ||
                        vchPlainHDChainCode.size() != 32)
                    {
                        strErrorRet = "could not decrypt HD chain code";
                        return false;
                    }
                    vchHDChainCode = vchPlainHDChainCode;
                }
                fWalletLocked = false;
                return true;
            }
        }
    }

    strErrorRet = "passphrase did not unlock the wallet";
    return false;
}

static bool WalletAlreadyHasKey(const vector<unsigned char>& vchPubKey)
{
    CRITICAL_BLOCK(cs_mapKeys)
        return mapKeys.count(vchPubKey) > 0 || mapCryptedKeys.count(vchPubKey) > 0;
    return false;
}

static bool AddKeyIfMissing(const CKey& key)
{
    if (WalletAlreadyHasKey(key.GetPubKey()))
        return true;
    return AddKey(key);
}

static bool DeriveNextHDReceiveKey(vector<unsigned char>& vchPubKeyRet, string& strErrorRet)
{
    vchPubKeyRet.clear();
    CRITICAL_BLOCK(cs_keyPool)
    {
        if (!HaveHDSeed())
        {
            strErrorRet = "no seed";
            return false;
        }

        CKey key;
        unsigned int nIndex = 0;
        if (nHDKeySchema == HD_SCHEMA_BIP44)
            nIndex = nHDReceiveNext;
        else
            nIndex = nHDNext;
        if (!DeriveHDKey(nIndex, key, strErrorRet))
            return false;
        if (!AddKeyIfMissing(key))
        {
            strErrorRet = "could not write the derived key to wallet.dat";
            return false;
        }

        unsigned int nNext = nIndex + 1;
        if (nHDKeySchema == HD_SCHEMA_BIP44)
        {
            if (!CWalletDB().WriteHDReceiveNext(nNext))
            {
                strErrorRet = "could not advance the receive derivation counter";
                return false;
            }
            nHDReceiveNext = nNext;
        }
        else
        {
            if (!CWalletDB().WriteHDNext(nNext))
            {
                strErrorRet = "could not advance the derivation counter";
                return false;
            }
            nHDNext = nNext;
        }

        vchPubKeyRet = key.GetPubKey();
    }
    return true;
}

static bool DeriveNextHDChangeKey(vector<unsigned char>& vchPubKeyRet, string& strErrorRet)
{
    vchPubKeyRet.clear();
    CRITICAL_BLOCK(cs_keyPool)
    {
        if (!HaveHDSeed())
        {
            strErrorRet = "no seed";
            return false;
        }

        CKey key;
        if (nHDKeySchema == HD_SCHEMA_BIP44)
        {
            if (!DeriveHDChangeKey(nHDChangeNext, key, strErrorRet))
                return false;
            if (!AddKeyIfMissing(key))
            {
                strErrorRet = "could not write the derived change key to wallet.dat";
                return false;
            }
            unsigned int nNext = nHDChangeNext + 1;
            if (!CWalletDB().WriteHDChangeNext(nNext))
            {
                strErrorRet = "could not advance the change derivation counter";
                return false;
            }
            nHDChangeNext = nNext;
        }
        else
        {
            if (!DeriveHDKey(nHDNext, key, strErrorRet))
                return false;
            if (!AddKeyIfMissing(key))
            {
                strErrorRet = "could not write the derived change key to wallet.dat";
                return false;
            }
            unsigned int nNext = nHDNext + 1;
            if (!CWalletDB().WriteHDNext(nNext))
            {
                strErrorRet = "could not advance the derivation counter";
                return false;
            }
            nHDNext = nNext;
        }
        vchPubKeyRet = key.GetPubKey();
    }
    return true;
}

vector<unsigned char> GenerateNewKey()
{
    CKey key;
    key.MakeNewKey();
    if (!AddKey(key))
        throw runtime_error("GenerateNewKey() : AddKey failed\n");
    return key.GetPubKey();
}

CCriticalSection cs_keyPool;
map<int64, vector<unsigned char> > mapKeyPool;

vector<unsigned char> vchHDMaster;
vector<unsigned char> vchHDChainCode;
unsigned int nHDNext = 0;
int nHDKeySchema = HD_SCHEMA_NONE;
unsigned int nHDReceiveNext = 0;
unsigned int nHDChangeNext = 0;
unsigned int nHDCoinType = HD_BIP44_COIN_TYPE_BITFLASH_PROVISIONAL;

string HDKeySchemaName(int nSchema)
{
    if (nSchema == HD_SCHEMA_LEGACY)
        return "legacy-hd";
    if (nSchema == HD_SCHEMA_BIP44)
        return "bip44";
    return "none";
}

std::vector<unsigned int> HDLegacyPath(unsigned int nIndex)
{
    std::vector<unsigned int> path;
    path.push_back(nIndex | bitflash::BIP32_HARDENED);
    return path;
}

std::vector<unsigned int> HDBIP44Path(unsigned int nCoinType,
                                      unsigned int nAccount,
                                      unsigned int nChain,
                                      unsigned int nIndex)
{
    std::vector<unsigned int> path;
    path.push_back(HD_BIP44_PURPOSE | bitflash::BIP32_HARDENED);
    path.push_back(nCoinType | bitflash::BIP32_HARDENED);
    path.push_back(nAccount | bitflash::BIP32_HARDENED);
    path.push_back(nChain);
    path.push_back(nIndex);
    return path;
}

static bool ClearKeyPoolRecords(string& strErrorRet)
{
    CWalletDB walletdb;
    for (map<int64, vector<unsigned char> >::const_iterator mi = mapKeyPool.begin();
         mi != mapKeyPool.end(); ++mi)
    {
        if (!walletdb.ErasePool(mi->first))
        {
            strErrorRet = strprintf("could not clear old key-pool entry %lld",
                                    (long long)mi->first);
            return false;
        }
    }
    mapKeyPool.clear();
    return true;
}

bool DeriveHDKey(unsigned int nIndex, CKey& keyRet, string& strErrorRet)
{
    if (!HaveHDSeed())
    {
        strErrorRet = "no seed";
        return false;
    }
    if (nIndex >= bitflash::BIP32_HARDENED)
    {
        strErrorRet = "child index must be non-hardened; hardening is applied here";
        return false;
    }

    bitflash::BIP32PrivateNode parent;
    parent.privateKey = vchHDMaster;
    parent.chainCode  = vchHDChainCode;

    bitflash::BIP32PrivateNode child;
    std::vector<unsigned int> path = nHDKeySchema == HD_SCHEMA_BIP44
        ? HDBIP44Path(nHDCoinType, HD_BIP44_ACCOUNT, HD_BIP44_CHAIN_RECEIVE, nIndex)
        : HDLegacyPath(nIndex);
    if (!bitflash::BIP32DerivePath(parent, path, child, strErrorRet))
        return false;

    if (!keyRet.SetSecret(child.privateKey))
    {
        strErrorRet = "derived scalar is not a usable key";
        return false;
    }
    return true;
}

bool DeriveHDChangeKey(unsigned int nIndex, CKey& keyRet, string& strErrorRet)
{
    if (!HaveHDSeed())
    {
        strErrorRet = "no seed";
        return false;
    }
    if (nIndex >= bitflash::BIP32_HARDENED)
    {
        strErrorRet = "child index must be non-hardened; hardening is applied here";
        return false;
    }

    if (nHDKeySchema != HD_SCHEMA_BIP44)
        return DeriveHDKey(nIndex, keyRet, strErrorRet);

    bitflash::BIP32PrivateNode parent;
    parent.privateKey = vchHDMaster;
    parent.chainCode  = vchHDChainCode;

    bitflash::BIP32PrivateNode child;
    if (!bitflash::BIP32DerivePath(parent,
                                   HDBIP44Path(nHDCoinType,
                                               HD_BIP44_ACCOUNT,
                                               HD_BIP44_CHAIN_CHANGE,
                                               nIndex),
                                   child,
                                   strErrorRet))
        return false;

    if (!keyRet.SetSecret(child.privateKey))
    {
        strErrorRet = "derived scalar is not a usable key";
        return false;
    }
    return true;
}

bool SetHDSeedFromMnemonic(const string& strMnemonic, string& strErrorRet)
{
    string strNormalized;
    if (!bitflash::BIP39ValidateMnemonic(strMnemonic, strNormalized, strErrorRet))
        return false;

    vector<unsigned char> vchSeed;
    if (!bitflash::BIP39MnemonicToSeed(strNormalized, "", vchSeed, strErrorRet))
        return false;

    bitflash::BIP32PrivateNode master;
    if (!bitflash::BIP32MasterFromSeed(vchSeed, master, strErrorRet))
        return false;

    CRITICAL_BLOCK(cs_keyPool)
    {
        // The pool is cleared before the seed is written, and the order is the
        // safe one of the two. Old private keys stay in wallet.dat either way;
        // what is at stake is which half-finished state a failure can leave.
        //
        //   clear, then write -- a failed write leaves the old seed and an
        //   empty pool. TopUpKeyPool refills it, and nothing was promised to
        //   anybody.
        //
        //   write, then clear -- a failed clear leaves a seed installed and the
        //   old random pool intact. The user has just been shown twelve words
        //   and the wallet goes on handing out addresses those words cannot
        //   reproduce. That is the bug this function exists to prevent.
        //
        // An earlier comment here said the seed was written first so a failure
        // left the wallet untouched. That was true of the seed alone and stops
        // being true once the pool has to move with it.
        if (!ClearKeyPoolRecords(strErrorRet))
            return false;

        if (!CWalletDB().WriteHDMaster(master.privateKey, master.chainCode) ||
            !CWalletDB().WriteHDSchema(HD_SCHEMA_BIP44) ||
            !CWalletDB().WriteHDCoinType(HD_BIP44_COIN_TYPE_BITFLASH_PROVISIONAL) ||
            !CWalletDB().WriteHDNext(0) ||
            !CWalletDB().WriteHDReceiveNext(1) ||
            !CWalletDB().WriteHDChangeNext(0))
        {
            strErrorRet = "could not write the seed metadata to wallet.dat";
            return false;
        }
        vchHDMaster    = master.privateKey;
        vchHDChainCode = master.chainCode;
        nHDKeySchema   = HD_SCHEMA_BIP44;
        nHDReceiveNext = 1;
        nHDChangeNext  = 0;
        nHDCoinType    = HD_BIP44_COIN_TYPE_BITFLASH_PROVISIONAL;

        // Index 0 is spoken for before it is derived, so a failure below cannot
        // leave the pool free to hand it out as an ordinary key. The cost of
        // the counter being ahead of the derivation is one unused index; the
        // cost of the reverse is the default address and a pool key sharing a
        // derivation path.
        nHDNext = 0;

        // Remember which address stops being the default, so it can be named
        // for what it is. Two entries reading "Your Address" -- one covered by
        // the phrase and one not -- is the wrong thing to find at the moment a
        // person has just written twelve words down.
        vector<unsigned char> vchOldDefault = keyUser.GetPubKey();

        CKey key;
        if (!DeriveHDKey(0, key, strErrorRet))
            return false;
        if (!AddKeyIfMissing(key))
        {
            strErrorRet = "could not write the default derived key to wallet.dat";
            return false;
        }
        vector<unsigned char> vchPubKey = key.GetPubKey();
        if (!CWalletDB().WriteDefaultKey(vchPubKey) ||
            !SetAddressBookName(PubKeyToAddress(vchPubKey), "Your Address"))
        {
            strErrorRet = "could not set the default derived receiving key";
            return false;
        }
        if (!vchOldDefault.empty() && vchOldDefault != vchPubKey)
            SetAddressBookName(PubKeyToAddress(vchOldDefault),
                               "Your Address (created before the recovery phrase)");
        keyUser = key;
    }
    return true;
}

void TopUpKeyPool()
{
    if (IsWalletLocked())
    {
        printf("TopUpKeyPool() : wallet is encrypted and locked\n");
        return;
    }

    CRITICAL_BLOCK(cs_keyPool)
    {
        while ((int)mapKeyPool.size() < KEYPOOL_SIZE)
        {
            // Indices only ever go up. Reusing one would mean two pool records
            // racing for the same slot after an erase.
            int64 nIndex = 1;
            if (!mapKeyPool.empty())
                nIndex = (--mapKeyPool.end())->first + 1;

            CKey key;
            if (HaveHDSeed())
            {
                // Derived, so a recovery phrase can reproduce this exact key.
                // A derivation that fails is not a reason to stop filling the
                // pool -- fall back to a random key, which is what a wallet
                // without a seed uses anyway. It will not come back from the
                // phrase, and that is better than a node that cannot mine.
                string strError;
                vector<unsigned char> vchPubKey;
                if (DeriveNextHDReceiveKey(vchPubKey, strError))
                {
                    if (!CWalletDB().WritePool(nIndex, vchPubKey))
                        return;
                    mapKeyPool[nIndex] = vchPubKey;
                    continue;
                }
                else
                {
                    printf("TopUpKeyPool() : receive derivation failed (%s), "
                           "falling back to a random key\n", strError.c_str());
                    key.MakeNewKey();
                }
            }
            else
            {
                key.MakeNewKey();
            }
            // AddKey writes the private key. Order matters: the key is in
            // wallet.dat before anything can point at it, so a crash between
            // the two writes costs an unused key, never a usable one.
            if (!AddKeyIfMissing(key))
                return;
            vector<unsigned char> vchPubKey = key.GetPubKey();
            if (!CWalletDB().WritePool(nIndex, vchPubKey))
                return;
            mapKeyPool[nIndex] = vchPubKey;
        }
    }
}

vector<unsigned char> GetKeyFromPool()
{
    if (IsWalletLocked())
    {
        printf("GetKeyFromPool() : wallet is encrypted and locked\n");
        return vector<unsigned char>();
    }

    CRITICAL_BLOCK(cs_keyPool)
    {
        TopUpKeyPool();
        if (!mapKeyPool.empty())
        {
            map<int64, vector<unsigned char> >::iterator mi = mapKeyPool.begin();
            int64 nIndex = mi->first;
            vector<unsigned char> vchPubKey = mi->second;
            mapKeyPool.erase(mi);
            CWalletDB().ErasePool(nIndex);
            // Leave the wallet with a full backup window after each draw too,
            // not only immediately before a draw. If topping up fails, the key
            // already chosen is still safe to use -- its private half was
            // written before it entered the pool.
            TopUpKeyPool();
            return vchPubKey;
        }
    }
    // Nothing in the pool and nothing could be added -- disk full, wallet
    // locked open elsewhere. Generating on demand is what this code did for
    // its whole life, so fall back to it rather than refuse to mine.
    printf("GetKeyFromPool() : pool empty, generating a key on demand\n");
    try
    {
        return GenerateNewKey();
    }
    catch (const std::exception& e)
    {
        printf("GetKeyFromPool() : failed to generate a key: %s\n", e.what());
        return vector<unsigned char>();
    }
}




//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//

bool AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    CRITICAL_BLOCK(cs_mapWallet)
    {
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
            wtx.nTimeReceived = GetAdjustedTime();

        //// debug print
        if (LogAcceptsCategory("net")) printf("AddToWallet %s  %s\n", wtxIn.GetHash().ToString().substr(0,6).c_str(), fInsertedNew ? "new" : "update");

        if (!fInsertedNew)
        {
            // Merge
            bool fUpdated = false;
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            if (wtxIn.fSpent && wtxIn.fSpent != wtx.fSpent)
            {
                wtx.fSpent = wtxIn.fSpent;
                fUpdated = true;
            }
            if (!fUpdated)
                return true;
        }

        // Write to disk
        if (!wtx.WriteToDisk())
            return false;

        // Notify UI
        vWalletUpdated.push_back(make_pair(hash, fInsertedNew));
    }

    // Refresh UI
    MainFrameRepaint();
    return true;
}

bool AddToWalletIfMine(const CTransaction& tx, const CBlock* pblock)
{
    if (tx.IsMine() || mapWallet.count(tx.GetHash()))
    {
        CWalletTx wtx(tx);
        // Get merkle branch if transaction was found in a block
        if (pblock)
            wtx.SetMerkleBranch(pblock);
        return AddToWallet(wtx);
    }
    return true;
}

bool CanScanWalletTransactions(string& strErrorRet)
{
    strErrorRet.clear();

    if (pindexGenesisBlock == NULL || pindexBest == NULL || hashBestChain == 0 || nBestHeight < 0)
    {
        strErrorRet = "The block index is not loaded, so the wallet scan cannot "
                      "prove whether imported or restored keys own coins.";
        return false;
    }

    if (nBestHeight == 0)
    {
        strErrorRet = "The local chain is only at height 0. A wallet scan would "
                      "inspect only the genesis block and could incorrectly "
                      "report zero transactions. Start the node and let it sync "
                      "before scanning. If this happened after copying a data "
                      "directory, keep wallet.dat safe and rebuild or re-download "
                      "the block data instead of trusting the copied database/ "
                      "environment.";
        return false;
    }

    return true;
}

int ScanForWalletTransactions(CBlockIndex* pindexStart)
{
    // Walk the chain looking for transactions that belong to keys this wallet
    // holds now, whatever it held when those blocks arrived.
    //
    // Nothing in this tree could do that. A key added after the fact -- from
    // /importwallet, or from a backup restored onto a node that had since
    // moved on -- was simply invisible: the coins were on the chain, the
    // private key was in wallet.dat, and the balance did not show them,
    // because a transaction only ever entered the wallet at the moment its
    // block arrived over the network.
    //
    // Bitcoin grew the same function for the same reason. It is also what any
    // recovery-phrase feature has to stand on: deriving the keys is the easy
    // half, and without this the other half does not exist.
    int nFound = 0;
    int nScanned = 0;
    CBlockIndex* pindex = pindexStart;
    CRITICAL_BLOCK(cs_main)
    {
        while (pindex)
        {
            CBlock block;
            if (block.ReadFromDisk(pindex, true))
            {
                foreach(CTransaction& tx, block.vtx)
                {
                    // Ask before handing it over: AddToWalletIfMine returns
                    // true for a transaction that is none of our business, so
                    // its return value cannot be counted.
                    if (tx.IsMine())
                    {
                        if (AddToWalletIfMine(tx, &block))
                            nFound++;
                    }
                }
            }
            nScanned++;
            if ((nScanned % 500) == 0)
                printf("ScanForWalletTransactions() : %d blocks scanned, %d transaction(s) found\n",
                       nScanned, nFound);
            pindex = pindex->pnext;
        }
    }
    printf("ScanForWalletTransactions() : %d block(s) scanned, %d transaction(s) added or updated\n",
           nScanned, nFound);
    return nFound;
}

bool EraseFromWallet(uint256 hash)
{
    CRITICAL_BLOCK(cs_mapWallet)
    {
        if (mapWallet.erase(hash))
            CWalletDB().EraseTx(hash);
    }
    return true;
}









//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

void AddOrphanTx(const CDataStream& vMsg)
{
    CTransaction tx;
    CDataStream(vMsg) >> tx;
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return;

    // Do not allow an orphan to have an unbounded number of inputs.
    // 10,000 inputs is enough for massive legitimate sweeps, but bounds the total
    // memory in mapOrphanTransactionsByPrev to ~10,000 * MAX_ORPHAN_TRANSACTIONS.
    if (tx.vin.size() > 10000)
    {
        if (LogAcceptsCategory("net")) printf("AddOrphanTx() : orphan with %d inputs rejected\n", (int)tx.vin.size());
        return;
    }

    CDataStream* pvMsg = mapOrphanTransactions[hash] = new CDataStream(vMsg);
    foreach(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev.insert(make_pair(txin.prevout.hash, pvMsg));
    LimitOrphanTx(MAX_ORPHAN_TRANSACTIONS);
}

// Orphans cost nothing to create -- a transaction naming a parent that does
// not exist is never validated, just held -- so without a ceiling any peer can
// grow this map until the node runs out of memory. Evict at random rather than
// in map order, so an attacker cannot keep its own orphans resident by
// choosing hashes that sort low.
// Drop orphan blocks at random until we are back under the ceiling.
//
// Random rather than oldest-first, matching LimitOrphanTx below: there is no
// arrival order recorded, and an attacker who knew the eviction rule could aim
// at it. Dropping one costs nothing that matters -- if its parent ever shows
// up, the block is requested again like any other.
//
// Both maps have to be kept in step, and the CBlock itself has to be deleted:
// mapOrphanBlocks owns it.
void LimitOrphanBlocks(unsigned int nMaxOrphans)
{
    while (mapOrphanBlocks.size() > nMaxOrphans)
    {
        uint256 randomhash;
        for (int i = 0; i < 4; i++)
            ((uint64*)&randomhash)[i] = GetRand(_UI64_MAX);
        map<uint256, CBlock*>::iterator it = mapOrphanBlocks.lower_bound(randomhash);
        if (it == mapOrphanBlocks.end())
            it = mapOrphanBlocks.begin();

        CBlock* pblock = it->second;
        uint256 hashPrev = pblock->hashPrevBlock;

        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);)
        {
            if (mi->second == pblock)
                mapOrphanBlocksByPrev.erase(mi++);
            else
                ++mi;
        }

        mapOrphanBlocks.erase(it);
        delete pblock;
    }
}

void LimitOrphanTx(unsigned int nMaxOrphans)
{
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        uint256 randomhash;
        for (int i = 0; i < 4; i++)
            ((uint64*)&randomhash)[i] = GetRand(_UI64_MAX);
        map<uint256, CDataStream*>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
    }
}

void EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CDataStream* pvMsg = mapOrphanTransactions[hash];
    CTransaction tx;
    CDataStream(*pvMsg) >> tx;
    foreach(const CTxIn& txin, tx.vin)
    {
        for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(txin.prevout.hash);
             mi != mapOrphanTransactionsByPrev.upper_bound(txin.prevout.hash);)
        {
            if ((*mi).second == pvMsg)
                mapOrphanTransactionsByPrev.erase(mi++);
            else
                mi++;
        }
    }
    delete pvMsg;
    mapOrphanTransactions.erase(hash);
}








//////////////////////////////////////////////////////////////////////////////
//
// CTransaction
//

bool CTxIn::IsMine() const
{
    CRITICAL_BLOCK(cs_mapWallet)
    {
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (prevout.n < prev.vout.size())
                if (prev.vout[prevout.n].IsMine())
                    return true;
        }
    }
    return false;
}

int64 CTxIn::GetDebit() const
{
    CRITICAL_BLOCK(cs_mapWallet)
    {
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (prevout.n < prev.vout.size())
                if (prev.vout[prevout.n].IsMine())
                    return prev.vout[prevout.n].nValue;
        }
    }
    return 0;
}

int64 CWalletTx::GetTxTime() const
{
    if (!fTimeReceivedIsTxTime && hashBlock != 0)
    {
        // If we did not receive the transaction directly, we rely on the block's
        // time to figure out when it happened.  We use the median over a range
        // of blocks to try to filter out inaccurate block times.
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* pindex = (*mi).second;
            if (pindex)
                return pindex->GetMedianTime();
        }
    }
    return nTimeReceived;
}






int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    if (fClient)
    {
        if (hashBlock == 0)
            return 0;
    }
    else
    {
        CBlock blockTmp;
        if (pblock == NULL)
        {
            // Load the block this tx is in
            CTxIndex txindex;
            if (!CTxDB("r").ReadTxIndex(GetHash(), txindex))
                return 0;
            if (!blockTmp.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, true))
                return 0;
            pblock = &blockTmp;
        }

        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < pblock->vtx.size(); nIndex++)
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == pblock->vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            if (LogAcceptsCategory("net")) printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}



void CWalletTx::AddSupportingTransactions(CTxDB& txdb)
{
    vtxPrev.clear();

    const int COPY_DEPTH = 3;
    if (SetMerkleBranch() < COPY_DEPTH)
    {
        vector<uint256> vWorkQueue;
        foreach(const CTxIn& txin, vin)
            vWorkQueue.push_back(txin.prevout.hash);

        // This critsect is OK because txdb is already open
        CRITICAL_BLOCK(cs_mapWallet)
        {
            map<uint256, const CMerkleTx*> mapWalletPrev;
            set<uint256> setAlreadyDone;
            for (int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hash = vWorkQueue[i];
                if (setAlreadyDone.count(hash))
                    continue;
                setAlreadyDone.insert(hash);

                CMerkleTx tx;
                if (mapWallet.count(hash))
                {
                    tx = mapWallet[hash];
                    foreach(const CMerkleTx& txWalletPrev, mapWallet[hash].vtxPrev)
                        mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
                }
                else if (mapWalletPrev.count(hash))
                {
                    tx = *mapWalletPrev[hash];
                }
                else if (!fClient && txdb.ReadDiskTx(hash, tx))
                {
                    ;
                }
                else
                {
                    if (LogAcceptsCategory("net")) printf("ERROR: AddSupportingTransactions() : unsupported transaction\n");
                    continue;
                }

                int nDepth = tx.SetMerkleBranch();
                vtxPrev.push_back(tx);

                if (nDepth < COPY_DEPTH)
                    foreach(const CTxIn& txin, tx.vin)
                        vWorkQueue.push_back(txin.prevout.hash);
            }
        }
    }

    reverse(vtxPrev.begin(), vtxPrev.end());
}











bool CTransaction::AcceptTransaction(CTxDB& txdb, bool fCheckInputs, bool* pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    // Coinbase is only valid in a block, not as a loose transaction
    if (IsCoinBase())
        return error("AcceptTransaction() : coinbase as individual tx");

    if (!CheckTransaction())
        return error("AcceptTransaction() : CheckTransaction failed");

    // Do we already have it?
    uint256 hash = GetHash();
    CRITICAL_BLOCK(cs_mapTransactions)
        if (mapTransactions.count(hash))
            return false;
    if (fCheckInputs)
        if (txdb.ContainsTx(hash))
            return false;

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    for (int i = 0; i < vin.size(); i++)
    {
        COutPoint outpoint = vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Allow replacing with a newer version of the same transaction
            if (i != 0)
                return false;
            ptxOld = mapNextTx[outpoint].ptx;
            if (!IsNewerThan(*ptxOld))
                return false;
            for (int i = 0; i < vin.size(); i++)
            {
                COutPoint outpoint = vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
                    return false;
            }
            break;
        }
    }

    // Check against previous transactions
    map<uint256, CTxIndex> mapUnused;
    int64 nFees = 0;
    if (fCheckInputs && !ConnectInputs(txdb, mapUnused, CDiskTxPos(1,1,1), 0, nFees, false, false))
    {
        if (pfMissingInputs)
            *pfMissingInputs = true;
        return error("AcceptTransaction() : ConnectInputs failed %s", hash.ToString().substr(0,6).c_str());
    }

    // Store transaction in memory
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        if (ptxOld)
        {
            if (LogAcceptsCategory("net")) printf("mapTransaction.erase(%s) replacing with new version\n", ptxOld->GetHash().ToString().c_str());
            mapTransactions.erase(ptxOld->GetHash());
        }
        AddToMemoryPool();
    }

    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    if (ptxOld)
        EraseFromWallet(ptxOld->GetHash());

    if (LogAcceptsCategory("net")) printf("AcceptTransaction(): accepted %s\n", hash.ToString().substr(0,6).c_str());
    return true;
}


bool CTransaction::AddToMemoryPool()
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call AcceptTransaction to properly check the transaction first.
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        uint256 hash = GetHash();
        mapTransactions[hash] = *this;
        for (int i = 0; i < vin.size(); i++)
            mapNextTx[vin[i].prevout] = CInPoint(&mapTransactions[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}


bool CTransaction::RemoveFromMemoryPool()
{
    // Remove transaction from memory pool
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        foreach(const CTxIn& txin, vin)
            mapNextTx.erase(txin.prevout);
        mapTransactions.erase(GetHash());
        nTransactionsUpdated++;
    }
    return true;
}






int CMerkleTx::GetDepthInMainChain() const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    return pindexBest->nHeight - pindex->nHeight + 1;
}


int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;
    return max(0, (COINBASE_MATURITY+20) - GetDepthInMainChain());
}


bool CMerkleTx::AcceptTransaction(CTxDB& txdb, bool fCheckInputs)
{
    if (fClient)
    {
        if (!IsInMainChain() && !ClientConnectInputs())
            return false;
        return CTransaction::AcceptTransaction(txdb, false);
    }
    else
    {
        return CTransaction::AcceptTransaction(txdb, fCheckInputs);
    }
}



bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs)
{
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        foreach(CMerkleTx& tx, vtxPrev)
        {
            if (!tx.IsCoinBase())
            {
                uint256 hash = tx.GetHash();
                if (!mapTransactions.count(hash) && !txdb.ContainsTx(hash))
                    tx.AcceptTransaction(txdb, fCheckInputs);
            }
        }
        if (!IsCoinBase())
            return AcceptTransaction(txdb, fCheckInputs);
    }
    return true;
}

int RescanSpentFlags()
{
    // Believe the chain, not the wallet, about what has already been spent.
    //
    // fSpent lives in wallet.dat and is written when this node spends
    // something. A wallet.dat that was restored from backup, or copied and
    // used on another machine, carries whatever that flag was at the moment
    // the copy was taken -- so it can say "unspent" about coins the chain
    // shows as gone. The balance then reads high, and the error only surfaces
    // when a send is attempted against coins that no longer exist.
    //
    // Issue #47 is about this shape of problem and #40 reports living through
    // it. Bitcoin fixed the same thing in 53d508072.
    //
    // One direction only. Marking spent when the chain says spent is safe;
    // clearing the flag because the chain has not caught up yet would offer
    // up coins that are already on their way out.
    CTxDB txdb("r");
    int nCorrected = 0;
    int nExamined = 0;
    int nAlreadySpent = 0, nNotIndexed = 0;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        foreach(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            nExamined++;
            if (wtx.fSpent)
                { nAlreadySpent++; continue; }

            CTxIndex txindex;
            if (!txdb.ReadTxIndex(wtx.GetHash(), txindex))
                { nNotIndexed++; continue; }

            // fSpent is one flag for the whole transaction, not one per
            // output -- CommitTransactionSpent already marks the entire
            // previous transaction when it spends any part of it, so matching
            // that here keeps the two consistent.
            bool fSeenSpent = false;
            for (int i = 0; i < (int)txindex.vSpent.size() && i < (int)wtx.vout.size(); i++)
                if (!txindex.vSpent[i].IsNull() && wtx.vout[i].IsMine())
                    fSeenSpent = true;

            if (fSeenSpent)
            {
                wtx.fSpent = true;
                wtx.WriteToDisk();
                nCorrected++;
                printf("RescanSpentFlags() : %s was spent on chain but the wallet did not know\n",
                       wtx.GetHash().ToString().substr(0,10).c_str());
            }
        }
    }
    // Always say it ran. A check that reports only when it finds something is
    // indistinguishable from a check that never executed, and this codebase has
    // paid for that confusion more than once.
    printf("RescanSpentFlags() : examined %d, already-spent %d, not-indexed %d, corrected %d\n",
           nExamined, nAlreadySpent, nNotIndexed, nCorrected);
    if (nCorrected)
        printf("RescanSpentFlags() : this wallet was behind the chain about what it had already spent, "
               "which is what a restored backup looks like\n");
    return nCorrected;
}


void ReacceptWalletTransactions()
{
    // Reaccept any txes of ours that aren't already in a block
    CTxDB txdb("r");
    CRITICAL_BLOCK(cs_mapWallet)
    {
        foreach(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            if (!wtx.IsCoinBase() && !txdb.ContainsTx(wtx.GetHash()))
                wtx.AcceptWalletTransaction(txdb, false);
        }
    }
}


void CWalletTx::RelayWalletTransaction(CTxDB& txdb)
{
    foreach(const CMerkleTx& tx, vtxPrev)
    {
        if (!tx.IsCoinBase())
        {
            uint256 hash = tx.GetHash();
            if (!txdb.ContainsTx(hash))
                RelayMessage(CInv(MSG_TX, hash), (CTransaction)tx);
        }
    }
    if (!IsCoinBase())
    {
        uint256 hash = GetHash();
        if (!txdb.ContainsTx(hash))
        {
            if (LogAcceptsCategory("net")) printf("Relaying wtx %s\n", hash.ToString().substr(0,6).c_str());
            RelayMessage(CInv(MSG_TX, hash), (CTransaction)*this);
        }
    }
}

void RelayWalletTransactions()
{
    static int64 nLastTime;
    if (GetTime() - nLastTime < 10 * 60)
        return;
    nLastTime = GetTime();

    // Rebroadcast any of our txes that aren't in a block yet
    if (LogAcceptsCategory("net")) printf("RelayWalletTransactions()\n");
    CTxDB txdb("r");
    CRITICAL_BLOCK(cs_mapWallet)
    {
        // Sort them in chronological order
        multimap<unsigned int, CWalletTx*> mapSorted;
        foreach(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
        }
        foreach(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
        {
            CWalletTx& wtx = *item.second;
            wtx.RelayWalletTransaction(txdb);
        }
    }
}










//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

bool CBlock::ReadFromDisk(const CBlockIndex* pblockindex, bool fReadTransactions)
{
    return ReadFromDisk(pblockindex->nFile, pblockindex->nBlockPos, fReadTransactions);
}

uint256 GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

int64 CBlock::GetBlockValue(int nHeight, int64 nFees) const
{
    int64 nSubsidy = 50 * COIN;

    // Halve on the height of this block, never on nBestHeight. The subsidy a
    // block is allowed to pay is a property of that block; deriving it from
    // the validating node's own tip makes the answer depend on how far that
    // node happens to have synced, so two nodes at different heights would
    // disagree about the same block across a halving boundary.
    nSubsidy >>= (nHeight / 210000);

    return nSubsidy + nFees;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast)
{
    // Bitflash: 2-minute target block time with a fast retarget (every 30
    // blocks, ~1h) so difficulty tracks the small, volatile CPU hashrate and
    // brief disconnections no longer spawn divergent forks.
    const unsigned int nTargetSpacing  = 2 * 60;                    // 2 minutes
    const unsigned int nInterval       = 30;                        // retarget window
    const unsigned int nTargetTimespan = nInterval * nTargetSpacing; // 3600s

    // Genesis block
    if (pindexLast == NULL)
        return bnProofOfWorkLimit.GetCompact();

    // Only change once per interval
    if ((pindexLast->nHeight+1) % nInterval != 0)
        return pindexLast->nBits;

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < nInterval-1; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    // Limit adjustment step
    unsigned int nActualTimespan = pindexLast->nTime - pindexFirst->nTime;
    if (LogAcceptsCategory("net")) printf("  nActualTimespan = %d  before bounds\n", nActualTimespan);
    if (nActualTimespan < nTargetTimespan/4)
        nActualTimespan = nTargetTimespan/4;
    if (nActualTimespan > nTargetTimespan*4)
        nActualTimespan = nTargetTimespan*4;

    // Retarget
    CBigNum bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnProofOfWorkLimit)
        bnNew = bnProofOfWorkLimit;

    /// debug print
    if (LogAcceptsCategory("net")) { printf("\n\n\nGetNextWorkRequired RETARGET *****\n"); printf("nTargetTimespan = %d    nActualTimespan = %d\n", nTargetTimespan, nActualTimespan); printf("Before: %08x  %s\n", pindexLast->nBits, CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str()); printf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str()); }

    return bnNew.GetCompact();
}









bool CTransaction::DisconnectInputs(CTxDB& txdb)
{
    // Relinquish previous transactions' spent pointers
    if (!IsCoinBase())
    {
        foreach(const CTxIn& txin, vin)
        {
            COutPoint prevout = txin.prevout;

            // Get prev txindex from disk
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : ReadTxIndex failed");

            if (prevout.n >= txindex.vSpent.size())
                return error("DisconnectInputs() : prevout.n out of range");

            // Mark outpoint as not spent
            txindex.vSpent[prevout.n].SetNull();

            // Write back
            txdb.UpdateTxIndex(prevout.hash, txindex);
        }
    }

    // Remove transaction from index
    if (!txdb.EraseTxIndex(*this))
        return error("DisconnectInputs() : EraseTxPos failed");

    return true;
}


bool CTransaction::ConnectInputs(CTxDB& txdb, map<uint256, CTxIndex>& mapTestPool, CDiskTxPos posThisTx, int nHeight, int64& nFees, bool fBlock, bool fMiner, int64 nMinFee)
{
    // Take over previous transactions' spent pointers
    if (!IsCoinBase())
    {
        int64 nValueIn = 0;
        for (int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;

            // Read txindex
            CTxIndex txindex;
            bool fFound = true;
            if (fMiner && mapTestPool.count(prevout.hash))
            {
                // Get txindex from current proposed changes
                txindex = mapTestPool[prevout.hash];
            }
            else
            {
                // Read txindex from txdb
                fFound = txdb.ReadTxIndex(prevout.hash, txindex);
            }
            if (!fFound && (fBlock || fMiner))
                return fMiner ? false : error("ConnectInputs() : %s prev tx %s index entry not found", GetHash().ToString().substr(0,6).c_str(),  prevout.hash.ToString().substr(0,6).c_str());

            // Read txPrev
            CTransaction txPrev;
            if (!fFound || txindex.pos == CDiskTxPos(1,1,1))
            {
                // Get prev tx from single transactions in memory
                CRITICAL_BLOCK(cs_mapTransactions)
                {
                    if (!mapTransactions.count(prevout.hash))
                        return error("ConnectInputs() : %s mapTransactions prev not found %s", GetHash().ToString().substr(0,6).c_str(),  prevout.hash.ToString().substr(0,6).c_str());
                    txPrev = mapTransactions[prevout.hash];
                }
                if (!fFound)
                    txindex.vSpent.resize(txPrev.vout.size());
            }
            else
            {
                // Get prev tx from disk
                if (!txPrev.ReadFromDisk(txindex.pos))
                    return error("ConnectInputs() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,6).c_str(),  prevout.hash.ToString().substr(0,6).c_str());
            }

            if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
                return error("ConnectInputs() : %s prevout.n out of range %d %d %d", GetHash().ToString().substr(0,6).c_str(), prevout.n, (int)txPrev.vout.size(), (int)txindex.vSpent.size());

            // If prev is coinbase, check that it's matured
            if (txPrev.IsCoinBase())
                for (CBlockIndex* pindex = pindexBest; pindex && nBestHeight - pindex->nHeight < COINBASE_MATURITY-1; pindex = pindex->pprev)
                    if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
                        return error("ConnectInputs() : tried to spend coinbase at depth %d", nBestHeight - pindex->nHeight);

            // Verify signature
            if (!VerifySignature(txPrev, *this, i))
                return error("ConnectInputs() : %s VerifySignature failed", GetHash().ToString().substr(0,6).c_str());

            // Check for conflicts
            if (!txindex.vSpent[prevout.n].IsNull())
                return fMiner ? false : error("ConnectInputs() : %s prev tx already used at %s", GetHash().ToString().substr(0,6).c_str(), txindex.vSpent[prevout.n].ToString().c_str());

            // Mark outpoints as spent
            txindex.vSpent[prevout.n] = posThisTx;

            // Write back
            if (fBlock)
                txdb.UpdateTxIndex(prevout.hash, txindex);
            else if (fMiner)
                mapTestPool[prevout.hash] = txindex;

            nValueIn += txPrev.vout[prevout.n].nValue;
            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return error("ConnectInputs() : txin values out of range");
        }

        // Tally transaction fees
        int64 nTxFee = nValueIn - GetValueOut();
        if (nTxFee < 0)
            return error("ConnectInputs() : %s nTxFee < 0", GetHash().ToString().substr(0,6).c_str());
        if (nTxFee < nMinFee)
            return false;
        nFees += nTxFee;
        if (!MoneyRange(nFees))
            return error("ConnectInputs() : nFees out of range");
    }

    if (fBlock)
    {
        // Add transaction to disk index
        if (!txdb.AddTxIndex(*this, posThisTx, nHeight))
            return error("ConnectInputs() : AddTxPos failed");
    }
    else if (fMiner)
    {
        // Add transaction to test pool
        mapTestPool[GetHash()] = CTxIndex(CDiskTxPos(1,1,1), vout.size());
    }

    return true;
}


bool CTransaction::ClientConnectInputs()
{
    if (IsCoinBase())
        return false;

    // Take over previous transactions' spent pointers
    CRITICAL_BLOCK(cs_mapTransactions)
    {
        int64 nValueIn = 0;
        for (int i = 0; i < vin.size(); i++)
        {
            // Get prev tx from single transactions in memory
            COutPoint prevout = vin[i].prevout;
            if (!mapTransactions.count(prevout.hash))
                return false;
            CTransaction& txPrev = mapTransactions[prevout.hash];

            if (prevout.n >= txPrev.vout.size())
                return false;

            // Verify signature
            if (!VerifySignature(txPrev, *this, i))
                return error("ConnectInputs() : VerifySignature failed");

            ///// this is redundant with the mapNextTx stuff, not sure which I want to get rid of
            ///// this has to go away now that posNext is gone
            // // Check for conflicts
            // if (!txPrev.vout[prevout.n].posNext.IsNull())
            //     return error("ConnectInputs() : prev tx already used");
            //
            // // Flag outpoints as used
            // txPrev.vout[prevout.n].posNext = posThisTx;

            nValueIn += txPrev.vout[prevout.n].nValue;
        }
        if (GetValueOut() > nValueIn)
            return false;
    }

    return true;
}




bool CBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
    // Disconnect in reverse order
    for (int i = vtx.size()-1; i >= 0; i--)
        if (!vtx[i].DisconnectInputs(txdb))
            return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = 0;
        txdb.WriteBlockIndex(blockindexPrev);
    }

    return true;
}

bool CBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
    //// issue here: it doesn't know the version
    unsigned int nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK) - 1 + GetSizeOfCompactSize(vtx.size());

    map<uint256, CTxIndex> mapUnused;
    int64 nFees = 0;
    foreach(CTransaction& tx, vtx)
    {
        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        nTxPos += ::GetSerializeSize(tx, SER_DISK);

        if (!tx.ConnectInputs(txdb, mapUnused, posThisTx, pindex->nHeight, nFees, true, false))
            return false;
    }

    if (vtx[0].GetValueOut() > GetBlockValue(pindex->nHeight, nFees))
        return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        txdb.WriteBlockIndex(blockindexPrev);
    }

    // Watch for transactions paying to me
    foreach(CTransaction& tx, vtx)
        AddToWalletIfMine(tx, this);

    return true;
}



bool Reorganize(CTxDB& txdb, CBlockIndex* pindexNew)
{
    LogPrint("net", "*** REORGANIZE ***\n");

    // Find the fork
    CBlockIndex* pfork = pindexBest;
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger)
    {
        if (!(pfork = pfork->pprev))
            return error("Reorganize() : pfork->pprev is null");
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev))
                return error("Reorganize() : plonger->pprev is null");
    }

    // List of what to disconnect
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    // Disconnect shorter branch
    vector<CTransaction> vResurrect;
    foreach(CBlockIndex* pindex, vDisconnect)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex->nFile, pindex->nBlockPos, true))
            return error("Reorganize() : ReadFromDisk for disconnect failed");
        if (!block.DisconnectBlock(txdb, pindex))
            return error("Reorganize() : DisconnectBlock failed");

        // Queue memory transactions to resurrect
        foreach(const CTransaction& tx, block.vtx)
            if (!tx.IsCoinBase())
                vResurrect.push_back(tx);
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    for (int i = 0; i < vConnect.size(); i++)
    {
        CBlockIndex* pindex = vConnect[i];
        CBlock block;
        if (!block.ReadFromDisk(pindex->nFile, pindex->nBlockPos, true))
            return error("Reorganize() : ReadFromDisk for connect failed");
        if (!block.ConnectBlock(txdb, pindex))
        {
            // Invalid block, delete the rest of this branch
            txdb.TxnAbort();
            for (int j = i; j < vConnect.size(); j++)
            {
                CBlockIndex* pindex = vConnect[j];
                pindex->EraseBlockFromDisk();
                txdb.EraseBlockIndex(pindex->GetBlockHash());
                mapBlockIndex.erase(pindex->GetBlockHash());
                delete pindex;
            }
            return error("Reorganize() : ConnectBlock failed");
        }

        // Queue memory transactions to delete
        foreach(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
    }
    if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        return error("Reorganize() : WriteHashBestChain failed");

    // Commit now because resurrecting could take some time
    txdb.TxnCommit();

    // Disconnect shorter branch
    foreach(CBlockIndex* pindex, vDisconnect)
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;

    // Connect longer branch
    foreach(CBlockIndex* pindex, vConnect)
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;

    // Resurrect memory transactions that were in the disconnected branch
    foreach(CTransaction& tx, vResurrect)
        tx.AcceptTransaction(txdb, false);

    // Delete redundant memory transactions that are in the connected branch
    foreach(CTransaction& tx, vDelete)
        tx.RemoveFromMemoryPool();

    return true;
}


bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,14).c_str());

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos, *this);
    if (!pindexNew)
        return error("AddToBlockIndex() : new CBlockIndex failed");
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }

    CTxDB txdb;
    txdb.TxnBegin();
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));

    // New best
    if (pindexNew->nHeight > nBestHeight)
    {
        if (pindexGenesisBlock == NULL && hash == hashGenesisBlock)
        {
            pindexGenesisBlock = pindexNew;
            txdb.WriteHashBestChain(hash);
        }
        else if (hashPrevBlock == hashBestChain)
        {
            // Adding to current best branch
            if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash))
            {
                txdb.TxnAbort();
                pindexNew->EraseBlockFromDisk();
                mapBlockIndex.erase(pindexNew->GetBlockHash());
                delete pindexNew;
                return error("AddToBlockIndex() : ConnectBlock failed");
            }
            txdb.TxnCommit();
            pindexNew->pprev->pnext = pindexNew;

            // Delete redundant memory transactions
            foreach(CTransaction& tx, vtx)
                tx.RemoveFromMemoryPool();
        }
        else
        {
            // New best branch
            if (!Reorganize(txdb, pindexNew))
            {
                txdb.TxnAbort();
                return error("AddToBlockIndex() : Reorganize failed");
            }
        }

        // New best link
        hashBestChain = hash;
        pindexBest = pindexNew;
        nBestHeight = pindexBest->nHeight;
        nTransactionsUpdated++;
        printf("AddToBlockIndex: new best=%s  height=%d\n", hashBestChain.ToString().substr(0,14).c_str(), nBestHeight);
    }

    txdb.TxnCommit();
    txdb.Close();

    // Relay wallet transactions that haven't gotten in yet
    if (pindexNew == pindexBest)
        RelayWalletTransactions();

    MainFrameRepaint();
    return true;
}




bool CBlock::CheckBlock() const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    // Size limits
    if (!CheckSizeLimits())
        return error("CheckBlock() : size limits failed");

    // Check timestamp
    if (nTime > GetAdjustedTime() + 2 * 60 * 60)
        return error("CheckBlock() : block timestamp too far in the future");

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return error("CheckBlock() : first tx is not coinbase");
    for (int i = 1; i < vtx.size(); i++)
        if (vtx[i].IsCoinBase())
            return error("CheckBlock() : more than one coinbase");

    // Check transactions
    foreach(const CTransaction& tx, vtx)
        if (!tx.CheckTransaction())
            return error("CheckBlock() : CheckTransaction failed");

    // Cap the work a block can demand. MAX_SIZE bounds the bytes, not the cost:
    // every signature operation is an elliptic-curve verification, and at this
    // chain's difficulty a block packed with them is affordable to mine and
    // expensive for everyone else to reject.
    unsigned int nSigOps = 0;
    foreach(const CTransaction& tx, vtx)
        nSigOps += tx.GetSigOpCount();
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return error("CheckBlock() : out-of-bounds signature operation count");

    // Reject blocks carrying the same transaction twice (CVE-2012-2459).
    //
    // BuildMerkleTree duplicates the last hash when a level has an odd width,
    // so appending a copy of the trailing transaction(s) yields a block with
    // an identical merkle root -- and therefore an identical block hash -- to
    // a legitimate one. The forgery fails validation, the hash gets recorded
    // as bad, and the real block is then refused because it hashes the same.
    set<uint256> setTxHashes;
    foreach(const CTransaction& tx, vtx)
    {
        uint256 hashTx = tx.GetHash();
        if (setTxHashes.count(hashTx))
            return error("CheckBlock() : duplicate transaction in block");
        setTxHashes.insert(hashTx);
    }

    // Check proof of work matches claimed amount (memory-hard RandomX PoW)
    if (CBigNum().SetCompact(nBits) > bnProofOfWorkLimit)
        return error("CheckBlock() : nBits below minimum work");
    if (GetPoWHash() > CBigNum().SetCompact(nBits).getuint256())
        return error("CheckBlock() : RandomX proof-of-work does not match nBits");

    // Check merkleroot
    if (hashMerkleRoot != BuildMerkleTree())
        return error("CheckBlock() : hashMerkleRoot mismatch");

    return true;
}

bool CBlock::AcceptBlock()
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AcceptBlock() : block already in mapBlockIndex");

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return error("AcceptBlock() : prev block not found");
    CBlockIndex* pindexPrev = (*mi).second;

    // Check timestamp against prev
    if (nTime <= pindexPrev->GetMedianTimePast())
        return error("AcceptBlock() : block's timestamp is too early");

    // Check proof of work
    if (nBits != GetNextWorkRequired(pindexPrev))
        return error("AcceptBlock() : incorrect proof of work");

    // Write block to history file
    unsigned int nFile;
    unsigned int nBlockPos;
    if (!WriteToDisk(!fClient, nFile, nBlockPos))
        return error("AcceptBlock() : WriteToDisk failed");
    if (!AddToBlockIndex(nFile, nBlockPos))
        return error("AcceptBlock() : AddToBlockIndex failed");

    if (hashBestChain == hash)
        RelayInventory(CInv(MSG_BLOCK, hash));

    // // Add atoms to user reviews for coins created
    // vector<unsigned char> vchPubKey;
    // if (ExtractPubKey(vtx[0].vout[0].scriptPubKey, false, vchPubKey))
    // {
    //     unsigned short nAtom = GetRand(USHRT_MAX - 100) + 100;
    //     vector<unsigned short> vAtoms(1, nAtom);
    //     AddAtomsAndPropagate(Hash(vchPubKey.begin(), vchPubKey.end()), vAtoms, true);
    // }

    return true;
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
    // Counted before any check, so the ratio below is against everything that
    // arrived rather than everything that was any good.
    if (pfrom)
        nBlocksReceived++;

    // Check for duplicate
    uint256 hash = pblock->GetHash();
    if (mapBlockIndex.count(hash))
        return error("ProcessBlock() : already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToString().substr(0,14).c_str());
    if (mapOrphanBlocks.count(hash))
        return error("ProcessBlock() : already have block (orphan) %s", hash.ToString().substr(0,14).c_str());

    // Preliminary checks
    if (!pblock->CheckBlock())
    {
        delete pblock;
        return error("ProcessBlock() : CheckBlock FAILED");
    }

    // If don't already have its previous block, shunt it off to holding area until we get it
    if (!mapBlockIndex.count(pblock->hashPrevBlock))
    {
        printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().substr(0,14).c_str());
        if (pfrom)
            nBlocksWithoutParent++;
        mapOrphanBlocks.insert(make_pair(hash, pblock));
        mapOrphanBlocksByPrev.insert(make_pair(pblock->hashPrevBlock, pblock));

        // Read what we need out of pblock before trimming: eviction picks at
        // random and is perfectly entitled to pick the block just inserted,
        // which would leave the GetOrphanRoot call below reading freed memory.
        uint256 hashOrphanRoot = GetOrphanRoot(pblock);

        LimitOrphanBlocks(MAX_ORPHAN_BLOCKS);

        // Ask this guy to fill in what we're missing
        if (pfrom)
            pfrom->PushGetBlocks(pindexBest, hashOrphanRoot);
        return true;
    }

    // Store to disk
    if (!pblock->AcceptBlock())
    {
        delete pblock;
        return error("ProcessBlock() : AcceptBlock FAILED");
    }
    delete pblock;

    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock* pblockOrphan = (*mi).second;
            if (pblockOrphan->AcceptBlock())
                vWorkQueue.push_back(pblockOrphan->GetHash());
            mapOrphanBlocks.erase(pblockOrphan->GetHash());
            delete pblockOrphan;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }

    printf("ProcessBlock: ACCEPTED\n");
    return true;
}








template<typename Stream>
bool ScanMessageStart(Stream& s)
{
    // Scan ahead to the next pchMessageStart, which should normally be immediately
    // at the file pointer.  Leaves file pointer at end of pchMessageStart.
    s.clear(0);
    short prevmask = s.exceptions(0);
    const char* p = BEGIN(pchMessageStart);
    try
    {
        loop
        {
            char c;
            s.read(&c, 1);
            if (s.fail())
            {
                s.clear(0);
                s.exceptions(prevmask);
                return false;
            }
            if (*p != c)
                p = BEGIN(pchMessageStart);
            if (*p == c)
            {
                if (++p == END(pchMessageStart))
                {
                    s.clear(0);
                    s.exceptions(prevmask);
                    return true;
                }
            }
        }
    }
    catch (...)
    {
        s.clear(0);
        s.exceptions(prevmask);
        return false;
    }
}

string GetAppDir()
{
    string strDir;
    if (!strSetDataDir.empty())
    {
        strDir = strSetDataDir;
    }
#ifdef _WIN32
    else if (getenv("APPDATA"))
    {
        strDir = strprintf("%s\\Bitflash", getenv("APPDATA"));
    }
    else if (getenv("USERPROFILE"))
    {
        string strAppData = strprintf("%s\\Application Data", getenv("USERPROFILE"));
        static bool fMkdirDone;
        if (!fMkdirDone)
        {
            fMkdirDone = true;
            _mkdir(strAppData.c_str());
        }
        strDir = strprintf("%s\\Bitflash", strAppData.c_str());
    }
#else
    else if (getenv("HOME"))
    {
        strDir = strprintf("%s/.bitflash", getenv("HOME"));
    }
#endif
    else
    {
        return ".";
    }
    static bool fMkdirDone;
    if (!fMkdirDone)
    {
        fMkdirDone = true;
        _mkdir(strDir.c_str());
    }
    return strDir;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if (nFile == -1)
        return NULL;
    FILE* file = fopen(strprintf("%s/blk%04d.dat", GetAppDir().c_str(), nFile).c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    loop
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 filesize max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < 0x7F000000 - MAX_SIZE)
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

bool LoadBlockIndex(bool fAllowNew)
{
    // Initialize the RandomX PoW before touching any block (both the genesis
    // and verification depend on it).
    if (!RandomXInit())
        return error("LoadBlockIndex() : RandomXInit failed");

    //
    // Load block index
    //
    CTxDB txdb("cr");
    if (!txdb.LoadBlockIndex())
        return false;
    txdb.Close();

    // Repair a bad tip found during verification.
    //
    // This has to happen after the handle above is closed. CTxDB::LoadBlockIndex
    // walks the index with a cursor it never closes, so it is still holding read
    // locks -- a write transaction opened alongside it waits on them forever.
    // Measured, not guessed: the node came up, printed the diagnosis, and hung
    // there with nothing in any log.
    if (pindexBadChainFork)
    {
        CBlockIndex* pindexFork = pindexBadChainFork;
        pindexBadChainFork = NULL;

        printf("LoadBlockIndex() : *** moving best chain back to height %d, discarding %d block(s)\n",
               pindexFork->nHeight, nBestHeight - pindexFork->nHeight);

        vector<CBlockIndex*> vDisconnect;
        for (CBlockIndex* pindex = pindexBest; pindex && pindex != pindexFork; pindex = pindex->pprev)
            vDisconnect.push_back(pindex);

        bool fRolledBack = false;
        try
        {
            CTxDB txdbWrite;
            txdbWrite.TxnBegin();
            foreach(CBlockIndex* pindex, vDisconnect)
            {
                CBlock block;
                if (!block.ReadFromDisk(pindex->nFile, pindex->nBlockPos, true))
                    throw runtime_error("ReadFromDisk for disconnect failed");
                if (!block.DisconnectBlock(txdbWrite, pindex))
                    throw runtime_error("DisconnectBlock failed");
            }
            if (!txdbWrite.WriteHashBestChain(pindexFork->GetBlockHash()))
                throw runtime_error("WriteHashBestChain failed");
            txdbWrite.TxnCommit();
            txdbWrite.Close();
            fRolledBack = true;
        }
        catch (const std::exception& e)
        {
            printf("LoadBlockIndex() : rollback failed: %s\n", e.what());
        }
        catch (...)
        {
            printf("LoadBlockIndex() : rollback failed\n");
        }

        if (fRolledBack)
        {
            foreach(CBlockIndex* pindex, vDisconnect)
                if (pindex->pprev)
                    pindex->pprev->pnext = NULL;

            pindexBest    = pindexFork;
            hashBestChain = pindexBest->GetBlockHash();
            nBestHeight   = pindexBest->nHeight;
            printf("LoadBlockIndex() : now at height %d, will re-download from peers\n", nBestHeight);
        }
        else
        {
            // Start anyway. The operator needs a running node to read this from.
            printf("LoadBlockIndex() : *** still on the bad chain at height %d -- back up the data directory and report this\n",
                   nBestHeight);
        }
    }

    //
    // Init with genesis block
    //
    if (mapBlockIndex.empty())
    {
        if (!fAllowNew)
            return false;


        // Genesis Block:
        // GetHash()      = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
        // hashMerkleRoot = 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
        // txNew.vin[0].scriptSig     = 486604799 4 0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854
        // txNew.vout[0].nValue       = 5000000000
        // txNew.vout[0].scriptPubKey = 0x5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704 OP_CHECKSIG
        // block.nVersion = 1
        // block.nTime    = 1231006505
        // block.nBits    = 0x1d00ffff
        // block.nNonce   = 2083236893
        // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
        //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
        //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
        //   vMerkleTree: 4a5e1e

        // Bitflash genesis block -- own header (fair launch, 2026 stable relaunch)
        char* pszTimestamp = "Bitflash 24/Jul/2026 Fair launch: one CPU one vote, no premine";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig     = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((unsigned char*)pszTimestamp, (unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue       = 50 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << CBigNum("0x5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704") << OP_CHECKSIG;
        CBlock block;
        block.vtx.push_back(txNew);
        block.hashPrevBlock = 0;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.nVersion = 1;
        block.nTime    = 1753315200; // 2026-07-24 00:00:00 UTC (stable relaunch)
        block.nBits    = 0x1f0fffff; // = bnProofOfWorkLimit (Bitflash RandomX floor)
        block.nNonce   = GENESIS_NONCE;

        // If the nonce has not been found yet, mine the genesis once (RandomX)
        // and print the values to be hardcoded in the constants above.
        if (block.GetHash() != hashGenesisBlock)
        {
            printf("Mining Bitflash genesis block (RandomX)...\n");
            uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
            while (block.GetPoWHash() > hashTarget)
            {
                if ((block.nNonce & 0x3ff) == 0)
                    printf("nonce %u\r", block.nNonce);
                block.nNonce++;
                if (block.nNonce == 0)
                {
                    printf("nonce overflow, incrementing nTime\n");
                    block.nTime++;
                }
            }
            printf("\n=== BITFLASH GENESIS (RandomX) FOUND ===\n");
            printf("nTime   = %u\n", block.nTime);
            printf("nNonce  = %u  (0x%08x)\n", block.nNonce, block.nNonce);
            printf("powhash = %s\n", block.GetPoWHash().ToString().c_str());
            printf("hash    = %s\n", block.GetHash().ToString().c_str());
            printf("merkle  = %s\n", block.hashMerkleRoot.ToString().c_str());
            printf("========================================\n");
        }

        // Asserts only apply once the genesis values are hardcoded
        if (hashGenesisBlock != uint256(0))
        {
            assert(block.hashMerkleRoot == hashGenesisMerkleRoot);
            assert(block.GetHash() == hashGenesisBlock);
        }

        // Start new block file
        unsigned int nFile;
        unsigned int nBlockPos;
        if (!block.WriteToDisk(!fClient, nFile, nBlockPos))
            return error("LoadBlockIndex() : writing genesis block to disk failed");
        if (!block.AddToBlockIndex(nFile, nBlockPos))
            return error("LoadBlockIndex() : genesis block not accepted");
    }

    return true;
}



void PrintBlockTree()
{
    // precompute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
        }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex, true);
        printf("%d (%u,%u) %s  %s  tx %d",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString().substr(0,14).c_str(),
            DateTimeStr(block.nTime).c_str(),
            (int)block.vtx.size());

        CRITICAL_BLOCK(cs_mapWallet)
        {
            if (mapWallet.count(block.vtx[0].GetHash()))
            {
                CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
                printf("    mine:  %d  %d  %lld", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), wtx.GetCredit());
            }
        }
        printf("\n");


        // put the main timechain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}










//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool AlreadyHave(CTxDB& txdb, const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:        return mapTransactions.count(inv.hash) || txdb.ContainsTx(inv.hash);
    case MSG_BLOCK:     return mapBlockIndex.count(inv.hash) || mapOrphanBlocks.count(inv.hash);
    case MSG_REVIEW:    return true;
    case MSG_PRODUCT:   return mapProducts.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}







bool ProcessMessages(CNode* pfrom)
{
    CDataStream& vRecv = pfrom->vRecv;
    if (vRecv.empty())
        return true;
    LogPrint("net", "ProcessMessages(%d bytes)\n", (int)vRecv.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (x) data
    //

    loop
    {
        // Scan for message start
        CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart), END(pchMessageStart));
        if (vRecv.end() - pstart < sizeof(CMessageHeader))
        {
            if (vRecv.size() > sizeof(CMessageHeader))
            {
                if (LogAcceptsCategory("net")) printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vRecv.erase(vRecv.begin(), vRecv.end() - sizeof(CMessageHeader));
            }
            break;
        }
        if (pstart - vRecv.begin() > 0)
            if (LogAcceptsCategory("net")) printf("\n\nPROCESSMESSAGE SKIPPED %d BYTES\n\n", (int)(pstart - vRecv.begin()));
        vRecv.erase(vRecv.begin(), pstart);

        // Read the header from a copy first. The old path consumed the header,
        // noticed the payload was incomplete, inserted the header back at the
        // front of the receive buffer, then slept inside the shared message
        // thread. A peer could announce a large payload and drip bytes forever,
        // making every pass pay for an O(n) insert and a 100 ms stall.
        CMessageHeader hdr;
        CDataStream vHeader(vRecv.begin(), vRecv.begin() + sizeof(CMessageHeader),
                            vRecv.nType, vRecv.nVersion);
        vHeader >> hdr;
        if (!hdr.IsValid())
        {
            if (LogAcceptsCategory("net")) printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            if (hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_SIZE)
                pfrom->fDisconnect = true;
            pfrom->nIncompleteMessageStart = 0;
            vRecv.ignore(sizeof(CMessageHeader));
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;
        unsigned int nPayloadAvailable = vRecv.size() - sizeof(CMessageHeader);
        if (nMessageSize > nPayloadAvailable)
        {
            if (pfrom->nIncompleteMessageStart == 0 ||
                pfrom->nIncompleteMessageSize != nMessageSize ||
                pfrom->strIncompleteMessageCommand != strCommand)
            {
                pfrom->nIncompleteMessageStart = GetTime();
                pfrom->nIncompleteMessageSize = nMessageSize;
                pfrom->strIncompleteMessageCommand = strCommand;
            }
            else if (GetTime() - pfrom->nIncompleteMessageStart >
                     BTF_INCOMPLETE_MESSAGE_TIMEOUT_SECS)
            {
                LogPrint("net",
                         "disconnecting %s: incomplete %s message, %u of %u bytes after %d seconds\n",
                         pfrom->addr.ToString().c_str(), strCommand.c_str(),
                         nPayloadAvailable, nMessageSize,
                         BTF_INCOMPLETE_MESSAGE_TIMEOUT_SECS);
                pfrom->fDisconnect = true;
            }
            break;
        }
        pfrom->nIncompleteMessageStart = 0;
        pfrom->nIncompleteMessageSize = 0;
        pfrom->strIncompleteMessageCommand.clear();
        vRecv.ignore(sizeof(CMessageHeader));

        // Copy message to its own buffer
        CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);
        vRecv.ignore(nMessageSize);

        // Process message
        bool fRet = false;
        try
        {
            CheckForShutdown(2);
            CRITICAL_BLOCK(cs_main)
                fRet = ProcessMessage(pfrom, strCommand, vMsg);
            CheckForShutdown(2);
        }
        CATCH_PRINT_EXCEPTION("ProcessMessage()")
        if (!fRet)
            if (LogAcceptsCategory("net")) printf("ProcessMessage(%s, %d bytes) from %s to %s FAILED\n", strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(), addrLocalHost.ToString().c_str());
    }

    vRecv.Compact();
    return true;
}




bool ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    static map<unsigned int, vector<unsigned char> > mapReuseKey;
    if (LogAcceptsCategory("net")) { printf("received: %-12s (%d bytes)  ", strCommand.c_str(), (int)vRecv.size()); for (int i = 0; i < min(vRecv.size(), (unsigned int)25); i++) printf("%02x ", vRecv[i] & 0xff); printf("\n"); }
    if (nDropMessagesTest > 0 && GetRand(nDropMessagesTest) == 0)
    {
        if (LogAcceptsCategory("net")) printf("dropmessages DROPPING RECV MESSAGE\n");
        return true;
    }



    if (strCommand == "version")
    {
        // Can only do this once
        if (pfrom->nVersion != 0)
            return false;

        int64 nTime;
        CAddress addrMe;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion == 0)
            return false;

        // Optional: peers older than this field simply end the message here,
        // and nStartingHeight stays -1 for them. Never make this a requirement
        // -- every node released so far sends the short form.
        if (!vRecv.empty())
            vRecv >> pfrom->nStartingHeight;

        pfrom->vSend.SetVersion(min(pfrom->nVersion, VERSION));
        pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION));

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);
        if (pfrom->fClient)
        {
            pfrom->vSend.nType |= SER_BLOCKHEADERONLY;
            pfrom->vRecv.nType |= SER_BLOCKHEADERONLY;
        }

        AddTimeData(pfrom->addr.ip, nTime);

        // Ask the first connected node for block updates
        static bool fAskedForBlocks;
        if (!fAskedForBlocks && !pfrom->fClient)
        {
            fAskedForBlocks = true;
            pfrom->PushGetBlocks(pindexBest, uint256(0));
        }

        // Introduce ourselves and hand over the .btf peers that answered us.
        // Everything in here is self-certifying, so this is safe to send to a
        // node we know nothing about, and safe for it to act on.
        vector<string> vPexOut;
        BtfPexCollect(vPexOut);
        if (!vPexOut.empty())
            pfrom->PushMessage("btfpeers", vPexOut);

        if (LogAcceptsCategory("net")) printf("version addrMe = %s, peer height = %d\n", addrMe.ToString().c_str(), pfrom->nStartingHeight);
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        return false;
    }


    else if (strCommand == "btfpeers")
    {
        // Peer exchange. Nothing here is taken on trust: BtfPexAccept checks
        // every descriptor's signature against the key its .btf address
        // decodes to, and drops the rest.
        int64 nNow = GetTime();
        if (nNow - pfrom->nLastPexRecv < PEX_MIN_INTERVAL)
        {
            if (LogAcceptsCategory("net"))
                printf("btfpeers: ignoring, %s is sending them too fast\n",
                       pfrom->addr.ToString().c_str());
            return true;
        }
        pfrom->nLastPexRecv = nNow;

        vector<string> vDesc;
        vRecv >> vDesc;
        int nKept = BtfPexAccept(vDesc);
        LogPrint("net", "btfpeers: kept %d of %zu descriptor(s) from %s\n",
                 nKept, vDesc.size(), pfrom->addr.ToString().c_str());
    }


    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;

        CTxDB txdb("r");
        foreach(const CInv& inv, vInv)
        {
            if (fShutdown)
                return true;
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(txdb, inv);
            if (LogAcceptsCategory("net")) printf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");

            if (!fAlreadyHave)
                pfrom->AskFor(inv);
            else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash))
                pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash]));
        }
    }


    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;

        foreach(const CInv& inv, vInv)
        {
            if (fShutdown)
                return true;
            if (LogAcceptsCategory("net")) printf("received getdata for: %s\n", inv.ToString().c_str());

            if (inv.type == MSG_BLOCK)
            {
                // Send block from disk
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    //// could optimize this to send header straight from blockindex for client
                    CBlock block;
                    block.ReadFromDisk((*mi).second, !pfrom->fClient);
                    pfrom->PushMessage("block", block);
                }
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                CRITICAL_BLOCK(cs_mapRelay)
                {
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end())
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                }
            }
        }
    }


    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // Find the first block the caller has in the main chain
        CBlockIndex* pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;
        if (LogAcceptsCategory("net")) printf("getblocks %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,14).c_str());
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                if (LogAcceptsCategory("net")) printf("  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,14).c_str());
                break;
            }

            // Bypass setInventoryKnown in case an inventory message got lost
            CRITICAL_BLOCK(pfrom->cs_inventory)
            {
                CInv inv(MSG_BLOCK, pindex->GetBlockHash());
                // returns true if wasn't already contained in the set
                if (pfrom->setInventoryKnown2.insert(inv).second)
                {
                    pfrom->setInventoryKnown.erase(inv);
                    pfrom->vInventoryToSend.push_back(inv);
                }
            }
        }
    }


    else if (strCommand == "tx")
    {
        vector<uint256> vWorkQueue;
        CDataStream vMsg(vRecv);
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        bool fMissingInputs = false;
        if (tx.AcceptTransaction(true, &fMissingInputs))
        {
            AddToWalletIfMine(tx, NULL);
            RelayMessage(inv, vMsg);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);

            // Recursively process any orphan transactions that depended on this one
            for (int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(hashPrev);
                     mi != mapOrphanTransactionsByPrev.upper_bound(hashPrev);
                     ++mi)
                {
                    const CDataStream& vMsg = *((*mi).second);
                    CTransaction tx;
                    CDataStream(vMsg) >> tx;
                    CInv inv(MSG_TX, tx.GetHash());

                    if (tx.AcceptTransaction(true))
                    {
                        if (LogAcceptsCategory("net")) printf("   accepted orphan tx %s\n", inv.hash.ToString().substr(0,6).c_str());
                        AddToWalletIfMine(tx, NULL);
                        RelayMessage(inv, vMsg);
                        mapAlreadyAskedFor.erase(inv);
                        vWorkQueue.push_back(inv.hash);
                    }
                }
            }

            foreach(uint256 hash, vWorkQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            if (LogAcceptsCategory("net")) printf("storing orphan tx %s\n", inv.hash.ToString().substr(0,6).c_str());
            AddOrphanTx(vMsg);
        }
    }


    else if (strCommand == "review")
    {
        CDataStream vMsg(vRecv);
        CReview review;
        vRecv >> review;

        CInv inv(MSG_REVIEW, review.GetHash());
        pfrom->AddInventoryKnown(inv);

        if (review.AcceptReview())
        {
            // Relay the original message as-is in case it's a higher version than we know how to parse
            RelayMessage(inv, vMsg);
            mapAlreadyAskedFor.erase(inv);
        }
    }


    else if (strCommand == "block")
    {
        auto_ptr<CBlock> pblock(new CBlock);
        vRecv >> *pblock;

        //// debug print
        if (LogAcceptsCategory("net")) { printf("received block:\n"); pblock->print(); }

        CInv inv(MSG_BLOCK, pblock->GetHash());
        pfrom->AddInventoryKnown(inv);

        if (ProcessBlock(pfrom, pblock.release()))
            mapAlreadyAskedFor.erase(inv);
    }


    else if (strCommand == "checkorder")
    {
        uint256 hashReply;
        CWalletTx order;
        vRecv >> hashReply >> order;

        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (!mapReuseKey.count(pfrom->addr.ip))
            mapReuseKey[pfrom->addr.ip] = GenerateNewKey();

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << mapReuseKey[pfrom->addr.ip] << OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
    }


    else if (strCommand == "submitorder")
    {
        uint256 hashReply;
        CWalletTx wtxNew;
        vRecv >> hashReply >> wtxNew;

        // Broadcast
        if (!wtxNew.AcceptWalletTransaction())
        {
            pfrom->PushMessage("reply", hashReply, (int)1);
            return error("submitorder AcceptWalletTransaction() failed, returning error 1");
        }
        wtxNew.fTimeReceivedIsTxTime = true;
        AddToWallet(wtxNew);
        wtxNew.RelayWalletTransaction();
        mapReuseKey.erase(pfrom->addr.ip);

        // Send back confirmation
        pfrom->PushMessage("reply", hashReply, (int)0);
    }


    else if (strCommand == "reply")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        CRITICAL_BLOCK(pfrom->cs_mapRequests)
        {
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end())
            {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    }


    else if (strCommand == "ping")
    {
        // Nothing to do and nothing to answer. Arriving at all is the entire
        // content of the message: the receive path has already stamped
        // nLastRecv, which is what the sender wanted us to notice.
        //
        // Deliberately no reply. A node old enough not to know "ping" ignores
        // it as an unknown command and would never answer one, so a scheme
        // that required an answer would read every such peer as dead.
    }


    else
    {
        // Ignore unknown commands for extensibility
        if (LogAcceptsCategory("net")) printf("ProcessMessage(%s) : Ignored unknown message\n", strCommand.c_str());
    }


    if (!vRecv.empty())
        if (LogAcceptsCategory("net")) printf("ProcessMessage(%s) : %d extra bytes\n", strCommand.c_str(), (int)vRecv.size());

    return true;
}









bool SendMessages(CNode* pto)
{
    CheckForShutdown(2);
    CRITICAL_BLOCK(cs_main)
    {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;


        //
        // Message: keep-alive ping
        //
        // Only when we have nothing else queued -- any real message serves the
        // same purpose. A peer with nothing to relay is otherwise silent, and
        // silence is exactly what the inactivity check disconnects on.
        //
        if (pto->nLastSend && GetTime() - pto->nLastSend > BTF_PING_INTERVAL_SECS && pto->vSend.empty())
            pto->PushMessage("ping");


        //
        // Message: inventory
        //
        vector<CInv> vInventoryToSend;
        CRITICAL_BLOCK(pto->cs_inventory)
        {
            vInventoryToSend.reserve(pto->vInventoryToSend.size());
            foreach(const CInv& inv, pto->vInventoryToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                    vInventoryToSend.push_back(inv);
            }
            pto->vInventoryToSend.clear();
            pto->setInventoryKnown2.clear();
        }
        if (!vInventoryToSend.empty())
            pto->PushMessage("inv", vInventoryToSend);


        //
        // Message: getdata
        //
        vector<CInv> vAskFor;
        int64 nNow = GetTime() * 1000000;
        CTxDB txdb("r");
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (LogAcceptsCategory("net")) printf("sending getdata: %s\n", inv.ToString().c_str());
            if (!AlreadyHave(txdb, inv))
                vAskFor.push_back(inv);
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vAskFor.empty())
            pto->PushMessage("getdata", vAskFor);

    }
    return true;
}














//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

int FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

using CryptoPP::ByteReverse;
static int detectlittleendian = 1;

void BlockSHA256(const void* pin, unsigned int nBlocks, void* pout)
{
    unsigned int* pinput = (unsigned int*)pin;
    unsigned int* pstate = (unsigned int*)pout;

    CryptoPP::SHA256::InitState(pstate);

    if (*(char*)&detectlittleendian != 0)
    {
        for (int n = 0; n < nBlocks; n++)
        {
            unsigned int pbuf[16];
            for (int i = 0; i < 16; i++)
                pbuf[i] = ByteReverse(pinput[n * 16 + i]);
            CryptoPP::SHA256::Transform(pstate, pbuf);
        }
        for (int i = 0; i < 8; i++)
            pstate[i] = ByteReverse(pstate[i]);
    }
    else
    {
        for (int n = 0; n < nBlocks; n++)
            CryptoPP::SHA256::Transform(pstate, pinput + n * 16);
    }
}


// ---------------------------------------------------------------------------
// Participant pool miner -- connects to an external Stratum server, receives
// RandomX jobs, hashes with the local CPU, and submits shares.
// Called from BitcoinMiner() when nMineMode == MINE_PARTICIPANT.
// ---------------------------------------------------------------------------

using json = nlohmann::json;


// ---------------------------------------------------------------------------
// Participant miner -- connects to a pool over a .btf tunnel, runs Stratum,
// hashes with RandomX, submits shares. Called from BitcoinMiner().
// ---------------------------------------------------------------------------

using json = nlohmann::json;

static std::string ToHexStr(const void* p, size_t n)
{
    const unsigned char* b = (const unsigned char*)p;
    std::string s; s.reserve(n*2);
    static const char* H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { s += H[b[i]>>4]; s += H[b[i]&0xf]; }
    return s;
}

static std::vector<unsigned char> FromHexStr(const std::string& s)
{
    std::vector<unsigned char> v;
    for (size_t i = 0; i+1 < s.size(); i += 2) {
        auto h = [](char c)->int{
            if(c>='0'&&c<='9') return c-'0';
            if(c>='a'&&c<='f') return c-'a'+10;
            if(c>='A'&&c<='F') return c-'A'+10;
            return 0;
        };
        v.push_back((unsigned char)((h(s[i])<<4)|h(s[i+1])));
    }
    return v;
}

static void UpdateParticipantHashRate(uint64 hashesSinceSample, int64 sampleStart)
{
    int64 elapsed = GetTime() - sampleStart;
    if (elapsed <= 0) elapsed = 1;
    gParticipantHashRateX1000.store(
        (uint64)((double)hashesSinceSample / (double)elapsed * 1000.0));
}

// Blocking send of a JSON line to the pool.
static bool StratumSendLine(SOCKET s, const json& j)
{
    std::string line = j.dump() + "\n";
    int sent = 0, total = (int)line.size();
    while (sent < total) {
        int r = send(s, line.c_str()+sent, total-sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

// Non-blocking recv into carry buffer. Returns true + fills line when a
// complete newline-terminated message is ready. Returns false in two cases:
//   disconnected=true  -- socket closed by peer; caller must stop
//   disconnected=false -- no complete line yet; caller should select() and retry
static bool StratumRecvLine(SOCKET s, std::string& buf,
                            std::string& line, bool& disconnected)
{
    disconnected = false;
    char tmp[4096];
#ifdef _WIN32
    u_long avail = 0;
    ioctlsocket(s, FIONREAD, &avail);
    if (avail > 0) {
        int r = recv(s, tmp, (int)std::min((u_long)(sizeof(tmp)-1), avail), 0);
        if (r > 0)       { tmp[r] = 0; buf += tmp; }
        else if (r == 0) { disconnected = true; return false; }
    }
#else
    {
        int r = recv(s, tmp, sizeof(tmp)-1, MSG_DONTWAIT);
        if (r > 0)       { tmp[r] = 0; buf += tmp; }
        else if (r == 0) { disconnected = true; return false; }
        // r < 0: EAGAIN -- no data right now
    }
#endif
    size_t pos = buf.find('\n');
    if (pos == std::string::npos) return false;
    line = buf.substr(0, pos);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    buf = buf.substr(pos + 1);
    return true;
}

// How long to wait for a mining.notify after authorize before giving up
static const int64 STUCK_NO_JOB_TIMEOUT_SECS = 120;

static bool PoolParticipantMiner()
{
    // ------------------------------------------------------------------
    // Step 1: resolve .btf address -> meeting node
    // ------------------------------------------------------------------
    if (strParticipantPool.empty()) {
        LogPrint("worker", "[worker] no pool selected\n");
        SetParticipantMiningStatus("no pool selected");
        return false;
    }

    LogPrint("worker", "[worker] connecting to pool %s\n", strParticipantPool.c_str());
    SetParticipantMiningStatus("resolving pool address");

    unsigned char target_pubkey[32];
    if (!btf::ParseAddress(strParticipantPool, target_pubkey)) {
        LogPrint("worker", "[worker] invalid .btf address: %s\n", strParticipantPool.c_str());
        SetParticipantMiningStatus("invalid pool address");
        return false;
    }

    std::string meetingHostPort;
    unsigned char service_enc_pub[32];
    if (!BtfResolve(strParticipantPool, meetingHostPort, service_enc_pub)) {
        LogPrint("worker", "[worker] failed to resolve pool %s"
                 " (no Nostr descriptor found -- pool may be offline or relays down)\n",
                 strParticipantPool.c_str());
        SetParticipantMiningStatus("failed to resolve pool");
        return false;
    }
    LogPrint("worker", "[worker] pool resolved to meeting node %s\n", meetingHostPort.c_str());

    size_t colon = meetingHostPort.rfind(':');
    if (colon == std::string::npos) {
        LogPrint("worker", "[worker] bad meeting node format '%s'\n", meetingHostPort.c_str());
        SetParticipantMiningStatus("bad pool endpoint");
        return false;
    }
    std::string host = meetingHostPort.substr(0, colon);
    int port = atoi(meetingHostPort.substr(colon + 1).c_str());
    if (port <= 0 || port > 65535) {
        LogPrint("worker", "[worker] bad meeting port %d in '%s'\n",
                 port, meetingHostPort.c_str());
        SetParticipantMiningStatus("bad pool port");
        return false;
    }

    // ------------------------------------------------------------------
    // Step 2: open encrypted tunnel to pool
    // ------------------------------------------------------------------
    SetParticipantMiningStatus("opening tunnel");
    btf_socket_t s = btf::BtfClientTunnel(host.c_str(), (unsigned short)port,
                                           target_pubkey, service_enc_pub);
    if (s == INVALID_SOCKET) {
        LogPrint("worker", "[worker] tunnel connect FAILED via %s"
                 " (relay unreachable or pool not listening)\n",
                 meetingHostPort.c_str());
        SetParticipantMiningStatus("tunnel connect failed");
        return false;
    }
    LogPrint("worker", "[worker] tunnel open via %s\n", meetingHostPort.c_str());
    SetParticipantMiningStatus("tunnel open");

    // ------------------------------------------------------------------
    // Step 3: determine our payout address (mining username)
    // ------------------------------------------------------------------
    std::string username;
    {
        std::vector<unsigned char> vchPubKey;
        if (CWalletDB("r").ReadDefaultKey(vchPubKey))
            username = PubKeyToAddress(vchPubKey);
    }
    if (username.empty()) username = BtfLocalAddress();
    if (username.empty()) {
        LogPrint("worker", "[worker] WARNING: could not determine wallet address"
                 " -- shares will not pay out\n");
        username = "unknown";
    }
    LogPrint("worker", "[worker] payout address: %s\n", username.c_str());

    // ------------------------------------------------------------------
    // Step 4: build the fast (~2 GB dataset) RandomX mode if not already
    // built, then start our VM. Without this, RandomXCreateMinerVM() falls
    // back to "light" mode (cache only) forever, which is dramatically
    // slower per hash than fast mode -- it recomputes dataset items on the
    // fly for every single hash instead of a direct memory lookup. That
    // alone can turn a "few seconds per share" pool into "many minutes per
    // share" regardless of how easy the share target is.
    //
    // This MUST happen before we send mining.subscribe/authorize, not
    // after: it's a synchronous, single-threaded-per-call build that can
    // take anywhere from several seconds to a couple of minutes depending
    // on core count. If it runs after the handshake messages are sent,
    // the pool's replies (subscribe ack, authorize ack, set_difficulty,
    // and the first job) all land in the OS socket buffer while we're
    // not reading -- nothing is lost, but we sit there looking (and
    // logging) like we're "stuck waiting for pool response" for the
    // entire build duration, when really we're just not listening yet.
    // Building the dataset first means that by the time we say
    // "subscribing", we're genuinely ready to read the reply the instant
    // it arrives.
    // ------------------------------------------------------------------
    if (!RandomXFastReady()) {
        SetParticipantMiningStatus("building RandomX dataset (~2GB, one-time)");
        unsigned int nThreads = std::thread::hardware_concurrency();
        RandomXInitDataset(nThreads > 0 ? (int)nThreads : 1);
    }
    void* rxvm = RandomXCreateMinerVM();
    if (!rxvm) {
        LogPrint("worker", "[worker] failed to create RandomX VM\n");
        SetParticipantMiningStatus("RandomX init failed");
        closesocket(s); return false;
    }
    LogPrint("worker", "[worker] RandomX VM ready (%s)\n",
             RandomXFastReady() ? "fast 2GB" : "light 256MB");

    // ------------------------------------------------------------------
    // Step 5: Stratum subscribe + authorize. The socket is read from
    // immediately after this, in the main loop below, so nothing sits
    // unread behind a blocking dataset build anymore.
    // ------------------------------------------------------------------
    std::string buf;
    int msgId = 1;
    std::set<int> pendingSubmitIds;

    SetParticipantMiningStatus("subscribing");
    LogPrint("worker", "[worker->pool] sending mining.subscribe\n");
    if (!StratumSendLine(s, json{{"id",msgId++},{"method","mining.subscribe"},
                                 {"params",json::array()}})) {
        LogPrint("worker", "[worker] subscribe send FAILED -- pool dropped connection\n");
        SetParticipantMiningStatus("subscribe send failed");
        RandomXDestroyMinerVM(rxvm);
        closesocket(s); return false;
    }

    SetParticipantMiningStatus("authorizing");
    LogPrint("worker", "[worker->pool] sending mining.authorize as %s\n", username.c_str());
    if (!StratumSendLine(s, json{{"id",msgId++},{"method","mining.authorize"},
                                 {"params",json::array({username,"x"})}})) {
        LogPrint("worker", "[worker] authorize send FAILED -- pool dropped connection\n");
        SetParticipantMiningStatus("authorize send failed");
        RandomXDestroyMinerVM(rxvm);
        closesocket(s); return false;
    }

    // ------------------------------------------------------------------
    // Step 6: main loop -- receive messages, hash, submit shares
    // ------------------------------------------------------------------
    std::string jobId;
    unsigned char header[80] = {};
    uint256 target;
    double currentDifficulty = 1.0; // updated by mining.set_difficulty from pool
    bool haveJob         = false;
    bool gotSubscribeAck = false;
    bool gotAuthorizeAck = false;
    int64 authWaitStart  = 0;
    int64 lastStuckLog   = 0;
    unsigned int nNonce  = 1;
    uint64 hashesSinceSample  = 0;
    uint64 sessionSharesSent  = 0; // this connection only
    uint64 sessionSharesAccepted = 0;
    int64  sampleStart       = GetTime();

    SetParticipantMiningStatus("waiting for pool response");

    while (fGenerateBitcoins && nMineMode == MINE_PARTICIPANT && !fShutdown)
    {
        // -- Receive: check buffer first, then select --
        {
            bool haveBuffered = buf.find('\n') != std::string::npos;
            bool readable     = false;
            if (!haveBuffered) {
                fd_set fds; FD_ZERO(&fds); FD_SET(s, &fds);
                struct timeval tv = {0, 50000}; // 50ms
                readable = select((int)s+1, &fds, NULL, NULL, &tv) > 0;
            }

            if (haveBuffered || readable) {
                std::string line;
                bool disc = false;
                while (StratumRecvLine(s, buf, line, disc)) {
                    json msg;
                    try { msg = json::parse(line); } catch (...) {
                        LogPrint("worker", "[pool->worker] JSON parse error: %.80s\n",
                                 line.c_str());
                        continue;
                    }

                    // -- Response to our subscribe (id=1) --
                    if (msg.contains("id") && msg["id"].is_number_integer()
                        && msg["id"].get<int>() == 1
                        && msg.contains("result") && !msg["result"].is_null()) {
                        gotSubscribeAck = true;
                        LogPrint("worker", "[pool->worker] subscribe ack received\n");
                        SetParticipantMiningStatus("subscribed; waiting for authorize ack");
                    }

                    // -- Response to our authorize (id=2) --
                    else if (msg.contains("id") && msg["id"].is_number_integer()
                             && msg["id"].get<int>() == 2
                             && msg.contains("result")) {
                        bool ok = msg["result"].is_boolean() && msg["result"].get<bool>();
                        authWaitStart = GetTime();
                        if (ok) {
                            gotAuthorizeAck = true;
                            LogPrint("worker", "[pool->worker] authorize OK -- waiting for job\n");
                            SetParticipantMiningStatus("authorized; waiting for job");
                        } else {
                            std::string reason = msg.value("error", json("unspecified")).is_string()
                                ? msg["error"].get<std::string>() : "unspecified";
                            LogPrint("worker", "[pool->worker] authorize REJECTED: %s\n",
                                     reason.c_str());
                            SetParticipantMiningStatus("authorization rejected");
                            // Don't break -- pool might still send a job (some pools
                            // reject bad addresses but still send work)
                        }
                    }

                    // -- Share submission response --
                    else if (msg.contains("id") && msg["id"].is_number_integer()) {
                        int rid = msg["id"].get<int>();
                        if (pendingSubmitIds.erase(rid) > 0) {
                            bool accepted = msg.contains("result")
                                         && msg["result"].is_boolean()
                                         && msg["result"].get<bool>();
                            if (accepted) {
                                gParticipantSharesAccepted.fetch_add(1);
                                sessionSharesAccepted++;
                                LogPrint("worker", "[pool->worker] share id=%d ACCEPTED\n", rid);
                                SetParticipantMiningStatus("share accepted");
                            } else {
                                std::string reason = (msg.contains("error")
                                    && msg["error"].is_string())
                                    ? msg["error"].get<std::string>() : "unspecified";
                                LogPrint("worker", "[pool->worker] share id=%d REJECTED: %s\n",
                                         rid, reason.c_str());
                                SetParticipantMiningStatus("share rejected: " + reason);
                            }
                        }
                    }

                    // -- Server notification --
                    else {
                        std::string method = msg.value("method", "");

                        if (method == "mining.notify") {
                            auto& p = msg["params"];
                            if (!p.is_array() || p.size() < 4) {
                                LogPrint("worker", "[pool->worker] malformed mining.notify"
                                         " (params size=%zu)\n", p.is_array() ? p.size() : 0);
                            } else {
                                std::string newJobId = p[0].get<std::string>();
                                auto hdrBytes = FromHexStr(p[1].get<std::string>());
                                auto tgtBytes = FromHexStr(p[3].get<std::string>());

                                if (hdrBytes.size() < 80) {
                                    LogPrint("worker", "[pool->worker] mining.notify:"
                                             " header too short (%zu bytes)\n",
                                             hdrBytes.size());
                                } else if (tgtBytes.size() < 32) {
                                    LogPrint("worker", "[pool->worker] mining.notify:"
                                             " target too short (%zu bytes)\n",
                                             tgtBytes.size());
                                } else {
                                    jobId = newJobId;
                                    memcpy(header, hdrBytes.data(), 80);
                                    memcpy(&target, tgtBytes.data(), 32);
                                    haveJob = true;
                                    nNonce  = 1;
                                    LogPrint("worker", "[pool->worker] new job %s received\n",
                                             jobId.c_str());
                                    SetParticipantMiningStatus("hashing job " + jobId);
                                }
                            }
                        } else if (method == "mining.set_difficulty") {
                            // Pool adjusts our share difficulty via vardiff.
                            // Apply it immediately so we start hashing at the new target.
                            if (msg.contains("params") && msg["params"].is_array()
                                && msg["params"].size() > 0
                                && msg["params"][0].is_number()) {
                                double newDiff = msg["params"][0].get<double>();
                                if (newDiff > 0.0) {
                                    bool changed = (newDiff != currentDifficulty);
                                    currentDifficulty = newDiff;
                                    LogPrint("worker", "[pool->worker] set_difficulty %.6f%s\n",
                                             newDiff, changed ? " (updated)" : " (initial)");
                                }
                            } else {
                                LogPrint("worker", "[pool->worker] set_difficulty"
                                         " received (no valid params)\n");
                            }
                        } else if (!method.empty()) {
                            LogPrint("worker", "[pool->worker] unknown server method: %s\n",
                                     method.c_str());
                        }
                    }
                }

                if (disc) {
                    LogPrint("worker", "[worker] pool closed the connection"
                             " (gotSubscribeAck=%d gotAuthorizeAck=%d haveJob=%d)\n",
                             gotSubscribeAck, gotAuthorizeAck, haveJob);
                    break;
                }
            }
        }

        // -- Stuck watchdog: authorized but no job arriving --
        if (gotAuthorizeAck && !haveJob && authWaitStart > 0) {
            int64 waited = GetTime() - authWaitStart;
            if (waited > 10 && GetTime() - lastStuckLog >= 15) {
                LogPrint("worker", "[worker] authorized but no job after %llds"
                         " -- pool tunnel is live, waiting on mining.notify\n",
                         (long long)waited);
                lastStuckLog = GetTime();
            }
            if (waited > STUCK_NO_JOB_TIMEOUT_SECS) {
                LogPrint("worker", "[worker] no job received after %llds -- disconnecting"
                         " and reconnecting\n", (long long)STUCK_NO_JOB_TIMEOUT_SECS);
                SetParticipantMiningStatus("timeout waiting for job; reconnecting");
                break;
            }
        }

        if (!haveJob) { Sleep(100); continue; }

        // -- Hash one nonce --
        memcpy(header+76, &nNonce, 4);
        uint256 hash = RandomXHashWithVM(rxvm, header, 80);
        hashesSinceSample++;
        gParticipantHashes.fetch_add(1);
        if ((hashesSinceSample & 0x3ff) == 0)
            UpdateParticipantHashRate(hashesSinceSample, sampleStart);

        if (hash <= target) {
            LogPrint("worker", "[worker] share found! nonce=%u job=%s difficulty=%.4f\n",
                     nNonce, jobId.c_str(), currentDifficulty);
            SetParticipantMiningStatus("share found; submitting");
            int submitId = msgId++;
            pendingSubmitIds.insert(submitId);
            gParticipantSharesSent.fetch_add(1);
            sessionSharesSent++;
            json submit = {{"id",submitId},{"method","mining.submit"},
                           {"params",json::array({username, jobId, ToHexStr(&nNonce,4)})}};
            if (!StratumSendLine(s, submit)) {
                LogPrint("worker", "[worker] share submit send FAILED"
                         " -- pool connection lost\n");
                break;
            }
        }

        nNonce++;
        if (nNonce == 0) {
            LogPrint("worker", "[worker] nonce space exhausted for job %s"
                     " -- waiting for new job\n", jobId.c_str());
            haveJob = false;
        }
    }

    // ------------------------------------------------------------------
    // Cleanup
    // ------------------------------------------------------------------
    RandomXDestroyMinerVM(rxvm);
    closesocket(s);
    UpdateParticipantHashRate(hashesSinceSample, sampleStart);
    SetParticipantMiningStatus("disconnected");
    LogPrint("worker", "[worker] disconnected from pool"
             " (hashes this session: %llu, shares sent: %llu, accepted: %llu)\n",
             (unsigned long long)hashesSinceSample,
             (unsigned long long)sessionSharesSent,
             (unsigned long long)sessionSharesAccepted);
    return true;
}

bool BitcoinMiner(int nThreadId)
{
    // Relay mode: never mines, just relays/syncs. (Shouldn't normally get here
    // since the GUI hides Start Mining for Relay, but guard it regardless.)
    if (nMineMode == MINE_RELAY)
        return true;

    // Participant mode: connect to external pool instead of mining solo/operator
    if (nMineMode == MINE_PARTICIPANT)
    {
        while (fGenerateBitcoins && nMineMode == MINE_PARTICIPANT && !fShutdown) {
            PoolParticipantMiner();
            if (fGenerateBitcoins && nMineMode == MINE_PARTICIPANT && !fShutdown) {
                LogPrint("worker", "PoolParticipantMiner: reconnecting in 10s\n");
                for (int i = 0; i < 10 && !fShutdown; i++) Sleep(1000);
            }
        }
        return true;
    }

    // Operator mode only serves the pool; it does not mine solo.
    if (nMineMode == MINE_OPERATOR)
        return true;

    LogPrint("net", "BitcoinMiner started\n");
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

    // Build the fast (~2 GB dataset) RandomX mode once, up front, so we're
    // not stuck mining in the much slower light/cache-only mode forever.
    if (!RandomXFastReady()) {
        unsigned int nThreads = std::thread::hardware_concurrency();
        RandomXInitDataset(nThreads > 0 ? (int)nThreads : 1);
    }

    // Drawn from the pool, so it is already in wallet.dat before a single hash
    // is computed. The old code generated a key here and only saved it if this
    // thread happened to win a block, which meant a backup taken while mining
    // could not spend what the very next block paid.
    vector<unsigned char> vchPubKey = GetKeyFromPool();
    if (vchPubKey.empty())
    {
        printf("BitcoinMiner: no wallet key available for coinbase; mining stopped\n");
        return false;
    }
    CBigNum bnExtraNonce = 0;
    while (fGenerateBitcoins)
    {
        Sleep(50);
        // Return instead of _endthread()ing. With more than one miner thread the
        // bookkeeping in ThreadBitcoinMiner has to run on the way out, and
        // _endthread() does not unwind on Windows, so a normal return is the
        // only exit that works the same on both platforms.
        if (fShutdown)
            return true;
        while (vNodes.empty() && !fSoloMineTest)
        {
            Sleep(1000);
            if (fShutdown)
                return true;
        }

        unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrev = pindexBest;
        unsigned int nBits = GetNextWorkRequired(pindexPrev);


        //
        // Create coinbase tx
        //
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vin[0].prevout.SetNull();
        // The height comes first and is what makes this transaction unique.
        //
        // Without it nothing in the coinbase belongs to the block: it is a
        // function of the difficulty, a counter, and the payout key. nBits
        // holds still for long stretches and bnExtraNonce is a local that
        // restarts at zero whenever the miner does, so the same combination
        // comes round again and produces a byte-identical transaction with the
        // same txid. Two blocks then name the same transaction and the index
        // keeps whichever arrived last, which silently destroys the outputs of
        // the first. It has already happened twice on this chain, at heights
        // 859 and 860 (#58).
        //
        // Two coinbases at different heights can now never be identical, no
        // matter what the counter or the key do.
        //
        // Nothing validates coinbase content, so this changes only what we
        // produce -- nodes that do not upgrade accept these blocks unchanged.
        // Requiring the height is a separate, coordinated step.
        txNew.vin[0].scriptSig << (pindexPrev ? pindexPrev->nHeight + 1 : 0) << nBits << ++bnExtraNonce;
        txNew.vout.resize(1);
        // Always pay coinbase to own wallet key. In operator mode, the pool
        // server distributes shares to miners via SendMoney() after each block.
        txNew.vout[0].scriptPubKey << vchPubKey << OP_CHECKSIG;


        //
        // Create new block
        //
        auto_ptr<CBlock> pblock(new CBlock());
        if (!pblock.get())
            return false;

        // Add our coinbase tx as first transaction
        pblock->vtx.push_back(txNew);

        // Collect the latest transactions into the block
        int64 nFees = 0;
        CRITICAL_BLOCK(cs_main)
        CRITICAL_BLOCK(cs_mapTransactions)
        {
            CTxDB txdb("r");
            map<uint256, CTxIndex> mapTestPool;
            vector<char> vfAlreadyAdded(mapTransactions.size());
            bool fFoundSomething = true;
            unsigned int nBlockSize = 0;
            while (fFoundSomething && nBlockSize < MAX_SIZE/2)
            {
                fFoundSomething = false;
                unsigned int n = 0;
                for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin(); mi != mapTransactions.end(); ++mi, ++n)
                {
                    if (vfAlreadyAdded[n])
                        continue;
                    CTransaction& tx = (*mi).second;
                    if (tx.IsCoinBase() || !tx.IsFinal())
                        continue;

                    // Transaction fee requirements, mainly only needed for flood control
                    // Under 10K (about 80 inputs) is free for first 100 transactions
                    // Base rate is 0.01 per KB
                    int64 nMinFee = tx.GetMinFee(pblock->vtx.size() < 100);

                    map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);
                    if (!tx.ConnectInputs(txdb, mapTestPoolTmp, CDiskTxPos(1,1,1), 0, nFees, false, true, nMinFee))
                        continue;
                    swap(mapTestPool, mapTestPoolTmp);

                    pblock->vtx.push_back(tx);
                    nBlockSize += ::GetSerializeSize(tx, SER_NETWORK);
                    vfAlreadyAdded[n] = true;
                    fFoundSomething = true;
                }
            }
        }
        pblock->nBits = nBits;
        pblock->vtx[0].vout[0].nValue = pblock->GetBlockValue(nBestHeight + 1, nFees);
        if (LogAcceptsCategory("net")) printf("\n\nRunning BitcoinMiner with %d transactions in block\n", (int)pblock->vtx.size());


        //
        // Prepare the block header
        //
        pblock->hashPrevBlock  = (pindexPrev ? pindexPrev->GetBlockHash() : 0);
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        pblock->nTime          = max((pindexPrev ? pindexPrev->GetMedianTimePast()+1 : 0), GetAdjustedTime());
        pblock->nBits          = nBits;
        pblock->nNonce         = 1;


        //
        // Search (memory-hard RandomX PoW) -- each thread uses its own VM
        //
        void* rxvm = RandomXCreateMinerVM();
        if (!rxvm)
        {
            LogPrint("net", "BitcoinMiner: failed to create RandomX VM\n");
            Sleep(1000);
            continue;
        }
        // The thread number is in the line on purpose: every miner would
        // otherwise print the same text, and the dedup filter would fold them
        // into one, leaving no way to tell four threads from one.
        LogPrint("net", "BitcoinMiner: thread %d hashing with RandomX (%s)\n",
               nThreadId, RandomXFastReady() ? "fast 2GB" : "light 256MB");

        unsigned int nStart = GetTime();
        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
        loop
        {
            uint256 hash = RandomXHashWithVM(rxvm, (const void*)BEGIN(pblock->nVersion),
                                             END(pblock->nNonce) - BEGIN(pblock->nVersion));

            if (hash <= hashTarget)
            {
                    //// debug print
                    if (LogAcceptsCategory("net")) printf("BitcoinMiner:\n");
                    if (LogAcceptsCategory("net")) printf("RandomX proof-of-work found  \n  powhash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
                    if (LogAcceptsCategory("net")) pblock->print();

                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
                CRITICAL_BLOCK(cs_main)
                {
                    // Is the parent we solved for still the tip?
                    //
                    // The loop only tests this every 256 hashes, and never
                    // again once a solution turns up. So a thread that found
                    // one just after somebody else extended the chain would
                    // submit a block built on a parent that is no longer the
                    // tip -- a block born orphaned, at a height already taken.
                    //
                    // Every miner thread on this machine works from the same
                    // pindexPrev, so the moment one of them wins, all the
                    // others are hashing a doomed template until their next
                    // checkpoint. On a 32-core box that is thirty threads with
                    // a standing chance of producing a guaranteed orphan, and
                    // it is why a healthy miner's wallet filled up with them.
                    if (pindexPrev != pindexBest)
                    {
                        LogPrint("net", "BitcoinMiner: thread %d solved for a parent that is no longer the tip, discarding\n",
                                 nThreadId);
                    }
                    else
                    {
                        // The key that just got paid was written to wallet.dat
                        // when it left the pool, so there is nothing to save
                        // here -- only a fresh one to take for the next block.
                        // Two threads never draw the same key: the pool hands
                        // them out one at a time under cs_keyPool, which is
                        // what keeps concurrent coinbases distinct (#58).
                        vchPubKey = GetKeyFromPool();
                        if (vchPubKey.empty())
                        {
                            printf("BitcoinMiner: no replacement wallet key available; mining stopped\n");
                            fGenerateBitcoins = false;
                        }

                        // Process this block the same as if we had received it from another node
                        if (!ProcessBlock(NULL, pblock.release()))
                            LogPrint("net", "ERROR in BitcoinMiner, ProcessBlock, block not accepted\n");
                    }
                }
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

                Sleep(500);
                break;
            }

            // Check stop conditions periodically (RandomX is slow, so every
            // ~256 hashes is already plenty of time)
            if ((++pblock->nNonce & 0xff) == 0)
            {
                if (fShutdown)
                    break;          // falls through to RandomXDestroyMinerVM below
                if (pblock->nNonce == 0)
                    break;
                if (pindexPrev != pindexBest)
                    break;
                if (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                    break;
                if (!fGenerateBitcoins)
                    break;
                pblock->nTime = max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());
            }
        }
        RandomXDestroyMinerVM(rxvm);
        if (fShutdown)
            break;
    }

    return true;
}


















//////////////////////////////////////////////////////////////////////////////
//
// Actions
//


WalletRecoveryAudit GetWalletRecoveryAudit()
{
    WalletRecoveryAudit audit;
    set<vector<unsigned char> > setDerivedPubKeys;

    CRITICAL_BLOCK(cs_keyPool)
    {
        audit.fHaveSeed = HaveHDSeed();
        audit.nSchema = nHDKeySchema;
        audit.nDerivedKnown = nHDNext;
        audit.nReceiveNext = nHDReceiveNext;
        audit.nChangeNext = nHDChangeNext;
        audit.nCoinType = nHDCoinType;
        if (nHDKeySchema == HD_SCHEMA_BIP44)
            audit.nDerivedKnown = nHDReceiveNext + nHDChangeNext + nHDNext;
        if (audit.fHaveSeed)
        {
            string strError;
            unsigned int nReceiveDepth = nHDKeySchema == HD_SCHEMA_BIP44
                ? nHDReceiveNext
                : nHDNext;
            for (unsigned int i = 0; i < nReceiveDepth; i++)
            {
                CKey key;
                if (!DeriveHDKey(i, key, strError))
                {
                    audit.fDeriveComplete = false;
                    audit.strDeriveError = strprintf("derivation failed at index %u: %s",
                                                      i, strError.c_str());
                    break;
                }
                setDerivedPubKeys.insert(key.GetPubKey());
            }
            if (nHDKeySchema == HD_SCHEMA_BIP44)
            {
                int nSavedSchema = nHDKeySchema;
                for (unsigned int i = 0; i < nHDChangeNext; i++)
                {
                    CKey key;
                    if (!DeriveHDChangeKey(i, key, strError))
                    {
                        audit.fDeriveComplete = false;
                        audit.strDeriveError = strprintf("change derivation failed at index %u: %s",
                                                          i, strError.c_str());
                        break;
                    }
                    setDerivedPubKeys.insert(key.GetPubKey());
                }
                nHDKeySchema = HD_SCHEMA_LEGACY;
                for (unsigned int i = 0; i < nHDNext; i++)
                {
                    CKey key;
                    if (!DeriveHDKey(i, key, strError))
                    {
                        audit.fDeriveComplete = false;
                        audit.strDeriveError = strprintf("legacy compatibility derivation failed at index %u: %s",
                                                          i, strError.c_str());
                        break;
                    }
                    setDerivedPubKeys.insert(key.GetPubKey());
                }
                nHDKeySchema = nSavedSchema;
            }
        }
    }

    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            CWalletTx& wtx = (*it).second;
            if (!wtx.IsFinal() || wtx.fSpent)
                continue;
            bool fImmature = wtx.IsCoinBase() && wtx.GetBlocksToMaturity() > 0;

            bool fTxRecoverable = false;
            bool fTxLegacy = false;
            for (int i = 0; i < (int)wtx.vout.size(); i++)
            {
                const CTxOut& txout = wtx.vout[i];
                if (!txout.IsMine())
                    continue;

                vector<unsigned char> vchPubKey;
                bool fRecoverable = false;
                if (audit.fHaveSeed && ExtractPubKey(txout.scriptPubKey, true, vchPubKey))
                    fRecoverable = setDerivedPubKeys.count(vchPubKey) > 0;

                if (fRecoverable)
                {
                    if (fImmature)
                        audit.nRecoverableImmatureCredit += txout.nValue;
                    else
                        audit.nRecoverableCredit += txout.nValue;
                    fTxRecoverable = true;
                }
                else
                {
                    if (fImmature)
                        audit.nLegacyImmatureCredit += txout.nValue;
                    else
                        audit.nLegacyCredit += txout.nValue;
                    fTxLegacy = true;
                }
            }

            if (fTxRecoverable)
            {
                if (fImmature)
                    audit.nRecoverableImmatureTx++;
                else
                    audit.nRecoverableTx++;
            }
            if (fTxLegacy)
            {
                if (fImmature)
                    audit.nLegacyImmatureTx++;
                else
                    audit.nLegacyTx++;
            }
        }
    }

    return audit;
}

int64 GetBalance()
{
    int64 nStart, nEnd;
    QueryPerformanceCounter((LARGE_INTEGER*)&nStart);

    int64 nTotal = 0;
    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || pcoin->fSpent)
                continue;
            nTotal += pcoin->GetCredit();
        }
    }

    QueryPerformanceCounter((LARGE_INTEGER*)&nEnd);
    ///printf(" GetBalance() time = %16lld\n", nEnd - nStart);
    return nTotal;
}



bool SelectCoins(int64 nTargetValue, set<CWalletTx*>& setCoinsRet)
{
    setCoinsRet.clear();

    // List of values less than target
    int64 nLowestLarger = _I64_MAX;
    CWalletTx* pcoinLowestLarger = NULL;
    vector<pair<int64, CWalletTx*> > vValue;
    int64 nTotalLower = 0;

    CRITICAL_BLOCK(cs_mapWallet)
    {
        for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || pcoin->fSpent)
                continue;
            int64 n = pcoin->GetCredit();
            if (n <= 0)
                continue;
            if (n < nTargetValue)
            {
                vValue.push_back(make_pair(n, pcoin));
                nTotalLower += n;
            }
            else if (n == nTargetValue)
            {
                setCoinsRet.insert(pcoin);
                return true;
            }
            else if (n < nLowestLarger)
            {
                nLowestLarger = n;
                pcoinLowestLarger = pcoin;
            }
        }
    }

    if (nTotalLower < nTargetValue)
    {
        if (pcoinLowestLarger == NULL)
            return false;
        setCoinsRet.insert(pcoinLowestLarger);
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend());
    vector<char> vfIncluded;
    vector<char> vfBest(vValue.size(), true);
    int64 nBest = nTotalLower;

    for (int nRep = 0; nRep < 1000 && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64 nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (int i = 0; i < vValue.size(); i++)
            {
                if (nPass == 0 ? rand() % 2 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }

    // If the next larger is still closer, return it
    if (pcoinLowestLarger && nLowestLarger - nTargetValue <= nBest - nTargetValue)
        setCoinsRet.insert(pcoinLowestLarger);
    else
    {
        for (int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                setCoinsRet.insert(vValue[i].second);

        //// debug print
        if (LogAcceptsCategory("net")) printf("SelectCoins() best subset: ");
        for (int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                if (LogAcceptsCategory("net")) printf("%s ", FormatMoney(vValue[i].first).c_str());
        if (LogAcceptsCategory("net")) printf("total %s\n", FormatMoney(nBest).c_str());
    }

    return true;
}




bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, int64& nFeeRequiredRet)
{
    nFeeRequiredRet = 0;
    CRITICAL_BLOCK(cs_main)
    {
        // txdb must be opened before the mapWallet lock
        CTxDB txdb("r");
        CRITICAL_BLOCK(cs_mapWallet)
        {
            int64 nFee = nTransactionFee;
            loop
            {
                wtxNew.vin.clear();
                wtxNew.vout.clear();
                if (nValue < 0)
                    return false;

                // nValue is the amount the payee asked for and must stay that.
                //
                // This used to read "nValueOut = nValue; nValue += nFee;", and
                // both lines are inside the retry loop. The first pass was
                // fine. But when the fee turned out to be too low the loop
                // starts over, and on the second pass nValueOut is read from
                // an nValue that already had the fee added -- so the payee is
                // sent the amount plus the fee, and it compounds on every
                // further retry, with the sender covering it.
                //
                // The retry fires whenever GetMinFee exceeds the fee we
                // guessed, which for this fee schedule means any transaction
                // over 10 KB: a wallet paying from many small inputs. Bitcoin
                // fixed this in 107d9e288.
                int64 nTotalValue = nValue + nFee;

                // Choose coins to use
                set<CWalletTx*> setCoins;
                if (!SelectCoins(nTotalValue, setCoins))
                    return false;
                int64 nValueIn = 0;
                foreach(CWalletTx* pcoin, setCoins)
                    nValueIn += pcoin->GetCredit();

                // Fill vout[0] to the payee
                wtxNew.vout.push_back(CTxOut(nValue, scriptPubKey));

                // Fill vout[1] back to self with any change
                if (nValueIn > nTotalValue)
                {
                    vector<unsigned char> vchPubKey;
                    if (HaveHDSeed())
                    {
                        string strError;
                        if (!DeriveNextHDChangeKey(vchPubKey, strError))
                        {
                            printf("CreateTransaction() : could not derive a phrase-backed change key: %s\n",
                                   strError.c_str());
                            return false;
                        }
                    }
                    else
                    {
                        // Legacy wallets have no deterministic seed. Preserve
                        // the 0.1.0 behaviour for them: return change to a key
                        // already proven to belong to this wallet.
                        CTransaction& txFirst = *(*setCoins.begin());
                        foreach(const CTxOut& txout, txFirst.vout)
                            if (txout.IsMine())
                                if (ExtractPubKey(txout.scriptPubKey, true, vchPubKey))
                                    break;
                    }
                    if (vchPubKey.empty())
                        return false;

                    // Fill vout[1] to ourself
                    CScript scriptPubKey;
                    scriptPubKey << vchPubKey << OP_CHECKSIG;
                    wtxNew.vout.push_back(CTxOut(nValueIn - nTotalValue, scriptPubKey));
                }

                // Fill vin
                foreach(CWalletTx* pcoin, setCoins)
                    for (int nOut = 0; nOut < pcoin->vout.size(); nOut++)
                        if (pcoin->vout[nOut].IsMine())
                            wtxNew.vin.push_back(CTxIn(pcoin->GetHash(), nOut));

                // Sign
                int nIn = 0;
                foreach(CWalletTx* pcoin, setCoins)
                    for (int nOut = 0; nOut < pcoin->vout.size(); nOut++)
                        if (pcoin->vout[nOut].IsMine())
                            SignSignature(*pcoin, wtxNew, nIn++);

                // Check that enough fee is included
                if (nFee < wtxNew.GetMinFee(true))
                {
                    nFee = nFeeRequiredRet = wtxNew.GetMinFee(true);
                    continue;
                }

                // Fill vtxPrev by copying from previous transactions vtxPrev
                wtxNew.AddSupportingTransactions(txdb);
                wtxNew.fTimeReceivedIsTxTime = true;

                break;
            }
        }
    }
    return true;
}

// Undo what CommitTransactionSpent did: unmark the inputs it marked spent
// and erase the half-committed wallet entry. Used when a transaction is
// accepted into the wallet but then rejected by the mempool/chain, so we
// don't end up with a wallet that thinks money is spent that never left.
void RollbackTransactionSpent(const CWalletTx& wtxNew)
{
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapWallet)
    {
        set<CWalletTx*> setCoins;
        foreach(const CTxIn& txin, wtxNew.vin)
        {
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
            if (mi != mapWallet.end())
                setCoins.insert(&mi->second);
        }
        foreach(CWalletTx* pcoin, setCoins)
        {
            pcoin->fSpent = false;
            pcoin->WriteToDisk();
            vWalletUpdated.push_back(make_pair(pcoin->GetHash(), false));
        }

        EraseFromWallet(wtxNew.GetHash());
    }
    MainFrameRepaint();
}

// Call after CreateTransaction unless you want to abort
bool CommitTransactionSpent(const CWalletTx& wtxNew)
{
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapWallet)
    {
        //// todo: make this transactional, never want to add a transaction
        ////  without marking spent transactions

        // Add tx to wallet, because if it has change it's also ours,
        // otherwise just for transaction history.
        AddToWallet(wtxNew);

        // Mark old coins as spent
        set<CWalletTx*> setCoins;
        foreach(const CTxIn& txin, wtxNew.vin)
            setCoins.insert(&mapWallet[txin.prevout.hash]);
        foreach(CWalletTx* pcoin, setCoins)
        {
            pcoin->fSpent = true;
            pcoin->WriteToDisk();
            vWalletUpdated.push_back(make_pair(pcoin->GetHash(), false));
        }
    }
    MainFrameRepaint();
    return true;
}




bool SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew)
{
    CRITICAL_BLOCK(cs_main)
    {
        int64 nFeeRequired;
        if (!CreateTransaction(scriptPubKey, nValue, wtxNew, nFeeRequired))
        {
            string strError;
            if (nValue + nFeeRequired > GetBalance())
                strError = strprintf("Error: This is an oversized transaction that requires a transaction fee of %s ", FormatMoney(nFeeRequired).c_str());
            else
                strError = "Error: Transaction creation failed ";
            return error("SendMoney() : %s\n", strError.c_str());
        }
        if (!CommitTransactionSpent(wtxNew))
        {
            return error("SendMoney() : Error finalizing transaction");
        }

        if (LogAcceptsCategory("net")) printf("SendMoney: %s\n", wtxNew.GetHash().ToString().substr(0,6).c_str());

        // Broadcast
        if (!wtxNew.AcceptTransaction())
        {
            // The transaction was already signed and committed to the wallet
            // above, but the chain/mempool just rejected it (e.g. a raced
            // input already spent by another transaction). Unwind the
            // wallet state we just wrote instead of crashing the app.
            RollbackTransactionSpent(wtxNew);
            return error("SendMoney() : wtxNew.AcceptTransaction() failed");
        }
        wtxNew.RelayWalletTransaction();
    }
    MainFrameRepaint();
    return true;
}
