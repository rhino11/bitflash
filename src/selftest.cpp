// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Integration self-tests that need the real wallet/database code linked into
// the node. These are intentionally run behind an explicit command-line flag
// and against a temporary data directory.

#include "headers_core.h"
#include "bip32.h"
#include "selftest.h"
#include "walletcmd.h"

// Test results go to the terminal, not to debug.log.
//
// printf in this tree is OutputDebugStringF, which writes into the data
// directory's debug.log and binds that path, once, on its first call. For a
// self-test that produced two bad outcomes at the same time. On Windows the
// binary is linked -mwindows and has no console, so `make tests` printed the
// bip32 results, echoed the self-test command, and then showed nothing at all --
// a failure was still caught, because a non-zero return stops make, but it
// arrived with no way to tell which check failed. And because the first line
// printed before strSetDataDir was pointed at the temporary directory, every
// line landed in the developer's real debug.log: the same file users are asked
// to paste into issues.
//
// Undefining the macro here gives this file the real printf, so results reach
// stdout. Nothing else in the tree is affected.
#undef printf

#include <mutex>
#include <stdexcept>
#include <thread>

#ifdef _WIN32
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

static std::string HexStrLocal(const std::vector<unsigned char>& v)
{
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (unsigned char c : v)
    {
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0x0f]);
    }
    return out;
}

static bool MakeTempDir(std::string& out)
{
#ifdef _WIN32
    char base[MAX_PATH + 1] = {0};
    if (!GetTempPathA(MAX_PATH, base))
        return false;
    for (int i = 0; i < 100; i++)
    {
        std::string path = strprintf("%sbitflash-selftest-%lu-%lld-%d",
            base, (unsigned long)GetCurrentProcessId(), (long long)GetTime(), i);
        if (CreateDirectoryA(path.c_str(), NULL))
        {
            out = path;
            return true;
        }
    }
    return false;
#else
    char tmpl[256];
    snprintf(tmpl, sizeof(tmpl), "/tmp/bitflash-selftest-%ld-XXXXXX", (long)getpid());
    char* p = mkdtemp(tmpl);
    if (!p)
        return false;
    out = p;
    return true;
#endif
}

static bool GetCurrentDir(std::string& out)
{
#ifdef _WIN32
    char buf[MAX_PATH + 1] = {0};
    DWORD n = GetCurrentDirectoryA(MAX_PATH, buf);
    if (n == 0 || n > MAX_PATH)
        return false;
    out = buf;
    return true;
#else
    char buf[4096];
    if (!getcwd(buf, sizeof(buf)))
        return false;
    out = buf;
    return true;
#endif
}

static bool SetCurrentDir(const std::string& path)
{
#ifdef _WIN32
    return SetCurrentDirectoryA(path.c_str()) != 0;
#else
    return chdir(path.c_str()) == 0;
#endif
}

static void RemoveTree(const std::string& path)
{
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
        return;
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY))
    {
        DeleteFileA(path.c_str());
        return;
    }

    WIN32_FIND_DATAA findData;
    std::string pattern = path + "\\*";
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            std::string name = findData.cFileName;
            if (name == "." || name == "..")
                continue;
            RemoveTree(path + "\\" + name);
        }
        while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    RemoveDirectoryA(path.c_str());
#else
    struct stat st;
    if (lstat(path.c_str(), &st) != 0)
        return;
    if (!S_ISDIR(st.st_mode))
    {
        unlink(path.c_str());
        return;
    }

    DIR* dir = opendir(path.c_str());
    if (dir)
    {
        struct dirent* ent;
        while ((ent = readdir(dir)) != NULL)
        {
            std::string name = ent->d_name;
            if (name == "." || name == "..")
                continue;
            RemoveTree(path + "/" + name);
        }
        closedir(dir);
    }
    rmdir(path.c_str());
#endif
}

static bool WalletHasPrivateKey(const std::vector<unsigned char>& vchPubKey)
{
    CPrivKey priv;
    return CWalletDB("r").ReadKey(vchPubKey, priv) && !priv.empty();
}

static bool Check(bool condition, const char* message)
{
    if (condition)
    {
        printf("  ok   %s\n", message);
        return true;
    }
    printf("  FAIL %s\n", message);
    return false;
}

static int RunWalletKeyPoolSelfTest()
{
    fflush(stdout);
    printf("wallet-keypool self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    // Before anything can open the database or resolve the log path: what the
    // node itself prints during the test belongs in the temporary directory,
    // and dies with it. The test's own results are on stdout, above.
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    try
    {
        if (!LoadWallet())
            throw std::runtime_error("LoadWallet failed");

        TopUpKeyPool();
        int nInitialPoolSize = 0;
        CRITICAL_BLOCK(cs_keyPool)
            nInitialPoolSize = (int)mapKeyPool.size();
        nFail += Check(nInitialPoolSize == KEYPOOL_SIZE, "TopUpKeyPool fills the pool") ? 0 : 1;

        bool fPooledKeysStored = true;
        CRITICAL_BLOCK(cs_keyPool)
        {
            for (map<int64, vector<unsigned char> >::const_iterator mi = mapKeyPool.begin();
                 mi != mapKeyPool.end(); ++mi)
                if (!WalletHasPrivateKey(mi->second))
                    fPooledKeysStored = false;
        }
        nFail += Check(fPooledKeysStored, "every pooled public key has a stored private key") ? 0 : 1;

        std::vector<std::vector<unsigned char> > drawn;
        std::mutex drawnMutex;
        const int nThreads = 8;
        const int nDrawsPerThread = 32;
        std::vector<std::thread> threads;

        for (int t = 0; t < nThreads; t++)
        {
            threads.emplace_back([&drawn, &drawnMutex, nDrawsPerThread]() {
                for (int i = 0; i < nDrawsPerThread; i++)
                {
                    std::vector<unsigned char> key = GetKeyFromPool();
                    std::lock_guard<std::mutex> lock(drawnMutex);
                    drawn.push_back(key);
                }
            });
        }
        for (std::thread& t : threads)
            t.join();

        nFail += Check((int)drawn.size() == nThreads * nDrawsPerThread,
                       "all concurrent draws returned a key") ? 0 : 1;

        std::set<std::string> seen;
        bool fUnique = true;
        bool fAllStored = true;
        for (const std::vector<unsigned char>& key : drawn)
        {
            if (!seen.insert(HexStrLocal(key)).second)
                fUnique = false;
            if (!WalletHasPrivateKey(key))
                fAllStored = false;
        }

        nFail += Check(fUnique, "concurrent draws never return the same key") ? 0 : 1;
        nFail += Check(fAllStored, "each drawn key was already stored in wallet.dat") ? 0 : 1;
        int nPoolSize = 0;
        CRITICAL_BLOCK(cs_keyPool)
            nPoolSize = (int)mapKeyPool.size();
        nFail += Check(nPoolSize == KEYPOOL_SIZE, "drawing leaves the key pool topped up") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

// AttachTerminal() moved to util.h: the wallet phrase commands need it too,
// and two copies of a console-attach that must get its one condition right is
// one copy too many.

static int RunWalletHDSelfTest()
{
    fflush(stdout);
    printf("wallet-hd self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    // Test-vector phrases, so nothing here depends on randomness.
    const std::string strPhraseA =
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about";
    const std::string strPhraseB =
        "legal winner thank year wave sausage worth useful "
        "legal winner thank yellow";

    try
    {
        if (!LoadWallet())
            throw std::runtime_error("LoadWallet failed");

        std::string strError;
        TopUpKeyPool();
        int nRandomPoolSize = 0;
        CRITICAL_BLOCK(cs_keyPool)
            nRandomPoolSize = (int)mapKeyPool.size();
        nFail += Check(nRandomPoolSize == KEYPOOL_SIZE,
                       "a wallet can start with a random key pool") ? 0 : 1;

        // The address the wallet was showing before any of this. It has to
        // survive under a name that says it is not covered by the phrase.
        std::vector<unsigned char> vchPreSeedKey = keyUser.GetPubKey();
        std::string strPreSeedAddr = PubKeyToAddress(keyUser.GetPubKey());

        nFail += Check(SetHDSeedFromMnemonic(strPhraseA, strError),
                       "a valid phrase installs a seed") ? 0 : 1;
        nFail += Check(HaveHDSeed(), "the wallet reports having a seed") ? 0 : 1;
        nFail += Check(nHDKeySchema == HD_SCHEMA_BIP44,
                       "a new recovery phrase records the BIP44 HD schema") ? 0 : 1;
        nFail += Check(nHDCoinType == HD_BIP44_COIN_TYPE_BITFLASH_PROVISIONAL,
                       "a new recovery phrase records the provisional BIP44 coin type") ? 0 : 1;
        nFail += Check(nHDReceiveNext == 1 && nHDChangeNext == 0,
                       "BIP44 receive/change counters reserve the default receive key") ? 0 : 1;
        std::vector<unsigned int> vBIP44Path = HDBIP44Path(HD_BIP44_COIN_TYPE_BITFLASH_PROVISIONAL,
                                                           HD_BIP44_ACCOUNT,
                                                           HD_BIP44_CHAIN_RECEIVE,
                                                           0);
        nFail += Check(vBIP44Path.size() == 5 &&
                       vBIP44Path[0] == (HD_BIP44_PURPOSE | bitflash::BIP32_HARDENED) &&
                       vBIP44Path[1] == (HD_BIP44_COIN_TYPE_BITFLASH_PROVISIONAL | bitflash::BIP32_HARDENED) &&
                       vBIP44Path[2] == (HD_BIP44_ACCOUNT | bitflash::BIP32_HARDENED) &&
                       vBIP44Path[3] == HD_BIP44_CHAIN_RECEIVE &&
                       vBIP44Path[4] == 0,
                       "the BIP44 helper builds m/44'/coin_type'/account'/change/index") ? 0 : 1;

        int nPoolAfterSeed = 0;
        CRITICAL_BLOCK(cs_keyPool)
            nPoolAfterSeed = (int)mapKeyPool.size();
        nFail += Check(nPoolAfterSeed == 0,
                       "installing a phrase clears the old random key pool") ? 0 : 1;
        nFail += Check(nHDNext == 0,
                       "installing a BIP44 phrase leaves the legacy counter unused") ? 0 : 1;

        CKey keyFirstDerived;
        if (!DeriveHDKey(0, keyFirstDerived, strError))
            throw std::runtime_error("default derivation failed: " + strError);
        bitflash::BIP32PrivateNode hdParent;
        hdParent.privateKey = vchHDMaster;
        hdParent.chainCode = vchHDChainCode;
        bitflash::BIP32PrivateNode hdBIP44ReceiveChild;
        if (!bitflash::BIP32DerivePath(hdParent,
                                       HDBIP44Path(HD_BIP44_COIN_TYPE_BITFLASH_PROVISIONAL,
                                                   HD_BIP44_ACCOUNT,
                                                   HD_BIP44_CHAIN_RECEIVE,
                                                   0),
                                       hdBIP44ReceiveChild,
                                       strError))
            throw std::runtime_error("BIP44 receive path derivation failed: " + strError);
        CKey keyBIP44ReceivePath;
        if (!keyBIP44ReceivePath.SetSecret(hdBIP44ReceiveChild.privateKey))
            throw std::runtime_error("BIP44 receive path produced an unusable key");
        nFail += Check(keyBIP44ReceivePath.GetPubKey() == keyFirstDerived.GetPubKey(),
                       "the default HD key path is m/44'/coin_type'/0'/0/0") ? 0 : 1;

        bitflash::BIP32PrivateNode hdLegacyChild;
        int nSchemaForLegacyCheck = nHDKeySchema;
        nHDKeySchema = HD_SCHEMA_LEGACY;
        CKey keyLegacyDerived;
        if (!DeriveHDKey(0, keyLegacyDerived, strError))
            throw std::runtime_error("legacy derivation failed: " + strError);
        nHDKeySchema = nSchemaForLegacyCheck;
        if (!bitflash::BIP32DerivePath(hdParent, HDLegacyPath(0), hdLegacyChild, strError))
            throw std::runtime_error("legacy path derivation failed: " + strError);
        CKey keyLegacyPath;
        if (!keyLegacyPath.SetSecret(hdLegacyChild.privateKey))
            throw std::runtime_error("legacy path produced an unusable key");
        nFail += Check(keyLegacyPath.GetPubKey() == keyLegacyDerived.GetPubKey(),
                       "the legacy HD key path remains m/index'") ? 0 : 1;

        std::vector<unsigned char> vchDefaultKey;
        bool fDefaultRead = CWalletDB("r").ReadDefaultKey(vchDefaultKey);
        nFail += Check(fDefaultRead && vchDefaultKey == keyFirstDerived.GetPubKey(),
                       "the default receiving key is derived from the phrase") ? 0 : 1;
        nFail += Check(WalletHasPrivateKey(vchDefaultKey),
                       "the derived default key is stored in wallet.dat") ? 0 : 1;

        std::string strNewAddr = PubKeyToAddress(vchDefaultKey);
        nFail += Check(strPreSeedAddr != strNewAddr,
                       "the visible address stops being the pre-seed one") ? 0 : 1;
        nFail += Check(mapAddressBook.count(strPreSeedAddr) > 0 &&
                       mapAddressBook[strPreSeedAddr] !=
                           mapAddressBook[strNewAddr],
                       "the pre-seed address is kept, named apart from the new one") ? 0 : 1;

        std::vector<unsigned char> vchBefore = vchHDMaster;
        int nSchemaBefore = nHDKeySchema;
        unsigned int nCoinTypeBefore = nHDCoinType;
        nFail += Check(!SetHDSeedFromMnemonic("not a mnemonic at all", strError),
                       "an invalid phrase is refused") ? 0 : 1;
        nFail += Check(vchHDMaster == vchBefore,
                       "a refused phrase leaves the existing seed alone") ? 0 : 1;
        nFail += Check(nHDKeySchema == nSchemaBefore,
                       "a refused phrase leaves the derivation schema alone") ? 0 : 1;
        nFail += Check(nHDCoinType == nCoinTypeBefore,
                       "a refused phrase leaves the BIP44 coin type alone") ? 0 : 1;

        // The property the whole feature exists for: the same words give back
        // the same keys, in the same order.
        std::vector<std::string> first;
        for (unsigned int i = 0; i < 5; i++)
        {
            CKey key;
            if (!DeriveHDKey(i, key, strError))
                throw std::runtime_error("derivation failed: " + strError);
            first.push_back(HexStrLocal(key.GetPubKey()));
        }

        SetHDSeedFromMnemonic(strPhraseA, strError);
        std::vector<std::string> again;
        for (unsigned int i = 0; i < 5; i++)
        {
            CKey key;
            if (!DeriveHDKey(i, key, strError))
                throw std::runtime_error("derivation failed: " + strError);
            again.push_back(HexStrLocal(key.GetPubKey()));
        }
        nFail += Check(first == again,
                       "the same phrase derives the same keys in the same order") ? 0 : 1;

        SetHDSeedFromMnemonic(strPhraseB, strError);
        std::vector<std::string> other;
        for (unsigned int i = 0; i < 5; i++)
        {
            CKey key;
            if (!DeriveHDKey(i, key, strError))
                throw std::runtime_error("derivation failed: " + strError);
            other.push_back(HexStrLocal(key.GetPubKey()));
        }
        nFail += Check(first != other, "a different phrase derives different keys") ? 0 : 1;

        std::set<std::string> distinct(first.begin(), first.end());
        nFail += Check(distinct.size() == first.size(),
                       "consecutive indices give distinct keys") ? 0 : 1;

        // With a seed installed the pool must be derived from it, and the
        // counter must move exactly once per key.
        SetHDSeedFromMnemonic(strPhraseA, strError);
        unsigned int nReceiveNextBefore = nHDReceiveNext;
        TopUpKeyPool();

        int nPool = 0;
        CRITICAL_BLOCK(cs_keyPool)
            nPool = (int)mapKeyPool.size();
        nFail += Check(nPool == KEYPOOL_SIZE, "the derived pool fills") ? 0 : 1;
        nFail += Check(nHDReceiveNext == nReceiveNextBefore + (unsigned int)KEYPOOL_SIZE,
                       "the BIP44 receive counter advances once per pooled key") ? 0 : 1;
        nFail += Check(nHDChangeNext == 0,
                       "filling the receive pool leaves the BIP44 change counter alone") ? 0 : 1;
        nFail += Check(!RestoreScanReachedDepth(HD_SCHEMA_BIP44, 600, 400, 600, 600),
                       "BIP44 restore depth is not satisfied by receive plus legacy alone") ? 0 : 1;
        nFail += Check(RestoreScanReachedDepth(HD_SCHEMA_BIP44, 600, 600, 600, 600),
                       "BIP44 restore depth is satisfied on each branch") ? 0 : 1;
        nFail += Check(RestoreScanReachedDepth(HD_SCHEMA_LEGACY, 0, 0, 600, 600),
                       "legacy restore depth still follows the legacy counter") ? 0 : 1;

        std::set<std::string> derived;
        for (unsigned int i = nReceiveNextBefore; i < nHDReceiveNext; i++)
        {
            CKey key;
            if (!DeriveHDKey(i, key, strError))
                throw std::runtime_error("derivation failed: " + strError);
            derived.insert(HexStrLocal(key.GetPubKey()));
        }

        bool fStored = true;
        bool fFromSeed = true;
        CRITICAL_BLOCK(cs_keyPool)
        {
            for (map<int64, vector<unsigned char> >::const_iterator mi = mapKeyPool.begin();
                 mi != mapKeyPool.end(); ++mi)
            {
                if (!WalletHasPrivateKey(mi->second))
                    fStored = false;
                if (!derived.count(HexStrLocal(mi->second)))
                    fFromSeed = false;
            }
        }
        nFail += Check(fStored, "every derived pooled key is stored in wallet.dat") ? 0 : 1;
        nFail += Check(fFromSeed, "every pooled key came from the seed, not from chance") ? 0 : 1;

        // A recovery phrase is only useful if the wallet can tell the user
        // what today's spendable balance would actually come back from it.
        CKey keyAuditDerived;
        if (!DeriveHDKey(0, keyAuditDerived, strError))
            throw std::runtime_error("audit derivation failed: " + strError);
        CKey keyAuditChange;
        if (!DeriveHDChangeKey(0, keyAuditChange, strError))
            throw std::runtime_error("audit change derivation failed: " + strError);
        nFail += Check(keyAuditChange.GetPubKey() != keyAuditDerived.GetPubKey(),
                       "BIP44 receive and change chains derive different keys") ? 0 : 1;
        if (!AddKey(keyAuditChange))
            throw std::runtime_error("could not store the audit change key");
        nHDChangeNext = 1;
        int nSchemaForLegacyAudit = nHDKeySchema;
        nHDKeySchema = HD_SCHEMA_LEGACY;
        CKey keyAuditLegacyHD;
        if (!DeriveHDKey(0, keyAuditLegacyHD, strError))
            throw std::runtime_error("audit legacy compatibility derivation failed: " + strError);
        nHDKeySchema = nSchemaForLegacyAudit;
        if (!AddKey(keyAuditLegacyHD))
            throw std::runtime_error("could not store the audit legacy compatibility key");
        nHDNext = 1;

        CWalletTx wtxLegacy;
        wtxLegacy.vout.push_back(CTxOut(5 * COIN, CScript() << vchPreSeedKey << OP_CHECKSIG));
        CWalletTx wtxDerived;
        wtxDerived.vout.push_back(CTxOut(7 * COIN, CScript() << keyAuditDerived.GetPubKey() << OP_CHECKSIG));
        CWalletTx wtxChange;
        wtxChange.vout.push_back(CTxOut(13 * COIN, CScript() << keyAuditChange.GetPubKey() << OP_CHECKSIG));
        CWalletTx wtxLegacyHD;
        wtxLegacyHD.vout.push_back(CTxOut(17 * COIN, CScript() << keyAuditLegacyHD.GetPubKey() << OP_CHECKSIG));
        CWalletTx wtxImmatureLegacy;
        wtxImmatureLegacy.vin.push_back(CTxIn());
        wtxImmatureLegacy.vout.push_back(CTxOut(11 * COIN, CScript() << vchPreSeedKey << OP_CHECKSIG));

        CRITICAL_BLOCK(cs_mapWallet)
        {
            mapWallet.clear();
            mapWallet[wtxLegacy.GetHash()] = wtxLegacy;
            mapWallet[wtxDerived.GetHash()] = wtxDerived;
            mapWallet[wtxChange.GetHash()] = wtxChange;
            mapWallet[wtxLegacyHD.GetHash()] = wtxLegacyHD;
            mapWallet[wtxImmatureLegacy.GetHash()] = wtxImmatureLegacy;
        }

        WalletRecoveryAudit audit = GetWalletRecoveryAudit();
        nFail += Check(audit.fHaveSeed, "the recovery audit reports the phrase") ? 0 : 1;
        nFail += Check(audit.nSchema == HD_SCHEMA_BIP44,
                       "the recovery audit reports the derivation schema") ? 0 : 1;
        nFail += Check(audit.nCoinType == HD_BIP44_COIN_TYPE_BITFLASH_PROVISIONAL,
                       "the recovery audit reports the BIP44 coin type") ? 0 : 1;
        nFail += Check(audit.nReceiveNext == nHDReceiveNext && audit.nChangeNext == 1,
                       "the recovery audit reports receive/change counters") ? 0 : 1;
        nFail += Check(audit.nLegacyCredit == 5 * COIN,
                       "the recovery audit finds wallet.dat-only balance") ? 0 : 1;
        nFail += Check(audit.nRecoverableCredit == 37 * COIN,
                       "the recovery audit finds BIP44 and legacy-HD phrase balance") ? 0 : 1;
        nFail += Check(audit.nLegacyTx == 1 && audit.nRecoverableTx == 3,
                       "the recovery audit counts wallet.dat-only and phrase-backed transactions") ? 0 : 1;
        nFail += Check(audit.nLegacyImmatureCredit == 11 * COIN,
                       "the recovery audit finds wallet.dat-only immature mining rewards") ? 0 : 1;
        nFail += Check(audit.nLegacyImmatureTx == 1,
                       "the recovery audit counts wallet.dat-only immature mining rewards") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunWalletFormatSelfTest()
{
    fflush(stdout);
    printf("wallet-format self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    try
    {
        class CWalletDBRaw : public CWalletDB
        {
        public:
            CWalletDBRaw(const char* pszMode="r+") : CWalletDB(pszMode) { }
            bool WriteStringRecord(const string& strType, int nValue)
            {
                return Write(strType, nValue);
            }
            bool EraseStringRecord(const string& strType)
            {
                return Erase(strType);
            }
        };

        if (!LoadWallet())
            throw std::runtime_error("LoadWallet failed");

        {
            CWalletDB walletdb;
            nFail += Check(walletdb.WriteWalletMinVersion(WALLET_FORMAT_SUPPORTED),
                           "the current wallet format marker can be written") ? 0 : 1;
        }

        std::vector<unsigned char> vchDefaultKey;
        nFail += Check(CWalletDB("r").LoadWallet(vchDefaultKey),
                       "the current wallet format marker loads") ? 0 : 1;

        {
            CWalletDBRaw walletdb;
            nFail += Check(walletdb.WriteStringRecord("mkey", 1),
                           "a malformed encrypted master-key record can be written") ? 0 : 1;
        }

        vchDefaultKey.clear();
        nFail += Check(!CWalletDB("r").LoadWallet(vchDefaultKey),
                       "a malformed encrypted master-key record is refused") ? 0 : 1;

        {
            CWalletDBRaw walletdb;
            nFail += Check(walletdb.EraseStringRecord("mkey"),
                           "the malformed encrypted master-key record can be removed") ? 0 : 1;
        }

        {
            CWalletDB walletdb;
            nFail += Check(walletdb.WriteWalletMinVersion(WALLET_FORMAT_SUPPORTED + 1),
                           "a future wallet format marker can be written") ? 0 : 1;
        }

        vchDefaultKey.clear();
        nFail += Check(!CWalletDB("r").LoadWallet(vchDefaultKey),
                       "a future wallet format marker is refused") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static void ClearWalletRuntimeForTest()
{
    CRITICAL_BLOCK(cs_mapKeys)
    {
        mapKeys.clear();
        mapCryptedKeys.clear();
        mapPubKeys.clear();
        mapMasterKeys.clear();
        vWalletMasterKey.clear();
        vchCryptedHDMaster.clear();
        vchCryptedHDChainCode.clear();
        fWalletEncrypted = false;
        fWalletLocked = true;
    }
    CRITICAL_BLOCK(cs_keyPool)
        mapKeyPool.clear();
    vchHDMaster.clear();
    vchHDChainCode.clear();
    nHDNext = 0;
}

static int RunWalletCryptoSelfTest()
{
    fflush(stdout);
    printf("wallet-crypto self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    try
    {
        const string strPassphrase = "btf-test-passphrase";
        const string strWrongPassphrase = "btf-test-passphraser";

        CKey key;
        key.MakeNewKey();
        vector<unsigned char> vchPubKey = key.GetPubKey();
        CPrivKey vchPrivKey = key.GetPrivKey();

        CKeyingMaterial vchMasterKey;
        for (int i = 0; i < 32; i++)
            vchMasterKey.push_back((unsigned char)(i + 1));

        CWalletMasterKey kMasterKey;
        kMasterKey.vchSalt.clear();
        for (int i = 0; i < 8; i++)
            kMasterKey.vchSalt.push_back((unsigned char)(0xa0 + i));
        kMasterKey.nDeriveIterations = 2500;

        CKeyingMaterial vchPassKey;
        vector<unsigned char> vchPassIV;
        nFail += Check(DeriveWalletPassphraseKey(strPassphrase, kMasterKey.vchSalt,
                                                 kMasterKey.nDeriveIterations,
                                                 vchPassKey, vchPassIV),
                       "a passphrase key can be derived") ? 0 : 1;
        nFail += Check(EncryptSecret(vchPassKey,
                                     vector<unsigned char>(vchMasterKey.begin(), vchMasterKey.end()),
                                     vchPassIV, kMasterKey.vchCryptedKey),
                       "the wallet master key can be encrypted") ? 0 : 1;

        vector<unsigned char> vchCryptedKey;
        nFail += Check(EncryptSecret(vchMasterKey,
                                     vector<unsigned char>(vchPrivKey.begin(), vchPrivKey.end()),
                                     WalletKeyIV(vchPubKey), vchCryptedKey),
                       "a private key can be encrypted under the wallet master key") ? 0 : 1;

        {
            CWalletDB walletdb("cr");
            nFail += Check(walletdb.WriteWalletMinVersion(WALLET_FORMAT_ENCRYPTED),
                           "an encrypted wallet format marker can be written") ? 0 : 1;
            nFail += Check(walletdb.WriteMasterKey(0, kMasterKey),
                           "the encrypted master key can be written") ? 0 : 1;
            nFail += Check(walletdb.WriteCryptedKey(vchPubKey, vchCryptedKey),
                           "the encrypted private key can be written") ? 0 : 1;
            nFail += Check(walletdb.WriteDefaultKey(vchPubKey),
                           "the encrypted wallet default key can be written") ? 0 : 1;
        }

        ClearWalletRuntimeForTest();

        vector<unsigned char> vchDefaultKey;
        nFail += Check(CWalletDB("r").LoadWallet(vchDefaultKey),
                       "an encrypted wallet can be loaded") ? 0 : 1;
        nFail += Check(vchDefaultKey == vchPubKey,
                       "the encrypted wallet default public key loads") ? 0 : 1;
        nFail += Check(IsWalletEncrypted() && IsWalletLocked(),
                       "an encrypted wallet loads locked") ? 0 : 1;
        nFail += Check(WalletCanSpendKey(vchPubKey),
                       "an encrypted key is recognized as wallet-owned while locked") ? 0 : 1;

        CPrivKey vchDecrypted;
        string strError;
        nFail += Check(!GetWalletPrivKey(vchPubKey, vchDecrypted, strError),
                       "a locked encrypted key cannot be read") ? 0 : 1;
        nFail += Check(!UnlockWallet(strWrongPassphrase, strError),
                       "the wrong-passphrase does not unlock") ? 0 : 1;
        nFail += Check(UnlockWallet(strPassphrase, strError),
                       "the right passphrase unlocks") ? 0 : 1;
        nFail += Check(!IsWalletLocked(),
                       "the wallet reports unlocked") ? 0 : 1;
        nFail += Check(GetWalletPrivKey(vchPubKey, vchDecrypted, strError) &&
                       vchDecrypted == vchPrivKey,
                       "an unlocked encrypted key decrypts to the original private key") ? 0 : 1;
        LockWallet();
        nFail += Check(IsWalletLocked(),
                       "locking clears the unlocked state") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static bool FileContainsBytes(const string& strPath, const vector<unsigned char>& vchNeedle)
{
    if (vchNeedle.empty())
        return false;
    FILE* pf = fopen(strPath.c_str(), "rb");
    if (!pf)
        return false;

    vector<unsigned char> vchHaystack;
    unsigned char buf[4096];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), pf)) > 0)
        vchHaystack.insert(vchHaystack.end(), buf, buf + n);
    fclose(pf);

    if (vchHaystack.size() < vchNeedle.size())
        return false;
    return search(vchHaystack.begin(), vchHaystack.end(),
                  vchNeedle.begin(), vchNeedle.end()) != vchHaystack.end();
}

static bool FileContainsText(const string& strPath, const string& strNeedle)
{
    FILE* pf = fopen(strPath.c_str(), "rb");
    if (!pf)
        return false;

    string strHaystack;
    char buf[4096];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), pf)) > 0)
        strHaystack.append(buf, buf + n);
    fclose(pf);

    return strHaystack.find(strNeedle) != string::npos;
}

static bool WriteTextFile(const string& strPath, const string& strText)
{
    FILE* pf = fopen(strPath.c_str(), "wb");
    if (!pf)
        return false;
    bool fOk = fwrite(strText.data(), 1, strText.size(), pf) == strText.size();
    if (fclose(pf) != 0)
        fOk = false;
    return fOk;
}

static string QuoteCommandArg(const string& str)
{
    string out = "\"";
    for (size_t i = 0; i < str.size(); i++)
    {
        if (str[i] == '"')
            out += "\\\"";
        else
            out += str[i];
    }
    out += "\"";
    return out;
}

static int RunBitflashChild(const string& strExe,
                            const vector<string>& vArgs,
                            const string* pStdinFile = NULL)
{
#ifdef _WIN32
    vector<char*> argv;
    argv.push_back((char*)strExe.c_str());
    for (size_t i = 0; i < vArgs.size(); i++)
        argv.push_back((char*)vArgs[i].c_str());
    argv.push_back(NULL);

    int nOldOut = _dup(1);
    int nOldErr = _dup(2);
    int nOldIn = _dup(0);
    int nNull = _open("NUL", _O_WRONLY);
    int nIn = -1;
    if (nNull >= 0)
    {
        _dup2(nNull, 1);
        _dup2(nNull, 2);
    }
    if (pStdinFile)
    {
        nIn = _open(pStdinFile->c_str(), _O_RDONLY);
        if (nIn >= 0)
            _dup2(nIn, 0);
    }
    int nRet = _spawnv(_P_WAIT, strExe.c_str(), &argv[0]);
    if (nIn >= 0)
        _close(nIn);
    if (nNull >= 0)
        _close(nNull);
    if (nOldIn >= 0)
    {
        _dup2(nOldIn, 0);
        _close(nOldIn);
    }
    if (nOldOut >= 0)
    {
        _dup2(nOldOut, 1);
        _close(nOldOut);
    }
    if (nOldErr >= 0)
    {
        _dup2(nOldErr, 2);
        _close(nOldErr);
    }
    return nRet;
#else
    string strCmd = QuoteCommandArg(strExe);
    for (size_t i = 0; i < vArgs.size(); i++)
        strCmd += " " + QuoteCommandArg(vArgs[i]);
    if (pStdinFile)
        strCmd += " < " + QuoteCommandArg(*pStdinFile);
    strCmd += " > /dev/null 2>&1";
    return system(strCmd.c_str());
#endif
}

static int RunWalletEncryptSelfTest()
{
    fflush(stdout);
    printf("wallet-encrypt self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd) || !SetCurrentDir(tmp))
    {
        printf("  FAIL could not move into the temporary data directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    bool fWalletEnvClosed = false;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    try
    {
        if (!LoadWallet())
            throw std::runtime_error("LoadWallet failed");

        string strError;
        const string strMnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        nFail += Check(SetHDSeedFromMnemonic(strMnemonic, strError),
                       "a phrase can be installed before encryption") ? 0 : 1;
        TopUpKeyPool();

        vector<unsigned char> vchDefaultPubKey = keyUser.GetPubKey();
        CPrivKey vchDefaultPrivKey;
        nFail += Check(GetWalletPrivKey(vchDefaultPubKey, vchDefaultPrivKey, strError),
                       "the default private key is readable before encryption") ? 0 : 1;
        vector<unsigned char> vchDefaultPrivBytes(vchDefaultPrivKey.begin(), vchDefaultPrivKey.end());
        vector<unsigned char> vchPlainHDMaster = vchHDMaster;
        vector<unsigned char> vchPlainHDChainCode = vchHDChainCode;

        string strBackup;
        nFail += Check(EncryptWallet("btf-test-passphrase", strBackup, strError),
                       "wallet.dat can be rewritten encrypted") ? 0 : 1;
        fWalletEnvClosed = true;
        nFail += Check(FileExists(strBackup.c_str()),
                       "the original wallet is preserved as an explicit backup") ? 0 : 1;

        string strWalletPath = GetAppDir() + "/wallet.dat";
        nFail += Check(!FileContainsBytes(strWalletPath, vchDefaultPrivBytes),
                       "the active wallet no longer contains the default private key bytes") ? 0 : 1;
        nFail += Check(!FileContainsBytes(strWalletPath, vchPlainHDMaster),
                       "the active wallet no longer contains the HD master key bytes") ? 0 : 1;
        nFail += Check(!FileContainsBytes(strWalletPath, vchPlainHDChainCode),
                       "the active wallet no longer contains the HD chain-code bytes") ? 0 : 1;

#ifdef _WIN32
        string strExe = cwd + "\\bitflash.exe";
#else
        string strExe = cwd + "/bitflash-node";
#endif
        string strWrongDump = tmp + "/wrong-pass-dump.txt";
        string strRightDump = tmp + "/right-pass-dump.txt";
        string strLiteralDump = tmp + "/literal-pass-dump.txt";
        string strStdinDump = tmp + "/stdin-pass-dump.txt";
        string strWrongPassFile = tmp + "/wrong-pass.txt";
        string strRightPassFile = tmp + "/right-pass.txt";
        nFail += Check(WriteTextFile(strWrongPassFile, "wrong-passphrase\n") &&
                       WriteTextFile(strRightPassFile, "btf-test-passphrase\n"),
                       "passphrase files can be written for restarted commands") ? 0 : 1;

        vector<string> vWrongArgs;
        vWrongArgs.push_back("-datadir=" + tmp);
        vWrongArgs.push_back("-walletpassphrase=@" + strWrongPassFile);
        vWrongArgs.push_back("-dumpwallet=" + strWrongDump);
        vWrongArgs.push_back("-nogui");
        int nWrongRet = RunBitflashChild(strExe, vWrongArgs);
        nFail += Check(nWrongRet != 0 && !FileExists(strWrongDump.c_str()),
                       "a restarted wallet rejects the wrong-passphrase") ? 0 : 1;

        vector<string> vLiteralArgs;
        vLiteralArgs.push_back("-datadir=" + tmp);
        vLiteralArgs.push_back("-walletpassphrase=btf-test-passphrase");
        vLiteralArgs.push_back("-dumpwallet=" + strLiteralDump);
        vLiteralArgs.push_back("-nogui");
        int nLiteralRet = RunBitflashChild(strExe, vLiteralArgs);
        nFail += Check(nLiteralRet != 0 && !FileExists(strLiteralDump.c_str()),
                       "literal passphrases on the command line are refused") ? 0 : 1;

        vector<string> vRightArgs;
        vRightArgs.push_back("-datadir=" + tmp);
        vRightArgs.push_back("-walletpassphrase=@" + strRightPassFile);
        vRightArgs.push_back("-dumpwallet=" + strRightDump);
        vRightArgs.push_back("-nogui");
        int nRightRet = RunBitflashChild(strExe, vRightArgs);
        nFail += Check(nRightRet == 0 && FileExists(strRightDump.c_str()),
                       "a restarted wallet unlocks with the right passphrase") ? 0 : 1;
        nFail += Check(FileContainsText(strRightDump, HexStrLocal(vchDefaultPrivBytes)),
                       "the restarted wallet can decrypt and dump the original key") ? 0 : 1;

        vector<string> vStdinArgs;
        vStdinArgs.push_back("-datadir=" + tmp);
        vStdinArgs.push_back("-walletpassphrase");
        vStdinArgs.push_back("-dumpwallet=" + strStdinDump);
        vStdinArgs.push_back("-nogui");
        int nStdinRet = RunBitflashChild(strExe, vStdinArgs, &strRightPassFile);
        nFail += Check(nStdinRet == 0 && FileExists(strStdinDump.c_str()),
                       "a restarted wallet can read the passphrase from stdin") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    if (!fWalletEnvClosed)
        DBFlush(true);
    SetCurrentDir(cwd);
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunNetMessageSelfTest()
{
    fflush(stdout);
    printf("net-message self-test\n");

    int nFail = 0;
    try
    {
        CNode complete(INVALID_SOCKET, CAddress("127.0.0.1"));
        complete.nVersion = VERSION;
        complete.vRecv << CMessageHeader("ping", 0);
        nFail += Check(ProcessMessages(&complete), "a complete empty message processes") ? 0 : 1;
        nFail += Check(complete.vRecv.empty(), "a complete message is consumed") ? 0 : 1;
        nFail += Check(!complete.fDisconnect, "a valid ping does not disconnect the peer") ? 0 : 1;

        CNode partial(INVALID_SOCKET, CAddress("127.0.0.1"));
        partial.nVersion = VERSION;
        partial.vRecv << CMessageHeader("block", 100);
        unsigned int nPartialBefore = partial.vRecv.size();
        nFail += Check(ProcessMessages(&partial), "an incomplete message returns cleanly") ? 0 : 1;
        nFail += Check(partial.vRecv.size() == nPartialBefore,
                       "an incomplete message keeps one header in the buffer") ? 0 : 1;
        nFail += Check(partial.nIncompleteMessageStart != 0,
                       "an incomplete message starts a timeout clock") ? 0 : 1;
        nFail += Check(!partial.fDisconnect,
                       "a fresh incomplete message does not disconnect immediately") ? 0 : 1;

        CNode stale(INVALID_SOCKET, CAddress("127.0.0.1"));
        stale.nVersion = VERSION;
        stale.vRecv << CMessageHeader("block", 100);
        stale.nIncompleteMessageStart = GetTime() - BTF_INCOMPLETE_MESSAGE_TIMEOUT_SECS - 1;
        stale.nIncompleteMessageSize = 100;
        stale.strIncompleteMessageCommand = "block";
        ProcessMessages(&stale);
        nFail += Check(stale.fDisconnect,
                       "a stale incomplete message disconnects the peer") ? 0 : 1;

        CNode oversized(INVALID_SOCKET, CAddress("127.0.0.1"));
        oversized.nVersion = VERSION;
        oversized.vRecv << CMessageHeader("block", MAX_PROTOCOL_MESSAGE_SIZE + 1);
        ProcessMessages(&oversized);
        nFail += Check(oversized.fDisconnect,
                       "an oversized message header disconnects the peer") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static CBlock MakeSizedConsensusBlock(size_t nScriptBytes)
{
    CTransaction tx;
    tx.vin.push_back(CTxIn(COutPoint(), CScript() << 1 << 1));
    tx.vout.push_back(CTxOut(0, CScript()));
    tx.vout[0].scriptPubKey.insert(tx.vout[0].scriptPubKey.end(), nScriptBytes, 0);

    CBlock block;
    block.vtx.push_back(tx);
    block.hashMerkleRoot = block.BuildMerkleTree();
    block.nVersion = 1;
    block.nTime = GetAdjustedTime();
    block.nBits = bnProofOfWorkLimit.GetCompact();
    block.nNonce = 0;
    return block;
}

static int RunConsensusLimitsSelfTest()
{
    fflush(stdout);
    printf("consensus-limits self-test\n");

    int nFail = 0;
    try
    {
        nFail += Check(MAX_BLOCK_SIZE == 1000000,
                       "the consensus block-size cap is 1 MB") ? 0 : 1;
        nFail += Check(MAX_BLOCK_SIZE < MAX_SIZE,
                       "the block cap is tighter than the serializer cap") ? 0 : 1;

        CBlock small = MakeSizedConsensusBlock(100);
        nFail += Check(small.CheckSizeLimits(),
                       "a small block is within the consensus size limit") ? 0 : 1;

        CBlock oversized = MakeSizedConsensusBlock(MAX_BLOCK_SIZE);
        unsigned int nSerialized = ::GetSerializeSize(oversized, SER_DISK);
        nFail += Check(nSerialized > MAX_BLOCK_SIZE && nSerialized <= MAX_SIZE,
                       "the test block sits between 1 MB and the old 32 MB cap") ? 0 : 1;
        nFail += Check(!oversized.CheckSizeLimits(),
                       "a block above 1 MB is outside the consensus size limit") ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        printf("  FAIL exception: %s\n", e.what());
        nFail++;
    }
    catch (...)
    {
        printf("  FAIL unknown exception\n");
        nFail++;
    }

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

int RunSelfTest(const std::string& name)
{
    AttachTerminal();

    if (name == "wallet-keypool")
        return RunWalletKeyPoolSelfTest();
    if (name == "wallet-hd")
        return RunWalletHDSelfTest();
    if (name == "wallet-format")
        return RunWalletFormatSelfTest();
    if (name == "wallet-crypto")
        return RunWalletCryptoSelfTest();
    if (name == "wallet-encrypt")
        return RunWalletEncryptSelfTest();
    if (name == "net-message")
        return RunNetMessageSelfTest();
    if (name == "consensus-limits")
        return RunConsensusLimitsSelfTest();

    printf("Unknown self-test '%s'\n", name.c_str());
    printf("Known self-tests: wallet-keypool, wallet-hd, wallet-format, wallet-crypto, wallet-encrypt, net-message, consensus-limits\n");
    return 1;
}
