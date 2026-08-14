// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Integration self-tests that need the real wallet/database code linked into
// the node. These are intentionally run behind an explicit command-line flag
// and against a temporary data directory.

#include "headers_core.h"
#include "btfaddr.h"
#include "bip32.h"
#include "proxy.h"
#include "selftest.h"
#include "sockcount.h"
#include "tor.h"
#include "walletcmd.h"
#include "wallet_sqlite.h"

extern int RunPoolStratumSelfTest();

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
#include <cerrno>
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

static vector<unsigned char> DataStreamBytes(const CDataStream& ss)
{
    return vector<unsigned char>(ss.begin(), ss.end());
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
        nFail += Check(nHDCoinType == HD_BIP44_COIN_TYPE_BITFLASH,
                       "a new recovery phrase records the SLIP-0044 BIP44 coin type") ? 0 : 1;
        nFail += Check(nHDReceiveNext == 1 && nHDChangeNext == 0,
                       "BIP44 receive/change counters reserve the default receive key") ? 0 : 1;
        std::vector<unsigned int> vBIP44Path = HDBIP44Path(HD_BIP44_COIN_TYPE_BITFLASH,
                                                           HD_BIP44_ACCOUNT,
                                                           HD_BIP44_CHAIN_RECEIVE,
                                                           0);
        nFail += Check(vBIP44Path.size() == 5 &&
                       vBIP44Path[0] == (HD_BIP44_PURPOSE | bitflash::BIP32_HARDENED) &&
                       vBIP44Path[1] == (HD_BIP44_COIN_TYPE_BITFLASH | bitflash::BIP32_HARDENED) &&
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
                                       HDBIP44Path(HD_BIP44_COIN_TYPE_BITFLASH,
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
        nFail += Check(audit.nCoinType == HD_BIP44_COIN_TYPE_BITFLASH,
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

        CKey keyLegacyHD11;
        nSchemaForLegacyAudit = nHDKeySchema;
        nHDKeySchema = HD_SCHEMA_LEGACY;
        if (!DeriveHDKey(11, keyLegacyHD11, strError))
            throw std::runtime_error("legacy compatibility index 11 derivation failed: " + strError);
        nHDKeySchema = nSchemaForLegacyAudit;
        if (!AddKey(keyLegacyHD11))
            throw std::runtime_error("could not store the legacy compatibility index 11 key");

        std::map<unsigned int, std::vector<unsigned char> > mapLegacyProbe;
        mapLegacyProbe[0] = keyAuditLegacyHD.GetPubKey();
        mapLegacyProbe[11] = keyLegacyHD11.GetPubKey();

        CWalletTx wtxLegacyHD11;
        wtxLegacyHD11.vout.push_back(CTxOut(19 * COIN, CScript() << keyLegacyHD11.GetPubKey() << OP_CHECKSIG));
        CRITICAL_BLOCK(cs_mapWallet)
        {
            mapWallet.clear();
            mapWallet[wtxLegacyHD11.GetHash()] = wtxLegacyHD11;
        }
        nFail += Check(WalletLastUsedPubKeyIndexNext(mapLegacyProbe) == 12,
                       "restore collapses legacy hdnext to the last used compatibility index plus one") ? 0 : 1;

        CRITICAL_BLOCK(cs_mapWallet)
            mapWallet.clear();
        nFail += Check(WalletLastUsedPubKeyIndexNext(mapLegacyProbe) == 0,
                       "restore does not persist legacy hdnext at the scan depth when no compatibility key was used") ? 0 : 1;
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

static bool FileContainsText(const string& strPath, const string& strNeedle);
static bool MakeDirLocal(const string& strPath);
static int RunBitflashChild(const string& strExe,
                            const vector<string>& vArgs,
                            const string* pStdinFile,
                            const string* pOutputFile);

class CWalletStorageSanityRawDB : public CWalletDB
{
public:
    CWalletStorageSanityRawDB(const char* pszMode="r+")
        : CWalletDB(pszMode) { }

    bool WriteUnknownRecord()
    {
        return Write(string("storage-sanity-unknown"), 1);
    }

    bool WriteMalformedKeyRecord()
    {
        if (!pdb)
            return false;
        unsigned char chKey = 0xff;
        unsigned char chValue = 0x01;
        Dbt datKey(&chKey, 1);
        Dbt datValue(&chValue, 1);
        return pdb->put(GetTxn(), &datKey, &datValue, 0) == 0;
    }

    bool MakePlainHDSeedIncomplete()
    {
        return Erase(string("hdchaincode"));
    }

    bool AddEncryptedMarkerToPlainWallet()
    {
        CWalletMasterKey kMasterKey;
        kMasterKey.vchCryptedKey.resize(48);
        for (size_t i = 0; i < kMasterKey.vchCryptedKey.size(); i++)
            kMasterKey.vchCryptedKey[i] = (unsigned char)(0x80 + (i & 0x3f));
        for (size_t i = 0; i < kMasterKey.vchSalt.size(); i++)
            kMasterKey.vchSalt[i] = (unsigned char)(0x40 + i);
        return WriteWalletMinVersion(WALLET_FORMAT_ENCRYPTED) &&
               WriteMasterKey(1, kMasterKey);
    }
};

static const char* SELFTEST_MUTATE_WALLET_MARKER =
    ".bitflash-selftest-wallet-mutate-ok";
static const char* SELFTEST_MUTATE_WALLET_MARKER_TEXT =
    "bitflash destructive wallet storage self-test\n";

static string SelfTestMutationMarkerPath()
{
    return GetAppDir() + "/" + SELFTEST_MUTATE_WALLET_MARKER;
}

static bool WriteSelfTestMutationMarker(const string& strDir)
{
    string strPath = strDir + "/" + SELFTEST_MUTATE_WALLET_MARKER;
    FILE* pf = fopen(strPath.c_str(), "wb");
    if (!pf)
        return false;
    bool fOk = fwrite(SELFTEST_MUTATE_WALLET_MARKER_TEXT, 1,
                      strlen(SELFTEST_MUTATE_WALLET_MARKER_TEXT), pf) ==
               strlen(SELFTEST_MUTATE_WALLET_MARKER_TEXT);
    if (fclose(pf) != 0)
        fOk = false;
    return fOk;
}

int RunSelfTestMutateWallet(const std::string& name)
{
    if (!FileContainsText(SelfTestMutationMarkerPath(),
                          SELFTEST_MUTATE_WALLET_MARKER_TEXT))
    {
        fprintf(stderr, "Refusing destructive wallet storage mutation outside "
                        "a marked self-test datadir.\n");
        return 1;
    }

    bool fOk = false;
    try
    {
        CWalletStorageSanityRawDB walletdb;
        if (name == "unknown-record")
            fOk = walletdb.WriteUnknownRecord();
        else if (name == "malformed-key")
            fOk = walletdb.WriteMalformedKeyRecord();
        else if (name == "incomplete-plain-hd")
            fOk = walletdb.MakePlainHDSeedIncomplete();
        else if (name == "encrypted-marker-with-plain-keys")
            fOk = walletdb.AddEncryptedMarkerToPlainWallet();
        else
        {
            fprintf(stderr, "Unknown wallet storage mutation '%s'\n", name.c_str());
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Cannot mutate wallet storage: %s\n", e.what());
        return 1;
    }
    catch (...)
    {
        fprintf(stderr, "Cannot mutate wallet storage: unknown exception\n");
        return 1;
    }

    DBFlush(true);
    return fOk ? 0 : 1;
}

static int RunWalletStorageSanitySelfTest()
{
    fflush(stdout);
    printf("wallet-storage-sanity self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd))
    {
        printf("  FAIL could not read current directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    printf("  temp root: %s\n", tmp.c_str());

    try
    {
#ifdef _WIN32
        string strExe = cwd + "\\bitflash.exe";
#else
        string strExe = cwd + "/bitflash-node";
#endif

        struct StorageScenario
        {
            const char* pszName;
            const char* pszExpectedFailure;
        };

        StorageScenario scenarios[] = {
            { "unknown-record", "wallet.dat contains unknown records" },
            { "malformed-key", "wallet.dat contains malformed records" },
            { "incomplete-plain-hd", "plain HD seed is incomplete" },
            { "encrypted-marker-with-plain-keys",
              "encrypted wallet still contains plain private key records" },
        };

        for (size_t i = 0; i < sizeof(scenarios)/sizeof(scenarios[0]); i++)
        {
            string strScenarioDir = tmp + "/" + scenarios[i].pszName;
            nFail += Check(MakeDirLocal(strScenarioDir),
                           "scenario datadir can be created") ? 0 : 1;

            string strCreateOut = tmp + "/" + scenarios[i].pszName + "-create.txt";
            vector<string> vCreateArgs;
            vCreateArgs.push_back("-datadir=" + strScenarioDir);
            vCreateArgs.push_back("-nomanagedtor");
            vCreateArgs.push_back("-nogui");
            vCreateArgs.push_back("-newphrase");
            int nCreateRet = RunBitflashChild(strExe, vCreateArgs, NULL, &strCreateOut);
            nFail += Check(nCreateRet == 0 &&
                           FileContainsText(strCreateOut, "Write these twelve words down"),
                           "scenario phrase wallet can be created") ? 0 : 1;

            if (i == 0)
            {
                string strBlockedOut = tmp + "/" + scenarios[i].pszName + "-blocked-mutate.txt";
                vector<string> vBlockedArgs;
                vBlockedArgs.push_back("-datadir=" + strScenarioDir);
                vBlockedArgs.push_back("-nomanagedtor");
                vBlockedArgs.push_back("-nogui");
                vBlockedArgs.push_back("-selftestmutatewallet=" + string(scenarios[i].pszName));
                int nBlockedRet = RunBitflashChild(strExe, vBlockedArgs, NULL, &strBlockedOut);
                nFail += Check(nBlockedRet != 0 &&
                               FileContainsText(strBlockedOut, "Refusing destructive wallet storage mutation"),
                               "wallet mutation helper is blocked without marker") ? 0 : 1;
            }

            nFail += Check(WriteSelfTestMutationMarker(strScenarioDir),
                           "scenario mutation marker can be written") ? 0 : 1;

            string strMutateOut = tmp + "/" + scenarios[i].pszName + "-mutate.txt";
            vector<string> vMutateArgs;
            vMutateArgs.push_back("-datadir=" + strScenarioDir);
            vMutateArgs.push_back("-nomanagedtor");
            vMutateArgs.push_back("-nogui");
            vMutateArgs.push_back("-selftestmutatewallet=" + string(scenarios[i].pszName));
            int nMutateRet = RunBitflashChild(strExe, vMutateArgs, NULL, &strMutateOut);
            nFail += Check(nMutateRet == 0, scenarios[i].pszName) ? 0 : 1;

            string strCheckOut = tmp + "/" + scenarios[i].pszName + "-check.txt";
            vector<string> vCheckArgs;
            vCheckArgs.push_back("-datadir=" + strScenarioDir);
            vCheckArgs.push_back("-nomanagedtor");
            vCheckArgs.push_back("-nogui");
            vCheckArgs.push_back("-walletstoragecheck");
            int nCheckRet = RunBitflashChild(strExe, vCheckArgs, NULL, &strCheckOut);
            nFail += Check(nCheckRet == 2 &&
                           FileContainsText(strCheckOut, "storage sanity:            failed") &&
                           FileContainsText(strCheckOut, scenarios[i].pszExpectedFailure),
                           scenarios[i].pszExpectedFailure) ? 0 : 1;
        }
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

    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunDbEnvReopenSelfTest()
{
    fflush(stdout);
    printf("db-env-reopen self-test\n");

    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }

    int nFail = 0;
    std::string strOldDataDir = strSetDataDir;
    strSetDataDir = tmp;
    printf("  temp datadir: %s\n", tmp.c_str());

    try
    {
        for (int i = 0; i < 5; i++)
        {
            int64 nValue = 1000 + i;
            {
                CWalletDB walletdb("cr+");
                nFail += Check(walletdb.WriteSetting("db-env-reopen-cycle", nValue),
                               "wallet setting can be written before shutdown") ? 0 : 1;
            }

            DBFlush(true);

            int64 nRead = 0;
            {
                CWalletDB walletdb("r");
                nFail += Check(walletdb.ReadSetting("db-env-reopen-cycle", nRead),
                               "wallet setting can be read after env reopen") ? 0 : 1;
            }
            nFail += Check(nRead == nValue,
                           "reopened environment reads the last committed value") ? 0 : 1;

            DBFlush(true);
        }
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
    strSetDataDir = strOldDataDir;
    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunWalletSQLiteSelfTest()
{
    fflush(stdout);
    printf("wallet-sqlite self-test\n");

    std::string tmp;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }

    int nFail = 0;
    string strPath = tmp + "/wallet.sqlite";
    string strError;

    try
    {
        CDataStream ssKeySetting(SER_DISK);
        ssKeySetting << make_pair(string("setting"), string("sqlite-roundtrip"));
        CDataStream ssValueSetting(SER_DISK);
        ssValueSetting << (int64)424242;

        vector<unsigned char> vchPubKey;
        vchPubKey.push_back(0x04);
        for (int i = 0; i < 64; i++)
            vchPubKey.push_back((unsigned char)i);
        CDataStream ssKeyDefault(SER_DISK);
        ssKeyDefault << string("defaultkey");
        CDataStream ssValueDefault(SER_DISK);
        ssValueDefault << vchPubKey;

        {
            CWalletDBSQLite db;
            nFail += Check(db.Open(strPath, strError),
                           "SQLite wallet opens and creates schema") ? 0 : 1;
            nFail += Check(db.BeginTransaction(strError),
                           "SQLite wallet begins a write transaction") ? 0 : 1;
            nFail += Check(db.WriteRecord(DataStreamBytes(ssKeySetting),
                                          DataStreamBytes(ssValueSetting),
                                          strError),
                           "SQLite wallet writes a serialized setting record") ? 0 : 1;
            nFail += Check(db.WriteRecord(DataStreamBytes(ssKeyDefault),
                                          DataStreamBytes(ssValueDefault),
                                          strError),
                           "SQLite wallet writes a serialized defaultkey record") ? 0 : 1;
            nFail += Check(db.CommitTransaction(strError),
                           "SQLite wallet commits a write transaction") ? 0 : 1;
            int nCount = 0;
            nFail += Check(db.CountRecords(nCount, strError) && nCount == 2,
                           "SQLite wallet counts raw records") ? 0 : 1;
        }

        {
            CWalletDBSQLite db;
            nFail += Check(db.Open(strPath, strError),
                           "SQLite wallet reopens") ? 0 : 1;
            vector<unsigned char> vchRead;
            nFail += Check(db.ReadRecord(DataStreamBytes(ssKeySetting),
                                         vchRead,
                                         strError),
                           "SQLite wallet reads a serialized setting record") ? 0 : 1;
            int64 nReadValue = 0;
            CDataStream ssRead(vchRead, SER_DISK);
            ssRead >> nReadValue;
            nFail += Check(!ssRead.fail() && nReadValue == 424242,
                           "SQLite wallet preserves serialized values byte-for-byte") ? 0 : 1;

            vchRead.clear();
            nFail += Check(db.ReadRecord(DataStreamBytes(ssKeyDefault),
                                         vchRead,
                                         strError),
                           "SQLite wallet reads a serialized defaultkey record") ? 0 : 1;
            vector<unsigned char> vchReadPubKey;
            CDataStream ssReadDefault(vchRead, SER_DISK);
            ssReadDefault >> vchReadPubKey;
            nFail += Check(!ssReadDefault.fail() && vchReadPubKey == vchPubKey,
                           "SQLite wallet preserves public key blobs") ? 0 : 1;
        }
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

    RemoveTree(tmp);
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

namespace {

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
        vector<unsigned char> vchKey = DataStreamBytes(ssKey);
        if (mapRecords.count(vchKey))
        {
            strErrorRet = "duplicate serialized wallet key";
            return false;
        }
        mapRecords[vchKey] = DataStreamBytes(ssValue);
        return true;
    }
};

} // namespace

static int RunWalletSQLiteMigrationSelfTest()
{
    fflush(stdout);
    printf("wallet-sqlite-migration self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd))
    {
        printf("  FAIL could not read current directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    printf("  temp root: %s\n", tmp.c_str());

    try
    {
#ifdef _WIN32
        string strExe = cwd + "\\bitflash.exe";
#else
        string strExe = cwd + "/bitflash-node";
#endif
        string strWalletDir = tmp + "/wallet";
        nFail += Check(MakeDirLocal(strWalletDir),
                       "temporary wallet directory can be created") ? 0 : 1;

        string strCreateOut = tmp + "/create.txt";
        vector<string> vCreateArgs;
        vCreateArgs.push_back("-datadir=" + strWalletDir);
        vCreateArgs.push_back("-nomanagedtor");
        vCreateArgs.push_back("-nogui");
        vCreateArgs.push_back("-newphrase");
        int nCreateRet = RunBitflashChild(strExe, vCreateArgs, NULL, &strCreateOut);
        nFail += Check(nCreateRet == 0 &&
                       FileContainsText(strCreateOut, "Write these twelve words down"),
                       "a phrase wallet can be created for SQLite export") ? 0 : 1;

        string strSQLite = tmp + "/wallet.sqlite";
        string strExportOut = tmp + "/sqlite-export.txt";
        vector<string> vExportArgs;
        vExportArgs.push_back("-datadir=" + strWalletDir);
        vExportArgs.push_back("-nomanagedtor");
        vExportArgs.push_back("-nogui");
        vExportArgs.push_back("-walletsqliteexport=" + strSQLite);
        int nExportRet = RunBitflashChild(strExe, vExportArgs, NULL, &strExportOut);
        nFail += Check(nExportRet == 0 &&
                       FileExists(strSQLite.c_str()) &&
                       FileContainsText(strExportOut, "SQLite wallet export written"),
                       "wallet.dat can be exported to SQLite") ? 0 : 1;

        string strVerifyOut = tmp + "/sqlite-verify.txt";
        vector<string> vVerifyArgs;
        vVerifyArgs.push_back("-datadir=" + strWalletDir);
        vVerifyArgs.push_back("-nomanagedtor");
        vVerifyArgs.push_back("-nogui");
        vVerifyArgs.push_back("-walletsqliteverify=" + strSQLite);
        int nVerifyRet = RunBitflashChild(strExe, vVerifyArgs, NULL, &strVerifyOut);
        nFail += Check(nVerifyRet == 0 &&
                       FileContainsText(strVerifyOut, "verification:              ok"),
                       "SQLite wallet export verifies against wallet.dat") ? 0 : 1;

        string strOverwriteOut = tmp + "/sqlite-export-overwrite.txt";
        int nOverwriteRet =
            RunBitflashChild(strExe, vExportArgs, NULL, &strOverwriteOut);
        nFail += Check(nOverwriteRet != 0 &&
                       FileContainsText(strOverwriteOut,
                                        "Refusing to overwrite existing SQLite wallet export"),
                       "SQLite wallet export refuses to overwrite") ? 0 : 1;
        remove((strSQLite + "-wal").c_str());
        remove((strSQLite + "-shm").c_str());

        std::map<vector<unsigned char>, vector<unsigned char> > mapBDB;
        string strOldDataDir = strSetDataDir;
        string strScanError;
        strSetDataDir = strWalletDir;
        CWalletRecordMapVisitor visitor(mapBDB);
        bool fScanOk = ScanWalletRecords(visitor, strScanError);
        DBFlush(true);
        strSetDataDir = strOldDataDir;
        nFail += Check(fScanOk && !mapBDB.empty(),
                       "wallet.dat records can be scanned for comparison") ? 0 : 1;

        CWalletDBSQLite db;
        string strError;
        nFail += Check(db.Open(strSQLite, strError),
                       "exported SQLite wallet opens") ? 0 : 1;
        int nSQLiteRecords = 0;
        nFail += Check(db.CountRecords(nSQLiteRecords, strError) &&
                       nSQLiteRecords == (int)mapBDB.size(),
                       "SQLite export has the same record count as wallet.dat") ? 0 : 1;

        bool fAllMatch = true;
        for (std::map<vector<unsigned char>, vector<unsigned char> >::const_iterator it =
                 mapBDB.begin(); it != mapBDB.end(); ++it)
        {
            vector<unsigned char> vchSQLiteValue;
            if (!db.ReadRecord(it->first, vchSQLiteValue, strError) ||
                vchSQLiteValue != it->second)
            {
                fAllMatch = false;
                break;
            }
        }
        nFail += Check(fAllMatch,
                       "SQLite export preserves every wallet.dat key/value byte-for-byte") ? 0 : 1;

        std::map<vector<unsigned char>, vector<unsigned char> > mapSQLite;
        CWalletRecordMapVisitor sqliteVisitor(mapSQLite);
        nFail += Check(db.ScanRecords(sqliteVisitor, strError) &&
                       mapSQLite == mapBDB,
                       "SQLite wallet scanner streams every exported record byte-for-byte") ? 0 : 1;

        db.Close();
        CWalletDBSQLite dbCorrupt;
        vector<unsigned char> vchBadValue;
        vchBadValue.push_back(0xba);
        vchBadValue.push_back(0xad);
        nFail += Check(!mapBDB.empty() &&
                       dbCorrupt.Open(strSQLite, strError) &&
                       dbCorrupt.BeginTransaction(strError) &&
                       dbCorrupt.WriteRecord(mapBDB.begin()->first,
                                             vchBadValue,
                                             strError) &&
                       dbCorrupt.CommitTransaction(strError) &&
                       dbCorrupt.Checkpoint(strError),
                       "SQLite export can be deliberately corrupted for verifier test") ? 0 : 1;
        dbCorrupt.Close();

        string strVerifyBadOut = tmp + "/sqlite-verify-bad.txt";
        int nVerifyBadRet =
            RunBitflashChild(strExe, vVerifyArgs, NULL, &strVerifyBadOut);
        nFail += Check(nVerifyBadRet == 2 &&
                       FileContainsText(strVerifyBadOut,
                                        "record value mismatches:   1") &&
                       FileContainsText(strVerifyBadOut,
                                        "verification:              failed"),
                       "SQLite wallet verifier detects a mismatched record value") ? 0 : 1;
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

static bool MakeDirLocal(const string& strPath)
{
#ifdef _WIN32
    return CreateDirectoryA(strPath.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
#else
    return mkdir(strPath.c_str(), 0700) == 0 || errno == EEXIST;
#endif
}

static bool CopyFileLocal(const string& strSrc, const string& strDst)
{
    FILE* in = fopen(strSrc.c_str(), "rb");
    if (!in)
        return false;
    FILE* out = fopen(strDst.c_str(), "wb");
    if (!out)
    {
        fclose(in);
        return false;
    }

    bool fOk = true;
    char buf[65536];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
    {
        if (fwrite(buf, 1, n, out) != n)
        {
            fOk = false;
            break;
        }
    }
    if (ferror(in))
        fOk = false;
    if (fclose(out) != 0)
        fOk = false;
    fclose(in);
    return fOk;
}

static bool DirectoryHasFileWithPrefix(const string& strDir, const string& strPrefix)
{
#ifdef _WIN32
    WIN32_FIND_DATAA findData;
    string pattern = strDir + "\\*";
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE)
        return false;
    bool fFound = false;
    do
    {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            string name = findData.cFileName;
            if (name.compare(0, strPrefix.size(), strPrefix) == 0)
            {
                fFound = true;
                break;
            }
        }
    }
    while (FindNextFileA(hFind, &findData));
    FindClose(hFind);
    return fFound;
#else
    DIR* dir = opendir(strDir.c_str());
    if (!dir)
        return false;
    bool fFound = false;
    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL)
    {
        string name = ent->d_name;
        if (name.compare(0, strPrefix.size(), strPrefix) == 0)
        {
            fFound = true;
            break;
        }
    }
    closedir(dir);
    return fFound;
#endif
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
                            const string* pStdinFile = NULL,
                            const string* pOutputFile = NULL)
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
    int nOut = -1;
    int nIn = -1;
    if (pOutputFile)
        nOut = _open(pOutputFile->c_str(), _O_WRONLY|_O_CREAT|_O_TRUNC|_O_BINARY, _S_IREAD|_S_IWRITE);
    if (nOut >= 0)
    {
        _dup2(nOut, 1);
        _dup2(nOut, 2);
    }
    else if (nNull >= 0)
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
    if (nOut >= 0)
        _close(nOut);
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
    if (pOutputFile)
        strCmd += " > " + QuoteCommandArg(*pOutputFile) + " 2>&1";
    else
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
        CKey publicLabelKey;
        publicLabelKey.MakeNewKey();
        string strPublicLabelAddress = PubKeyToAddress(publicLabelKey.GetPubKey());
        nFail += Check(CWalletDB().WriteName(strPublicLabelAddress, "rewrite-public-name") &&
                       CWalletDB().WriteSetting("rewrite-public-setting", (int64)424242),
                       "public wallet records can be written before encryption") ? 0 : 1;

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
        string strStorageAudit = tmp + "/encrypted-storage-audit.txt";
        string strWrongDump = tmp + "/wrong-pass-dump.txt";
        string strRightDump = tmp + "/right-pass-dump.txt";
        string strLiteralDump = tmp + "/literal-pass-dump.txt";
        string strStdinDump = tmp + "/stdin-pass-dump.txt";
        string strLockedAudit = tmp + "/locked-recovery-audit.txt";
        string strUnlockedAudit = tmp + "/unlocked-recovery-audit.txt";
        string strWrongPassFile = tmp + "/wrong-pass.txt";
        string strRightPassFile = tmp + "/right-pass.txt";
        nFail += Check(WriteTextFile(strWrongPassFile, "wrong-passphrase\n") &&
                       WriteTextFile(strRightPassFile, "btf-test-passphrase\n"),
                       "passphrase files can be written for restarted commands") ? 0 : 1;

        vector<string> vStorageAuditArgs;
        vStorageAuditArgs.push_back("-datadir=" + tmp);
        vStorageAuditArgs.push_back("-walletstorageaudit");
        vStorageAuditArgs.push_back("-nogui");
        int nStorageAuditRet = RunBitflashChild(strExe, vStorageAuditArgs, NULL, &strStorageAudit);
        nFail += Check(nStorageAuditRet == 0 &&
                       FileContainsText(strStorageAudit, "address book labels:       3"),
                       "the encrypted rewrite keeps address-book records") ? 0 : 1;
        nFail += Check(nStorageAuditRet == 0 &&
                       FileContainsText(strStorageAudit, "settings:                  1"),
                       "the encrypted rewrite keeps wallet setting records") ? 0 : 1;

        vector<string> vWrongArgs;
        vWrongArgs.push_back("-datadir=" + tmp);
        vWrongArgs.push_back("-walletpassphrase=@" + strWrongPassFile);
        vWrongArgs.push_back("-dumpwallet=" + strWrongDump);
        vWrongArgs.push_back("-nogui");
        int nWrongRet = RunBitflashChild(strExe, vWrongArgs);
        nFail += Check(nWrongRet != 0 && !FileExists(strWrongDump.c_str()),
                       "a restarted wallet rejects the wrong-passphrase") ? 0 : 1;

        vector<string> vLockedAuditArgs;
        vLockedAuditArgs.push_back("-datadir=" + tmp);
        vLockedAuditArgs.push_back("-recoveryaudit");
        vLockedAuditArgs.push_back("-nogui");
        int nLockedAuditRet = RunBitflashChild(strExe, vLockedAuditArgs, NULL, &strLockedAudit);
        nFail += Check(nLockedAuditRet == 2 &&
                       FileContainsText(strLockedAudit, "recovery phrase: encrypted, unlock wallet to audit") &&
                       FileContainsText(strLockedAudit, "recovery coverage:            unavailable while wallet is locked") &&
                       FileContainsText(strLockedAudit, "Unlock the wallet with /walletpassphrase"),
                       "a locked encrypted wallet reports that phrase coverage needs unlock") ? 0 : 1;

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

        vector<string> vUnlockedAuditArgs;
        vUnlockedAuditArgs.push_back("-datadir=" + tmp);
        vUnlockedAuditArgs.push_back("-walletpassphrase=@" + strRightPassFile);
        vUnlockedAuditArgs.push_back("-recoveryaudit");
        vUnlockedAuditArgs.push_back("-nogui");
        int nUnlockedAuditRet = RunBitflashChild(strExe, vUnlockedAuditArgs, NULL, &strUnlockedAudit);
        nFail += Check(nUnlockedAuditRet == 0 &&
                       FileContainsText(strUnlockedAudit, "recovery phrase: present") &&
                       !FileContainsText(strUnlockedAudit, "recovery phrase: not installed"),
                       "an unlocked encrypted wallet audits the installed recovery phrase") ? 0 : 1;

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

static int RunWalletPortabilitySelfTest()
{
    fflush(stdout);
    printf("wallet-portability self-test\n");

    std::string tmp;
    std::string cwd;
    if (!MakeTempDir(tmp))
    {
        printf("  FAIL could not create a temporary data directory\n");
        return 1;
    }
    if (!GetCurrentDir(cwd))
    {
        printf("  FAIL could not read current directory\n");
        RemoveTree(tmp);
        return 1;
    }

    int nFail = 0;
    printf("  temp root: %s\n", tmp.c_str());

    try
    {
#ifdef _WIN32
        string strExe = cwd + "\\bitflash.exe";
#else
        string strExe = cwd + "/bitflash-node";
#endif
        string strOriginal = tmp + "/original";
        string strRawCopy = tmp + "/raw-copy";
        string strBackupCopy = tmp + "/backup-copy";
        nFail += Check(MakeDirLocal(strOriginal) &&
                       MakeDirLocal(strRawCopy) &&
                       MakeDirLocal(strBackupCopy),
                       "temporary wallet directories can be created") ? 0 : 1;

        string strCreateOut = tmp + "/create.txt";
        vector<string> vCreateArgs;
        vCreateArgs.push_back("-datadir=" + strOriginal);
        vCreateArgs.push_back("-nomanagedtor");
        vCreateArgs.push_back("-nogui");
        vCreateArgs.push_back("-newphrase");
        int nCreateRet = RunBitflashChild(strExe, vCreateArgs, NULL, &strCreateOut);
        nFail += Check(nCreateRet == 0 &&
                       FileContainsText(strCreateOut, "Write these twelve words down"),
                       "a phrase wallet can be created in a fresh datadir") ? 0 : 1;

        string strOriginalAudit = tmp + "/original-audit.txt";
        vector<string> vOriginalAuditArgs;
        vOriginalAuditArgs.push_back("-datadir=" + strOriginal);
        vOriginalAuditArgs.push_back("-nomanagedtor");
        vOriginalAuditArgs.push_back("-nogui");
        vOriginalAuditArgs.push_back("-recoveryaudit");
        int nOriginalAuditRet = RunBitflashChild(strExe, vOriginalAuditArgs, NULL, &strOriginalAudit);
        nFail += Check(nOriginalAuditRet == 0 &&
                       FileContainsText(strOriginalAudit, "recovery phrase: present") &&
                       FileContainsText(strOriginalAudit, "SLIP-0044 BITFLASH"),
                       "the original wallet reports its recovery phrase") ? 0 : 1;

        string strOriginalStorageAudit = tmp + "/original-storage-audit.txt";
        vector<string> vOriginalStorageAuditArgs;
        vOriginalStorageAuditArgs.push_back("-datadir=" + strOriginal);
        vOriginalStorageAuditArgs.push_back("-nomanagedtor");
        vOriginalStorageAuditArgs.push_back("-nogui");
        vOriginalStorageAuditArgs.push_back("-walletstorageaudit");
        int nOriginalStorageAuditRet =
            RunBitflashChild(strExe, vOriginalStorageAuditArgs, NULL, &strOriginalStorageAudit);
        nFail += Check(nOriginalStorageAuditRet == 0 &&
                       FileContainsText(strOriginalStorageAudit, "Wallet storage audit") &&
                       FileContainsText(strOriginalStorageAudit, "plain HD seed:             complete") &&
                       FileContainsText(strOriginalStorageAudit, "encrypted HD seed:         none") &&
                       FileContainsText(strOriginalStorageAudit, "malformed records:         0"),
                       "the storage audit recognizes a plaintext phrase wallet") ? 0 : 1;

        string strOriginalStorageCheck = tmp + "/original-storage-check.txt";
        vector<string> vOriginalStorageCheckArgs;
        vOriginalStorageCheckArgs.push_back("-datadir=" + strOriginal);
        vOriginalStorageCheckArgs.push_back("-nomanagedtor");
        vOriginalStorageCheckArgs.push_back("-nogui");
        vOriginalStorageCheckArgs.push_back("-walletstoragecheck");
        int nOriginalStorageCheckRet =
            RunBitflashChild(strExe, vOriginalStorageCheckArgs, NULL, &strOriginalStorageCheck);
        nFail += Check(nOriginalStorageCheckRet == 0 &&
                       FileContainsText(strOriginalStorageCheck, "storage sanity:            ok") &&
                       FileContainsText(strOriginalStorageCheck, "plain HD seed:             complete"),
                       "the storage sanity check accepts a plaintext phrase wallet") ? 0 : 1;

        string strOriginalStorageAuditJson = tmp + "/original-storage-audit.json";
        vector<string> vOriginalStorageAuditJsonArgs;
        vOriginalStorageAuditJsonArgs.push_back("-datadir=" + strOriginal);
        vOriginalStorageAuditJsonArgs.push_back("-nomanagedtor");
        vOriginalStorageAuditJsonArgs.push_back("-nogui");
        vOriginalStorageAuditJsonArgs.push_back("-walletstorageauditjson=" +
                                                strOriginalStorageAuditJson);
        int nOriginalStorageAuditJsonRet =
            RunBitflashChild(strExe, vOriginalStorageAuditJsonArgs);
        nFail += Check(nOriginalStorageAuditJsonRet == 0 &&
                       FileContainsText(strOriginalStorageAuditJson,
                                        "\"format\": \"bitflash-wallet-storage-audit-v1\"") &&
                       FileContainsText(strOriginalStorageAuditJson,
                                        "\"plain_hd_seed\": \"complete\"") &&
                       FileContainsText(strOriginalStorageAuditJson,
                                        "\"encrypted_hd_seed\": \"none\""),
                       "the storage audit can write plaintext-wallet JSON") ? 0 : 1;

        string strPortableWallet = tmp + "/portable-wallet.dat";
        string strBackupOut = tmp + "/backupwallet.txt";
        vector<string> vBackupArgs;
        vBackupArgs.push_back("-datadir=" + strOriginal);
        vBackupArgs.push_back("-nomanagedtor");
        vBackupArgs.push_back("-nogui");
        vBackupArgs.push_back("-backupwallet=" + strPortableWallet);
        int nBackupRet = RunBitflashChild(strExe, vBackupArgs, NULL, &strBackupOut);
        nFail += Check(nBackupRet == 0 && FileExists(strPortableWallet.c_str()),
                       "/backupwallet writes a portable wallet.dat") ? 0 : 1;

        string strBackupOut2 = tmp + "/backupwallet-overwrite.txt";
        int nBackupRet2 = RunBitflashChild(strExe, vBackupArgs, NULL, &strBackupOut2);
        nFail += Check(nBackupRet2 == 0 && FileExists(strPortableWallet.c_str()) &&
                       !DirectoryHasFileWithPrefix(tmp, "portable-wallet.dat.tmp.") &&
                       !DirectoryHasFileWithPrefix(tmp, "portable-wallet.dat.old."),
                       "/backupwallet replaces an existing backup without leaving temp files") ? 0 : 1;

        nFail += Check(CopyFileLocal(strOriginal + "/wallet.dat",
                                     strRawCopy + "/wallet.dat"),
                       "a raw wallet.dat can be copied without database logs") ? 0 : 1;
        string strRawAudit = tmp + "/raw-copy-audit.txt";
        vector<string> vRawAuditArgs;
        vRawAuditArgs.push_back("-datadir=" + strRawCopy);
        vRawAuditArgs.push_back("-nomanagedtor");
        vRawAuditArgs.push_back("-nogui");
        vRawAuditArgs.push_back("-recoveryaudit");
        int nRawAuditRet = RunBitflashChild(strExe, vRawAuditArgs, NULL, &strRawAudit);
        nFail += Check(nRawAuditRet == 0 &&
                       FileContainsText(strRawAudit, "recovery phrase: present") &&
                       !FileContainsText(strRawAudit, "Cannot open wallet.dat"),
                       "a raw wallet.dat copy opens in a new datadir") ? 0 : 1;

        nFail += Check(CopyFileLocal(strPortableWallet,
                                     strBackupCopy + "/wallet.dat"),
                       "the portable backup can be installed as wallet.dat") ? 0 : 1;
        string strBackupAudit = tmp + "/backup-copy-audit.txt";
        vector<string> vBackupAuditArgs;
        vBackupAuditArgs.push_back("-datadir=" + strBackupCopy);
        vBackupAuditArgs.push_back("-nomanagedtor");
        vBackupAuditArgs.push_back("-nogui");
        vBackupAuditArgs.push_back("-recoveryaudit");
        int nBackupAuditRet = RunBitflashChild(strExe, vBackupAuditArgs, NULL, &strBackupAudit);
        nFail += Check(nBackupAuditRet == 0 &&
                       FileContainsText(strBackupAudit, "recovery phrase: present") &&
                       FileContainsText(strBackupAudit, "SLIP-0044 BITFLASH"),
                       "a /backupwallet copy opens in a new datadir") ? 0 : 1;

        string strPassFile = tmp + "/encrypt-pass.txt";
        string strEncryptOut = tmp + "/encryptwallet.txt";
        nFail += Check(WriteTextFile(strPassFile, "portable-test-passphrase\n"),
                       "an encryption passphrase file can be written") ? 0 : 1;
        vector<string> vEncryptArgs;
        vEncryptArgs.push_back("-datadir=" + strOriginal);
        vEncryptArgs.push_back("-nomanagedtor");
        vEncryptArgs.push_back("-nogui");
        vEncryptArgs.push_back("-encryptwallet=@" + strPassFile);
        int nEncryptRet = RunBitflashChild(strExe, vEncryptArgs, NULL, &strEncryptOut);
        nFail += Check(nEncryptRet == 0 &&
                       !DirectoryHasFileWithPrefix(strOriginal + "/database", "log."),
                       "the encryptwallet command purges Berkeley DB environment logs") ? 0 : 1;

        string strEncryptedStorageAudit = tmp + "/encrypted-storage-audit.txt";
        vector<string> vEncryptedStorageAuditArgs;
        vEncryptedStorageAuditArgs.push_back("-datadir=" + strOriginal);
        vEncryptedStorageAuditArgs.push_back("-nomanagedtor");
        vEncryptedStorageAuditArgs.push_back("-nogui");
        vEncryptedStorageAuditArgs.push_back("-walletstorageaudit");
        int nEncryptedStorageAuditRet =
            RunBitflashChild(strExe, vEncryptedStorageAuditArgs, NULL, &strEncryptedStorageAudit);
        nFail += Check(nEncryptedStorageAuditRet == 0 &&
                       FileContainsText(strEncryptedStorageAudit, "plain private keys:        0") &&
                       FileContainsText(strEncryptedStorageAudit, "encrypted private keys:") &&
                       FileContainsText(strEncryptedStorageAudit, "plain HD seed:             none") &&
                       FileContainsText(strEncryptedStorageAudit, "encrypted HD seed:         complete") &&
                       FileContainsText(strEncryptedStorageAudit, "wallet minimum version:    present") &&
                       FileContainsText(strEncryptedStorageAudit, "malformed records:         0"),
                       "the storage audit recognizes an encrypted wallet") ? 0 : 1;

        string strEncryptedStorageCheck = tmp + "/encrypted-storage-check.txt";
        vector<string> vEncryptedStorageCheckArgs;
        vEncryptedStorageCheckArgs.push_back("-datadir=" + strOriginal);
        vEncryptedStorageCheckArgs.push_back("-nomanagedtor");
        vEncryptedStorageCheckArgs.push_back("-nogui");
        vEncryptedStorageCheckArgs.push_back("-walletstoragecheck");
        int nEncryptedStorageCheckRet =
            RunBitflashChild(strExe, vEncryptedStorageCheckArgs, NULL, &strEncryptedStorageCheck);
        nFail += Check(nEncryptedStorageCheckRet == 0 &&
                       FileContainsText(strEncryptedStorageCheck, "storage sanity:            ok") &&
                       FileContainsText(strEncryptedStorageCheck, "plain private keys:        0") &&
                       FileContainsText(strEncryptedStorageCheck, "encrypted HD seed:         complete"),
                       "the storage sanity check accepts an encrypted wallet") ? 0 : 1;

        string strEncryptedStorageAuditJson = tmp + "/encrypted-storage-audit.json";
        vector<string> vEncryptedStorageAuditJsonArgs;
        vEncryptedStorageAuditJsonArgs.push_back("-datadir=" + strOriginal);
        vEncryptedStorageAuditJsonArgs.push_back("-nomanagedtor");
        vEncryptedStorageAuditJsonArgs.push_back("-nogui");
        vEncryptedStorageAuditJsonArgs.push_back("-walletstorageauditjson=" +
                                                 strEncryptedStorageAuditJson);
        int nEncryptedStorageAuditJsonRet =
            RunBitflashChild(strExe, vEncryptedStorageAuditJsonArgs);
        nFail += Check(nEncryptedStorageAuditJsonRet == 0 &&
                       FileContainsText(strEncryptedStorageAuditJson,
                                        "\"plain_private_keys\": 0") &&
                       FileContainsText(strEncryptedStorageAuditJson,
                                        "\"plain_hd_seed\": \"none\"") &&
                       FileContainsText(strEncryptedStorageAuditJson,
                                        "\"encrypted_hd_seed\": \"complete\"") &&
                       FileContainsText(strEncryptedStorageAuditJson,
                                        "\"wallet_minimum_version\": \"present\""),
                       "the storage audit can write encrypted-wallet JSON") ? 0 : 1;
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

static int RunParseMoneySelfTest()
{
    printf("parse-money self-test\n");
    int nFail = 0;
    struct Case { const char* in; bool ok; int64 val; };
    Case cases[] = {
        {"0.5", true, 50000000LL},
        {"1", true, 100000000LL},
        {"1.23456789", true, 123456789LL},
        {"0.00000001", true, 1LL},
        {"10.00000000", true, 1000000000LL},
        {"1,000", true, 100000000000LL},
        {"1.5 ", true, 150000000LL},
        {"0.123456789", false, 0LL},
        {"1.2.3", false, 0LL},
        {"abc", false, 0LL},
        {"-1", false, 0LL},
        {"1e5", false, 0LL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        int64 v = -1;
        bool r = ParseMoney(cases[i].in, v);
        bool pass = (r == cases[i].ok) && (!r || v == cases[i].val);
        char desc[160];
        snprintf(desc, sizeof(desc), "ParseMoney(\"%s\") %s and value matches",
                 cases[i].in, cases[i].ok ? "accepts" : "rejects");
        nFail += Check(pass, desc) ? 0 : 1;
    }
    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static bool SelfTestReadN(SOCKET s, void* buf, int n)
{
    char* p = (char*)buf;
    int off = 0;
    while (off < n)
    {
        int r = recv(s, p + off, n - off, 0);
        if (r <= 0)
            return false;
        off += r;
    }
    return true;
}

static bool SelfTestWriteN(SOCKET s, const void* buf, int n)
{
    const char* p = (const char*)buf;
    int off = 0;
    while (off < n)
    {
        int r = send(s, p + off, n - off, 0);
        if (r <= 0)
            return false;
        off += r;
    }
    return true;
}

static void SelfTestSetSocketTimeout(SOCKET s, int nTimeoutSecs)
{
#ifdef _WIN32
    DWORD tv = (DWORD)nTimeoutSecs * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = nTimeoutSecs;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

#ifdef _WIN32
struct SelfTestWinsock
{
    bool fStarted;
    SelfTestWinsock() : fStarted(false)
    {
        WSADATA wsadata;
        fStarted = (WSAStartup(MAKEWORD(2,2), &wsadata) == 0);
    }
    ~SelfTestWinsock()
    {
        if (fStarted)
            WSACleanup();
    }
};
#endif

static bool RunSocks5HandshakeProbe(std::string& errOut)
{
    errOut.clear();
#ifdef _WIN32
    SelfTestWinsock winsock;
    if (!winsock.fStarted)
    {
        errOut = "could not start Winsock";
        return false;
    }
#endif

    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET)
    {
        errOut = "could not create listener";
        return false;
    }
    SelfTestSetSocketTimeout(listener, 5);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(listener, 1) != 0)
    {
        closesocket(listener);
        errOut = "could not bind/listen on loopback";
        return false;
    }

#ifdef _WIN32
    int addrLen = sizeof(addr);
#else
    socklen_t addrLen = sizeof(addr);
#endif
    if (getsockname(listener, (struct sockaddr*)&addr, &addrLen) != 0)
    {
        closesocket(listener);
        errOut = "could not read listener port";
        return false;
    }
    unsigned short proxyPort = ntohs(addr.sin_port);

    bool fServerOk = false;
    std::string serverErr;
    std::string requestedHost;
    unsigned short requestedPort = 0;
    std::thread server([&]() {
        SOCKET s = accept(listener, NULL, NULL);
        if (s == INVALID_SOCKET)
        {
            serverErr = "accept failed";
            return;
        }
        SelfTestSetSocketTimeout(s, 5);

        unsigned char hello[3] = {0,0,0};
        if (!SelfTestReadN(s, hello, sizeof(hello)) ||
            hello[0] != 0x05 || hello[1] != 0x01 || hello[2] != 0x00)
        {
            serverErr = "bad SOCKS5 greeting";
            closesocket(s);
            return;
        }
        unsigned char choice[2] = {0x05, 0x00};
        if (!SelfTestWriteN(s, choice, sizeof(choice)))
        {
            serverErr = "could not write method choice";
            closesocket(s);
            return;
        }

        unsigned char hdr[5] = {0,0,0,0,0};
        if (!SelfTestReadN(s, hdr, sizeof(hdr)) ||
            hdr[0] != 0x05 || hdr[1] != 0x01 || hdr[2] != 0x00 || hdr[3] != 0x03)
        {
            serverErr = "CONNECT did not use domain-name address type";
            closesocket(s);
            return;
        }

        unsigned char len = hdr[4];
        std::vector<unsigned char> rest((size_t)len + 2);
        if (!SelfTestReadN(s, &rest[0], (int)rest.size()))
        {
            serverErr = "could not read CONNECT target";
            closesocket(s);
            return;
        }
        requestedHost.assign((const char*)&rest[0], (size_t)len);
        requestedPort = ((unsigned short)rest[len] << 8) | rest[len + 1];

        unsigned char reply[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
        if (!SelfTestWriteN(s, reply, sizeof(reply)))
        {
            serverErr = "could not write CONNECT reply";
            closesocket(s);
            return;
        }
        fServerOk = true;
        closesocket(s);
    });

    std::string err;
    BtfClearSocks5Proxy();
    bool fClientOk = BtfSetSocks5Proxy(strprintf("127.0.0.1:%u", (unsigned)proxyPort), err);
    SOCKET client = INVALID_SOCKET;
    if (fClientOk)
        client = BtfConnectSocket("relay.example", 443, SOCK_NOSTR, 5);
    if (client != INVALID_SOCKET)
        BtfCloseSocket(client);
    BtfClearSocks5Proxy();
    closesocket(listener);
    server.join();

    if (!fClientOk)
        errOut = strprintf("could not enable proxy: %s", err.c_str());
    else if (client == INVALID_SOCKET)
        errOut = "client SOCKS5 connect failed";
    else if (!fServerOk)
        errOut = serverErr.empty() ? "mock server failed" : serverErr;
    else if (requestedHost != "relay.example" || requestedPort != 443)
        errOut = strprintf("unexpected CONNECT target %s:%u", requestedHost.c_str(), (unsigned)requestedPort);
    else
        return true;
    return false;
}

static int RunSocks5ProxySelfTest()
{
    printf("socks5-proxy self-test\n");
    int nFail = 0;
    std::string host, err;
    unsigned short port = 0;

    nFail += Check(BtfParseSocks5Proxy("127.0.0.1:9050", host, port, err) &&
                   host == "127.0.0.1" && port == 9050,
                   "parses local Tor proxy endpoint") ? 0 : 1;
    nFail += Check(BtfParseSocks5Proxy("localhost:9050", host, port, err) &&
                   host == "localhost" && port == 9050,
                   "parses hostname proxy endpoint") ? 0 : 1;
    nFail += Check(BtfParseSocks5Proxy("[::1]:9050", host, port, err) &&
                   host == "::1" && port == 9050,
                   "parses bracketed IPv6 proxy endpoint") ? 0 : 1;
    nFail += Check(!BtfParseSocks5Proxy("::1:9050", host, port, err),
                   "rejects unbracketed IPv6 proxy endpoint") ? 0 : 1;
    nFail += Check(!BtfParseSocks5Proxy("localhost", host, port, err),
                   "rejects missing port") ? 0 : 1;
    nFail += Check(!BtfParseSocks5Proxy("localhost:0", host, port, err),
                   "rejects zero port") ? 0 : 1;
    nFail += Check(!BtfParseSocks5Proxy("localhost:70000", host, port, err),
                   "rejects out-of-range port") ? 0 : 1;
    nFail += Check(!BtfParseSocks5Proxy("localhost:999999999999999999999999999999", host, port, err),
                   "rejects overflowing port") ? 0 : 1;
    nFail += Check(!BtfParseSocks5Proxy("user:pass@localhost:9050", host, port, err),
                   "rejects unsupported authenticated proxy syntax") ? 0 : 1;
    nFail += Check(BtfIsTorOnionHost("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion") &&
                   BtfIsTorOnionHost("Relay.Example.ONION.") &&
                   !BtfIsTorOnionHost("relay.example") &&
                   !BtfIsTorOnionHost(".onion"),
                   "detects .onion hosts without accepting lookalikes") ? 0 : 1;
    std::string onion;
    nFail += Check(btf::NormalizeOnionEndpoint("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCD.onion.:8433", onion) &&
                   onion == "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion:8433",
                   "normalizes v3 onion peer endpoint") ? 0 : 1;
    nFail += Check(!btf::NormalizeOnionEndpoint("short.onion:8433", onion) &&
                   !btf::NormalizeOnionEndpoint("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion:0", onion) &&
                   !btf::NormalizeOnionEndpoint("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabc1.onion:8433", onion),
                   "rejects malformed onion peer endpoints") ? 0 : 1;

    BtfClearSocks5Proxy();
    nFail += Check(!BtfSocks5ProxyEnabled(), "starts disabled after clear") ? 0 : 1;
    nFail += Check(BtfSetSocks5Proxy("127.0.0.1:9050", err) &&
                   BtfSocks5ProxyEnabled() &&
                   BtfSocks5ProxyName() == "127.0.0.1:9050",
                   "enables parsed SOCKS5 proxy") ? 0 : 1;
    BtfClearSocks5Proxy();
    nFail += Check(!BtfSocks5ProxyEnabled(), "clear disables proxy") ? 0 : 1;

    nFail += Check(BtfSetSocks5Proxy("[::1]:9050", err) &&
                   BtfSocks5ProxyEnabled() &&
                   BtfSocks5ProxyName() == "[::1]:9050",
                   "enables bracketed IPv6 proxy endpoint") ? 0 : 1;
    BtfClearSocks5Proxy();

    nFail += Check(BtfEnableTorProxy("", err) &&
                   BtfSocks5ProxyEnabled() &&
                   BtfTorProxyEnabled() &&
                   BtfSocks5ProxyName() == "127.0.0.1:9050",
                   "enables Tor mode on the default local SOCKS5 endpoint") ? 0 : 1;
    BtfClearSocks5Proxy();

    nFail += Check(BtfEnableTorProxy("[::1]:9050", err) &&
                   BtfSocks5ProxyEnabled() &&
                   BtfTorProxyEnabled() &&
                   BtfSocks5ProxyName() == "[::1]:9050",
                   "enables Tor mode on a custom IPv6 endpoint") ? 0 : 1;
    BtfClearSocks5Proxy();

    nFail += Check(BtfSetSocks5Proxy("127.0.0.1:9051", err) &&
                   BtfSocks5ProxyEnabled() &&
                   !BtfTorProxyEnabled(),
                   "plain SOCKS5 mode is distinct from Tor mode") ? 0 : 1;
    BtfClearSocks5Proxy();

    std::string handshakeErr;
    bool fHandshakeOk = RunSocks5HandshakeProbe(handshakeErr);
    nFail += Check(fHandshakeOk, handshakeErr.empty() ?
                   "completes SOCKS5 domain-name CONNECT handshake" :
                   strprintf("completes SOCKS5 domain-name CONNECT handshake (%s)",
                             handshakeErr.c_str()).c_str()) ? 0 : 1;

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    fflush(stdout);
    return nFail == 0 ? 0 : 1;
}

static int RunManagedTorSelfTest()
{
    printf("managed-tor self-test\n");
    int nFail = 0;

    std::string torrc = BtfBuildManagedTorrcForTest("C:/Bitflash Managed Tor/data",
                                                   "C:/Bitflash Managed Tor/onion-service",
                                                   19050, 19051, 8433);
    nFail += Check(torrc.find("DataDirectory \"C:/Bitflash Managed Tor/data\"") != std::string::npos,
                   "quotes the Tor data directory") ? 0 : 1;
    nFail += Check(torrc.find("SocksPort 127.0.0.1:19050") != std::string::npos,
                   "binds SOCKS5 to localhost only") ? 0 : 1;
    nFail += Check(torrc.find("ControlPort 127.0.0.1:19051") != std::string::npos &&
                   torrc.find("CookieAuthentication 1") != std::string::npos,
                   "binds an authenticated Tor control port to localhost only") ? 0 : 1;
    nFail += Check(torrc.find("IsolateSOCKSAuth") != std::string::npos &&
                   torrc.find("IsolateClientAddr") != std::string::npos &&
                   torrc.find("IsolateDestAddr") != std::string::npos &&
                   torrc.find("IsolateDestPort") != std::string::npos,
                   "enables strict Tor stream isolation") ? 0 : 1;
    nFail += Check(torrc.find("HiddenServiceDir \"C:/Bitflash Managed Tor/onion-service\"") != std::string::npos,
                   "writes a hidden service directory") ? 0 : 1;
    nFail += Check(torrc.find("HiddenServiceVersion 3") != std::string::npos,
                   "requests a v3 onion service") ? 0 : 1;
    nFail += Check(torrc.find("HiddenServicePort 8433 127.0.0.1:8433") != std::string::npos,
                   "maps the onion service to the Bitflash P2P listener") ? 0 : 1;
    nFail += Check(BtfManagedTorStatus() == "disabled",
                   "managed Tor starts disabled") ? 0 : 1;

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
    if (name == "wallet-storage-sanity")
        return RunWalletStorageSanitySelfTest();
    if (name == "db-env-reopen")
        return RunDbEnvReopenSelfTest();
    if (name == "wallet-sqlite")
        return RunWalletSQLiteSelfTest();
    if (name == "wallet-sqlite-migration")
        return RunWalletSQLiteMigrationSelfTest();
    if (name == "wallet-crypto")
        return RunWalletCryptoSelfTest();
    if (name == "wallet-encrypt")
        return RunWalletEncryptSelfTest();
    if (name == "wallet-portability")
        return RunWalletPortabilitySelfTest();
    if (name == "net-message")
        return RunNetMessageSelfTest();
    if (name == "consensus-limits")
        return RunConsensusLimitsSelfTest();
    if (name == "pool-stratum")
        return RunPoolStratumSelfTest();
    if (name == "parse-money")
        return RunParseMoneySelfTest();
    if (name == "socks5-proxy")
        return RunSocks5ProxySelfTest();
    if (name == "managed-tor")
        return RunManagedTorSelfTest();

    printf("Unknown self-test '%s'\n", name.c_str());
    printf("Known self-tests: wallet-keypool, wallet-hd, wallet-format, wallet-storage-sanity, db-env-reopen, wallet-sqlite, wallet-sqlite-migration, wallet-crypto, wallet-encrypt, wallet-portability, net-message, consensus-limits, pool-stratum, parse-money, socks5-proxy, managed-tor\n");
    return 1;
}
