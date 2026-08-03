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
    if (name == "net-message")
        return RunNetMessageSelfTest();
    if (name == "consensus-limits")
        return RunConsensusLimitsSelfTest();

    printf("Unknown self-test '%s'\n", name.c_str());
    printf("Known self-tests: wallet-keypool, wallet-hd, net-message, consensus-limits\n");
    return 1;
}
