// Bitflash entry point -- starts node threads then runs GUI (or headless).

#include "headers_core.h"
#include "nostr.h"
#include "proxy.h"
#include "selftest.h"
#include "tor.h"
#include "walletcmd.h"
#include <thread>          // hardware_concurrency, to sanity-check /genproclimit
#ifndef _WIN32
#include <csignal>
#endif

// BITFLASH_NO_GUI builds the same entry point without ImGui, GLFW or OpenGL,
// so the binary does not need libGL present just to start. See headless.cpp.
#ifndef BITFLASH_NO_GUI
int RunGUI(int argc, char* argv[]);
#endif

// Global definitions (were in ui.cpp, now here)
map<string,string> mapAddressBook;
bool               gPoolServerRunning = false;

static bool arg(int argc, char* argv[], const char* key)
{
    for (int i=1;i<argc;i++) { string s=argv[i]; if(s==key||s.substr(0,s.find('='))==key) return true; }
    return false;
}
static string argval(int argc, char* argv[], const char* key)
{
    for (int i=1;i<argc;i++) {
        string s=argv[i]; size_t eq=s.find('=');
        if(eq!=string::npos && s.substr(0,eq)==key) return s.substr(eq+1);
    }
    return "";
}

static string argval2(int argc, char* argv[], const char* keySlash, const char* keyDash)
{
    string v = argval(argc, argv, keySlash);
    if (!v.empty())
        return v;
    return argval(argc, argv, keyDash);
}

static bool ReadPassphraseArgument(const string& strArg, string& strPassphraseRet, string& strErrorRet)
{
    strPassphraseRet.clear();
    strErrorRet.clear();
    if (strArg.empty())
    {
        AttachTerminal();
        fprintf(stderr, "Enter wallet passphrase: ");
        fflush(stderr);
        char buf[4096];
        if (!fgets(buf, sizeof(buf), stdin))
        {
            strErrorRet = "could not read passphrase from stdin";
            return false;
        }
        strPassphraseRet = buf;
    }
    else if (strArg[0] == '@')
    {
        string strPath = strArg.substr(1);
        FILE* pf = fopen(strPath.c_str(), "rb");
        if (!pf)
        {
            strErrorRet = strprintf("could not read passphrase file %s", strPath.c_str());
            return false;
        }
        char buf[4096];
        if (!fgets(buf, sizeof(buf), pf))
        {
            fclose(pf);
            strErrorRet = strprintf("passphrase file %s is empty", strPath.c_str());
            return false;
        }
        fclose(pf);
        strPassphraseRet = buf;
    }
    else
    {
        strErrorRet = "passphrase literals on the command line are unsafe; use the option without a value to read stdin, or use @FILE";
        return false;
    }

    while (!strPassphraseRet.empty() &&
           (strPassphraseRet[strPassphraseRet.size() - 1] == '\n' ||
            strPassphraseRet[strPassphraseRet.size() - 1] == '\r'))
        strPassphraseRet.resize(strPassphraseRet.size() - 1);
    if (strPassphraseRet.empty())
    {
        strErrorRet = "empty passphrase";
        return false;
    }
    return true;
}

// The real printf, not the one util.h remaps to OutputDebugStringF. Help that
// goes to debug.log is help nobody asked for: `-help` printed a full page into
// the data directory and returned 0 with an empty terminal, which reads as a
// command that does nothing. Same reason walletcmd.cpp undefines it.
#undef printf

static void PrintUsage()
{
    printf("Bitflash command-line options\n");
    printf("\n");
    printf("General:\n");
    printf("  /help, -help, --help, /?\n");
    printf("  /datadir=PATH\n");
    printf("  /debug\n");
    printf("  /gen\n");
    printf("  /nogui or /daemon\n");
    printf("  /selftest=wallet-keypool, wallet-hd, wallet-format, wallet-storage-sanity,\n");
    printf("            db-env-reopen, wallet-sqlite, wallet-sqlite-migration,\n");
    printf("            wallet-crypto, wallet-encrypt, wallet-portability,\n");
    printf("            net-message,\n");
    printf("            consensus-limits, pool-stratum,\n");
    printf("            parse-money, network-params, socks5-proxy, or managed-tor\n");
    printf("\n");
    printf("Mining mode:\n");
    printf("  /operator\n");
    printf("  /participant=POOL_BTF_ADDRESS\n");
    printf("  /stratumbridge=POOL_BTF_ADDRESS\n");
    printf("  /stratumbridgeport=N       (default 3333; listen on 127.0.0.1)\n");
    printf("  /solomine\n");
    printf("  /genproclimit=N            (mining threads; 0 or absent = every core but one)\n");
    printf("  /nolargepages              (do not ask for 2 MB pages for the RandomX\n");
    printf("                              cache, dataset and scratchpads)\n");
    printf("  /checkblocks=N             (blocks re-verified at startup, default 288, 0 = all)\n");
    printf("\n");
    printf("Pool operator announcement:\n");
    printf("  /poolname=NAME\n");
    printf("  /poolfee=PCT\n");
    printf("  /pooldashboard=URL  (alias: /pooldash=URL)\n");
    printf("  /poolstatusfile=PATH       (write pool status JSON for dashboards)\n");
    printf("  /poolroundsfile=PATH       (write public pool round proofs JSON)\n");
    printf("\n");
    printf(".btf and rendezvous:\n");
    printf("  /connectbtf=PEER_BTF_ADDRESS\n");
    printf("  /rvrelay=HOST:PORT\n");
    printf("  /announcerelay=HOST:PORT\n");
    printf("  /onionservice=HOST.onion:PORT  (advertise this node's Tor hidden service)\n");
    printf("\n");
    printf("Network:\n");
    printf("  /testnet                   (isolated test network genesis, datadir, port, and magic)\n");
    printf("  /port=N                    (P2P listen port, default 8433; testnet 18433)\n");
    printf("  /socks=HOST:PORT           (SOCKS5 proxy for Nostr, .btf relay, and onion dials)\n");
    printf("  /tor[=HOST:PORT]           (Tor mode; default SOCKS5 proxy is 127.0.0.1:9050)\n");
    printf("  /managedtor[=PATH]         (start Tor, create a hidden service, advertise its onion)\n");
    printf("  /nomanagedtor              (disable automatic bundled Tor startup)\n");
    printf("  /oniononly                 (do not fall back to rendezvous when a .btf onion dial fails)\n");
    printf("  /btfseed=ADDRESS:ENCHEX    (extra bootstrap peer, repeatable)\n");
    printf("\n");
    printf("Wallet:\n");
    printf("  /backupwallet=FILE         (write a wallet.dat that opens on its own,\n");
    printf("                              then exit; run it again after new addresses)\n");
    printf("  /dumpwallet=FILE           (export private keys as text -- readable by\n");
    printf("                              anyone, so guard it like cash)\n");
    printf("  /importwallet=FILE         (load keys from such a file back in)\n");
    printf("  /encryptwallet[=@FILE]     (rewrite wallet.dat with encrypted private keys\n");
    printf("                              and encrypted HD seed, then exit)\n");
    printf("  /walletpassphrase[=@FILE]  (unlock an encrypted wallet for one-shot\n");
    printf("                              commands; without @FILE reads stdin)\n");
    printf("  /newaddress                (print the next receiving address, then exit)\n");
    printf("  /sendto=ADDRESS,AMOUNT     (spend from this wallet, then exit -- the\n");
    printf("                              only way to send without the window)\n");
    printf("  /newphrase                 (create a twelve-word recovery phrase for a\n");
    printf("                              wallet that has none, show it once, exit)\n");
    printf("  /restorephrase=\"WORDS\"     (rebuild this wallet from a phrase and scan\n");
    printf("                              the chain for its coins, then exit)\n");
    printf("  /restoredepth=N            (with /restorephrase: derive at least N\n");
    printf("                              addresses before giving up)\n");
    printf("  /showderived=N             (list the first N addresses a phrase\n");
    printf("                              installed in this wallet derives)\n");
    printf("  /recoveryaudit             (show how much spendable balance is\n");
    printf("                              covered by the recovery phrase;\n");
    printf("                              exits 2 when wallet.dat is still needed)\n");
    printf("  /walletstorageaudit        (count wallet.dat record types without\n");
    printf("                              printing wallet values, then exit)\n");
    printf("  /walletstorageauditjson=FILE\n");
    printf("                              (write the same audit as deterministic JSON)\n");
    printf("  /walletstoragecheck        (fail closed on inconsistent or unsafe\n");
    printf("                              wallet.dat storage state)\n");
    printf("  /walletsqliteexport=FILE   (copy raw wallet.dat records into an\n");
    printf("                              SQLite store, then exit)\n");
    printf("  /walletsqliteverify=FILE   (compare wallet.dat with a SQLite export,\n");
    printf("                              printing counts only, then exit)\n");
    printf("  /walletsqliterestore=FILE  (rebuild wallet.dat from a SQLite export in\n");
    printf("                              an empty data directory, then exit)\n");
    printf("  /walletsqliteloadcheck=FILE\n");
    printf("                              (parse a SQLite export like the wallet loader)\n");
    printf("  /walletsqlite=FILE         (stage-load a SQLite wallet export, then exit)\n");
    printf("  /walletbackend=sqlite      (opt-in: run the node on <datadir>/wallet.sqlite\n");
    printf("                              instead of wallet.dat; export one first)\n");
    printf("  /rescan                    (walk the chain for coins this wallet owns\n");
    printf("                              but never recorded, then exit)\n");
    printf("\n");
    printf("Each option also accepts '-' instead of '/'.\n");
}

#define printf OutputDebugStringF

static void ParseStartupArguments(int argc, char* argv[])
{
    if (arg(argc,argv,"/datadir") || arg(argc,argv,"-datadir"))
        strSetDataDir = argval2(argc, argv, "/datadir", "-datadir");

    bool fUseTestNet = arg(argc, argv, "/testnet") || arg(argc, argv, "-testnet");
    SelectChainParams(fUseTestNet);

    if (arg(argc,argv,"/debug") || arg(argc,argv,"-debug"))
        fDebug = true;

    if (arg(argc,argv,"/gen") || arg(argc,argv,"-gen"))
    {
        fGenerateBitcoins = 1;
        // Mining mode defaults to MINE_RELAY, and nothing in this parser ever
        // changed it, so BitcoinMiner() returned immediately at its relay guard
        // and /gen mined nothing at all. /operator and /participant still set
        // their own mode below, so only the unqualified case is affected.
        if (nMineMode == MINE_RELAY)
            nMineMode = MINE_SOLO;
        fMineModeFromCommandLine = true;
    }

    if (arg(argc,argv,"/solomine") || arg(argc,argv,"-solomine"))
        fSoloMineTest = true;

    string strCheckBlocks = argval2(argc, argv, "/checkblocks", "-checkblocks");
    if (!strCheckBlocks.empty())
        nCheckBlocksOnLoad = atoi(strCheckBlocks.c_str());

    // Must be read before LoadBlockIndex(), which is what first calls
    // RandomXInit() and fixes how the cache is allocated.
    if (arg(argc,argv,"/nolargepages") || arg(argc,argv,"-nolargepages"))
        fRandomXLargePages = false;

    // /genproclimit=N -- threads to hash with. 0 or absent means automatic,
    // which is every core but one. Named after Bitcoin's own option so it reads
    // familiarly to anyone who has run one of these before.
    string strProcLimit = argval2(argc, argv, "/genproclimit", "-genproclimit");
    if (!strProcLimit.empty())
    {
        int n = atoi(strProcLimit.c_str());
        unsigned int nCores = std::thread::hardware_concurrency();
        if (n < 0)
            fprintf(stderr, "Ignoring /genproclimit=%s: not a thread count\n",
                    strProcLimit.c_str());
        else if (nCores > 0 && n > (int)nCores * 4)
            // Well past diminishing returns, and every thread still costs a
            // scratchpad. Refuse rather than quietly thrash the machine.
            fprintf(stderr, "Ignoring /genproclimit=%d: this machine has %u core(s)\n",
                    n, nCores);
        else
            nMinerThreads = n;   // 0 stays automatic
    }

    if (arg(argc,argv,"/operator") || arg(argc,argv,"-operator"))
    {
        nMineMode = MINE_OPERATOR;
        fMineModeFromCommandLine = true;
    }

    if (arg(argc,argv,"/participant") || arg(argc,argv,"-participant"))
    {
        nMineMode = MINE_PARTICIPANT;
        strParticipantPool = argval2(argc, argv, "/participant", "-participant");
        fMineModeFromCommandLine = true;
    }

    if (arg(argc,argv,"/stratumbridge") || arg(argc,argv,"-stratumbridge"))
    {
        fStratumBridge = true;
        string bridgePool = argval2(argc, argv, "/stratumbridge", "-stratumbridge");
        if (!bridgePool.empty())
            strParticipantPool = bridgePool;
    }

    string bridgePort = argval2(argc, argv, "/stratumbridgeport", "-stratumbridgeport");
    if (!bridgePort.empty())
    {
        int nPort = atoi(bridgePort.c_str());
        if (nPort > 0 && nPort <= 65535)
            nStratumBridgePort = nPort;
    }

    string poolName = argval2(argc, argv, "/poolname", "-poolname");
    if (!poolName.empty())
        strPoolName = poolName;

    string poolDash = argval2(argc, argv, "/pooldashboard", "-pooldashboard");
    if (poolDash.empty())
        poolDash = argval2(argc, argv, "/pooldash", "-pooldash");
    if (!poolDash.empty())
        strPoolDashboardUrl = poolDash;

    string poolFee = argval2(argc, argv, "/poolfee", "-poolfee");
    if (!poolFee.empty())
        dPoolFeePercent = atof(poolFee.c_str());

    string poolStatusFile = argval2(argc, argv, "/poolstatusfile", "-poolstatusfile");
    if (!poolStatusFile.empty())
        strPoolStatusFile = poolStatusFile;

    string poolRoundsFile = argval2(argc, argv, "/poolroundsfile", "-poolroundsfile");
    if (!poolRoundsFile.empty())
        strPoolRoundsFile = poolRoundsFile;

    string btfConnect = argval2(argc, argv, "/connectbtf", "-connectbtf");
    if (!btfConnect.empty())
        strBtfConnect = btfConnect;
    fBtfOnionOnly = arg(argc, argv, "/oniononly") || arg(argc, argv, "-oniononly");

    string rvRelay = argval2(argc, argv, "/rvrelay", "-rvrelay");
    if (!rvRelay.empty())
    {
        vBtfMeetingRelays.clear();
        vBtfMeetingRelays.push_back(rvRelay);
    }

    // net.cpp has described nListenPort as "tunable via /port" since it was
    // written, but nothing ever read the option, so the port was fixed at 8433
    // and a second node could not start on a machine already running one. Parse
    // it before Tor setup so a managed hidden service maps the real listener.
    string strPort = argval2(argc, argv, "/port", "-port");
    if (!strPort.empty())
    {
        int nPort = atoi(strPort.c_str());
        if (nPort <= 0 || nPort > 65535)
            fprintf(stderr, "Ignoring /port=%s: not a port number\n", strPort.c_str());
        else
        {
            nListenPort = htons((unsigned short)nPort);
            // Or we would announce a port we never bound.
            addrLocalHost.port = nListenPort;
        }
    }

    string announceRelay = argval2(argc, argv, "/announcerelay", "-announcerelay");
    if (!announceRelay.empty())
        strBtfAnnounceRelay = announceRelay;

    string onionService = argval2(argc, argv, "/onionservice", "-onionservice");
    if (!onionService.empty())
    {
        string err;
        if (!BtfSetLocalOnionEndpoint(onionService, err))
            fprintf(stderr, "Ignoring /onionservice=%s: %s\n", onionService.c_str(), err.c_str());
        else
            fprintf(stderr, "Direct onion peer endpoint advertised: %s\n",
                    BtfLocalOnionEndpoint().c_str());
    }

    bool fManagedTor = arg(argc, argv, "/managedtor") || arg(argc, argv, "-managedtor");
    bool fNoManagedTor = arg(argc, argv, "/nomanagedtor") || arg(argc, argv, "-nomanagedtor");
    bool fTorMode = arg(argc, argv, "/tor") || arg(argc, argv, "-tor");
    string socksProxy = argval2(argc, argv, "/socks", "-socks");
    string bundledTorPath;
    bool fAutoManagedTor = !fManagedTor && !fNoManagedTor && !fTorMode &&
                            socksProxy.empty() && BtfBundledTorPath(bundledTorPath);
    if (fManagedTor || fAutoManagedTor)
    {
        if (fManagedTor && (fTorMode || !socksProxy.empty()))
            fprintf(stderr, "Warning: /managedtor takes precedence over /tor and /socks\n");

        string torPath = fManagedTor ? argval2(argc, argv, "/managedtor", "-managedtor") : bundledTorPath;
        string err;
        if (!BtfStartManagedTor(torPath, err))
        {
            if (fAutoManagedTor)
                fprintf(stderr, "Bundled Tor not enabled automatically: %s\n", err.c_str());
            else
                fprintf(stderr, "Ignoring /managedtor=%s: %s\n", torPath.c_str(), err.c_str());
        }
        else
            fprintf(stderr, "Managed Tor enabled%s: %s\n",
                    fAutoManagedTor ? " automatically" : "",
                    BtfManagedTorStatus().c_str());
    }
    else if (fTorMode)
    {
        if (!socksProxy.empty())
            fprintf(stderr, "Warning: /tor takes precedence over /socks=%s\n",
                    socksProxy.c_str());

        string torProxy = argval2(argc, argv, "/tor", "-tor");
        string err;
        if (!BtfEnableTorProxy(torProxy, err))
            fprintf(stderr, "Ignoring /tor=%s: %s\n", torProxy.c_str(), err.c_str());
        else
            fprintf(stderr, "Tor mode enabled through SOCKS5 proxy %s\n",
                    BtfSocks5ProxyName().c_str());
    }
    else
    {
        if (!socksProxy.empty())
        {
            string err;
            if (!BtfSetSocks5Proxy(socksProxy, err))
                fprintf(stderr, "Ignoring /socks=%s: %s\n", socksProxy.c_str(), err.c_str());
            else
                fprintf(stderr, "SOCKS5 proxy enabled for outbound discovery/relay dials: %s\n",
                        BtfSocks5ProxyName().c_str());
        }
    }
    if (fBtfOnionOnly && !BtfSocks5ProxyEnabled())
        fprintf(stderr, "Warning: /oniononly without /tor, /managedtor, or /socks cannot dial .onion peers\n");

    // /btfseed=ADDRESS:ENCHEX -- extra bootstrap peers, repeatable. Useful for
    // testing the seed path and for private networks that ship no compiled list.
    for (int i = 1; i < argc; i++)
    {
        string s = argv[i];
        size_t eq = s.find('=');
        if (eq == string::npos) continue;
        string key = s.substr(0, eq);
        if (key != "/btfseed" && key != "-btfseed") continue;
        string val = s.substr(eq + 1);
        size_t colon = val.rfind(':');
        if (colon == string::npos || colon + 1 >= val.size())
        {
            fprintf(stderr, "Ignoring %s: expected ADDRESS:ENCHEX\n", s.c_str());
            continue;
        }
        vBtfExtraSeeds.push_back(make_pair(val.substr(0, colon), val.substr(colon + 1)));
    }

}

// Report a startup failure somewhere the user will actually see it.
//
// Every fatal path here wrote to stderr and to printf, and on the platform most
// people use, neither reaches anybody. printf is remapped to OutputDebugStringF,
// so it lands in debug.log inside the data directory. A -mwindows binary
// launched by double-clicking has no stderr at all, and AttachTerminal() cannot
// help: it attaches to a *parent* console, which a double-clicked exe does not
// have.
//
// So the program exited silently. Someone whose wallet.dat needs a newer build
// -- which is exactly what the wallet format guard was added to tell them --
// double-clicked Bitflash and watched nothing happen.
//
// The box is deliberately not shown for a headless node: those run under
// scheduled tasks and services, where a modal dialog waits forever for a click
// nobody is there to make. Headless already has a console when it has one, and
// its output goes to stderr and the log as before.
static void FatalStartupError(bool fHeadless, const string& strWhat, const string& strDetail)
{
    printf("FATAL: %s\n", strWhat.c_str());
    if (!strDetail.empty())
        printf("FATAL: %s\n", strDetail.c_str());

    AttachTerminal();
    fprintf(stderr, "%s\n", strWhat.c_str());
    if (!strDetail.empty())
        fprintf(stderr, "%s\n", strDetail.c_str());
    fflush(stderr);

#ifdef _WIN32
    if (!fHeadless && GetConsoleWindow() == NULL)
    {
        string strBody = strWhat;
        if (!strDetail.empty())
            strBody += "\n\n" + strDetail;
        strBody += "\n\nNothing was changed. More detail is in debug.log, "
                   "inside the data directory.";
        MessageBoxA(NULL, strBody.c_str(), "Bitflash", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
    }
#else
    (void)fHeadless;
#endif
}

#ifdef _WIN32
// Windows equivalent of the SIGINT/SIGTERM handler the headless loop installs on
// POSIX. Without it a headless node on Windows had no way to reach the clean
// StopNode()+DBFlush() path: Ctrl-C, closing the console window, a service stop
// and OS shutdown all killed it mid-write, and a wallet.dat left unflushed by
// Berkeley DB will not reopen. For CLOSE/LOGOFF/SHUTDOWN the OS terminates us
// shortly after the handler returns, so we set fShutdown and then block until the
// main loop signals the flush is done -- returning any sooner throws the flush
// away, which is the whole bug. (A `taskkill /F` is still an uncatchable hard
// kill; nothing can help there, and nothing should pretend to.)
static volatile bool g_fHeadlessShutdownDone = false;
static BOOL WINAPI HeadlessConsoleCtrlHandler(DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        fShutdown = true;
        while (!g_fHeadlessShutdownDone)
            Sleep(50);
        return TRUE;
    default:
        return FALSE;
    }
}
#endif

int main(int argc, char* argv[])
{
    if (arg(argc,argv,"/help") || arg(argc,argv,"-help") ||
        arg(argc,argv,"--help") || arg(argc,argv,"/?"))
    {
        // Without this the help prints into nothing. A -mwindows binary starts
        // with no console, so every one of those printfs went nowhere and the
        // one command whose entire job is to tell you something told you
        // nothing at all -- exit code 0, not a byte of output.
        AttachTerminal();
        PrintUsage();
        return 0;
    }

    ParseStartupArguments(argc, argv);

#ifdef _WIN32
    // Set by the GUI "Restart Now" button: give the previous instance a moment
    // to release the network port and the block-index files before this one
    // opens them, so a relaunch does not race the process it is replacing.
    if (arg(argc, argv, "/restartwait") || arg(argc, argv, "-restartwait"))
        Sleep(2500);
#endif

    // Hidden self-test helper. It must run before LoadWallet(): several
    // storage-sanity scenarios deliberately make wallet.dat unsafe to load.
    string strSelfTestMutateWallet =
        argval2(argc, argv, "/selftestmutatewallet", "-selftestmutatewallet");
    if (!strSelfTestMutateWallet.empty())
        return RunSelfTestMutateWallet(strSelfTestMutateWallet);

    string strSelfTest = argval2(argc, argv, "/selftest", "-selftest");
    if (!strSelfTest.empty())
        return RunSelfTest(strSelfTest);

    // Storage diagnostics must run before LoadWallet(). Their job is to
    // explain wallet.dat states that the normal wallet loader may refuse.
    string strWalletStorageAuditJson =
        argval2(argc, argv, "/walletstorageauditjson", "-walletstorageauditjson");
    bool fDiagWantsAudit = arg(argc,argv,"/walletstorageaudit") ||
                           arg(argc,argv,"-walletstorageaudit") ||
                           !strWalletStorageAuditJson.empty();
    bool fDiagWantsCheck = arg(argc,argv,"/walletstoragecheck") ||
                           arg(argc,argv,"-walletstoragecheck");

    // These diagnostics normally read wallet.dat. Under -walletbackend=sqlite
    // the live wallet is wallet.sqlite, so open it read-only as the active
    // store and let the same scan walk the right file. This runs before the
    // normal backend resolution further down, so validate the value here too.
    string strDiagBackend = argval2(argc, argv, "/walletbackend", "-walletbackend");
    if ((fDiagWantsAudit || fDiagWantsCheck) && !strDiagBackend.empty() &&
        strDiagBackend != "sqlite" && strDiagBackend != "bdb")
    {
        AttachTerminal();
        fprintf(stderr, "Unknown wallet backend '%s'. Use -walletbackend=sqlite "
                        "or -walletbackend=bdb.\n", strDiagBackend.c_str());
        return 1;
    }
    bool fDiagSQLite = (strDiagBackend == "sqlite") &&
                       (fDiagWantsAudit || fDiagWantsCheck);
    if (fDiagSQLite)
    {
        AttachTerminal();
        string strSQLitePath = GetAppDir() + "/wallet.sqlite";
        string strOpenErr;
        if (!WalletSQLiteRuntimeOpenReadOnly(strSQLitePath, strOpenErr))
        {
            fprintf(stderr, "Cannot open the SQLite wallet for diagnostics: %s\n",
                    strOpenErr.c_str());
            return 1;
        }
    }

    if (fDiagWantsAudit)
    {
        int nRet = CmdWalletStorageAudit(strWalletStorageAuditJson);
        if (fDiagSQLite)
            WalletSQLiteRuntimeClose();
        else
            DBFlush(true);
        return nRet;
    }

    if (fDiagWantsCheck)
    {
        int nRet = CmdWalletStorageCheck();
        if (fDiagSQLite)
            WalletSQLiteRuntimeClose();
        else
            DBFlush(true);
        return nRet;
    }

    string strWalletSQLiteExport =
        argval2(argc, argv, "/walletsqliteexport", "-walletsqliteexport");
    if (!strWalletSQLiteExport.empty())
    {
        int nRet = CmdWalletSQLiteExport(strWalletSQLiteExport);
        DBFlush(true);
        return nRet;
    }

    string strWalletSQLiteVerify =
        argval2(argc, argv, "/walletsqliteverify", "-walletsqliteverify");
    if (!strWalletSQLiteVerify.empty())
    {
        int nRet = CmdWalletSQLiteVerify(strWalletSQLiteVerify);
        DBFlush(true);
        return nRet;
    }

    string strWalletSQLiteRestore =
        argval2(argc, argv, "/walletsqliterestore", "-walletsqliterestore");
    if (!strWalletSQLiteRestore.empty())
    {
        int nRet = CmdWalletSQLiteRestore(strWalletSQLiteRestore);
        DBFlush(true);
        return nRet;
    }

    string strWalletSQLiteLoadCheck =
        argval2(argc, argv, "/walletsqliteloadcheck", "-walletsqliteloadcheck");
    if (!strWalletSQLiteLoadCheck.empty())
    {
        int nRet = CmdWalletSQLiteLoadCheck(strWalletSQLiteLoadCheck);
        DBFlush(true);
        return nRet;
    }

    // Berkeley DB reports failure by throwing, and CDB's constructor lets it
    // through. Nothing on this path caught anything, so an unreadable
    // blkindex.dat or wallet.dat -- one written by another platform's Berkeley
    // DB, a truncated file, a version mismatch -- unwound out of main() into
    // std::terminate and abort(). On Windows that surfaces as
    // STATUS_STACK_BUFFER_OVERRUN (0xC0000409) inside ucrtbase.dll: no message,
    // no log line past "Loading wallet...", and a faulting module with nothing
    // to do with the real problem. Confirmed by stack trace:
    //
    //   libdb_cxx-6.2.dll -> CDB::CDB(...) -> LoadBlockIndex(...) -> main()
    //
    // The program knew what had gone wrong and threw the reason away.
    // Needed here, long before the headless branch runs, because whether a
    // startup failure may pop a dialog depends on it.
#ifdef BITFLASH_NO_GUI
    bool fHeadlessStartup = true;
#else
    bool fHeadlessStartup = arg(argc,argv,"/nogui") || arg(argc,argv,"-nogui") ||
                            arg(argc,argv,"/daemon") || arg(argc,argv,"-daemon");
#endif

    string strErrors;
    printf("Loading block index...\n");
    try
    {
        if (!LoadBlockIndex())
        {
            FatalStartupError(fHeadlessStartup, "Cannot load the block index.", "");
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        FatalStartupError(fHeadlessStartup,
                          strprintf("Cannot read the block index: %s", e.what()),
                          "blkindex.dat and blk0001.dat may be from another machine or "
                          "incomplete. Deleting both is safe -- they are re-downloaded -- "
                          "but never delete wallet.dat, which holds your keys.");
        return 1;
    }

    printf("Loading wallet...\n");
    try
    {
        string strWalletBackend =
            argval2(argc, argv, "/walletbackend", "-walletbackend");
        string strWalletSQLite =
            argval2(argc, argv, "/walletsqlite", "-walletsqlite");

        // A misspelled backend must not fall through to Berkeley DB silently --
        // someone who typed -walletbackend=sqlit meant to run on SQLite, and
        // opening wallet.dat instead of telling them is the wrong surprise.
        if (!strWalletBackend.empty() &&
            strWalletBackend != "sqlite" && strWalletBackend != "bdb")
        {
            AttachTerminal();
            FatalStartupError(fHeadlessStartup,
                strprintf("Unknown wallet backend '%s'.", strWalletBackend.c_str()),
                "Use -walletbackend=sqlite for the SQLite backend, or "
                "-walletbackend=bdb for the Berkeley DB wallet.dat.");
            return 1;
        }

        if (strWalletBackend == "sqlite")
        {
            // Explicit opt-in via the flag. The node runs on
            // <datadir>/wallet.sqlite and never opens wallet.dat, but the user
            // has to have exported one first -- there is no silent migration,
            // and wallet.dat is left
            // exactly where it is so a plain restart goes back to it.
            AttachTerminal();
            string strSQLitePath = GetAppDir() + "/wallet.sqlite";
            if (!FileExists(strSQLitePath.c_str()))
            {
                string strGuide = strprintf(
                    "No SQLite wallet was found at\n"
                    "  %s\n\n"
                    "The SQLite wallet backend is opt-in and needs an exported\n"
                    "wallet first. Your Berkeley DB wallet.dat is not touched by\n"
                    "any of this.\n\n"
                    "  Step 1  Export your existing wallet to SQLite:\n"
                    "            bitflash -walletsqliteexport=\"%s\"\n"
                    "  Step 2  Start again with the SQLite backend:\n"
                    "            bitflash -walletbackend=sqlite\n\n"
                    "To go back to Berkeley DB at any time, just start without\n"
                    "-walletbackend=sqlite. wallet.dat is still your wallet.",
                    strSQLitePath.c_str(), strSQLitePath.c_str());
                FatalStartupError(fHeadlessStartup,
                                  "The SQLite wallet backend needs an exported wallet first.",
                                  strGuide);
                return 1;
            }

            if (!LoadWalletFromSQLiteRuntime(strSQLitePath))
            {
                FatalStartupError(fHeadlessStartup,
                                  "Cannot open the SQLite wallet backend.",
                                  strWalletLoadError);
                return 1;
            }

            fprintf(stderr,
                    "Wallet backend: SQLite\n"
                    "  %s\n"
                    "Your Berkeley DB wallet.dat is left untouched. Restart without\n"
                    "-walletbackend=sqlite to go back to it.\n",
                    strSQLitePath.c_str());
            fflush(stderr);
            // Fall through and run the node normally: every CWalletDB read,
            // write, and erase now routes to this SQLite file.
        }
        else if (!strWalletSQLite.empty())
        {
            AttachTerminal();
            if (!LoadWalletFromSQLite(strWalletSQLite))
            {
                FatalStartupError(fHeadlessStartup,
                                  "Cannot open SQLite wallet export.",
                                  strWalletLoadError);
                return 1;
            }

            fprintf(stderr, "SQLite wallet loaded: read-only staging backend\n");
            fprintf(stderr, "SQLite runtime writes are not enabled yet; exiting before "
                            "network, mining, GUI, or wallet mutation starts.\n");
            fflush(stderr);
            DBFlush(true);
            return 0;
        }
        else if (strWalletBackend == "bdb")
        {
            // Explicit -walletbackend=bdb overrides the marker and the default:
            // force Berkeley DB (LoadWallet creates wallet.dat if none exists).
            if (!LoadWallet())
            {
                FatalStartupError(fHeadlessStartup, "Cannot open wallet.dat.",
                                  strWalletLoadError);
                return 1;
            }
        }
        else
        {
            // No explicit -walletbackend on the command line. Resolve it from
            // the persistent marker, then defaults: an existing wallet.sqlite
            // stays on SQLite, an existing wallet.dat stays on Berkeley DB (the
            // GUI offers to convert), and a fresh install starts on SQLite --
            // the new default. wallet.dat is never touched by any of this.
            string strSQLitePath = GetAppDir() + "/wallet.sqlite";
            bool fSQLiteExists = FileExists(strSQLitePath.c_str());
            bool fWalletDatExists = FileExists((GetAppDir() + "/wallet.dat").c_str());
            string strMarker = ReadWalletBackendMarker();

            bool fUseSQLite = false;
            bool fCreateSQLite = false;
            if (strMarker == "sqlite")
            {
                if (fSQLiteExists)          fUseSQLite = true;
                else if (fWalletDatExists)  fUseSQLite = false;  // marker stale; real wallet is BDB
                else { fUseSQLite = true; fCreateSQLite = true; }
            }
            else if (strMarker == "bdb")
            {
                fUseSQLite = false;
            }
            else  // no marker recorded yet
            {
                if (fSQLiteExists && !fWalletDatExists) fUseSQLite = true;
                else if (fWalletDatExists)              fUseSQLite = false;
                else { fUseSQLite = true; fCreateSQLite = true; }
            }

            if (fUseSQLite)
            {
                AttachTerminal();
                bool fOk = fCreateSQLite
                    ? CreateNewSQLiteWallet(strSQLitePath)
                    : LoadWalletFromSQLiteRuntime(strSQLitePath);
                if (!fOk)
                {
                    FatalStartupError(fHeadlessStartup,
                        fCreateSQLite ? "Cannot create the SQLite wallet."
                                      : "Cannot open the SQLite wallet.",
                        strWalletLoadError);
                    return 1;
                }
                // Record the choice so it is stable from here on.
                if (ReadWalletBackendMarker() != "sqlite")
                    WriteWalletBackendMarker("sqlite");
                fprintf(stderr, "Wallet backend: SQLite\n  %s\n%s",
                        strSQLitePath.c_str(),
                        fCreateSQLite ? "A new wallet was created here.\n" : "");
                fflush(stderr);
                // Fall through and run the node; CWalletDB routes to this file.
            }
            else if (!LoadWallet())
            {
                // LoadWallet() explains itself into strWalletLoadError when it
                // knows why -- an unsupported wallet format, for one, which is
                // the case this whole path exists to make visible.
                FatalStartupError(fHeadlessStartup, "Cannot open wallet.dat.",
                                  strWalletLoadError);
                return 1;
            }
        }

        // After the block index, so there is a chain to compare the wallet
        // against, and before anything reports a balance. Works on either
        // backend: RescanSpentFlags writes corrected flags through CWalletDB,
        // which routes to SQLite when that backend is active.
        RescanSpentFlags();
    }
    catch (const std::exception& e)
    {
        FatalStartupError(fHeadlessStartup,
                          strprintf("Cannot read wallet.dat: %s", e.what()),
                          "The file was left untouched. A wallet.dat written by a "
                          "different platform's Berkeley DB is the usual cause; back it "
                          "up before trying anything else.");
        return 1;
    }
    printf("Height=%d\n", nBestHeight);

    bool fEncryptWallet = arg(argc, argv, "/encryptwallet") || arg(argc, argv, "-encryptwallet");
    string strEncryptWallet = argval2(argc, argv, "/encryptwallet", "-encryptwallet");
    if (fEncryptWallet)
    {
        string strPassphrase;
        string strPassphraseError;
        if (!ReadPassphraseArgument(strEncryptWallet, strPassphrase, strPassphraseError))
        {
            fprintf(stderr, "Cannot read encryption passphrase: %s\n", strPassphraseError.c_str());
            DBFlush(true);
            return 1;
        }
        int nRet = CmdEncryptWallet(strPassphrase);
        if (nRet != 0)
            DBFlush(true);
        return nRet;
    }

    bool fWalletPassphrase = arg(argc, argv, "/walletpassphrase") || arg(argc, argv, "-walletpassphrase");
    string strWalletPassphrase = argval2(argc, argv, "/walletpassphrase", "-walletpassphrase");
    if (fWalletPassphrase)
    {
        string strPassphrase;
        string strUnlockError;
        if (!ReadPassphraseArgument(strWalletPassphrase, strPassphrase, strUnlockError) ||
            !UnlockWallet(strPassphrase, strUnlockError))
        {
            fprintf(stderr, "Cannot unlock wallet: %s\n", strUnlockError.c_str());
            DBFlush(true);
            return 1;
        }
    }

    // Before the node opens sockets or touches anything: the wallet is loaded,
    // which is all a backup needs, and finishing here means the copy is taken
    // from a quiet directory rather than from under a running node.
    string strBackup = argval2(argc, argv, "/backupwallet", "-backupwallet");
    if (!strBackup.empty())
    {
        bool fOk = BackupWallet(strBackup);
        if (fOk)
        {
            printf("Backed up to %s\n", strBackup.c_str());
            printf("This file opens on its own -- it does not need the database/ "
                   "directory beside it.\n");
            printf("It is a snapshot: coins paid to addresses created after now are "
                   "not in it, so back up again whenever you receive to a new address.\n");
        }
        else
            fprintf(stderr, "Backup failed -- nothing was written.\n");
        DBFlush(true);
        return fOk ? 0 : 1;
    }

    string strDump = argval2(argc, argv, "/dumpwallet", "-dumpwallet");
    if (!strDump.empty())
    {
        bool fOk = DumpWallet(strDump);
        if (fOk)
        {
            printf("Wrote %s\n", strDump.c_str());
            printf("It holds your private keys as readable text. Anyone with the file "
                   "can spend these coins -- keep it off shared storage and delete it "
                   "once you have it somewhere safe.\n");
        }
        else
            fprintf(stderr, "Export failed -- nothing was written.\n");
        DBFlush(true);
        return fOk ? 0 : 1;
    }

    string strImport = argval2(argc, argv, "/importwallet", "-importwallet");
    if (!strImport.empty())
    {
        int nAdded = 0, nSkipped = 0;
        bool fOk = ImportWallet(strImport, nAdded, nSkipped);
        if (fOk)
        {
            printf("Imported %d key(s); %d were already here.\n", nAdded, nSkipped);
            // Importing a key without looking for its coins leaves the user
            // holding a wallet that says zero about money that is on the
            // chain. That was the old behaviour and it looks exactly like the
            // import having failed.
            if (nAdded > 0)
            {
                string strScanError;
                if (!CanScanWalletTransactions(strScanError))
                {
                    fprintf(stderr, "Cannot scan for imported coins: %s\n",
                            strScanError.c_str());
                    fprintf(stderr, "The key import was written, but the wallet "
                                    "balance was not proven against the chain.\n");
                    DBFlush(true);
                    return 1;
                }
                printf("Looking through the chain for coins belonging to the imported key(s)...\n");
                int nFound = ScanForWalletTransactions(pindexGenesisBlock);
                printf("Found %d transaction(s). Start the node normally to see the balance.\n", nFound);
            }
        }
        else
            fprintf(stderr, "Import failed.\n");
        DBFlush(true);
        return fOk ? 0 : 1;
    }

    // /rescan -- walk the chain and pick up anything the wallet's keys own but
    // the wallet never recorded. Cheap to offer and the only recourse when a
    // balance is wrong for this reason.
    string strShow = argval2(argc, argv, "/showderived", "-showderived");
    if (!strShow.empty())
    {
        int nRet = CmdShowDerived(atoi(strShow.c_str()));
        DBFlush(true);
        return nRet;
    }

    if (arg(argc,argv,"/newaddress") || arg(argc,argv,"-newaddress"))
    {
        int nRet = CmdNewAddress();
        DBFlush(true);
        return nRet;
    }

    // -sendto -- the counterpart to -newaddress. Without it a headless node can
    // be paid and can never pay: SendMoney() has been here since 0.1.0 and only
    // the window ever reached it.
    string strSendTo = argval2(argc, argv, "/sendto", "-sendto");
    if (!strSendTo.empty())
    {
        int nRet = CmdSendTo(strSendTo);
        DBFlush(true);
        return nRet;
    }

    if (arg(argc,argv,"/recoveryaudit") || arg(argc,argv,"-recoveryaudit"))
    {
        int nRet = CmdRecoveryAudit();
        DBFlush(true);
        return nRet;
    }

    if (arg(argc,argv,"/newphrase") || arg(argc,argv,"-newphrase"))
    {
        int nRet = CmdNewPhrase();
        DBFlush(true);
        return nRet;
    }

    string strRestore = argval2(argc, argv, "/restorephrase", "-restorephrase");
    if (!strRestore.empty())
    {
        string strDepth = argval2(argc, argv, "/restoredepth", "-restoredepth");
        int nMinDepth = strDepth.empty() ? 0 : atoi(strDepth.c_str());
        int nRet = CmdRestorePhrase(strRestore, nMinDepth);
        DBFlush(true);
        return nRet;
    }

    if (arg(argc,argv,"/rescan") || arg(argc,argv,"-rescan"))
    {
        string strScanError;
        if (!CanScanWalletTransactions(strScanError))
        {
            fprintf(stderr, "Cannot rescan wallet transactions: %s\n",
                    strScanError.c_str());
            DBFlush(true);
            return 1;
        }
        printf("Rescanning the chain for this wallet's transactions...\n");
        int nFound = ScanForWalletTransactions(pindexGenesisBlock);
        printf("Rescan done: %d transaction(s) added or updated.\n", nFound);
        DBFlush(true);
        return 0;
    }

    if (fGenerateBitcoins && IsWalletLocked())
    {
        fprintf(stderr, "Cannot mine while the encrypted wallet is locked. "
                        "Start with /walletpassphrase or /walletpassphrase=@FILE, or disable mining.\n");
        DBFlush(true);
        return 1;
    }

    ReacceptWalletTransactions();

    if (!StartNode(strErrors))
    {
        fprintf(stderr,"StartNode: %s\n",strErrors.c_str());
        BtfStopManagedTor();
        return 1;
    }

    if (nMineMode == MINE_OPERATOR) {
        gPoolServerRunning = true;
        gPoolRunning = true;
        if (_beginthread(ThreadRPCServer, 0, NULL) == (uintptr_t)-1)
            printf("Error: _beginthread(ThreadRPCServer) failed\n");
    }
    if (fStratumBridge) {
        if (_beginthread(ThreadStratumBridge, 0, NULL) == (uintptr_t)-1)
            printf("Error: _beginthread(ThreadStratumBridge) failed\n");
    }
    if (fGenerateBitcoins)
        StartMinerThreads();

#ifdef BITFLASH_NO_GUI
    // Nothing else this binary can do; /nogui is accepted and redundant.
    bool fHeadless = true;
#else
    bool fHeadless = arg(argc,argv,"/nogui") || arg(argc,argv,"-nogui") ||
                     arg(argc,argv,"/daemon") || arg(argc,argv,"-daemon");
#endif

    if (fHeadless) {
#ifdef _WIN32
        SetConsoleCtrlHandler(HeadlessConsoleCtrlHandler, TRUE);
#else
        auto sig=[](int){fShutdown=true;};
        signal(SIGINT,sig); signal(SIGTERM,sig);
#endif
        printf("Running headless. Ctrl-C to stop.\n");
        while (!fShutdown) Sleep(500);
        StopNode();
        BtfStopManagedTor();
        // Checkpoints, releases wallet.dat from this directory's Berkeley DB
        // environment, and closes it. Declared since 2009 and never once
        // called here, which is why a wallet.dat copied elsewhere would not
        // open -- issue #40. Not optional.
        DBFlush(true);
        // Checkpoint and close the SQLite wallet backend if one is active. A
        // no-op on the Berkeley DB path. Safe to kill before this runs: WAL +
        // synchronous=FULL already made every committed write durable.
        WalletSQLiteRuntimeClose();
#ifdef _WIN32
        // wallet.dat is safely flushed and closed now; let a pending console
        // control handler (CLOSE/LOGOFF/SHUTDOWN) return so the OS can finish.
        g_fHeadlessShutdownDone = true;
#endif
        return 0;
    }

#ifdef BITFLASH_NO_GUI
    return 0;   // unreachable: fHeadless is always true in this build
#else
    int ret = RunGUI(argc, argv);
    fShutdown = true;
    StopNode();
    BtfStopManagedTor();
    DBFlush(true);
    WalletSQLiteRuntimeClose();
    return ret;
#endif
}
