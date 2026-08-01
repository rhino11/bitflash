// Bitflash entry point -- starts node threads then runs GUI (or headless).

#include "headers_core.h"
#include "selftest.h"
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
    printf("  /selftest=wallet-keypool\n");
    printf("\n");
    printf("Mining mode:\n");
    printf("  /operator\n");
    printf("  /participant=POOL_BTF_ADDRESS\n");
    printf("  /solomine\n");
    printf("  /genproclimit=N            (mining threads; 0 or absent = every core but one)\n");
    printf("  /checkblocks=N             (blocks re-verified at startup, default 288, 0 = all)\n");
    printf("\n");
    printf("Pool operator announcement:\n");
    printf("  /poolname=NAME\n");
    printf("  /poolfee=PCT\n");
    printf("  /pooldashboard=URL  (alias: /pooldash=URL)\n");
    printf("\n");
    printf(".btf and rendezvous:\n");
    printf("  /connectbtf=PEER_BTF_ADDRESS\n");
    printf("  /rvrelay=HOST:PORT\n");
    printf("  /announcerelay=HOST:PORT\n");
    printf("\n");
    printf("Network:\n");
    printf("  /port=N                    (P2P listen port, default 8433)\n");
    printf("  /btfseed=ADDRESS:ENCHEX    (extra bootstrap peer, repeatable)\n");
    printf("\n");
    printf("Wallet:\n");
    printf("  /backupwallet=FILE         (write a wallet.dat that opens on its own,\n");
    printf("                              then exit; run it again after new addresses)\n");
    printf("  /dumpwallet=FILE           (export private keys as text -- readable by\n");
    printf("                              anyone, so guard it like cash)\n");
    printf("  /importwallet=FILE         (load keys from such a file back in)\n");
    printf("  /newaddress                (print the next receiving address, then exit)\n");
    printf("  /newphrase                 (create a twelve-word recovery phrase for a\n");
    printf("                              wallet that has none, show it once, exit)\n");
    printf("  /restorephrase=\"WORDS\"     (rebuild this wallet from a phrase and scan\n");
    printf("                              the chain for its coins, then exit)\n");
    printf("  /rescan                    (walk the chain for coins this wallet owns\n");
    printf("                              but never recorded, then exit)\n");
    printf("\n");
    printf("Each option also accepts '-' instead of '/'.\n");
}

static void ParseStartupArguments(int argc, char* argv[])
{
    if (arg(argc,argv,"/datadir") || arg(argc,argv,"-datadir"))
        strSetDataDir = argval2(argc, argv, "/datadir", "-datadir");

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

    string btfConnect = argval2(argc, argv, "/connectbtf", "-connectbtf");
    if (!btfConnect.empty())
        strBtfConnect = btfConnect;

    string rvRelay = argval2(argc, argv, "/rvrelay", "-rvrelay");
    if (!rvRelay.empty())
    {
        vBtfMeetingRelays.clear();
        vBtfMeetingRelays.push_back(rvRelay);
    }

    string announceRelay = argval2(argc, argv, "/announcerelay", "-announcerelay");
    if (!announceRelay.empty())
        strBtfAnnounceRelay = announceRelay;

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

    // net.cpp has described nListenPort as "tunable via /port" since it was
    // written, but nothing ever read the option, so the port was fixed at 8433
    // and a second node could not start on a machine already running one.
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
}

int main(int argc, char* argv[])
{
    if (arg(argc,argv,"/help") || arg(argc,argv,"-help") ||
        arg(argc,argv,"--help") || arg(argc,argv,"/?"))
    {
        PrintUsage();
        return 0;
    }

    ParseStartupArguments(argc, argv);

    string strSelfTest = argval2(argc, argv, "/selftest", "-selftest");
    if (!strSelfTest.empty())
        return RunSelfTest(strSelfTest);

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
    string strErrors;
    printf("Loading block index...\n");
    try
    {
        if (!LoadBlockIndex()) { fprintf(stderr, "LoadBlockIndex failed\n"); return 1; }
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Cannot read the block index: %s\n", e.what());
        fprintf(stderr, "blkindex.dat and blk0001.dat may be from another machine or "
                        "incomplete. Deleting both is safe -- they are re-downloaded -- "
                        "but never delete wallet.dat, which holds your keys.\n");
        return 1;
    }

    printf("Loading wallet...\n");
    try
    {
        if (!LoadWallet()) { fprintf(stderr, "LoadWallet failed\n"); return 1; }

        // After the block index, so there is a chain to compare the wallet
        // against, and before anything reports a balance.
        RescanSpentFlags();
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Cannot read wallet.dat: %s\n", e.what());
        fprintf(stderr, "The file was left untouched. A wallet.dat written by a "
                        "different platform's Berkeley DB is the usual cause; back it "
                        "up before trying anything else.\n");
        return 1;
    }
    printf("Height=%d\n", nBestHeight);

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

    ReacceptWalletTransactions();

    if (!StartNode(strErrors)) { fprintf(stderr,"StartNode: %s\n",strErrors.c_str()); return 1; }

    if (nMineMode == MINE_OPERATOR) {
        gPoolServerRunning = true;
        gPoolRunning = true;
        if (_beginthread(ThreadRPCServer, 0, NULL) == (uintptr_t)-1)
            printf("Error: _beginthread(ThreadRPCServer) failed\n");
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
#ifndef _WIN32
        auto sig=[](int){fShutdown=true;};
        signal(SIGINT,sig); signal(SIGTERM,sig);
#endif
        printf("Running headless. Ctrl-C to stop.\n");
        while (!fShutdown) Sleep(500);
        StopNode();
        // Checkpoints, releases wallet.dat from this directory's Berkeley DB
        // environment, and closes it. Declared since 2009 and never once
        // called here, which is why a wallet.dat copied elsewhere would not
        // open -- issue #40. Not optional.
        DBFlush(true);
        return 0;
    }

#ifdef BITFLASH_NO_GUI
    return 0;   // unreachable: fHeadless is always true in this build
#else
    int ret = RunGUI(argc, argv);
    fShutdown = true;
    StopNode();
    DBFlush(true);
    return ret;
#endif
}
