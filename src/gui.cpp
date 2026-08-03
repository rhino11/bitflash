// Bitflash GUI -- ImGui + GLFW + OpenGL3
// Same source on Linux and Windows. No platform ifdefs.

#include "imgui/imgui.h"
#include "imgui/imgui_impl_glfw.h"
#include "imgui/imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include "headers_core.h"
#include <string>
#include <vector>
#include <ctime>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <atomic>
#include <mutex>
#include <thread>
#include "bip32.h"
#include "walletcmd.h"
#include "font_roboto.h"

// ---------------------------------------------------------------------------
// Node API
// ---------------------------------------------------------------------------
extern int64         nTransactionFee;
extern int           fGenerateBitcoins;
extern int           nBestHeight;
extern int           nMineMode;
extern std::string   strParticipantPool;
extern CAddress      addrLocalHost;

void   MainFrameRepaint();
int    GetDiscoveredPeerCount();
int    GetPeerMedianHeight();
string DateTimeStr(int64 nTime);
bool   SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew);
int64  GetBalance();
string PubKeyToAddress(const std::vector<unsigned char>& vchPubKey);
bool   AddressToHash160(const std::string& str, uint160& hash160Ret);
void   ThreadBitcoinMiner(void*);
int    StartMinerThreads();
void   ThreadRPCServer(void*);

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------
static const float STATUS_BAR_H = 22.0f;

// ---------------------------------------------------------------------------
// GUI state
// ---------------------------------------------------------------------------
static std::string g_myAddress;
static int64       g_balance           = 0;
static int64       g_lastWalletRefresh = 0;
static bool        g_showSend          = false;
static bool        g_showOptions       = false;
static bool        g_showAbout         = false;
static bool        g_showDiagnostics   = false;
static bool        g_showWalletSafety  = false;
static bool        g_needRefresh       = true;

static char        g_sendAddr[128]        = {};
static char        g_sendAmount[32]       = {};
static std::string g_sendStatus;
static char        g_backupPath[512]      = {};
static std::string g_backupStatus;
static int64       g_lastWalletBackup     = 0;
static WalletRecoveryAudit g_recoveryAudit;
static int64       g_recoveryAuditTime    = 0;
static bool        g_walletSafetyLoaded   = false;
static char        g_participantPool[256] = {};
static char        g_poolName[128]        = {};
static char        g_poolFee[32]          = {};
static char        g_poolDash[256]        = {};
static int         g_mineRadio            = 0;

struct TxRow { std::string date, desc; int64 amount; int depth; };
static std::vector<TxRow> g_txRows;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static std::string FmtMoney(int64 n)
{
    bool neg = n < 0; if (neg) n = -n;
    char buf[64];
    snprintf(buf, sizeof(buf), "%s%lld.%08lld",
             neg?"-":"", (long long)(n/COIN), (long long)(n%COIN));
    char* dot = strchr(buf, '.');
    if (dot) { char* e = buf+strlen(buf)-1; while(e>dot+2&&*e=='0') *e--='\0'; }
    return buf;
}

static std::string FmtAge(int64 createdAt)
{
    int64 age = GetTime() - createdAt;
    if (age < 0)  age = 0;
    if (age < 60)   return strprintf("%llds",  (long long)age);
    if (age < 3600) return strprintf("%lldm",  (long long)(age / 60));
    return              strprintf("%lldh",  (long long)(age / 3600));
}

static ImVec4 StatusColor(const std::string& s)
{
    if (s.find("failed")   != std::string::npos ||
        s.find("rejected") != std::string::npos ||
        s.find("stopped")  != std::string::npos)
        return ImVec4(1.0f, 0.38f, 0.38f, 1.0f);   // red
    if (s.find("hashing")  != std::string::npos ||
        s.find("accepted") != std::string::npos ||
        s.find("connected")!= std::string::npos)
        return ImVec4(0.35f, 1.0f, 0.45f, 1.0f);   // green
    if (s.find("asking")   != std::string::npos ||
        s.find("authoriz") != std::string::npos ||
        s.find("subscrib") != std::string::npos)
        return ImVec4(1.0f, 0.75f, 0.25f, 1.0f);   // amber
    return ImVec4(0.55f, 0.80f, 1.0f, 1.0f);        // blue-grey
}

static std::string PoolLabel(const BtfPoolAnnouncement& ann)
{
    std::ostringstream o;
    o << ann.poolName << " - "
      << std::fixed << std::setprecision(2) << ann.feePercent << "%";
    if (ann.connectedMiners > 0)
        o << " - " << ann.connectedMiners << " miners";
    return o.str();
}

static std::string BackupTimeSuffix()
{
    return strprintf("%lld", (long long)GetTime());
}

// Where to put a backup by default.
//
// Not the data directory. A copy that lives in the folder it is meant to
// outlive is not a backup: same disk, same directory the README tells people to
// copy wholesale, and the same directory they are eventually going to delete --
// which is the moment the backup was for. The home directory is not off-site
// either, but it survives the one accident this file exists to survive.
static std::string DefaultBackupDir()
{
#ifdef _WIN32
    const char* pszHome = getenv("USERPROFILE");
#else
    const char* pszHome = getenv("HOME");
#endif
    if (pszHome && *pszHome)
        return std::string(pszHome);
    return GetAppDir();   // nothing better available; the warning below still fires
}

// True when a path sits inside the data directory, so the dialog can say so.
static bool PathIsInsideDataDir(const std::string& strPath)
{
    std::string strDir = GetAppDir();
    if (strPath.size() < strDir.size())
        return false;
    std::string a = strPath.substr(0, strDir.size());
    // Windows paths are case-insensitive and mix separators; compare loosely.
    for (size_t i = 0; i < a.size(); i++)
    {
        char c1 = a[i], c2 = strDir[i];
        if (c1 == '\\') c1 = '/';
        if (c2 == '\\') c2 = '/';
        if (tolower((unsigned char)c1) != tolower((unsigned char)c2))
            return false;
    }
    return true;
}

static void SetDefaultBackupPath()
{
    std::string path = DefaultBackupDir() + "/wallet-backup-" + BackupTimeSuffix() + ".dat";
    strncpy(g_backupPath, path.c_str(), sizeof(g_backupPath)-1);
    g_backupPath[sizeof(g_backupPath)-1] = '\0';
}

static void LoadWalletSafetyState()
{
    if (g_walletSafetyLoaded)
        return;
    CWalletDB("r").ReadSetting("nLastWalletBackup", g_lastWalletBackup);
    SetDefaultBackupPath();
    g_walletSafetyLoaded = true;
}

static void RefreshRecoveryAudit(bool fForce=false)
{
    int64 nNow = GetTime();
    if (!fForce && g_recoveryAuditTime != 0 && nNow - g_recoveryAuditTime < 5)
        return;
    g_recoveryAudit = GetWalletRecoveryAudit();
    g_recoveryAuditTime = nNow;
}

static int KeyPoolCount()
{
    int n = 0;
    CRITICAL_BLOCK(cs_keyPool)
        n = (int)mapKeyPool.size();
    return n;
}

static void RefreshWallet()
{
    LoadWalletSafetyState();
    std::vector<unsigned char> vchPubKey;
    if (CWalletDB("r").ReadDefaultKey(vchPubKey))
        g_myAddress = PubKeyToAddress(vchPubKey);
    g_balance = GetBalance();

    g_txRows.clear();
    TRY_CRITICAL_BLOCK(cs_mapWallet)
    {
        // Sort: pending first, then confirmed by depth ascending (least deep =
        // most recent), then orphaned coinbases at the very bottom.
        //
        // Orphans have to be pushed down explicitly. They are depth 0, exactly
        // like a genuinely pending transaction, so sorting on depth alone put
        // every orphan the node had ever produced at the top of the list -- and
        // they never age out, because depth 0 is where they stay forever. A
        // miner with a week of ordinary orphaned races opened the wallet and
        // saw nothing but failures stacked above every block it had actually
        // won. The balance was right; the list was telling a different story.
        //
        // We can't sort on nTimeReceived because a resync re-stamps every
        // transaction with the same time. Depth is always correct.
        //
        // 0 = pending, 1 = confirmed, 2 = orphaned.
        std::vector<std::pair<std::pair<int,int>,uint256>> vs;
        for (auto& kv : mapWallet) {
            int d = kv.second.GetDepthInMainChain();
            bool orphaned = kv.second.IsCoinBase() && kv.second.hashBlock != 0 && d == 0;
            int rank = orphaned ? 2 : (d == 0 ? 0 : 1);
            vs.push_back({{rank, d}, kv.second.GetHash()});
        }
        std::sort(vs.begin(), vs.end(),
            [](const std::pair<std::pair<int,int>,uint256>& a,
               const std::pair<std::pair<int,int>,uint256>& b) {
                return a.first < b.first;
            });
        for (auto& sv : vs) {
            auto mi = mapWallet.find(sv.second);
            if (mi == mapWallet.end()) continue;
            CWalletTx& wtx = mi->second;
            int   depth    = wtx.GetDepthInMainChain();
            int   toMature = wtx.IsCoinBase() ? wtx.GetBlocksToMaturity() : 0;
            // An orphaned coinbase has hashBlock set but depth=0 (block not in main chain).
            // A genuinely unconfirmed tx has hashBlock==0.
            bool isOrphaned = wtx.IsCoinBase() && wtx.hashBlock != 0 && depth == 0;
            int64 net;
            std::string desc;
            if (wtx.IsCoinBase()) {
                if (isOrphaned) {
                    net  = 0;
                    desc = "Generated (orphaned -- block not in main chain)";
                } else if (toMature > 0) {
                    net  = wtx.GetValueOut();
                    char buf[64];
                    snprintf(buf, sizeof(buf), "Generated (matures in %d blocks)", toMature);
                    desc = buf;
                } else {
                    net  = wtx.GetCredit() - wtx.GetDebit();
                    desc = depth < 1 ? "Generated (unconfirmed)" : "Generated";
                }
            } else if (wtx.GetDebit() > 0) {
                net  = wtx.GetCredit() - wtx.GetDebit();
                desc = "Sent";
            } else {
                net  = wtx.GetCredit() - wtx.GetDebit();
                desc = "Received";
            }
            g_txRows.push_back({DateTimeStr(wtx.GetTxTime()), desc, net, depth});
        }
    }
    g_lastWalletRefresh = GetTime();
}

void MainFrameRepaint()
{
    g_needRefresh = true;
    g_recoveryAuditTime = 0;
}

// DateTimeStr moved to util.cpp: main.cpp logs block times with it, so it is
// needed by builds that have no GUI at all.

// ---------------------------------------------------------------------------
// Status bar -- separate fullscreen-width overlay pinned to bottom edge.
// Drawn last so it always sits on top of everything else.
// ---------------------------------------------------------------------------
static void DrawStatusBar()
{
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0.0f, io.DisplaySize.y - STATUS_BAR_H));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, STATUS_BAR_H));
    ImGui::SetNextWindowBgAlpha(1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,  ImVec2(10.0f, 3.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.13f, 0.13f, 0.13f, 1.0f));
    ImGui::Begin("##statusbar", nullptr,
        ImGuiWindowFlags_NoTitleBar       |
        ImGuiWindowFlags_NoResize         |
        ImGuiWindowFlags_NoMove           |
        ImGuiWindowFlags_NoScrollbar      |
        ImGuiWindowFlags_NoScrollWithMouse|
        ImGuiWindowFlags_NoSavedSettings  |
        ImGuiWindowFlags_NoBringToFrontOnFocus);
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor();

    int connected  = (int)vNodes.size();
    int discovered = GetDiscoveredPeerCount();

    if (nMineMode == MINE_PARTICIPANT) {
        uint64 sent = 0, accepted = 0;
        double hashRate = 0.0;
        std::string st = GetParticipantMiningStatus();
        GetParticipantMiningStats(sent, accepted, hashRate);
        if (sent > 0 || accepted > 0 || hashRate > 0.0)
            ImGui::TextDisabled(
                "Connected peers: %d  Detected peers: %d  Height: %d"
                "  Shares: %llu sent / %llu accepted  %.2f H/s",
                connected, discovered, nBestHeight,
                (unsigned long long)sent, (unsigned long long)accepted, hashRate);
        else if (!st.empty())
            ImGui::TextDisabled(
                "Connected peers: %d  Detected peers: %d  Height: %d  %s",
                connected, discovered, nBestHeight, st.c_str());
        else
            ImGui::TextDisabled(
                "Connected peers: %d  Detected peers: %d  Height: %d",
                connected, discovered, nBestHeight);
    } else if (nMineMode == MINE_OPERATOR) {
        int miners = 0, blocksFound = 0;
        uint64 roundShares = 0;
        double totalHashRate = 0.0;
        GetPoolOperatorStats(miners, blocksFound, roundShares, totalHashRate);
        ImGui::TextDisabled(
            "Connected peers: %d  Detected peers: %d  Height: %d"
            "  Miners: %d  Round shares: %llu  Blocks found: %d  %.2f H/s",
            connected, discovered, nBestHeight,
            miners, (unsigned long long)roundShares, blocksFound, totalHashRate);
    } else {
        ImGui::TextDisabled(
            "Connected peers: %d  Detected peers: %d  Height: %d",
            connected, discovered, nBestHeight);
    }

    // A node that has stopped receiving looks exactly like one with nothing to
    // do. Now that peers announce their height, say the difference out loud
    // instead of leaving the user to guess from a number that stopped moving.
    int peerHeight = GetPeerMedianHeight();
    if (peerHeight >= 0 && nBestHeight < peerHeight - 1)
        ImGui::TextColored(ImVec4(0.95f, 0.65f, 0.20f, 1.0f),
                           "Behind the network by %d block(s) -- peers report height %d",
                           peerHeight - nBestHeight, peerHeight);

    ImGui::End();
}

// ---------------------------------------------------------------------------
// Main window
//
// Layout:
//   [menu bar]                  -- ImGui built-in menu
//   [header strip]              -- address, balance, send button, mine status
//   [separator]
//   [telemetry strip]           -- mode-specific live stats (never scrolls)
//   [separator]
//   [scrollable content child]  -- transactions + mode panels
//
// The scrollable child ends at the top of the status bar so content never
// hides behind it. The child is explicitly sized to fill the remaining space.
// ---------------------------------------------------------------------------
static void DrawMainWindow()
{
    ImGuiIO& io = ImGui::GetIO();

    // Full display height minus the status bar at the bottom.
    const float winH = io.DisplaySize.y - STATUS_BAR_H;

    ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, winH));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f, 12.0f));
    ImGui::Begin("##main", nullptr,
        ImGuiWindowFlags_NoTitleBar        |
        ImGuiWindowFlags_NoResize          |
        ImGuiWindowFlags_NoMove            |
        ImGuiWindowFlags_NoScrollbar       |
        ImGuiWindowFlags_NoScrollWithMouse |
        ImGuiWindowFlags_MenuBar           |
        ImGuiWindowFlags_NoBringToFrontOnFocus);
    ImGui::SetWindowFontScale(0.92f);
    ImGui::PopStyleVar();

    // ---- Menu bar ----
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Backup Wallet")) g_showWalletSafety = true;
            if (ImGui::MenuItem("Exit")) glfwSetWindowShouldClose(glfwGetCurrentContext(), true);
            ImGui::EndMenu();
        }
        if (ImGui::MenuItem("Options")) g_showOptions = true;
        if (ImGui::MenuItem("Wallet Safety")) g_showWalletSafety = true;
        if (ImGui::MenuItem("Diagnostics")) g_showDiagnostics = true;
        if (ImGui::MenuItem("About"))   g_showAbout   = true;
        ImGui::EndMenuBar();
    }

    // ---- Header strip (never scrolls) ----
    ImGui::Spacing();
    ImGui::TextDisabled("Address:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-80.0f);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.14f, 0.14f, 0.14f, 1.0f));
    ImGui::InputText("##addr", (char*)g_myAddress.c_str(), g_myAddress.size()+1,
                     ImGuiInputTextFlags_ReadOnly);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    if (ImGui::Button("Copy##a")) ImGui::SetClipboardText(g_myAddress.c_str());

    ImGui::TextDisabled("Balance:");
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.35f, 1.0f, 0.35f, 1.0f));
    ImGui::Text("%s BTF", FmtMoney(g_balance).c_str());
    ImGui::PopStyleColor();

    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.15f, 0.40f, 0.15f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.55f, 0.20f, 1.0f));
    if (ImGui::Button("  Send Coins  ")) g_showSend = true;
    ImGui::PopStyleColor(2);

    ImGui::SameLine(0.0f, 8.0f);
    if (ImGui::Button("  Backup Wallet  ")) g_showWalletSafety = true;

    ImGui::SameLine(0.0f, 20.0f);
    if (fGenerateBitcoins) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.6f, 0.0f, 1.0f));
        const char* modeLabel =
            nMineMode == MINE_OPERATOR   ? "Mining (operator)"  :
            nMineMode == MINE_PARTICIPANT ? "Mining (pool)"       :
            nMineMode == MINE_RELAY       ? "Relay"               : "Mining";
        ImGui::Text("* %s", modeLabel);
        ImGui::PopStyleColor();
        if (nMineMode == MINE_PARTICIPANT) {
            std::string st = GetParticipantMiningStatus();
            if (!st.empty()) {
                ImGui::SameLine(0.0f, 12.0f);
                ImGui::PushStyleColor(ImGuiCol_Text, StatusColor(st));
                ImGui::Text("[%s]", st.c_str());
                ImGui::PopStyleColor();
            }
        }
    } else {
        ImGui::TextDisabled("Not mining");
    }

    ImGui::Spacing();
    ImGui::Separator();

    // ---- Telemetry strip (never scrolls) ----
    {
        ImGui::Spacing();
        const char* modeName =
            nMineMode == MINE_OPERATOR    ? "Operator"    :
            nMineMode == MINE_PARTICIPANT  ? "Participant" :
            nMineMode == MINE_RELAY        ? "Relay"       : "Solo";
        int64 age = g_lastWalletRefresh > 0 ? GetTime() - g_lastWalletRefresh : 0;

        ImGui::Text("Mode: %s", modeName);
        ImGui::SameLine(0.0f, 16.0f);
        ImGui::TextDisabled("Wallet refreshed %llds ago", (long long)age);

        if (nMineMode == MINE_PARTICIPANT) {
            uint64 sent = 0, accepted = 0;
            double hashRate = 0.0;
            std::string st = GetParticipantMiningStatus();
            GetParticipantMiningStats(sent, accepted, hashRate);
            if (sent > 0 || accepted > 0 || hashRate > 0.0) {
                double pct = sent ? (100.0 * (double)accepted / (double)sent) : 0.0;
                ImGui::TextDisabled(
                    "Sent %llu shares, accepted %llu (%.1f%%),  %.2f H/s",
                    (unsigned long long)sent, (unsigned long long)accepted, pct, hashRate);
            } else if (!st.empty()) {
                ImGui::TextDisabled("Status: %s", st.c_str());
            } else {
                ImGui::TextDisabled("Waiting for pool work...");
            }
        } else if (nMineMode == MINE_OPERATOR) {
            int miners = 0, blocksFound = 0;
            uint64 roundShares = 0;
            double totalHashRate = 0.0;
            GetPoolOperatorStats(miners, blocksFound, roundShares, totalHashRate);
            if (miners > 0 || blocksFound > 0 || roundShares > 0)
                ImGui::TextDisabled(
                    "Authorized miners: %d  Round shares: %llu  Blocks found: %d  %.2f H/s",
                    miners, (unsigned long long)roundShares, blocksFound, totalHashRate);
            else
                ImGui::TextDisabled("Pool server running, waiting for miners");
        } else if (nMineMode == MINE_RELAY) {
            ImGui::TextDisabled("Relay mode: syncing, not mining");
        } else {
            ImGui::TextDisabled("Solo mining");
        }
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
    }

    // ---- Scrollable content child ----
    // Fills all remaining height in the window (cursor Y to bottom of window).
    // Content that overflows scrolls; nothing leaks past the window edge.
    // Size the scrollable child to fill exactly the remaining window height.
    // GetContentRegionAvail() already accounts for padding/borders.
    const float availH = ImGui::GetContentRegionAvail().y;
    ImGui::BeginChild("##scroll", ImVec2(0.0f, availH), false, 0);

    // ---- Transaction list ----
    float txH = io.DisplaySize.y * 0.26f;
    if (txH < 180.0f) txH = 180.0f;
    if (txH > 260.0f) txH = 260.0f;

    if (ImGui::BeginTable("txlist", 4,
        ImGuiTableFlags_Borders     |
        ImGuiTableFlags_RowBg       |
        ImGuiTableFlags_ScrollY     |
        ImGuiTableFlags_SizingStretchProp,
        ImVec2(0.0f, txH)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Status",      ImGuiTableColumnFlags_WidthFixed,   110.0f);
        ImGui::TableSetupColumn("Date",        ImGuiTableColumnFlags_WidthFixed,   130.0f);
        ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Amount",      ImGuiTableColumnFlags_WidthFixed,   140.0f);
        ImGui::TableHeadersRow();

        for (auto& row : g_txRows) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            bool isImmatureCoinbase = (row.desc.find("matures in") != std::string::npos);
            bool isOrphaned         = (row.desc.find("orphaned") != std::string::npos);
            if (isOrphaned)
                ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Orphaned");
            else if (row.depth < 1)
                ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "Unconfirmed");
            else if (isImmatureCoinbase)
                ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.25f, 1.0f), "Immature");
            else if (row.depth < 6)
                ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.3f, 1.0f), "%d confirm%s",
                    row.depth, row.depth == 1 ? "" : "s");
            else
                ImGui::TextColored(ImVec4(0.5f, 0.9f, 0.5f, 1.0f), "Confirmed");
            ImGui::TableSetColumnIndex(1);
            ImGui::TextDisabled("%s", row.date.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(row.desc.c_str());
            ImGui::TableSetColumnIndex(3);
            if (row.amount >= 0)
                ImGui::TextColored(ImVec4(0.35f, 1.0f, 0.35f, 1.0f),
                    "+%s BTF", FmtMoney(row.amount).c_str());
            else
                ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f),
                    "%s BTF",  FmtMoney(row.amount).c_str());
        }
        ImGui::EndTable();
    }

    // ---- Mode panels ----
    std::vector<BtfPoolAnnouncement> pools;
    BtfGetPoolAnnouncements(pools);

    if (nMineMode == MINE_PARTICIPANT) {
        ImGui::Spacing();
        ImGui::SeparatorText("Participant Mining");

        ImGui::TextDisabled("Selected pool:");
        ImGui::SameLine();
        if (strParticipantPool.empty())
            ImGui::TextDisabled("none");
        else
            ImGui::TextWrapped("%s", strParticipantPool.c_str());

        const BtfPoolAnnouncement* sel = nullptr;
        for (size_t i = 0; i < pools.size(); i++)
            if (pools[i].btfAddress == strParticipantPool) { sel = &pools[i]; break; }

        if (sel) {
            ImGui::Text("Pool: %s  Fee: %.2f%%  Miners: %d  Blocks: %d  %.2f H/s",
                sel->poolName.c_str(), sel->feePercent,
                sel->connectedMiners, sel->blocksFound, sel->hashRate);
            if (!sel->dashboardUrl.empty())
                ImGui::TextDisabled("Dashboard: %s", sel->dashboardUrl.c_str());
        } else if (!strParticipantPool.empty()) {
            ImGui::TextDisabled("No live announcement for this pool yet.");
        }

        if (!pools.empty()) {
            ImGui::Spacing();
            ImGui::SeparatorText("Live Pools");
            if (ImGui::BeginTable("livepools", 5,
                ImGuiTableFlags_Borders |
                ImGuiTableFlags_RowBg   |
                ImGuiTableFlags_SizingStretchProp))
            {
                ImGui::TableSetupColumn("Pool",      ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Fee",       ImGuiTableColumnFlags_WidthFixed,  60.0f);
                ImGui::TableSetupColumn("Stats",     ImGuiTableColumnFlags_WidthFixed, 150.0f);
                ImGui::TableSetupColumn("Dashboard", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Use",       ImGuiTableColumnFlags_WidthFixed,  50.0f);
                ImGui::TableHeadersRow();
                for (size_t i = 0; i < pools.size(); i++) {
                    const BtfPoolAnnouncement& ann = pools[i];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextUnformatted(ann.poolName.c_str());
                    ImGui::TextDisabled("%s", ann.btfAddress.c_str());
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%.2f%%", ann.feePercent);
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("%d miners  %d blocks  %.2f H/s  %s",
                        ann.connectedMiners, ann.blocksFound, ann.hashRate,
                        FmtAge(ann.createdAt).c_str());
                    ImGui::TableSetColumnIndex(3);
                    if (!ann.dashboardUrl.empty())
                        ImGui::TextWrapped("%s", ann.dashboardUrl.c_str());
                    else
                        ImGui::TextDisabled("-");
                    ImGui::TableSetColumnIndex(4);
                    std::string btnId = "Use##" + ann.btfAddress;
                    if (ImGui::SmallButton(btnId.c_str())) {
                        strncpy(g_participantPool, ann.btfAddress.c_str(),
                                sizeof(g_participantPool)-1);
                        strParticipantPool = ann.btfAddress;
                        CWalletDB().WriteSetting("strParticipantPool", strParticipantPool);
                        g_needRefresh = true;
                    }
                }
                ImGui::EndTable();
            }
        }
    }

    if (nMineMode == MINE_OPERATOR) {
        ImGui::Spacing();
        ImGui::SeparatorText("Operator Overview");

        std::string opAddr = BtfLocalAddress();
        ImGui::TextDisabled("Pool .btf address:");
        ImGui::SameLine();
        if (opAddr.empty())
            ImGui::TextDisabled("identity not ready");
        else
            ImGui::TextWrapped("%s", opAddr.c_str());

        // Pending payouts
        std::vector<PendingPayoutView> owed;
        GetPendingPayouts(owed);
        ImGui::Spacing();
        ImGui::SeparatorText("Pending Payouts (owed to miners)");
        if (owed.empty()) {
            ImGui::TextDisabled("No pending payouts");
        } else if (ImGui::BeginTable("owedpayouts", 4,
                   ImGuiTableFlags_Borders |
                   ImGuiTableFlags_RowBg   |
                   ImGuiTableFlags_SizingStretchProp))
        {
            ImGui::TableSetupColumn("Matures At",  ImGuiTableColumnFlags_WidthFixed,  90.0f);
            ImGui::TableSetupColumn("Blocks left", ImGuiTableColumnFlags_WidthFixed,  80.0f);
            ImGui::TableSetupColumn("Recipients",  ImGuiTableColumnFlags_WidthFixed,  80.0f);
            ImGui::TableSetupColumn("Total",       ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            for (const PendingPayoutView& row : owed) {
                int left = std::max(0, row.matureAtHeight - nBestHeight);
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::Text("%d", row.matureAtHeight);
                ImGui::TableSetColumnIndex(1); ImGui::Text("%d", left);
                ImGui::TableSetColumnIndex(2); ImGui::Text("%d", row.recipients);
                ImGui::TableSetColumnIndex(3); ImGui::Text("%s BTF", FmtMoney(row.totalAmount).c_str());
            }
            ImGui::EndTable();
        }

        // Workers
        std::vector<PoolWorkerStatView> workers;
        GetPoolWorkerStats(workers);
        ImGui::Spacing();
        ImGui::SeparatorText("Current Round Workers");
        if (workers.empty()) {
            ImGui::TextDisabled("No active workers this round");
        } else if (ImGui::BeginTable("workers", 5,
                   ImGuiTableFlags_Borders |
                   ImGuiTableFlags_RowBg   |
                   ImGuiTableFlags_SizingStretchProp))
        {
            ImGui::TableSetupColumn("Payout Address", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Worker",         ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Hashrate",       ImGuiTableColumnFlags_WidthFixed,  90.0f);
            ImGui::TableSetupColumn("Round shares",   ImGuiTableColumnFlags_WidthFixed,  90.0f);
            ImGui::TableSetupColumn("Last seen",      ImGuiTableColumnFlags_WidthFixed,  90.0f);
            ImGui::TableHeadersRow();
            for (const PoolWorkerStatView& row : workers) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(row.address.empty() ? "unknown" : row.address.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("%s", row.worker.empty() ? "worker" : row.worker.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%.2f H/s", row.hashRate);
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%llu", (unsigned long long)row.roundShares);
                ImGui::TableSetColumnIndex(4);
                ImGui::TextDisabled("%s ago", FmtAge(row.lastSeen).c_str());
            }
            ImGui::EndTable();
        }
    }

    ImGui::EndChild(); // ##scroll
    ImGui::SetWindowFontScale(1.0f);
    ImGui::End(); // ##main
}

// ---------------------------------------------------------------------------
// Send dialog
// ---------------------------------------------------------------------------
static void DrawSendDialog()
{
    if (!g_showSend) return;
    ImGui::SetNextWindowSize(ImVec2(500.0f, 180.0f), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(),
                            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    if (ImGui::Begin("Send Coins", &g_showSend,
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse))
    {
        ImGui::Text("Recipient address:");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("##sa", g_sendAddr, sizeof(g_sendAddr));

        ImGui::Text("Amount (BTF):");
        ImGui::SetNextItemWidth(180.0f);
        ImGui::InputText("##sm", g_sendAmount, sizeof(g_sendAmount));

        if (!g_sendStatus.empty()) {
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f),
                "%s", g_sendStatus.c_str());
        }

        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
        if (ImGui::Button("Send", ImVec2(90.0f, 0.0f))) {
            uint160 h; int64 nv = 0;
            if (!AddressToHash160(g_sendAddr, h))
                g_sendStatus = "Invalid address.";
            else if (!ParseMoney(g_sendAmount, nv) || nv <= 0)
                g_sendStatus = "Invalid amount.";
            else {
                CScript sc;
                sc << OP_DUP << OP_HASH160 << h << OP_EQUALVERIFY << OP_CHECKSIG;
                CWalletTx wtx;
                if (SendMoney(sc, nv, wtx)) {
                    g_showSend = false;
                    g_sendStatus = "";
                    memset(g_sendAddr,   0, sizeof(g_sendAddr));
                    memset(g_sendAmount, 0, sizeof(g_sendAmount));
                    g_needRefresh = true;
                } else {
                    g_sendStatus = "Transaction failed.";
                }
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(90.0f, 0.0f))) {
            g_showSend = false;
            g_sendStatus = "";
        }
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Options dialog
// ---------------------------------------------------------------------------
static void DrawOptionsDialog()
{
    if (!g_showOptions) return;

    static bool wasOpen = false;
    if (!wasOpen) {
        g_mineRadio = nMineMode;
        strncpy(g_participantPool, strParticipantPool.c_str(), sizeof(g_participantPool)-1);
        strncpy(g_poolName, strPoolName.c_str(), sizeof(g_poolName)-1);
        snprintf(g_poolFee, sizeof(g_poolFee), "%.2f", dPoolFeePercent);
        strncpy(g_poolDash, strPoolDashboardUrl.c_str(), sizeof(g_poolDash)-1);
    }
    wasOpen = true;

    ImGui::SetNextWindowSize(ImVec2(540.0f, 385.0f), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(),
                            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    if (ImGui::Begin("Options", &g_showOptions,
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse))
    {
        // Transaction fee
        ImGui::SeparatorText("Transaction Fee");
        static char feeStr[32] = {};
        if (feeStr[0] == '\0')
            snprintf(feeStr, sizeof(feeStr), "%s", FmtMoney(nTransactionFee).c_str());
        ImGui::SetNextItemWidth(180.0f);
        ImGui::InputText("BTF per transaction##fee", feeStr, sizeof(feeStr));

        // Mining mode
        ImGui::SeparatorText("Mining Mode");
        ImGui::RadioButton("Relay -- just run the node, don't mine",  &g_mineRadio, MINE_RELAY);
        ImGui::RadioButton("Solo -- rewards go to your wallet",        &g_mineRadio, MINE_SOLO);
        ImGui::RadioButton("Operator -- run a pool for other miners",  &g_mineRadio, MINE_OPERATOR);
        ImGui::RadioButton("Participant -- mine to someone's pool",    &g_mineRadio, MINE_PARTICIPANT);

        if (g_mineRadio != MINE_RELAY && g_lastWalletBackup == 0) {
            ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.75f, 0.25f, 1.0f));
            ImGui::TextWrapped("Back up this wallet before mining. The key pool covers the next %d generated addresses, but only after you save a backup that contains those keys.", KEYPOOL_SIZE);
            ImGui::PopStyleColor();
            if (ImGui::SmallButton("Backup now")) g_showWalletSafety = true;
        }

        if (g_mineRadio == MINE_OPERATOR) {
            ImGui::Spacing();
            ImGui::SeparatorText("Pool Announcement");
            ImGui::Text("Pool name:");
            ImGui::SetNextItemWidth(-1.0f);
            ImGui::InputText("##poolname", g_poolName, sizeof(g_poolName));
            ImGui::Text("Fee %%:");
            ImGui::SetNextItemWidth(120.0f);
            ImGui::InputText("##poolfee", g_poolFee, sizeof(g_poolFee));
            ImGui::Text("Dashboard URL:");
            ImGui::SetNextItemWidth(-1.0f);
            ImGui::InputText("##pooldash", g_poolDash, sizeof(g_poolDash));
        }

        if (g_mineRadio == MINE_PARTICIPANT) {
            ImGui::Spacing();
            ImGui::SeparatorText("Pool Selection");
            ImGui::TextDisabled("Pick from live discovered pools.");

            std::vector<BtfPoolAnnouncement> pools;
            BtfGetPoolAnnouncements(pools);
            if (!pools.empty()) {
                std::string current = "Select a live pool";
                for (size_t i = 0; i < pools.size(); i++) {
                    if (pools[i].btfAddress == g_participantPool) {
                        current = PoolLabel(pools[i]);
                        break;
                    }
                }
                if (ImGui::BeginCombo("Discovered pools##combo", current.c_str())) {
                    for (size_t i = 0; i < pools.size(); i++) {
                        const BtfPoolAnnouncement& ann = pools[i];
                        bool selected = (ann.btfAddress == g_participantPool);
                        if (ImGui::Selectable(PoolLabel(ann).c_str(), selected))
                            strncpy(g_participantPool, ann.btfAddress.c_str(),
                                    sizeof(g_participantPool)-1);
                    }
                    ImGui::EndCombo();
                }
            } else {
                ImGui::TextDisabled("No live pools discovered yet.");
            }
        }

        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
        if (ImGui::Button("OK", ImVec2(90.0f, 0.0f))) {
            int64 fee = 0;
            if (ParseMoney(feeStr, fee)) {
                nTransactionFee = fee;
                CWalletDB().WriteSetting("nTransactionFee", nTransactionFee);
            }

            bool poolChanged =
                nMineMode != g_mineRadio ||
                strPoolName != (g_poolName[0] ? g_poolName : "Bitflash Pool") ||
                strPoolDashboardUrl != g_poolDash ||
                dPoolFeePercent != atof(g_poolFee);

            nMineMode            = g_mineRadio;
            strParticipantPool   = g_participantPool;
            strPoolName          = g_poolName[0] ? g_poolName : "Bitflash Pool";
            strPoolDashboardUrl  = g_poolDash;
            dPoolFeePercent      = atof(g_poolFee);

            if (nMineMode == MINE_OPERATOR && poolChanged) gAnnounceNow = true;

            if (nMineMode == MINE_RELAY) {
                fGenerateBitcoins = 0;
            } else {
                fGenerateBitcoins = 1;
                if (!vfThreadRunning[3]) StartMinerThreads();
            }

            // Remember the choice. Without this the node came back from every
            // restart as a plain relay, and a machine that had been mining for
            // days looked identical to one that had never been asked to.
            CWalletDB().WriteSetting("nMineMode", nMineMode);
            CWalletDB().WriteSetting("fGenerateBitcoins", fGenerateBitcoins);
            CWalletDB().WriteSetting("strParticipantPool", strParticipantPool);

            if (nMineMode == MINE_OPERATOR) {
                if (!gPoolServerRunning) {
                    gPoolServerRunning = true;
                    _beginthread(ThreadRPCServer, 0, NULL);
                } else if (!gPoolRunning) {
                    gPoolRunning = true;
                }
            } else {
                gPoolRunning = false;
            }
            g_showOptions = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(90.0f, 0.0f))) g_showOptions = false;
    }
    if (!g_showOptions) wasOpen = false;
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Wallet safety dialog
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Recovery phrase
//
// The phrase is shown once, and the seed is installed only after the user says
// they have written it down. Generating it and storing it in the same breath
// would hand somebody a wallet whose only backup is twelve words they may have
// closed the window on -- which is worse than no phrase at all, because they
// would believe they had one.
//
// Nothing here writes the words to disk or to debug.log. They live in one
// std::string that is cleared the moment the dialog closes.
// ---------------------------------------------------------------------------
static bool        g_showCreatePhrase   = false;
static bool        g_showRestorePhrase  = false;
static std::string g_pendingMnemonic;
static bool        g_phraseWrittenDown  = false;
static std::string g_phraseStatus;

static char        g_restoreInput[600]  = {};
static std::string g_restoreStatus;
static std::atomic<bool> g_restoreRunning(false);
static std::atomic<int>  g_restoreDerived(0);
static std::atomic<int>  g_restoreRecovered(0);
static std::string g_restoreResult;
static std::mutex  g_restoreResultMutex;

static void RestoreProgress(void*, int nDerived, int nRecovered)
{
    g_restoreDerived.store(nDerived);
    g_restoreRecovered.store(nRecovered);
}

static void RestoreThread(std::string strPhrase)
{
    std::string strError;
    int nRecovered = 0, nDerived = 0;
    bool fOk = RestoreFromPhrase(strPhrase, 0, RestoreProgress, NULL,
                                 strError, nRecovered, nDerived);
    {
        std::lock_guard<std::mutex> lock(g_restoreResultMutex);
        if (!fOk)
            g_restoreResult = "Nothing was changed. " + strError;
        else if (nRecovered > 0)
            g_restoreResult = strprintf(
                "Restored %d transaction(s) across %d derived addresses. "
                "Restart the node to see the balance.", nRecovered, nDerived);
        else
            g_restoreResult = strprintf(
                "No transactions found for the first %d addresses of that phrase. "
                "Check the words and their order.", nDerived);
    }
    g_restoreRunning.store(false);
    g_recoveryAuditTime = 0;
    g_needRefresh = true;
}

static void DrawCreatePhraseDialog()
{
    if (!g_showCreatePhrase) return;

    ImGui::SetNextWindowSize(ImVec2(640.0f, 340.0f), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(),
                            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    if (ImGui::Begin("Recovery Phrase", &g_showCreatePhrase,
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse))
    {
        ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.25f, 1.0f),
                           "Write these twelve words down, in order, on paper.");
        ImGui::TextWrapped(
            "They are the only thing that can rebuild this wallet if the file is lost. "
            "Anyone who reads them can spend your coins. They are not stored anywhere, "
            "and this is the only time they will be shown.");
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.10f, 0.10f, 0.10f, 1.0f));
        ImGui::BeginChild("##phrase", ImVec2(0.0f, 70.0f), true);
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextColored(ImVec4(0.55f, 1.0f, 0.6f, 1.0f), "%s", g_pendingMnemonic.c_str());
        ImGui::PopTextWrapPos();
        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::TextWrapped(
            "Keys already in this wallet are NOT covered by the phrase -- they existed "
            "before it did. Keep your file backups as well.");
        ImGui::Spacing();

        ImGui::Checkbox("I have written these words down", &g_phraseWrittenDown);
        ImGui::Spacing();

        // Read the condition once, before the button that changes it.
        //
        // Pressing Finish clears g_phraseWrittenDown, so testing it again after
        // the click asked BeginDisabled and EndDisabled two different questions:
        // the pair was opened while the checkbox was ticked and closed after the
        // handler had unticked it. ImGui asserts on the unmatched EndDisabled --
        // on the success path, so every phrase created from the window hit it.
        const bool fFinishDisabled = !g_phraseWrittenDown;
        if (fFinishDisabled)
            ImGui::BeginDisabled();
        if (ImGui::Button("Finish", ImVec2(120.0f, 0.0f)))
        {
            std::string strError;
            if (SetHDSeedFromMnemonic(g_pendingMnemonic, strError))
            {
                TopUpKeyPool();
                g_recoveryAuditTime = 0;
                g_phraseStatus = "Recovery phrase created. New addresses come from it.";
            }
            else
            {
                g_phraseStatus = "Could not install the seed: " + strError;
            }
            g_pendingMnemonic.clear();
            g_phraseWrittenDown = false;
            g_showCreatePhrase = false;
            g_needRefresh = true;
        }
        if (fFinishDisabled)
            ImGui::EndDisabled();

        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120.0f, 0.0f)))
        {
            // Nothing was installed, so there is nothing to undo. The words go
            // away with the string.
            g_pendingMnemonic.clear();
            g_phraseWrittenDown = false;
            g_showCreatePhrase = false;
            g_phraseStatus = "Cancelled. No recovery phrase was created.";
        }
    }
    ImGui::End();

    // Closing with the window X is the same as cancelling.
    if (!g_showCreatePhrase && !g_pendingMnemonic.empty())
    {
        g_pendingMnemonic.clear();
        g_phraseWrittenDown = false;
        g_phraseStatus = "Cancelled. No recovery phrase was created.";
    }
}

static void DrawRestorePhraseDialog()
{
    if (!g_showRestorePhrase) return;

    ImGui::SetNextWindowSize(ImVec2(640.0f, 330.0f), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(),
                            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    if (ImGui::Begin("Restore From Phrase", &g_showRestorePhrase,
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse))
    {
        ImGui::TextWrapped(
            "Type the twelve words, in order, separated by spaces. The node will "
            "derive the addresses they describe and search the chain for their coins.");
        ImGui::Spacing();

        if (HaveHDSeed())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.75f, 0.25f, 1.0f));
            ImGui::TextWrapped(
                "This wallet already has a recovery phrase. Restoring replaces it: "
                "coins on addresses from the current phrase would no longer come back "
                "from the words you wrote down for it. Back up wallet.dat first.");
            ImGui::PopStyleColor();
            ImGui::Spacing();
        }

        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputTextMultiline("##phrase-in", g_restoreInput, sizeof(g_restoreInput),
                                  ImVec2(0.0f, 60.0f));

        ImGui::Spacing();
        bool fBusy = g_restoreRunning.load();
        if (fBusy)
            ImGui::BeginDisabled();
        if (ImGui::Button("Restore", ImVec2(140.0f, 0.0f)))
        {
            std::string strWhy;
            if (!CanScanWalletTransactions(strWhy))
            {
                std::lock_guard<std::mutex> lock(g_restoreResultMutex);
                g_restoreResult = strWhy;
            }
            else
            {
                {
                    std::lock_guard<std::mutex> lock(g_restoreResultMutex);
                    g_restoreResult.clear();
                }
                g_restoreDerived.store(0);
                g_restoreRecovered.store(0);
                g_restoreRunning.store(true);
                // On its own thread: a restore walks the whole chain once per
                // batch and would otherwise freeze the window for as long as it
                // takes.
                std::thread(RestoreThread, std::string(g_restoreInput)).detach();
            }
        }
        if (fBusy)
            ImGui::EndDisabled();

        ImGui::SameLine();
        if (ImGui::Button("Close", ImVec2(100.0f, 0.0f)) && !fBusy)
            g_showRestorePhrase = false;

        ImGui::Spacing();
        if (fBusy)
        {
            ImGui::Text("Searching: %d addresses checked, %d transaction(s) so far",
                        g_restoreDerived.load(), g_restoreRecovered.load());
        }
        else
        {
            std::lock_guard<std::mutex> lock(g_restoreResultMutex);
            if (!g_restoreResult.empty())
                ImGui::TextWrapped("%s", g_restoreResult.c_str());
        }
    }
    ImGui::End();
}

static void DrawWalletSafetyDialog()
{
    if (!g_showWalletSafety) return;
    LoadWalletSafetyState();
    RefreshRecoveryAudit();

    ImGui::SetNextWindowSize(ImVec2(650.0f, 450.0f), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(),
                            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    if (ImGui::Begin("Wallet Safety", &g_showWalletSafety,
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse))
    {
        ImGui::SeparatorText("Backup");
        if (g_lastWalletBackup > 0)
            ImGui::Text("Last GUI backup: %s", DateTimeStr(g_lastWalletBackup).c_str());
        else
            ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.25f, 1.0f),
                               "Last GUI backup: never");

        ImGui::TextDisabled("Data directory:");
        ImGui::SameLine();
        ImGui::TextWrapped("%s", GetAppDir().c_str());

        ImGui::Spacing();
        ImGui::Text("Backup file:");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("##backup-path", g_backupPath, sizeof(g_backupPath));

        if (PathIsInsideDataDir(g_backupPath))
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.75f, 0.25f, 1.0f));
            ImGui::TextWrapped(
                "This path is inside the data directory. A backup kept there is lost "
                "with the thing it was protecting -- put it on another disk, or at "
                "least somewhere you would not delete along with the node's files.");
            ImGui::PopStyleColor();
        }

        if (ImGui::Button("Use new default name", ImVec2(170.0f, 0.0f)))
            SetDefaultBackupPath();
        ImGui::SameLine();
        if (ImGui::Button("Copy data dir", ImVec2(120.0f, 0.0f)))
            ImGui::SetClipboardText(GetAppDir().c_str());

        ImGui::Spacing();
        if (ImGui::Button("Write Backup", ImVec2(150.0f, 0.0f)))
        {
            std::string path = g_backupPath;
            if (path.empty())
            {
                g_backupStatus = "Choose a backup file first.";
            }
            else if (FileExists(path.c_str()))
            {
                g_backupStatus = "Refusing to overwrite an existing file. Use a new name.";
            }
            else
            {
                TopUpKeyPool();
                if (BackupWallet(path))
                {
                    // BackupWallet records the time itself, so a backup taken
                    // with /backupwallet counts the same as one taken here.
                    CWalletDB("r").ReadSetting("nLastWalletBackup", g_lastWalletBackup);
                    g_backupStatus = "Backup written: " + path;
                    SetDefaultBackupPath();
                }
                else
                {
                    g_backupStatus = "Backup failed. See debug.log for the detailed error.";
                }
            }
        }

        if (!g_backupStatus.empty())
        {
            ImVec4 col = g_backupStatus.find("Backup written") == 0
                ? ImVec4(0.35f, 1.0f, 0.45f, 1.0f)
                : ImVec4(1.0f, 0.45f, 0.35f, 1.0f);
            ImGui::PushStyleColor(ImGuiCol_Text, col);
            ImGui::TextWrapped("%s", g_backupStatus.c_str());
            ImGui::PopStyleColor();
        }

        ImGui::Spacing();
        ImGui::SeparatorText("Recovery Phrase");
        if (HaveHDSeed())
            ImGui::TextColored(ImVec4(0.55f, 1.0f, 0.6f, 1.0f),
                               "This wallet has a recovery phrase.");
        else
            ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.25f, 1.0f),
                               "No recovery phrase. Only a file backup can rebuild this wallet.");

        if (g_recoveryAudit.fHaveSeed)
        {
            ImGui::Text("Derivation schema: %s", HDKeySchemaName(g_recoveryAudit.nSchema).c_str());
            ImGui::Text("BIP44 coin type: %u (provisional BITFLASH)", g_recoveryAudit.nCoinType);
        }
        ImGui::Text("Phrase-backed spendable balance: %s BTF",
                    FmtMoney(g_recoveryAudit.nRecoverableCredit).c_str());
        ImGui::Text("Wallet.dat-only spendable balance: %s BTF",
                    FmtMoney(g_recoveryAudit.nLegacyCredit).c_str());
        ImGui::Text("Phrase-backed immature mining rewards: %s BTF",
                    FmtMoney(g_recoveryAudit.nRecoverableImmatureCredit).c_str());
        ImGui::Text("Wallet.dat-only immature mining rewards: %s BTF",
                    FmtMoney(g_recoveryAudit.nLegacyImmatureCredit).c_str());
        if (!g_recoveryAudit.fDeriveComplete)
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.75f, 0.25f, 1.0f));
            ImGui::TextWrapped("%s", g_recoveryAudit.strDeriveError.c_str());
            ImGui::PopStyleColor();
        }
        if (g_recoveryAudit.nLegacyCredit > 0 ||
            g_recoveryAudit.nLegacyImmatureCredit > 0)
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.75f, 0.25f, 1.0f));
            ImGui::TextWrapped(
                "Some coins are on keys the phrase does not reproduce. "
                "Keep wallet.dat backups until that balance has been moved to a "
                "phrase-backed address.");
            ImGui::PopStyleColor();
        }
        else if (HaveHDSeed() &&
                 g_recoveryAudit.nRecoverableCredit +
                 g_recoveryAudit.nRecoverableImmatureCredit > 0)
        {
            ImGui::TextColored(ImVec4(0.55f, 1.0f, 0.6f, 1.0f),
                               "All known wallet balance is covered by the phrase.");
        }

        if (!HaveHDSeed())
        {
            if (ImGui::Button("Create recovery phrase", ImVec2(200.0f, 0.0f)))
            {
                std::string strError;
                if (bitflash::BIP39GenerateMnemonic(g_pendingMnemonic, strError))
                {
                    g_phraseWrittenDown = false;
                    g_phraseStatus.clear();
                    g_showCreatePhrase = true;
                }
                else
                {
                    g_phraseStatus = "Could not generate a phrase: " + strError;
                }
            }
            ImGui::SameLine();
        }
        if (ImGui::Button("Restore from phrase", ImVec2(190.0f, 0.0f)))
            g_showRestorePhrase = true;

        if (!g_phraseStatus.empty())
            ImGui::TextWrapped("%s", g_phraseStatus.c_str());

        ImGui::TextWrapped(
            "A phrase covers addresses created after it. Keys that already existed "
            "are not derived from it, so keep the file backups above as well.");

        ImGui::Spacing();
        ImGui::SeparatorText("Key Pool");
        int nPool = KeyPoolCount();
        ImGui::Text("Pre-generated keys ready: %d / %d", nPool, KEYPOOL_SIZE);
        ImGui::ProgressBar(KEYPOOL_SIZE > 0 ? (float)nPool / (float)KEYPOOL_SIZE : 0.0f,
                           ImVec2(-1.0f, 0.0f));
        ImGui::TextWrapped(
            "A backup contains the keys that already exist. The key pool keeps "
            "future mining rewards and receive addresses inside the next backup "
            "window, but it is not a seed phrase. Back up again after heavy use.");

        ImGui::Spacing();
        ImGui::Separator();
        if (ImGui::Button("Close", ImVec2(90.0f, 0.0f)))
            g_showWalletSafety = false;
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------
// About dialog
// ---------------------------------------------------------------------------
// What the node knows about itself, in the words it writes to the log. Same
// text in both places on purpose: what a user pastes into an issue is then
// exactly what a developer has already read a hundred times.
static void DrawDiagnosticsDialog()
{
    if (!g_showDiagnostics) return;
    ImGui::SetNextWindowSize(ImVec2(720.0f, 460.0f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(),
                            ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
    if (ImGui::Begin("Diagnostics", &g_showDiagnostics, ImGuiWindowFlags_NoCollapse))
    {
        // Rebuilt at most once a second: it walks every peer and takes their
        // send locks, which is not something to do at frame rate.
        static std::string strReport;
        static int64 nLastBuilt = 0;
        if (GetTime() != nLastBuilt)
        {
            nLastBuilt = GetTime();
            strReport = GetDiagnosticsText();
        }

        if (ImGui::Button("Copy to clipboard", ImVec2(160.0f, 0.0f)))
            ImGui::SetClipboardText(strReport.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("The same report goes to debug.log every ten minutes.");
        ImGui::Separator();

        ImGui::BeginChild("##diagtext", ImVec2(0.0f, 0.0f), false,
                          ImGuiWindowFlags_HorizontalScrollbar);
        ImGui::TextUnformatted(strReport.c_str());
        ImGui::EndChild();
    }
    ImGui::End();
}

static void DrawAboutDialog()
{
    if (!g_showAbout) return;
    ImGui::SetNextWindowSize(ImVec2(380.0f, 170.0f), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(),
                            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    if (ImGui::Begin("About Bitflash", &g_showAbout,
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse))
    {
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "Bitflash  BTF  v1.1.0");
        ImGui::Spacing();
        ImGui::TextWrapped(
            "CPU-only cryptocurrency. RandomX proof of work. "
            "Anonymous .btf addressing over Nostr. No premine.");
        ImGui::Spacing();
        ImGui::TextDisabled("Based on Bitcoin 0.1.0 (Satoshi Nakamoto, 2009)");
        ImGui::Spacing();
        if (ImGui::Button("OK", ImVec2(90.0f, 0.0f))) g_showAbout = false;
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int RunGUI(int argc, char* argv[])
{
    if (!glfwInit()) {
        printf("GUI ERROR: glfwInit() failed -- no display or GL available. Run headless with -nogui.\n");
        return 1;
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif

    GLFWwindow* window = glfwCreateWindow(960, 640, "Bitflash", nullptr, nullptr);
    if (!window) {
        printf("GUI ERROR: could not create an OpenGL 3.3 window.\n");
        printf("           Your GPU/driver may not support OpenGL 3.3 core -- common over Remote Desktop, in VMs, or on old GPUs.\n");
        printf("           Fixes: update graphics drivers, use a software OpenGL (Mesa), or run headless with -nogui.\n");
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;

    io.Fonts->AddFontFromMemoryCompressedTTF(
        RobotoMedium_compressed_data, RobotoMedium_compressed_size, 14.0f);

    ImGui::StyleColorsDark();
    ImGuiStyle& st = ImGui::GetStyle();
    st.WindowRounding = st.FrameRounding = st.PopupRounding = 4.0f;
    st.ItemSpacing  = ImVec2(10.0f, 7.0f);
    st.FramePadding = ImVec2(8.0f, 5.0f);
    st.WindowPadding = ImVec2(12.0f, 12.0f);
    // Orange accent
    st.Colors[ImGuiCol_TitleBgActive]   = ImVec4(.80f, .45f, .00f, 1.0f);
    st.Colors[ImGuiCol_CheckMark]       = ImVec4(1.0f, .60f, .00f, 1.0f);
    st.Colors[ImGuiCol_SliderGrab]      = ImVec4(.80f, .45f, .00f, 1.0f);
    st.Colors[ImGuiCol_Button]          = ImVec4(.25f, .25f, .25f, 1.0f);
    st.Colors[ImGuiCol_ButtonHovered]   = ImVec4(.80f, .45f, .00f, 1.0f);
    st.Colors[ImGuiCol_ButtonActive]    = ImVec4(.60f, .30f, .00f, 1.0f);
    st.Colors[ImGuiCol_Header]          = ImVec4(.80f, .45f, .00f, .40f);
    st.Colors[ImGuiCol_HeaderHovered]   = ImVec4(.80f, .45f, .20f, .80f);
    st.Colors[ImGuiCol_Tab]             = ImVec4(.20f, .20f, .20f, 1.0f);
    st.Colors[ImGuiCol_TabHovered]      = ImVec4(.80f, .45f, .00f, 1.0f);
    st.Colors[ImGuiCol_TabActive]       = ImVec4(.80f, .45f, .00f, 1.0f);
    st.Colors[ImGuiCol_SeparatorHovered]= ImVec4(.80f, .45f, .00f, 1.0f);
    st.Colors[ImGuiCol_FrameBg]         = ImVec4(.14f, .14f, .14f, 1.0f);
    st.Colors[ImGuiCol_FrameBgHovered]  = ImVec4(.20f, .20f, .20f, 1.0f);
    st.Colors[ImGuiCol_TableHeaderBg]   = ImVec4(.18f, .18f, .18f, 1.0f);
    st.Colors[ImGuiCol_TableRowBg]      = ImVec4(.11f, .11f, .11f, 1.0f);
    st.Colors[ImGuiCol_TableRowBgAlt]   = ImVec4(.14f, .14f, .14f, 1.0f);

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    g_mineRadio = nMineMode;
    strncpy(g_participantPool, strParticipantPool.c_str(), sizeof(g_participantPool)-1);

    int frame = 0;
    while (!glfwWindowShouldClose(window) && !fShutdown)
    {
        glfwPollEvents();
        if (g_needRefresh || (frame % 120 == 0)) {
            RefreshWallet();
            g_needRefresh = false;
        }
        frame++;

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Draw order matters: status bar last so it is always on top.
        DrawMainWindow();
        DrawSendDialog();
        DrawOptionsDialog();
        DrawWalletSafetyDialog();
        DrawCreatePhraseDialog();
        DrawRestorePhraseDialog();
        DrawDiagnosticsDialog();
        DrawAboutDialog();
        DrawStatusBar();

        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(.08f, .08f, .08f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    fShutdown = true;
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
