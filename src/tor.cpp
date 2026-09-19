// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers_core.h"
#include "tor.h"
#include "nostr.h"
#include "proxy.h"
// util.h's snprintf macro breaks nlohmann/json (see nostr.cpp).
#ifdef snprintf
#undef snprintf
#endif
#include <nlohmann/json.hpp>

#include <errno.h>

#ifndef _WIN32
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

static CCriticalSection cs_managedTor;
static bool g_fManagedTor = false;
static bool g_fManagedTorStopping = false;
static unsigned short g_managedTorSocksPort = 0;
static unsigned short g_managedTorControlPort = 0;
static unsigned short g_managedTorP2PPort = 0;
static std::string g_managedTorPath;
static std::string g_managedTorDataDir;
static std::string g_managedTorHiddenServiceDir;
static std::string g_managedTorOnion;
static std::string g_managedTorStatus;
static std::vector<std::string> g_torBridges;              // bridge lines
int nTorBridgeFallbackSecs = 4 * 60;
int nTorBridgeRungSecs = 6 * 60;
static int64 g_managedTorStartedAt = 0;
static std::string g_torMode = "direct";     // "direct", "user", or a rung name
static bool g_fTorLadderExhausted = false;
static bool g_fTorFirstPeerSeen = false;
static int g_torBootstrapPct = -1;           // -1: not polled yet
static std::string g_torBootstrapLine;
static std::map<std::string, std::string> g_torPtExec;     // transport -> PT binary
#ifdef _WIN32
static PROCESS_INFORMATION g_managedTorProcess;
#else
static pid_t g_managedTorPid = -1;
#endif

static std::string PathJoin(const std::string& a, const std::string& b)
{
    if (a.empty())
        return b;
    char last = a[a.size() - 1];
    if (last == '/' || last == '\\')
        return a + b;
    return a + "/" + b;
}

static std::string NormalizeTorrcPath(std::string path)
{
    for (size_t i = 0; i < path.size(); i++)
        if (path[i] == '\\')
            path[i] = '/';
    return path;
}

static std::string QuoteTorrcPath(const std::string& path)
{
    std::string out = "\"";
    for (size_t i = 0; i < path.size(); i++)
    {
        if (path[i] == '"' || path[i] == '\\')
            out += '\\';
        out += path[i];
    }
    out += "\"";
    return out;
}

static std::string QuoteCommandArg(const std::string& arg)
{
    std::string out = "\"";
    for (size_t i = 0; i < arg.size(); i++)
    {
        if (arg[i] == '"')
            out += '\\';
        out += arg[i];
    }
    out += "\"";
    return out;
}

static bool EnsureDir(const std::string& path, std::string& errOut)
{
    if (path.empty())
    {
        errOut = "directory path is empty";
        return false;
    }
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES)
    {
        if (attr & FILE_ATTRIBUTE_DIRECTORY)
            return true;
        errOut = strprintf("%s exists and is not a directory", path.c_str());
        return false;
    }
    if (CreateDirectoryA(path.c_str(), NULL))
        return true;
    DWORD err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS)
        return true;
    errOut = strprintf("could not create %s (error %lu)", path.c_str(), (unsigned long)err);
    return false;
#else
    struct stat st;
    if (stat(path.c_str(), &st) == 0)
    {
        if (S_ISDIR(st.st_mode))
        {
            chmod(path.c_str(), 0700);
            return true;
        }
        errOut = strprintf("%s exists and is not a directory", path.c_str());
        return false;
    }
    if (mkdir(path.c_str(), 0700) == 0)
        return true;
    if (errno == EEXIST)
    {
        if (stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode))
        {
            chmod(path.c_str(), 0700);
            return true;
        }
    }
    errOut = strprintf("could not create %s: %s", path.c_str(), strerror(errno));
    return false;
#endif
}

static bool WriteTextFile(const std::string& path, const std::string& data,
                          std::string& errOut)
{
    std::string tmp = path + ".tmp";
    FILE* f = fopen(tmp.c_str(), "wb");
    if (!f)
    {
        errOut = strprintf("could not write %s", tmp.c_str());
        return false;
    }
    bool ok = fwrite(data.data(), 1, data.size(), f) == data.size();
    if (fclose(f) != 0)
        ok = false;
    if (!ok)
    {
        remove(tmp.c_str());
        errOut = strprintf("could not finish writing %s", tmp.c_str());
        return false;
    }
#ifdef _WIN32
    if (!MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        remove(tmp.c_str());
        errOut = strprintf("could not install %s atomically (error %lu)",
                           path.c_str(), (unsigned long)GetLastError());
        return false;
    }
#else
    if (rename(tmp.c_str(), path.c_str()) != 0)
    {
        remove(tmp.c_str());
        errOut = strprintf("could not install %s atomically: %s",
                           path.c_str(), strerror(errno));
        return false;
    }
#endif
    return true;
}

static bool ReadBinaryFile(const std::string& path, std::vector<unsigned char>& data,
                           std::string& errOut)
{
    data.clear();
    FILE* f = fopen(path.c_str(), "rb");
    if (!f)
    {
        errOut = strprintf("could not read %s", path.c_str());
        return false;
    }
    unsigned char buf[256];
    for (;;)
    {
        size_t n = fread(buf, 1, sizeof(buf), f);
        if (n > 0)
            data.insert(data.end(), buf, buf + n);
        if (n < sizeof(buf))
        {
            if (ferror(f))
            {
                fclose(f);
                errOut = strprintf("could not finish reading %s", path.c_str());
                return false;
            }
            break;
        }
        if (data.size() > 1024)
        {
            fclose(f);
            errOut = strprintf("%s is unexpectedly large", path.c_str());
            return false;
        }
    }
    fclose(f);
    if (data.empty())
    {
        errOut = strprintf("%s is empty", path.c_str());
        return false;
    }
    return true;
}

static void SetSocketTimeouts(SOCKET s, int millis)
{
#ifdef _WIN32
    DWORD timeout = millis;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = millis / 1000;
    tv.tv_usec = (millis % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

static bool SendAll(SOCKET s, const std::string& data)
{
    const char* p = data.data();
    int left = (int)data.size();
    while (left > 0)
    {
        int n = send(s, p, left, BTF_SEND_FLAGS);
        if (n <= 0)
            return false;
        p += n;
        left -= n;
    }
    return true;
}

static bool RecvControlLine(SOCKET s, std::string& line)
{
    line.clear();
    while (line.size() < 4096)
    {
        char ch = 0;
        int n = recv(s, &ch, 1, 0);
        if (n <= 0)
            return false;
        if (ch == '\n')
            return true;
        if (ch != '\r')
            line += ch;
    }
    return false;
}

static SOCKET ConnectLoopback(unsigned short port, std::string& errOut)
{
#ifdef _WIN32
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR)
    {
        errOut = strprintf("could not start Winsock for Tor control shutdown (WSAStartup returned %d)", ret);
        return INVALID_SOCKET;
    }
#endif
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        errOut = "could not create Tor control socket";
#ifdef _WIN32
        WSACleanup();
#endif
        return INVALID_SOCKET;
    }
    SetSocketTimeouts(s, 3000);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        closesocket(s);
        errOut = strprintf("could not connect to Tor control port 127.0.0.1:%u", (unsigned)port);
#ifdef _WIN32
        WSACleanup();
#endif
        return INVALID_SOCKET;
    }
    return s;
}

static void CloseLoopback(SOCKET s)
{
    if (s != INVALID_SOCKET)
        closesocket(s);
#ifdef _WIN32
    WSACleanup();
#endif
}

static bool ReadPositiveTorControlReply(SOCKET s, std::string& errOut)
{
    std::string line;
    if (!RecvControlLine(s, line))
    {
        errOut = "Tor control port closed before replying";
        return false;
    }
    if (line.size() >= 3 && line.substr(0, 3) == "250")
        return true;
    errOut = strprintf("Tor control command failed: %s", line.c_str());
    return false;
}

static bool RequestManagedTorShutdown(std::string& errOut)
{
    std::string dataDir;
    unsigned short controlPort = 0;
    CRITICAL_BLOCK(cs_managedTor)
    {
        dataDir = g_managedTorDataDir;
        controlPort = g_managedTorControlPort;
    }
    if (controlPort == 0 || dataDir.empty())
    {
        errOut = "Tor control port is not available";
        return false;
    }

    std::vector<unsigned char> cookie;
    if (!ReadBinaryFile(PathJoin(dataDir, "control_auth_cookie"), cookie, errOut))
        return false;

    SOCKET s = ConnectLoopback(controlPort, errOut);
    if (s == INVALID_SOCKET)
        return false;

    bool ok = false;
    std::string auth = "AUTHENTICATE " + HexStr(cookie.begin(), cookie.end(), false) + "\r\n";
    if (!SendAll(s, auth) || !ReadPositiveTorControlReply(s, errOut))
        goto done;

    if (!SendAll(s, "SIGNAL SHUTDOWN\r\n"))
    {
        errOut = "could not send Tor shutdown signal";
        goto done;
    }

    {
        std::string reply;
        if (RecvControlLine(s, reply) && !(reply.size() >= 3 && reply.substr(0, 3) == "250"))
        {
            errOut = strprintf("Tor rejected shutdown signal: %s", reply.c_str());
            goto done;
        }
    }
    ok = true;

done:
    CloseLoopback(s);
    return ok;
}

// GETINFO status/bootstrap-phase over the control port. Tor answers with
// one line like
//   250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=25 TAG=requesting_status SUMMARY="Asking for networkstatus consensus"
// The watchdog polls this so the node can tell "Tor cannot even reach a
// directory" from "Tor is fine, nobody answers".
static bool QueryManagedTorBootstrap(int& pctOut, std::string& summaryOut)
{
    std::string dataDir;
    unsigned short controlPort = 0;
    CRITICAL_BLOCK(cs_managedTor)
    {
        dataDir = g_managedTorDataDir;
        controlPort = g_managedTorControlPort;
    }
    if (controlPort == 0 || dataDir.empty())
        return false;
    std::string err;
    std::vector<unsigned char> cookie;
    if (!ReadBinaryFile(PathJoin(dataDir, "control_auth_cookie"), cookie, err))
        return false;
    SOCKET s = ConnectLoopback(controlPort, err);
    if (s == INVALID_SOCKET)
        return false;
    bool ok = false;
    std::string auth = "AUTHENTICATE " + HexStr(cookie.begin(), cookie.end(), false) + "\r\n";
    if (SendAll(s, auth) && ReadPositiveTorControlReply(s, err) &&
        SendAll(s, "GETINFO status/bootstrap-phase\r\n"))
    {
        std::string line;
        for (int i = 0; i < 8 && RecvControlLine(s, line); i++)
        {
            size_t p = line.find("PROGRESS=");
            if (p != std::string::npos)
            {
                pctOut = atoi(line.c_str() + p + 9);
                size_t q = line.find("SUMMARY=\"");
                summaryOut.clear();
                if (q != std::string::npos)
                {
                    size_t e = line.find('"', q + 9);
                    summaryOut = line.substr(q + 9, e == std::string::npos ? std::string::npos : e - (q + 9));
                }
                ok = true;
            }
            if (line == "250 OK" || (line.size() >= 4 && line[3] == ' '))
                break;
        }
    }
    CloseLoopback(s);
    return ok;
}

int BtfManagedTorBootstrapPercent()
{
    CRITICAL_BLOCK(cs_managedTor)
        return g_torBootstrapPct;
    return -1;
}

std::string BtfManagedTorBootstrapLine()
{
    CRITICAL_BLOCK(cs_managedTor)
    {
        if (g_torBootstrapPct < 0)
            return "";
        return strprintf("%d%% %s", g_torBootstrapPct, g_torBootstrapLine.c_str());
    }
    return "";
}

static bool ReadOneLine(const std::string& path, std::string& out)
{
    out.clear();
    FILE* f = fopen(path.c_str(), "rb");
    if (!f)
        return false;
    char buf[256] = {0};
    if (!fgets(buf, sizeof(buf), f))
    {
        fclose(f);
        return false;
    }
    fclose(f);
    out = buf;
    while (!out.empty() && (out[out.size() - 1] == '\n' || out[out.size() - 1] == '\r' ||
                           out[out.size() - 1] == ' ' || out[out.size() - 1] == '\t'))
        out.erase(out.size() - 1);
    return !out.empty();
}

static bool PickLocalPort(unsigned short& portOut, std::string& errOut)
{
    portOut = 0;
    bool ok = false;
#ifdef _WIN32
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR)
    {
        errOut = strprintf("could not start Winsock for local port probe (WSAStartup returned %d)", ret);
        return false;
    }
#endif
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        errOut = "could not create local port probe socket";
        goto done;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        errOut = "could not bind local port probe socket";
        goto done;
    }
    if (getsockname(s, (struct sockaddr*)&addr, &len) != 0)
    {
        errOut = "could not read local port probe socket";
        goto done;
    }
    portOut = ntohs(addr.sin_port);
    if (portOut == 0)
    {
        errOut = "local port probe returned port zero";
        goto done;
    }
    ok = true;
done:
    if (s != INVALID_SOCKET)
        closesocket(s);
#ifdef _WIN32
    WSACleanup();
#endif
    return ok;
}

static std::string ExecutableDir()
{
#ifdef _WIN32
    char path[MAX_PATH + 1] = {0};
    DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return ".";
    std::string s = path;
    size_t slash = s.find_last_of("\\/");
    if (slash == std::string::npos)
        return ".";
    return s.substr(0, slash);
#else
    char path[4096] = {0};
    ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (n <= 0)
        return ".";
    path[n] = 0;
    std::string s = path;
    size_t slash = s.find_last_of('/');
    if (slash == std::string::npos)
        return ".";
    return s.substr(0, slash);
#endif
}

static bool FileIsExecutableCandidate(const std::string& path)
{
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
#else
    return access(path.c_str(), X_OK) == 0;
#endif
}

static std::string ResolveTorPath(const std::string& torPathOpt)
{
    if (!torPathOpt.empty())
        return torPathOpt;

    std::vector<std::string> candidates;
    std::string exeDir = ExecutableDir();
#ifdef _WIN32
    candidates.push_back(PathJoin(exeDir, "tor/tor.exe"));
    candidates.push_back(PathJoin(exeDir, "tor.exe"));
    candidates.push_back("tor.exe");
#else
    candidates.push_back(PathJoin(exeDir, "tor/tor"));
    candidates.push_back(PathJoin(exeDir, "tor"));
    candidates.push_back("tor");
#endif
    for (size_t i = 0; i < candidates.size(); i++)
    {
        if (candidates[i].find('/') == std::string::npos &&
            candidates[i].find('\\') == std::string::npos)
            return candidates[i]; // Let the OS search PATH.
        if (FileIsExecutableCandidate(candidates[i]))
            return candidates[i];
    }
#ifdef _WIN32
    return "tor.exe";
#else
    return "tor";
#endif
}

bool BtfBundledTorPath(std::string& torPathOut)
{
    torPathOut.clear();
    std::string exeDir = ExecutableDir();
#ifdef _WIN32
    std::string path = PathJoin(exeDir, "tor/tor.exe");
#else
    std::string path = PathJoin(exeDir, "tor/tor");
#endif
    if (!FileIsExecutableCandidate(path))
        return false;
    torPathOut = path;
    return true;
}

void BtfSetTorBridges(const std::vector<std::string>& bridges,
                      const std::map<std::string, std::string>& ptExecByTransport)
{
    g_torBridges = bridges;
    g_torPtExec = ptExecByTransport;
}

bool BtfTorBridgesConfigured()
{
    return !g_torBridges.empty();
}

void BtfSetManagedTorPath(const std::string& torPath)
{
    CRITICAL_BLOCK(cs_managedTor)
        g_managedTorPath = torPath;
}

std::string BtfTorTransportMode()
{
    CRITICAL_BLOCK(cs_managedTor)
        return g_torBridges.empty() ? std::string("direct") : g_torMode;
    return "direct";
}

bool BtfConfigureBridges(const std::vector<std::string>& lines, const std::string& mode,
                         std::string& errOut)
{
    std::map<std::string, std::string> ptExec;
    std::vector<std::string> usable;
    for (size_t i = 0; i < lines.size(); i++)
    {
        std::string tr = BtfBridgeTransport(lines[i]);
        if (tr.empty())
            continue;
        if (!ptExec.count(tr))
        {
            std::string path;
            if (!BtfResolveTransportPath(tr, path))
            {
                errOut = strprintf("no pluggable-transport binary for '%s'", tr.c_str());
                return false;
            }
            ptExec[tr] = path;
        }
        usable.push_back(lines[i]);
    }
    if (usable.empty())
    {
        errOut = "no usable bridge line";
        return false;
    }
    BtfSetTorBridges(usable, ptExec);
    CRITICAL_BLOCK(cs_managedTor)
        g_torMode = mode;
    return true;
}

std::vector<std::string> BtfParseBridgeLines(const std::string& text)
{
    std::vector<std::string> out;
    std::string line;
    for (size_t i = 0; i <= text.size(); i++)
    {
        char c = i < text.size() ? text[i] : '\n';
        if (c != '\n' && c != '\r')
        {
            line += c;
            continue;
        }
        size_t a = line.find_first_not_of(" \t");
        size_t b = line.find_last_not_of(" \t");
        std::string t = a == std::string::npos ? "" : line.substr(a, b - a + 1);
        line.clear();
        if (t.empty() || t[0] == '#')
            continue;
        if (t.size() > 7 && (t.substr(0, 7) == "Bridge " || t.substr(0, 7) == "bridge "))
        {
            t = t.substr(7);
            a = t.find_first_not_of(" \t");
            t = a == std::string::npos ? "" : t.substr(a);
        }
        if (!t.empty())
            out.push_back(t);
    }
    return out;
}

std::string BtfUserBridgesPath()
{
    return PathJoin(GetAppDir(), "bridges.txt");
}

std::vector<std::string> BtfLoadUserBridges()
{
    std::vector<unsigned char> data;
    std::string err;
    FILE* f = fopen(BtfUserBridgesPath().c_str(), "rb");
    if (!f)
        return std::vector<std::string>();
    std::string text;
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0 && text.size() < 65536)
        text.append(buf, n);
    fclose(f);
    return BtfParseBridgeLines(text);
}

bool BtfSaveUserBridges(const std::string& text, std::string& errOut)
{
    std::vector<std::string> lines = BtfParseBridgeLines(text);
    std::string body = "# Bridge lines for reaching Tor where it is blocked, one per line.\n"
                       "# From https://bridges.torproject.org, bridges@torproject.org or the\n"
                       "# Telegram bot @GetBridgesBot. Read when Bitflash starts.\n";
    for (size_t i = 0; i < lines.size(); i++)
        body += lines[i] + "\n";
    return WriteTextFile(BtfUserBridgesPath(), body, errOut);
}

// What reached the network last time lives in managed-tor/last-working, so
// the next start does not spend four minutes finding out again.
static std::string LastWorkingPath()
{
    return PathJoin(PathJoin(GetAppDir(), "managed-tor"), "last-working");
}

std::string BtfLastWorkingTransport()
{
    std::string s;
    if (!ReadOneLine(LastWorkingPath(), s))
        return "";
    return s;
}

void BtfForgetLastWorkingTransport()
{
    remove(LastWorkingPath().c_str());
}

static std::string NoFallbackPath()
{
    return PathJoin(PathJoin(GetAppDir(), "managed-tor"), "no-fallback");
}

bool BtfTorFallbackDisabledByFile()
{
    FILE* f = fopen(NoFallbackPath().c_str(), "rb");
    if (!f)
        return false;
    fclose(f);
    return true;
}

void BtfSetTorFallbackEnabled(bool fEnabled)
{
    if (fEnabled)
    {
        remove(NoFallbackPath().c_str());
        if (nTorBridgeFallbackSecs <= 0)
            nTorBridgeFallbackSecs = 4 * 60;
        return;
    }
    std::string err;
    EnsureDir(PathJoin(GetAppDir(), "managed-tor"), err);
    WriteTextFile(NoFallbackPath(), "# Bitflash: do not switch to bridges on its own. Delete to re-enable.\n", err);
    nTorBridgeFallbackSecs = 0;
}

static void RememberWorkingTransport(const std::string& mode)
{
    if (mode == "direct")
    {
        BtfForgetLastWorkingTransport();
        return;
    }
    std::string err;
    WriteTextFile(LastWorkingPath(), mode + "\n", err);
}

// The rung after the current mode: the first one when on direct or on the
// user's own bridges, else the next in the ladder. Empty name: none left.
static BtfBridgeRung NextRung()
{
    std::vector<BtfBridgeRung> rungs = BtfBundledBridgeRungs();
    std::string mode;
    CRITICAL_BLOCK(cs_managedTor)
        mode = g_torBridges.empty() ? std::string("direct") : g_torMode;
    BtfBridgeRung none;
    if (rungs.empty())
        return none;
    if (mode == "direct" || mode == "user")
        return rungs[0];
    for (size_t i = 0; i + 1 < rungs.size(); i++)
        if (rungs[i].name == mode)
            return rungs[i + 1];
    return none;
}

// Restart the managed Tor with the given bridge lines under the given mode.
// Keeps the onion (same hidden-service directory).
static bool RestartManagedTorWithBridges(const std::vector<std::string>& lines,
                                         const std::string& mode, std::string& errOut)
{
    std::string torPath;
    CRITICAL_BLOCK(cs_managedTor)
        torPath = g_managedTorPath;
    BtfStopManagedTor();
    if (!BtfConfigureBridges(lines, mode, errOut))
        return false;
    return BtfStartManagedTor(torPath, errOut);
}

bool BtfTryBridgesNow(std::string& errOut)
{
    if (!BtfManagedTorEnabled())
    {
        errOut = "managed Tor is not running";
        return false;
    }
    std::vector<std::string> user = BtfLoadUserBridges();
    if (!user.empty() && BtfTorTransportMode() != "user")
    {
        printf("managed Tor: switching to your bridges (%d line(s) in bridges.txt)\n", (int)user.size());
        return RestartManagedTorWithBridges(user, "user", errOut);
    }
    BtfBridgeRung rung = NextRung();
    if (rung.name.empty())
    {
        errOut = "every bundled transport has been tried; put bridges of your own in bridges.txt";
        return false;
    }
    printf("managed Tor: switching to the bundled %s bridges (%d line(s))\n",
           rung.name.c_str(), (int)rung.lines.size());
    return RestartManagedTorWithBridges(rung.lines, rung.name, errOut);
}

std::string BtfBridgeTransport(const std::string& bridgeLine)
{
    std::string t;
    for (size_t i = 0; i < bridgeLine.size(); i++)
    {
        char c = bridgeLine[i];
        if (c == ' ' || c == '\t')
            break;
        t += c;
    }
    return t;
}

static bool ResolvePtFrom(const std::vector<std::string>& candidates, std::string& out)
{
    out.clear();
    for (size_t i = 0; i < candidates.size(); i++)
        if (FileIsExecutableCandidate(candidates[i]))
        {
            out = candidates[i];
            return true;
        }
    return false;
}

// Where the transports may sit: next to us under tor/, and next to the
// Tor we were pointed at (-managedtor=PATH), which carries its own.
static std::vector<std::string> PtDirs()
{
    std::vector<std::string> dirs;
    dirs.push_back(PathJoin(ExecutableDir(), "tor/pluggable_transports"));
    std::string torPath;
    CRITICAL_BLOCK(cs_managedTor)
        torPath = g_managedTorPath;
    if (!torPath.empty())
    {
        size_t cut = torPath.find_last_of("/\\");
        std::string torDir = cut == std::string::npos ? "." : torPath.substr(0, cut);
        dirs.push_back(PathJoin(torDir, "pluggable_transports"));
    }
    return dirs;
}

bool BtfResolveObfs4Path(std::string& pathOut)
{
    std::vector<std::string> dirs = PtDirs();
    std::vector<std::string> c;
    for (size_t i = 0; i < dirs.size(); i++)
    {
#ifdef _WIN32
        c.push_back(PathJoin(dirs[i], "lyrebird.exe"));
        c.push_back(PathJoin(dirs[i], "obfs4proxy.exe"));
#else
        c.push_back(PathJoin(dirs[i], "lyrebird"));
        c.push_back(PathJoin(dirs[i], "obfs4proxy"));
#endif
    }
#ifndef _WIN32
    c.push_back("/usr/bin/lyrebird");
    c.push_back("/usr/bin/obfs4proxy");
#endif
    return ResolvePtFrom(c, pathOut);
}

bool BtfResolveSnowflakePath(std::string& pathOut)
{
    std::vector<std::string> dirs = PtDirs();
    std::vector<std::string> c;
    for (size_t i = 0; i < dirs.size(); i++)
    {
#ifdef _WIN32
        c.push_back(PathJoin(dirs[i], "lyrebird.exe"));
        c.push_back(PathJoin(dirs[i], "snowflake-client.exe"));
#else
        c.push_back(PathJoin(dirs[i], "lyrebird"));
        c.push_back(PathJoin(dirs[i], "snowflake-client"));
#endif
    }
#ifndef _WIN32
    c.push_back("/usr/bin/snowflake-client");
    c.push_back("/usr/bin/lyrebird");
#endif
    return ResolvePtFrom(c, pathOut);
}

bool BtfResolveTransportPath(const std::string& transport, std::string& pathOut)
{
    if (transport == "snowflake")
        return BtfResolveSnowflakePath(pathOut);
    if (transport == "conjure")
    {
        std::vector<std::string> dirs = PtDirs();
        std::vector<std::string> c;
        for (size_t i = 0; i < dirs.size(); i++)
#ifdef _WIN32
            c.push_back(PathJoin(dirs[i], "conjure-client.exe"));
#else
            c.push_back(PathJoin(dirs[i], "conjure-client"));
#endif
        return ResolvePtFrom(c, pathOut);
    }
    // obfs4, meek_lite, webtunnel, scramblesuit, obfs2/3: all lyrebird.
    return BtfResolveObfs4Path(pathOut);
}

// Tor Browser's bridge list ships beside the transports as pt_config.json.
// Read it when it is there so the set stays as fresh as the Tor bundle;
// the built-in Snowflake lines cover a bundle without it.
static bool ReadPtConfigBridges(std::map<std::string, std::vector<std::string> >& out)
{
    std::vector<std::string> dirs = PtDirs();
    for (size_t d = 0; d < dirs.size(); d++)
    {
        FILE* f = fopen(PathJoin(dirs[d], "pt_config.json").c_str(), "rb");
        if (!f)
            continue;
        std::string text;
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0 && text.size() < 262144)
            text.append(buf, n);
        fclose(f);
        try
        {
            nlohmann::json j = nlohmann::json::parse(text);
            if (!j.contains("bridges") || !j["bridges"].is_object())
                continue;
            for (nlohmann::json::iterator it = j["bridges"].begin(); it != j["bridges"].end(); ++it)
            {
                if (!it.value().is_array())
                    continue;
                std::vector<std::string> lines;
                for (size_t i = 0; i < it.value().size(); i++)
                    if (it.value()[i].is_string())
                        lines.push_back(it.value()[i].get<std::string>());
                if (!lines.empty())
                    out[it.key()] = lines;
            }
            return !out.empty();
        }
        catch (...)
        {
            continue;
        }
    }
    return false;
}

std::vector<BtfBridgeRung> BtfBundledBridgeRungs()
{
    std::map<std::string, std::vector<std::string> > sets;
    ReadPtConfigBridges(sets);
    if (!sets.count("snowflake"))
    {
        std::vector<std::string> b = BtfDefaultBridges();
        sets["snowflake"] = b;
    }
    // Order of survival under blocking: Snowflake (volunteer WebRTC, CDN
    // broker) first, obfs4 (fixed IPs, blocked one by one) second,
    // webtunnel (looks like HTTPS to a real site) and meek (CDN fronting)
    // after, whatever else the file lists last. Only rungs whose transport
    // binary is here.
    static const char* order[] = { "snowflake", "obfs4", "webtunnel", "meek" };
    std::vector<BtfBridgeRung> rungs;
    std::set<std::string> taken;
    for (size_t o = 0; o < sizeof(order) / sizeof(order[0]); o++)
    {
        std::map<std::string, std::vector<std::string> >::const_iterator it = sets.find(order[o]);
        if (it == sets.end())
            continue;
        std::string path;
        if (!BtfResolveTransportPath(BtfBridgeTransport(it->second[0]), path))
            continue;
        BtfBridgeRung r;
        r.name = it->first;
        r.lines = it->second;
        rungs.push_back(r);
        taken.insert(it->first);
    }
    for (std::map<std::string, std::vector<std::string> >::const_iterator it = sets.begin();
         it != sets.end(); ++it)
    {
        if (taken.count(it->first) || it->first == "conjure")
            continue;
        std::string path;
        if (!BtfResolveTransportPath(BtfBridgeTransport(it->second[0]), path))
            continue;
        BtfBridgeRung r;
        r.name = it->first;
        r.lines = it->second;
        rungs.push_back(r);
    }
    return rungs;
}

std::vector<std::string> BtfDefaultBridges()
{
    std::vector<std::string> b;
    // Standard Snowflake bridge: reaches Tor through volunteer WebRTC proxies
    // via Tor's broker, needing no infrastructure of ours and no bridge
    // curation. The broker fronts/STUN list is the long-standing Tor Browser
    // default; proven to bootstrap end to end on the bench.
    b.push_back("snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
                "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
                "url=https://1098762253.rsc.cdn77.org/ "
                "fronts=www.cdn77.com,www.phpmyadmin.net "
                "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,"
                "stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478 "
                "utls-imitate=hellorandomizedalpn");
    // A second Snowflake bridge with the current Tor Browser domain fronts
    // (datapacket): more resilience -- Tor warns with a single bridge -- and a
    // live fallback for when the cdn77 fronts above stop resolving.
    b.push_back("snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA "
                "fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA "
                "url=https://1098762253.rsc.cdn77.org/ "
                "fronts=app.datapacket.com,www.datapacket.com "
                "ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,"
                "stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,"
                "stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478 "
                "utls-imitate=hellorandomizedalpn");
    return b;
}

std::string BtfBuildManagedTorrcForTest(const std::string& dataDir,
                                        const std::string& hiddenServiceDir,
                                        unsigned short socksPort,
                                        unsigned short controlPort,
                                        unsigned short p2pPort,
                                        const std::vector<std::string>& bridges,
                                        const std::map<std::string, std::string>& ptExecByTransport)
{
    std::string torData = NormalizeTorrcPath(dataDir);
    std::string hsDir = NormalizeTorrcPath(hiddenServiceDir);
    std::string s;
    s += "# Generated by Bitflash. Edit only while Bitflash is not managing Tor.\n";
    s += "DataDirectory " + QuoteTorrcPath(torData) + "\n";
    s += strprintf("SocksPort 127.0.0.1:%u IsolateSOCKSAuth IsolateClientAddr IsolateDestAddr IsolateDestPort\n",
                   (unsigned)socksPort);
    s += strprintf("ControlPort 127.0.0.1:%u\n", (unsigned)controlPort);
    s += "CookieAuthentication 1\n";
    s += "HiddenServiceDir " + QuoteTorrcPath(hsDir) + "\n";
    s += "HiddenServiceVersion 3\n";
    s += strprintf("HiddenServicePort %u 127.0.0.1:%u\n",
                   (unsigned)p2pPort, (unsigned)p2pPort);
    // A second virtual port on the same .onion for the cooperative mining pool,
    // so a pool operator accepts miners over its hidden service instead of a
    // rendezvous relay. Miners derive it as p2pPort+1 from the operator's
    // advertised P2P onion, so it needs no separate announcement. Always mapped
    // (harmless when no pool listens -- the connection is simply refused): the
    // pool binds this local port only when it runs, needing no Tor reconfig to
    // toggle. Guard the +1 so a p2p port of 65535 (absurd but possible) does
    // not map an out-of-range pool port -- the arithmetic must not wrap.
    if (p2pPort < 65535)
        s += strprintf("HiddenServicePort %u 127.0.0.1:%u\n",
                       (unsigned)(p2pPort + 1), (unsigned)(p2pPort + 1));
    // Pluggable transports for reaching Tor where it is blocked, without our
    // rendezvous relays. Emit one ClientTransportPlugin per PT binary, listing
    // every transport it serves that we actually have a bridge for, then the
    // bridge lines. Tor takes the rest of the exec line verbatim and does NOT
    // strip quotes, so the path is left bare (keep bundled PTs space-free).
    if (!bridges.empty())
    {
        std::map<std::string, std::string> transportsByExec; // exec -> "obfs4,snowflake"
        for (size_t i = 0; i < bridges.size(); i++)
        {
            std::string tr = BtfBridgeTransport(bridges[i]);
            std::map<std::string, std::string>::const_iterator it = ptExecByTransport.find(tr);
            if (it == ptExecByTransport.end() || it->second.empty())
                continue; // no binary for this transport -> skip its plugin line
            std::string exec = NormalizeTorrcPath(it->second);
            std::string& list = transportsByExec[exec];
            if (list.empty())
                list = tr;
            else if ((list + ",").find(tr + ",") == std::string::npos && list != tr)
                list += "," + tr;
        }
        if (!transportsByExec.empty())
        {
            s += "UseBridges 1\n";
            for (std::map<std::string, std::string>::const_iterator it = transportsByExec.begin();
                 it != transportsByExec.end(); ++it)
                s += "ClientTransportPlugin " + it->second + " exec " + it->first + "\n";
            for (size_t i = 0; i < bridges.size(); i++)
                s += "Bridge " + bridges[i] + "\n";
        }
    }
    return s;
}

static bool StartTorProcess(const std::string& torPath, const std::string& torrcPath,
                            std::string& errOut)
{
#ifdef _WIN32
    memset(&g_managedTorProcess, 0, sizeof(g_managedTorProcess));
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    std::string cmd = QuoteCommandArg(torPath) + " -f " + QuoteCommandArg(torrcPath);
    std::vector<char> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(0);
    if (!CreateProcessA(NULL, &mutableCmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &g_managedTorProcess))
    {
        errOut = strprintf("could not start Tor process %s (error %lu)",
                           torPath.c_str(), (unsigned long)GetLastError());
        return false;
    }
    return true;
#else
    // The Tor Expert Bundle's tor carries no RUNPATH: it expects the launcher
    // to point LD_LIBRARY_PATH at the libevent/libssl/libcrypto shipped next
    // to it, the way Tor Browser does. Left to the system copies it dies with
    // "symbol lookup error: undefined symbol: evutil_secure_rng_add_bytes"
    // (exit 127) on any distribution whose libevent was built on a libc with
    // arc4random -- Fedora 44 and Ubuntu 26.04 among them. Everything the
    // child needs is assembled here, before fork(): in a threaded program the
    // child may only call async-signal-safe functions, and setenv/malloc are
    // not. A bare name (no '/') is left to execlp and the PATH search.
    std::vector<std::string> envStrings;
    std::string torDir;
    {
        size_t slash = torPath.rfind('/');
        if (slash != std::string::npos)
            torDir = torPath.substr(0, slash);
    }
    bool fHaveLdPath = false;
    for (char** e = environ; e && *e; e++)
    {
        if (!torDir.empty() && strncmp(*e, "LD_LIBRARY_PATH=", 16) == 0)
        {
            envStrings.push_back("LD_LIBRARY_PATH=" + torDir + ":" + std::string(*e + 16));
            fHaveLdPath = true;
        }
        else
            envStrings.push_back(*e);
    }
    if (!torDir.empty() && !fHaveLdPath)
        envStrings.push_back("LD_LIBRARY_PATH=" + torDir);
    std::vector<const char*> envpTor;
    for (size_t i = 0; i < envStrings.size(); i++)
        envpTor.push_back(envStrings[i].c_str());
    envpTor.push_back(NULL);
    const char* argvTor[] = { torPath.c_str(), "-f", torrcPath.c_str(), NULL };

    g_managedTorPid = fork();
    if (g_managedTorPid < 0)
    {
        errOut = strprintf("could not fork Tor process: %s", strerror(errno));
        return false;
    }
    if (g_managedTorPid == 0)
    {
        if (torPath.find('/') == std::string::npos)
            execlp(torPath.c_str(), torPath.c_str(), "-f", torrcPath.c_str(), (char*)NULL);
        else
            execve(torPath.c_str(), const_cast<char* const*>(&argvTor[0]),
                   const_cast<char* const*>(&envpTor[0]));
        _exit(127);
    }
    return true;
#endif
}

static bool ManagedTorProcessAlive(bool& fExited, int& nExitCode)
{
    fExited = false;
    nExitCode = 0;
#ifdef _WIN32
    HANDLE hProcess = NULL;
    CRITICAL_BLOCK(cs_managedTor)
        hProcess = g_managedTorProcess.hProcess;
    if (!hProcess)
        return false;
    DWORD code = 0;
    if (!GetExitCodeProcess(hProcess, &code))
        return false;
    if (code != STILL_ACTIVE)
    {
        fExited = true;
        nExitCode = (int)code;
        return false;
    }
    return true;
#else
    pid_t pid = -1;
    CRITICAL_BLOCK(cs_managedTor)
        pid = g_managedTorPid;
    if (pid <= 0)
        return false;
    int status = 0;
    pid_t r = waitpid(pid, &status, WNOHANG);
    if (r == 0)
        return true;
    if (r == pid)
    {
        fExited = true;
        if (WIFEXITED(status))
            nExitCode = WEXITSTATUS(status);
        else if (WIFSIGNALED(status))
            nExitCode = 128 + WTERMSIG(status);
        CRITICAL_BLOCK(cs_managedTor)
            if (g_managedTorPid == pid)
                g_managedTorPid = -1;
    }
    return false;
#endif
}

static bool ValidateManagedTorStartup(std::string& errOut)
{
    Sleep(500);
    bool fExited = false;
    int nExitCode = 0;
    if (ManagedTorProcessAlive(fExited, nExitCode))
        return true;
    if (fExited && nExitCode == 127)
        errOut = "Tor could not be executed (exit code 127: the binary or a shared library it needs was not found)";
    else if (fExited)
        errOut = strprintf("Tor exited during startup with code %d", nExitCode);
    else
        errOut = "Tor process is not running after startup";
    return false;
}

static void MarkManagedTorDead(int nExitCode)
{
    BtfStopManagedTor();
    CRITICAL_BLOCK(cs_managedTor)
        g_managedTorStatus = strprintf("stopped unexpectedly, Tor exit code %d", nExitCode);
}

static void ThreadManagedTorWatchdog(void*)
{
    for (;;)
    {
        Sleep(5000);
        CRITICAL_BLOCK(cs_managedTor)
        {
            if (!g_fManagedTor || g_fManagedTorStopping || fShutdown)
                return;
        }

        bool fExited = false;
        int nExitCode = 0;
        if (!ManagedTorProcessAlive(fExited, nExitCode))
        {
            if (fExited)
                MarkManagedTorDead(nExitCode);
            else
            {
                BtfStopManagedTor();
                CRITICAL_BLOCK(cs_managedTor)
                    g_managedTorStatus = "stopped unexpectedly, Tor process handle is gone";
            }
            return;
        }

        // Tor's own view: how far it got. Cheap, local, every 5 s.
        {
            int pct = -1;
            std::string summary;
            if (QueryManagedTorBootstrap(pct, summary))
                CRITICAL_BLOCK(cs_managedTor)
                {
                    g_torBootstrapPct = pct;
                    g_torBootstrapLine = summary;
                }
        }

        bool fAnyPeer = false;
        CRITICAL_BLOCK(cs_vNodes)
            fAnyPeer = !vNodes.empty();
        std::string mode = BtfTorTransportMode();

        if (fAnyPeer)
        {
            if (!g_fTorFirstPeerSeen)
            {
                g_fTorFirstPeerSeen = true;
                printf("managed Tor: network reached via %s\n",
                       mode == "direct" ? "direct Tor" :
                       mode == "user" ? "your bridges" : (mode + " bridges").c_str());
                RememberWorkingTransport(mode);
            }
            continue;
        }

        // Nobody reached. A firewall that blocks Tor's public relays looks
        // like this; so does a bridge that died. Climb the ladder: direct ->
        // snowflake -> obfs4 -> webtunnel -> meek, each given its time, the
        // direct rung cut short when Tor cannot even fetch a consensus.
        if (nTorBridgeFallbackSecs <= 0 || g_fTorLadderExhausted || g_fTorFirstPeerSeen ||
            !g_managedTorStartedAt)
            continue;
        int64 waited = GetTime() - g_managedTorStartedAt;
        int pct = BtfManagedTorBootstrapPercent();
        bool fDue;
        if (mode == "direct")
            fDue = waited > nTorBridgeFallbackSecs ||
                   (pct >= 0 && pct < 10 && waited > 90);   // no directory in 90 s: blocked
        else
            fDue = waited > nTorBridgeRungSecs;
        if (!fDue)
            continue;

        BtfBridgeRung rung = NextRung();
        if (rung.name.empty())
        {
            g_fTorLadderExhausted = true;
            if (mode == "direct")
                printf("managed Tor: no peer after %d s and no pluggable transports bundled; nothing to fall back to\n",
                       (int)waited);
            else
                printf("managed Tor: no peer after %d s on %s and every bundled transport has been tried. "
                       "Get bridges of your own (https://bridges.torproject.org, bridges@torproject.org, "
                       "Telegram @GetBridgesBot) and put them in %s\n",
                       (int)waited, mode == "user" ? "your bridges" : (mode + " bridges").c_str(),
                       BtfUserBridgesPath().c_str());
            continue;
        }
        if (mode == "direct")
            printf("managed Tor: no peer after %d s (Tor bootstrap %s) -- Tor's public relays may be blocked here. "
                   "Restarting Tor with the bundled %s bridges (%d line(s)); -notorfallback disables this.\n",
                   (int)waited, BtfManagedTorBootstrapLine().empty() ? "unknown" : BtfManagedTorBootstrapLine().c_str(),
                   rung.name.c_str(), (int)rung.lines.size());
        else
            printf("managed Tor: no peer after %d s on %s (Tor bootstrap %s). Trying the bundled %s bridges (%d line(s)).\n",
                   (int)waited, mode == "user" ? "your bridges" : (mode + " bridges").c_str(),
                   BtfManagedTorBootstrapLine().empty() ? "unknown" : BtfManagedTorBootstrapLine().c_str(),
                   rung.name.c_str(), (int)rung.lines.size());
        std::string strError;
        if (!RestartManagedTorWithBridges(rung.lines, rung.name, strError))
            printf("managed Tor: restart with bridges failed: %s\n", strError.c_str());
        return;   // the new Tor has its own watchdog
    }
}

static void ThreadManagedTorHostname(void*)
{
    std::string hostnamePath;
    unsigned short p2pPort = 0;
    CRITICAL_BLOCK(cs_managedTor)
    {
        hostnamePath = PathJoin(g_managedTorHiddenServiceDir, "hostname");
        p2pPort = g_managedTorP2PPort;
    }

    for (int i = 0; i < 90 && !fShutdown; i++)
    {
        std::string onion;
        if (ReadOneLine(hostnamePath, onion))
        {
            std::string endpoint = strprintf("%s:%u", onion.c_str(), (unsigned)p2pPort);
            std::string err;
            if (BtfSetLocalOnionEndpoint(endpoint, err))
            {
                CRITICAL_BLOCK(cs_managedTor)
                {
                    g_managedTorOnion = BtfLocalOnionEndpoint();
                    g_managedTorStatus = strprintf("running, SOCKS5 127.0.0.1:%u, onion %s",
                                                   (unsigned)g_managedTorSocksPort,
                                                   g_managedTorOnion.c_str());
                }
                printf("Managed Tor hidden service ready: %s\n", BtfLocalOnionEndpoint().c_str());
                return;
            }
            CRITICAL_BLOCK(cs_managedTor)
                g_managedTorStatus = strprintf("running, but generated onion endpoint was rejected: %s",
                                               err.c_str());
            return;
        }
        Sleep(1000);
    }

    BtfStopManagedTor();
    CRITICAL_BLOCK(cs_managedTor)
        g_managedTorStatus = "failed: Tor did not create a hidden service hostname within 90s";
}

bool BtfStartManagedTor(const std::string& torPathOpt, std::string& errOut)
{
    CRITICAL_BLOCK(cs_managedTor)
    {
        if (g_fManagedTor)
        {
            errOut = "managed Tor is already running";
            return false;
        }
    }

    g_managedTorStartedAt = GetTime();
    g_fTorFirstPeerSeen = false;
    CRITICAL_BLOCK(cs_managedTor)
    {
        g_torBootstrapPct = -1;
        g_torBootstrapLine.clear();
    }
    std::string root = PathJoin(GetAppDir(), "managed-tor");
    std::string dataDir = PathJoin(root, "data");
    std::string hsDir = PathJoin(root, "onion-service");
    std::string torrcPath = PathJoin(root, "torrc");
    if (!EnsureDir(root, errOut) || !EnsureDir(dataDir, errOut) || !EnsureDir(hsDir, errOut))
        return false;

    unsigned short socksPort = 0;
    if (!PickLocalPort(socksPort, errOut))
        return false;
    unsigned short controlPort = 0;
    if (!PickLocalPort(controlPort, errOut))
        return false;

    unsigned short p2pPort = ntohs(nListenPort);
    std::string torrc = BtfBuildManagedTorrcForTest(dataDir, hsDir, socksPort,
                                                   controlPort, p2pPort,
                                                   g_torBridges, g_torPtExec);
    if (!WriteTextFile(torrcPath, torrc, errOut))
        return false;

    std::string torPath = ResolveTorPath(torPathOpt);
    {
        CRITICAL_BLOCK(cs_managedTor)
        {
            g_fManagedTor = true;
            g_fManagedTorStopping = false;
            g_managedTorPath = torPath;
            g_managedTorDataDir = dataDir;
            g_managedTorHiddenServiceDir = hsDir;
            g_managedTorSocksPort = socksPort;
            g_managedTorControlPort = controlPort;
            g_managedTorP2PPort = p2pPort;
            g_managedTorOnion.clear();
            g_managedTorStatus = strprintf("starting %s, SOCKS5 127.0.0.1:%u",
                                           torPath.c_str(), (unsigned)socksPort);
        }
    }

    if (!StartTorProcess(torPath, torrcPath, errOut))
    {
        CRITICAL_BLOCK(cs_managedTor)
        {
            g_fManagedTor = false;
            g_managedTorStatus = strprintf("failed: %s", errOut.c_str());
        }
        return false;
    }
    if (!ValidateManagedTorStartup(errOut))
    {
        BtfStopManagedTor();
        CRITICAL_BLOCK(cs_managedTor)
            g_managedTorStatus = strprintf("failed: %s", errOut.c_str());
        return false;
    }

    std::string proxyErr;
    if (!BtfEnableTorProxy(strprintf("127.0.0.1:%u", (unsigned)socksPort), proxyErr))
    {
        BtfStopManagedTor();
        errOut = strprintf("could not enable managed Tor SOCKS5 proxy: %s", proxyErr.c_str());
        return false;
    }

    if (_beginthread(ThreadManagedTorHostname, 0, NULL) == (uintptr_t)-1)
    {
        BtfStopManagedTor();
        errOut = "could not start managed Tor hostname watcher";
        return false;
    }
    if (_beginthread(ThreadManagedTorWatchdog, 0, NULL) == (uintptr_t)-1)
    {
        BtfStopManagedTor();
        errOut = "could not start managed Tor watchdog";
        return false;
    }

    return true;
}

void BtfStopManagedTor()
{
    bool fWasRunning = false;
    CRITICAL_BLOCK(cs_managedTor)
    {
        fWasRunning = g_fManagedTor;
        if (!fWasRunning)
            return;
        g_fManagedTorStopping = true;
        g_fManagedTor = false;
        g_managedTorStatus = "stopping";
    }
#ifdef _WIN32
    if (g_managedTorProcess.hProcess)
    {
        std::string shutdownErr;
        bool fGraceful = RequestManagedTorShutdown(shutdownErr);
        DWORD waitResult = WaitForSingleObject(g_managedTorProcess.hProcess,
                                               fGraceful ? 10000 : 1000);
        if (waitResult != WAIT_OBJECT_0)
        {
            TerminateProcess(g_managedTorProcess.hProcess, 0);
            WaitForSingleObject(g_managedTorProcess.hProcess, 5000);
        }
        CloseHandle(g_managedTorProcess.hProcess);
        CloseHandle(g_managedTorProcess.hThread);
        memset(&g_managedTorProcess, 0, sizeof(g_managedTorProcess));
    }
#else
    if (g_managedTorPid > 0)
    {
        std::string shutdownErr;
        if (!RequestManagedTorShutdown(shutdownErr))
            kill(g_managedTorPid, SIGTERM);
        bool fExited = false;
        for (int i = 0; i < 100; i++)
        {
            int status = 0;
            pid_t r = waitpid(g_managedTorPid, &status, WNOHANG);
            if (r == g_managedTorPid)
            {
                fExited = true;
                break;
            }
            Sleep(100);
        }
        if (!fExited)
        {
            kill(g_managedTorPid, SIGKILL);
            waitpid(g_managedTorPid, NULL, 0);
        }
        g_managedTorPid = -1;
    }
#endif
    CRITICAL_BLOCK(cs_managedTor)
    {
        g_managedTorStatus = "stopped";
        g_managedTorOnion.clear();
        g_managedTorSocksPort = 0;
        g_managedTorControlPort = 0;
        g_managedTorP2PPort = 0;
    }
}

bool BtfManagedTorEnabled()
{
    CRITICAL_BLOCK(cs_managedTor)
        return g_fManagedTor;
    return false;
}

std::string BtfManagedTorStatus()
{
    CRITICAL_BLOCK(cs_managedTor)
    {
        if (!g_fManagedTor && g_managedTorStatus.empty())
            return "disabled";
        std::string s = g_managedTorStatus;
        if (g_fManagedTor)
        {
            if (!g_torBridges.empty())
                s += ", via " + (g_torMode == "user" ? std::string("your bridges") : g_torMode + " bridges");
            if (g_torBootstrapPct >= 0 && g_torBootstrapPct < 100)
                s += strprintf(", Tor bootstrap %d%% (%s)", g_torBootstrapPct, g_torBootstrapLine.c_str());
        }
        return s;
    }
    return "disabled";
}
