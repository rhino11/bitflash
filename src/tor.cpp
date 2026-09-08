// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers_core.h"
#include "tor.h"
#include "nostr.h"
#include "proxy.h"

#include <errno.h>

#ifndef _WIN32
#include <signal.h>
#include <sys/wait.h>
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
        int n = send(s, p, left, 0);
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

bool BtfResolveObfs4Path(std::string& pathOut)
{
    std::string exeDir = ExecutableDir();
    std::vector<std::string> c;
#ifdef _WIN32
    c.push_back(PathJoin(exeDir, "tor/pluggable_transports/lyrebird.exe"));
    c.push_back(PathJoin(exeDir, "tor/pluggable_transports/obfs4proxy.exe"));
#else
    c.push_back(PathJoin(exeDir, "tor/pluggable_transports/lyrebird"));
    c.push_back(PathJoin(exeDir, "tor/pluggable_transports/obfs4proxy"));
    c.push_back("/usr/bin/lyrebird");
    c.push_back("/usr/bin/obfs4proxy");
#endif
    return ResolvePtFrom(c, pathOut);
}

bool BtfResolveSnowflakePath(std::string& pathOut)
{
    std::string exeDir = ExecutableDir();
    std::vector<std::string> c;
#ifdef _WIN32
    c.push_back(PathJoin(exeDir, "tor/pluggable_transports/lyrebird.exe"));
    c.push_back(PathJoin(exeDir, "tor/pluggable_transports/snowflake-client.exe"));
#else
    c.push_back(PathJoin(exeDir, "tor/pluggable_transports/lyrebird"));
    c.push_back(PathJoin(exeDir, "tor/pluggable_transports/snowflake-client"));
    c.push_back("/usr/bin/snowflake-client");
    c.push_back("/usr/bin/lyrebird");
#endif
    return ResolvePtFrom(c, pathOut);
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
    // toggle. p2pPort is well below 65535 in every real config.
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
    g_managedTorPid = fork();
    if (g_managedTorPid < 0)
    {
        errOut = strprintf("could not fork Tor process: %s", strerror(errno));
        return false;
    }
    if (g_managedTorPid == 0)
    {
        execlp(torPath.c_str(), torPath.c_str(), "-f", torrcPath.c_str(), (char*)NULL);
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
    if (fExited)
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
        return g_managedTorStatus;
    }
    return "disabled";
}
