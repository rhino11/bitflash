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
static unsigned short g_managedTorP2PPort = 0;
static std::string g_managedTorPath;
static std::string g_managedTorDataDir;
static std::string g_managedTorHiddenServiceDir;
static std::string g_managedTorOnion;
static std::string g_managedTorStatus;
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
    if (mkdir(path.c_str(), 0700) == 0 || errno == EEXIST)
        return true;
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

std::string BtfBuildManagedTorrcForTest(const std::string& dataDir,
                                        const std::string& hiddenServiceDir,
                                        unsigned short socksPort,
                                        unsigned short p2pPort)
{
    std::string torData = NormalizeTorrcPath(dataDir);
    std::string hsDir = NormalizeTorrcPath(hiddenServiceDir);
    std::string s;
    s += "# Generated by Bitflash. Edit only while Bitflash is not managing Tor.\n";
    s += "DataDirectory " + QuoteTorrcPath(torData) + "\n";
    s += strprintf("SocksPort 127.0.0.1:%u IsolateSOCKSAuth IsolateClientAddr IsolateDestAddr IsolateDestPort\n",
                   (unsigned)socksPort);
    s += "HiddenServiceDir " + QuoteTorrcPath(hsDir) + "\n";
    s += "HiddenServiceVersion 3\n";
    s += strprintf("HiddenServicePort %u 127.0.0.1:%u\n",
                   (unsigned)p2pPort, (unsigned)p2pPort);
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

    unsigned short p2pPort = ntohs(nListenPort);
    std::string torrc = BtfBuildManagedTorrcForTest(dataDir, hsDir, socksPort, p2pPort);
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
        TerminateProcess(g_managedTorProcess.hProcess, 0);
        WaitForSingleObject(g_managedTorProcess.hProcess, 5000);
        CloseHandle(g_managedTorProcess.hProcess);
        CloseHandle(g_managedTorProcess.hThread);
        memset(&g_managedTorProcess, 0, sizeof(g_managedTorProcess));
    }
#else
    if (g_managedTorPid > 0)
    {
        kill(g_managedTorPid, SIGTERM);
        for (int i = 0; i < 50; i++)
        {
            int status = 0;
            pid_t r = waitpid(g_managedTorPid, &status, WNOHANG);
            if (r == g_managedTorPid)
                break;
            Sleep(100);
        }
        g_managedTorPid = -1;
    }
#endif
    CRITICAL_BLOCK(cs_managedTor)
    {
        g_managedTorStatus = "stopped";
        g_managedTorOnion.clear();
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
