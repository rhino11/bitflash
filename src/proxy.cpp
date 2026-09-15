// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers_core.h"
#include "proxy.h"
#include "sockcount.h"

#include <errno.h>

static CCriticalSection cs_socks5;
static bool g_fSocks5Proxy = false;
static bool g_fTorProxy = false;
static std::string g_socks5Host;
static unsigned short g_socks5Port = 0;
static const char* DEFAULT_TOR_SOCKS5_PROXY = "127.0.0.1:9050";
static const int TOR_CONNECT_TIMEOUT_SECS = 120;

static void SetSocketTimeout(SOCKET s, int nTimeoutSecs)
{
    if (nTimeoutSecs <= 0)
        return;
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

static bool ReadN(SOCKET s, void* buf, int n)
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

static bool WriteN(SOCKET s, const void* buf, int n)
{
    const char* p = (const char*)buf;
    int off = 0;
    while (off < n)
    {
        int r = send(s, p + off, n - off, BTF_SEND_FLAGS);
        if (r <= 0)
            return false;
        off += r;
    }
    return true;
}

static bool ValidProxyHostChar(char c)
{
    return isalnum((unsigned char)c) || c == '.' || c == '-' || c == '_';
}

static bool ValidProxyIpv6HostChar(char c)
{
    return isxdigit((unsigned char)c) || c == ':' || c == '.';
}

static std::string LowerProxyHost(std::string host)
{
    if (!host.empty() && host[host.size() - 1] == '.')
        host.erase(host.size() - 1);
    for (size_t i = 0; i < host.size(); i++)
        host[i] = (char)tolower((unsigned char)host[i]);
    return host;
}

bool BtfIsTorOnionHost(const std::string& host)
{
    std::string lower = LowerProxyHost(host);
    static const char* suffix = ".onion";
    size_t suffixLen = strlen(suffix);
    return lower.size() > suffixLen &&
           lower.compare(lower.size() - suffixLen, suffixLen, suffix) == 0;
}

static bool ParsePort(const std::string& port, unsigned short& portOut,
                      std::string& errOut)
{
    if (port.empty())
    {
        errOut = "port is empty";
        return false;
    }
    for (size_t i = 0; i < port.size(); i++)
    {
        if (!isdigit((unsigned char)port[i]))
        {
            errOut = "port is not numeric";
            return false;
        }
    }

    errno = 0;
    char* end = NULL;
    long nPort = strtol(port.c_str(), &end, 10);
    if (errno == ERANGE || end == NULL || *end != '\0' || nPort <= 0 || nPort > 65535)
    {
        errOut = "port is out of range";
        return false;
    }
    portOut = (unsigned short)nPort;
    return true;
}

bool BtfParseSocks5Proxy(const std::string& spec, std::string& hostOut,
                         unsigned short& portOut, std::string& errOut)
{
    hostOut.clear();
    portOut = 0;
    errOut.clear();

    std::string host;
    std::string port;
    bool fBracketedIpv6 = false;
    if (!spec.empty() && spec[0] == '[')
    {
        size_t close = spec.find(']');
        if (close == std::string::npos || close == 1 || close + 1 >= spec.size() || spec[close + 1] != ':')
        {
            errOut = "expected [IPv6]:PORT";
            return false;
        }
        host = spec.substr(1, close - 1);
        port = spec.substr(close + 2);
        fBracketedIpv6 = true;
    }
    else
    {
        size_t colon = spec.rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 >= spec.size())
        {
            errOut = "expected HOST:PORT";
            return false;
        }
        host = spec.substr(0, colon);
        port = spec.substr(colon + 1);
        if (host.find(':') != std::string::npos)
        {
            errOut = "IPv6 proxy hosts must use [ADDR]:PORT";
            return false;
        }
    }

    if (host.size() > 255)
    {
        errOut = "host is too long";
        return false;
    }
    if (fBracketedIpv6)
    {
        bool fHasColon = false;
        for (size_t i = 0; i < host.size(); i++)
        {
            fHasColon = fHasColon || host[i] == ':';
            if (!ValidProxyIpv6HostChar(host[i]))
            {
                errOut = "IPv6 proxy host contains unsupported characters";
                return false;
            }
        }
        if (!fHasColon)
        {
            errOut = "bracketed proxy host is not IPv6";
            return false;
        }
    }
    else
    {
        for (size_t i = 0; i < host.size(); i++)
        {
            if (!ValidProxyHostChar(host[i]))
            {
                errOut = "host contains unsupported characters";
                return false;
            }
        }
    }
    if (!ParsePort(port, portOut, errOut))
        return false;

    hostOut = host;
    return true;
}

static bool SetSocks5Proxy(const std::string& spec, bool fTorMode,
                           std::string& errOut)
{
    std::string host;
    unsigned short port = 0;
    if (!BtfParseSocks5Proxy(spec, host, port, errOut))
        return false;
    CRITICAL_BLOCK(cs_socks5)
    {
        g_socks5Host = host;
        g_socks5Port = port;
        g_fSocks5Proxy = true;
        g_fTorProxy = fTorMode;
    }
    return true;
}

bool BtfSetSocks5Proxy(const std::string& spec, std::string& errOut)
{
    return SetSocks5Proxy(spec, false, errOut);
}

bool BtfEnableTorProxy(const std::string& spec, std::string& errOut)
{
    return SetSocks5Proxy(spec.empty() ? DEFAULT_TOR_SOCKS5_PROXY : spec, true, errOut);
}

void BtfClearSocks5Proxy()
{
    CRITICAL_BLOCK(cs_socks5)
    {
        g_fSocks5Proxy = false;
        g_fTorProxy = false;
        g_socks5Host.clear();
        g_socks5Port = 0;
    }
}

bool BtfSocks5ProxyEnabled()
{
    CRITICAL_BLOCK(cs_socks5)
        return g_fSocks5Proxy;
    return false;
}

bool BtfTorProxyEnabled()
{
    CRITICAL_BLOCK(cs_socks5)
        return g_fSocks5Proxy && g_fTorProxy;
    return false;
}

std::string BtfSocks5ProxyName()
{
    CRITICAL_BLOCK(cs_socks5)
    {
        if (!g_fSocks5Proxy)
            return "";
        if (g_socks5Host.find(':') != std::string::npos)
            return strprintf("[%s]:%u", g_socks5Host.c_str(), (unsigned)g_socks5Port);
        return strprintf("%s:%u", g_socks5Host.c_str(), (unsigned)g_socks5Port);
    }
    return "";
}

static SOCKET ConnectDirect(const std::string& host, unsigned short port,
                            int nSockSite, int nTimeoutSecs)
{
    struct addrinfo hints, *res = NULL, *rp = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    sprintf(portstr, "%u", (unsigned)port);
    if (getaddrinfo(host.c_str(), portstr, &hints, &res) != 0 || !res)
        return INVALID_SOCKET;

    SOCKET s = INVALID_SOCKET;
    for (rp = res; rp != NULL; rp = rp->ai_next)
    {
        s = BtfSocketTag(socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol), nSockSite);
        if (s == INVALID_SOCKET)
            continue;
        SetSocketTimeout(s, nTimeoutSecs);
        if (connect(s, rp->ai_addr, (int)rp->ai_addrlen) == 0)
            break;
        BtfCloseSocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return s;
}

static bool Socks5Connect(SOCKET s, const std::string& destHost,
                          unsigned short destPort)
{
    if (destHost.empty() || destHost.size() > 255)
        return false;

    unsigned char hello[3] = { 0x05, 0x01, 0x00 }; // SOCKS5, one method, no auth
    if (!WriteN(s, hello, sizeof(hello)))
    {
        error("SOCKS5 hello write failed for %s:%u\n",
              destHost.c_str(), (unsigned)destPort);
        return false;
    }
    unsigned char choice[2] = { 0, 0 };
    if (!ReadN(s, choice, sizeof(choice)))
    {
        error("SOCKS5 method selection read failed for %s:%u\n",
              destHost.c_str(), (unsigned)destPort);
        return false;
    }
    if (choice[0] != 0x05 || choice[1] != 0x00)
    {
        error("SOCKS5 proxy rejected no-auth method for %s:%u (version=0x%02x method=0x%02x)\n",
              destHost.c_str(), (unsigned)destPort,
              (unsigned)choice[0], (unsigned)choice[1]);
        return false;
    }

    std::vector<unsigned char> req;
    req.reserve(7 + destHost.size());
    req.push_back(0x05); // version
    req.push_back(0x01); // CONNECT
    req.push_back(0x00); // reserved
    req.push_back(0x03); // domain name; proxy resolves, avoiding local DNS leak
    req.push_back((unsigned char)destHost.size());
    req.insert(req.end(), destHost.begin(), destHost.end());
    req.push_back((unsigned char)(destPort >> 8));
    req.push_back((unsigned char)(destPort & 0xff));
    if (!WriteN(s, &req[0], (int)req.size()))
    {
        error("SOCKS5 CONNECT request write failed for %s:%u\n",
              destHost.c_str(), (unsigned)destPort);
        return false;
    }

    unsigned char rep[4] = {0,0,0,0};
    if (!ReadN(s, rep, sizeof(rep)))
    {
        error("SOCKS5 CONNECT reply read failed for %s:%u\n",
              destHost.c_str(), (unsigned)destPort);
        return false;
    }
    if (rep[0] != 0x05)
    {
        error("SOCKS5 CONNECT reply has invalid version 0x%02x for %s:%u\n",
              (unsigned)rep[0], destHost.c_str(), (unsigned)destPort);
        return false;
    }
    if (rep[1] != 0x00)
    {
        error("SOCKS5 CONNECT to %s:%u failed with reply 0x%02x\n",
              destHost.c_str(), (unsigned)destPort, (unsigned)rep[1]);
        return false;
    }
    int nAddr = 0;
    if (rep[3] == 0x01) nAddr = 4;
    else if (rep[3] == 0x04) nAddr = 16;
    else if (rep[3] == 0x03)
    {
        unsigned char len = 0;
        if (!ReadN(s, &len, 1))
            return false;
        nAddr = len;
    }
    else
    {
        error("SOCKS5 CONNECT reply has invalid address type 0x%02x for %s:%u\n",
              (unsigned)rep[3], destHost.c_str(), (unsigned)destPort);
        return false;
    }

    std::vector<unsigned char> discard(nAddr + 2);
    if (!ReadN(s, &discard[0], (int)discard.size()))
    {
        error("SOCKS5 CONNECT bind address read failed for %s:%u\n",
              destHost.c_str(), (unsigned)destPort);
        return false;
    }
    return true;
}

SOCKET BtfConnectSocket(const std::string& destHost, unsigned short destPort,
                        int nSockSite, int nTimeoutSecs)
{
    std::string proxyHost;
    unsigned short proxyPort = 0;
    bool fProxy = false;
    bool fTorProxy = false;
    CRITICAL_BLOCK(cs_socks5)
    {
        fProxy = g_fSocks5Proxy;
        fTorProxy = g_fTorProxy;
        proxyHost = g_socks5Host;
        proxyPort = g_socks5Port;
    }

    if (!fProxy)
    {
        if (BtfIsTorOnionHost(destHost))
        {
            error("Refusing direct .onion connection to %s:%u; use /tor or /socks\n",
                  destHost.c_str(), (unsigned)destPort);
            return INVALID_SOCKET;
        }
        return ConnectDirect(destHost, destPort, nSockSite, nTimeoutSecs);
    }

    if (fTorProxy && nTimeoutSecs > 0 && nTimeoutSecs < TOR_CONNECT_TIMEOUT_SECS)
        nTimeoutSecs = TOR_CONNECT_TIMEOUT_SECS;

    SOCKET s = ConnectDirect(proxyHost, proxyPort, nSockSite, nTimeoutSecs);
    if (s == INVALID_SOCKET)
        return INVALID_SOCKET;
    if (!Socks5Connect(s, destHost, destPort))
    {
        BtfCloseSocket(s);
        return INVALID_SOCKET;
    }
    return s;
}
