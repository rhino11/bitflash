// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Bitflash rendezvous transport. See btfrv.h.
// Windows/Winsock implementation (Layer 6 will #ifdef this for Linux/BSD sockets).

#include "btfrv.h"

// Portable sockets: Winsock on Windows, BSD sockets on Linux/POSIX (for the
// headless relay `bitflashd` that runs on the VPS).
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define CLOSESOCK BtfCloseSocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <csignal>
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define CLOSESOCK BtfCloseSocket
#ifndef SD_BOTH
#define SD_BOTH SHUT_RDWR
#endif
#endif

#include "sockcount.h"

#include <cstring>
#include <cstdio>
#include <string>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>

namespace btf
{

static std::atomic<bool> g_stop(false);
static SOCKET            g_listen = INVALID_SOCKET;

// Services that have registered and are waiting for a client, keyed by pubkey.
static std::map<std::string, SOCKET> g_waiting;
static std::mutex                    g_mtx;

bool RvInit()
{
    static bool done = false;
    if (done) return true;
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
#else
    signal(SIGPIPE, SIG_IGN); // don't die when writing to a closed peer
#endif
    done = true;
    return true;
}

// ---- low-level helpers ----

static bool ReadN(SOCKET s, void* buf, int n)
{
    char* p = (char*)buf;
    int off = 0;
    while (off < n)
    {
        int r = recv(s, p + off, n - off, 0);
        if (r <= 0) return false;
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
        int r = send(s, p + off, n - off, 0);
        if (r <= 0) return false;
        off += r;
    }
    return true;
}

static SOCKET ConnectTo(const char* host, unsigned short port)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16]; sprintf(portstr, "%u", (unsigned)port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return INVALID_SOCKET;
    SOCKET s = BtfSocketTag(socket(res->ai_family, res->ai_socktype, res->ai_protocol), SOCK_RV_DIAL);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return INVALID_SOCKET; }

    // Apply a short timeout only for the connect() and initial handshake so an
    // unresponsive relay doesn't block the thread. Once the tunnel is live the
    // timeout is cleared -- a forwarding pipe must block indefinitely on recv().
#ifdef _WIN32
    DWORD tvShort = 10000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tvShort, sizeof(tvShort));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tvShort, sizeof(tvShort));
#else
    struct timeval tvShort; tvShort.tv_sec = 10; tvShort.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tvShort, sizeof(tvShort));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tvShort, sizeof(tvShort));
#endif

    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0)
    {
        CLOSESOCK(s); freeaddrinfo(res); return INVALID_SOCKET;
    }
    freeaddrinfo(res);

    // Clear the timeout -- the socket is now a live tunnel and must not
    // time out when idle. recv() will block until data arrives or peer closes.
#ifdef _WIN32
    DWORD tvOff = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tvOff, sizeof(tvOff));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tvOff, sizeof(tvOff));
#else
    struct timeval tvOff; tvOff.tv_sec = 0; tvOff.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tvOff, sizeof(tvOff));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tvOff, sizeof(tvOff));
#endif

    return s;
}

// ---- relay side ----

// Pump bytes from `from` to `to`. Owns closing `from`; shuts down `to` on exit
// so the peer-direction thread unblocks and closes its own socket exactly once.
static void Forward(SOCKET from, SOCKET to)
{
    char buf[32 * 1024];
    for (;;)
    {
        int r = recv(from, buf, sizeof(buf), 0);
        if (r <= 0) break;
        if (!WriteN(to, buf, r)) break;
    }
    shutdown(to, SD_BOTH);
    CLOSESOCK(from);
}

static void HandleIncoming(SOCKET s)
{
    unsigned char hdr[33];
    if (!ReadN(s, hdr, 33)) { CLOSESOCK(s); return; }
    char role = (char)hdr[0];
    std::string pubkey((char*)hdr + 1, 32);

    if (role == 'S')
    {
        // Register and wait; a future client will pair us.
        std::lock_guard<std::mutex> lk(g_mtx);
        // If a stale service for this key exists, drop it.
        std::map<std::string, SOCKET>::iterator it = g_waiting.find(pubkey);
        if (it != g_waiting.end()) CLOSESOCK(it->second);
        g_waiting[pubkey] = s;
        // leave the socket open in the map; do not close here.
    }
    else if (role == 'C')
    {
        SOCKET svc = INVALID_SOCKET;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            std::map<std::string, SOCKET>::iterator it = g_waiting.find(pubkey);
            if (it != g_waiting.end()) { svc = it->second; g_waiting.erase(it); }
        }
        if (svc == INVALID_SOCKET)
        {
            unsigned char no = 0x00;
            WriteN(s, &no, 1);
            CLOSESOCK(s);
            return;
        }
        // Pair: tell both sides, then forward raw bytes bidirectionally.
        unsigned char ok = 0x01;
        bool a = WriteN(svc, &ok, 1);
        bool b = WriteN(s, &ok, 1);
        if (!a || !b) { CLOSESOCK(svc); CLOSESOCK(s); return; }
        std::thread(Forward, s, svc).detach();
        std::thread(Forward, svc, s).detach();
    }
    else
    {
        CLOSESOCK(s);
    }
}

bool RvRelayRun(unsigned short port)
{
    if (!RvInit()) return false;
    g_stop = false;

    g_listen = BtfSocketTag(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), SOCK_RV_LISTEN);
    if (g_listen == INVALID_SOCKET) return false;
    int yes = 1;
    setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(g_listen, (struct sockaddr*)&addr, sizeof(addr)) != 0) { CLOSESOCK(g_listen); return false; }
    if (listen(g_listen, 16) != 0) { CLOSESOCK(g_listen); return false; }

    while (!g_stop)
    {
        struct sockaddr_in cli;
        socklen_t len = sizeof(cli);
        SOCKET s = BtfSocketTag(accept(g_listen, (struct sockaddr*)&cli, &len), SOCK_RV_ACCEPT);
        if (s == INVALID_SOCKET)
        {
            if (g_stop) break;
            continue;
        }
        std::thread(HandleIncoming, s).detach();
    }
    CLOSESOCK(g_listen);
    g_listen = INVALID_SOCKET;
    return true;
}

void RvRelayStop()
{
    g_stop = true;
    if (g_listen != INVALID_SOCKET)
        CLOSESOCK(g_listen); // unblock accept()
}

// ---- service / client helpers ----

RvSocket RvServiceRegister(const char* relay_host, unsigned short port,
                           const unsigned char my_pubkey[32])
{
    if (!RvInit()) return RV_INVALID;
    SOCKET s = ConnectTo(relay_host, port);
    if (s == INVALID_SOCKET) return RV_INVALID;
    unsigned char hdr[33];
    hdr[0] = (unsigned char)'S';
    memcpy(hdr + 1, my_pubkey, 32);
    if (!WriteN(s, hdr, 33)) { CLOSESOCK(s); return RV_INVALID; }
    // Return here: registered, not yet paired. The relay lists the service as
    // soon as it reads this header. The 0x01 that used to be consumed below
    // only arrives when somebody dials us, so blocking on it made "registered"
    // and "already in use" indistinguishable to the caller -- and left the node
    // unable to advertise a meeting node until after it had been reached there.
    return (RvSocket)s;
}

bool RvServiceWaitPaired(RvSocket s, int nTimeoutSecs)
{
    // A registration socket is idle on purpose -- we announce ourselves and
    // wait, possibly for a long time, for someone to dial. ConnectTo() clears
    // the socket timeout for exactly that reason, and with no timeout at all
    // this recv() has no way to end when the path dies without either side
    // saying so: a NAT drops the idle mapping, a relay restarts, a route
    // changes. No FIN arrives, nothing is readable, and the call never
    // returns. The thread stays alive and asleep, so ThreadBtfAccept never
    // reaches the `continue` that would register again, and the node goes deaf
    // while every outward sign says it is healthy.
    //
    // Seen in production on the bootstrap seed: 27 minutes without a block,
    // eight behind the network, relay reachable throughout, fixed instantly by
    // a restart.
    //
    // TCP keepalive is the obvious answer and it does not work here -- I
    // measured it. With probes every 5s and a 2-probe limit, a socket whose
    // replies were being dropped was still ESTAB after four minutes, the probe
    // counter stuck at zero. So the timeout is ours to enforce, at the one
    // place that knows what waiting means.
    //
    // Expiring is not a failure. It costs one reconnect per interval and
    // returns the loop to a known state.
    if (nTimeoutSecs > 0)
    {
#ifdef _WIN32
        DWORD tv = (DWORD)nTimeoutSecs * 1000;
        setsockopt((SOCKET)s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
        struct timeval tv; tv.tv_sec = nTimeoutSecs; tv.tv_usec = 0;
        setsockopt((SOCKET)s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    }

    unsigned char paired = 0;
    bool fOk = ReadN((SOCKET)s, &paired, 1) && paired == 0x01;

    // Hand back a socket that blocks again: from here it is a data tunnel, and
    // a tunnel legitimately sits quiet between messages.
    if (fOk && nTimeoutSecs > 0)
    {
#ifdef _WIN32
        DWORD tvOff = 0;
        setsockopt((SOCKET)s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tvOff, sizeof(tvOff));
#else
        struct timeval tvOff; tvOff.tv_sec = 0; tvOff.tv_usec = 0;
        setsockopt((SOCKET)s, SOL_SOCKET, SO_RCVTIMEO, &tvOff, sizeof(tvOff));
#endif
    }
    return fOk;
}

RvSocket RvClientConnect(const char* relay_host, unsigned short port,
                         const unsigned char target_pubkey[32])
{
    if (!RvInit()) return RV_INVALID;
    SOCKET s = ConnectTo(relay_host, port);
    if (s == INVALID_SOCKET) return RV_INVALID;
    unsigned char hdr[33];
    hdr[0] = (unsigned char)'C';
    memcpy(hdr + 1, target_pubkey, 32);
    if (!WriteN(s, hdr, 33)) { CLOSESOCK(s); return RV_INVALID; }
    unsigned char paired = 0;
    if (!ReadN(s, &paired, 1) || paired != 0x01) { CLOSESOCK(s); return RV_INVALID; }
    return (RvSocket)s;
}

bool RvReadN(RvSocket s, void* buf, int n)  { return ReadN((SOCKET)s, buf, n); }
bool RvWriteN(RvSocket s, const void* buf, int n) { return WriteN((SOCKET)s, buf, n); }
void RvClose(RvSocket s) { if (s != RV_INVALID) CLOSESOCK((SOCKET)s); }

} // namespace btf
