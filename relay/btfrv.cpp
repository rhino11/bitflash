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
#define CLOSESOCK closesocket
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
#define CLOSESOCK ::close
#ifndef SD_BOTH
#define SD_BOTH SHUT_RDWR
#endif
#endif

#include <cstring>
#include <cstdio>
#include <string>
#include <deque>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>

namespace btf
{

static std::atomic<bool> g_stop(false);
static SOCKET            g_listen = INVALID_SOCKET;

// Services that have registered and are waiting for a client, keyed by pubkey.
// More than one registration per node, on purpose.
//
// This used to be one socket per pubkey, and a dial *consumed* it: the first
// caller took the registration and everyone else was told "not found" until the
// node noticed and registered again. A node re-registers only after its pairing
// has been handed off, so between the two there is a window where it is
// unreachable to the whole network. Measured from a node's own counters: half
// of all outbound dials failed that way -- 15 of 30 in eleven minutes -- while
// descriptors resolved 53 times out of 54 and the node's own registrations
// paired 11 times out of 12. The rendezvous was not losing anybody; it was
// letting one caller in at a time.
//
// A queue per key lets a node keep spare registrations parked, so a dial that
// arrives while another is being paired finds the next one instead of a closed
// door. Old nodes register exactly as before and simply keep one entry: the
// wire protocol does not change, so a relay running this serves both.
static const size_t MAX_WAITING_PER_KEY = 4;
static std::map<std::string, std::deque<SOCKET> > g_waiting;
static std::mutex                    g_mtx;

// How often the reaper walks the waiting map.
static const int REAP_INTERVAL_SECS = 60;

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
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return INVALID_SOCKET; }
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0)
    {
        CLOSESOCK(s); freeaddrinfo(res); return INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return s;
}

// ---- liveness of a waiting registration ----

// True when the far end of a registration socket is provably gone.
//
// A registered service sends nothing while it waits, so the socket should never
// be readable. Readable therefore means one of two things, and recv tells them
// apart: 0 is a clean close, negative is an error, and either way the
// registration is worthless. Anything else -- including a service that somehow
// has data pending -- is left alone, because guessing wrong here unregisters a
// node that is perfectly fine.
//
// select() rather than MSG_DONTWAIT so the same code compiles on Windows, and
// so the socket's blocking mode is never touched.
static bool RegistrationDead(SOCKET s)
{
    fd_set rd;
    FD_ZERO(&rd);
    FD_SET(s, &rd);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    int r = select((int)(s + 1), &rd, NULL, NULL, &tv);
    if (r <= 0)
        return false;               // not readable: still waiting, healthy
    char c;
    int n = recv(s, &c, 1, MSG_PEEK);
    return (n <= 0);
}

// Drop registrations whose far end has gone away.
//
// Deliberately no expiry by age. Nodes older than v1.2.7 register once and then
// block forever waiting to be dialled -- they never re-register, so a clock
// based rule would quietly make every one of them unreachable, and being
// blocked in recv they would never find out. Only provable death counts.
static void ReapDeadRegistrations()
{
    int nBefore = 0, nReaped = 0;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        std::map<std::string, std::deque<SOCKET> >::iterator it = g_waiting.begin();
        while (it != g_waiting.end())
        {
            std::deque<SOCKET>& q = it->second;
            nBefore += (int)q.size();
            for (std::deque<SOCKET>::iterator jt = q.begin(); jt != q.end();)
            {
                if (RegistrationDead(*jt))
                {
                    CLOSESOCK(*jt);
                    jt = q.erase(jt);
                    nReaped++;
                }
                else
                    ++jt;
            }
            if (q.empty())
                g_waiting.erase(it++);
            else
                ++it;
        }
    }
    if (nReaped > 0)
        printf("reaper: dropped %d dead registration(s), %d waiting\n",
               nReaped, nBefore - nReaped);
    fflush(stdout);
}

static void ReaperThread()
{
    while (!g_stop)
    {
        for (int i = 0; i < REAP_INTERVAL_SECS && !g_stop; i++)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (g_stop) break;
        ReapDeadRegistrations();
    }
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
        std::deque<SOCKET>& q = g_waiting[pubkey];

        // Drop registrations this node has already lost the far end of, rather
        // than dropping the previous one on principle. The old code closed the
        // prior registration on every new one, which is why a node could never
        // hold a spare.
        for (std::deque<SOCKET>::iterator it = q.begin(); it != q.end();)
        {
            if (RegistrationDead(*it)) { CLOSESOCK(*it); it = q.erase(it); }
            else ++it;
        }

        // A ceiling, because a stranger can open these. Oldest goes first: it
        // is the one most likely to be stale.
        while (q.size() >= MAX_WAITING_PER_KEY)
        {
            CLOSESOCK(q.front());
            q.pop_front();
        }
        q.push_back(s);
        // leave the socket open in the queue; do not close here.
    }
    else if (role == 'C')
    {
        SOCKET svc = INVALID_SOCKET;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            std::map<std::string, std::deque<SOCKET> >::iterator it = g_waiting.find(pubkey);
            if (it != g_waiting.end())
            {
                std::deque<SOCKET>& q = it->second;
                // Take the oldest one that is still alive, discarding the dead
                // as we go. Checking before handing it over matters: pairing a
                // client with a dead registration produces a tunnel that fails
                // after both sides think they succeeded, which is the failure
                // the dialling node reports as "tunnel to X failed" with
                // nothing to explain it.
                while (!q.empty())
                {
                    SOCKET candidate = q.front();
                    q.pop_front();
                    if (RegistrationDead(candidate))
                    {
                        CLOSESOCK(candidate);
                        continue;
                    }
                    svc = candidate;
                    break;
                }
                if (q.empty())
                    g_waiting.erase(it);
            }
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

    g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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

    std::thread(ReaperThread).detach();

    while (!g_stop)
    {
        struct sockaddr_in cli;
        socklen_t len = sizeof(cli);
        SOCKET s = accept(g_listen, (struct sockaddr*)&cli, &len);
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
    unsigned char paired = 0;
    if (!ReadN(s, &paired, 1) || paired != 0x01) { CLOSESOCK(s); return RV_INVALID; }
    return (RvSocket)s;
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
