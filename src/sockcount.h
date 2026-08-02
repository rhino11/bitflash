// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Socket accounting -- which part of the program is holding the sockets.
//
// A node on a 32-core machine was found with 1502 sockets in Windows' "bound"
// state, each apparently holding a distinct ephemeral port. Reading the code
// did not find it: every connect() failure path in this tree closes its socket.
// So count instead -- tag each socket where it is created, untag it where it is
// closed, report the difference per site.
//
// The counting is what showed the counting was wrong. Windows lists a socket
// bound to the wildcard address TWICE in MSFT_NetTCPConnection: once for the
// binding (0.0.0.0:port, state "Bound") and once for the connection itself
// (state "Established"). Measured: 35 of a node's 38 "Bound" rows had the same
// local port as one of its established connections. The bound count therefore
// rises because the node is talking to more peers, not because it is leaking,
// which is why a fix that plainly worked looked like it had done nothing.
//
// The honest metric is the ORPHAN: a "Bound" row whose port appears nowhere
// else in that process's table.
//
//   $b = $c | ? State -eq 'Bound'
//   $rest = ($c | ? State -ne 'Bound').LocalPort
//   ($b | ? { $rest -notcontains $_.LocalPort }).Count
//
// By that metric, measured the same evening on three machines: a node on 1.2.10
// with 26h of uptime had 1262 orphans and was still taking on 30-90 an hour; a
// node on 1.2.11 with 4h40m had 3; a node on 1.2.12 had 3, all from its first
// half minute. At the 1.2.10 rate the 1.2.11 node would have had ~230.
//
// So the leak was real and 1.2.11 ended it -- most likely the 60-second reaper
// for undeliverable nodes, which was written for a different problem. The
// counters below stay: they are how the question got answered, and they are how
// it would be answered again.
//
// Header-only on purpose. btfrv.cpp is compiled a second time, on its own, into
// the standalone rendezvous relay -- a separate tree that does not link net.cpp.
// Anything here that needed a .cpp would break that build, and it would break
// it on the VPS rather than on this machine. Include after the platform socket
// headers; each of those files defines SOCKET for itself.

#ifndef BITFLASH_SOCKCOUNT_H
#define BITFLASH_SOCKCOUNT_H

#include <cerrno>
#include <map>
#include <mutex>

#ifndef _WIN32
#include <unistd.h>
#endif

enum
{
    SOCK_EXTIP,       // GetMyExternalIP probe
    SOCK_LISTEN,      // the node's own listening socket
    SOCK_ACCEPT,      // inbound connections
    SOCK_RV_DIAL,     // outbound to a rendezvous relay
    SOCK_RV_LISTEN,   // rendezvous listener
    SOCK_RV_ACCEPT,   // inbound at the rendezvous
    SOCK_PAIR_LISTEN, // loopback pair: the temporary listener
    SOCK_PAIR_APP,    // loopback pair: the app end handed to CNode
    SOCK_PAIR_PUMP,   // loopback pair: the pump end
    SOCK_NOSTR,       // outbound to a Nostr relay
    SOCK_SITES
};

struct BtfSockAccount
{
    std::mutex mtx;
    std::map<SOCKET, int> mapSite;
    long long nOpened[SOCK_SITES];
    long long nClosed[SOCK_SITES];
    long long nCloseFailed[SOCK_SITES];
    // Why the close failed, counted per code per site. Kept because nothing in
    // this codebase had ever looked at what closesocket returns, and a close
    // that fails leaves the descriptor and its port in place. It is not the
    // leak -- see the note at the top of this file -- but it is the one number
    // that would say so if it ever became the leak.
    std::map<int, long long> mapCloseErr[SOCK_SITES];
    // A handle number arriving from socket()/accept() while some site still
    // claims it. The operating system only hands a number back out after the
    // last close of it, so a collision means somebody's bookkeeping outlived
    // its socket -- and whoever still believes they own that number will
    // eventually close it, taking down a connection that now belongs to
    // someone else. Counted against the site that was still holding it, which
    // is the one to go and read.
    long long nCollided[SOCK_SITES];
    long long nClosedUntagged;
    BtfSockAccount() : nClosedUntagged(0)
    {
        for (int i = 0; i < SOCK_SITES; i++) { nOpened[i] = 0; nClosed[i] = 0; nCloseFailed[i] = 0; nCollided[i] = 0; }
    }
};

// One instance across every translation unit: a function-local static in an
// inline function is the same object everywhere it is used.
inline BtfSockAccount& BtfSockAccounting()
{
    static BtfSockAccount account;
    return account;
}

// Record a freshly created socket and return it unchanged, so call sites read
// as they did before. INVALID_SOCKET passes through untouched.
inline SOCKET BtfSocketTag(SOCKET hSocket, int nSite)
{
    if (hSocket == INVALID_SOCKET || nSite < 0 || nSite >= SOCK_SITES)
        return hSocket;
    BtfSockAccount& a = BtfSockAccounting();
    std::lock_guard<std::mutex> lock(a.mtx);
    std::map<SOCKET, int>::iterator mi = a.mapSite.find(hSocket);
    if (mi != a.mapSite.end())
        a.nCollided[mi->second]++;
    a.mapSite[hSocket] = nSite;
    a.nOpened[nSite]++;
    return hSocket;
}

// Close a socket and forget it. Closing one nobody tagged is counted too --
// that number staying at zero is what says the accounting is complete.
inline int BtfCloseSocket(SOCKET hSocket)
{
    if (hSocket == INVALID_SOCKET)
        return 0;
    int nSite = -1;
    {
        BtfSockAccount& a = BtfSockAccounting();
        std::lock_guard<std::mutex> lock(a.mtx);
        std::map<SOCKET, int>::iterator mi = a.mapSite.find(hSocket);
        if (mi == a.mapSite.end())
            a.nClosedUntagged++;
        else
        {
            nSite = mi->second;
            a.nClosed[nSite]++;
            a.mapSite.erase(mi);
        }
    }
#ifdef _WIN32
    int nRet = ::closesocket(hSocket);
    int nErr = (nRet != 0) ? WSAGetLastError() : 0;
#else
    int nRet = ::close(hSocket);
    int nErr = (nRet != 0) ? errno : 0;
#endif
    // A close that fails leaves the descriptor -- and on Windows the ephemeral
    // port it holds -- in place. Counted because a socket the program believes
    // it released and the operating system still shows is exactly the shape of
    // the leak being chased, and nothing in this codebase has ever looked at
    // what closesocket returns.
    if (nRet != 0 && nSite >= 0)
    {
        BtfSockAccount& a = BtfSockAccounting();
        std::lock_guard<std::mutex> lock(a.mtx);
        a.nCloseFailed[nSite]++;
        a.mapCloseErr[nSite][nErr]++;
    }
    return nRet;
}

// Copy the counters out. Formatting lives in net.cpp, which has strprintf --
// and which the relay build does not compile.
inline void BtfSockSnapshot(long long* pOpened, long long* pClosed, long long* pFailed,
                            long long* pCollided, long long* pUntagged)
{
    BtfSockAccount& a = BtfSockAccounting();
    std::lock_guard<std::mutex> lock(a.mtx);
    for (int i = 0; i < SOCK_SITES; i++)
    {
        pOpened[i] = a.nOpened[i];
        pClosed[i] = a.nClosed[i];
        pFailed[i] = a.nCloseFailed[i];
        pCollided[i] = a.nCollided[i];
    }
    *pUntagged = a.nClosedUntagged;
}

// Of the sockets still tagged live, how many have no peer on the other end.
//
// This is the check that ended the socket hunt, by answering it with a zero.
// The suspicion was that some site created sockets, never connected them and
// never let go. Run against a live node it reports 1 -- the listening socket,
// which has no peer by definition. Every other tagged socket is connected.
//
// See the note at the top of this file for what the pile actually was.
inline void BtfSockLiveUnconnected(long long* pUnconnected)
{
    for (int i = 0; i < SOCK_SITES; i++)
        pUnconnected[i] = 0;
    BtfSockAccount& a = BtfSockAccounting();
    std::lock_guard<std::mutex> lock(a.mtx);
    for (std::map<SOCKET, int>::const_iterator mi = a.mapSite.begin(); mi != a.mapSite.end(); ++mi)
    {
        struct sockaddr_storage ss;
#ifdef _WIN32
        int len = sizeof(ss);
#else
        socklen_t len = sizeof(ss);
#endif
        if (getpeername(mi->first, (struct sockaddr*)&ss, &len) != 0)
            pUnconnected[mi->second]++;
    }
}

// The close-failure codes for one site, newest counts included. Separate call
// because the table above is fixed-width and this is a list of unknown length.
inline void BtfSockCloseErrors(int nSite, std::map<int, long long>& mapOut)
{
    mapOut.clear();
    if (nSite < 0 || nSite >= SOCK_SITES)
        return;
    BtfSockAccount& a = BtfSockAccounting();
    std::lock_guard<std::mutex> lock(a.mtx);
    mapOut = a.mapCloseErr[nSite];
}

#endif
