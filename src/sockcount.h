// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Socket accounting -- which part of the program is holding the sockets.
//
// A node on a 32-core machine was found with 1502 sockets in Windows' "bound"
// state: created, never connected, never closed, each holding a distinct
// ephemeral port. That is 9% of the machine's whole dynamic port range gone in
// nineteen hours, and when the range runs out nothing on that machine can open
// an outbound connection -- not just this program.
//
// Reading the code did not find it. Every connect() failure path in this tree
// closes its socket. So count instead: tag each socket where it is created,
// untag it where it is closed, and report the difference per site. Whichever
// site's live count tracks the leak is the answer.
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
    // Why the close failed, counted per code per site. Measured on a node with
    // 3h51m of uptime: the program believed it held 58 sockets and Windows
    // attributed 112 to the process, 47 of them bound to an ephemeral port and
    // never connected -- against 55 closes that had returned an error. The
    // shapes match, and the error code is the piece that says whether the
    // descriptor is still there or was already gone.
    std::map<int, long long> mapCloseErr[SOCK_SITES];
    long long nClosedUntagged;
    BtfSockAccount() : nClosedUntagged(0)
    {
        for (int i = 0; i < SOCK_SITES; i++) { nOpened[i] = 0; nClosed[i] = 0; nCloseFailed[i] = 0; }
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
inline void BtfSockSnapshot(long long* pOpened, long long* pClosed, long long* pFailed, long long* pUntagged)
{
    BtfSockAccount& a = BtfSockAccounting();
    std::lock_guard<std::mutex> lock(a.mtx);
    for (int i = 0; i < SOCK_SITES; i++)
    {
        pOpened[i] = a.nOpened[i];
        pClosed[i] = a.nClosed[i];
        pFailed[i] = a.nCloseFailed[i];
    }
    *pUntagged = a.nClosedUntagged;
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
