// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Transparent anonymous tunnel. See btftunnel.h.

#include "btftunnel.h"
#include "btfchan.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int SOCKET;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#define closesocket(s) ::close(s)
#ifndef SD_BOTH
#define SD_BOTH SHUT_RDWR
#endif
#endif
#include "sockcount.h"
#include <cstring>
#include <vector>
#include <thread>

namespace btf
{

bool TunnelInit()
{
    return RvInit() && ChanInit();
}

// Create a connected loopback socket pair (no socketpair() on Windows).
// Returns app end and pump end; both are ordinary full-duplex TCP sockets.
static bool MakeLocalPair(btf_socket_t& appEnd, btf_socket_t& pumpEnd)
{
    SOCKET listener = BtfSocketTag(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), SOCK_PAIR_LISTEN);
    if (listener == INVALID_SOCKET) return false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // ephemeral
    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) != 0) { BtfCloseSocket(listener); return false; }
    if (listen(listener, 1) != 0) { BtfCloseSocket(listener); return false; }

#ifdef _WIN32
    int len = sizeof(addr);
#else
    socklen_t len = sizeof(addr);
#endif
    if (getsockname(listener, (struct sockaddr*)&addr, &len) != 0) { BtfCloseSocket(listener); return false; }

    SOCKET a = BtfSocketTag(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), SOCK_PAIR_APP);
    if (a == INVALID_SOCKET) { BtfCloseSocket(listener); return false; }
    if (connect(a, (struct sockaddr*)&addr, sizeof(addr)) != 0) { BtfCloseSocket(a); BtfCloseSocket(listener); return false; }

    SOCKET b = BtfSocketTag(accept(listener, NULL, NULL), SOCK_PAIR_PUMP);
    BtfCloseSocket(listener);
    if (b == INVALID_SOCKET) { BtfCloseSocket(a); return false; }

    appEnd = a;
    pumpEnd = b;
    return true;
}

static bool SockReadN(SOCKET s, void* buf, int n)
{
    char* p = (char*)buf; int off = 0;
    while (off < n) { int r = recv(s, p + off, n - off, 0); if (r <= 0) return false; off += r; }
    return true;
}
static bool SockWriteN(SOCKET s, const void* buf, int n)
{
    const char* p = (const char*)buf; int off = 0;
    while (off < n) { int r = send(s, p + off, n - off, 0); if (r <= 0) return false; off += r; }
    return true;
}

// Outbound pump: plaintext from the app -> echan frame -> rendezvous socket.
static void PumpOut(SOCKET pumpEnd, RvSocket rv, std::vector<unsigned char> key)
{
    char buf[16 * 1024];
    for (;;)
    {
        int r = recv(pumpEnd, buf, sizeof(buf), 0);
        if (r <= 0) break;
        std::vector<unsigned char> frame = ChanEncryptFrame(key.data(), (const unsigned char*)buf, r);
        if (!RvWriteN(rv, frame.data(), (int)frame.size())) break;
    }
    // Tear down: unblock the inbound pump and the app.
    shutdown((SOCKET)rv, SD_BOTH);
    shutdown(pumpEnd, SD_BOTH);
}

// Inbound pump: echan frames from the rendezvous socket -> plaintext to the app.
static void PumpIn(SOCKET pumpEnd, RvSocket rv, std::vector<unsigned char> key)
{
    for (;;)
    {
        unsigned char len[4];
        if (!RvReadN(rv, len, 4)) break;
        size_t n = ((size_t)len[0]<<24)|((size_t)len[1]<<16)|((size_t)len[2]<<8)|len[3];
        if (n < (size_t)(CHAN_NONCEBYTES + CHAN_MACBYTES) || n > (1u<<20)) break;
        std::vector<unsigned char> body(n);
        if (!RvReadN(rv, body.data(), (int)n)) break;
        std::vector<unsigned char> pt;
        if (!ChanDecryptBody(key.data(), body.data(), (int)n, pt)) break; // auth fail -> drop
        if (!pt.empty() && !SockWriteN(pumpEnd, pt.data(), (int)pt.size())) break;
    }
    shutdown(pumpEnd, SD_BOTH);
    shutdown((SOCKET)rv, SD_BOTH);
}

// Start the two pumps and hand back the app-facing socket. When both pumps
// finish, close the pump end and the rendezvous socket.
static btf_socket_t StartTunnel(RvSocket rv, const unsigned char shared[32])
{
    btf_socket_t appEnd, pumpEnd;
    if (!MakeLocalPair(appEnd, pumpEnd)) { RvClose(rv); return INVALID_SOCKET; }

    std::vector<unsigned char> key(shared, shared + 32);
    std::thread(PumpOut, pumpEnd, rv, key).detach();
    std::thread([pumpEnd, rv, key]() {
        PumpIn(pumpEnd, rv, key);
        BtfCloseSocket(pumpEnd);
        RvClose(rv);
    }).detach();
    return appEnd;
}

btf_socket_t BtfClientTunnel(const char* meeting_host, unsigned short port,
                             const unsigned char target_pubkey[32],
                             const unsigned char service_enc_pub[32])
{
    if (!TunnelInit()) return INVALID_SOCKET;
    RvSocket rv = RvClientConnect(meeting_host, port, target_pubkey);
    if (rv == RV_INVALID) return INVALID_SOCKET;

    unsigned char eph_pub[32], shared[32];
    if (!ChanClientHandshake(service_enc_pub, eph_pub, shared)) { RvClose(rv); return INVALID_SOCKET; }
    if (!RvWriteN(rv, eph_pub, 32)) { RvClose(rv); return INVALID_SOCKET; }
    return StartTunnel(rv, shared);
}

btf_socket_t BtfServiceWrap(RvSocket rv, const unsigned char my_enc_sk[32])
{
    if (!TunnelInit()) { RvClose(rv); return INVALID_SOCKET; }
    unsigned char eph_pub[32], shared[32];
    if (!RvReadN(rv, eph_pub, 32)) { RvClose(rv); return INVALID_SOCKET; }
    if (!ChanEndpointHandshake(eph_pub, my_enc_sk, shared)) { RvClose(rv); return INVALID_SOCKET; }
    return StartTunnel(rv, shared);
}

} // namespace btf
