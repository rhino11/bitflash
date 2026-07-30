// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Bitflash rendezvous transport -- the "meeting node" that lets two nodes behind
// CGNAT connect without a public IP or port forwarding. Both sides connect OUT
// to the relay (which HAS a public IP, e.g. the VPS); the relay pairs them by
// `.btf` pubkey and forwards raw bytes between them. The endpoints then run the
// echan end-to-end channel on top, so the relay sees only ciphertext and cannot
// MITM (the client boxes to the service's STATIC key from its self-certified
// descriptor -- a substituting relay just breaks the channel, never reads it).
//
// This is the server that runs on the VPS (headless, Layer 6 ports it to Linux)
// plus the client/service helpers the desktop node uses.

#ifndef BITFLASH_BTFRV_H
#define BITFLASH_BTFRV_H

#include <stdint.h>

namespace btf
{

// A connected, paired rendezvous socket (opaque). Read/write raw bytes; the
// caller layers echan on top. Close with RvClose.
typedef intptr_t RvSocket;
static const RvSocket RV_INVALID = (RvSocket)-1;

// Initialize sockets (Winsock on Windows). Idempotent.
bool RvInit();

// ---- relay side (runs on the VPS) ----
// Run the rendezvous relay forever on `port`, forwarding between paired peers.
// Blocks; run it in a thread. Returns false if it can't bind/listen.
bool RvRelayRun(unsigned short port);

// Stop a running relay (signals RvRelayRun to return).
void RvRelayStop();

// ---- service side (the node being reached by its .btf address) ----
// Register at the relay under `my_pubkey` (32 bytes). Returns as soon as the
// relay has us listed, WITHOUT waiting for anyone to dial -- the caller needs
// that moment to start advertising this relay as its meeting node. Waiting for
// the dial was folded into this call before, which deadlocked discovery: a node
// could not be advertised until it had been dialled, and could not be dialled
// until it was advertised. Returns RV_INVALID on error.
RvSocket RvServiceRegister(const char* relay_host, unsigned short port,
                           const unsigned char my_pubkey[32]);

// Block on a registered service socket until a client is paired to us. Returns
// false if the relay drops us or errors, in which case the caller should close
// the socket and register again.
// Blocks until a client is paired with us. Give it a timeout, in seconds, and
// it returns false once that passes with nobody arriving -- which the caller
// should treat as "register again", not as an error. Zero means wait forever,
// which is what this used to do unconditionally and must not be used for a
// registration socket: see the note on the implementation.
bool RvServiceWaitPaired(RvSocket s, int nTimeoutSecs = 0);

// ---- client side (the node dialing a .btf address) ----
// Connect through the relay to the service registered under `target_pubkey`.
// Returns the paired socket, or RV_INVALID on error.
RvSocket RvClientConnect(const char* relay_host, unsigned short port,
                         const unsigned char target_pubkey[32]);

// Blocking read/write of exactly n bytes over a rendezvous socket. Return false
// on error/EOF.
bool RvReadN(RvSocket s, void* buf, int n);
bool RvWriteN(RvSocket s, const void* buf, int n);
void RvClose(RvSocket s);

} // namespace btf

#endif
