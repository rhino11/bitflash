// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Portable socket handle type shared by the pool server and the .btf peer
// dialers. It used to live in btftunnel.h; that module (the rendezvous tunnel)
// is gone now that peers and pools are reached only over Tor onion services, so
// the type moved here where it has no dependency on the removed transport.

#ifndef BITFLASH_BTFSOCK_H
#define BITFLASH_BTFSOCK_H

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <winsock2.h>
typedef SOCKET btf_socket_t;
#else
typedef int btf_socket_t;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#endif

#endif
