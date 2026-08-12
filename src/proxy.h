// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Optional SOCKS5 outbound proxy support. This is transport plumbing only:
// no consensus, wallet, mining, or .btf identity data depends on it.

#ifndef BITFLASH_PROXY_H
#define BITFLASH_PROXY_H

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <winsock2.h>
#else
#include "compat.h"
#endif

#include <string>

bool BtfParseSocks5Proxy(const std::string& spec, std::string& hostOut,
                         unsigned short& portOut, std::string& errOut);
bool BtfSetSocks5Proxy(const std::string& spec, std::string& errOut);
bool BtfEnableTorProxy(const std::string& spec, std::string& errOut);
void BtfClearSocks5Proxy();
bool BtfSocks5ProxyEnabled();
bool BtfTorProxyEnabled();
bool BtfIsTorOnionHost(const std::string& host);
std::string BtfSocks5ProxyName();

SOCKET BtfConnectSocket(const std::string& destHost, unsigned short destPort,
                        int nSockSite, int nTimeoutSecs);

#endif
