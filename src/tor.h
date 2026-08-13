// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Managed Tor process support. This is transport bootstrapping only: it does
// not touch consensus, wallet keys, mining, or the .btf identity.

#ifndef BITFLASH_TOR_H
#define BITFLASH_TOR_H

#include <string>

bool BtfStartManagedTor(const std::string& torPathOpt, std::string& errOut);
void BtfStopManagedTor();
bool BtfManagedTorEnabled();
std::string BtfManagedTorStatus();
bool BtfBundledTorPath(std::string& torPathOut);

std::string BtfBuildManagedTorrcForTest(const std::string& dataDir,
                                        const std::string& hiddenServiceDir,
                                        unsigned short socksPort,
                                        unsigned short controlPort,
                                        unsigned short p2pPort);

#endif
