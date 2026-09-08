// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Managed Tor process support. This is transport bootstrapping only: it does
// not touch consensus, wallet keys, mining, or the .btf identity.

#ifndef BITFLASH_TOR_H
#define BITFLASH_TOR_H

#include <string>
#include <vector>

bool BtfStartManagedTor(const std::string& torPathOpt, std::string& errOut);
void BtfStopManagedTor();
bool BtfManagedTorEnabled();
std::string BtfManagedTorStatus();
bool BtfBundledTorPath(std::string& torPathOut);

// Pluggable transports (obfs4/snowflake bridges) for reaching Tor where plain
// Tor is blocked. Set before BtfStartManagedTor; empty ptExecPath or empty
// bridges leaves managed Tor on direct connections. Transport only.
void BtfSetTorBridges(const std::string& ptExecPath,
                      const std::vector<std::string>& bridges);
// Locate the obfs4/snowflake pluggable-transport binary (bundled or on PATH).
bool BtfResolveObfs4Path(std::string& pathOut);
// Built-in obfs4 bridge lines used by -torbridges when none are given.
std::vector<std::string> BtfDefaultObfs4Bridges();

std::string BtfBuildManagedTorrcForTest(const std::string& dataDir,
                                        const std::string& hiddenServiceDir,
                                        unsigned short socksPort,
                                        unsigned short controlPort,
                                        unsigned short p2pPort,
                                        const std::string& obfs4ExecPath = "",
                                        const std::vector<std::string>& bridges =
                                            std::vector<std::string>());

#endif
