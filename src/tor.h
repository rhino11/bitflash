// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Managed Tor process support. This is transport bootstrapping only: it does
// not touch consensus, wallet keys, mining, or the .btf identity.

#ifndef BITFLASH_TOR_H
#define BITFLASH_TOR_H

#include <string>
#include <vector>
#include <map>

bool BtfStartManagedTor(const std::string& torPathOpt, std::string& errOut);
void BtfStopManagedTor();
bool BtfManagedTorEnabled();
std::string BtfManagedTorStatus();
bool BtfBundledTorPath(std::string& torPathOut);

// Pluggable transports (obfs4/snowflake bridges) for reaching Tor where plain
// Tor is blocked. Set before BtfStartManagedTor; empty bridges leaves managed
// Tor on direct connections. ptExecByTransport maps a transport name
// ("obfs4"/"snowflake") to its PT binary. Transport only, no consensus/wallet.
void BtfSetTorBridges(const std::vector<std::string>& bridges,
                      const std::map<std::string, std::string>& ptExecByTransport);
// Locate the obfs4 / snowflake pluggable-transport binaries (bundled or PATH).
bool BtfResolveObfs4Path(std::string& pathOut);
bool BtfResolveSnowflakePath(std::string& pathOut);
// Built-in bridge lines used by -torbridges: the standard Snowflake bridge,
// which needs no infrastructure of ours and no curation.
std::vector<std::string> BtfDefaultBridges();
// Transport name (first token) of a bridge line, e.g. "obfs4" or "snowflake".
std::string BtfBridgeTransport(const std::string& bridgeLine);

std::string BtfBuildManagedTorrcForTest(const std::string& dataDir,
                                        const std::string& hiddenServiceDir,
                                        unsigned short socksPort,
                                        unsigned short controlPort,
                                        unsigned short p2pPort,
                                        const std::vector<std::string>& bridges =
                                            std::vector<std::string>(),
                                        const std::map<std::string, std::string>& ptExecByTransport =
                                            std::map<std::string, std::string>());

#endif
