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
// Watchdog policy: with no peer reached this long after managed Tor came
// up, and no bridges configured, restart Tor with the bundled bridges. A
// network that blocks Tor's public relays looks exactly like this from the
// inside. 0 disables (-notorfallback). Once on bridges, each rung of the
// ladder gets nTorBridgeRungSecs before the next transport is tried.
extern int nTorBridgeFallbackSecs;
extern int nTorBridgeRungSecs;
bool BtfTorBridgesConfigured();
// Tell the transport lookup where Tor lives before it is started (empty:
// the bundled one).
void BtfSetManagedTorPath(const std::string& torPath);
// Transport name (first token) of a bridge line, e.g. "obfs4" or "snowflake".
std::string BtfBridgeTransport(const std::string& bridgeLine);

// --- Censorship ladder ------------------------------------------------
// One rung = one transport family with its bundled bridge lines, read from
// pt_config.json beside the transports (Tor Browser's current list) or
// built in when the file is not there. Order: the ones that survive the
// most blocking first.
struct BtfBridgeRung
{
    std::string name;                 // "snowflake", "obfs4", "webtunnel", "meek"
    std::vector<std::string> lines;   // bridge lines
};
std::vector<BtfBridgeRung> BtfBundledBridgeRungs();
// PT binary for a transport name. lyrebird serves obfs4, meek_lite,
// webtunnel, scramblesuit and snowflake; snowflake-client is taken too.
bool BtfResolveTransportPath(const std::string& transport, std::string& pathOut);
// Bridge lines: "Bridge " prefix optional, '#' comments, blank lines skipped.
std::vector<std::string> BtfParseBridgeLines(const std::string& text);
// The user's own bridges, bridges.txt in the data directory.
std::string BtfUserBridgesPath();
std::vector<std::string> BtfLoadUserBridges();
bool BtfSaveUserBridges(const std::string& text, std::string& errOut);
// Configure bridges from lines and name the mode ("user" or a rung name).
// False with errOut when a transport binary is missing or no line is usable.
bool BtfConfigureBridges(const std::vector<std::string>& lines, const std::string& mode,
                         std::string& errOut);
// What Tor goes through now: "direct", "your bridges", or a rung name.
std::string BtfTorTransportMode();
// The mode that reached the network last time, remembered in the data
// directory ("" when nothing is remembered). Cleared when direct works.
std::string BtfLastWorkingTransport();
void BtfForgetLastWorkingTransport();
// Tor's own bootstrap, as last polled by the watchdog: percent and a line
// such as "25% Asking for networkstatus consensus".
int BtfManagedTorBootstrapPercent();
std::string BtfManagedTorBootstrapLine();
// Restart managed Tor with bridges right now: the user's bridges.txt when
// it has lines, else the next rung of the ladder.
bool BtfTryBridgesNow(std::string& errOut);
// The GUI's switch for the fallback, kept as managed-tor/no-fallback so it
// survives restarts without touching the wallet database.
bool BtfTorFallbackDisabledByFile();
void BtfSetTorFallbackEnabled(bool fEnabled);

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
