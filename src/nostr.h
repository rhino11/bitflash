// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Peer discovery over Nostr relays -- replaces the old ThreadIRCSeed. Each
// node publishes a replaceable event (NIP-78, kind 30078) containing its
// "ip:port", signed with Schnorr/secp256k1 (BIP340, the same scheme used by
// Nostr), and subscribes to receive the announcements of other nodes, feeding
// them into the Bitflash address manager.

#ifndef BITFLASH_NOSTR_H
#define BITFLASH_NOSTR_H

#include <string>
#include <vector>
#include <map>

// Thread entry point (signature compatible with _beginthread)
void ThreadNostrSeed(void* parg);
void ThreadBtfPoolAnnouncer(void* parg);

// Set to true to make ThreadBtfPoolAnnouncer publish immediately instead of
// waiting for its ~60s sleep loop (e.g. right after the operator changes pool
// name/fee/dashboard URL in Options). The announcer clears it after publishing.
extern volatile bool gAnnounceNow;

// Public relays used for discovery. Tunable.
extern const char* pszNostrRelays[];
extern const int nNostrRelays;

// Rendezvous meeting relays ("host:port") this node can register its .btf
// service at. It registers at the first reachable one and advertises that in
// its descriptor; if the relay dies it fails over to another, so attacking a
// single relay's IP can't take the network down. Overridable with /rvrelay.
extern std::vector<std::string> vBtfMeetingRelays;
// The relay this node is currently registered at (set by ThreadBtfAccept).
extern std::string strBtfActiveRelay;
// The relay we are registered at, or "" if registration hasn't succeeded yet.
// Never guesses a seed: an unregistered node has no meeting node to advertise.
std::string BtfActiveRelay();
// Record the relay this node just registered its service at (thread-safe).
void BtfSetActiveRelay(const std::string& relay);

// Optional Tor hidden-service endpoint for this node's normal P2P listener.
// Set by /onionservice=HOST.onion:PORT. The endpoint is signed into this node's
// .btf descriptor, so peers with -tor can dial it directly before falling back
// to rendezvous relays.
bool BtfSetLocalOnionEndpoint(const std::string& endpoint, std::string& errOut);
std::string BtfLocalOnionEndpoint();

// If set (via /announcerelay=host:port), this node announces that relay on
// Nostr so other nodes discover it automatically -- no manual seed-list edit.
extern std::string strBtfAnnounceRelay;
// Every relay to try: curated seeds + relays discovered from Nostr announcements.
std::vector<std::string> BtfAllRelays();

struct BtfPoolAnnouncement
{
    std::string btfAddress;
    std::string poolName;
    std::string dashboardUrl;
    double feePercent;
    int connectedMiners;
    int blocksFound;
    double hashRate;
    int64 createdAt;

    BtfPoolAnnouncement()
        : feePercent(0.0), connectedMiners(0), blocksFound(0), hashRate(0.0), createdAt(0)
    {
    }
};

// Number of .btf peers discovered from Nostr relays (includes not-yet-connected).
int GetDiscoveredPeerCount();

// Current live pool announcements discovered from Nostr relays.
void BtfGetPoolAnnouncements(std::vector<BtfPoolAnnouncement>& out);

// Publish a live pool announcement on Nostr.
bool BtfPublishPoolAnnouncement(const BtfPoolAnnouncement& ann);

// Query the latest pool announcement for a specific .btf pool address.
bool BtfQueryPoolAnnouncement(const std::string& poolBtfAddr, BtfPoolAnnouncement& out);

// Copy this node's .btf identity (lazily loading or generating it): the x-only
// pubkey (= the .btf address) and the x25519 secret for the end-to-end channel.
bool BtfGetIdentity(unsigned char pubkey[32], unsigned char enc_sk[32]);

// This node's printable .btf address, or "" if the identity failed to load.
std::string BtfLocalAddress();

// This node's own signed descriptor, ready to hand to a peer over the wire.
// "" until ThreadBtfAccept has registered at a rendezvous.
std::string BtfLocalDescriptor();

// The shared secp256k1 context, for btf::VerifyDescriptor (which takes it as
// void* to keep headers free of secp). NULL if the identity failed to load.
void* BtfSecpContext();

// Resolve a .btf address via the public discovery relays: fetch the owner's
// self-certified descriptor and return its meeting node ("host:port") and
// x25519 public key for the end-to-end channel.
bool BtfResolve(const std::string& btfAddr, std::string& meetingHostPort,
                unsigned char enc_pub[32],
                std::string* onionHostPort = NULL);

// Result of resolving one .btf address via BtfResolveMany.
struct BtfResolvedPeer
{
    std::string meetingHostPort;
    std::string onionHostPort;
    std::string descriptor;
    unsigned char enc_pub[32];
};

// Resolve many .btf addresses at once. Batches all still-unresolved addresses
// into a single Nostr REQ per relay (multiple "authors"), instead of opening
// one relay connection per address like BtfResolve does. Use this whenever
// resolving more than a handful of addresses in the same pass -- e.g. before
// dialing several discovered peers in parallel -- to avoid hammering the
// same few public relays with a burst of simultaneous connections. Returns
// true if at least one address resolved; check `out` for which ones.
bool BtfResolveMany(const std::vector<std::string>& btfAddrs,
                     std::map<std::string, BtfResolvedPeer>& out);

#endif
