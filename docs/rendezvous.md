# How Bitflash nodes reach each other

This is the specification of how Bitflash nodes find and connect to each other,
and how miners reach pools, without revealing an IP address and without any
central directory. It documents the protocol as implemented in `src/btfaddr.cpp`,
`src/net.cpp` and `src/nostr.cpp`.

A `.btf` address names a public key. A node proves ownership of that key by
signing a service descriptor that says where it can be reached, and other nodes
dial that address directly over Tor. Nothing else is trusted: not the peer that
passed the descriptor on, not the relay it was published to, not the seed that
answered first.

> **This document changed with 1.2.21.** Until then, two nodes met through an
> untrusted rendezvous relay over an end-to-end encrypted tunnel, ported from the
> Itzal hidden service design. That transport has been removed from the code, not
> merely deprecated: `btfrv`, `btftunnel` and the relay daemon are gone. The
> reason is that a relay is a machine your TCP connection terminates on, so it
> saw your IP unless you also ran Tor, and it was one more thing that had to be
> up. A hidden service is both the address and the transport, and nobody
> operates it but you.

---

## The address

A `.btf` address is 52 base32 characters and encodes an ed25519 public key, the
same shape and for the same reason as a Tor v3 `.onion`:

```
fd5gieenz3oep42siocc7z7ldealvt6iztu3nkekzphc6prwwcs45xi.btf
```

The address *is* the key. There is no registry to consult and nothing to
impersonate: a signature either verifies against the key the address decodes to,
or it does not.

## The descriptor

A node publishes a small signed JSON object describing where it is:

```json
{
  "v": 3,
  "created": 1788975691,
  "onion": "btjui62nrnc4ysmqkfxkkastvn65mecgf4j6qn2fxll3ayc7lb2vkuid.onion:8443",
  "enc": "<x25519 public key, hex>",
  "pubkey": "<ed25519 public key, hex>",
  "sig": "<signature over the canonical form>",
  "sig3": "<signature over the v3 canonical form>"
}
```

`onion` is the hidden service the node listens on. `enc` is an x25519 key used
for the encrypted Nostr lookup path; the P2P connection itself does not need it,
because reaching a hidden service already proves who is answering.

The signature is what makes the descriptor self-certifying. Whoever hands you one
— a Nostr relay, a peer, a seed — is trusted for nothing, because forging an
entry would require the secret key behind the address.

## Connecting

1. Resolve the `.btf` address to an `.onion`, from the peer cache, from a
   descriptor a peer handed over, from the baked seed list, or from Nostr.
2. Dial that `.onion` through the local Tor SOCKS5 proxy.
3. Speak the ordinary Bitflash P2P protocol over it: magic bytes, `version`,
   `verack`, and on from there.

Reaching the hidden service at the address the descriptor names is the
authentication. Tor's own handshake proves the far end holds the key that the
onion encodes, and the descriptor ties that onion to the `.btf` address.

## Discovery

Three sources feed one connection scheduler, and none of them is required for
the others to work:

| | |
|---|---|
| **Baked seed** | a pinned `.onion` compiled into the binary, dialled directly, so a cold start needs no relay to answer. Mainnet and testnet each have their own. |
| **Peer cache** | `btfpeers.json` in the data directory: peers that answered before, most recent first, capped at 50. |
| **Peer exchange** | connected nodes hand each other signed descriptors over the `btfpeers` message, so the network grows and heals with nothing in the middle. |

Nostr is used to look up a descriptor when nothing else has one, and that is the
whole of its role. Tor frequently has no exit to reach the Nostr relays, so
nothing load-bearing may depend on it.

The scheduler re-reads the cache every round — which is what puts peer exchange
to use — and keeps per-address exponential backoff with jitter. A dead address
costs one dial and then goes quiet. An address that was merely unreachable for a
moment is tried again. Seeds are retried whenever the peer count is on the floor,
not only on the first run.

> A fresh hidden service usually loses its opening dial: it has not finished
> publishing and the circuits are cold. Before 1.2.21 discovery ran once at
> startup, so that first failure was final and the node sat with no peers until
> somebody restarted it. This is why the retry loop exists.

## Pools

A pool operator's node listens on a second port on the same hidden service, at
`p2p + 1`. A worker resolves the pool's `.btf` address the same way it resolves
any peer — cache first, Nostr only on a miss — and dials that port over Tor.

Stratum then runs unchanged over that connection, with one addition: the worker
names the chain it is mining in `mining.subscribe`, and a pool on the other
network refuses it before handing out work whose shares could never be paid.

## What this hides, and what it does not

**A peer does not learn your IP.** Every dial leaves through Tor and every
inbound connection arrives through your hidden service.

**No third party is on the path.** There is no relay to see either end.

**Your listener is not a way around it.** Under managed Tor the P2P socket binds
loopback only, because that is where Tor forwards the hidden service. Binding
every interface, which is what earlier versions did, let anything that could
reach the plain port complete a handshake and receive your signed descriptor —
onion included — so whoever dialled the IP learned which onion it was. If your
Tor runs on another machine, `-bindaddr=IP` opens that up deliberately.

**This is not anonymity against a global observer.** It is unlinkability between
peers, with Tor's properties and Tor's limits.

## Testnet

Testnet nodes speak the same protocol with their own genesis, magic bytes, port
and seed. Descriptor and pool announcements are namespaced per network, so a
testnet node does not learn mainnet peers and waste dials on handshakes the magic
bytes were always going to reject.
