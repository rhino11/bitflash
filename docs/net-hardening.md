# Network hardening (protocol 102)

What Bitcoin's P2P layer learned between 0.2 and 0.3.x, applied here in one
release. None of it touches consensus: a block valid before is valid after, and
no node has to update by any date. What changes is how a node treats what its
peers send it, and what it does while it is behind.

## Message checksum

Protocol 102 adds four bytes to every message header: the first four bytes of
`Hash(payload)`. 0.1.0's header was message start, command and size, and a
payload mangled in transit -- or by a peer -- parsed as whatever it happened to
be. A message whose checksum does not match is dropped unread.

Both framings live on one network. A node speaks 101 to every peer until that
peer's version message says 102; its own version message always leaves in 101
framing, because nothing is known about the peer when it is sent. The peer's
version message is the one being read when the switch happens, so both streams
change over cleanly, with no message in flight in the wrong layout. Nodes on
1.2.27 and earlier never see a 24-byte header.

The layout of a message being built is fixed when it is begun, not when it is
finished: a peer's version message can arrive on another thread in between.

## Misbehavior and bans

Each peer carries a score. A malformed header costs 10, a bad checksum 20, a
block no honest node would send 50 to 100 (see below), a coinbase relayed as a
transaction 100, a transaction that fails the shape checks 10. At 100 the peer
is disconnected. If the node had dialled it by `.btf` address, that address is
not dialled again for 24 hours. An inbound onion peer has nothing to ban -- Tor
hides where it came from, which is the point -- so for it a ban is the
disconnect and no more.

What a block failure is worth, for the peer that sent it:

| failure | score |
|---|---|
| block from the future, block we already have, orphan, timestamp too early | 0 |
| proof of work does not meet nBits | 50 |
| nBits wrong for its height, coinbase without the height (rules v2) | 100 |
| size limits, first tx not coinbase, two coinbases, bad transaction, sigops, duplicate tx, nBits below the floor, merkle root mismatch | 100 |

Zero for the first row because clocks differ and relays overlap; an honest
peer sends those. A block on the old proof of work after the switch is 50: two
of them and the peer is gone, which is what happens to a node left on 1.2.23
after 2026-09-21 12:00 UTC.

## Initial block download

`IsInitialBlockDownload()` is true while peers' announced heights are more than
three blocks past ours. While it holds, the miner waits -- a template built on
a stale tip mines a fork, and one node here mined a 323-block fork that way --
and blocks being replayed are not announced to every peer. A node with no peer
heights is not syncing: refusing to mine on a chain nobody claims to be ahead
of would only wedge a stalled network. Diagnostics say `syncing yes` while it
holds.

## Coin selection by confirmation depth

0.1.0 spent any credit the moment it was in the wallet. A payment somebody had
just announced, unconfirmed, was fair input for the next send, and if that
payment never made it into a block the send built on it died with it. Now
coins from others need one confirmation to be inputs, six preferred; the
wallet's own change may be spent unconfirmed when nothing else covers the
amount. Selection tries (mine 1, theirs 6), then (1, 1), then (0, 1).

## Diagnostics

A `syncing` line while it holds, a `banned` count while any address is, and a
`proto` column in the peer table showing the version each peer announced.

## Checked by

`-selftest=net-hardening`: header size at each version, a message built at 102
carrying the right checksum, a message with one flipped payload bit caught by
`ProcessMessages()` itself and costing 20 points, 101 framing still round
tripping, the ban at 100 points and its absence for an inbound peer, the score
of each block failure, the syncing rule at two, four and ten blocks behind and
alone, and coin selection refusing an unconfirmed 7 from somebody else while
spending our own unconfirmed 3.
