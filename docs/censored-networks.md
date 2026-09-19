# Bitflash on censored networks

Bitflash speaks only over Tor, so what blocks Bitflash is whatever blocks Tor.
This page is for the places where that happens: what the node does on its own,
what you can do, and where to get the software when the usual sites are gone.

## What the node does on its own: the ladder

The managed Tor that ships with Bitflash reaches the Tor network directly. On a
network that blocks Tor's public relays, that looks like a node that never gets
a peer. So the node watches for exactly that and climbs a ladder of transports,
each given its time, until one reaches the network:

| rung | what it is | why it survives blocking |
|---|---|---|
| direct | Tor's public relays | it does not; this is the fast path where Tor is allowed |
| snowflake | volunteer WebRTC proxies, broker behind a CDN | no fixed address to block; looks like a video call |
| obfs4 | fixed bridges with an obfuscated handshake | not in the public relay list; blocked one at a time |
| webtunnel | a bridge hidden behind a real HTTPS site | indistinguishable from visiting that site |
| meek | domain fronting through a CDN | blocking it means blocking the CDN |

The bridge lines come from Tor Browser's own list, shipped beside the transports
as `pt_config.json`, so they are as fresh as the Tor bundle in the release.
Rungs whose transport binary is not there are skipped.

The rules of the climb:

- **Direct** gets four minutes (`-torfallback=SECS`), or only 90 s when Tor
  itself reports it could not fetch a directory (bootstrap under 10 %): that is
  not slowness, that is a wall.
- Every bridge rung gets six minutes (`-torrung=SECS`). Snowflake needs about
  three of them just to bootstrap from cold, so do not set this low.
- The node reads Tor's own bootstrap over the control port the whole time, so
  the log says what Tor saw, not just that nobody came:

```
managed Tor: no peer after 240 s (Tor bootstrap 5% Connecting to a relay) -- Tor's public relays may be blocked here.
Restarting Tor with the bundled snowflake bridges (2 line(s)); -notorfallback disables this.
managed Tor: no peer after 360 s on snowflake bridges (Tor bootstrap 65% Loading relay descriptors). Trying the bundled obfs4 bridges (7 line(s)).
managed Tor: network reached via obfs4 bridges
```

- The onion address is kept across every restart (the hidden-service keys live
  in the same folder), so nothing changes for the peers that already know you.
- **What worked is remembered** in `managed-tor/last-working`. The next start
  begins on that rung instead of spending the four minutes again:

```
Tor: last time only the obfs4 bridges reached the network; starting on them (delete managed-tor/last-working to try direct Tor again)
```

  When direct Tor works, the file is removed. Moving to a free network and
  wanting direct Tor back: delete the file, or *Forget what worked* in Options,
  or `settorbridges forget` over RPC.
- When the last rung fails too, the node stays on it and says where to get
  bridges of your own (next section). It never climbs *down* to direct on its
  own once bridges were asked for.
- `-notorfallback` turns the whole ladder off, as does the checkbox in
  Options (kept in `managed-tor/no-fallback`). Use it if reaching the bridge
  broker or the CDN fronts from your network is itself something you would
  rather not do.

Where to see it: *Options* in the desktop app shows the transport in use and
Tor's bootstrap line; the diagnostics dump (`managed Tor` line) and the
`gettorinfo` RPC show the same for a headless node.

## Bridges of your own

The bundled lines are public and the first thing a censor blocks. Private
bridges are handed out a few at a time, and those are what carry people where
the ladder fails:

- <https://bridges.torproject.org> (needs a way to reach it; Tor Browser with
  its own bridges, or a friend abroad)
- email `bridges@torproject.org` from a Gmail or Riseup address, body `get transport obfs4`
- Telegram: the bot `@GetBridgesBot`, send `/bridges`
- a friend who runs one: an obfs4 or webtunnel bridge line

Paste the lines, one per line, into `bridges.txt` in the data directory. The
`Bridge ` prefix is optional, `#` starts a comment. Three ways to do that:

- **Desktop app:** *Options → Tor & Censorship*, paste, *Use bridges now*. Tor
  restarts on your lines at once; the onion stays the same.
- **Any node:** create the file and restart; or over RPC,
  `settorbridges ["obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0"]`
  saves the file and switches now.
- **Command line:** `-torbridge="LINE"` (repeatable in `bitflash.conf`), or
  `-torbridges` for the bundled Snowflake set without waiting.

Your own lines are always preferred over the bundled ones, and the node never
starts direct Tor while they exist. If they stop working, the ladder carries on
from them to the bundled rungs, never to direct.

If you ask for bridges and the transport binary is missing, the node refuses to
start instead of quietly reaching Tor directly. That silent downgrade is the
one thing this whole page is trying to prevent.

## Getting the software

The download sites (`bitflash.network`, the forge) may be unreachable from the
same networks. The releases are also served from an onion address, over Tor
only:

```
http://rqzruhh4sm2s3fl6b4mpselkqsaaxebnyptpqhdpt236g57lof7j7sid.onion/
```

Tor Browser opens it directly. It carries the current release for every
platform, `SHA256SUMS`, its signature, and the signing key. Verify before
running anything, whichever way you got the file:

```bash
gpg --import bitflash-signing-key.asc      # fingerprint 910A 2B4C CA87 9E81 FB4B 2AEA 1D4A 53D3 B78A A4B8
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

The signature is what makes a copy trustworthy, not where it came from. A
release passed hand to hand on a USB stick, verified against that key, is
exactly as good as one downloaded from the project site. See
[release-verification.md](release-verification.md).

## What is and is not hidden

- Your ISP sees Tor traffic (or, with Snowflake, WebRTC traffic to a CDN), never
  Bitflash traffic. Nothing in the protocol reaches the clear net.
- Peers see your `.onion` address and nothing else about where you are.
- The node makes no DNS lookups and no plain-HTTP requests for anything.
- Bridges hide *that you use Tor* from a passive observer only as well as the
  transport does; obfs4 with `iat-mode` and Snowflake are both designed for
  that, but none of it is a guarantee against active probing.

## A word on the law

In some countries using Tor, using bridges, or holding cryptocurrency is itself
an offence. Bitflash cannot change that. Know the rules where you are before
you decide that the software's protections are enough; the project can make the
traffic hard to see, not make the act legal.
