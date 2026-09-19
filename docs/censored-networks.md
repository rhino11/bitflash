# Bitflash on censored networks

Bitflash speaks only over Tor, so what blocks Bitflash is whatever blocks Tor.
This page is for the places where that happens: what the node does on its own,
what you can do, and where to get the software when the usual sites are gone.

## What the node does on its own

The managed Tor that ships with Bitflash reaches the Tor network directly. On a
network that blocks Tor's public relays, that looks like a node that never gets
a peer. So the node watches for exactly that: **no peer within four minutes of
managed Tor coming up, and no bridges configured**, and then restarts its Tor
once with the bundled Snowflake bridges. In `debug.log`:

```
managed Tor: no peer after 240 s -- Tor's public relays may be blocked here.
Restarting Tor with the bundled bridges (2 line(s)); -notorfallback disables this.
```

The onion address is kept across the restart (the hidden-service keys live in
the same folder), so nothing changes for the peers that already know you.

- `-notorfallback` turns this off. Use it if reaching the Tor bridge broker from
  your network is itself something you would rather not do.
- `-torfallback=SECS` changes the wait.
- It only fires when the pluggable-transport binary is present
  (`tor/pluggable_transports/lyrebird` next to the Tor binary, or next to
  `bitflash` under `tor/`). Without it the node logs that there is nothing to
  fall back to and keeps trying directly.

## Asking for bridges up front

If you already know Tor is blocked where you are, do not wait the four minutes:

```bash
bitflash -torbridges                                   # bundled Snowflake set
bitflash -torbridge="obfs4 1.2.3.4:1234 CERT=... iat-mode=0"   # a bridge of your own
```

Snowflake needs no bridge address at all: it reaches Tor through volunteer
WebRTC proxies via a broker that is fronted by a large CDN, which is why it keeps
working where fixed bridge IPs get blocked one by one. obfs4 bridges are faster
and quieter but their addresses can be blocked; get private ones from
<https://bridges.torproject.org> or by mailing `bridges@torproject.org`, and pass
the line with `-torbridge=`. Both can be repeated in `bitflash.conf`.

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
