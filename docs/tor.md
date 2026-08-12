# Tor mode

Bitflash can route outbound discovery traffic through a local Tor SOCKS5 proxy.
This is transport plumbing only: it does not change consensus, wallet keys,
mining, `.btf` addresses, or the encrypted rendezvous protocol.

## Client mode

Start Tor locally, then start Bitflash with:

```bash
bitflash -tor
```

`-tor` is shorthand for:

```bash
bitflash -socks=127.0.0.1:9050
```

If Tor listens somewhere else:

```bash
bitflash -tor=127.0.0.1:9150
bitflash -tor=[::1]:9050
```

For a SOCKS5 proxy that is not Tor, use `-socks` directly:

```bash
bitflash -socks=127.0.0.1:9050
bitflash -socks=[::1]:9050
```

If both `-tor` and `-socks` are present, Tor mode wins and the node prints a
warning. That keeps a command line with `-tor` from silently becoming a custom
proxy route.

When Tor mode is enabled:

- outbound Nostr relay dials use Tor;
- outbound `.btf` rendezvous relay dials use Tor;
- destination names are sent to Tor as SOCKS5 domain-name CONNECT requests, so
  the local DNS resolver does not see them;
- direct `.onion` dials are refused unless a SOCKS5/Tor proxy is enabled;
- plain HTTP external-IP probes are skipped.

Tor mode affects outbound discovery and relay dials. It does not encrypt
`wallet.dat`, hide mining rewards on-chain, or change the `.btf` identity. A
relay still sees the TCP client that connected to it; with Tor mode that client
is the Tor exit or onion circuit endpoint instead of the user's direct IP.

## What to test

Use the public status page only as a rough health check. To prove the local node
is using Tor/SOCKS, test from the node machine:

```bash
bitflash -tor -debug
```

Then confirm in `debug.log` that Nostr and rendezvous dials report the proxy
path. A DNS leak test should show no local resolver lookup for relay hostnames:
the SOCKS5 request uses the domain-name form and asks the proxy to resolve it.

## Onion rendezvous relay

An operator can expose a Bitflash rendezvous relay as a Tor hidden service. The
node does not create hidden services itself; Tor owns that configuration.

Example `torrc`:

```text
HiddenServiceDir /var/lib/tor/bitflash-rendezvous/
HiddenServicePort 8434 127.0.0.1:8434
```

After restarting Tor, read the generated onion name:

```bash
sudo cat /var/lib/tor/bitflash-rendezvous/hostname
```

Then run the relay on localhost/VPS as usual and announce the onion endpoint from
nodes that use Tor:

```bash
bitflash -tor -rvrelay=exampleexampleexampleexampleexampleexampleexampleexample.onion:8434
bitflash -tor -announcerelay=exampleexampleexampleexampleexampleexampleexampleexample.onion:8434
```

For a pool operator that wants the pool descriptor to point at an onion
rendezvous relay, use both:

```bash
bitflash -operator -tor \
  -rvrelay=exampleexampleexampleexampleexampleexampleexampleexample.onion:8434 \
  -announcerelay=exampleexampleexampleexampleexampleexampleexampleexample.onion:8434
```

## Full-node hidden service

The legacy P2P listener still binds to port `8433`. You can expose it through
Tor manually:

```text
HiddenServiceDir /var/lib/tor/bitflash-node/
HiddenServicePort 8433 127.0.0.1:8433
```

Current automatic peer discovery is `.btf`/rendezvous based, not onion-address
gossip. Treat direct full-node onion access as an operator/admin tool unless a
future release adds first-class onion peer advertisements.
