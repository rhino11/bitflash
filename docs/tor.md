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

When Tor mode is enabled:

- outbound Nostr relay dials use Tor;
- outbound `.btf` rendezvous relay dials use Tor;
- destination names are sent to Tor as SOCKS5 domain-name CONNECT requests, so
  the local DNS resolver does not see them;
- direct `.onion` dials are refused unless a SOCKS5/Tor proxy is enabled;
- plain HTTP external-IP probes are skipped.

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
