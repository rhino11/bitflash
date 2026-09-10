# Tor mode

Tor is not an option on this network, it is the network. Since 1.2.21 a peer is
reached only at the `.onion` its signed descriptor names, and the rendezvous
relays that used to pair nodes have been removed from the code. What the options
below choose is *which* Tor a node uses — one it starts itself, one you already
run, or one reached through bridges — not whether it uses one.

None of this touches consensus, wallet keys, mining, or `.btf` addresses.

## Managed Tor: the default

The desktop app and the release packages ship Tor and start it themselves when no
other Tor option is given. The node creates a v3 hidden service, points it at its
own P2P port, and publishes that onion in its descriptor. There is nothing to
install and nothing to configure.

```bash
bitflash-node -nogui                    # bundled Tor starts on its own
bitflash-node -nogui -managedtor        # ask for it explicitly
bitflash-node -nogui -managedtor=/path/to/tor
bitflash-node -nogui -nomanagedtor      # turn it off
```

The hidden service lives under `<datadir>/managed-tor`. **Always pass `-datadir`
explicitly when running more than one node on a machine.** Without it both land
in the same application directory and fight over the same hidden service, which
fails in ways that look like a network problem.

If `-managedtor` is asked for and Tor does not start, the node refuses to start
too. A node that came up without the Tor you asked for would dial peers over the
clear network while looking like it was protected.

## A Tor you already run

```bash
bitflash -tor                  # shorthand for the usual 127.0.0.1:9050
bitflash -tor=127.0.0.1:9150   # Tor Browser's listener
bitflash -tor=[::1]:9050
```

For a SOCKS5 proxy that is not Tor, use `-socks=HOST:PORT` directly. Either way
the node stops probing for its external IP, so nothing leaks outside the proxy.

When Tor runs on another machine it has to be able to reach this one, which means
the P2P listener cannot stay on loopback:

```bash
bitflash-node -nogui -socks=10.0.0.5:9050 -bindaddr=10.0.0.9
```

`-bindaddr` has to be asked for by name, and for a reason. The listener used to
bind every interface by default, so anything that could reach the plain TCP port
completed the same handshake a Tor peer does and was handed the node's signed
descriptor — onion included. Whoever dialled the IP then knew which onion it was.

## Bridges, where Tor itself is blocked

```bash
bitflash -torbridges          # built-in Snowflake set, no infrastructure needed
bitflash -torbridge="obfs4 1.2.3.4:1234 CERT=... iat-mode=0"
```

The transport binaries ship in the release packages under
`tor/pluggable_transports/`. If you ask for bridges and the binary for that
transport is missing, **the node refuses to start** rather than reaching Tor
directly — that fallback would perform the exact observable act you were trying
to avoid, while reporting success.

## What to test

Use the public status page only as a rough health check. To prove the local node
is really using Tor, test on the node itself:

```bash
bitflash-node -nogui -debug -datadir=<a folder of its own>
```

Then look in `debug.log` for:

```text
Managed Tor hidden service ready: <host>.onion:8433
[net] btfpeers: connection scheduler started
[net] btfseed: reached <address>.btf over onion <host>.onion:8443
[net] connected <address>.btf via direct onion <host>.onion:8443
Onion-only: P2P listener bound to 127.0.0.1; reachable through the hidden service
```

The `btfseed` lines need `-debug`: they are category logs, and without them a
healthy cold start looks identical to a dead one.

A DNS leak test should show no local resolver lookup for `.onion` hostnames. The
SOCKS5 request uses the domain-name form and asks the proxy to resolve it.

## Running a bootstrap seed

There is no relay to run any more. A node behind NAT needs nothing forwarded,
because its hidden service is its address. What still helps a stranger is
somebody answering the very first dial, and any node with a stable onion can be
that:

```bash
bitflash-node -nogui -managedtor -port=8433
```

Publish the `.btf` address it prints and others can pass it with
`-btfseed=ADDRESS:ENCHEX`. A seed holds no balance, does not mine, and is trusted
for nothing: it serves the same signed descriptors any peer does.

A fresh hidden service usually loses its opening dial — it has not finished
publishing and the circuits are cold. That is expected, and the connection
scheduler retries with backoff. Before 1.2.21 it did not, which is why a node
that lost its first dial would sit with no peers until somebody restarted it.

## A hidden service you manage yourself

Managed Tor is the path for ordinary nodes. If you would rather own the
configuration, point a hidden service at the P2P port yourself:

```text
HiddenServiceDir /var/lib/tor/bitflash-node/
HiddenServicePort 8433 127.0.0.1:8433
```

Restart Tor, read `/var/lib/tor/bitflash-node/hostname`, and advertise it:

```bash
bitflash-node -nogui -nomanagedtor -socks=127.0.0.1:9050 \
  -onionservice=<host>.onion:8433
```

## Pools over Tor

A pool operator's node listens on a second port on the same hidden service, at
`p2p + 1`. Workers resolve the pool's `.btf` address and dial that port over Tor
like any other peer, so a pool needs no public IP and no port forwarding.

```bash
bitflash-node -nogui -gen -operator -managedtor
```

Workers name the chain they are mining when they subscribe, so a pool on the
other network refuses them rather than handing out work whose shares could never
be paid.

## Testnet

Testnet uses the same machinery with its own genesis, magic bytes, port 18433 and
its own baked seed. Descriptor and pool announcements are namespaced per network,
so a testnet node does not learn mainnet peers.

```bash
bitflash-node -nogui -testnet -datadir=<a folder of its own> -managedtor
```

Free coins for testing: <https://faucet.bitflash.network>
