<div align="center">

<img src="docs/social.png" width="820" alt="Bitflash"/>

# Bitflash `BTF`

CPU-only cryptocurrency. A revival of Bitcoin 0.1.0 with RandomX proof of work and anonymous `.btf` addressing over Nostr.

![PoW](https://img.shields.io/badge/PoW-RandomX%20(CPU)-2ea44f?style=for-the-badge)
![Privacy](https://img.shields.io/badge/addresses-.btf%20anonymous-2ea44f?style=for-the-badge)
![Fair Launch](https://img.shields.io/badge/premine-none-2ea44f?style=for-the-badge)

**[Download](../../releases/latest)**

</div>

---

## What it is

Bitflash keeps Satoshi's original consensus rules and replaces two things:

**RandomX proof of work.** Memory-hard algorithm used by Monero. A laptop competes equally with a server. ASICs and GPUs have no advantage.

**Anonymous addressing.** Every node has a `.btf` address derived from its public key, similar to a Tor `.onion`. Nodes reach each other through encrypted rendezvous tunnels, so no port forwarding is needed and a node behind CGNAT works normally.

No premine. No ICO. 50 BTF per block, halving on schedule, 21M cap, ~2 minute blocks.

### What `.btf` does and does not hide

Worth being precise, because the difference matters if you are relying on it.

**A peer you reach over `.btf` does not learn your IP.** All outbound connections go through a rendezvous tunnel; there is no IP-based peer dialling left in the node. The relay forwards encrypted bytes and cannot read or alter them.

**The rendezvous relay does see your IP.** It has to — it is the thing your TCP connection terminates on. Relays are run by volunteers, so treat that as a party who knows you are on the network.

**The node still listens on 8433.** Nothing dials by IP any more, but the listener is still there, so anyone who already knows your address and can reach that port may connect directly. If that matters to you, firewall it.

This is unlinkability between peers, not anonymity against a network observer. It is not Tor.

---

## Quick start

Download the [latest release](../../releases/latest) and run. No install, no
configuration — it connects automatically and starts syncing.

**Linux:** make the `.AppImage` executable and run it.

**Windows:** extract the `-windows.zip` and run `Bitflash.exe`.

Every release ships a `SHA256SUMS` covering both assets. Verifying takes a second
and is worth doing:

```bash
sha256sum -c SHA256SUMS
```

**Keep your node current.** Consensus rules have changed since the first
releases — 1.2.1 fixed a bug that let anyone spend anyone's coins, and 1.2.2
added a per-block signature-operation cap. A node on an older build will accept
blocks that current nodes reject, which puts it on a different chain without any
warning.

Your wallet and chain data live in `%APPDATA%\Bitflash` (Windows) or
`~/.bitflash` (Linux) and are shared by every version, so upgrading is just
replacing the binary. Never delete that directory to "fix" something without a
backup — it holds your keys.

---

## Backing up your wallet

Two things about this wallet will cost you money if you do not know them. Both
are consequences of the 0.1.0 wallet format, and neither is obvious.

**Copying `wallet.dat` on its own is not a backup.** Berkeley DB ties the file
to the environment in the `database/` subdirectory beside it, so a lone
`wallet.dat` will not open elsewhere — the keys are all still in there, and the
file is refused anyway. Use the built-in command, which writes a copy that
stands on its own:

```
bitflash -backupwallet=/path/to/wallet-backup.dat
```

It loads the wallet, writes the copy, and exits without starting the node. If
you would rather copy by hand, shut the node down first and take the **whole**
data directory, not just `wallet.dat`.

**Every backup is still a snapshot, but it now has a safety margin.** The wallet
keeps a pool of 100 pre-generated keys. A backup contains those keys, so it
covers the next 100 mining rewards or receive addresses the node hands out after
the backup. That makes a normal backup much safer than the original 0.1.0
wallet, where the very next block could land on a key the backup did not have.

It is not a seed phrase. Heavy use can drain the key pool, and deterministic
wallet restore is still tracked in [#47](https://github.com/Bitflash-sh/bitflash/issues/47).
Back up again after mining for a while, after creating many receive addresses,
and before moving the wallet to another machine.

The GUI has a **Backup Wallet** button and a **Wallet Safety** view. Use that if
you do not want to run the command by hand; it fills the key pool before writing
the backup.

### When wallet.dat itself will not open

Everything above still runs through Berkeley DB. If the database is the thing
that is broken — a build that will not read it, a file truncated by a bad copy,
an environment beyond recovery — the keys are usually still fine, and you can
take them out as text:

```
bitflash -dumpwallet=/path/to/keys.txt
bitflash -importwallet=/path/to/keys.txt   # into any wallet, on any machine
```

One key per line with its address and label, no database and no environment.
Importing skips keys the wallet already holds, so running it twice is safe, and
an unreadable line is reported and stepped over rather than abandoning the rest.
Restart the node afterwards so it scans the chain for transactions belonging to
the new keys.

**The dump is your private keys in the clear.** Anyone who reads that file can
spend those coins. It is written owner-only on Linux and macOS; on Windows it
inherits whatever the containing folder allows, so choose the folder carefully.
Move it somewhere safe and delete the copy. `-dumpwallet` will not overwrite an
existing file.

---

## Mining

Open **Options** from the menu bar. Under Mining Mode:

**Solo** — mine directly to your wallet. Default.

**Operator** — run a pool. The pool server uses `.btf` rendezvous only. The window shows the pool's `.btf` address, discovered pools, and owed payouts.

Pool announcements are published on Nostr with live status fields, so external tools can query the latest pool state by `.btf` address.

**Participant** — mine to someone else's pool. Enter or select the pool's `.btf` address and enable Start Mining.

SRBMiner and XMRig connect to operator pools through the `.btf` path:

```bash
SRBMiner-MULTI --algorithm randomx --pool POOL_BTF_ADDRESS --wallet YOUR_BTF_ADDRESS --password x
xmrig -a rx/0 -o POOL_BTF_ADDRESS -u YOUR_BTF_ADDRESS -p x
```

---

## Headless / server mode

```bash
./bitflash /nogui                     # node only
./bitflash /nogui /gen                # node + solo mining
./bitflash /nogui /gen /operator      # pool operator
./bitflash /nogui /gen /participant=POOL_BTF_ADDRESS  # mine to pool
```

Mining is off unless you pass `/gen` — it is not remembered between restarts, so
put the flag in whatever starts the node rather than enabling it in the window.

Other options worth knowing:

```bash
/datadir=PATH    # wallet and chain data elsewhere
/port=N          # P2P listen port, default 8433
/debug           # verbose log; without it debug.log is nearly silent
/help            # full list
```

`/port` plus `/datadir` is what lets two nodes share one machine. Both are
needed — the data directory takes an exclusive lock, so a second node pointed at
the same one will refuse to start.

As a systemd service:

```ini
[Unit]
Description=Bitflash node
After=network.target

[Service]
ExecStart=/opt/bitflash/bitflash /nogui /gen /operator
Restart=always
User=bitcoin
WorkingDirectory=/opt/bitflash

[Install]
WantedBy=multi-user.target
```

---

## How nodes find each other

A node publishes a **self-certifying descriptor**: its `.btf` address, an
encryption key, and the rendezvous relay where it is currently reachable, signed
with the key the address decodes to. Nobody can publish a descriptor for an
address they do not own, so a hostile relay can withhold descriptors but cannot
forge one.

Discovery runs on four layers, so no single failure takes the network down:

| | |
|---|---|
| **Nostr relays** | where descriptors are published and looked up |
| **Rendezvous relays** | the tunnel itself, where two nodes are paired |
| **Peer cache** | peers that answered last time, saved to `btfpeers.json` and dialled on start before any relay is contacted |
| **Peer exchange** | connected nodes hand each other signed descriptors, so discovery keeps working while relays are down |

Peer exchange carries the same signed descriptors, verified the same way, so a
peer passing one on is trusted for nothing.

The cache is what makes a restart fast: on a clean install the first peer takes
about 36 seconds, and on the next start about 2.

---

## Running a relay

Relays are the meeting points that let nodes behind NAT connect to each other. More relays make the network more resilient.

```bash
sudo bash relay/install-bitflash-relay.sh 8434
./bitflash /nogui /announcerelay=YOUR_PUBLIC_IP:8434
```

Relays forward encrypted bytes and cannot read or modify traffic.

---

## Build from source

**Linux:**
```bash
make linux
```
Installs deps via apt, builds libsecp256k1 and RandomX, produces `Bitflash-*.AppImage`.

**Windows (MSYS2 UCRT64):**
```bash
make windows
```
Installs deps via pacman, produces `Bitflash-*-windows.zip`.

---

## At a glance

| | |
|---|---|
| Ticker | BTF |
| Proof of work | RandomX (CPU, memory-hard) |
| Block time | ~2 minutes |
| Difficulty retarget | every 30 blocks (~1 hour) |
| Block reward | 50 BTF, halving every 210,000 blocks |
| Halving interval | **~292 days** at target block time |
| Max supply | 21,000,000 BTF |
| Coinbase maturity | 100 blocks (~3.3 hours) before mined coins can be spent |
| Max signature ops | 20,000 per block |
| P2P port | 8433 |
| Addressing | `.btf` rendezvous — see the caveats above |
| Premine | None |
| Pool server | Built-in — `.btf` rendezvous only |

The halving interval is the number most people get wrong coming from Bitcoin.
Same 210,000 blocks, but at two minutes instead of ten, so it arrives in about
ten months rather than four years.

---

Experimental software. Young network. Don't put in more than you are willing to lose.

MIT. Built on Bitcoin 0.1.0 (Satoshi Nakamoto, 2009).
