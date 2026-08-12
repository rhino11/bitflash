Bitflash (BTF) v0.1 ALPHA
=========================

A revival of Satoshi Nakamoto's original Bitcoin v0.1 client (2009), ported to
a modern toolchain and turned into its own Layer 1 network.

Philosophy: fair launch, no pre-mine, no ICO. One CPU, one vote.

Based on code Copyright (c) 2009 Satoshi Nakamoto.
Copyright (c) 2026 The Bitflash developers.
Distributed under the MIT/X11 software license, see the accompanying
file license.txt or http://www.opensource.org/licenses/mit-license.php.
This product includes software developed by the OpenSSL Project.


Differences from the original Bitcoin
-------------------------------------
- Own genesis block (22/Jul/2026 headline, independent chain)
- Own magic bytes (0xbf 0x1a 0x5c 0xfd) and P2P port 8433
- Addresses start with "B" (ADDRESSVERSION = 25)
- Consensus fixes applied: value overflow (CVE-2010-5139), duplicate inputs,
  money range checks (MoneyRange)
- IRC peer discovery replaced by Nostr relay discovery
- Memory-hard Proof of Work (RandomX, CPU + RAM) instead of SHA-256d
- Economics identical to Bitcoin: 50 BTF/block, halving every 210,000 blocks,
  21 million total


Build (Windows, MSYS2 UCRT64)
-----------------------------
Modern toolchain:
  g++ 16 (MinGW-w64 UCRT), wxWidgets 3.2, OpenSSL 3, Berkeley DB 6, Boost,
  libsecp256k1 (Schnorr), nlohmann/json, RandomX

Bundled dependencies are built from source into ../deps and ../RandomX.
In the MSYS2 UCRT64 shell:
  bash build.sh          (uses src/makefile.mingw)

The resulting executable is src/bitflash.exe.


Command-line options (in addition to the original ones)
-------------------------------------------------------
  /port=N        listen on P2P port N (default 8433)
  /socks=HOST:PORT
                 route outbound Nostr and .btf rendezvous dials through a
                 SOCKS5 proxy, e.g. /socks=127.0.0.1:9050 for local Tor
                 or /socks=[::1]:9050 for an IPv6 loopback proxy
  /solomine      mine without requiring a connected peer (local testing)
  /operator      operator mode (run pool server)
  /participant=ADDR
                 participant mode; mine to pool .btf address ADDR
  /stratumbridge=ADDR
                 listen on 127.0.0.1:3333 and bridge external Stratum miners
                 to pool .btf address ADDR
  /stratumbridgeport=N
                 local Stratum bridge port (default 3333)
  /poolname=NAME operator announcement pool name
  /poolfee=PCT   operator announcement fee percent (example: 0.75)
  /pooldashboard=URL
                 operator announcement dashboard URL
  /poolstatusfile=PATH
                 write pool status JSON for dashboards
  /poolroundsfile=PATH
                 write public pool round proofs JSON
  /connectbtf=ADDR
                 keep an outbound .btf connection to ADDR
  /rvrelay=HOST:PORT
                 override meeting relay list with one relay
  /announcerelay=HOST:PORT
                 announce this relay on Nostr for discovery


Roadmap
-------
Milestone 0  Compile the original client on a modern toolchain   [done]
Milestone 1  Bitflash identity + genesis + consensus fixes       [done]
Milestone 2  Peer discovery over Nostr relays                    [done]
Milestone 3  Memory-hard PoW (RandomX) instead of SHA-256d       [done]
Milestone 4  Public testnet
