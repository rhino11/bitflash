#!/bin/sh
# Bitflash Miner: XMRig over Tor, straight to the pool's hidden service.
#   ./mine.sh YOUR_BTF_ADDRESS            mainnet
#   ./mine.sh YOUR_BTF_ADDRESS testnet    testnet pool (testnet address!)
# Anything after those two is passed to XMRig, e.g. -t 4 to use 4 threads.
cd "$(dirname "$0")" || exit 1

POOL=mddjuyuctouv62eqdaofvwf4timxxmp72d2ghmc6qp5mdey6f5au56id.onion:8436
SOCKS=127.0.0.1:9251

if [ -z "$1" ]; then
    cat <<EOF

  usage: ./mine.sh YOUR_BTF_ADDRESS [testnet] [xmrig options]

  YOUR_BTF_ADDRESS is a Bitflash payment address -- the kind the Bitflash
  wallet shows under Receive, or -newaddress prints. Not a .btf address.
  The pool pays out to it. Fee 1%.

EOF
    exit 1
fi
ADDR=$1; shift
if [ "$1" = "testnet" ]; then
    POOL=vocwzaqll3vzuvs4nkva5fxh6q5odlokkqvfc2uvhcjtmjlygae5l4id.onion:18438
    shift
fi

mkdir -p tor-data
chmod 700 tor-data
echo "Starting Tor (own instance, SOCKS on $SOCKS)..."
# The Expert Bundle's tor has no RUNPATH; it needs the libevent/libssl/libcrypto
# shipped in tor/ ahead of the system's, or it dies with "undefined symbol:
# evutil_secure_rng_add_bytes" (exit 127) on Fedora 44 / Ubuntu 26.04.
LD_LIBRARY_PATH="$PWD/tor${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ./tor/tor --SocksPort "$SOCKS" --DataDirectory tor-data --Log "notice file tor-data/tor.log" --ClientOnly 1 >/dev/null 2>&1 &
TORPID=$!
echo "Tor bootstraps in 10-60 s; XMRig retries until it is through."
echo "Pool: $POOL"
echo

./xmrig/xmrig -a rx/0 -x "$SOCKS" -o "$POOL" -u "$ADDR" -p x --retries=100000 --retry-pause=5 "$@" &
XMPID=$!
# Whatever ends this script -- Ctrl+C, a kill, XMRig exiting -- takes both
# processes with it, and only these two.
trap 'kill $XMPID $TORPID 2>/dev/null' EXIT INT TERM
wait $XMPID
