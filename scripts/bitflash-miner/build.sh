#!/bin/sh
# Assemble Bitflash-Miner-VERSION-{windows,linux} from the official XMRig
# builds (hashes checked against the release page) and the Tor Expert
# Bundle. Runs on the 202; nothing is executed, only unpacked and packed.
set -e
V=$1; [ -n "$V" ] || { echo "usage: build-bfminer.sh VERSION"; exit 1; }
W=/root/bfminer
cd $W
sha256sum -c <<EOF
bba8097cb37d9b458a1cb1137876b27cde6740d17fe4ccbc086ba07d87d9e147  dl/xmrig-6.26.0-windows-x64.zip
fc6f8ae5f64e4f17481f7e3be29a1c56949f216a998414188003eae1db20c9e5  dl/xmrig-6.26.0-linux-static-x64.tar.gz
EOF

rm -rf stage && mkdir -p stage
# ---- windows ----
D=stage/Bitflash-Miner-$V-windows
mkdir -p $D/xmrig $D/tor $D/licenses
(cd stage && unzip -q ../dl/xmrig-6.26.0-windows-x64.zip)
cp stage/xmrig-6.26.0/xmrig.exe stage/xmrig-6.26.0/WinRing0x64.sys $D/xmrig/
cp dl/xmrig-LICENSE $D/licenses/XMRIG-LICENSE.txt
cp win-tor/tor.exe $D/tor/
cp win-tor/docs/*.txt $D/licenses/ 2>/dev/null || true
cp tor-LICENSE $D/licenses/TOR-LICENSE.txt
cp src/mine.cmd src/README.txt $D/
sed -i 's/$/\r/' $D/mine.cmd $D/README.txt
(cd $D && sha256sum $(find . -type f ! -name SHA256SUMS | sed 's#^\./##' | sort) > SHA256SUMS)
(cd stage && zip -qr ../Bitflash-Miner-$V-windows.zip Bitflash-Miner-$V-windows)

# ---- linux ----
D=stage/Bitflash-Miner-$V-linux
mkdir -p $D/xmrig $D/tor $D/licenses
(cd stage && tar xzf ../dl/xmrig-6.26.0-linux-static-x64.tar.gz)
cp stage/xmrig-6.26.0/xmrig $D/xmrig/
cp dl/xmrig-LICENSE $D/licenses/XMRIG-LICENSE.txt
mkdir -p stage/lintor && tar xzf /root/rel16/.cache/tor-expert-bundle-linux-x86_64-15.0.19.tar.gz -C stage/lintor
cp stage/lintor/tor/tor $D/tor/
cp stage/lintor/tor/libevent-2.1.so.7 stage/lintor/tor/libcrypto.so.3 stage/lintor/tor/libssl.so.3 $D/tor/
cp tor-LICENSE $D/licenses/TOR-LICENSE.txt
cp src/mine.sh src/README.txt $D/
chmod +x $D/mine.sh $D/xmrig/xmrig $D/tor/tor
(cd $D && sha256sum $(find . -type f ! -name SHA256SUMS | sed 's#^\./##' | sort) > SHA256SUMS)
(cd stage && tar czf ../Bitflash-Miner-$V-linux.tar.gz Bitflash-Miner-$V-linux)

ls -la Bitflash-Miner-$V-*
sha256sum Bitflash-Miner-$V-*
