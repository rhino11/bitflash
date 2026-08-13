# Bitflash `.btf` Rendezvous Protocol

This is the specification of how Bitflash nodes reach each other, and how miners
reach pools, without revealing an IP address and without any central directory.
It documents the protocol as implemented in `src/btfaddr.cpp`, `src/btfchan.cpp`,
`src/btfrv.cpp`, `src/btftunnel.cpp` and `src/nostr.cpp`.

The design is ported from the Itzal hidden service design. A `.btf` address names
a public key, a node proves ownership of that key by signing a service
descriptor, other nodes find the descriptor over Nostr, and the two sides then
meet through an untrusted relay over an end to end encrypted tunnel. The relay
carries ciphertext only and never learns the plaintext.

## 1. Overview

A connection to a `.btf` service has three layers:

1. **Discovery (Nostr).** The service publishes a signed descriptor as a Nostr
   event. A caller fetches it by the service public key and verifies the
   signature. The descriptor says which rendezvous relay the service is waiting
   at, which encryption key to use, and optionally which Tor hidden service can
   be dialed directly.
2. **Rendezvous (TCP).** Caller and service both connect out to the same relay
   and are paired by public key. Neither needs an inbound port or a public IP.
   After pairing the relay is a blind byte pipe.
3. **Direct onion fallback bypass.** If the descriptor carries a valid signed
   `.onion:port` endpoint and the caller is running with Tor mode, the caller
   tries that endpoint before using rendezvous. This removes the rendezvous
   relay from the data path for peers that choose to run hidden services.
4. **Encrypted channel (X25519 + XChaCha20-Poly1305).** Over the paired pipe the
   caller and service run an ephemeral to static handshake and then exchange
   authenticated frames. The relay sees only ciphertext.

The caller ends up holding an ordinary local socket that behaves like a direct
TCP connection to the peer. The node treats it exactly like any other peer
socket.

## 2. Identities and keys

A node holds two independent keypairs.

- **Signing / identity key**: a secp256k1 x-only key (BIP340 Schnorr). This is
  the `.btf` identity and also the node's Nostr identity. Persisted in
  `nostr.key`.
- **Encryption key**: an X25519 (Curve25519) keypair. Persisted in
  `btf_enc.key`. Its public half is published in the descriptor as `enc` and is
  used for the tunnel key agreement.

The identity key names the service and authenticates the descriptor. The
encryption key secures the tunnel. They are separate so the long term identity
never performs Diffie-Hellman and the encryption key can be rotated in a new
signed descriptor.

## 3. The `.btf` address

An address is the identity public key plus a short checksum, Base32 encoded, with
the suffix `.btf`.

```
label   = Base32( pubkey[32] || checksum[2] )
address = label + ".btf"
```

- `pubkey` is the 32 byte secp256k1 x-only public key.
- `checksum` is the first two bytes of `SHA256(".btf-checksum-v1" || pubkey)`.
- Base32 uses the lowercase alphabet `abcdefghijklmnopqrstuvwxyz234567`, no
  padding. The 34 byte payload encodes to 55 characters.
- Parsing is case insensitive, trims surrounding whitespace, and strips a
  trailing dot. A wrong checksum is rejected.

The address is self certifying: it *is* the public key, so no registry has to be
trusted to map a name to a key.

## 4. Discovery over Nostr

Nodes publish and read three kinds of parameterized replaceable Nostr events.
Parameterized replaceable means the newest event for a given author and `d` tag
supersedes the older one, so a descriptor is always the latest state.

| Purpose | kind | `d` tag |
|---|---|---|
| Service descriptor | 38501 | `btf-descriptor-2` |
| Rendezvous relay announcement | 38502 | `btf-relay-2` |
| Pool announcement | 38503 | `btf-pool-2` |

The Nostr event is signed with the node's identity key, so the event author
equals the `.btf` public key. That binds the descriptor to the address at the
Nostr layer, and the descriptor is *also* signed inside its own content (see
below), so a relay operator cannot forge or swap a descriptor for an address it
does not control.

**Resolving an address.** To reach `X.btf`, a caller parses the address to the 32
byte key and sends a Nostr `REQ` filtered by `authors = [X]`, `kinds = [38501]`,
`#d = ["btf-descriptor-2"]`, `limit = 1`. It verifies the returned descriptor and
uses its `meeting_node` and `enc`.

**Relay auto discovery.** A relay operator runs a rendezvous relay and publishes a
kind 38502 event carrying `host:port`. Every node that reads it adds the relay to
the set it can register at and dial through. No seed list edit or maintainer
approval is needed. A small curated seed list is still shipped for bootstrap:

```
92.246.128.180:8434
31.44.4.249:8434
90.156.222.107:8434
```

The default rendezvous port is `8434`.

## 5. The service descriptor

The descriptor is a JSON object, signed with the identity key over a domain
separated digest of its own fields.

Legacy descriptor:

```json
{
  "v": 2,
  "pubkey": "<hex 32-byte x-only identity key>",
  "enc": "<hex 32-byte X25519 public key>",
  "meeting_node": "host:port",
  "created": <unix seconds>,
  "sig": "<hex 64-byte BIP340 Schnorr signature>"
}
```

Onion-capable descriptor:

```json
{
  "v": 3,
  "pubkey": "<hex 32-byte x-only identity key>",
  "enc": "<hex 32-byte X25519 public key>",
  "meeting_node": "host:port",
  "onion": "<56-char-v3-name>.onion:8433",
  "created": <unix seconds>,
  "sig": "<legacy v2 signature>",
  "sig3": "<signature over the onion-capable digest>"
}
```

The legacy signed digest is:

```
digest = SHA256( ".btf-descriptor-v2"
               || pubkey[32]
               || enc            (raw bytes of the string)
               || meeting_node   (raw bytes of the string)
               || created        (8 bytes, big endian) )
```

`sig` is kept on v3 descriptors so old nodes can still resolve and dial through
the rendezvous relay. The onion-capable digest is:

```
digest3 = SHA256( ".btf-descriptor-v3-onion"
                || pubkey[32]
                || enc            (raw bytes of the string)
                || meeting_node   (raw bytes of the string)
                || onion          (raw bytes of the normalized string)
                || created        (8 bytes, big endian) )
```

`sig` and `sig3` are deterministic BIP340 Schnorr signatures (no auxiliary
randomness) over their respective digests by the identity key.

**Verification** (untrusted input, must never throw): parse the JSON, require all
fields with the right types, confirm `pubkey` equals the address being resolved,
recompute the digest, and verify the Schnorr signature. Any failure rejects the
descriptor.

If `onion` is present, readers accept it only when it is a normalized v3 onion
endpoint and `sig3` verifies. A bad or tampered onion field is ignored; the v2
descriptor can still be used for rendezvous fallback if `sig` verifies.

`created` lets a reader prefer the freshest descriptor when more than one is
seen. A node without a direct onion endpoint only publishes a descriptor once it
has actually registered at a `meeting_node`, so it never advertises a relay it
cannot be reached at. A node with a direct onion endpoint may publish before
rendezvous registration using `meeting_node = "rendezvous-pending"`; Tor peers
can still dial the signed onion endpoint, and rendezvous becomes fallback once
registration succeeds.

## 6. Rendezvous transport

The relay is a small TCP server. Every connection opens with a fixed 33 byte
header:

```
byte 0     role: 'S' (service) or 'C' (client)
bytes 1..32 target public key (the .btf identity, 32 bytes)
```

**Service registration (`S`).** The service connects out to the relay and sends
`'S' || own_pubkey`. The relay stores the connection in a table keyed by the
public key and leaves it open, waiting. There is one slot per key: a new
registration for the same key replaces and closes the old one. The service does
not block waiting to be paired at registration time; it is considered registered
the moment the relay reads the header, which is what lets it publish a descriptor
pointing at this relay.

**Client dial (`C`).** The caller connects out to the same relay and sends
`'C' || target_pubkey`. The relay looks up the waiting service:

- If present, it removes it from the table, writes a single `0x01` byte to both
  sockets, and then forwards raw bytes in both directions until either side
  closes. From this point the relay is a blind pipe.
- If absent, it writes `0x00` to the caller and closes.

Both sides connect *outbound* to the relay, so neither needs a public IP or an
open inbound port. The relay never sees the identity of the caller (the caller
sends no key of its own, only the target it wants).

**Liveness.** A registration socket is idle by design and can outlive the network
path that created it (a NAT drops the idle mapping, the relay restarts, a route
changes) with no FIN and nothing readable. TCP keepalive was measured and does
not reliably detect this. The service therefore imposes its own timeout on the
wait for the pairing byte and re-registers on expiry. Expiring is not a failure;
it costs one reconnect per interval and returns the loop to a known state.

## 7. The encrypted channel

Once paired through the relay, the caller and service run an end to end handshake
and then exchange authenticated frames. The primitive is libsodium
`crypto_box_curve25519xchacha20poly1305` (X25519 key agreement, XChaCha20-Poly1305
AEAD), the same construction as Rust's `crypto_box` ChaChaBox.

**Handshake (ephemeral to static).**

1. The caller generates a fresh ephemeral X25519 keypair, computes
   `shared = X25519(eph_sk, service_enc_pub)` reduced to a box key
   (`crypto_box_beforenm`), and sends the 32 byte ephemeral public key over the
   paired pipe.
2. The service reads the ephemeral public key and computes the same
   `shared = X25519(enc_sk, eph_pub)`.

Because the caller uses a new ephemeral key per connection, each session has an
independent key and forward secrecy against later compromise of the service
encryption key.

**Framing.** Every message is length prefixed:

```
frame = len[4]  (big endian, length of the body that follows)
        body    = nonce[24] || ciphertext || mac[16]
```

The nonce is 24 random bytes per frame (XChaCha20), the MAC is 16 bytes
(Poly1305). A body shorter than `nonce + mac` or larger than 1 MiB is rejected.
Decryption that fails authentication drops the frame and tears the tunnel down.

The tunnel is transparent: the application is handed a local socket pair end and
reads and writes plaintext. Two pump threads move data between that socket and
the relay socket, encrypting outbound and decrypting inbound.

## 8. End to end connection flow

To dial `X.btf`:

1. Parse `X.btf` to the 32 byte identity key.
2. Fetch and verify the descriptor over Nostr (kind 38501). Obtain
   `meeting_node` and `enc`.
3. Connect to `meeting_node`, send `'C' || X`, and wait for `0x01`.
4. Generate an ephemeral X25519 key, derive the shared key against `enc`, send
   the ephemeral public key.
5. Exchange XChaCha20-Poly1305 frames. Hand the application a local socket that
   speaks the ordinary peer protocol.

A service, symmetrically: registers at a relay (`'S' || own_pubkey`), publishes a
descriptor pointing at that relay, waits for `0x01`, reads the caller ephemeral
public key, derives the shared key with its encryption secret, and serves the
tunnel.

## 9. Security properties

- **Address unforgeability.** The address is the identity key and the descriptor
  is Schnorr signed by it, and the Nostr event is signed by it. A relay or Nostr
  operator cannot publish a working descriptor for an address it does not own.
- **Relay confidentiality.** The relay forwards ciphertext and never holds the
  channel key. It cannot read or modify traffic undetected; a tampered frame
  fails the Poly1305 tag and the tunnel closes.
- **Caller anonymity to the service and relay.** The caller presents no identity
  key, only the target it wants to reach. It connects outbound, so its address is
  not published anywhere.
- **Forward secrecy.** The caller's per connection ephemeral key means a later
  compromise of the service encryption key does not decrypt past sessions.
- **IP privacy.** Neither side needs a public IP or an inbound port for
  rendezvous. With a signed `.onion` endpoint, the reachable side exposes only a
  Tor hidden service and the relay is not in the peer connection path.

## 10. Threat model and limitations

- **The relay is trusted for availability, not for confidentiality.** It can
  refuse to pair, drop a connection, or go offline. This is why relays are
  plural, auto discovered, and re-registration is periodic. It cannot read
  traffic.
- **Traffic analysis is not addressed.** A network observer, or the relay, can
  see connection timing and byte volumes. There is no padding or mixing.
- **Single slot registration causes churn.** One waiting slot per key per relay
  means a race or a stale registration can briefly make a service unreachable at
  that relay. Multiple relays and the wait timeout bound the damage, but this is
  a known source of connection churn.
- **Descriptor freshness is best effort.** `created` is a self reported
  timestamp; readers prefer the newest descriptor they have seen but there is no
  global clock.
- **Discovery depends on public Nostr relays.** If the relays a node uses are all
  unreachable, discovery stalls until one is reachable again. Relay TLS is
  verified, which closes a man in the middle path on discovery, but availability
  still rests on the relay set.
- **Direct onion needs Tor.** With `-managedtor`, Bitflash starts a Tor process,
  writes a local hidden-service config, and advertises the generated onion
  endpoint. With `-onionservice`, an operator can still run Tor manually and
  provide the endpoint. In both cases Tor owns the hidden-service private key and
  uptime.

## 11. Wire reference

| Item | Value |
|---|---|
| `.btf` Base32 alphabet | `abcdefghijklmnopqrstuvwxyz234567`, no padding |
| Address payload | `pubkey[32] || checksum[2]`, 55 Base32 chars |
| Address checksum | `SHA256(".btf-checksum-v1" || pubkey)[0..2]` |
| Descriptor domain sep | `.btf-descriptor-v2`; optional onion sep `.btf-descriptor-v3-onion` |
| Descriptor version | `2`; `3` when a signed onion endpoint is present |
| Descriptor signature | BIP340 Schnorr, deterministic (no aux rand), v3 keeps `sig` plus `sig3` |
| Nostr descriptor event | kind `38501`, `d = btf-descriptor-2` |
| Nostr relay event | kind `38502`, `d = btf-relay-2` |
| Nostr pool event | kind `38503`, `d = btf-pool-2` |
| Rendezvous port (default) | `8434` |
| Rendezvous header | `role[1] ('S'/'C') || pubkey[32]`, 33 bytes |
| Rendezvous pairing byte | `0x01` paired, `0x00` no service |
| Channel primitive | `crypto_box_curve25519xchacha20poly1305` |
| Nonce / MAC / key sizes | 24 / 16 / 32 bytes |
| Frame | `len[4 big endian] || nonce[24] || ct || mac[16]` |
| Max frame body | 1 MiB |
