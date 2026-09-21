# btfchat — messaging that burns

*Design document, 2026-09-18. Nothing here is implemented yet; the parts that
exist in the tree are named where they do. Status of each phase is at the end.*

## What it is

A messenger inside the Bitflash wallet where the identity is a `.btf`
address, the transport is the Bitflash P2P network over Tor, and every message
**burns** a little BTF. No server, no phone number, no e-mail, no IP address
anywhere in the system — not even ours. Sending a message makes the coin
scarcer for everyone who holds it.

Why burn rather than pay the recipient: paying the recipient makes it
profitable to spam yourself, and makes the recipient a party with something
to hide. Burning benefits no one in particular and everyone a little, and the
burn transaction reveals nothing but "someone burned this much at this time".

## Threat model

Protect, in this order:

1. **Who talks to whom, and when.** End-to-end encryption is table stakes;
   every messenger has it, and every one of them still knows the graph. This
   design treats metadata as the secret.
2. **Content**, against anyone, now and after quantum computers.
3. **The past**, when a device or a key is taken later.
4. **Deniability**: a transcript proves nothing to a third party.

Not protected: an endpoint that is already compromised, and a user who
publishes their `.btf` address next to their name.

## Identity

The `.btf` address the node already generates (`btfaddr.cpp`): a public key
encoded as an address, self-certifying, nothing to register. A person is a
key. Reachability is separate from identity (below), so knowing someone's
address tells you nothing about where their node is.

## Transport

The node's existing encrypted channels between `.btf` addresses over Tor
(`btfchan.cpp`), extended with four properties:

- **Sealed sender.** The outer envelope names only the recipient's channel.
  Who sent it is inside the encrypted payload. Relaying nodes see a recipient
  and a burn stamp, nothing else.
- **Fixed size.** Every envelope on the wire is exactly 4,096 bytes, padded;
  a three-letter reply and a small image look the same. Longer messages are
  several envelopes with no visible relation between them.
- **Cover traffic.** Every participating node emits envelopes at a constant
  rate whether it has anything to say or not; real and dummy envelopes are
  indistinguishable to anyone but the recipient. An observer of the whole
  network sees a uniform hum (the Loopix/Nym idea, without the company).
- **Ephemeral onions.** Each conversation gets its own hidden service, created
  for it and discarded after. Even Tor cannot link one contact of yours to
  another; the node's main onion is never tied to chat.

Delivery to a peer that is offline is **store-and-forward by the nodes of the
network**, with the burn buying the time (next section). No mailbox server:
the same nodes that carry blocks carry envelopes.

## The burn stamp

Every envelope references a transaction with an `OP_RETURN` output — provably
unspendable, gone from the supply — of at least the network's minimum burn.
The stamp is what a node checks before it relays or stores: no valid stamp,
no relay. This is Hashcash paid in coin rather than in hashing, seventeen
years after the whitepaper cited it.

What the stamp buys, beyond relay:

- **Spam is priced out.** A fraction of a cent per message is nothing to a
  person and a fortune to a bot sending millions.
- **Your inbox has a price.** Each user sets the minimum burn required to
  reach them; approved contacts get a lower floor, strangers a higher one.
  Interrupting you costs.
- **Storage.** Nodes hold an envelope for an offline recipient for as long as
  the burn paid for, on a published price per byte-hour. Bigger burn, longer
  patience.
- **Key anchoring** (next section): the stamp of the first message in a
  conversation carries the hash of the handshake.

The minimum burn is a relay policy, not consensus: nodes agree on it the way
they agree on minimum fees, and it can move.

## Cryptography

Nothing invented. The strongest published components, combined under the
threat model above:

- **Handshake: PQXDH** — X25519 plus **ML-KEM-1024** (Kyber, NIST FIPS 203),
  hybrid, so that breaking either one alone breaks nothing. What Signal
  deployed in 2023, with the larger parameter set. Messages recorded today do
  not open on a quantum computer later.
- **Session: double ratchet** — a fresh key for every message, in both
  directions; compromise of a key opens neither the past nor the future.
- **Cipher: XChaCha20-Poly1305** from libsodium, which the node already links.
- **Authentication by MAC, not signature** (the OTR property). The recipient
  knows the message is from you; nobody can prove it to anyone else. The
  transcript is worthless as evidence.
- **Key verification against the chain.** The unsolved problem of every
  messenger is the first contact: whose key is this? Here the burn stamp of
  the first message carries `Hash(handshake public values)`. Both sides check
  the chain. An attacker in the middle would have to rewrite a block. The
  safety-number ritual becomes: look at a block. Optional QR verification
  stays for those who want it.
- **Nothing kept.** Ratchet keys are erased as they are used; nodes drop
  envelopes at their TTL; local history is encrypted under the wallet's
  passphrase and can be set to expire.

## Money is a message

An envelope may carry a transaction. "Here is 5" is a line of chat; the
payment travels inside the encrypted payload and is broadcast when the
recipient opens it, or by the sender at once, their choice. A 2-of-3 escrow
between buyer, seller and arbiter is negotiated in the conversation the three
share, with `createmultisig`/`signrawtransaction` (1.2.28) underneath. Not a
chat with payments: the wallet, talking.

## Communities

Public, many members, no secrecy of content among strangers — what is
protected is who writes and who reads. A community is a channel key; posting
to it is broadcasting an envelope to it.

- **Joining burns; posting burns.** The creator sets both prices. This is the
  only moderation that works without identities: an anonymous troll cannot
  be banned, but can be made to pay for every line.
- **Reputation without identity.** What an address has burned in a community
  is on the chain. Seniority is investment, not followers.
- **Nothing to take down.** No owner, no server, no terms of service. The
  community exists on the nodes for as long as someone burns to keep it.
- **Paid reading**, optionally: a channel may require a burn to read, and the
  author may require a payment to themselves besides. A newsletter, a leak, a
  paper, where neither writer nor readers are known.

## Groups

Private, up to about a thousand members, real secrecy. **MLS** (RFC 9420):
a key tree, membership changes rotate the key in O(log n), designed with
post-quantum in mind, the standard the large messengers have moved to. Each
group message is an envelope like any other — burn, fixed size, sealed sender;
a relaying node cannot tell a group message from a private one.

Administration is not an account: it is a **multisig key** of the founders.
Group rules change only with their signatures, and no server exists that could
remove an admin.

## Clients

One protocol, three faces:

- **The wallet window** (Windows, Linux, macOS): a `btfchat` tab beside the
  balance — contacts on the left, conversation on the right, "attach BTF"
  next to send. Installing the chat is installing the wallet.
- **RPC** for headless nodes, bots and Termux: `chatsend`, `chatlist`,
  `chatread`, `chatburn`.
- **Android**: the native app, on the ARM64 node that already runs on a phone
  (2026-09-18). No Google/Apple push — the node keeps its Tor circuit and
  receives directly.

No browser client, by design: a web page needs a server or a local one behind
it, and a browser leaks (cache, extensions, WebRTC).

## What is ours

Most of the above is assembly of proven parts. Three things exist nowhere
else and cannot be copied without rebuilding the project: the **burn
economy** (spam, inbox price, storage and scarcity from one mechanism), the
**key anchored in the chain**, and **the wallet that talks** (money inside the
envelope, escrow in the conversation). All three exist because the messenger
and the coin are the same program on a network that only speaks Tor.

## Phases

| phase | scope | depends on |
|---|---|---|
| 0 | `OP_RETURN` standard in relay policy; burn stamp format; `docs` | 1.2.28 (relay policy only, no consensus) |
| 1 | one-to-one: PQXDH + ratchet + MAC auth, sealed sender, fixed size, burn stamp, chain-anchored handshake, money in messages; wallet tab + RPC | rules v3 shipped; ~3 weeks after |
| 2 | communities: channels, join/post burns, paid reading, reputation | phase 1 |
| 3 | cover traffic, ephemeral onions per conversation, node storage market | phase 1 |
| 4 | groups (MLS, multisig admins) | phase 1; OpenMLS or an equivalent integrated |
| 5 | Android client | the native app |

## Open questions

- The minimum burn, and how it moves: fixed in policy, or a median of recent
  stamps like fee estimation. Too low and spam returns; too high and nobody
  talks.
- Cover traffic costs bandwidth and, on phones, battery; the rate must be
  tunable per client, which weakens the guarantee for those who tune it down.
- Store-and-forward pricing: what a node charges per byte-hour, and how a
  sender learns it.
- ML-KEM-1024 handshakes are about 3 KB; that fits one envelope with room to
  spare, but a ratchet with post-quantum re-keying on every message does not.
  Hybrid re-keying on a schedule (Signal's approach) is the likely answer.
- Deniability and the chain anchor pull in opposite directions: the anchor
  proves a handshake happened, not who did it. Whether that is enough
  deniability is a question for the people who need it most.
