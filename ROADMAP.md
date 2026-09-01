# Lightning from scratch, in Common Lisp

A full Lightning node, built bottom-up in SBCL on top of
[cl-consensus](../cl-consensus)'s Bitcoin engine. Going all the way: the
encrypted transport, the peer protocol, channel state machines, commitment
transactions, onion routing, gossip, and invoices — nothing wrapping LND or
Core Lightning.

## Guiding principle: verify against a real node at every layer

The same principle as cl-consensus, applied to a different stack. We run a
**private signet devnet** at `/mnt/lisp/signet` with three Lightning nodes across
two independent implementations:

- **cln1, cln2** — Core Lightning v26.06.7
- **lnd1** — LND v0.21.2-beta
- **bitcoind** — Core v29.1 on a signet whose block-signing key we hold

Two implementations is deliberate. CLN and LND disagree in small, legal ways —
feature-bit negotiation, gossip timing, which optional TLVs they send — and a
from-scratch BOLT stack tested against only one of them ends up encoding that
one's reading of the spec. Every phase below has a milestone checkable against
*both*.

The devnet mines on demand (`./mine.sh 6` ≈ 2 seconds), so the confirmation
waits that dominate Lightning testing cost seconds instead of hours. cl-consensus
validates this chain natively (signet + BIP325), so the same chain is ground truth
for both projects. See `/mnt/lisp/signet/README.md`.

## Layers

```
crypto.lisp     Phase 0  HKDF, ChaCha20-Poly1305, ECDH                 [DONE]
wire.lisp       Phase 0  BigSize, TLV, message envelope, big-endian IO [DONE]
transport.lisp  Phase 1  BOLT #8 Noise_XK handshake + framing          [DONE]
features.lisp   Phase 2  BOLT #9 feature bits and negotiation           [DONE]
peer.lisp       Phase 2  init/ping/pong/error + the async read loop     [DONE]
gossip.lisp     Phase 3  BOLT #7 channel/node announcements, routing graph
channel.lisp    Phase 4  BOLT #2 open/accept, funding, commitment_signed
commitment.lisp Phase 5  BOLT #3 commitment + HTLC transactions, key derivation
onion.lisp      Phase 6  BOLT #4 Sphinx onion construction and peeling
invoice.lisp    Phase 7  BOLT #11 invoice encode/decode
onchain.lisp    Phase 8  BOLT #5 force-close, penalty, HTLC timeout/success
```

---

## Phase 0 — primitives and wire format  **[DONE]**

HKDF (RFC 5869), ChaCha20-Poly1305 (RFC 8439) assembled from ironclad's separate
ChaCha20 and Poly1305, ECDH over secp256k1-fast. BOLT #1 readers/writers,
BigSize, TLV streams, message envelope.

**Milestone — met.** 89 offline checks pass against the RFCs' and BOLT #1's own
vectors, including non-canonical BigSize rejection and TLV ordering rules.

## Phase 1 — BOLT #8 transport  **[DONE]**

Noise_XK over secp256k1/ChaChaPoly/SHA-256. Three acts, encrypted length
framing, key rotation every 1000 messages.

**Milestone — met.** The spec's initiator, responder and key-rotation vectors all
reproduce exactly (`inspect/transport-test.lisp`), *and* `inspect/live-peer.lisp`
completes a real handshake against both cln1 and lnd1, exchanging BOLT #1 `init`
and decoding CLN's gossip that follows.

## Phase 2 — the peer protocol  **[DONE]**

BOLT #9 feature bits with the required/optional pairing and dependency rules;
`init` with the networks TLV; `ping`/`pong` with the length rules;
`error`/`warning`; and an async read loop in the shape of cl-consensus's
`peer.lisp`.

**Milestone — met.** cl-payments stays connected to both cln1 and lnd1, answers
pings, and `lightning-cli listpeers` shows it as a connected peer.

Three things this phase taught, each of which cost a debugging session:

- **Advertising no features is not neutral, it is fatal.** LND closes the
  connection immediately after `init` and says nothing. We now advertise the five
  both implementations mark required — `data_loss_protect`, `var_onion_optin`,
  `static_remotekey`, `payment_secret`, `channel_type` — as *odd* bits: honest
  about what we can speak, without demanding the peer treat any of it as
  mandatory.

- **The connect-time socket timeout must be cleared before the read loop.** A
  Lightning connection is idle most of the time, so an inherited read timeout
  kills the loop on the first quiet gap — and it presents as *the peer dropped
  us* when in fact we dropped the peer. cl-consensus's peer layer has the same
  fix for the same reason.

- **The `networks` TLV is load-bearing.** Send the wrong chain hash and CLN
  rejects the connection with `No common network`. That is the TLV working: a
  clear failure at `init` rather than a confusing one at the first channel. LND
  is laxer and stays connected, so testing against a single implementation would
  have hidden it.

## Phase 3 — gossip and the routing graph

BOLT #7 `channel_announcement`, `channel_update`, `node_announcement`; signature
validation on each; `query_channel_range` / `gossip_timestamp_filter`. Build the
routing graph and find paths.

**Milestone.** Our graph of the devnet matches `lightning-cli listchannels` and
`lncli describegraph` exactly — same channels, same policies, same directions.
The devnet's topology is known by construction, which makes this diffable.

## Phase 4 — channels

BOLT #2: `open_channel`/`accept_channel`, `funding_created`/`funding_signed`,
`channel_ready`, then the HTLC lifecycle (`update_add_htlc`,
`commitment_signed`, `revoke_and_ack`) and `shutdown`/`closing_signed`.

**Milestone.** Open a channel from cl-payments to cln1, confirm it with
`./mine.sh 6`, and have CLN report it as `CHANNELD_NORMAL`. Then the same
against lnd1.

## Phase 5 — commitment transactions

BOLT #3: the per-commitment secret chain, key derivation
(`localpubkey`/`revocationpubkey`/…), to-local and to-remote outputs, HTLC
outputs and their timeout/success transactions, anchor outputs.

This is where cl-consensus does the heavy lifting: every commitment transaction
is a Bitcoin transaction our own script interpreter can validate, and every
signature is checked by our own secp256k1.

**Milestone.** BOLT #3's test vectors reproduce byte-for-byte, and a commitment
transaction we build validates under cl-consensus's script interpreter.

## Phase 6 — onion routing

BOLT #4 Sphinx: construct a 1300-byte onion, peel a layer, handle the error
onion. Constant-size routing packets with per-hop keys.

**Milestone.** BOLT #4's vectors reproduce, and a payment we onion-route reaches
lnd1 through cln2 — the same path `smoke.sh` proves works between the
implementations.

## Phase 7 — invoices

BOLT #11 bech32 invoice encode/decode, including the signature and the tagged
fields. cl-consensus's `encoding.lisp` already has bech32.

**Milestone.** Decode invoices produced by both CLN and LND; produce invoices
both of them accept and pay.

## Phase 8 — on-chain handling

BOLT #5: watch for commitment transactions on chain, sweep to-local after the
CSV delay, penalise a revoked commitment, resolve HTLCs by timeout or preimage.

**Milestone.** Force-close from cl-payments and sweep correctly; and separately,
publish a revoked commitment on the devnet and confirm the counterparty
penalises us — the one test that is genuinely dangerous anywhere but here.

---

## Non-goals (for now)

Watchtowers, dual funding, splicing, BOLT #12 offers, trampoline routing. Each is
worth doing; none is worth doing before a channel can be opened and a payment
routed end to end.

## Status

Phases 0–2 are done and verified against both the spec vectors and two live
implementations: 142 offline checks, and a connection that both Core Lightning
and LND accept and keep. Phase 3 (gossip and the routing graph) is next.

One finding already waiting for it: LND enforces **strictly increasing
short-channel-ids** during the BOLT #7 channel-range sync and disconnects a peer
whose reply doesn't satisfy it — it does this to CLN on the devnet today. Our
gossip must get that ordering right.
