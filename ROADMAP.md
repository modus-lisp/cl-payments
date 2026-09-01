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
gossip.lisp     Phase 3  BOLT #7 announcements, signatures, routing graph [DONE]
channel.lisp    Phase 4  BOLT #2 open/accept, funding, commitment_signed
keys.lisp       Phase 4  BOLT #3 per-commitment key derivation           [DONE]
commitment.lisp Phase 5  BOLT #3 commitment + HTLC transactions
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

## Phase 3 — gossip and the routing graph  **[DONE]**

BOLT #7 `channel_announcement`, `channel_update`, `node_announcement`, with
signature validation on every one; short-channel-id packing;
`gossip_timestamp_filter`, `query_channel_range` and `query_short_channel_ids`;
and the routing graph they build.

**Milestone — met.** `inspect/graph-diff.lisp` connects to a live node, asks for
its whole gossip stream, verifies every signature itself, and diffs the resulting
graph against `lightning-cli listchannels` field by field — destination, base
fee, proportional fee, CLTV delta, and both HTLC bounds, per direction. 26 checks,
0 failures, 0 signature rejections. Run against **both** implementations: the
graph built from LND's gossip matches CLN's view exactly, and vice versa.

Counts alone would have proved little; the interesting failures are in the policy
fields, where a misread offset still yields a plausible number.

- **`channel_announcement` carries four signatures**, and all four are checked.
  Two node keys agree the channel exists; two *bitcoin* keys — the ones in the
  funding output's 2-of-2 — agree as well. Drop the bitcoin pair and anyone can
  announce a channel over someone else's UTXO.
- **A `channel_update` for an unannounced channel is rejected**, not stored on
  trust: without the announcement we do not know whose key should have signed it.
- **The scid ordering rule is enforced in both directions.** We sort on the way
  out and reject an unsorted `reply_channel_range` on the way in — this is the
  rule LND disconnects CLN over on the devnet.

Not yet done: pathfinding. The graph is built and verified; choosing a route
across it belongs with Phase 6, where there is something to route.

## Phase 4 — channels

BOLT #2: `open_channel`/`accept_channel`, `funding_created`/`funding_signed`,
`channel_ready`, then the HTLC lifecycle (`update_add_htlc`,
`commitment_signed`, `revoke_and_ack`) and `shutdown`/`closing_signed`.

**The phase ordering below was wrong and has been corrected in practice.** BOLT
#2 sits *on top of* BOLT #3, not beside it: `funding_created` carries a signature
over the peer's first commitment transaction, so the commitment keys and the
transaction itself must exist before the message can be sent at all. BOLT #3 is
therefore being built first, starting with key derivation.

### 4a — key derivation  **[DONE]**

`src/keys.lisp`: per-commitment blinding, the revocation key, per-commitment
secret generation, and the O(log n) store for revoked secrets.

**Verified** against BOLT #3's published vectors (Appendices D and E) — all five
reproduce. But the vectors only pin PUBLIC values, so the gate also checks the
algebra: that each private key actually inverts its public counterpart. Breaking
only `derive-revocation-privkey` passes every published vector and is caught by
exactly one check. That failure mode is the worst one available here — the
channel works, states get revoked, and the punishment branch that gives
revocation its meaning is silently unspendable.

### 4b — commitment transactions  **[DONE]**

`src/commitment.lisp`: the funding 2-of-2, `to_local` and `to_remote` scripts,
the obscured commitment number, fees, dust, BIP69 ordering, and the commitment
transaction itself.

**Verified** byte-for-byte against Appendix C's "simple commitment tx with no
HTLCs". That single equality covers script construction, key sorting, the
commitment number hidden across the locktime and sequence, the fee, the dust
rule and output ordering — any one wrong and the bytes differ.

This is where **cl-consensus becomes a dependency**. Everything before it was
Lightning's own wire format and could stand alone; a commitment is a Bitcoin
transaction, and the premise of the project is that we validate it with our own
consensus engine rather than trusting that what we built is spendable.

HTLC outputs, trimming and signing are done too. Reproduced from Appendix C:
the offered and received HTLC scripts, the five-HTLC commitment transaction
(seven outputs, correct BIP69 order), and `local_signature` itself — which
exercises BIP143 (with the funding amount in the digest) and RFC6979
deterministic nonces at once, since a wrong digest or nonce gives a different
but still valid signature.

Trimming is not "amount below the dust limit". It is the amount **minus the fee
of the second-stage transaction** that would claim it, and offered and received
HTLCs use different weights (663 vs 703) — so the same amount can be trimmed in
one direction and not the other.

`build-commitment` now also returns the surviving HTLCs in **output order**.
`commitment_signed` carries one signature per HTLC in that order, and two offered
HTLCs with the same rounded amount and payment hash produce byte-identical
outputs — so the order is only recoverable from the CLTV tiebreak, and the caller
cannot reconstruct it.

The second-stage HTLC transactions are done as well — HTLC-success and
HTLC-timeout both reproduce from Appendix C, and so does `local_htlc_signature`.
Winning an HTLC does not hand you the money: it hands you another delayed,
revocable output, so an HTLC claimed from a revoked commitment is still
punishable.

Not done: anchor outputs (`option_anchors`), which is a feature we do not
negotiate. BOLT #3 is otherwise complete.

### 4c — the BOLT #2 messages, and a live channel open  **[DONE]**

`src/channel.lisp`: `open_channel`, `accept_channel`, `funding_created`,
`funding_signed`, `channel_ready`, and the channel id derivation.

**Milestone — met.** `inspect/open-channel.lisp` opens a real channel against
Core Lightning, which then reports `CHANNELD_NORMAL`. CLN verifies our signature
over the commitment transaction *it* will hold, so every piece of BOLT #3 —
key derivation, output construction, the fee, the obscured commitment number,
the BIP143 digest — is checked by an independent implementation at once.

The funding transaction is built but **not broadcast** until `funding_signed`
arrives. That ordering is the opener's only protection: the funding output is a
2-of-2, so broadcasting before holding a signature that returns the money lets an
uncooperative counterparty strand it forever.

Two things the live run taught:

- **`channel_type` is not optional.** A peer that advertises
  `option_channel_type` — CLN and LND both do — rejects an `open_channel`
  without the TLV, with `Did not set channel_type in open_channel message`. We
  send `option_static_remotekey`, which is what the commitment builder
  implements.
- **`option_static_remotekey` changes `to_remote`**: it is the payment basepoint
  verbatim, with no per-commitment blinding, so the peer can sweep it even from
  an outdated state.

**Milestone.** Open a channel from cl-payments to cln1, confirm it with
`./mine.sh 6`, and have CLN report it as `CHANNELD_NORMAL`. Then the same
against lnd1.

### 4c-bis — LND interop and reconnection  **[DONE]**

The milestone's "then the same against lnd1" clause. LND accepted our commitment
signature first try, with parameters materially different from CLN's —
`to_self_delay` 144 vs 6, `dust_limit` 354 vs 546 — which the commitment builder
handled without change.

`channel_reestablish` (type 136) is implemented. LND sends it on every reconnect
to a channel; before this, cl-payments simply never answered. LND tolerates the
silence and stays connected, but the channel is never resynced and so is
permanently unusable. Exchanged successfully against LND: its
`next_commitment_number 1`, `next_revocation_number 0`, secret all zeroes,
exactly as the spec prescribes for a channel that has revoked nothing.

**LND is a leaf, not a hop, and that is a config decision with a reason.** With
graph sync on, LND disconnects CLN over short-channel-id ordering and every link
flaps; with it off, LND never relays gossip and routes die at the LND hop. As a
leaf with sync off the links are stable, which is what BOLT #8/#1/#2 interop
needs.

### 4e — the daemon  **[DONE]**

`src/node.lisp` and `bin/cl-payments.lisp`: a process that listens, accepts
inbound connections, holds a peer registry, persists channel state, and answers
`channel_reestablish` and `announcement_signatures`.

Three things needed this and could not be faked with a script:

- **Inbound.** Core Lightning now dials *us*. That is the first time cl-payments
  has been the BOLT #8 responder against a real implementation rather than the
  initiator.
- **Reconnection.** The daemon answers `channel_reestablish` for an existing
  channel and CLN accepts it, replying `channel_ready` — the channel is resynced
  across a reconnect.
- **`announcement_signatures`.** Received for `258x1x0`. They arrive once the
  funding is buried, to a CONNECTED peer, so a script that exits after
  `channel_ready` can never see them. This was the concrete blocker on
  cl-payments ever being routable, and it is now cleared.

Channel state is written as s-expressions via a temp-file-and-rename, so a crash
mid-write leaves the previous good file: losing channel state means losing the
ability to claim your own money.

The thread rule from the loopback gate is load-bearing here. In SBCL a socket is
torn down when its creating thread exits, so `on-inbound` ends in
`run-read-loop` — becoming the connection's owner — rather than spawning a
reader and returning.

### 4f — announcing, and 4g — accepting  **[DONE]**

Our channels are in the routing graph, and Core Lightning can open channels TO
us.

`gossip.lisp` could only parse and verify; it now encodes `channel_announcement`,
`channel_update` and `node_announcement` too.  The asymmetry is the point: a
lenient parser accepts junk, but a wrong ENCODER gets you silently ignored by
the whole network — nobody replies "your announcement was malformed", the
channel simply never appears in anyone's graph.

`node.lisp` answers `open_channel` with `accept_channel`, verifies the
counterparty's signature over OUR first commitment before producing ours, and
replies to `channel_ready`.  Order matters there: their signature is what lets
us spend the funding output unilaterally, so sending `funding_signed` first
would risk a funding transaction we can never claim from.

Verified against Core Lightning on the devnet:

- `273x1x1` (we opened) and `291x1x0` (CLN opened to us) are both announced,
  with both directions active on nodes three hops away that have never spoken
  to us.  A real implementation checked our node signature AND our bitcoin
  signature and relayed the announcement on our behalf.
- `getroute` from cln1 finds a 3-hop path terminating at our node.
  cl-payments is a routable destination.

Channel keys are derived from the node key and an index rather than generated
randomly — `open-channel.lisp` had been generating them fresh, which made the
script the only thing holding half of a 2-of-2 over real funds.

### 5a — the forwarding decision  **[DONE]**

`src/forward.lisp`: BOLT #4 failure codes, our fee/CLTV policy, and the check
that decides whether to forward an HTLC.  No onion yet — peeling a layer tells
us WHAT the sender asked for, but whether that request is acceptable is a
policy question about our own channel, and it is the half where the money is.

Every check exists because skipping it loses funds:

- **Fee.** Our fee is the DIFFERENCE between the two HTLCs, fixed the instant we
  forward.  There is no later opportunity to collect, so an underpaying sender
  is asking us to subsidise them.
- **CLTV.** We must have strictly more time to claim the incoming HTLC than the
  downstream node has to claim the outgoing one.  Reverse that and they can sit
  on the preimage until our incoming HTLC expires and only then claim the
  outgoing one — we have paid and cannot collect.  That margin is exactly what
  `cltv_expiry_delta` is for.
- **Expiry vs the tip.** An HTLC near its deadline cannot be safely claimed
  on-chain, because a force-close needs confirmations we do not have time for.
  One far in the future locks our liquidity for weeks at no cost to the sender.

The failure FLAGS matter as much as the codes.  Marking a transient failure PERM
tells every sender to stop using our channel; omitting UPDATE on a fee change
means senders keep retrying with the old fee and never learn why.  The flags are
read off the code rather than tabulated, so a new code cannot be classified
inconsistently with its own number.

Validated against Core Lightning: `getroute` through our node pays 1001001 msat
to forward 1000000 with a CLTV margin of 40 — exactly what our formula says, and
the baseline every test in `forward-test.lisp` perturbs.

66 checks, 13 mutations, 13 killed — including "forward everything", which fails
24 of them.

### 4d — the HTLC lifecycle  **[PARTIAL]**

`src/updates.lisp`: `update_add_htlc`, `update_fulfill_htlc`, `update_fail_htlc`,
`commitment_signed`, `revoke_and_ack`, `update_fee`, and the state machine that
tracks what has been proposed, what is irrevocably committed, and whether a
revocation is outstanding.

The ordering discipline is the point, not the encodings:

- An HTLC's amount leaves the sender's balance when **proposed**, not when
  committed — it is in flight, belonging to neither side, and returns only if
  the HTLC fails.
- A fulfill is honoured only if the preimage really hashes to the payment hash,
  in **both** directions. Accepting an unproven claim gives money away; sending
  one pays out against nothing redeemable on chain.
- `commitment_signed` may not be sent while a `revoke_and_ack` is outstanding —
  the peer would hold two commitments with no way to say which it revoked.
- A commitment is never revoked before its replacement is signed. Revoking first
  leaves you holding nothing enforceable: the old state is punishable if you
  publish it and the new one is unsigned, so the balance is entirely at the
  counterparty's discretion.

**Not done, and this is the larger part.** The state machine is tested in
isolation; it has never driven a real channel. Making an actual payment needs:
re-signing the commitment on every update (both directions, with HTLC outputs
and their signatures), the `channel_reestablish` resync after a reconnect, and
BOLT #4's onion — `update_add_htlc` carries a 1366-byte onion packet that this
code can carry but not yet construct or peel. Until that exists, no payment can
move.

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

Phases 0–3 are done and verified against both the spec vectors and two live
implementations: 185 offline checks, a connection both Core Lightning and LND
accept and keep, and a routing graph that matches theirs exactly.

Phase 4 (channels) is next — the first phase where we put money at risk, and the
first that needs cl-consensus for more than a chain hash.
