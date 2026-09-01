# cl-payments

A from-scratch, clean-room **Lightning Network implementation in Common Lisp** —
the BOLT stack on top of [cl-consensus](../cl-consensus)'s Bitcoin engine.

It speaks BOLT #8's encrypted transport, frames BOLT #1 messages, and talks to
real Core Lightning and LND nodes. Nothing here wraps LND, Core Lightning, or
LDK: the Noise handshake, the AEAD construction, the wire format and the
cryptography are all re-implemented in Lisp, on the same secp256k1 that
cl-consensus differential-tests against Bitcoin Core.

## ⚠️ Status & disclaimer

**Early.** Phases 0–2 of the [ROADMAP](ROADMAP.md) are complete: the primitives,
the BOLT #1 wire format, the BOLT #8 transport, and the peer protocol. It can
connect to a real node and stay connected; it cannot yet open a channel, and so
there is no way to lose money with it — which is just as well, because this is
**unaudited research software**. Do not point it at mainnet.

## What works today

- **Crypto** — HKDF (RFC 5869), ChaCha20-Poly1305 (RFC 8439) assembled from
  ironclad's separate ChaCha20 and Poly1305, BOLT #8 ECDH over secp256k1-fast.
- **Wire** — BOLT #1 big-endian readers/writers, BigSize (with non-canonical
  rejection), TLV streams (with the ordering rules enforced), message envelope.
- **Transport** — BOLT #8 `Noise_XK`: all three acts, encrypted length framing,
  key rotation every 1000 messages.
- **Peer** — BOLT #9 feature bits (required/optional pairing, dependencies) and
  the BOLT #1 setup messages: `init` with the networks TLV, `ping`/`pong`,
  `error`/`warning`, and an async read loop.

**Verified against**: the RFCs' own vectors, BOLT #1's and BOLT #8's own vectors
(initiator, responder, and key rotation), the real feature vectors CLN and LND
emit, **and** live connections to Core Lightning v26.06.7 and LND v0.21.2-beta —
both of which accept us as a peer and keep the connection open.

```
$ sbcl --eval '(asdf:test-system "cl-payments")'
...
PASS — 146 checks
```

## Layout

```
cl-payments.asd     ASDF system
src/
  crypto.lisp       BOLT #8 primitives: HKDF, ChaCha20-Poly1305, ECDH
  wire.lisp         BOLT #1: readers/writers, BigSize, TLV, message envelope
  transport.lisp    BOLT #8: Noise_XK handshake + encrypted transport
  features.lisp     BOLT #9: feature bits and their negotiation rules
  peer.lisp         BOLT #1: init/ping/pong/error + the async read loop
inspect/
  harness.lisp      the tiny check/report harness every gate shares
  crypto-test.lisp  gate 1 — RFC 5869 / RFC 8439 vectors
  wire-test.lisp    gate 2 — BOLT #1 BigSize + TLV vectors
  transport-test.lisp  gate 3 — BOLT #8 handshake + key-rotation vectors
  peer-test.lisp    gate 4 — BOLT #9 features + BOLT #1 setup messages
  run-all.lisp      the full offline suite, one command
  live-peer.lisp    the live gate — a real handshake against a real node
ROADMAP.md          the phase plan and what each phase is verified against
```

Same shape as cl-consensus: `src/` for the node, `inspect/` for the gates, one
command to run everything offline and a separate live gate that needs a peer.

## Dependencies

A strict subset of cl-consensus's, deliberately — `secp256k1-fast` (the crypto),
`ironclad` (ChaCha20, Poly1305, SHA-256), `bordeaux-threads`, and `cl-transport`
(which gives us Tor dialing for `.onion` peers at no extra cost).

Notably absent: `pagetree`, `usocket`, `jzon`, `hunchentoot` — nothing here needs
a UTXO store or an HTTP server yet.

`secp256k1-fast` and `cl-transport` are not on Quicklisp, so they are vendored as
submodules under `deps/`:

```sh
git clone --recursive <url>       # already cloned?  git submodule update --init
export CL_SOURCE_REGISTRY="(:source-registry (:tree \"$PWD\") :inherit-configuration)"
```

**`secp256k1-fast` must be at a commit with `WITH-FRESH-CT-SCRATCH`.** Without
it, concurrent key derivation silently returns wrong points — see the note under
Testing. The build warns loudly if the dependency is too old.

## Testing

```sh
inspect/run-all.sh        # everything offline, in one command
```

Two kinds of gate. The **vector** gates check each layer against the RFCs' and
BOLTs' own published vectors. The **loopback** gate stands the whole stack up
against itself over a real socket — our initiator against our own responder —
and drives handshake, init, ping/pong, oversized payloads, key rotation past the
1000-message boundary, an idle period, and error propagation.

The loopback gate exists because every published vector is one-sided: BOLT #8
pins what an initiator *sends*, and nothing in it proves our responder can read
what our initiator writes. It found three bugs on its first run —

- **concurrent key derivation returning wrong points**, because
  `secp256k1-fast`'s constant-time scratch is module-level and the macro that
  looked like it protected them covers a disjoint set of buffers (fixed
  upstream; 1600/1600 wrong before, 0 after);
- **a socket torn down when its creating thread exited**, surfacing as a NIL
  buffer deep inside SBCL rather than anything about threads;
- **`noise-recv` holding the session lock while blocked on the socket**, so a
  read loop waiting for a message — i.e. nearly always — deadlocked every send.

`inspect/live-peer.lisp` is separate and needs a real node; CI does not run it.

## Quick start

```lisp
(asdf:load-system "cl-payments")
(asdf:test-system "cl-payments")     ; the offline gates
```

Connect to a real node (`CL_PAYMENTS_NETWORK` defaults to `signet`, matching the
devnet — the `networks` TLV must name the peer's chain or CLN rejects the
connection):

```sh
CL_PAYMENTS_PEER=<node_id>@127.0.0.1:9835 sbcl --load inspect/live-peer.lisp --quit
```

```
✓ BOLT #8 handshake + BOLT #1 init exchanged
  their node id matches the one we dialed: yes

  they advertise (15 bits set)
      bit   0  REQUIRED  DATA-LOSS-PROTECT
      bit   8  REQUIRED  VAR-ONION-OPTIN
      ...
  features we both support:
      DATA-LOSS-PROTECT  GOSSIP-QUERIES  VAR-ONION-OPTIN
      STATIC-REMOTEKEY   PAYMENT-SECRET  CHANNEL-TYPE

→ ping (asking for 32 bytes of pong padding)
← pongs received: 1
  still alive after 20s: yes
```

`lightning-cli listpeers` then shows us as a connected peer.

## The devnet

Development runs against a **private signet** at `/mnt/lisp/signet` — our own
chain, whose blocks only we can sign — with two Core Lightning nodes and one LND
node on it. `./status.sh` prints each node's `<node_id>@host:port`, which is
exactly what the live gate takes.

Blocks are mined on demand (`./mine.sh 6` ≈ 2 seconds), so the confirmation waits
that dominate Lightning testing cost seconds rather than hours. See
`/mnt/lisp/signet/README.md` for the harness and the several sharp edges of
standing up a chain that has never had a mempool.

## License

MIT.
