# cl-payments

A from-scratch, clean-room **Lightning Network implementation in Common Lisp** —
the BOLT stack on top of [cl-consensus](../cl-consensus)'s Bitcoin engine.

It speaks BOLT #8's encrypted transport, frames BOLT #1 messages, and talks to
real Core Lightning and LND nodes. Nothing here wraps LND, Core Lightning, or
LDK: the Noise handshake, the AEAD construction, the wire format and the
cryptography are all re-implemented in Lisp, on the same secp256k1 that
cl-consensus differential-tests against Bitcoin Core.

## ⚠️ Status & disclaimer

**Early.** Phases 0 and 1 of the [ROADMAP](ROADMAP.md) are complete: the
primitives, the BOLT #1 wire format, and the BOLT #8 transport. There are no
channels yet, and therefore no way to lose money with it — which is just as well,
because this is **unaudited research software**. Do not point it at mainnet.

## What works today

- **Crypto** — HKDF (RFC 5869), ChaCha20-Poly1305 (RFC 8439) assembled from
  ironclad's separate ChaCha20 and Poly1305, BOLT #8 ECDH over secp256k1-fast.
- **Wire** — BOLT #1 big-endian readers/writers, BigSize (with non-canonical
  rejection), TLV streams (with the ordering rules enforced), message envelope.
- **Transport** — BOLT #8 `Noise_XK`: all three acts, encrypted length framing,
  key rotation every 1000 messages.

**Verified against**: the RFCs' own vectors, BOLT #1's and BOLT #8's own vectors
(initiator, responder, and key rotation), **and** live handshakes against Core
Lightning v26.06.7 and LND v0.21.2-beta.

```
$ sbcl --eval '(asdf:test-system "cl-payments")'
...
PASS — 89 checks
```

## Layout

```
cl-payments.asd     ASDF system
src/
  crypto.lisp       BOLT #8 primitives: HKDF, ChaCha20-Poly1305, ECDH
  wire.lisp         BOLT #1: readers/writers, BigSize, TLV, message envelope
  transport.lisp    BOLT #8: Noise_XK handshake + encrypted transport
inspect/
  harness.lisp      the tiny check/report harness every gate shares
  crypto-test.lisp  gate 1 — RFC 5869 / RFC 8439 vectors
  wire-test.lisp    gate 2 — BOLT #1 BigSize + TLV vectors
  transport-test.lisp  gate 3 — BOLT #8 handshake + key-rotation vectors
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

```sh
export CL_SOURCE_REGISTRY="(:source-registry (:tree \"$PWD\") :inherit-configuration)"
```

## Quick start

```lisp
(asdf:load-system "cl-payments")
(asdf:test-system "cl-payments")     ; the offline gates
```

Handshake with a real node:

```sh
CL_PAYMENTS_PEER=<node_id>@127.0.0.1:9835 sbcl --load inspect/live-peer.lisp --quit
```

```
peer      029fcdcf2646a8654c778a56c565d24703ce940642a2ef53a1cdced2ea254b48c9@127.0.0.1:9835
us        039b069afecb3a39048584e3ad54391f7e66e12cd4fad50af029b8b3dac1da3dcc

✓ BOLT #8 handshake complete
  remote static key matches the node id we dialed: yes
→ init sent
← init  globalfeatures=2 bytes features=800898880a8a59a1 tlv-records=2
← type 256  (430 byte payload)      ; channel_announcement
← type 258  (136 byte payload)      ; channel_update
```

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
