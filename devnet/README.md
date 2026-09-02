# cl-payments signet devnet

A **private signet** — our own Bitcoin chain, whose blocks only we can produce —
running three Lightning nodes across two independent implementations, for
developing and differential-testing [cl-payments](../../home/claude/cl-payments).

```
              bitcoind (signet, private challenge)   RPC 38332  P2P 38333

  routing spine   cln1 ── cln2 ── cln3 ── cln4       CLN v26.06.7
                          │       │
  interop leaves        lnd1    lnd2                 LND v0.21.2

  cl-payments     clp1  clp2  clp3                   persistent keys, no daemon
```

Three hops across the spine, so two intermediate nodes each peel an onion layer
and forward — the smallest topology that exercises onion routing at all.

## Why a private signet

`regtest` throws away the parts of consensus Lightning depends on: difficulty is
trivial, timestamps are loose, and there is no block signature. A private signet
keeps real headers, real (if minimal) proof-of-work, real median-time-past and
real BIP325 block-signature validation — the rules cl-consensus validates, and
that every CLTV/CSV timelock in a channel relies on — while still letting us
produce a block on demand.

A *public* signet (the default one, or Mutinynet) is a real network: millions of
blocks to sync and a faucet between you and your first coin. Here the chain
starts at height 0, we hold the signing key, and funding is a local RPC call.

**The consequence that matters:** `./mine.sh 6` takes about two seconds. On any
public network that is an hour. Channel-open and force-close tests are dominated
by confirmation waits, so this is the difference between a usable edit/test loop
and an unusable one.

## Quick start

```sh
. /mnt/lisp/signet/env.sh     # PATH + bcli/cln1/cln2/lncli1 aliases
./up.sh all                   # start bitcoind + all three LN nodes
./status.sh                   # chain height, node ids, balances, channels
./smoke.sh                    # build a topology and route a payment across it
```

| command | what it does |
|---|---|
| `./up.sh [all\|bitcoind\|cln1\|cln2\|lnd1]` | start; idempotent |
| `./down.sh [...]` | stop, LN nodes before bitcoind |
| `./status.sh` | one screen: chain, nodes, node ids, funds, channels |
| `./mine.sh [n]` | mine n blocks **immediately** |
| `./mine.sh --every 30` | mine a block every 30s until Ctrl-C |
| `./fund.sh [node] [btc]` | send on-chain coins from the miner wallet and confirm |
| `./prime-fees.sh [rounds]` | give bitcoind's fee estimator some history |
| `./smoke.sh [--clean]` | end-to-end: peer, open channels, route a payment |
| `./topology.sh` | build the routing spine + leaves; `--show` to inspect |

## Layout

```
lib/_common.sh     single source of truth: every path, port, binary, and the
                   per-node accessors.  No other file hardcodes a port.
bin/               binaries (symlinks into opt/ and Core's build)
opt/cln, opt/lnd   unpacked release trees
bitcoin/           bitcoind datadir + bitcoin.conf (the signet challenge)
wallets/           the block-signing wallet — OUTSIDE bitcoin/, deliberately
cln1 cln2 lnd1/    per-node datadirs and configs
logs/              everything's stdout and logfiles
.signer-address       the address whose scriptPubKey IS the signet challenge
.signer-descriptor    its private descriptor (mode 600) — lose this and the
                      chain becomes unmineable and has to be rebuilt
```

Structure is lifted from `bitcoin-deposits/deposits-rust`
(`deposits-tools/bin/_common.sh`): one file owns the configuration, the verb
scripts on top stay thin, and every value is env-overridable so a second cluster
can run side-by-side with a different `SIGNET_ROOT`.

Adding a fourth node is one line in `LN_NODES` in `lib/_common.sh`.

## Ports

| | |
|---|---|
| bitcoind | RPC 38332, P2P 38333 |
| cln1 | LN 9835, gRPC 9935 |
| cln2 | LN 9836, gRPC 9936 |
| cln3 | LN 9837, gRPC 9937 |
| cln4 | LN 9838, gRPC 9938 |
| lnd1 | LN 9735, gRPC 10009, REST 8092 |
| lnd2 | LN 9736, gRPC 10010, REST 8093 |

All bound to `127.0.0.1`. Chosen to avoid cl-consensus's daemon (JSON-RPC 8432,
control socket 4008). `8081` is occupied by an unrelated process on this box,
hence LND's REST on 8092.

## Resetting

Nothing here is precious except `.signer-descriptor` — the block-signing key. As
long as that survives, the chain can be rebuilt:

```sh
./down.sh all
rm -rf bitcoin/signet cln*/signet lnd*/data
./up.sh all && ./mine.sh 150 && ./prime-fees.sh && ./fund.sh && ./smoke.sh
```

Lose `.signer-descriptor` and the chain is **unmineable** — no more blocks can
ever be produced for it, and the only recovery is generating a new challenge and
starting from height 0 (see the header of `bitcoin/bitcoin.conf` for why the
wallet lives outside the chaindata directory).

## Things that bit us, and why

These are all consequences of the chain being brand new and privately mined.
They are written down because each one costs an hour to rediscover.

- **`estimatesmartfee` returns nothing.** A fresh chain has never had a mempool,
  so Core's estimator has no observations. CLN then refuses to *accept* a channel
  with `Cannot accept channel: feerates unknown` — and `force-feerates` does not
  fix it, because that sets the feerates CLN *uses*, not the estimates it
  *validates against*. `./prime-fees.sh` generates real fee history to fix this
  properly. `fallbackfee` in `bitcoin.conf` is unrelated: that is a Core *wallet*
  setting.

- **Wallets must be unloaded before `bitcoind stop`.** This Core build leaves an
  uncommitted SQLite journal if a wallet is loaded at shutdown, and the wallet is
  then unreadable (`Data is not in recognized format`). `stop_bitcoind` in
  `_common.sh` unloads first. Related: never `rm` chaindata while bitcoind is
  still flushing — wait for the process to actually exit, which is why nothing
  here uses a fixed `sleep`.

- **The block-signing wallet lives outside the chaindata directory.** Changing
  the signet challenge means wiping blocks/chainstate, and the signing key has to
  survive that. Hence `walletdir=` — which, being network-scoped, must be in the
  `[signet]` section of `bitcoin.conf`, not the global one.

- **Changing the challenge changes the P2P magic**, so `peers.dat` from a
  previous challenge makes bitcoind refuse to start. Wipe the whole chain
  directory, not just `blocks/`.

- **CLN's `cln-grpc` plugin defaults to the same port for every instance.** Two
  CLN nodes on one box collide, and because the plugin is marked *important*, the
  second node's `lightningd` shuts itself down. Pin `grpc-port` per node.

- **This bitcoind has no ZMQ** (it is the build cl-consensus made for its
  libbitcoinkernel diff), so LND runs with `bitcoind.rpcpolling=1` and
  `txindex=1`. Nodes notice blocks within ~10s rather than instantly, which is
  why `fund.sh` and `smoke.sh` wait rather than assuming.

- **LND runs with `noseedbackup=1`** so it starts without an interactive unlock.
  Dev only — that is an unencrypted wallet.

- **LND reports `synced_to_chain: false` when the chain sits idle.** It judges
  sync partly by how old the tip is, and on a chain that only produces blocks
  when we ask, an overnight gap looks like a stalled backend. One `./mine.sh`
  fixes it. For anything long-running, leave `./mine.sh --every 30` going in
  another terminal — that is what the interval mode is for.

- **LND drops CLN peers over gossip ordering.** LND requires short-channel-ids in
  strictly increasing order during the BOLT #7 channel-range sync and disconnects
  with `current sid: NxNxN isn't greater than last sid` when CLN's reply doesn't
  satisfy it. The channel stays open but goes *inactive*, because the peer
  connection itself dies — so this reads as "my channel broke" rather than "my
  gossip sync disagreed". `numgraphsyncpeers=0` and
  `ignore-historical-gossip-filters=1` in `lnd1/lnd.conf` skip that sync; on a
  3-node devnet the topology is known by construction and there is no graph worth
  syncing. Note these must sit under `[Application Options]` — appending them to
  the end of the file puts them in `[Bitcoind]`, where LND rejects them as
  unknown options.

  This one is worth keeping in view rather than just papering over: it is a real
  disagreement between two conformant-ish implementations, and BOLT #7 ordering is
  something cl-payments will have to get right in Phase 3.

## Topology

`./topology.sh` builds it; `./topology.sh --show` prints what exists.

**The spine is deliberately all Core Lightning.** An LND node in the middle does
not work here, and the reason is worth recording because both halves of it are
dead ends:

- With graph sync ON, LND enforces strictly increasing short-channel-ids during
  the BOLT #7 range sync and **disconnects CLN** over it. The links flap
  (`resuming link failed: link shutting down`) and forwarding fails.
- With graph sync OFF (`numgraphsyncpeers=0`), LND never learns the graph and
  never relays it, so gossip **stops dead at the LND hop** and CLN reports
  `Unknown destination node` for anything beyond it.

That is a CLN/LND disagreement rather than anything of ours, and the devnet
should not be blocked on it. LND stays as **leaf** nodes: cl-payments still
speaks BOLT #8, #1 and #7 to a second implementation, which is the interop that
matters — LND just is not asked to forward.

### Getting a cl-payments node INTO the route

`clp1` has two channels (`164x1x0` to cln2, `250x1x0` to cln3) so it sits
structurally between them — but nothing routes through it, and the reasons are
worth writing down because each one is a separate missing piece:

1. **`channel_flags` bit 0 is `announce_channel`.** With it clear the channel is
   PRIVATE: the peer never sends `announcement_signatures`, no
   `channel_announcement` is ever produced, and the channel is invisible to the
   routing graph — usable by its two ends and nobody else. `open-channel.lisp`
   sent 0 for its first channels; CLN reports those as `private = True` and the
   one opened with the flag set as `private = False`.
2. **`announcement_signatures` needs a node that STAYS UP.** CLN sends them once
   the funding is buried, to a *connected* peer. `open-channel.lisp` exits after
   `channel_ready`, and cln3's log shows `Peer connection lost` seconds later —
   so the moment to receive them never arrives. This is the first thing that
   genuinely requires a cl-payments daemon rather than a script.
3. **Then it must actually forward**, which needs the HTLC update flow driving
   real commitments plus BOLT #4's onion.

So the honest status is: cl-payments can be an ENDPOINT of a route (open a
channel, hold it, reconnect and resync) but not yet a HOP.

### cl-payments nodes

`clp1`, `clp2`, `clp3` are directories holding a **persistent** `node.key` — the
static key BOLT #8 authenticates and the `node_id` peers address. There is no
daemon yet; `inspect/open-channel.lisp` reads the key via `CL_PAYMENTS_NODE`.

Persisting it matters: a channel is a 2-of-2 with a specific counterparty, so a
node that forgets its key can never reconnect to a channel it opened. Earlier
runs generated a fresh key each time and left un-reclaimable channels behind
(`158x1x1` on cln1 is one of them — 200,000 sat in a 2-of-2 whose other half no
longer exists anywhere). Harmless on a chain where we mine our own money, but it
is why the key is a file now.

## Funding something from the miner wallet

The pattern `open-channel.lisp` uses, and the one to copy for anything that needs
an output at a specific script. The point is that the transaction is **built and
signed but not broadcast** until the protocol says it is safe:

```sh
bcli createrawtransaction '[]' '[{"<address>":0.002}]'      # outputs only
bcli fundrawtransaction   <hex>                             # picks inputs, adds change
bcli signrawtransactionwithwallet <hex>                     # still not broadcast
# ... do the thing that must happen before the money moves ...
bcli sendrawtransaction   <hex>
```

For a Lightning funding output that ordering is not optional: the funding output
is a 2-of-2, so broadcasting before you hold a counterparty signature that
returns the money lets an uncooperative peer strand it forever.

## bitcoin-cli gotchas on this chain

- **`deriveaddresses` needs a descriptor CHECKSUM** and fails with exit code 5
  without one. Either run the descriptor through `getdescriptorinfo` first, or —
  simpler — compute the address yourself; cl-consensus has bech32
  (`cl-consensus.encoding:encode-p2wsh`).
- **Signet uses the `tb` human-readable part**, not `bc`. cl-consensus defaults
  `*bech32-hrp*` to mainnet, so an address computed without rebinding it looks
  perfectly valid and belongs to a different network. `createrawtransaction`
  rejects it, which is the good outcome; anything that does not check would send
  real-looking coins nowhere.
- The miner wallet must be **loaded** after a restart (`bcli loadwallet miner`);
  wallets do not auto-load. `up.sh` does this.

## What these nodes actually demand

Measured against cln1 on this devnet, useful when writing a client:

| | |
|---|---|
| `minimum_depth` | 1 |
| `to_self_delay` | 6 |
| `dust_limit_satoshis` | 546 |
| feerates | pinned at 5000/kw (`force-feerates`) |

And one hard requirement that is easy to miss: **a peer advertising
`option_channel_type` rejects an `open_channel` without the `channel_type` TLV**,
with `Did not set channel_type in open_channel message`. Both CLN and LND
advertise it. `option_static_remotekey` is the type to send, and it changes
`to_remote`: the payment basepoint verbatim, with no per-commitment blinding.

## Using it from cl-payments

`./status.sh` prints each node's `uri` — the `<node_id>@<host>:<port>` string
that is exactly what a BOLT #8 initiator needs:

```
uri  029fcdcf2646a8654c778a56c565d24703ce940642a2ef53a1cdced2ea254b48c9@127.0.0.1:9835
```

The node id is the 33-byte compressed static key the Noise_XK handshake
authenticates. Two implementations are here on purpose: CLN and LND disagree in
small legal ways (feature-bit negotiation, gossip timing, which optional TLVs
they send), and a from-scratch BOLT stack that only ever talks to one of them
ends up encoding that one's reading of the spec.

bitcoind also listens on P2P 38333, and **cl-consensus speaks this chain**: it
knows signet and enforces BIP325, so it validates our blocks properly rather than
trusting a proof-of-work that is trivial by design.

```lisp
(cl-consensus.wire:select-signet
  "0014...")                        ; the signetchallenge from bitcoin.conf
(cl-consensus.peer:connect-peer "127.0.0.1" :port 38333)
```

The challenge is all it needs — the P2P magic is derived from it, so pointing
cl-consensus at the wrong signet fails at the handshake rather than silently
syncing the wrong chain. `cat .signet-challenge` is the value to pass.

## Driving cl-payments

- `./clp-pay.sh clp3 <bolt11>` — have a cl-payments node pay an invoice (or
  `--graph` to see what it knows of the network). The daemon has no RPC; this
  drops a one-form file in `<dir>/commands/` and reads the outcome beside it.
- `./integration.sh` — the whole story against CLN and LND with a pass/fail
  line per step: open to clp3, lock in, announce, receive, forward, fail,
  pay both implementations, close. A minute or two, mostly mining sleeps.
