# cl-payments

A from-scratch, clean-room **Lightning Network implementation in Common Lisp**,
built on [cl-consensus](https://github.com/modus-lisp/cl-consensus)'s Bitcoin
engine and [secp256k1-fast](https://github.com/modus-lisp/secp256k1-fast).
Nothing here wraps LND, Core Lightning or LDK: the Noise transport, the wire
format, the commitment transactions, the onion, the invoices and the on-chain
handling are all written here, and every layer is checked against the BOLT
vectors and then against real Core Lightning and LND nodes on a private signet.

## ⚠️ Status & disclaimer

**Unaudited research software.** It does what the roadmap says it does, and it
has been driven end to end against two other implementations — but it has
never held money that mattered, and it must not. Do not point it at mainnet.
Two things it does on purpose that a real node never would: a `:publish-revoked`
command that broadcasts a revoked state so a counterparty's penalty can be
proven real, and a control socket with no authentication at all (it listens on
localhost only; anyone who can reach it already owns the key file).

## What it does

Verified against Core Lightning and LND on the private signet, as `devnet/integration.sh`
runs it in 27 steps:

- **Transport and peering** (BOLT #8, #1, #9): Noise_XK, framing, `init`,
  feature negotiation, ping/pong. Both implementations accept us and stay.
- **Gossip and routing** (BOLT #7): the graph, verified signature by signature;
  our own channels announced and relayed; pathfinding over it.
- **Channels** (BOLT #2, #3): open in either direction, `channel_reestablish`,
  the full HTLC commitment cycle, cooperative close. Commitments reproduce the
  spec's vectors byte for byte, with and without anchors.
- **Payments** (BOLT #4, #11): the Sphinx onion built and peeled; invoices
  minted and paid; receiving at the final hop; **forwarding** between two other
  nodes with the fee kept; every failure a readable onion the sender decodes;
  retry around channels that turn out empty.
- **On chain** (BOLT #5): a watcher confirms fundings, sees every spend of a
  funding output and answers it — sweep, delayed sweep, penalty, HTLC claims and
  second-stage transactions, funded by inputs of our own. A revoked commitment
  we published on purpose was punished by Core Lightning; one the daemon gate's
  cheater published was punished by its tower.
- **Anchor outputs**, negotiated with any peer that offers them (CLN does by
  default), including child-pays-for-parent through our anchor.
- **Watchtowers**: pre-signed penalties, encrypted under the revoked txid,
  handed to any daemon acting as a tower.

See [ROADMAP.md](ROADMAP.md) for the phase-by-phase account, what each layer's
tests can and cannot see, and what is left.

## Layout

    src/          crypto wire transport features peer gossip keys commitment
                  channel updates node forward live onion invoice route chain
                  onchain            — one BOLT concern per file, in load order
    inspect/      the gates: one *-test.lisp per module, plus loopback-test
                  (the stack against itself over TCP) and daemon-test (two
                  daemons and a watchtower over a mock chain)
    inspect/vectors/   the spec's published vectors, verbatim
    bin/cl-payments.lisp   the daemon
    devnet/       the private-signet environment: bitcoind, four CLN, two LND,
                  three cl-payments daemons, and integration.sh
    deps/         cl-consensus, secp256k1-fast, cl-transport as submodules

## Testing

Three offline gates, all in CI, every check mutation-verified before it counts:

    inspect/run-all.sh

`vectors` holds every module to the spec's numbers and stated properties;
`loopback` runs the transport and peer stack against itself; `daemon` runs two
node instances over TCP on a mock chain through open, payments both ways, a
readable failure, a revoked publish punished by a tower and by the peer, and a
reload from disk. What offline gates cannot see — a symmetric mistake both ends
make together — is what the devnet is for.

## Quick start

    git clone --recursive https://github.com/modus-lisp/cl-payments
    cd cl-payments && inspect/run-all.sh

Needs SBCL and Quicklisp with `ironclad`, `usocket` and `bordeaux-threads`.
Running the daemon:

    CLP_DIR=~/clp CLP_PORT=9735 CLP_NETWORK=signet \
    CLP_BITCOIN_CLI="bitcoin-cli -signet" CLP_CONTROL_PORT=9835 \
    sbcl --non-interactive --load bin/cl-payments.lisp

with a 32-byte hex `node.key` in `CLP_DIR`. Commands are one s-expression per
line on the control socket (or a file dropped in `CLP_DIR/commands/`):
`(:info)`, `(:channels)`, `(:invoice :amount-msat N :description "...")`,
`(:pay :bolt11 "...")`, `(:close :channel "...")`, `(:force-close ...)`,
`(:address)`, `(:watch ...)`.

## The devnet

`devnet/` is the environment everything above was verified in: a signet we
mine ourselves (blocks in seconds, nobody else's chain), Core Lightning and LND
nodes in a spine, and the cl-payments daemons in the middle of it. See
[devnet/README.md](devnet/README.md). `integration.sh` is the whole story with
a pass/fail line per step.

## License

MIT — see [LICENSE](LICENSE).
