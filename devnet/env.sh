# /mnt/lisp/signet/env.sh — source this to get the signet dev environment on PATH.
#
#   . /mnt/lisp/signet/env.sh
#
# Signet is the right network for Lightning development: real block times, real
# PoW headers, real gossip propagation, and a real (small) chain — but coins are
# free from a faucet and the whole chain fits in a few GB.  regtest can't
# exercise timing, gossip, or IBD; mainnet costs money.

export SIGNET_ROOT=/mnt/lisp/signet
export PATH="$SIGNET_ROOT/bin:$PATH"

# --- Bitcoin Core ------------------------------------------------------------
# The v29.1 build cl-consensus already produced for its libbitcoinkernel diff.
export BITCOIN_DATADIR="$SIGNET_ROOT/bitcoin"
export BITCOIN_CLI="bitcoin-cli -signet -datadir=$BITCOIN_DATADIR"
alias bcli="$BITCOIN_CLI"

# --- Core Lightning ----------------------------------------------------------
export CLN1_DIR="$SIGNET_ROOT/cln1"
export CLN2_DIR="$SIGNET_ROOT/cln2"
alias cln1="lightning-cli --lightning-dir=$CLN1_DIR"
alias cln2="lightning-cli --lightning-dir=$CLN2_DIR"

# --- LND ---------------------------------------------------------------------
export LND1_DIR="$SIGNET_ROOT/lnd1"
alias lncli1="lncli --network=signet --lnddir=$LND1_DIR --rpcserver=127.0.0.1:10009"

# --- Ports -------------------------------------------------------------------
# Chosen to avoid cl-consensus's daemon (JSON-RPC 8432, control socket 4008).
#
#   bitcoind signet   P2P 38333   RPC 38332
#   cln1              LN  9835
#   cln2              LN  9836
#   lnd1              LN  9735    gRPC 10009   REST 8081
#
# Everything binds 127.0.0.1 only.  These are unfunded dev nodes, but an
# LN node with an open RPC port is an open wallet, so nothing listens publicly.

echo "signet env ready — nodes: bitcoind, cln1, cln2, lnd1   (\$SIGNET_ROOT=$SIGNET_ROOT)"
