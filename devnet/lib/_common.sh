#!/usr/bin/env bash
# _common.sh — single source of truth for the cl-payments signet devnet.
#
# Source this from every script:  source "$(dirname "$0")/lib/_common.sh"
#
# Structure lifted from bitcoin-deposits/deposits-rust (deposits-tools/bin/_common.sh):
# one file owns every path, port and binary; the verb scripts on top stay thin.
# NO OTHER FILE IN THIS TREE SHOULD HARDCODE A PORT OR A PATH.
#
# Every setting below is env-overridable, so a second cluster can run
# side-by-side by exporting a different SIGNET_ROOT and port base before
# sourcing this file.

# ─── Root and layout ─────────────────────────────────────────────────────────
SIGNET_ROOT="${SIGNET_ROOT:-/mnt/lisp/signet}"
BIN="$SIGNET_ROOT/bin"                  # binaries (symlinks into opt/ and the Core build)
OPT="$SIGNET_ROOT/opt"                  # unpacked release trees
LOGS="$SIGNET_ROOT/logs"
WALLETS="$SIGNET_ROOT/wallets"          # OUTSIDE the chaindata dir, deliberately
BITCOIN_DATADIR="$SIGNET_ROOT/bitcoin"

# ─── Bitcoin Core ────────────────────────────────────────────────────────────
BITCOIND="${BITCOIND:-$BIN/bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-$BIN/bitcoin-cli}"
BITCOIN_UTIL="${BITCOIN_UTIL:-$BIN/bitcoin-util}"
BITCOIN_RPC_PORT="${BITCOIN_RPC_PORT:-38332}"
BITCOIN_P2P_PORT="${BITCOIN_P2P_PORT:-38333}"
MINER_WALLET="${MINER_WALLET:-miner}"

# Core's signet miner + its python deps live in the source tree that produced
# the binary, so they always match the daemon's consensus rules.
CORE_SRC="${CORE_SRC:-/mnt/lisp/bitcoin-kernel}"
SIGNET_MINER="$CORE_SRC/contrib/signet/miner"
CORE_PYTHONPATH="$CORE_SRC/test/functional"

# Signet's easiest allowed difficulty. Our chain is protected by the block
# SIGNATURE, not by work, so there is no reason to grind harder than the minimum.
MIN_NBITS="1e0377ae"

bcli()  { "$BITCOIN_CLI" -signet -datadir="$BITCOIN_DATADIR" "$@"; }
wcli()  { "$BITCOIN_CLI" -signet -datadir="$BITCOIN_DATADIR" -rpcwallet="$MINER_WALLET" "$@"; }

# ─── Lightning node registry ─────────────────────────────────────────────────
# Adding a node means adding one line here and nothing else.
#   name : implementation : LN p2p port : rpc port (0 = unix socket)
#     cln1 ── cln2 ── cln3 ── cln4        the routing spine
#              │        │
#            lnd1     lnd2                 interop leaves
#
# An onion carries one encrypted layer per hop, and a two-hop route exercises
# almost none of it: no intermediate node ever peels a layer and forwards to
# ANOTHER intermediate.  The spine gives three hops and two real forwarding
# nodes, which is the smallest topology that does.
#
# The spine is deliberately ALL CORE LIGHTNING.  An LND node in the middle does
# not work here: LND enforces strictly increasing short-channel-ids during the
# BOLT #7 range sync and disconnects CLN over it, and with graph sync disabled to
# avoid that, LND never learns or relays the graph — so gossip dies at the LND
# hop and CLN reports "Unknown destination node" for anything beyond it.  Either
# way the links flap ("resuming link failed: link shutting down") and forwarding
# fails.  That is a CLN/LND disagreement, not ours, and the devnet should not be
# blocked on it.
#
# LND stays as LEAF nodes: cl-payments still talks BOLT #8, #1 and #7 to a second
# implementation, which is the interop that matters here — it just is not asked
# to forward.
LN_NODES=(
  "cln1:cln:9835:0"
  "cln2:cln:9836:0"
  "cln3:cln:9837:0"
  "cln4:cln:9838:0"
  "lnd1:lnd:9735:10009"
  "lnd2:lnd:9736:10010"
)

# The routing spine, plus the LND leaves, as (from to) pairs.
LN_LINE=("cln1 cln2" "cln2 cln3" "cln3 cln4" "cln2 lnd1" "cln3 lnd2")

# ─── cl-payments nodes ───────────────────────────────────────────────────────
#
# These are OUR nodes, and they are daemons now: `bin/cl-payments.lisp` listens,
# accepts inbound connections, and persists channel state, so up.sh/down.sh
# manage them the same way they manage CLN and LND.
#
# What makes them nodes rather than throwaway scripts is the PERSISTENT KEY in
# <dir>/node.key: a channel is a 2-of-2 with a specific counterparty, so a node
# that forgets its key can never reconnect to a channel it opened.  Channel state
# lives beside it in <dir>/channels.sexp.
#
# clp3 sits IN the line rather than hanging off it:
#
#     cln1 ── cln2 ── cln3 ─────────── cln4
#                       \             /
#                        \── clp3 ──/
#
# Core Lightning will compute a route through it — `getroute` from cln3 to cln4
# with the direct channel excluded returns cln3 → clp3 → cln4.  A leaf node only
# ever exercises being an endpoint; a middle hop is what an onion is FOR.
#
# Both directions of channel opening are exercised: clp2 opened 273x1x1 to cln1,
# and cln3/cln4 opened 291x1x0 and 300x1x0 to clp3.  The second direction is the
# only way we get inbound liquidity — a channel we funded is outbound-only, so
# nobody can route a payment toward us over it.
CLP_NODES=("clp1:9931" "clp2:9932" "clp3:9933")
CLP_SRC="${CLP_SRC:-$HOME/cl-payments}"

clp_names(){ for e in "${CLP_NODES[@]}"; do echo "${e%%:*}"; done; }
clp_dir()  { echo "$SIGNET_ROOT/$1"; }
clp_key()  { cat "$SIGNET_ROOT/$1/node.key"; }
clp_port() { for e in "${CLP_NODES[@]}"; do
               [ "${e%%:*}" = "$1" ] && { echo "${e##*:}"; return 0; }
             done; return 1; }
clp_is()   { clp_port "$1" >/dev/null 2>&1; }

# The node id, derived from the key by cl-payments itself so there is one
# implementation of the derivation rather than two.  Loading the system takes
# seconds, and status.sh asks for every id every time, so the answer is cached
# beside the key — it is a pure function of a file that never changes.
clp_id() {
  local dir; dir=$(clp_dir "$1")
  if [ -s "$dir/node.id" ] && [ "$dir/node.id" -nt "$dir/node.key" ]; then
    cat "$dir/node.id"; return 0
  fi
  local key; key=$(clp_key "$1")
  sbcl --noinform --disable-debugger --non-interactive \
       --eval '(require :asdf)' \
       --eval "(handler-bind ((warning (function muffle-warning))) (asdf:load-system \"cl-payments\"))" \
       --eval "(princ (cl-payments.crypto:bytes->hex (cl-payments.crypto:compressed-pubkey (cl-payments.crypto:pubkey-of (secp256k1-fast:bytes-to-int (cl-payments.crypto:hex->bytes \"$key\"))))))" \
       2>/dev/null | tail -1 | tee "$dir/node.id"
}

clp_uri()     { echo "$(clp_id "$1")@127.0.0.1:$(clp_port "$1")"; }
clp_ctl_port(){ echo "$(( $(clp_port "$1") + 100 ))"; }
# One form in, one form out, over the control socket.
clp_ctl()     { local n=$1; shift; printf '%s\n' "$*" | timeout 30 bash -c "exec 3<>/dev/tcp/127.0.0.1/$(clp_ctl_port "$n"); cat >&3; head -n1 <&3"; }
clp_pidfile() { echo "$(clp_dir "$1")/clp.pid"; }
clp_running() {
  local pf; pf=$(clp_pidfile "$1")
  [ -f "$pf" ] && kill -0 "$(cat "$pf")" 2>/dev/null
}

# Started with setsid so the daemon outlives the shell that launched it.  A bare
# `nohup ... &` from a script that then exits leaves the process in a process
# group that the next Ctrl-C in that terminal can still reach.
start_clp() {
  local n=$1 dir port
  dir=$(clp_dir "$n"); port=$(clp_port "$n") || return 1
  clp_running "$n" && { printf "%-10s already up\n" "$n"; return 0; }
  # The daemon writes its own pidfile once it is up; see bin/cl-payments.lisp.
  # Recording $! here would record setsid's pid, and setsid forks.
  rm -f "$(clp_pidfile "$n")"
  ( cd "$CLP_SRC" && CLP_DIR="$dir/" CLP_PORT="$port" CLP_NETWORK=signet \
      CLP_BITCOIN_CLI="$BITCOIN_CLI -signet -datadir=$BITCOIN_DATADIR" \
      CLP_CONTROL_PORT="$((port + 100))" CLP_FUNDING_DEPTH=3 \
      CLP_TOWERS="$( [ "$n" = clp3 ] && echo 127.0.0.1:$(( $(clp_port clp1) + 100 )) )" \
      setsid nohup sbcl --non-interactive --load bin/cl-payments.lisp \
      >>"$LOGS/$n.out" 2>&1 & )
  # The daemon compiles on load, so it is not listening the instant it forks —
  # and it does not write its pidfile until after that.  Wait on the LISTENING
  # SOCKET, which is the thing callers actually need; treating a missing pidfile
  # as "it died" gives up a second into a thirty-second startup.
  for _ in $(seq 1 90); do
    ss -ltn 2>/dev/null | grep -q "127.0.0.1:$port " \
      && { printf "%-10s ${C_OK}up${C_OFF}  %s\n" "$n" "$(clp_id "$n" | cut -c1-16)…"; return 0; }
    sleep 1
  done
  printf "%-10s ${C_ERR}FAILED${C_OFF} — see %s\n" "$n" "$LOGS/$n.out"; return 1
}

stop_clp() {
  local n=$1 pf port; pf=$(clp_pidfile "$n"); port=$(clp_port "$n")
  # Fall back to whoever holds the port.  A daemon that died before writing its
  # pidfile, or one started by hand, still has to be stoppable — otherwise the
  # next start fails on address-in-use and the cause is invisible.
  if ! clp_running "$n"; then
    local holder
    holder=$(ss -ltnp 2>/dev/null | grep "127.0.0.1:$port " | grep -oP 'pid=\K[0-9]+' | head -1)
    [ -n "$holder" ] && { kill "$holder" 2>/dev/null; printf "%-10s stopped (by port)\n" "$n"; }
    rm -f "$pf"; return 0
  fi
  kill "$(cat "$pf")" 2>/dev/null
  for _ in $(seq 1 20); do clp_running "$n" || break; sleep 0.5; done
  clp_running "$n" && kill -9 "$(cat "$pf")" 2>/dev/null
  rm -f "$pf"; printf "%-10s stopped\n" "$n"
}

node_field()  { local n=$1 f=$2; for e in "${LN_NODES[@]}"; do
                  [ "${e%%:*}" = "$n" ] && { echo "$e" | cut -d: -f"$f"; return 0; }
                done; return 1; }
node_impl()   { node_field "$1" 2; }
node_port()   { node_field "$1" 3; }
node_rpcport(){ node_field "$1" 4; }
node_dir()    { echo "$SIGNET_ROOT/$1"; }
node_names()  { for e in "${LN_NODES[@]}"; do echo "${e%%:*}"; done; }

# ─── Per-implementation CLI dispatch ─────────────────────────────────────────
# `ln_cli cln1 getinfo` and `ln_cli lnd1 getinfo` both work; callers that just
# want "ask this node something" never branch on implementation.
ln_cli() {
  local n=$1; shift
  case "$(node_impl "$n")" in
    cln) "$BIN/lightning-cli" --lightning-dir="$(node_dir "$n")" "$@" ;;
    lnd) "$BIN/lncli" --network=signet --lnddir="$(node_dir "$n")" \
           --rpcserver=127.0.0.1:"$(node_rpcport "$n")" "$@" ;;
    *)   echo "unknown node: $n" >&2; return 1 ;;
  esac
}

# Node id (33-byte compressed pubkey) — the thing cl-payments dials in BOLT #8.
node_id() {
  local n=$1
  case "$(node_impl "$n")" in
    cln) ln_cli "$n" getinfo 2>/dev/null | py_get id ;;
    lnd) ln_cli "$n" getinfo 2>/dev/null | py_get identity_pubkey ;;
  esac
}

# `<node_id>@<host>:<port>` — the standard Lightning connection string.
node_uri() {
  local n=$1 id
  id=$(node_id "$n") || return 1
  [ -n "$id" ] && echo "$id@127.0.0.1:$(node_port "$n")"
}

# A fresh on-chain receive address (native segwit on both implementations).
node_address() {
  local n=$1
  case "$(node_impl "$n")" in
    cln) ln_cli "$n" newaddr 2>/dev/null | py_get bech32 ;;
    lnd) ln_cli "$n" newaddress p2wkh 2>/dev/null | py_get address ;;
  esac
}

# On-chain confirmed balance, in satoshis.
node_balance() {
  local n=$1
  case "$(node_impl "$n")" in
    cln) ln_cli "$n" listfunds 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(sum(o['amount_msat'] for o in d.get('outputs',[]) if o.get('status')=='confirmed')//1000)" ;;
    lnd) ln_cli "$n" walletbalance 2>/dev/null | py_get confirmed_balance ;;
  esac
}

# ─── Process helpers ─────────────────────────────────────────────────────────
node_pattern() {
  case "$(node_impl "$1")" in
    cln) echo "lightning-dir=$(node_dir "$1")" ;;
    lnd) echo "lnd --lnddir=$(node_dir "$1")" ;;
  esac
}
is_running()      { pgrep -f "$1" >/dev/null 2>&1; }
node_running()    { is_running "$(node_pattern "$1")"; }
bitcoind_running(){ is_running "bitcoind -datadir=$BITCOIN_DATADIR"; }

# ─── Bitcoin lifecycle ───────────────────────────────────────────────────────
# Always wait for the PROCESS to exit, never a fixed sleep: bitcoind flushes
# chainstate and wallet on shutdown, and racing that is how you corrupt them.
stop_bitcoind() {
  bitcoind_running || { echo "bitcoind   not running"; return 0; }
  # Unload wallets first.  This build leaves an uncommitted SQLite journal if a
  # wallet is still loaded at shutdown, which makes the wallet unreadable on the
  # next start ("Data is not in recognized format").
  for w in $(bcli listwallets 2>/dev/null | python3 -c \
      "import json,sys;[print(w) for w in json.load(sys.stdin)]" 2>/dev/null); do
    bcli unloadwallet "$w" >/dev/null 2>&1 || true
  done
  bcli stop >/dev/null 2>&1 || true
  for _ in $(seq 1 120); do bitcoind_running || { echo "bitcoind   stopped"; return 0; }; sleep 1; done
  echo "bitcoind   WARN: still running after 120s"; return 1
}

start_bitcoind() {
  bitcoind_running && { echo "bitcoind   already running"; ensure_miner_wallet; return 0; }
  nohup "$BITCOIND" -datadir="$BITCOIN_DATADIR" >>"$LOGS/bitcoind.out" 2>&1 &
  for _ in $(seq 1 90); do
    bcli getblockchaininfo >/dev/null 2>&1 && { echo "bitcoind   up"; ensure_miner_wallet; return 0; }
    sleep 1
  done
  echo "bitcoind   FAILED — see $LOGS/bitcoind.out"; tail -3 "$LOGS/bitcoind.out"; return 1
}

ensure_miner_wallet() {
  bcli listwallets 2>/dev/null | grep -q "\"$MINER_WALLET\"" && return 0
  bcli loadwallet "$MINER_WALLET" >/dev/null 2>&1 || true
}

# ─── Mining ──────────────────────────────────────────────────────────────────
# The whole point of a private signet: blocks exist only when we ask.
#
# Core's miner paces blocks to track wall-clock, so --max-blocks=6 would take an
# hour once the chain has caught up.  --set-block-time mines exactly one block
# at a given timestamp with no delay, so we drive it one block at a time and
# choose the timestamp ourselves: max(now, prev+1) keeps it strictly increasing
# (staying ahead of median-time-past) without drifting into the 2-hour future
# limit.  Result: N blocks in about N/3 seconds instead of N*10 minutes.
tip_time() { bcli getblock "$(bcli getbestblockhash)" 2>/dev/null | py_get time; }

mine_blocks() {
  local n=${1:-1} addr prev now t
  addr=$(cat "$SIGNET_ROOT/.signer-address") || return 1
  for _ in $(seq 1 "$n"); do
    prev=$(tip_time); now=$(date +%s)
    t=$(( now > prev ? now : prev + 1 ))
    ( cd "$CORE_SRC" && PYTHONPATH="$CORE_PYTHONPATH" python3 "$SIGNET_MINER" \
        --cli="$BITCOIN_CLI -signet -datadir=$BITCOIN_DATADIR -rpcwallet=$MINER_WALLET" \
        generate --grind-cmd="$BITCOIN_UTIL grind" --address="$addr" \
        --min-nbits --set-block-time="$t" ) >>"$LOGS/mine.log" 2>&1 || return 1
  done
}

# ─── Small helpers ───────────────────────────────────────────────────────────
py_get() { python3 -c "import json,sys
try: print(json.load(sys.stdin).get('$1',''))
except Exception: pass"; }

C_OK=$'\033[0;32m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[0;31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
