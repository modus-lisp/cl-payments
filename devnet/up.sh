#!/usr/bin/env bash
# up.sh — start the devnet.   usage: ./up.sh [all|bitcoind|cln1|cln2|lnd1]
#
# Idempotent: starting something already running is a no-op, so it is safe to
# re-run after a partial failure.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/_common.sh"

start_node() {
  local n=$1 dir; dir=$(node_dir "$n")
  node_running "$n" && { printf "%-10s already running\n" "$n"; return 0; }
  case "$(node_impl "$n")" in
    cln) nohup "$BIN/lightningd" --lightning-dir="$dir" >>"$LOGS/$n.out" 2>&1 & ;;
    lnd) nohup "$BIN/lnd" --lnddir="$dir" --configfile="$dir/lnd.conf" >>"$LOGS/$n.out" 2>&1 & ;;
  esac
  # Wait for the node to actually answer RPC, not just for the process to exist —
  # both implementations take several seconds to open their databases.
  for _ in $(seq 1 60); do
    ln_cli "$n" getinfo >/dev/null 2>&1 && { printf "%-10s ${C_OK}up${C_OFF}\n" "$n"; return 0; }
    node_running "$n" || break
    sleep 1
  done
  printf "%-10s ${C_ERR}FAILED${C_OFF} — see %s\n" "$n" "$LOGS/$n.out"; return 1
}

TARGET=${1:-all}
case "$TARGET" in
  bitcoind) start_bitcoind ;;
  all)
    start_bitcoind || exit 1
    for n in $(node_names); do start_node "$n"; done
    for n in $(clp_names); do start_clp "$n"; done
    echo; echo "${C_DIM}chain height $(bcli getblockcount) — ./status.sh for detail${C_OFF}" ;;
  *)
    if node_impl "$TARGET" >/dev/null 2>&1; then start_node "$TARGET"
    elif clp_is "$TARGET"; then start_clp "$TARGET"
    else echo "usage: $0 [all|bitcoind|$(node_names | tr '\n' '|' | sed 's/|$//')|$(clp_names | tr '\n' '|' | sed 's/|$//')]"; exit 1; fi ;;
esac
