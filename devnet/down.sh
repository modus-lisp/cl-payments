#!/usr/bin/env bash
# down.sh — stop the devnet.   usage: ./down.sh [all|bitcoind|cln1|lnd1|clp1|...]
#
# Lightning nodes stop BEFORE bitcoind: they hold RPC connections to it, and a
# node that loses its chain backend mid-write logs alarming (harmless, but
# alarming) errors.  Shut down in reverse dependency order.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/_common.sh"

stop_node() {
  local n=$1 pat; pat=$(node_pattern "$n")
  node_running "$n" || { printf "%-10s not running\n" "$n"; return 0; }
  case "$(node_impl "$n")" in
    cln) ln_cli "$n" stop >/dev/null 2>&1 || true ;;
    lnd) ln_cli "$n" stop >/dev/null 2>&1 || true ;;
  esac
  for _ in $(seq 1 30); do
    node_running "$n" || { printf "%-10s stopped\n" "$n"; return 0; }
    sleep 1
  done
  pkill -f "$pat" 2>/dev/null && printf "%-10s killed\n" "$n"
}

TARGET=${1:-all}
case "$TARGET" in
  bitcoind) stop_bitcoind ;;
  all) for n in $(clp_names); do stop_clp "$n"; done
       for n in $(node_names); do stop_node "$n"; done
       stop_bitcoind ;;
  *)   if node_impl "$TARGET" >/dev/null 2>&1; then stop_node "$TARGET"
       elif clp_is "$TARGET"; then stop_clp "$TARGET"
       else echo "usage: $0 [all|bitcoind|$(node_names | tr '\n' '|' | sed 's/|$//')|$(clp_names | tr '\n' '|' | sed 's/|$//')]"; exit 1; fi ;;
esac
