#!/usr/bin/env bash
# clp-pay.sh — have a cl-payments node pay a BOLT #11 invoice.
#   ./clp-pay.sh clp3 lntbs...            pay
#   ./clp-pay.sh clp3 --graph             what the node knows of the network
# The daemon has no RPC; it watches <dir>/commands/ for one-form files and
# writes the outcome beside them.  The block height is still passed along, but
# a daemon with a chain view (CLP_BITCOIN_CLI) prefers its own.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/_common.sh"
n=$1; shift
dir=$(clp_dir "$n")/commands; mkdir -p "$dir"
id="cmd-$(date +%s%N)"
if [ "${1:-}" = "--graph" ]; then
  echo "(:graph)" > "$dir/$id.cmd"
else
  h=$(bcli getblockcount)
  printf '(:pay :bolt11 "%s" :height %s%s)\n' "$1" "$h" "${2:+ :amount-msat $2}" > "$dir/$id.cmd"
fi
for _ in $(seq 1 120); do
  if [ -f "$dir/$id.result" ]; then
    r=$(cat "$dir/$id.result")
    echo "$r"
    case "${r,,}" in *":status :pending"*) sleep 0.5; continue;; esac
    exit 0
  fi
  sleep 0.5
done
echo "timed out waiting for $id"; exit 1
