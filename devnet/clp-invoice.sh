#!/usr/bin/env bash
# clp-invoice.sh — have a cl-payments node mint an invoice.
#   ./clp-invoice.sh clp3 <amount_msat> "description"      -> prints the bolt11
#   ./clp-invoice.sh clp3 --status <payment_hash>          -> paid or not
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/_common.sh"
n=$1; shift; dir=$(clp_dir "$n")/commands; mkdir -p "$dir"; id="inv-$(date +%s%N)"
if [ "${1:-}" = "--status" ]; then printf '(:invoice-status :payment-hash "%s")\n' "$2" > "$dir/$id.cmd"
else printf '(:invoice :amount-msat %s :description %s)\n' "$1" "\"${2:-}\"" > "$dir/$id.cmd"; fi
for _ in $(seq 1 60); do [ -f "$dir/$id.result" ] && { cat "$dir/$id.result"; exit 0; }; sleep 0.5; done
echo "timed out"; exit 1
