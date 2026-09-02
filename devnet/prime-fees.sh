#!/usr/bin/env bash
# prime-fees.sh — teach bitcoind's fee estimator what a fee looks like.
#
# A freshly-minted signet has never had a mempool: every transaction in it is a
# coinbase.  So `estimatesmartfee` answers "Insufficient data or no feerate
# found" for every target, and CLN refuses to accept a channel with
# "Cannot accept channel: feerates unknown" — force-feerates sets the values CLN
# *uses* but not the estimates it *validates against*.
#
# The fix is to give Core's estimator real observations: send batches of
# transactions at a spread of feerates, confirm them, and repeat.  Core records
# how many blocks each bucket took to confirm and can then answer for a target.
#
#   ./prime-fees.sh          default 30 rounds
#   ./prime-fees.sh 60       more rounds if estimates are still missing
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/_common.sh"

ROUNDS="${1:-30}"
FEERATES=(1 2 3 5 8 13 21 34)     # sat/vB spread, so buckets aren't all identical

bitcoind_running || { echo "${C_ERR}bitcoind is not running${C_OFF}"; exit 1; }

echo "priming the fee estimator: $ROUNDS rounds × ${#FEERATES[@]} transactions"
ADDR=$(wcli getnewaddress "fee-priming")

for r in $(seq 1 "$ROUNDS"); do
  for f in "${FEERATES[@]}"; do
    wcli -named sendtoaddress address="$ADDR" amount=0.001 fee_rate="$f" >/dev/null 2>&1 || true
  done
  mine_blocks 1
  printf "\r  round %d/%d  height %s  mempool %s" \
    "$r" "$ROUNDS" "$(bcli getblockcount)" "$(bcli getmempoolinfo | py_get size)"
done
echo; echo

echo "estimatesmartfee results:"
for t in 1 2 3 6 12 24 144; do
  out=$(bcli estimatesmartfee "$t" 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f\"{d['feerate']:.8f} BTC/kvB\" if 'feerate' in d else 'unavailable: '+'; '.join(d.get('errors',[])))" 2>/dev/null)
  printf "  target %3d blocks : %s\n" "$t" "${out:-error}"
done
