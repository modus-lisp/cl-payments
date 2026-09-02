#!/usr/bin/env bash
# status.sh — one screen: the chain, every node, its funds, and its node id.
#
# The node ids are the useful part for cl-payments: each one is the 33-byte
# compressed static key that BOLT #8's handshake authenticates, and the `uri`
# line is exactly what CONNECT-PEER takes.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/_common.sh"

echo "═══ chain ══════════════════════════════════════════════════════════════"
if info=$(bcli getblockchaininfo 2>/dev/null); then
  echo "$info" | python3 -c "
import json,sys; d=json.load(sys.stdin)
print(f\"  bitcoind    height {d['blocks']:>6d}   {d['size_on_disk']/1e6:8.1f} MB   signet (private)\")"
  bal=$(wcli getbalances 2>/dev/null | python3 -c "
import json,sys
try:
  m=json.load(sys.stdin)['mine']; print(f\"{m['trusted']:.2f} spendable / {m['immature']:.2f} immature BTC\")
except Exception: print('(miner wallet not loaded)')")
  echo "  miner       $bal"
else
  echo "  bitcoind    ${C_ERR}DOWN${C_OFF}"
fi

echo
echo "═══ lightning ══════════════════════════════════════════════════════════"
for n in $(node_names); do
  impl=$(node_impl "$n"); port=$(node_port "$n")
  if ! node_running "$n"; then
    printf "  %-6s %-4s ${C_DIM}down${C_OFF}\n" "$n" "$impl"; continue
  fi
  if ! out=$(ln_cli "$n" getinfo 2>/dev/null); then
    printf "  %-6s %-4s ${C_WARN}starting${C_OFF}\n" "$n" "$impl"; continue
  fi
  echo "$out" | python3 -c "
import json,sys
d=json.load(sys.stdin)
impl='$impl'
if impl=='cln':
    nid,h,peers=d['id'],d.get('blockheight','?'),d.get('num_peers',0)
    act,pend=d.get('num_active_channels',0),d.get('num_pending_channels',0)
    synced='—'
else:
    nid,h,peers=d['identity_pubkey'],d.get('block_height','?'),d.get('num_peers',0)
    act,pend=d.get('num_active_channels',0),d.get('num_pending_channels',0)
    synced=str(d.get('synced_to_chain'))
print(f\"  {'$n':<6} {impl:<4} ${C_OK}up${C_OFF}   height {h}  peers {peers}  channels {act} active / {pend} pending  synced={synced}\")
print(f\"         uri  {nid}@127.0.0.1:$port\")"
  case "$impl" in
    cln) ln_cli "$n" listfunds 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
onch=sum(o['amount_msat'] for o in d.get('outputs',[]) if o.get('status')=='confirmed')//1000
chans=sum(c.get('our_amount_msat',0) for c in d.get('channels',[]))//1000
print(f'         funds {onch:,} sat on-chain, {chans:,} sat in channels')" ;;
    lnd) ln_cli "$n" walletbalance 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin); print(f\"         funds {int(d['confirmed_balance']):,} sat on-chain\")" ;;
  esac
done
echo
