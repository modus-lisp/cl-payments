#!/usr/bin/env bash
# smoke.sh — prove the devnet actually works, end to end.
#
# Builds the topology   cln1 ── cln2 ── lnd1   and routes a payment from cln1 to
# lnd1 across it.  That last step is the real test: it only succeeds if channel
# establishment, gossip, route-finding, onion construction and HTLC settlement
# all work — and because the middle hop is CLN while the destination is LND, it
# exercises the interop between two independent implementations, which is
# exactly the surface cl-payments has to match.
#
#   ./smoke.sh          build the topology and pay
#   ./smoke.sh --clean  also close channels afterwards
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/_common.sh"

CHANNEL_SATS="${CHANNEL_SATS:-1000000}"     # 0.01 BTC per channel
PAY_MSATS="${PAY_MSATS:-25000000}"          # 25k sat
CLEAN=""
[[ "${1:-}" == "--clean" ]] && CLEAN=1

step() { echo; echo "${C_DIM}── $* ────────────────────────────────────────${C_OFF}"; }
ok()   { echo "  ${C_OK}✓${C_OFF} $*"; }
bad()  { echo "  ${C_ERR}✗${C_OFF} $*"; exit 1; }

for n in $(node_names); do node_running "$n" || bad "$n is not running — ./up.sh all"; done

# ── connect ──────────────────────────────────────────────────────────────────
step "peering"
connect_pair() {
  local from=$1 to=$2 uri; uri=$(node_uri "$to") || bad "no uri for $to"
  case "$(node_impl "$from")" in
    cln) ln_cli "$from" connect "$uri" >/dev/null 2>&1 ;;
    lnd) ln_cli "$from" connect "$uri" >/dev/null 2>&1 || true ;;   # already-connected is an error in lncli
  esac
  ok "$from → $to"
}
connect_pair cln1 cln2
connect_pair cln2 lnd1

# ── open channels ────────────────────────────────────────────────────────────
step "opening channels (${CHANNEL_SATS} sat each)"
open_channel() {
  local from=$1 to=$2 id; id=$(node_id "$to")
  case "$(node_impl "$from")" in
    cln) ln_cli "$from" fundchannel "$id" "$CHANNEL_SATS" >/dev/null 2>&1 \
           && ok "$from → $to funded" || bad "$from → $to fundchannel failed" ;;
    lnd) ln_cli "$from" openchannel --node_key "$id" --local_amt "$CHANNEL_SATS" >/dev/null 2>&1 \
           && ok "$from → $to funded" || bad "$from → $to openchannel failed" ;;
  esac
}
open_channel cln1 cln2
open_channel cln2 lnd1

# ── confirm ──────────────────────────────────────────────────────────────────
# Channels need burial before either side will route over them; this is the one
# place a public signet would cost 30+ minutes and ours costs a couple seconds.
step "confirming"
mine_blocks 6
ok "mined to height $(bcli getblockcount)"

active_channels() {
  local n=$1
  case "$(node_impl "$n")" in
    cln) ln_cli "$n" listpeerchannels 2>/dev/null | python3 -c "
import json,sys
print(sum(1 for c in json.load(sys.stdin).get('channels',[]) if c.get('state')=='CHANNELD_NORMAL'))" ;;
    lnd) ln_cli "$n" listchannels 2>/dev/null | python3 -c "
import json,sys
print(sum(1 for c in json.load(sys.stdin).get('channels',[]) if c.get('active')))" ;;
  esac
}

echo -n "  waiting for channels to activate"
for _ in $(seq 1 40); do
  a=$(active_channels cln1); b=$(active_channels lnd1)
  [[ "${a:-0}" -ge 1 && "${b:-0}" -ge 1 ]] && break
  echo -n "."; mine_blocks 1 >/dev/null 2>&1; sleep 3
done
echo
ok "cln1 active=$(active_channels cln1)  cln2 active=$(active_channels cln2)  lnd1 active=$(active_channels lnd1)"

# ── route a payment cln1 → (cln2) → lnd1 ─────────────────────────────────────
step "paying cln1 → cln2 → lnd1  (${PAY_MSATS} msat)"
INV=$(ln_cli lnd1 addinvoice --amt $((PAY_MSATS/1000)) 2>/dev/null | py_get payment_request)
[[ -n "$INV" ]] || bad "lnd1 would not produce an invoice"
ok "invoice ${INV:0:36}…"

# cln1 needs to know the cln2→lnd1 channel exists before it can build a route,
# and that knowledge arrives by gossip, which is not instant.
for _ in $(seq 1 20); do
  ln_cli cln1 listchannels >/dev/null 2>&1
  n=$(ln_cli cln1 listchannels 2>/dev/null | python3 -c "
import json,sys; print(len(json.load(sys.stdin).get('channels',[])))" 2>/dev/null)
  [[ "${n:-0}" -ge 2 ]] && break
  sleep 3
done
ok "cln1 sees ${n:-0} channel direction(s) in its routing graph"

if OUT=$(ln_cli cln1 pay "$INV" 2>&1); then
  echo "$OUT" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print('  ${C_OK}✓${C_OFF} paid:', d.get('status'), d.get('amount_sent_msat'),'msat sent,', len(d.get('parts',[]) or [1]),'part(s)')
except Exception: pass" 2>/dev/null || ok "paid"
else
  echo "$OUT" | tail -4; bad "payment failed"
fi

step "result"
for n in $(node_names); do
  printf "  %-6s %s active channel(s)\n" "$n" "$(active_channels "$n")"
done

if [[ -n "$CLEAN" ]]; then
  step "closing"
  ln_cli cln1 close "$(node_id cln2)" >/dev/null 2>&1 && ok "cln1 → cln2 closed"
  ln_cli cln2 close "$(node_id lnd1)" >/dev/null 2>&1 && ok "cln2 → lnd1 closed"
  mine_blocks 6; ok "mined to height $(bcli getblockcount)"
fi
echo
echo "${C_OK}devnet is working end to end.${C_OFF}"
