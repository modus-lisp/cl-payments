#!/usr/bin/env bash
# topology.sh — build the routing line, so there is something to route ACROSS.
#
#   ./topology.sh            connect and open the whole line
#   ./topology.sh --show     just print what exists now
#
# The line is
#
#     cln1 ── cln2 ── lnd1 ── cln3 ── lnd2
#
# with cl-payments nodes hanging off it.  Two nodes are enough to open a channel
# and three to route once, but an onion is a fixed-size packet carrying one
# encrypted layer per hop, and a two-hop route exercises almost none of it: no
# intermediate node ever has to peel a layer and forward to ANOTHER intermediate.
# Four hops does, and alternating CLN and LND means every forward crosses an
# implementation boundary rather than staying inside one codebase's assumptions.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/_common.sh"

CHANNEL_SATS="${CHANNEL_SATS:-1000000}"

show () {
  echo "═══ nodes ══════════════════════════════════════════════════════════════"
  for n in $(node_names); do
    if node_running "$n"; then
      printf "  %-6s %-4s %s\n" "$n" "$(node_impl "$n")" "$(node_id "$n")"
    else
      printf "  %-6s %-4s ${C_DIM}down${C_OFF}\n" "$n" "$(node_impl "$n")"
    fi
  done
  for n in $(clp_names); do
    if clp_running "$n"; then
      printf "  %-6s %-4s %s\n" "$n" "clp" "$(clp_id "$n")"
    else
      printf "  %-6s %-4s ${C_DIM}down${C_OFF}\n" "$n" "clp"
    fi
  done
  echo
  echo "═══ channels ═══════════════════════════════════════════════════════════"
  for n in $(node_names); do
    node_running "$n" || continue
    case "$(node_impl "$n")" in
      cln) ln_cli "$n" listpeerchannels 2>/dev/null | python3 -c "
import json,sys
for c in json.load(sys.stdin).get('channels',[]):
    print(f\"  $n  {c.get('short_channel_id') or '(pending)'}  {c.get('state')}  peer {c.get('peer_id','')[:16]}\")" ;;
      lnd) ln_cli "$n" listchannels 2>/dev/null | python3 -c "
import json,sys
for c in json.load(sys.stdin).get('channels',[]):
    print(f\"  $n  {c.get('chan_id')}  active={c.get('active')}  peer {c.get('remote_pubkey','')[:16]}\")" ;;
    esac
  done
}

[ "${1:-}" = "--show" ] && { show; exit 0; }

have_channel () {   # $1 from, $2 to — is there already one between them?
  local from=$1 to=$2 tid; tid=$(node_id "$to")
  case "$(node_impl "$from")" in
    cln) ln_cli "$from" listpeerchannels 2>/dev/null | python3 -c "
import json,sys
print(any(c.get('peer_id')=='$tid' for c in json.load(sys.stdin).get('channels',[])))" | grep -q True ;;
    lnd) ln_cli "$from" listchannels 2>/dev/null | python3 -c "
import json,sys
print(any(c.get('remote_pubkey')=='$tid' for c in json.load(sys.stdin).get('channels',[])))" | grep -q True ;;
  esac
}

echo "building the routing line (${CHANNEL_SATS} sat per channel)"
for pair in "${LN_LINE[@]}"; do
  set -- $pair; from=$1; to=$2
  if ! node_running "$from" || ! node_running "$to"; then
    printf "  %-14s ${C_WARN}skipped (a node is down)${C_OFF}\n" "$from → $to"; continue
  fi
  if have_channel "$from" "$to"; then
    printf "  %-14s already open\n" "$from → $to"; continue
  fi
  ln_cli "$from" connect "$(node_uri "$to")" >/dev/null 2>&1 || true
  sleep 1
  case "$(node_impl "$from")" in
    cln) ln_cli "$from" fundchannel "$(node_id "$to")" "$CHANNEL_SATS" >/dev/null 2>&1 \
           && printf "  %-14s ${C_OK}opened${C_OFF}\n" "$from → $to" \
           || printf "  %-14s ${C_ERR}failed${C_OFF}\n" "$from → $to" ;;
    lnd) ln_cli "$from" openchannel --node_key "$(node_id "$to")" \
              --local_amt "$CHANNEL_SATS" >/dev/null 2>&1 \
           && printf "  %-14s ${C_OK}opened${C_OFF}\n" "$from → $to" \
           || printf "  %-14s ${C_ERR}failed${C_OFF}\n" "$from → $to" ;;
  esac
done

echo
echo "confirming"
mine_blocks 6
echo "  height $(bcli getblockcount)"

# Channels need burial before either end will route over them, and the graph
# needs to propagate before anyone can FIND the route.
echo -n "  waiting for the line to come up"
for _ in $(seq 1 30); do
  ready=$(ln_cli cln1 listchannels 2>/dev/null | python3 -c "
import json,sys
print(len(json.load(sys.stdin).get('channels',[])))" 2>/dev/null || echo 0)
  [ "${ready:-0}" -ge 8 ] && break     # 4 channels x 2 directions
  echo -n "."; mine_blocks 1; sleep 3
done
echo
echo "  cln1 sees ${ready:-0} directed edges"
echo
show
