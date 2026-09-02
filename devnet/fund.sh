#!/usr/bin/env bash
# fund.sh — put on-chain coins in the Lightning nodes' wallets.
#
#   ./fund.sh              give every node the default amount
#   ./fund.sh cln1         give one node the default amount
#   ./fund.sh cln1 2.5     give one node 2.5 BTC
#
# Coins come from the `miner` wallet, which holds every block subsidy on this
# chain — no faucet, no captcha, no rate limit.  That is the practical payoff of
# running our own signet: funding is a local RPC call, so a test that needs a
# freshly funded node can just make one.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/_common.sh"

AMOUNT_DEFAULT="${FUND_AMOUNT:-1.0}"
TARGETS=$(node_names)
AMOUNT="$AMOUNT_DEFAULT"

if [[ $# -ge 1 ]]; then
  node_impl "$1" >/dev/null 2>&1 || { echo "unknown node: $1"; exit 1; }
  TARGETS="$1"; [[ $# -ge 2 ]] && AMOUNT="$2"
fi

bitcoind_running || { echo "${C_ERR}bitcoind is not running${C_OFF}"; exit 1; }

SENT=0
for n in $TARGETS; do
  node_running "$n" || { printf "%-6s ${C_DIM}down, skipped${C_OFF}\n" "$n"; continue; }
  addr=$(node_address "$n")
  if [[ -z "$addr" ]]; then printf "%-6s ${C_WARN}no address${C_OFF}\n" "$n"; continue; fi
  txid=$(wcli sendtoaddress "$addr" "$AMOUNT" 2>&1) || { printf "%-6s ${C_ERR}%s${C_OFF}\n" "$n" "$txid"; continue; }
  printf "%-6s %s BTC → %s\n" "$n" "$AMOUNT" "$addr"
  printf "       ${C_DIM}%s${C_OFF}\n" "$txid"
  SENT=$((SENT+1))
done

if [[ $SENT -gt 0 ]]; then
  # One block confirms them; a few more so the nodes treat the coins as settled
  # and will spend them into a channel funding transaction.
  mine_blocks 3
  echo "${C_OK}confirmed${C_OFF} at height $(bcli getblockcount)"
  echo
  for n in $TARGETS; do
    node_running "$n" && printf "  %-6s %'d sat\n" "$n" "$(node_balance "$n")"
  done
fi
