#!/usr/bin/env bash
# mine.sh — produce blocks on demand.
#
#   ./mine.sh              mine 1 block, immediately
#   ./mine.sh 6            mine 6 blocks (confirm a channel open, say)
#   ./mine.sh --every 30   mine 1 block every 30s until Ctrl-C
#
# On a private signet we are the ONLY source of blocks, which is the whole
# reason to run one: nothing confirms until you say so, so a test can park a
# channel in a half-open state indefinitely and then advance the chain by
# exactly one block to watch what each implementation does.
#
# Core's signet miner normally PACES blocks so the chain tracks wall-clock —
# once the chain catches up, `--max-blocks=6` would take an hour.  We bypass the
# pacing with --set-block-time, which mines one block at an explicit timestamp
# with no delay.  Each block gets max(now, prev+1): monotonically increasing (so
# it stays ahead of median-time-past) but never running ahead of real time, so
# the chain can't drift into the 2-hours-in-the-future rejection window.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/_common.sh"

COUNT=1
EVERY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --every)   EVERY="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)         COUNT="$1"; shift ;;
  esac
done

bitcoind_running || { echo "${C_ERR}bitcoind is not running${C_OFF} — run ./up.sh bitcoind"; exit 1; }

if [[ -n "$EVERY" ]]; then
  echo "mining 1 block every ${EVERY}s — Ctrl-C to stop"
  trap 'echo; echo "stopped at height $(bcli getblockcount)"; exit 0' INT
  while true; do
    mine_blocks 1 && echo "$(date +%H:%M:%S)  height $(bcli getblockcount)"
    sleep "$EVERY"
  done
fi

BEFORE=$(bcli getblockcount)
mine_blocks "$COUNT"
AFTER=$(bcli getblockcount)
echo "${C_OK}mined $((AFTER-BEFORE)) block(s)${C_OFF}  height $BEFORE → $AFTER"
