#!/usr/bin/env bash
# inspect/run-all.sh — the full OFFLINE gate suite (no network, no Lightning node).
#
#   inspect/run-all.sh
#
# Two kinds of gate run here:
#
#   * the VECTOR gates (crypto, wire, transport, peer) check each layer against
#     the RFCs' and BOLTs' own published vectors, in one process;
#   * the LOOPBACK gate stands the whole stack up against itself over a real
#     socket, in its own process because it spawns threads and listens.
#
# The live gate (inspect/live-peer.lisp) is NOT run here: it needs a real
# Lightning node, which CI does not have.  See the devnet at /mnt/lisp/signet.
set -u
cd "$(dirname "$0")/.."                       # repo root
ROOT="$(pwd -P)"
SBCL="${SBCL:-sbcl}"

# Let ASDF find cl-payments + its deps (secp256k1-fast, cl-transport) in either
# layout: vendored under deps/ (git clone --recursive), or as sibling checkouts.
export CL_SOURCE_REGISTRY="(:source-registry (:tree \"$ROOT\") (:tree \"$ROOT/..\") :inherit-configuration)"

pass=0; fail=0; failed=()

run_gate () {
  local name="$1"; shift
  local log="/tmp/lnpay-gate-$name.log"
  local start=$SECONDS
  if "$@" >"$log" 2>&1; then
    printf "  %-22s PASS  (%ds)\n" "$name" "$((SECONDS-start))"
    pass=$((pass+1))
  else
    printf "  %-22s FAIL  (%ds)  -> %s\n" "$name" "$((SECONDS-start))" "$log"
    fail=$((fail+1)); failed+=("$name")
  fi
}

echo "== cl-payments offline gate suite =="

# The vector gates share one image; run-all.lisp aggregates their check counts.
run_gate "vectors" "$SBCL" --non-interactive \
  --eval '(require :asdf)' \
  --eval '(handler-bind ((warning (function muffle-warning))) (asdf:load-system "cl-payments/test"))' \
  --eval '(unless (cl-payments.test:run-all) (sb-ext:exit :code 1))'

# Own process: listens on a socket and spawns threads.
run_gate "loopback" "$SBCL" --non-interactive \
  --load inspect/loopback-test.lisp \
  --eval '(unless (loopback-test:run) (sb-ext:exit :code 1))'

echo "== $pass passed, $fail failed =="
if [ "$fail" -gt 0 ]; then
  echo "failed: ${failed[*]}"
  exit 1
fi
