#!/usr/bin/env bash
# clp-ctl.sh — talk to a cl-payments daemon over its control socket.
#   ./clp-ctl.sh clp3 '(:info)'
#   ./clp-ctl.sh clp3 '(:channels)'
#   ./clp-ctl.sh clp3 '(:invoice :amount-msat 1000 :description "x")'
#   ./clp-ctl.sh clp3 '(:pay :bolt11 "lntbs...")'        then (:payment-status :payment-hash "...")
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/_common.sh"
clp_ctl "$1" "$2"
