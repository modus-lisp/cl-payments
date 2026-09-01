;;;; inspect/run-all.lisp
;;;;
;;;; The offline gate suite — every check in one command, no network, no peer,
;;;; no Bitcoin node.  Mirrors cl-consensus's inspect/run-all.sh: if this is
;;;; green, the primitives and the wire format agree with the specs that define
;;;; them.  What it CANNOT tell you is whether a real implementation will talk to
;;;; us — that is inspect/live-peer.lisp, against the signet devnet.

(in-package #:cl-payments.test)

(defun run-all ()
  (setf *checks* 0 *failures* '())
  (format t "~&cl-payments — offline gates~%")
  (run-crypto-tests)
  (run-wire-tests)
  (run-transport-tests)
  (run-peer-tests)
  (run-gossip-tests)
  (run-keys-tests)
  (run-commitment-tests)
  (run-channel-tests)
  (run-updates-tests)
  (let ((ok (report)))
    (unless ok (uiop:quit 1))
    ok))
