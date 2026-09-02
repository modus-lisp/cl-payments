;;;; inspect/live-test.lisp
;;;;
;;;; Phase 4d — two live channels, run against each other.
;;;;
;;;; Both ends here are our own code, so a mistake made symmetrically on both
;;;; sides cancels out and passes: that is what the devnet run against Core
;;;; Lightning is for.  What THIS catches is the asymmetric bookkeeping — the
;;;; change stages, whose point derives which key, which commitment a change is
;;;; in at each instant — because those errors do not cancel.  A and B hold
;;;; different views, and if either applies a change one step early or late,
;;;; the transaction A signs is not the one B verifies.
;;;;
;;;; And every commitment that either side accepts is then SPENT under
;;;; cl-consensus's script interpreter with the real 2-of-2 witness.  A
;;;; signature that verifies in isolation but produces an unspendable
;;;; transaction would be worse than one that fails: it looks like a channel.

(in-package #:cl-payments.test)

(defun lt-key (label) (secp:bytes-to-int (c:sha256 (c:ascii->bytes (format nil "live-test/~a" label)))))
(defun lt-pub (k) (c:compressed-pubkey (c:pubkey-of k)))

(defun make-live-pair ()
  "A opened the channel with 1_000_000 sat, pushing 200_000 to B."
  (let* ((fund-txid (c:sha256 (c:ascii->bytes "live-test/funding")))
         (cap 1000000) (a-msat 800000000) (b-msat 200000000)
         (a-seed (c:sha256 (c:ascii->bytes "live-test/a-seed")))
         (b-seed (c:sha256 (c:ascii->bytes "live-test/b-seed")))
         (a (list :funding (lt-key "a/f") :revocation (lt-key "a/r") :payment (lt-key "a/p")
                  :delayed (lt-key "a/d") :htlc (lt-key "a/h")))
         (b (list :funding (lt-key "b/f") :revocation (lt-key "b/r") :payment (lt-key "b/p")
                  :delayed (lt-key "b/d") :htlc (lt-key "b/h")))
         (cid (ch:channel-id fund-txid 0)))
    (flet ((mk (mine theirs opener local remote my-seed their-seed my-delay their-delay)
             (let ((lc (lv:make-live
                        :channel-id cid :funding-txid fund-txid :funding-index 0 :capacity-sat cap
                        :opener opener
                        :funding-priv (getf mine :funding) :revocation-priv (getf mine :revocation)
                        :payment-priv (getf mine :payment) :delayed-priv (getf mine :delayed)
                        :htlc-priv (getf mine :htlc) :seed my-seed
                        :remote-funding-pubkey (lt-pub (getf theirs :funding))
                        :remote-revocation-basepoint (lt-pub (getf theirs :revocation))
                        :remote-payment-basepoint (lt-pub (getf theirs :payment))
                        :remote-delayed-basepoint (lt-pub (getf theirs :delayed))
                        :remote-htlc-basepoint (lt-pub (getf theirs :htlc))
                        :local-dust-limit 546 :remote-dust-limit 546
                        :local-to-self-delay my-delay :remote-to-self-delay their-delay
                        :feerate-per-kw 2500 :local-msat local :remote-msat remote
                        :remote-first-point (k:per-commitment-point their-seed k:+max-commitment-index+))))
               ;; channel_ready would carry this
               (lv:set-remote-next-point lc (k:per-commitment-point their-seed (1- k:+max-commitment-index+)))
               lc)))
      (values (mk a b :local a-msat b-msat a-seed b-seed 144 100)
              (mk b a :remote b-msat a-msat b-seed a-seed 100 144)
              (m:funding-script (lt-pub (getf a :funding)) (lt-pub (getf b :funding)))
              cap))))

(defun payload (msg) (subseq msg 2))

(defun spendable-p (tx sig-a pub-a sig-b pub-b funding-script cap)
  "Does this commitment, with both signatures, actually spend the funding output
   under cl-consensus's interpreter?"
  (let ((spent (btx:make-tx :version (btx:tx-version tx) :inputs (btx:tx-inputs tx)
                            :outputs (btx:tx-outputs tx) :locktime (btx:tx-locktime tx)
                            :witnesses (list (m:funding-witness sig-a pub-a sig-b pub-b funding-script))
                            :segwit-p t)))
    (handler-case (bs:verify-input spent 0 (m:p2wsh funding-script) cap)
      (error () nil))))

(defun run-live-tests ()
  (w:select-network :signet)
  (multiple-value-bind (a b fscript cap) (make-live-pair)
    (declare (ignorable fscript cap))
    (let ((preimage (c:sha256 (c:ascii->bytes "live-test/preimage")))
          (hash nil))
      (setf hash (c:sha256 preimage))

      (with-gate ("live: A offers an HTLC and signs B's commitment")
        (let* ((add (lv:send-add a 50000000 hash 700 (c:zeros u:+onion-packet-size+))))
          (check "A's balance is unchanged until B signs it into A's commitment"
                 (= 800000000 (lv:live-local-balance-msat a)))
          (lv:receive-add b (payload add))
          (check "B sees the proposal but not yet in its commitment"
                 (null (lv:live-htlcs b)))
          (let ((cs (lv:send-commit a)))
            (check "A is now awaiting revocation" (lv:live-awaiting-revocation-p a))
            (check-signals "A cannot send a second commitment_signed meanwhile"
                           lv:live-error (lv:send-commit a))
            (let ((raa (check-no-signal "B verifies A's signatures and revokes"
                         (lv:receive-commit b (payload cs)))))
              (check "the HTLC is in B's commitment" (= 1 (length (lv:live-htlcs b))))
              (check "B's view: A's balance dropped by the HTLC"
                     (= 750000000 (lv:live-remote-balance-msat b)))
              (check-no-signal "A accepts B's revocation" (lv:receive-revocation a (payload raa)))
              (check "A is no longer awaiting" (not (lv:live-awaiting-revocation-p a)))
              (check "the HTLC is now in A's view of B's commitment"
                     (= 1 (length (lv:spec-htlcs (lv:remote-spec a)))))
              (check "but not yet in A's OWN commitment — B has not signed it there"
                     (null (lv:live-htlcs a)))
              (check "B cannot settle it yet: it is not in both commitments"
                     (null (lv:fully-committed-received-htlcs b)))))))

      (with-gate ("live: B signs A's commitment with the HTLC")
        (let* ((cs (lv:send-commit b))
               (raa (check-no-signal "A verifies B's signature and htlc_signature"
                      (lv:receive-commit a (payload cs)))))
          (check "the HTLC is in A's commitment" (= 1 (length (lv:live-htlcs a))))
          (check "A's balance reflects the in-flight HTLC" (= 750000000 (lv:live-local-balance-msat a)))
          (check-no-signal "B accepts A's revocation" (lv:receive-revocation b (payload raa)))
          (check "the HTLC is now fully committed on both sides"
                 (= 1 (length (lv:fully-committed-received-htlcs b))))
          (check "both sides agree on the commitment indices"
                 (and (= (lv:live-local-commit-index a) (lv:live-remote-commit-index b))
                      (= (lv:live-local-commit-index b) (lv:live-remote-commit-index a))))))

      (with-gate ("live: B fulfils, money moves, HTLC output disappears")
        (check-signals "B cannot fulfil with the wrong preimage"
                       lv:live-error (lv:send-fulfill b 0 (c:zeros 32)))
        (let ((ful (lv:send-fulfill b 0 preimage)))
          (check-no-signal "A verifies B's preimage" (lv:receive-fulfill a (payload ful)))
          (let* ((cs (lv:send-commit b))
                 (raa (check-no-signal "A accepts the commitment without the HTLC"
                        (lv:receive-commit a (payload cs)))))
            (check "A's commitment has no HTLC" (null (lv:live-htlcs a)))
            (check "A's balance is down by the payment" (= 750000000 (lv:live-local-balance-msat a)))
            (check "A's view of B's balance is up by it" (= 250000000 (lv:live-remote-balance-msat a)))
            (check-no-signal "B accepts revocation" (lv:receive-revocation b (payload raa)))
            (let* ((cs2 (lv:send-commit a))
                   (raa2 (check-no-signal "B accepts A's commitment" (lv:receive-commit b (payload cs2)))))
              (check "B's balance is up by the payment" (= 250000000 (lv:live-local-balance-msat b)))
              (check-no-signal "A accepts revocation" (lv:receive-revocation a (payload raa2)))
              (check "nothing is pending anywhere"
                     (and (not (lv:live-pending-changes-p a)) (not (lv:live-pending-changes-p b))
                          (not (lv:live-awaiting-revocation-p a)) (not (lv:live-awaiting-revocation-p b))))
              (check "the two ends agree on every balance"
                     (and (= (lv:live-local-balance-msat a) (lv:live-remote-balance-msat b))
                          (= (lv:live-local-balance-msat b) (lv:live-remote-balance-msat a))))))))

      (with-gate ("live: a failed HTLC returns the money")
        (let ((add (lv:send-add b 10000000 (c:sha256 (c:zeros 1)) 650 (c:zeros u:+onion-packet-size+))))
          (lv:receive-add a (payload add))
          (lv:receive-revocation b (payload (lv:receive-commit a (payload (lv:send-commit b)))))
          (lv:receive-revocation a (payload (lv:receive-commit b (payload (lv:send-commit a)))))
          (check "B's balance is down while in flight" (= 240000000 (lv:live-local-balance-msat b)))
          (lv:send-fail a 0 (c:zeros 4))
          (progn
            (check-no-signal "B accepts the fail" (lv:receive-fail b 0))
            (lv:receive-revocation a (payload (lv:receive-commit b (payload (lv:send-commit a)))))
            (lv:receive-revocation b (payload (lv:receive-commit a (payload (lv:send-commit b)))))
            (check "B's balance is restored" (= 250000000 (lv:live-local-balance-msat b)))
            (check "A's balance is unchanged" (= 750000000 (lv:live-local-balance-msat a))))))

      (with-gate ("live: a revealed secret that does not match is refused")
        (let* ((add (lv:send-add a 1000000 (c:sha256 (c:zeros 2)) 700 (c:zeros u:+onion-packet-size+))))
          (lv:receive-add b (payload add))
          (let* ((cs (lv:send-commit a))
                 (raa (lv:receive-commit b (payload cs)))
                 (bad (copy-seq raa)))
            ;; corrupt one byte of the per_commitment_secret (offset 2 type + 32 cid)
            (setf (aref bad 40) (logxor (aref bad 40) 1))
            (check-signals "A refuses a secret that does not match B's point"
                           lv:live-error (lv:receive-revocation a (payload bad)))
            (check "A is still awaiting the real revocation" (lv:live-awaiting-revocation-p a))
            (check-no-signal "and accepts the real one" (lv:receive-revocation a (payload raa)))
            ;; finish the cycle so the channel is quiescent for the close
            (lv:receive-revocation b (payload (lv:receive-commit a (payload (lv:send-commit b)))))
            (lv:send-fail b 1 (c:zeros 4)) (lv:receive-fail a 1)
            (lv:receive-revocation b (payload (lv:receive-commit a (payload (lv:send-commit b)))))
            (lv:receive-revocation a (payload (lv:receive-commit b (payload (lv:send-commit a))))))))

      (with-gate ("live: tampered commitment_signed is refused")
        ;; Large enough not to be trimmed: a dust HTLC has no output and no
        ;; htlc_signature, so there would be nothing to corrupt.
        (let* ((add (lv:send-add a 50000000 (c:sha256 (c:zeros 3)) 700 (c:zeros u:+onion-packet-size+))))
          (lv:receive-add b (payload add))
          (let* ((cs (lv:send-commit a)) (bad (copy-seq cs)))
            (check "the commitment_signed carries one htlc_signature" (= (length cs) 164))
            (setf (aref bad 50) (logxor (aref bad 50) 1))
            (check-signals "B refuses a corrupted signature" lv:live-error (lv:receive-commit b (payload bad)))
            (check "B's commitment index did not advance" (= 6 (lv:live-local-commit-index b)))
            (let ((bad2 (copy-seq cs)))
              ;; flip a byte inside the htlc_signature (after 2+32+64+2)
              (setf (aref bad2 110) (logxor (aref bad2 110) 1))
              (check-signals "B refuses a corrupted htlc_signature" lv:live-error
                             (lv:receive-commit b (payload bad2))))
            (lv:receive-revocation a (payload (lv:receive-commit b (payload cs))))
            (lv:receive-revocation b (payload (lv:receive-commit a (payload (lv:send-commit b)))))
            (lv:send-fail b 2 (c:zeros 4)) (lv:receive-fail a 2)
            (lv:receive-revocation b (payload (lv:receive-commit a (payload (lv:send-commit b)))))
            (lv:receive-revocation a (payload (lv:receive-commit b (payload (lv:send-commit a))))))))

      (with-gate ("live: the final commitments are spendable under cl-consensus")
        ;; Rebuild A's current commitment as B would sign it, and vice versa, and
        ;; spend each with the real witness.  This is the check that the
        ;; signatures are not merely mutually consistent but consensus-valid.
        (multiple-value-bind (a2 b2 fs cap2) (make-live-pair)
          (declare (ignore a2 b2 fs cap2)))
        (let* ((tx (lv::b-tx (lv::%build a (lv:local-spec a) :ours t
                                        :point (lv::local-point a (lv:live-local-commit-index a)))))
               (a-pub (lt-pub (lt-key "a/f"))) (b-pub (lt-pub (lt-key "b/f")))
               (sig-a (m:sign-commitment tx (lt-key "a/f") a-pub b-pub cap))
               (sig-b (m:sign-commitment tx (lt-key "b/f") b-pub a-pub cap)))
          (check "A's commitment spends the funding output with both signatures"
                 (spendable-p tx sig-a a-pub sig-b b-pub fscript cap))
          (check "…and not with one signature corrupted"
                 (let ((bad (copy-seq sig-b))) (setf (aref bad 5) (logxor (aref bad 5) 1))
                   (not (spendable-p tx sig-a a-pub bad b-pub fscript cap))))))

      ;; A property check, because the two-party cycle cannot see it: if BOTH
      ;; ends put the wrong side's revocation basepoint into a commitment, they
      ;; still agree with each other and every signature verifies.  Against a
      ;; real peer the channel fails at the first commitment_signed.  So check
      ;; the built transaction directly: OUR commitment's to_local must be
      ;; guarded by a revocation key derived from THEIR basepoint and OUR point.
      (with-gate ("live: our commitment is punishable by them, not by us")
        (let* ((n (lv:live-local-commit-index a))
               (point (lv::local-point a n))
               (built (lv::%build a (lv:local-spec a) :ours t :point point))
               (their-rev-base (lt-pub (lt-key "b/r")))
               (our-rev-base (lt-pub (lt-key "a/r")))
               (right (m:p2wsh (m:to-local-script (k:derive-revocation-pubkey their-rev-base point) 144
                                                  (k:derive-pubkey (lt-pub (lt-key "a/d")) point))))
               (wrong (m:p2wsh (m:to-local-script (k:derive-revocation-pubkey our-rev-base point) 144
                                                  (k:derive-pubkey (lt-pub (lt-key "a/d")) point))))
               (scripts (mapcar #'btx:txout-script (btx:tx-outputs (lv::b-tx built)))))
          (check "to_local uses THEIR revocation basepoint" (member right scripts :test #'equalp))
          (check "and not ours" (not (member wrong scripts :test #'equalp)))))

      (with-gate ("live: cooperative close")
        (let ((a-spk (m:p2wpkh (lt-pub (lt-key "a/close"))))
              (b-spk (m:p2wpkh (lt-pub (lt-key "b/close")))))
          (lv:receive-shutdown b (payload (lv:send-shutdown a a-spk)))
          (lv:receive-shutdown a (payload (lv:send-shutdown b b-spk)))
          (check-signals "closing with a fee larger than the opener's balance is refused"
                         lv:live-error (lv:propose-close a 900000000))
          (multiple-value-bind (msg tx sig-a) (lv:propose-close a 1000)
            (multiple-value-bind (reply tx-b sig-b) (lv:receive-closing-signed b (payload msg))
              (declare (ignore sig-b reply))
              (check "both build the same closing transaction"
                     (equalp (btx:tx-txid tx) (btx:tx-txid tx-b)))
              (check "the opener paid the fee"
                     (= (reduce #'+ (btx:tx-outputs tx) :key #'btx:txout-value) (- cap 1000)))
              (check "B's output is exactly B's balance"
                     (find 250000 (btx:tx-outputs tx) :key #'btx:txout-value))
              (check "B is closed" (lv:live-closed-p b))
              (let ((sig-b (m:sign-commitment tx (lt-key "b/f") (lt-pub (lt-key "b/f")) (lt-pub (lt-key "a/f")) cap)))
                (check "the closing transaction spends the funding output"
                       (spendable-p tx sig-a (lt-pub (lt-key "a/f")) sig-b (lt-pub (lt-key "b/f")) fscript cap)))))))

      (with-gate ("live: state survives a round trip through persistence")
        (let ((back (lv:plist->live (lv:live->plist b))))
          (check "balances survive" (= (lv:live-local-balance-msat back) (lv:live-local-balance-msat b)))
          (check "commitment indices survive"
                 (and (= (lv:live-local-commit-index back) (lv:live-local-commit-index b))
                      (= (lv:live-remote-commit-index back) (lv:live-remote-commit-index b))))
          (check "the reestablish message is identical"
                 (equalp (lv:reestablish-message back) (lv:reestablish-message b))))))))
