;;;; inspect/onchain-test.lisp
;;;;
;;;; Phase 8 — every on-chain answer, validated by cl-consensus's interpreter.
;;;;
;;;; These transactions are the ones that matter when the peer has stopped
;;;; cooperating, which means there is nobody to tell us we got them wrong.  A
;;;; penalty transaction with a bad witness is not rejected by the peer — it is
;;;; rejected by the network, silently, while their CSV delay runs out.  So
;;;; every transaction built here is spent under the same script interpreter
;;;; that validates blocks, with CSV enforcement on.

(in-package #:cl-payments.test)

(defun oc-spends-p (tx prevout-script amount &key (flags '(:p2sh :witness :csv)))
  (handler-case (bs:verify-input tx 0 prevout-script amount :flags flags)
    (error () nil)))

(defun oc-cycle (a b)
  "One full add/commit/revoke round from A, then B settles; leaves both quiescent."
  (let ((pre (c:sha256 (c:ascii->bytes "onchain/pre"))))
    (lv:receive-add b (payload (lv:send-add a 50000000 (c:sha256 pre) 700 (c:zeros u:+onion-packet-size+))))
    (lv:receive-revocation a (payload (lv:receive-commit b (payload (lv:send-commit a)))))
    (lv:receive-revocation b (payload (lv:receive-commit a (payload (lv:send-commit b)))))
    (lv:receive-fulfill a (payload (lv:send-fulfill b 0 pre)))
    ;; The fulfil is B's change: B signs it into A's commitment first, then A
    ;; signs it into B's.  Doing it the other way round leaves B's commitment
    ;; still carrying the HTLC.
    (lv:receive-revocation b (payload (lv:receive-commit a (payload (lv:send-commit b)))))
    (lv:receive-revocation a (payload (lv:receive-commit b (payload (lv:send-commit a)))))))

(defun run-onchain-tests ()
  (w:select-network :signet)
  (multiple-value-bind (a b fscript cap) (make-live-pair)
    (let ((dest (m:p2wpkh (lt-pub (lt-key "sweep-dest")))))
      ;; Commitment 0 on both sides is signed during the funding handshake; the
      ;; live pair starts AFTER it, so run a cycle to get real signatures stored.
      (oc-cycle a b)
      (let ((old-a-tx (lv::b-tx (lv::%build a (lv:local-spec a) :ours t :point (lv::local-point a 1) :index 1))))
        ;; A's commitment 1 was revoked during the cycle above (A is now at 3).
        (check "setup: A has advanced past commitment 1" (> (lv:live-local-commit-index a) 1))

        (with-gate ("onchain: a force-close is a valid, fully-signed commitment")
          (let ((ours (lv:local-commitment-tx a)))
            (check "A can produce its current commitment with both signatures" (and ours t))
            (check "it spends the funding output under cl-consensus"
                   (oc-spends-p ours (m:p2wsh fscript) cap))
            (check "B recognises it as A's current commitment"
                   (eq :their-commitment (oc:classify-spend b ours)))))

        (with-gate ("onchain: classification")
          (multiple-value-bind (kind n) (oc:classify-spend a (lv:local-commitment-tx a))
            (check "A sees its own commitment as :our-commitment" (eq kind :our-commitment))
            (check "at its current index" (= n (lv:live-local-commit-index a))))
          (multiple-value-bind (kind n) (oc:classify-spend b (lv:local-commitment-tx a))
            (check "B sees A's current commitment as :their-commitment" (eq kind :their-commitment))
            (check "and reads the right number off the obscured fields" (= n (lv:live-local-commit-index a))))
          (multiple-value-bind (kind n) (oc:classify-spend b old-a-tx)
            (check "B sees A's commitment 1 as :revoked" (eq kind :revoked))
            (check-equal "number 1" n 1))
          (check "A cannot claim its own current commitment is revoked"
                 (null (lv:revoked-secret-for b (lv:live-local-commit-index a)))))

        (with-gate ("onchain: B sweeps its to_remote from A's commitment, immediately")
          (let* ((their (lv:local-commitment-tx a))
                 (sweep (oc:sweep-to-remote b their dest)))
            (multiple-value-bind (idx value) (oc:to-remote-output b their)
              (check "B's to_remote is present" (and idx t))
              (check "the sweep spends it under cl-consensus"
                     (oc-spends-p sweep (btx:txout-script (nth idx (btx:tx-outputs their))) value))
              (check "the sweep pays our destination minus the fee"
                     (and (equalp (btx:txout-script (first (btx:tx-outputs sweep))) dest)
                          (= (btx:txout-value (first (btx:tx-outputs sweep))) (- value 500)))))))

        (with-gate ("onchain: A sweeps its own to_local, only after the delay")
          (let* ((ours (lv:local-commitment-tx a))
                 (sweep (oc:sweep-to-local a ours dest)))
            (multiple-value-bind (idx value script) (oc:to-local-output a ours)
              (declare (ignore script))
              (check "A's to_local is present" (and idx t))
              (check "with the CSV delay in nSequence, it spends"
                     (oc-spends-p sweep (btx:txout-script (nth idx (btx:tx-outputs ours))) value))
              ;; The same transaction with a shorter sequence must FAIL: CSV is
              ;; what stops us taking our money before they can punish a cheat.
              (let* ((in (first (btx:tx-inputs sweep)))
                     (early (btx:make-tx :version 2
                                         :inputs (list (btx:make-txin :prev-hash (btx:txin-prev-hash in) :prev-index (btx:txin-prev-index in)
                                                                      :script #() :sequence 1))
                                         :outputs (btx:tx-outputs sweep) :witnesses (btx:tx-witnesses sweep)
                                         :locktime 0 :segwit-p t)))
                (check "a sweep before the delay is rejected"
                       (not (oc-spends-p early (btx:txout-script (nth idx (btx:tx-outputs ours))) value)))))))

        (with-gate ("onchain: B punishes A's revoked commitment")
          (let ((pen (oc:penalty b old-a-tx 1 dest)))
            (multiple-value-bind (lidx lvalue) (oc:to-local-output b old-a-tx :theirs t :n 1)
              (multiple-value-bind (ridx rvalue) (oc:to-remote-output b old-a-tx)
                (check "the penalty takes A's to_local AND B's to_remote" (and lidx ridx (= 2 (length (btx:tx-inputs pen)))))
                (check "input 0 (A's to_local, via the revocation key) spends"
                       (oc-spends-p pen (btx:txout-script (nth lidx (btx:tx-outputs old-a-tx))) lvalue))
                (check "input 1 (B's to_remote) spends"
                       (handler-case (bs:verify-input pen 1 (btx:txout-script (nth ridx (btx:tx-outputs old-a-tx))) rvalue
                                                      :flags '(:p2sh :witness :csv))
                         (error () nil)))
                (check "the penalty pays it all to B minus one fee"
                       (= (btx:txout-value (first (btx:tx-outputs pen))) (- (+ lvalue rvalue) 500)))
                ;; And it cannot be done to a commitment that was NOT revoked.
                (check-signals "no penalty against A's current commitment" oc:onchain-error
                               (oc:penalty b (lv:local-commitment-tx a) (lv:live-local-commit-index a) dest))))))

        (with-gate ("onchain: the mutual close is recognised")
          (let ((a-spk (m:p2wpkh (lt-pub (lt-key "a/close")))) (b-spk (m:p2wpkh (lt-pub (lt-key "b/close")))))
            (lv:receive-shutdown b (payload (lv:send-shutdown a a-spk)))
            (lv:receive-shutdown a (payload (lv:send-shutdown b b-spk)))
            (multiple-value-bind (msg tx) (lv:propose-close a 1000)
              (lv:receive-closing-signed b (payload msg))
              (check "A: :mutual-close" (eq :mutual-close (oc:classify-spend a tx)))
              (check "B: :mutual-close" (eq :mutual-close (oc:classify-spend b tx))))))

        (with-gate ("onchain: revocation secrets survive persistence")
          (let ((back (lv:plist->live (lv:live->plist b))))
            (check "the reloaded channel can still punish commitment 1"
                   (equalp (lv:revoked-secret-for back 1) (lv:revoked-secret-for b 1)))
            (check "and still holds their signature over our commitment"
                   (equalp (lv:live-local-commit-sig back) (lv:live-local-commit-sig b)))))))))
