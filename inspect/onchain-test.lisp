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

        (with-gate ("onchain: HTLCs in flight when a commitment is published")
          (multiple-value-bind (a2 b2 fs2 cap2) (make-live-pair)
            (declare (ignore fs2 cap2))
            ;; A offers B an HTLC; both sides commit it; nobody settles it.
            (let* ((pre (c:sha256 (c:ascii->bytes "onchain/htlc-pre")))
                   (hash (c:sha256 pre)) (expiry 700))
              (oc-cycle a2 b2)   ; some history first, so indices are not 0
              (lv:receive-add b2 (payload (lv:send-add a2 60000000 hash expiry (c:zeros u:+onion-packet-size+))))
              (lv:receive-revocation a2 (payload (lv:receive-commit b2 (payload (lv:send-commit a2)))))
              (lv:receive-revocation b2 (payload (lv:receive-commit a2 (payload (lv:send-commit b2)))))
              (check "the HTLC is in both commitments"
                     (and (= 1 (length (lv:live-htlcs a2))) (= 1 (length (lv:live-htlcs b2)))))
              (let* ((a-tx (lv:local-commitment-tx a2))     ; A force-closes
                     (b-tx (lv:local-commitment-tx b2))     ; or B does
                     (dest2 (m:p2wpkh (lt-pub (lt-key "sweep2")))))

                ;; ---- B claims from A's commitment, with the preimage, at once -----
                (let* ((n (lv:live-local-commit-index a2))
                       (outs (oc:their-htlc-outputs b2 a-tx n))
                       (claims (oc:claim-htlcs-from-their-commitment b2 a-tx n dest2 (list pre))))
                  (check "B locates the HTLC output in A's commitment" (= 1 (length outs)))
                  (check "B builds one preimage claim" (= 1 (length claims)))
                  (when (and outs claims)
                    (destructuring-bind (idx value script rec) (first outs)
                      (declare (ignore script rec))
                      (check "B's preimage claim spends under cl-consensus"
                             (oc-spends-p (first claims) (btx:txout-script (nth idx (btx:tx-outputs a-tx))) value
                                          :flags '(:p2sh :witness :csv :cltv)))))
                  (check "without the preimage B can build nothing"
                         (null (oc:claim-htlcs-from-their-commitment b2 a-tx n dest2 '()))))

                ;; ---- A's own second stage on A's commitment: timeout after expiry -
                (check "before expiry A has no timeout to make"
                       (null (oc:our-htlc-second-stage a2 dest2 '() :height (1- expiry))))
                (let ((stage (oc:our-htlc-second-stage a2 dest2 '() :height expiry)))
                  (check "at expiry A builds an HTLC-timeout" (and (= 1 (length stage)) (eq :timeout (first (first stage)))))
                  (when stage
                    (let* ((htx (third (first stage)))
                           (outs (lv:b-htlc-outputs (lv:built-local a2)))
                           (idx (first (first outs))) (value (floor (lv:hr-amount-msat (second (first outs))) 1000)))
                      (check "the HTLC-timeout, signed by both, spends the HTLC output"
                             (oc-spends-p htx (btx:txout-script (nth idx (btx:tx-outputs a-tx))) value
                                          :flags '(:p2sh :witness :csv :cltv)))
                      (check "its locktime is the expiry" (= expiry (btx:tx-locktime htx)))
                      ;; ---- and then the delayed output is A's, after the CSV --------
                      (let ((sweep (oc:sweep-second-stage a2 htx dest2)))
                        (check "A sweeps the second-stage output after the delay"
                               (oc-spends-p sweep (btx:txout-script (first (btx:tx-outputs htx)))
                                            (btx:txout-value (first (btx:tx-outputs htx)))))))))

                ;; ---- B's second stage on B's commitment: success with the preimage -
                (let ((stage (oc:our-htlc-second-stage b2 dest2 (list pre))))
                  (check "B builds an HTLC-success" (and (= 1 (length stage)) (eq :success (first (first stage)))))
                  (when stage
                    (let* ((htx (third (first stage)))
                           (outs (lv:b-htlc-outputs (lv:built-local b2)))
                           (idx (first (first outs))) (value (floor (lv:hr-amount-msat (second (first outs))) 1000)))
                      (check "the HTLC-success spends B's HTLC output"
                             (oc-spends-p htx (btx:txout-script (nth idx (btx:tx-outputs b-tx))) value
                                          :flags '(:p2sh :witness :csv :cltv))))))

                ;; ---- A times out its offered HTLC on B's commitment, directly ------
                (let* ((n (lv:live-local-commit-index b2))
                       (early (oc:claim-htlcs-from-their-commitment a2 b-tx n dest2 '() :height (1- expiry)))
                       (claims (oc:claim-htlcs-from-their-commitment a2 b-tx n dest2 '() :height expiry)))
                  (check "before expiry A cannot reclaim" (null early))
                  (check "at expiry A builds a timeout claim" (= 1 (length claims)))
                  (when claims
                    (destructuring-bind (idx value script rec) (first (oc:their-htlc-outputs a2 b-tx n))
                      (declare (ignore script rec))
                      (check "the timeout claim spends under CLTV"
                             (oc-spends-p (first claims) (btx:txout-script (nth idx (btx:tx-outputs b-tx))) value
                                          :flags '(:p2sh :witness :csv :cltv))))))

                ;; ---- revoked WITH an HTLC: the penalty takes that too --------------
                ;; Advance B past this commitment (a fee update will do), then punish
                ;; the captured b-tx as revoked.
                (let ((n (lv:live-local-commit-index b2)))
                  (lv:send-fee a2 2600) (lv:receive-fee b2 2600)
                  (lv:receive-revocation a2 (payload (lv:receive-commit b2 (payload (lv:send-commit a2)))))
                  (check "B's commitment with the HTLC is now revoked at A" (and (lv:revoked-secret-for a2 n) t))
                  (let ((pen (oc:penalty a2 b-tx n dest2)))
                    (check "the penalty has three inputs: to_local, to_remote, and the HTLC"
                           (= 3 (length (btx:tx-inputs pen))))
                    (destructuring-bind (hidx hvalue) (subseq (first (oc:their-htlc-outputs a2 b-tx n)) 0 2)
                      (check "the HTLC input spends via the revocation key"
                             (handler-case (bs:verify-input pen 2 (btx:txout-script (nth hidx (btx:tx-outputs b-tx))) hvalue
                                                            :flags '(:p2sh :witness :csv :cltv))
                               (error () nil))))))))))

        (with-gate ("onchain: every HTLC output in their commitment is located, whatever the ordering")
          ;; The commitment orders HTLC outputs by value, then script, then cltv.
          ;; Locating them must not depend on re-deriving that order: equal
          ;; amounts with different hashes, and expiries past 1,000,000, used
          ;; to drop outputs from the penalty silently.
          (let ((rng (sb-ext:seed-random-state 20261009)) (all-found t) (rounds 0))
            (dotimes (round 12)
              (multiple-value-bind (a3 b3) (make-live-pair)
                (oc-cycle a3 b3)
                (let* ((n-htlcs (+ 2 (random 3 rng)))
                       (equal-amt (+ 50000000 (* 1000 (random 50 rng)))))
                  (dotimes (i n-htlcs)
                    (let ((hash (c:sha256 (c:ascii->bytes (format nil "p3/~d/~d" round i))))
                          (amt (if (< i 2) equal-amt (+ 50000000 (* 1000 (random 20000 rng)))))
                          (cltv (if (evenp round) (+ 500 (random 400 rng)) (+ 1000000 (random 600000 rng)))))
                      (lv:receive-add b3 (payload (lv:send-add a3 amt hash cltv (c:zeros u:+onion-packet-size+))))))
                  (lv:receive-revocation a3 (payload (lv:receive-commit b3 (payload (lv:send-commit a3)))))
                  (lv:receive-revocation b3 (payload (lv:receive-commit a3 (payload (lv:send-commit b3)))))
                  (let* ((a-tx (lv:local-commitment-tx a3))
                         (n (lv:live-local-commit-index a3))
                         (outs (oc:their-htlc-outputs b3 a-tx n)))
                    (incf rounds)
                    (unless (and (= n-htlcs (length outs))
                                 (= n-htlcs (length (remove-duplicates (mapcar #'first outs)))))
                      (setf all-found nil))))))
            (check (format nil "all HTLC outputs found, each once, in ~d random commitments" rounds) all-found)))

        (with-gate ("onchain: fees follow the feerate")
          (check-equal "a P2WPKH sweep at 1 sat/vB" (oc:fee-for 1000 :p2wpkh-inputs 1) 110)
          (check-equal "the same at 10 sat/vB" (oc:fee-for 10000 :p2wpkh-inputs 1) 1100)
          (check "a penalty with three script inputs costs more than one"
                 (> (oc:fee-for 2000 :script-inputs 3) (oc:fee-for 2000 :script-inputs 1)))
          (check "never zero" (>= (oc:fee-for 1 :p2wpkh-inputs 1) 1))
          ;; and the builders actually use it: the same sweep at two rates
          (let* ((their (lv:local-commitment-tx a))
                 (cheap (oc:sweep-to-remote b their dest :feerate 1000))
                 (dear (oc:sweep-to-remote b their dest :feerate 20000)))
            (multiple-value-bind (idx value) (oc:to-remote-output b their)
              (declare (ignore idx))
              (check "a higher feerate leaves less in the sweep"
                     (< (btx:txout-value (first (btx:tx-outputs dear))) (btx:txout-value (first (btx:tx-outputs cheap)))))
              (check-equal "and the cheap one paid exactly its estimate"
                           (- value (btx:txout-value (first (btx:tx-outputs cheap)))) (oc:fee-for 1000 :p2wpkh-inputs 1))
              (check "the mock chain reports a feerate above the floor"
                     (>= (chn:chain-feerate (chn:make-mock-chain)) 1000)))))

        (with-gate ("onchain: anchor channels — sweeps, funded second stage, and the bump")
          (multiple-value-bind (a3 b3 fs3 cap3) (make-live-pair :anchors t)
            (declare (ignore fs3 cap3))
            (let* ((pre (c:sha256 (c:ascii->bytes "onchain/anchor-pre"))) (hash (c:sha256 pre)) (expiry 700)
                   (dest3 (m:p2wpkh (lt-pub (lt-key "sweep3"))))
                   (fee-key (lt-key "fee-utxo"))
                   (utxo (oc:make-utxo :txid (c:sha256 (c:ascii->bytes "a deposit")) :vout 0 :value 50000 :privkey fee-key)))
              (oc-cycle a3 b3)
              (lv:receive-add b3 (payload (lv:send-add a3 60000000 hash expiry (c:zeros u:+onion-packet-size+))))
              (lv:receive-revocation a3 (payload (lv:receive-commit b3 (payload (lv:send-commit a3)))))
              (lv:receive-revocation b3 (payload (lv:receive-commit a3 (payload (lv:send-commit b3)))))
              (let ((a-tx (lv:local-commitment-tx a3)))
                (check "A's anchor commitment has two anchors"
                       (= 2 (count 330 (btx:tx-outputs a-tx) :key #'btx:txout-value)))
                (check "A's commitment spends the funding output" (oc-spends-p a-tx (m:p2wsh fs3) cap3))
                ;; to_remote: B sweeps through the 1-CSV script path
                (let ((sweep (oc:sweep-to-remote b3 a-tx dest3)))
                  (multiple-value-bind (idx value) (oc:to-remote-output b3 a-tx)
                    (check "B's to_remote is a script output" (and idx t))
                    (check "B sweeps it with sequence 1 under CSV"
                           (oc-spends-p sweep (btx:txout-script (nth idx (btx:tx-outputs a-tx))) value))))
                ;; second stage: A's HTLC-timeout is zero-fee and needs funding
                (let ((stage (oc:our-htlc-second-stage a3 dest3 '() :height expiry)))
                  (check "A builds a zero-fee HTLC-timeout" (and stage (eq :timeout (first (first stage)))))
                  (when stage
                    (destructuring-bind (kind rec htx) (first stage)
                      (declare (ignore kind))
                      (let* ((built (lv:built-local a3))
                             (out (find (btx:txin-prev-index (first (btx:tx-inputs htx))) (lv:b-htlc-outputs built) :key #'first))
                             (their-der (second (first (btx:tx-witnesses htx))))
                             (amount (floor (lv:hr-amount-msat rec) 1000))
                             (funded (oc:fund-second-stage a3 htx their-der (third out) amount nil utxo 5000)))
                        (check "the zero-fee tx pays exactly its input" (= amount (btx:txout-value (first (btx:tx-outputs htx)))))
                        (check "funded: two inputs, two outputs" (and (= 2 (length (btx:tx-inputs funded))) (= 2 (length (btx:tx-outputs funded)))))
                        (check "input 0 (the HTLC, both signatures) spends under cl-consensus"
                               (oc-spends-p funded (btx:txout-script (nth (first out) (btx:tx-outputs a-tx))) amount
                                            :flags '(:p2sh :witness :csv :cltv)))
                        (check "input 1 (our fee UTXO) spends"
                               (handler-case (bs:verify-input funded 1 (m:p2wpkh (lt-pub fee-key)) 50000 :flags '(:p2sh :witness :csv :cltv))
                                 (error () nil)))))))
                ;; the anchor bump
                (let ((bump (oc:bump-with-anchor a3 a-tx utxo 5000)))
                  (multiple-value-bind (aidx ascript) (oc:anchor-output a3 a-tx)
                    (declare (ignore ascript))
                    (check "the bump spends A's anchor" (oc-spends-p bump (btx:txout-script (nth aidx (btx:tx-outputs a-tx))) 330))
                    (check "and the fee UTXO"
                           (handler-case (bs:verify-input bump 1 (m:p2wpkh (lt-pub fee-key)) 50000 :flags '(:p2sh :witness))
                             (error () nil)))
                    (check "paying change back to us" (equalp (btx:txout-script (first (btx:tx-outputs bump))) (m:p2wpkh (lt-pub fee-key))))
                    (check "B's anchor in A's commitment is a different output, locked to B's funding key"
                           (let ((bidx (oc:anchor-output b3 a-tx))) (and bidx (/= bidx aidx))))))))))

        (with-gate ("onchain: revocation secrets survive persistence")
          (let ((back (lv:plist->live (lv:live->plist b))))
            (check "the reloaded channel can still punish commitment 1"
                   (equalp (lv:revoked-secret-for back 1) (lv:revoked-secret-for b 1)))
            (check "and still holds their signature over our commitment"
                   (equalp (lv:live-local-commit-sig back) (lv:live-local-commit-sig b)))))))))
