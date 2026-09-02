;;;; inspect/commitment-anchors-test.lisp — BOLT #3 Appendix F, anchors.
;;;;
;;;; Same keys, same funding, same HTLCs as Appendix C — and a different
;;;; transaction at every turn: two 330-sat anchors paid for by the funder, a
;;;; to_remote behind one block of CSV, HTLC scripts that end in `1 OP_CSV
;;;; OP_DROP`, and second-stage transactions with sequence 1, zero fee, and the
;;;; peer's signature under SIGHASH_SINGLE|ANYONECANPAY.  Nine vectors; each
;;;; checks the unsigned commitment byte for byte, the peer's signature over
;;;; it, and every HTLC transaction and signature the vector carries.

(in-package #:cl-payments.test)

(defun anchors-vectors ()
  (with-open-file (s (asdf:system-relative-pathname "cl-payments" "inspect/vectors/commitment-anchors.sexp"))
    (loop for form = (read s nil) while form collect form)))

(defun %c-htlcs (name)
  "Appendix C's HTLCs 0-4, or 1, 5 and 6 for the tiebreak vector."
  (if (search "same amount and preimage" name)
      (list (m:make-htlc :direction :received :amount-msat 2000000 :expiry 501
                         :payment-hash (%preimage-hash "0101010101010101010101010101010101010101010101010101010101010101"))
            (m:make-htlc :direction :offered :amount-msat 5000000 :expiry 506
                         :payment-hash (%preimage-hash "0505050505050505050505050505050505050505050505050505050505050505"))
            (m:make-htlc :direction :offered :amount-msat 5000000 :expiry 505
                         :payment-hash (%preimage-hash "0505050505050505050505050505050505050505050505050505050505050505")))
      (list (m:make-htlc :direction :received :amount-msat 1000000 :expiry 500
                         :payment-hash (%preimage-hash "0000000000000000000000000000000000000000000000000000000000000000"))
            (m:make-htlc :direction :received :amount-msat 2000000 :expiry 501
                         :payment-hash (%preimage-hash "0101010101010101010101010101010101010101010101010101010101010101"))
            (m:make-htlc :direction :offered :amount-msat 2000000 :expiry 502
                         :payment-hash (%preimage-hash "0202020202020202020202020202020202020202020202020202020202020202"))
            (m:make-htlc :direction :offered :amount-msat 3000000 :expiry 503
                         :payment-hash (%preimage-hash "0303030303030303030303030303030303030303030303030303030303030303"))
            (m:make-htlc :direction :received :amount-msat 4000000 :expiry 504
                         :payment-hash (%preimage-hash "0404040404040404040404040404040404040404040404040404040404040404")))))

(defun %strip-witness (hex)
  "The spec publishes signed transactions; we build unsigned ones."
  (btx:serialize-tx (btx:parse-tx (cl-consensus.wire:make-reader (hx hex))) :witness nil))

(defun %der-verifies (der-hex hash pubkey expected-sighash)
  "The spec's JSON gives bare DER signatures, no sighash byte — the DER length
   prefix says whether one is present.  EXPECTED-SIGHASH is what the hash was
   computed with; when a byte is present it must agree."
  (let* ((der (hx der-hex))
         (der-len (+ 2 (aref der 1)))
         (has-type (= (length der) (1+ der-len)))
         (rs (bs:parse-der-sig (subseq der 0 der-len))))
    (and (or (not has-type) (= (aref der der-len) expected-sighash))
         (secp:ecdsa-verify (c:parse-pubkey pubkey) (c:octets hash) (car rs) (cdr rs)))))

(defun run-commitment-anchors-tests ()
  (let ((obs (m:obscuring-factor (hx *c-local-payment-basepoint*) (hx *c-remote-payment-basepoint*))))
    (with-gate ("BOLT #3 — anchor scripts (Appendix F)")
      (check "an anchor script is <pubkey> CHECKSIG IFDUP NOTIF 16 CSV ENDIF"
             (equalp (m:anchor-script (hx *c-local-funding-pubkey*))
                     (c:bytes (vector 33) (hx *c-local-funding-pubkey*) (vector #xac #x73 #x64 #x60 #xb2 #x68))))
      (check "to_remote with anchors is <key> CHECKSIGVERIFY 1 CSV"
             (equalp (m:to-remote-anchors-script (hx *c-remote-payment-basepoint*))
                     (c:bytes (vector 33) (hx *c-remote-payment-basepoint*) (vector #xad #x51 #xb2))))
      (check-equal "anchor commitment base weight" (m:commitment-fee 1000 0 :anchors t) 1124)
      (check-equal "HTLC transactions pay no fee with anchors"
                   (btx:txout-value (first (btx:tx-outputs
                                            (m:build-htlc-tx :commitment-txid (c:zeros 32) :output-index 0
                                                             :htlc-amount-msat 5000000 :direction :offered :cltv-expiry 500
                                                             :feerate-per-kw 15000 :revocation-pubkey (hx *c-revocation-pubkey*)
                                                             :to-self-delay 144 :delayed-pubkey (hx *c-delayed-pubkey*) :anchors t))))
                   5000))
    (dolist (v (anchors-vectors))
      (with-gate ((format nil "BOLT #3 anchors — ~a" (getf v :name)))
        (let ((htlcs (and (getf v :test-htlcs) (%c-htlcs (getf v :name)))))
          (multiple-value-bind (tx desc order)
              (m:build-commitment
               :funding-txid (cl-consensus.wire:hex->hash *c-funding-txid*)
               :funding-output-index 0 :funding-amount-sat 10000000
               :commitment-number 42 :obscuring obs
               :to-local-msat (getf v :local) :to-remote-msat (getf v :remote)
               :local-feerate-per-kw (getf v :feerate) :dust-limit-sat (getf v :dust)
               :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
               :delayed-pubkey (hx *c-delayed-pubkey*)
               :remote-pubkey (hx *c-remote-payment-basepoint*) :opener :local
               :htlcs htlcs
               :local-htlc-pubkey (hx *c-local-htlc-pubkey*) :remote-htlc-pubkey (hx *c-remote-htlc-pubkey*)
               :anchors t
               :local-funding-pubkey (hx *c-local-funding-pubkey*)
               :remote-funding-pubkey (hx *c-remote-funding-pubkey*))
            (declare (ignorable desc))
            (check-bytes "the commitment transaction, byte for byte"
                         (btx:serialize-tx tx :witness nil) (%strip-witness (getf v :commitment)))
            (check "the peer's signature over it verifies (SIGHASH_ALL)"
                   (%der-verifies (getf v :remote-sig)
                                  (m:commitment-sighash tx (hx *c-local-funding-pubkey*) (hx *c-remote-funding-pubkey*) 10000000)
                                  (hx *c-remote-funding-pubkey*) #x01))
            (check-equal "as many HTLC transactions as the vector carries"
                         (length order) (length (getf v :htlcs)))
            ;; Each HTLC transaction: the vector lists them in output order.
            (let ((outputs (btx:tx-outputs tx)) (start 0))
              (loop for mh in order for hd in (getf v :htlcs) for i from 0
                    do (let* ((script (ecase (m:htlc-direction mh)
                                        (:offered (m:offered-htlc-script (hx *c-revocation-pubkey*) (hx *c-remote-htlc-pubkey*)
                                                                         (hx *c-local-htlc-pubkey*) (m:htlc-payment-hash mh) :anchors t))
                                        (:received (m:received-htlc-script (hx *c-revocation-pubkey*) (hx *c-remote-htlc-pubkey*)
                                                                           (hx *c-local-htlc-pubkey*) (m:htlc-payment-hash mh)
                                                                           (m:htlc-expiry mh) :anchors t))))
                              (idx (position (m:p2wsh script) outputs :start start :key #'btx:txout-script :test #'equalp)))
                         (setf start (1+ idx))
                         (let ((htx (m:build-htlc-tx :commitment-txid (btx:tx-txid tx) :output-index idx
                                                     :htlc-amount-msat (m:htlc-amount-msat mh) :direction (m:htlc-direction mh)
                                                     :cltv-expiry (m:htlc-expiry mh) :feerate-per-kw (getf v :feerate)
                                                     :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
                                                     :delayed-pubkey (hx *c-delayed-pubkey*) :anchors t)))
                           (check-bytes (format nil "HTLC tx ~d (output ~d), byte for byte" i idx)
                                        (btx:serialize-tx htx :witness nil) (%strip-witness (getf hd :resolution)))
                           (check (format nil "HTLC tx ~d: the peer's signature is SINGLE|ANYONECANPAY and verifies" i)
                                  (%der-verifies (getf hd :remote-sig)
                                                 (m:htlc-tx-sighash htx script (floor (m:htlc-amount-msat mh) 1000)
                                                                    :sighash m:+sighash-single-anyonecanpay+)
                                                 (hx *c-remote-htlc-pubkey*) #x83))))))))))))
