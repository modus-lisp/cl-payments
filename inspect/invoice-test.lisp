;;;; inspect/invoice-test.lisp
;;;;
;;;; Phase 7 — BOLT #11 against the spec's own examples.
;;;;
;;;; Every example in the spec is signed by one published private key, with
;;;; RFC 6979 deterministic nonces.  That gives an unusually strong test: not
;;;; just "does it decode", but "if we re-sign the decoded fields with that key,
;;;; do we get back the identical string?"  Any drift in field encoding, group
;;;; padding, hrp formatting or the signing hash shows up as a different
;;;; signature — and a signature is the one thing you cannot be approximately
;;;; right about.

(in-package #:cl-payments.test)

(defun bolt11-vectors ()
  (with-open-file (s (asdf:system-relative-pathname "cl-payments" "inspect/vectors/bolt11.txt"))
    (loop for line = (read-line s nil) while line
          collect (let* ((a (position #\Tab line)) (b (position #\Tab line :start (1+ a))))
                    (list (subseq line 0 a) (subseq line (1+ a) b) (subseq line (1+ b)))))))

(defparameter *bolt11-priv* (secp:bytes-to-int (hx "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734")))
(defparameter *bolt11-payee* (hx "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"))

(defun run-invoice-tests ()
  (let ((valid (remove-if-not (lambda (v) (string= (first v) "valid")) (bolt11-vectors)))
        (invalid (remove-if-not (lambda (v) (string= (first v) "invalid")) (bolt11-vectors))))

    (with-gate ("invoice: every valid spec example decodes, verifies, and recovers the payee")
      (check-equal "fifteen valid examples" (length valid) 15)
      (dolist (v valid)
        (let* ((str (third v))
               (inv (check-no-signal (format nil "decodes: ~a" (subseq (second v) 0 (min 50 (length (second v))))) (inv:decode-invoice str))))
          (when inv
            (check "  payment hash present and 32 bytes" (= 32 (length (inv:inv-payment-hash inv))))
            (cond
              ;; The high-S example is the donation invoice with s replaced by
              ;; n - s under the SAME recovery id.  That is still a valid
              ;; signature, and recovery still succeeds — but it recovers a
              ;; different point, and no low-S signer can reproduce it.  The
              ;; spec lists it to show decoding must not choke on high S, not
              ;; to name a payee.
              ((search "high-S" (second v))
               (check "  high-S: a payee is still recovered" (= 33 (length (inv:inv-payee inv))))
               (check "  high-S: and it is NOT the low-S signer's key"
                      (not (equalp (inv:inv-payee inv) *bolt11-payee*))))
              (t
               (check "  payee recovered from the signature is the spec's key"
                      (equalp (inv:inv-payee inv) *bolt11-payee*))
               ;; The strong check: re-sign the decoded fields with the spec's
               ;; key and require the identical string back.
               (check "  re-signing reproduces the exact invoice"
                      (string= (string-downcase str)
                               (inv:encode-invoice (inv:sign-invoice (copy-structure inv) *bolt11-priv*))))))))))

    (with-gate ("invoice: the spec's field breakdowns")
      (let ((donation (inv:decode-invoice (third (first valid))))
            (coffee (inv:decode-invoice (third (second valid)))))
        (check "donation: any amount" (null (inv:inv-amount-msat donation)))
        (check "donation: mainnet" (eq :mainnet (inv:inv-network donation)))
        (check-equal "donation: timestamp" (inv:inv-timestamp donation) 1496314658)
        (check "donation: payment hash"
               (equalp (inv:inv-payment-hash donation)
                       (hx "0001020304050607080900010203040506070809000102030405060708090102")))
        (check "donation: payment secret"
               (equalp (inv:inv-payment-secret donation)
                       (hx "1111111111111111111111111111111111111111111111111111111111111111")))
        (check-equal "donation: description" (inv:inv-description donation) "Please consider supporting this project")
        (check-equal "donation: default expiry" (inv:inv-expiry donation) 3600)
        (check-equal "donation: default min_final_cltv" (inv:inv-min-final-cltv-expiry-delta donation) 18)
        ;; features b100000100000000 = bits 8 and 14
        (check "donation: features bits 8 and 14" (= (inv:inv-features donation) (logior (ash 1 8) (ash 1 14))))
        ;; 2500u = 2500 * 10^5 msat = 250_000_000 msat
        (check-equal "coffee: 2500u is 250,000,000 msat" (inv:inv-amount-msat coffee) 250000000)
        (check-equal "coffee: description" (inv:inv-description coffee) "1 cup coffee")
        (check-equal "coffee: expiry 60s" (inv:inv-expiry coffee) 60)
        (check "coffee: is expired by now" (inv:inv-expired-p coffee)))
      ;; testnet, description hash
      (let ((tb (inv:decode-invoice (third (fifth valid)))))
        (check "lntb decodes as testnet" (eq :testnet (inv:inv-network tb)))
        (check-equal "20m is 2,000,000,000 msat" (inv:inv-amount-msat tb) 2000000000)
        (check "description hash present, no description"
               (and (inv:inv-description-hash tb) (null (inv:inv-description tb))))
        (check "a fallback address is carried" (= 1 (length (inv:inv-fallbacks tb)))))
      ;; route hints: example with two `r` hops
      (let ((hinted (find-if (lambda (v) (search "route hint" (second v))) valid)))
        (when hinted
          (let* ((inv (inv:decode-invoice (third hinted)))
                 (hints (inv:inv-route-hints inv)))
            (check "route hints parse" (and hints (= 2 (length (first hints)))))
            (check "hint node ids are 33 bytes" (every (lambda (h) (= 33 (length (inv:rh-node-id h)))) (first hints))))))
      ;; the `n` field example: payee is READ, and the signature checked against it
      (let ((n-ex (find-if (lambda (v) (search "payee" (second v))) valid)))
        (when n-ex
          (check "n field: payee is the spec's key"
                 (equalp (inv:inv-payee (inv:decode-invoice (third n-ex))) *bolt11-payee*)))))

    (with-gate ("invoice: the spec's invalid examples are refused")
      (dolist (v invalid)
        ;; The "unknown feature 100" case is a POLICY refusal (unknown required
        ;; feature), not a parse failure — it decodes but should not be paid.
        (unless (search "feature" (second v))
          (check-signals (format nil "refused: ~a" (subseq (second v) 0 (min 50 (length (second v)))))
                         inv:invoice-error (inv:decode-invoice (third v))))))

    (with-gate ("invoice: amounts")
      (check-equal "12 BTC" (inv::parse-amount "12") (* 12 (expt 10 11)))
      (check-equal "25m" (inv::parse-amount "25m") 2500000000)
      (check-equal "2500u" (inv::parse-amount "2500u") 250000000)
      (check-equal "1n is 100 msat" (inv::parse-amount "1n") 100)
      (check-equal "10p is 1 msat" (inv::parse-amount "10p") 1)
      (check-signals "1p is sub-millisatoshi" inv:invoice-error (inv::parse-amount "1p"))
      (check-signals "leading zero" inv:invoice-error (inv::parse-amount "025m"))
      (check-signals "bad multiplier" inv:invoice-error (inv::parse-amount "25x"))
      ;; format is the shortest exact form, and round-trips
      (dolist (msat '(1 100 1000 250000000 2500000000 100000000000 123))
        (check (format nil "~d msat round-trips through the hrp" msat)
               (= msat (inv::parse-amount (inv::format-amount msat))))))

    ;; Many keys, not one: the recovery id is right for about half of all
    ;; signatures if taken naively from the signer, and a single fixed key
    ;; passes or fails by luck.  Sixteen keys make luck unlikely enough.
    (with-gate ("invoice: signatures recover to the signer for many keys")
      (loop for i from 1 to 16
            do (let* ((k (secp:bytes-to-int (c:sha256 (c:ascii->bytes (format nil "invoice-test/many/~d" i)))))
                      (inv (inv:sign-invoice
                            (inv::make-invoice-for :network :signet :amount-msat (* i 1000)
                                                   :payment-hash (c:sha256 (c:ascii->bytes (format nil "h~d" i)))
                                                   :payment-secret (c:sha256 (c:ascii->bytes (format nil "s~d" i)))
                                                   :description "k" :timestamp (+ 1756000000 i))
                            k))
                      (back (inv:decode-invoice (inv:encode-invoice inv))))
                 (check (format nil "key ~d recovers to its signer" i)
                        (equalp (inv:inv-payee back) (c:compressed-pubkey (c:pubkey-of k)))))))

    (with-gate ("invoice: we produce invoices we can decode, signed by our key")
      (let* ((k (secp:bytes-to-int (c:sha256 (c:ascii->bytes "invoice-test/key"))))
             (pre (c:sha256 (c:ascii->bytes "invoice-test/preimage")))
             (inv (inv:sign-invoice
                   (inv::make-invoice-for :network :signet :amount-msat 50000000
                                          :payment-hash (c:sha256 pre)
                                          :payment-secret (c:sha256 (c:ascii->bytes "invoice-test/secret"))
                                          :description "cl-payments test" :timestamp 1756000000
                                          :expiry 600 :min-final-cltv 40
                                          :features (f:features-from '((:payment-secret . :required) (:var-onion-optin . :required))))
                   k))
             (str (inv:encode-invoice inv))
             (back (inv:decode-invoice str)))
        (check "starts with lntbs (signet)" (string= "lntbs" str :end2 5))
        (check "amount 500u in the hrp" (string= "lntbs500u1" str :end2 10))
        (check "payee recovered is our key" (equalp (inv:inv-payee back) (c:compressed-pubkey (c:pubkey-of k))))
        (check "hash round-trips" (equalp (inv:inv-payment-hash back) (c:sha256 pre)))
        (check-equal "description round-trips" (inv:inv-description back) "cl-payments test")
        (check-equal "expiry round-trips" (inv:inv-expiry back) 600)
        (check-equal "min_final_cltv round-trips" (inv:inv-min-final-cltv-expiry-delta back) 40)
        ;; A recovery id outside 0..3 must be refused outright, not masked
        ;; down to one of them — the same signature bytes with a different id
        ;; would otherwise decode to a different, valid-looking payee.
        (let ((bad-id (copy-structure inv)))
          (setf (inv:inv-recovery-id bad-id) 5)
          (check-signals "recovery id 5 is refused" inv:invoice-error
                         (inv:decode-invoice (inv:encode-invoice bad-id))))
        ;; Tamper with one data character: the checksum or the signature must catch it.
        (let ((bad (copy-seq str)))
          (setf (char bad 30) (if (char= (char bad 30) #\q) #\p #\q))
          (check-signals "one changed character is refused" inv:invoice-error (inv:decode-invoice bad)))))))
