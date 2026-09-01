;;;; inspect/commitment-test.lisp
;;;;
;;;; Gate 8 — BOLT #3 commitment transactions, against Appendix C.
;;;;
;;;; The headline check is a byte-for-byte comparison with the spec's own
;;;; "simple commitment tx with no HTLCs" vector.  That single equality covers a
;;;; startling amount: script construction, key sorting, the obscured commitment
;;;; number in both the locktime and the sequence, the fee, the dust rule, and
;;;; BIP69 output ordering.  Any one of them wrong and the bytes differ.
;;;;
;;;; But a single vector says nothing about WHY each piece is the way it is, so
;;;; the rest of this gate pins the individual rules — the ones where a mistake
;;;; produces a transaction that is perfectly well-formed and that the
;;;; counterparty silently refuses to sign.

(in-package #:cl-payments.test)

;;; BOLT #3, Appendix C — common parameters.
(defparameter *c-funding-txid* "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be")
(defparameter *c-local-funding-pubkey*
  "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb")
(defparameter *c-remote-funding-pubkey*
  "030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1")
(defparameter *c-local-payment-basepoint*
  "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa")
(defparameter *c-remote-payment-basepoint*
  "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991")
(defparameter *c-revocation-pubkey*
  "0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19")
(defparameter *c-delayed-pubkey*
  "03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c")

(defun test-commitment-scripts ()
  (with-gate ("BOLT #3 — output scripts (Appendix C)")
    (check-bytes "funding 2-of-2 witness script"
                 (m:funding-script (hx *c-local-funding-pubkey*) (hx *c-remote-funding-pubkey*))
                 (hx "5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae"))
    ;; The keys are sorted lexicographically, NOT by who is local.  If each side
    ;; used its own key first they would derive different funding addresses and
    ;; the channel would be funded to an output neither could spend.
    (check-bytes "funding script is independent of argument order"
                 (m:funding-script (hx *c-remote-funding-pubkey*) (hx *c-local-funding-pubkey*))
                 (m:funding-script (hx *c-local-funding-pubkey*) (hx *c-remote-funding-pubkey*)))
    (check-bytes "to_local witness script"
                 (m:to-local-script (hx *c-revocation-pubkey*) 144 (hx *c-delayed-pubkey*))
                 (hx "63210212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b1967029000b2752103fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c68ac"))
    ;; to_self_delay is a CScriptNum: 144 needs two bytes, and a delay in the
    ;; OP_1..OP_16 range encodes as a single opcode instead.
    (check "a small to_self_delay encodes as one opcode"
           (< (length (m:to-local-script (hx *c-revocation-pubkey*) 6 (hx *c-delayed-pubkey*)))
              (length (m:to-local-script (hx *c-revocation-pubkey*) 144 (hx *c-delayed-pubkey*)))))
    (check "the delay actually appears in the script"
           (not (equalp (m:to-local-script (hx *c-revocation-pubkey*) 144 (hx *c-delayed-pubkey*))
                        (m:to-local-script (hx *c-revocation-pubkey*) 145 (hx *c-delayed-pubkey*)))))
    ;; to_remote is plain P2WPKH — the counterparty did not publish this
    ;; commitment, so there is nothing to delay and nothing to punish.
    (check-bytes "to_remote is P2WPKH of the remote key"
                 (m:to-remote-scriptpubkey (hx *c-remote-payment-basepoint*))
                 (hx "0014cc1b07838e387deacd0e5232e1e8b49f4c29e484"))
    (check-bytes "p2wsh wraps a script as OP_0 <sha256>"
                 (m:p2wsh (hx "51")) (c:bytes (hx "0020") (c:sha256 (hx "51"))))
    (check-bytes "p2wpkh wraps a key as OP_0 <hash160>"
                 (m:p2wpkh (hx *c-remote-payment-basepoint*))
                 (hx "0014cc1b07838e387deacd0e5232e1e8b49f4c29e484"))
    (check-bytes "script-push uses a minimal length prefix"
                 (m:script-push (hx "0102")) (hx "020102"))))

(defun test-obscured-commitment-number ()
  (with-gate ("BOLT #3 — the obscured commitment number")
    (let ((obs (m:obscuring-factor (hx *c-local-payment-basepoint*)
                                   (hx *c-remote-payment-basepoint*))))
      (check-equal "obscuring factor" obs #x2bb038521914)
      ;; Order is by ROLE — opener first — not local/remote.  Each side is local
      ;; to itself, so using your own basepoint first gives two different factors
      ;; and a commitment number neither party can read.
      (check "the factor depends on the argument order"
             (/= obs (m:obscuring-factor (hx *c-remote-payment-basepoint*)
                                         (hx *c-local-payment-basepoint*))))
      (check-equal "it fits in 48 bits" (integer-length obs) (integer-length #x2bb038521914))
      (let ((n (m:obscured-commitment-number 42 obs)))
        (check-equal "commitment 42 obscured" n (logxor 42 #x2bb038521914))
        ;; Split across the two fields the spec hides it in.
        (check-equal "locktime carries the low 24 bits" (m:commitment-locktime n) #x2052193e)
        (check-equal "sequence carries the high 24 bits" (m:commitment-sequence n) #x802bb038)
        ;; The disguise must be reversible by the two parties and by nobody else.
        (check-equal "the number is recoverable from the two fields"
                     (logxor obs (logior (ash (logand (m:commitment-sequence n) #xffffff) 24)
                                         (logand (m:commitment-locktime n) #xffffff)))
                     42)))))

(defun test-commitment-fees ()
  (with-gate ("BOLT #3 — fees and dust")
    (check-equal "base weight is 724" m:+commit-weight-base+ 724)
    (check-equal "fee at 15000/kw with no HTLCs" (m:commitment-fee 15000 0) 10860)
    (check-equal "fee at zero feerate" (m:commitment-fee 0 0) 0)
    ;; per_kw is per 1000 WEIGHT units, not per 1000 bytes, and truncates.
    (check-equal "each untrimmed HTLC adds weight"
                 (- (m:commitment-fee 1000 1) (m:commitment-fee 1000 0))
                 (floor m:+htlc-output-weight+ 1))
    (check "the fee truncates rather than rounds"
           (= (m:commitment-fee 1 0) 0))
    (check "an output below the dust limit is dust" (m:dust-p 545 546))
    (check "an output at the dust limit is not" (not (m:dust-p 546 546)))))

(defun test-commitment-vector ()
  "The Appendix C vector, byte for byte."
  (with-gate ("BOLT #3 — simple commitment tx with no HTLCs (Appendix C)")
    (let ((obs (m:obscuring-factor (hx *c-local-payment-basepoint*)
                                   (hx *c-remote-payment-basepoint*))))
      (multiple-value-bind (tx described)
          (m:build-commitment
           :funding-txid (cl-consensus.wire:hex->hash *c-funding-txid*)
           :funding-output-index 0 :funding-amount-sat 10000000
           :commitment-number 42 :obscuring obs
           :to-local-msat 7000000000 :to-remote-msat 3000000000
           :local-feerate-per-kw 15000 :dust-limit-sat 546
           :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
           :delayed-pubkey (hx *c-delayed-pubkey*)
           :remote-pubkey (hx *c-remote-payment-basepoint*) :opener :local)
        (check-bytes "the unsigned commitment transaction"
                     (cl-consensus.tx:serialize-tx tx)
                     (hx "0200000001bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014cc1b07838e387deacd0e5232e1e8b49f4c29e48454a56a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e3e195220"))
        ;; The opener pays the WHOLE fee out of its own balance.  Splitting it,
        ;; or taking it from the wrong side, yields a transaction the peer simply
        ;; declines to sign.
        (check-equal "to_local is the balance minus the fee"
                     (second (assoc :to-local described)) (- 7000000 10860))
        (check-equal "to_remote is untouched by the fee"
                     (second (assoc :to-remote described)) 3000000)
        (check-equal "two outputs" (length (cl-consensus.tx:tx-outputs tx)) 2)
        (check-equal "version 2" (cl-consensus.tx:tx-version tx) 2)))))

(defun test-commitment-structure ()
  (with-gate ("BOLT #3 — ordering, dust, and who pays")
    (let ((obs (m:obscuring-factor (hx *c-local-payment-basepoint*)
                                   (hx *c-remote-payment-basepoint*)))
          (common (list :funding-txid (cl-consensus.wire:hex->hash *c-funding-txid*)
                        :funding-output-index 0 :funding-amount-sat 10000000
                        :commitment-number 42
                        :local-feerate-per-kw 15000 :dust-limit-sat 546
                        :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
                        :delayed-pubkey (hx *c-delayed-pubkey*)
                        :remote-pubkey (hx *c-remote-payment-basepoint*))))
      ;; BIP69: ascending by amount.  A canonical order is what lets both sides
      ;; build byte-identical transactions independently.
      (let ((tx (apply #'m:build-commitment :obscuring obs
                       :to-local-msat 7000000000 :to-remote-msat 3000000000
                       :opener :local common)))
        (let ((values (mapcar #'cl-consensus.tx:txout-value
                              (cl-consensus.tx:tx-outputs tx))))
          (check "outputs are sorted ascending by value" (apply #'<= values))))
      ;; A balance below the dust limit produces NO output; its value goes to
      ;; fees.  Both sides must drop exactly the same outputs or their
      ;; transactions differ and no signature validates.
      (let ((tx (apply #'m:build-commitment :obscuring obs
                       :to-local-msat 7000000000 :to-remote-msat 400000    ; 400 sat
                       :opener :local common)))
        (check-equal "a dust to_remote is omitted entirely"
                     (length (cl-consensus.tx:tx-outputs tx)) 1))
      ;; Whoever opened pays, for the life of the channel.
      (let ((remote-opened (nth-value 1 (apply #'m:build-commitment :obscuring obs
                                               :to-local-msat 7000000000
                                               :to-remote-msat 3000000000
                                               :opener :remote common))))
        (check-equal "with a remote opener, to_local keeps its full balance"
                     (second (assoc :to-local remote-opened)) 7000000)
        (check-equal "…and to_remote pays the fee"
                     (second (assoc :to-remote remote-opened)) (- 3000000 10860)))
      ;; A fee larger than the opener's balance is not a transaction to sign, it
      ;; is a bug to report.
      (check-signals "a fee exceeding the opener's balance is refused" m:commitment-error
        (apply #'m:build-commitment :obscuring obs
               :to-local-msat 1000 :to-remote-msat 3000000000 :opener :local common)))))

(defparameter *c-local-htlc-pubkey*
  "030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7")
(defparameter *c-remote-htlc-pubkey*
  "0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b")
(defparameter *c-local-funding-privkey*
  "30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749")

(defun %preimage-hash (hex) (c:sha256 (hx hex)))

(defun test-htlc-scripts ()
  (with-gate ("BOLT #3 — HTLC output scripts (Appendix C)")
    ;; Both scripts share a three-way shape: the counterparty sweeps immediately
    ;; with the revocation key if this commitment was revoked; otherwise one side
    ;; takes it with the preimage and the other after a timeout.  Which side gets
    ;; which branch is the whole difference between offered and received.
    (check-bytes "offered HTLC (#2)"
                 (m:offered-htlc-script (hx *c-revocation-pubkey*) (hx *c-remote-htlc-pubkey*)
                                        (hx *c-local-htlc-pubkey*)
                                        (%preimage-hash "0202020202020202020202020202020202020202020202020202020202020202"))
                 (hx "76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6868"))
    (check-bytes "received HTLC (#0, expiry 500)"
                 (m:received-htlc-script (hx *c-revocation-pubkey*) (hx *c-remote-htlc-pubkey*)
                                         (hx *c-local-htlc-pubkey*)
                                         (%preimage-hash "0000000000000000000000000000000000000000000000000000000000000000")
                                         500)
                 (hx "76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac6868"))
    ;; The expiry is IN the received script, so two HTLCs differing only in
    ;; expiry get different outputs — offered ones do not, which is exactly why
    ;; the ordering needs a CLTV tiebreak.
    (check "a received script depends on its expiry"
           (not (equalp (m:received-htlc-script (hx *c-revocation-pubkey*) (hx *c-remote-htlc-pubkey*)
                                                (hx *c-local-htlc-pubkey*) (%preimage-hash "00") 500)
                        (m:received-htlc-script (hx *c-revocation-pubkey*) (hx *c-remote-htlc-pubkey*)
                                                (hx *c-local-htlc-pubkey*) (%preimage-hash "00") 501))))
    (check "an offered script does NOT depend on any expiry"
           (equalp (m:offered-htlc-script (hx *c-revocation-pubkey*) (hx *c-remote-htlc-pubkey*)
                                          (hx *c-local-htlc-pubkey*) (%preimage-hash "00"))
                   (m:offered-htlc-script (hx *c-revocation-pubkey*) (hx *c-remote-htlc-pubkey*)
                                          (hx *c-local-htlc-pubkey*) (%preimage-hash "00"))))
    (check "offered and received scripts differ"
           (not (equalp (m:offered-htlc-script (hx *c-revocation-pubkey*) (hx *c-remote-htlc-pubkey*)
                                               (hx *c-local-htlc-pubkey*) (%preimage-hash "00"))
                        (m:received-htlc-script (hx *c-revocation-pubkey*) (hx *c-remote-htlc-pubkey*)
                                                (hx *c-local-htlc-pubkey*) (%preimage-hash "00") 500))))))

(defun test-htlc-trimming ()
  (with-gate ("BOLT #3 — HTLC trimming")
    ;; The test is NOT the amount against the dust limit.  It is the amount MINUS
    ;; the fee of the second-stage transaction that would claim it: an HTLC worth
    ;; a little over dust is still worthless if redeeming it costs more.
    (check-equal "timeout weight" m:+htlc-timeout-weight+ 663)
    (check-equal "success weight" m:+htlc-success-weight+ 703)
    (check "at zero feerate nothing is trimmed by the second stage"
           (not (m:htlc-trimmed-p 1000000 :offered 0 546)))
    ;; At 15000/kw an offered HTLC must clear 546 + 9945 sat.
    (let ((offered-fee (floor (* 15000 663) 1000))
          (success-fee (floor (* 15000 703) 1000)))
      (check "an HTLC just under the threshold is trimmed"
             (m:htlc-trimmed-p (* 1000 (+ 546 offered-fee -1)) :offered 15000 546))
      (check "an HTLC just over it is not"
             (not (m:htlc-trimmed-p (* 1000 (+ 546 offered-fee)) :offered 15000 546)))
      ;; Offered and received use DIFFERENT weights, so the same amount can be
      ;; trimmed one way and not the other.
      (check "the two directions have different thresholds" (/= offered-fee success-fee))
      (let ((between (* 1000 (+ 546 offered-fee))))
        (check "an amount between the thresholds trims as received but not offered"
               (and (not (m:htlc-trimmed-p between :offered 15000 546))
                    (m:htlc-trimmed-p between :received 15000 546)))))))

(defun test-five-htlc-commitment ()
  (with-gate ("BOLT #3 — commitment with five HTLCs (Appendix C)")
    (let* ((expected
             (with-open-file (f (asdf:system-relative-pathname
                                 "cl-payments" "inspect/vectors/commitment-five-htlcs.txt")
                                :if-does-not-exist nil)
               (when f (loop for line = (read-line f nil)
                             while line
                             unless (or (zerop (length line)) (char= (char line 0) #\#))
                               return (string-trim '(#\Space #\Return) line)))))
           (obs (m:obscuring-factor (hx *c-local-payment-basepoint*)
                                    (hx *c-remote-payment-basepoint*)))
           (htlcs (list (m:make-htlc :direction :received :amount-msat 1000000 :expiry 500
                                     :payment-hash (%preimage-hash "0000000000000000000000000000000000000000000000000000000000000000"))
                        (m:make-htlc :direction :received :amount-msat 2000000 :expiry 501
                                     :payment-hash (%preimage-hash "0101010101010101010101010101010101010101010101010101010101010101"))
                        (m:make-htlc :direction :offered  :amount-msat 2000000 :expiry 502
                                     :payment-hash (%preimage-hash "0202020202020202020202020202020202020202020202020202020202020202"))
                        (m:make-htlc :direction :offered  :amount-msat 3000000 :expiry 503
                                     :payment-hash (%preimage-hash "0303030303030303030303030303030303030303030303030303030303030303"))
                        (m:make-htlc :direction :received :amount-msat 4000000 :expiry 504
                                     :payment-hash (%preimage-hash "0404040404040404040404040404040404040404040404040404040404040404")))))
      (unless (check "the five-HTLC vector is present" expected)
        (return-from test-five-htlc-commitment))
      (let ((tx (m:build-commitment
                 :funding-txid (cl-consensus.wire:hex->hash *c-funding-txid*)
                 :funding-output-index 0 :funding-amount-sat 10000000
                 :commitment-number 42 :obscuring obs
                 :to-local-msat 6988000000 :to-remote-msat 3000000000
                 :local-feerate-per-kw 0 :dust-limit-sat 546
                 :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
                 :delayed-pubkey (hx *c-delayed-pubkey*)
                 :remote-pubkey (hx *c-remote-payment-basepoint*) :opener :local
                 :htlcs htlcs
                 :local-htlc-pubkey (hx *c-local-htlc-pubkey*)
                 :remote-htlc-pubkey (hx *c-remote-htlc-pubkey*))))
        (check-bytes "the unsigned five-HTLC commitment"
                     (cl-consensus.tx:serialize-tx tx) (hx expected))
        (check-equal "seven outputs: two balances and five HTLCs"
                     (length (cl-consensus.tx:tx-outputs tx)) 7)
        ;; At feerate 0 nothing is trimmed; at a high feerate the small ones go.
        (let ((trimmed (m:build-commitment
                        :funding-txid (cl-consensus.wire:hex->hash *c-funding-txid*)
                        :funding-output-index 0 :funding-amount-sat 10000000
                        :commitment-number 42 :obscuring obs
                        :to-local-msat 6988000000 :to-remote-msat 3000000000
                        :local-feerate-per-kw 15000 :dust-limit-sat 546
                        :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
                        :delayed-pubkey (hx *c-delayed-pubkey*)
                        :remote-pubkey (hx *c-remote-payment-basepoint*) :opener :local
                        :htlcs htlcs
                        :local-htlc-pubkey (hx *c-local-htlc-pubkey*)
                        :remote-htlc-pubkey (hx *c-remote-htlc-pubkey*))))
          (check "a high feerate trims the small HTLCs away"
                 (< (length (cl-consensus.tx:tx-outputs trimmed)) 7)))))))

(defun test-cltv-tiebreak ()
  "Two offered HTLCs with the same ROUNDED amount and the same payment hash
   produce byte-identical outputs.  The spec calls this case out explicitly: the
   only thing that orders them is `cltv_expiry`, and the peers must agree,
   because `commitment_signed` sends one signature per HTLC in output order.
   Order them differently and each side attaches the other's signatures to the
   wrong HTLC — both then fail to verify, for no visible reason."
  (with-gate ("BOLT #3 — the CLTV tiebreak for identical HTLC outputs")
    (let* ((obs (m:obscuring-factor (hx *c-local-payment-basepoint*)
                                    (hx *c-remote-payment-basepoint*)))
           ;; Appendix C's HTLCs 5 and 6: same preimage, and 5000000 / 5000001
           ;; msat both round DOWN to 5000 sat.  Different expiries.
           (hash5 (%preimage-hash "0505050505050505050505050505050505050505050505050505050505050505"))
           (later   (m:make-htlc :direction :offered :amount-msat 5000000 :expiry 506
                                 :payment-hash hash5))
           (earlier (m:make-htlc :direction :offered :amount-msat 5000001 :expiry 505
                                 :payment-hash hash5)))
      (flet ((order-for (htlcs)
               (nth-value 2 (m:build-commitment
                             :funding-txid (cl-consensus.wire:hex->hash *c-funding-txid*)
                             :funding-output-index 0 :funding-amount-sat 10000000
                             :commitment-number 42 :obscuring obs
                             :to-local-msat 6988000000 :to-remote-msat 3000000000
                             :local-feerate-per-kw 0 :dust-limit-sat 546
                             :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
                             :delayed-pubkey (hx *c-delayed-pubkey*)
                             :remote-pubkey (hx *c-remote-payment-basepoint*) :opener :local
                             :htlcs htlcs
                             :local-htlc-pubkey (hx *c-local-htlc-pubkey*)
                             :remote-htlc-pubkey (hx *c-remote-htlc-pubkey*)))))
        (let ((tx (m:build-commitment
                   :funding-txid (cl-consensus.wire:hex->hash *c-funding-txid*)
                   :funding-output-index 0 :funding-amount-sat 10000000
                   :commitment-number 42 :obscuring obs
                   :to-local-msat 6988000000 :to-remote-msat 3000000000
                   :local-feerate-per-kw 0 :dust-limit-sat 546
                   :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
                   :delayed-pubkey (hx *c-delayed-pubkey*)
                   :remote-pubkey (hx *c-remote-payment-basepoint*) :opener :local
                   :htlcs (list later earlier)
                   :local-htlc-pubkey (hx *c-local-htlc-pubkey*)
                   :remote-htlc-pubkey (hx *c-remote-htlc-pubkey*))))
          (let ((htlc-outs (remove 5000 (cl-consensus.tx:tx-outputs tx)
                                   :key #'cl-consensus.tx:txout-value :test #'/=)))
            (check-equal "both HTLCs are present" (length htlc-outs) 2)
            ;; The premise: they really are indistinguishable in the transaction,
            ;; so the ORDER is the only thing carrying the distinction.
            (check "the two HTLC outputs are byte-identical"
                   (equalp (cl-consensus.tx:txout-script (first htlc-outs))
                           (cl-consensus.tx:txout-script (second htlc-outs))))))
        ;; The property that matters: BOTH peers must arrive at the same order,
        ;; and they assemble their HTLC lists independently.  So the output order
        ;; must not depend on the input order — testing only one permutation
        ;; passes even with no tiebreak at all, because the list happens to
        ;; arrive already sorted.
        (check-equal "input order (later, earlier) sorts by expiry"
                     (mapcar #'m:htlc-expiry (order-for (list later earlier))) '(505 506))
        (check-equal "input order (earlier, later) sorts the same way"
                     (mapcar #'m:htlc-expiry (order-for (list earlier later))) '(505 506))
        (check "the two permutations agree"
               (equal (mapcar #'m:htlc-expiry (order-for (list later earlier)))
                      (mapcar #'m:htlc-expiry (order-for (list earlier later)))))))))

(defun test-commitment-signing ()
  (with-gate ("BOLT #3 — signing the commitment (Appendix C)")
    (let* ((obs (m:obscuring-factor (hx *c-local-payment-basepoint*)
                                    (hx *c-remote-payment-basepoint*)))
           (tx (m:build-commitment
                :funding-txid (cl-consensus.wire:hex->hash *c-funding-txid*)
                :funding-output-index 0 :funding-amount-sat 10000000
                :commitment-number 42 :obscuring obs
                :to-local-msat 7000000000 :to-remote-msat 3000000000
                :local-feerate-per-kw 15000 :dust-limit-sat 546
                :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
                :delayed-pubkey (hx *c-delayed-pubkey*)
                :remote-pubkey (hx *c-remote-payment-basepoint*) :opener :local))
           (sig (m:sign-commitment tx
                                   (secp256k1-fast:bytes-to-int (hx *c-local-funding-privkey*))
                                   (hx *c-local-funding-pubkey*) (hx *c-remote-funding-pubkey*)
                                   10000000)))
      ;; Reproducing the spec's signature exercises BIP143 (with the funding
      ;; amount in the digest) AND RFC6979 deterministic nonce generation at
      ;; once — a wrong digest or a wrong nonce gives a different, still-valid
      ;; signature, so only an exact match proves both.
      (check-bytes "local_signature matches the spec"
                   sig
                   (hx "616210b2cc4d3afb601013c373bbd8aac54febd9f15400379a8cb65ce7deca6034236c010991beb7ff770510561ae8dc885b8d38d1947248c38f2ae055647142"))
      (check-equal "signatures are 64 bytes on the wire, never DER" (length sig) 64)
      ;; And it must verify under the signing key.
      (let ((hash (m:commitment-sighash tx (hx *c-local-funding-pubkey*)
                                        (hx *c-remote-funding-pubkey*) 10000000)))
        (check "the signature verifies against the funding pubkey"
               (secp256k1-fast:ecdsa-verify
                (c:parse-pubkey (hx *c-local-funding-pubkey*))
                (c:octets hash)
                (secp256k1-fast:bytes-to-int (subseq sig 0 32))
                (secp256k1-fast:bytes-to-int (subseq sig 32 64))))
        ;; The funding AMOUNT is part of the BIP143 digest — that is the whole
        ;; reason BIP143 exists, and signing the wrong amount must be detectable.
        (check "a different funding amount gives a different digest"
               (not (equalp hash (m:commitment-sighash tx (hx *c-local-funding-pubkey*)
                                                       (hx *c-remote-funding-pubkey*)
                                                       10000001))))))))

(defun htlc-tx-vector (name)
  (with-open-file (f (asdf:system-relative-pathname "cl-payments" "inspect/vectors/htlc-txs.txt")
                     :if-does-not-exist nil)
    (when f
      (loop for line = (read-line f nil)
            while line
            for l = (string-trim '(#\Space #\Return) line)
            unless (or (zerop (length l)) (char= (char l 0) #\#))
              do (let ((sp (position #\Space l)))
                   (when (string= (subseq l 0 sp) name)
                     (return (subseq l (1+ sp)))))))))

(defun test-htlc-transactions ()
  "The SECOND-stage transactions.  Winning an HTLC does not hand you the money —
   it hands you another delayed, revocable output, so an HTLC claimed from a
   revoked commitment is still punishable."
  (with-gate ("BOLT #3 — HTLC-success and HTLC-timeout transactions (Appendix C)")
    (let ((commitment-txid
            (hx "ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b")))
      ;; HTLC-success: locktime 0.  The preimage is proof enough; there is
      ;; nothing to wait for.
      (let ((tx (m:build-htlc-tx
                 :commitment-txid commitment-txid :output-index 0
                 :htlc-amount-msat 1000000 :direction :received
                 :cltv-expiry 500 :feerate-per-kw 0
                 :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
                 :delayed-pubkey (hx *c-delayed-pubkey*))))
        (check-bytes "htlc_success_tx (htlc #0)"
                     (cl-consensus.tx:serialize-tx tx) (hx (htlc-tx-vector "htlc_success_0")))
        (check-equal "success locktime is 0" (cl-consensus.tx:tx-locktime tx) 0))
      ;; HTLC-timeout: locktime is the expiry.  The counterparty signed this
      ;; transaction when the HTLC was added, so the timelock is the ONLY thing
      ;; preventing the offerer from reclaiming the HTLC immediately.
      (let ((tx (m:build-htlc-tx
                 :commitment-txid commitment-txid :output-index 1
                 :htlc-amount-msat 2000000 :direction :offered
                 :cltv-expiry 502 :feerate-per-kw 0
                 :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
                 :delayed-pubkey (hx *c-delayed-pubkey*))))
        (check-bytes "htlc_timeout_tx (htlc #2)"
                     (cl-consensus.tx:serialize-tx tx) (hx (htlc-tx-vector "htlc_timeout_2")))
        (check-equal "timeout locktime is the cltv_expiry"
                     (cl-consensus.tx:tx-locktime tx) 502))
      ;; The output pays into the SAME script as to_local — delay and all.
      (check-bytes "the HTLC tx output script is the to_local script"
                   (m:htlc-tx-script (hx *c-revocation-pubkey*) 144 (hx *c-delayed-pubkey*))
                   (m:to-local-script (hx *c-revocation-pubkey*) 144 (hx *c-delayed-pubkey*)))
      ;; Fees: the two directions differ, and at a high enough feerate the HTLC
      ;; cannot pay for its own claim — which is exactly why it would have been
      ;; trimmed from the commitment.
      (check-equal "timeout fee at 15000/kw" (m:htlc-tx-fee 15000 :offered) (floor (* 15000 663) 1000))
      (check-equal "success fee at 15000/kw" (m:htlc-tx-fee 15000 :received) (floor (* 15000 703) 1000))
      (check "success costs more than timeout"
             (> (m:htlc-tx-fee 15000 :received) (m:htlc-tx-fee 15000 :offered)))
      (check-signals "an HTLC too small to pay its own second-stage fee is refused"
          m:commitment-error
        (m:build-htlc-tx :commitment-txid commitment-txid :output-index 0
                         :htlc-amount-msat 1000 :direction :received
                         :cltv-expiry 500 :feerate-per-kw 15000
                         :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
                         :delayed-pubkey (hx *c-delayed-pubkey*))))))

(defun test-htlc-signatures ()
  "Reproduce the spec's htlc_signature values.  The scriptCode for an HTLC
   transaction is the HTLC OUTPUT's witness script — the offered/received script
   from the commitment — not the HTLC transaction's own output script.  Using the
   wrong one produces a valid signature over the wrong thing."
  (with-gate ("BOLT #3 — HTLC transaction signatures (Appendix C)")
    (let* ((commitment-txid
             (hx "ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b"))
           (local-htlc-privkey
             ;; From local_htlc_basepoint_secret via the per-commitment point;
             ;; the spec lists the derived key directly.
             (k:derive-privkey
              (secp256k1-fast:bytes-to-int
               (hx "1111111111111111111111111111111111111111111111111111111111111111"))
              (hx "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486")))
           (witness-script
             (m:received-htlc-script (hx *c-revocation-pubkey*) (hx *c-remote-htlc-pubkey*)
                                     (hx *c-local-htlc-pubkey*)
                                     (%preimage-hash "0000000000000000000000000000000000000000000000000000000000000000")
                                     500))
           (tx (m:build-htlc-tx
                :commitment-txid commitment-txid :output-index 0
                :htlc-amount-msat 1000000 :direction :received
                :cltv-expiry 500 :feerate-per-kw 0
                :revocation-pubkey (hx *c-revocation-pubkey*) :to-self-delay 144
                :delayed-pubkey (hx *c-delayed-pubkey*)))
           (sig (m:sign-htlc-tx tx local-htlc-privkey witness-script 1000)))
      (check-bytes "local_htlc_signature for HTLC #0 matches the spec"
                   sig
                   (hx "636de5682ef0c5b61f124ec74e8aa2461a69777521d6998295dcea36bc333811165285594b23c50b28b82df200234566628a27bcd17f7f14404bd865354eb3ce"))
      ;; The HTLC amount is in the BIP143 digest too.
      (check "a different HTLC amount gives a different digest"
             (not (equalp (m:htlc-tx-sighash tx witness-script 1000)
                          (m:htlc-tx-sighash tx witness-script 1001))))
      ;; And the scriptCode must be the HTLC output's script, not the tx's own.
      (check "using the wrong scriptCode gives a different digest"
             (not (equalp (m:htlc-tx-sighash tx witness-script 1000)
                          (m:htlc-tx-sighash tx (m:htlc-tx-script (hx *c-revocation-pubkey*)
                                                                  144 (hx *c-delayed-pubkey*))
                                             1000)))))))

(defun run-commitment-tests ()
  (test-commitment-scripts)
  (test-obscured-commitment-number)
  (test-commitment-fees)
  (test-commitment-vector)
  (test-commitment-structure)
  (test-htlc-scripts)
  (test-htlc-trimming)
  (test-five-htlc-commitment)
  (test-cltv-tiebreak)
  (test-commitment-signing)
  (test-htlc-transactions)
  (test-htlc-signatures))
