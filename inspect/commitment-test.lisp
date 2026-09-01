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

(defun run-commitment-tests ()
  (test-commitment-scripts)
  (test-obscured-commitment-number)
  (test-commitment-fees)
  (test-commitment-vector)
  (test-commitment-structure))
