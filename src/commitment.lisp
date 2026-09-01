;;;; src/commitment.lisp
;;;;
;;;; Phase 4b — BOLT #3 commitment transactions.
;;;;
;;;; A channel's entire state is one Bitcoin transaction that either party could
;;;; broadcast but neither wants to.  It spends the 2-of-2 funding output and
;;;; pays each side its current balance, with one crucial asymmetry: MY
;;;; commitment pays me only after a delay and via a script YOU can sweep if I
;;;; ever publish a revoked version.  Yours is the mirror image.  That asymmetry
;;;; is the entire enforcement mechanism, and it means the two sides hold
;;;; DIFFERENT transactions for the same state.
;;;;
;;;; Two details here look arbitrary and are not:
;;;;
;;;;   The commitment number is hidden in the locktime and sequence, obscured by
;;;;   a hash of both payment basepoints.  Without it, anyone watching the chain
;;;;   could read a channel's exact age off a published commitment.  With it, the
;;;;   number is recoverable only by the two parties.
;;;;
;;;;   The opener pays the fee, and it is deducted from ITS balance — so
;;;;   `to_local` is the balance minus the fee, not the balance.  Getting this
;;;;   backwards produces a transaction the counterparty simply refuses to sign,
;;;;   with no explanation.
;;;;
;;;; Transactions are built and serialized with cl-consensus, so what we produce
;;;; is checkable by our own consensus engine rather than merely by our own
;;;; reading of the spec.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/03-transactions.md

(defpackage #:cl-payments.commitment
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:k #:cl-payments.keys)
                    (#:btx #:cl-consensus.tx) (#:bw #:cl-consensus.wire)
                    (#:secp #:secp256k1-fast))
  (:nicknames #:ln-commitment)
  (:export
   ;; scripts
   #:funding-script #:funding-scriptpubkey
   #:to-local-script #:to-remote-scriptpubkey
   #:p2wsh #:p2wpkh #:script-push
   ;; the commitment number's disguise
   #:obscuring-factor #:obscured-commitment-number
   #:commitment-locktime #:commitment-sequence
   ;; fees and weights
   #:+commit-weight-base+ #:+htlc-output-weight+
   #:commitment-fee #:dust-p
   ;; the transaction
   #:build-commitment #:commitment-tx #:commitment-outputs
   #:commitment-error))

(in-package #:cl-payments.commitment)

(define-condition commitment-error (error)
  ((detail :initarg :detail :reader commitment-error-detail))
  (:report (lambda (c s) (format s "commitment: ~a" (commitment-error-detail c)))))

;;; ----------------------------------------------------------------------------
;;; Script building
;;; ----------------------------------------------------------------------------

(defun bytes (&rest seqs)
  (apply #'concatenate '(vector (unsigned-byte 8)) seqs))

(defun script-push (data)
  "A minimal data push.  Only the sizes BOLT #3 actually uses are needed here —
   33-byte keys, 20-byte hashes, and small CSV/CLTV numbers."
  (let ((n (length data)))
    (cond ((< n 76) (bytes (vector n) data))
          ((<= n #xff) (bytes (vector 76 n) data))
          (t (error 'commitment-error :detail "push too large for a BOLT #3 script")))))

(defun script-number (n)
  "CScriptNum encoding, as a push.  Used for `to_self_delay` and HTLC expiries."
  (cond ((zerop n) (bytes (vector 0)))
        ((<= 1 n 16) (bytes (vector (+ #x50 n))))
        (t (let ((out '()))
             (loop for v = n then (ash v -8)
                   while (plusp v)
                   do (push (logand v #xff) out))
             (setf out (nreverse out))
             (when (logtest (car (last out)) #x80) (setf out (append out (list 0))))
             (script-push (coerce out '(vector (unsigned-byte 8))))))))

(defun p2wsh (witness-script)
  "OP_0 <sha256(script)> — the scriptPubKey committing to a witness script."
  (bytes (vector 0 32) (c:sha256 witness-script)))

(defun p2wpkh (pubkey)
  "OP_0 <hash160(pubkey)>."
  (bytes (vector 0 20) (bw:hash160 (c:octets pubkey))))

(defun funding-script (local-funding-pubkey remote-funding-pubkey)
  "The 2-of-2 the channel is anchored to.

   The keys are sorted LEXICOGRAPHICALLY, not by who is local — both sides must
   produce identical bytes or they compute different funding addresses and the
   channel is funded to an output neither can spend."
  (let* ((a (c:octets local-funding-pubkey))
         (b (c:octets remote-funding-pubkey))
         (first (if (string< (c:bytes->hex a) (c:bytes->hex b)) a b))
         (second (if (string< (c:bytes->hex a) (c:bytes->hex b)) b a)))
    (bytes (vector #x52)                  ; OP_2
           (script-push first)
           (script-push second)
           (vector #x52 #xae))))          ; OP_2 OP_CHECKMULTISIG

(defun funding-scriptpubkey (local-funding-pubkey remote-funding-pubkey)
  (p2wsh (funding-script local-funding-pubkey remote-funding-pubkey)))

(defun to-local-script (revocation-pubkey to-self-delay delayed-pubkey)
  "The output paying the commitment's OWNER, and the reason a revoked commitment
   is punishable:

     OP_IF   <revocationpubkey>
     OP_ELSE <to_self_delay> OP_CSV OP_DROP <local_delayedpubkey>
     OP_ENDIF OP_CHECKSIG

   The owner takes the ELSE branch and must wait `to_self_delay` blocks.  That
   delay is the window in which the counterparty, holding the revocation key for
   a revoked state, takes the IF branch immediately and sweeps everything."
  (bytes (vector #x63)                              ; OP_IF
         (script-push (c:octets revocation-pubkey))
         (vector #x67)                              ; OP_ELSE
         (script-number to-self-delay)
         (vector #xb2 #x75)                         ; OP_CHECKSEQUENCEVERIFY OP_DROP
         (script-push (c:octets delayed-pubkey))
         (vector #x68 #xac)))                       ; OP_ENDIF OP_CHECKSIG

(defun to-remote-scriptpubkey (remote-pubkey)
  "The counterparty's side of a commitment I hold.  Plain P2WPKH: they are not
   the one who published it, so they need no delay and there is nothing to
   punish."
  (p2wpkh remote-pubkey))

;;; ----------------------------------------------------------------------------
;;; Hiding the commitment number
;;; ----------------------------------------------------------------------------

(defun obscuring-factor (open-payment-basepoint accept-payment-basepoint)
  "The lower 48 bits of SHA256(opener_payment_basepoint ‖ accepter_payment_basepoint).

   Order is by ROLE, not by local/remote: both sides must agree, and each is
   local to itself.  Using your own basepoint first gives two different factors
   and a commitment number neither party can read."
  (let ((h (c:sha256 (bytes (c:octets open-payment-basepoint)
                            (c:octets accept-payment-basepoint)))))
    (loop with v = 0
          for i from (- (length h) 6) below (length h)
          do (setf v (logior (ash v 8) (aref h i)))
          finally (return v))))

(defun obscured-commitment-number (number obscuring)
  (logxor number obscuring))

(defun commitment-locktime (obscured)
  "Upper nibble 0x20 marks it as a locktime by height; the low 24 bits carry
   half the obscured commitment number."
  (logior #x20000000 (logand obscured #xffffff)))

(defun commitment-sequence (obscured)
  "The other 24 bits, with the high bit set so the sequence disables locktime
   semantics it does not want."
  (logior #x80000000 (logand (ash obscured -24) #xffffff)))

;;; ----------------------------------------------------------------------------
;;; Fees
;;; ----------------------------------------------------------------------------

(defconstant +commit-weight-base+ 724
  "Weight of a commitment transaction with no HTLC outputs (BOLT #3 Appendix A).")
(defconstant +htlc-output-weight+ 172
  "Each untrimmed HTLC output adds this much weight.")

(defun commitment-fee (feerate-per-kw num-htlcs)
  "Fee in satoshis.  Note `per_kw` is per 1000 WEIGHT units, not per 1000 bytes,
   and the result is truncated."
  (floor (* feerate-per-kw (+ +commit-weight-base+ (* num-htlcs +htlc-output-weight+)))
         1000))

(defun dust-p (amount-sat dust-limit)
  "An output below the dust limit is not created at all — its value goes to fees
   instead.  Both sides must agree exactly on which outputs vanish, or their
   commitment transactions differ and no signature validates."
  (< amount-sat dust-limit))

;;; ----------------------------------------------------------------------------
;;; The transaction
;;; ----------------------------------------------------------------------------

(defun %bip69-sort (outputs)
  "BIP69: ascending by amount, then by scriptPubKey.  A canonical order is what
   lets both parties build byte-identical transactions independently."
  (sort (copy-list outputs)
        (lambda (a b)
          (let ((va (btx:txout-value a)) (vb (btx:txout-value b)))
            (if (/= va vb)
                (< va vb)
                (string< (c:bytes->hex (btx:txout-script a))
                         (c:bytes->hex (btx:txout-script b))))))))

(defun build-commitment (&key funding-txid funding-output-index funding-amount-sat
                              commitment-number obscuring
                              to-local-msat to-remote-msat
                              local-feerate-per-kw dust-limit-sat
                              revocation-pubkey to-self-delay delayed-pubkey
                              remote-pubkey (opener :local))
  "Build one commitment transaction.  Returns (values tx outputs-description).

   OPENER says whose balance the fee comes out of.  The fee is NOT split: the
   channel opener pays all of it, for the life of the channel."
  (let* ((obscured (obscured-commitment-number commitment-number obscuring))
         (fee (commitment-fee local-feerate-per-kw 0))
         (to-local-sat (floor to-local-msat 1000))
         (to-remote-sat (floor to-remote-msat 1000)))
    ;; Deduct the fee from whoever opened, before dust is considered — an output
    ;; can be dusted BY the fee.
    (ecase opener
      (:local (setf to-local-sat (- to-local-sat fee)))
      (:remote (setf to-remote-sat (- to-remote-sat fee))))
    (when (or (minusp to-local-sat) (minusp to-remote-sat))
      (error 'commitment-error
             :detail (format nil "fee ~d exceeds the ~(~a~) balance" fee opener)))
    (let* ((local-script (to-local-script revocation-pubkey to-self-delay delayed-pubkey))
           (outputs '())
           (described '()))
      (unless (dust-p to-remote-sat dust-limit-sat)
        (push (btx:make-txout :value to-remote-sat
                              :script (to-remote-scriptpubkey remote-pubkey))
              outputs)
        (push (list :to-remote to-remote-sat) described))
      (unless (dust-p to-local-sat dust-limit-sat)
        (push (btx:make-txout :value to-local-sat :script (p2wsh local-script)) outputs)
        (push (list :to-local to-local-sat local-script) described))
      (let ((tx (btx:make-tx
                 :version 2
                 :inputs (list (btx:make-txin
                                :prev-hash (c:octets funding-txid)
                                :prev-index funding-output-index
                                :script #()
                                :sequence (commitment-sequence obscured)))
                 :outputs (%bip69-sort outputs)
                 :witnesses (list nil)
                 :locktime (commitment-locktime obscured)
                 :segwit-p nil)))
        (declare (ignorable funding-amount-sat))
        (values (btx:parse-tx (bw:make-reader (btx:serialize-tx tx)))
                (nreverse described))))))
