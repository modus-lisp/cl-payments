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
                    (#:bs #:cl-consensus.script) (#:secp #:secp256k1-fast))
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
   #:+htlc-timeout-weight+ #:+htlc-success-weight+
   #:commitment-fee #:dust-p #:htlc-trimmed-p
   ;; HTLCs
   #:htlc #:make-htlc #:htlc-direction #:htlc-amount-msat #:htlc-expiry
   #:htlc-payment-hash #:offered-htlc-script #:received-htlc-script
   ;; the transaction
   #:build-commitment #:sign-commitment #:verify-commitment #:commitment-sighash
   #:anchor-script #:to-remote-anchors-script #:+anchor-sat+ #:+commit-weight-base-anchors+
   #:+sighash-single-anyonecanpay+
   #:sig->der #:funding-witness
   ;; second-stage HTLC transactions
   #:htlc-tx-script #:build-htlc-tx #:htlc-tx-fee #:sign-htlc-tx #:htlc-tx-sighash
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

(defconstant +anchor-sat+ 330 "An anchor's value: the default P2WSH dust limit.")

(defun anchor-script (funding-pubkey)
  "`<funding_pubkey> OP_CHECKSIG OP_IFDUP OP_NOTIF OP_16 OP_CSV OP_ENDIF`: the
   owner can spend at once to bump the commitment's fee (child-pays-for-parent);
   after 16 blocks anyone can, so unspent anchors do not pollute the UTXO set."
  (bytes (script-push (c:octets funding-pubkey))
         (vector #xac #x73 #x64 #x60 #xb2 #x68)))

(defun to-remote-anchors-script (remote-pubkey)
  "With option_anchors, to_remote is not a bare P2WPKH but
   `<remotepubkey> OP_CHECKSIGVERIFY 1 OP_CSV`: one block of CSV, so the
   commitment cannot be pinned by a child spending it in the same block."
  (bytes (script-push (c:octets remote-pubkey)) (vector #xad #x51 #xb2)))

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

(defconstant +commit-weight-base-anchors+ 1124
  "With option_anchors: two more P2WSH outputs and a larger to_remote.")
(defconstant +commit-weight-base+ 724
  "Weight of a commitment transaction with no HTLC outputs (BOLT #3 Appendix A).")
(defconstant +htlc-output-weight+ 172
  "Each untrimmed HTLC output adds this much weight.")
(defconstant +htlc-timeout-weight+ 663
  "Weight of the second-stage HTLC-timeout transaction (no option_anchors).")
(defconstant +htlc-success-weight+ 703
  "Weight of the second-stage HTLC-success transaction (no option_anchors).")

(defun commitment-fee (feerate-per-kw num-htlcs &key anchors)
  "Fee in satoshis.  Note `per_kw` is per 1000 WEIGHT units, not per 1000 bytes,
   and the result is truncated."
  (floor (* feerate-per-kw (+ (if anchors +commit-weight-base-anchors+ +commit-weight-base+)
                              (* num-htlcs +htlc-output-weight+)))
         1000))

(defun htlc-trimmed-p (amount-msat direction feerate-per-kw dust-limit &key anchors)
  "An HTLC is trimmed when its second-stage transaction's output would be
   dust: the HTLC amount minus that transaction's fee, against the owner's
   dust limit.  With anchors the second stage pays no fee, so the amount alone
   decides — a higher dust limit is the only trimming lever left."
  (< (- (floor amount-msat 1000) (if anchors 0 (htlc-tx-fee feerate-per-kw direction)))
     dust-limit))

(defun dust-p (amount-sat dust-limit)
  "An output below the dust limit is not created at all — its value goes to fees
   instead.  Both sides must agree exactly on which outputs vanish, or their
   commitment transactions differ and no signature validates."
  (< amount-sat dust-limit))

;;; ----------------------------------------------------------------------------
;;; HTLC output scripts
;;;
;;; Both scripts have the same three-way shape: the counterparty sweeps it
;;; immediately with the revocation key if this commitment was revoked; otherwise
;;; one party takes it with the preimage and the other after a timeout.  Which
;;; party gets which branch is the only difference, and it is the difference
;;; between offered and received.
;;;
;;; The `OP_SIZE 32 OP_EQUAL` test is what distinguishes the two spending paths
;;; without a separate flag: a preimage is exactly 32 bytes, so pushing anything
;;; else selects the other branch.
;;; ----------------------------------------------------------------------------

(defstruct htlc
  direction          ; :offered (we pay) or :received (we are paid)
  amount-msat
  expiry             ; cltv_expiry
  payment-hash)      ; 32 bytes

(defun %ripemd160 (bytes) (ironclad:digest-sequence :ripemd-160 (c:octets bytes)))

(defun offered-htlc-script (revocation-pubkey remote-htlc-pubkey local-htlc-pubkey
                            payment-hash &key anchors)
  "An HTLC WE offered: the remote takes it with the preimage, we reclaim it
   through a timelocked HTLC-timeout transaction."
  (bytes (vector #x76 #xa9)                                   ; OP_DUP OP_HASH160
         (script-push (%ripemd160 (c:sha256 (c:octets revocation-pubkey))))
         (vector #x87 #x63)                                   ; OP_EQUAL OP_IF
         (vector #xac)                                        ;   OP_CHECKSIG
         (vector #x67)                                        ; OP_ELSE
         (script-push (c:octets remote-htlc-pubkey))
         (vector #x7c #x82 #x01 #x20 #x87)                    ; OP_SWAP OP_SIZE 32 OP_EQUAL
         (vector #x64)                                        ; OP_NOTIF
         (vector #x75 #x52 #x7c)                              ;   OP_DROP 2 OP_SWAP
         (script-push (c:octets local-htlc-pubkey))
         (vector #x52 #xae)                                   ;   2 OP_CHECKMULTISIG
         (vector #x67)                                        ; OP_ELSE
         (vector #xa9)                                        ;   OP_HASH160
         (script-push (%ripemd160 payment-hash))
         (vector #x88 #xac)                                   ;   OP_EQUALVERIFY OP_CHECKSIG
         (vector #x68)                                        ; OP_ENDIF
         ;; option_anchors: every non-anchor output is one block CSV-locked.
         (if anchors (vector #x51 #xb2 #x75) (vector))        ;   1 OP_CSV OP_DROP
         (vector #x68)))                                      ; OP_ENDIF

(defun received-htlc-script (revocation-pubkey remote-htlc-pubkey local-htlc-pubkey
                             payment-hash cltv-expiry &key anchors)
  "An HTLC we RECEIVED: we take it with the preimage via an HTLC-success
   transaction, the remote reclaims it after `cltv_expiry`."
  (bytes (vector #x76 #xa9)                                   ; OP_DUP OP_HASH160
         (script-push (%ripemd160 (c:sha256 (c:octets revocation-pubkey))))
         (vector #x87 #x63)                                   ; OP_EQUAL OP_IF
         (vector #xac)                                        ;   OP_CHECKSIG
         (vector #x67)                                        ; OP_ELSE
         (script-push (c:octets remote-htlc-pubkey))
         (vector #x7c #x82 #x01 #x20 #x87)                    ; OP_SWAP OP_SIZE 32 OP_EQUAL
         (vector #x63)                                        ; OP_IF
         (vector #xa9)                                        ;   OP_HASH160
         (script-push (%ripemd160 payment-hash))
         (vector #x88)                                        ;   OP_EQUALVERIFY
         (vector #x52 #x7c)                                   ;   2 OP_SWAP
         (script-push (c:octets local-htlc-pubkey))
         (vector #x52 #xae)                                   ;   2 OP_CHECKMULTISIG
         (vector #x67)                                        ; OP_ELSE
         (vector #x75)                                        ;   OP_DROP
         (script-number cltv-expiry)
         (vector #xb1 #x75)                                   ;   OP_CLTV OP_DROP
         (vector #xac)                                        ;   OP_CHECKSIG
         (vector #x68)                                        ; OP_ENDIF
         (if anchors (vector #x51 #xb2 #x75) (vector))        ;   1 OP_CSV OP_DROP
         (vector #x68)))                                      ; OP_ENDIF

;;; ----------------------------------------------------------------------------
;;; The transaction
;;; ----------------------------------------------------------------------------

(defun %bip69-sort (entries)
  "BOLT #3 output ordering: by value, then scriptPubKey, then — for HTLC outputs
   only — by increasing `cltv_expiry`.

   The CLTV tiebreak exists for a specific case: two offered HTLCs with the same
   rounded amount and the same payment hash produce IDENTICAL outputs even though
   their expiries differ.  The peers exchange `htlc_signatures` in this order and
   the second-stage transactions are not identical, so without an agreed tiebreak
   they would attach the signatures to the wrong HTLCs.

   ENTRIES are (txout . cltv-or-nil); the cltv is carried alongside because it
   does not appear in the output itself."
  (sort (copy-list entries)
        (lambda (x y)
          (let* ((a (car x)) (b (car y))
                 (va (btx:txout-value a)) (vb (btx:txout-value b)))
            (cond
              ((/= va vb) (< va vb))
              ((not (equalp (btx:txout-script a) (btx:txout-script b)))
               ;; memcmp over the common prefix; if one is a prefix of the
               ;; other, the shorter sorts first.
               (let* ((sa (btx:txout-script a)) (sb (btx:txout-script b))
                      (n (min (length sa) (length sb)))
                      (diff (loop for i from 0 below n
                                  when (/= (aref sa i) (aref sb i)) return i)))
                 (if diff
                     (< (aref sa diff) (aref sb diff))
                     (< (length sa) (length sb)))))
              ;; Identical outputs: only an HTLC can reach here, and then the
              ;; expiry decides.  Without this the two peers can order such a
              ;; pair differently, attach each other's htlc_signatures to the
              ;; wrong HTLC, and neither signature verifies.
              ((and (cdr x) (cdr y)) (< (car (cdr x)) (car (cdr y))))
              (t nil))))))

(defun build-commitment (&key funding-txid funding-output-index funding-amount-sat
                              commitment-number obscuring
                              to-local-msat to-remote-msat
                              local-feerate-per-kw dust-limit-sat
                              revocation-pubkey to-self-delay delayed-pubkey
                              remote-pubkey (opener :local)
                              htlcs local-htlc-pubkey remote-htlc-pubkey
                              anchors local-funding-pubkey remote-funding-pubkey)
  "Build one commitment transaction.  Returns (values tx description htlc-order).

   HTLC-ORDER is the surviving HTLCs in OUTPUT order, which the caller needs and
   cannot recompute: `commitment_signed` carries one signature per HTLC in the
   order of the HTLC outputs, and two offered HTLCs with the same rounded amount
   and payment hash produce IDENTICAL outputs — so the order is only recoverable
   from the CLTV tiebreak applied here.

   OPENER says whose balance the fee comes out of.  The fee is NOT split: the
   channel opener pays all of it, for the life of the channel."
  (let* ((obscured (obscured-commitment-number commitment-number obscuring))
         ;; Trim FIRST: a trimmed HTLC contributes no output and therefore no
         ;; weight, so the fee depends on how many survive.
         (live-htlcs (remove-if (lambda (h)
                                  (htlc-trimmed-p (htlc-amount-msat h)
                                                  (htlc-direction h)
                                                  local-feerate-per-kw dust-limit-sat
                                                  :anchors anchors))
                                htlcs))
         (fee (commitment-fee local-feerate-per-kw (length live-htlcs) :anchors anchors))
         (to-local-sat (floor to-local-msat 1000))
         (to-remote-sat (floor to-remote-msat 1000)))
    ;; Deduct the fee from whoever opened, before dust is considered — an output
    ;; can be dusted BY the fee.
    ;; With anchors, the funder also pays for the anchors themselves — both of
    ;; them, whenever both exist.  Whether both exist depends on the dust
    ;; decision below, so the anchor cost is taken first assuming both and
    ;; refunded if one turns out not to be needed.
    (let ((anchor-cost (if anchors (* 2 +anchor-sat+) 0)))
      (ecase opener
        (:local (setf to-local-sat (- to-local-sat fee anchor-cost)))
        (:remote (setf to-remote-sat (- to-remote-sat fee anchor-cost))))
      (when (or (minusp to-local-sat) (minusp to-remote-sat))
        (error 'commitment-error
               :detail (format nil "fee ~d exceeds the ~(~a~) balance" fee opener)))
      ;; The single-anchor rule: with no HTLCs, a side whose balance output is
      ;; dust gets no anchor either — there is nothing of theirs to bump.
      (let* ((local-dust (dust-p to-local-sat dust-limit-sat))
             (remote-dust (dust-p to-remote-sat dust-limit-sat))
             (local-anchor (and anchors (or live-htlcs (not local-dust))))
             (remote-anchor (and anchors (or live-htlcs (not remote-dust)))))
        ;; When only one anchor exists the funder STILL pays for two: the
        ;; absent anchor's 330 sat goes to fees, as a trimmed output would.
        ;; (Appendix F's single-anchor vector is the proof.)
    (let* ((local-script (to-local-script revocation-pubkey to-self-delay delayed-pubkey))
           (outputs '())
           (described '()))
      (unless remote-dust
        (push (cons (btx:make-txout :value to-remote-sat
                                    :script (if anchors
                                                (p2wsh (to-remote-anchors-script remote-pubkey))
                                                (to-remote-scriptpubkey remote-pubkey)))
                    nil)
              outputs)
        (push (list :to-remote to-remote-sat) described))
      (unless local-dust
        (push (cons (btx:make-txout :value to-local-sat :script (p2wsh local-script)) nil)
              outputs)
        (push (list :to-local to-local-sat local-script) described))
      (when local-anchor
        (push (cons (btx:make-txout :value +anchor-sat+ :script (p2wsh (anchor-script local-funding-pubkey))) nil) outputs)
        (push (list :to-local-anchor +anchor-sat+) described))
      (when remote-anchor
        (push (cons (btx:make-txout :value +anchor-sat+ :script (p2wsh (anchor-script remote-funding-pubkey))) nil) outputs)
        (push (list :to-remote-anchor +anchor-sat+) described))
      (dolist (h live-htlcs)
        (let* ((script (ecase (htlc-direction h)
                         (:offered (offered-htlc-script revocation-pubkey
                                                        remote-htlc-pubkey
                                                        local-htlc-pubkey
                                                        (htlc-payment-hash h) :anchors anchors))
                         (:received (received-htlc-script revocation-pubkey
                                                          remote-htlc-pubkey
                                                          local-htlc-pubkey
                                                          (htlc-payment-hash h)
                                                          (htlc-expiry h) :anchors anchors))))
               ;; The millisatoshi remainder is dropped, not rounded — and it is
               ;; dropped for the ORDERING comparison too.
               (sat (floor (htlc-amount-msat h) 1000)))
          (push (cons (btx:make-txout :value sat :script (p2wsh script))
                      (cons (htlc-expiry h) h))
                outputs)
          (push (list :htlc (htlc-direction h) sat (htlc-expiry h) script) described)))
      (let* ((sorted (%bip69-sort outputs))
             (htlc-order (loop for e in sorted when (cdr e) collect (cdr (cdr e))))
             (tx (btx:make-tx
                 :version 2
                 :inputs (list (btx:make-txin
                                :prev-hash (c:octets funding-txid)
                                :prev-index funding-output-index
                                :script #()
                                :sequence (commitment-sequence obscured)))
                 :outputs (mapcar #'car sorted)
                 :witnesses (list nil)
                 :locktime (commitment-locktime obscured)
                 :segwit-p nil)))
        (declare (ignorable funding-amount-sat))
        (values (btx:parse-tx (bw:make-reader (btx:serialize-tx tx)))
                (nreverse described)
                htlc-order)))))))

;;; ----------------------------------------------------------------------------
;;; Signing
;;;
;;; A commitment spends the funding output, which is a P2WSH 2-of-2 — so the
;;; digest is BIP143's, with the funding witness script as the scriptCode and the
;;; funding amount included.  Including the amount is the point of BIP143: it is
;;; what stopped a signer being lied to about how much it was spending.
;;;
;;; `funding_created` and `commitment_signed` both carry exactly this signature,
;;; over the transaction the COUNTERPARTY holds.  You never sign your own
;;; commitment — you sign theirs, and they sign yours, which is why either side
;;; can publish but neither can publish alone.
;;; ----------------------------------------------------------------------------

(defun commitment-sighash (tx local-funding-pubkey remote-funding-pubkey funding-amount-sat)
  "The BIP143 digest a commitment signature covers.  SIGHASH_ALL only —
   Lightning has no use for any other mode here, and accepting one would let a
   counterparty reuse a signature against different outputs."
  (bs:bip143-sighash tx 0
                     (funding-script local-funding-pubkey remote-funding-pubkey)
                     funding-amount-sat
                     bs:+sighash-all+))

(defun verify-commitment (tx signature local-funding-pubkey remote-funding-pubkey
                          funding-amount-sat signer-pubkey)
  "Check a counterparty's 64-byte signature over a commitment transaction.

   This is the check that decides whether it is safe to have money in a channel
   at all.  Accepting a funding output without a valid remote signature over OUR
   commitment means we hold a 2-of-2 we can never unilaterally spend: the funds
   are gone the moment the peer stops cooperating, and nothing on the wire
   distinguishes that from a healthy channel until you try to close it.

   Returns NIL rather than signalling, so a caller can refuse politely."
  (handler-case
      (let ((hash (commitment-sighash tx local-funding-pubkey remote-funding-pubkey
                                      funding-amount-sat))
            (r (secp:bytes-to-int (subseq signature 0 32)))
            (s (secp:bytes-to-int (subseq signature 32 64))))
        (and (secp:ecdsa-verify (c:parse-pubkey signer-pubkey) hash r s) t))
    (error () nil)))

(defconstant +sighash-all-byte+ 1)

(defun sig->der (sig64 &optional (sighash-type +sighash-all-byte+))
  "The 64-byte compact signature the wire carries, as the DER form Bitcoin
   script requires, with the sighash byte appended.

   Two encodings for one signature because the two audiences differ: BOLT #1
   wants fixed-size fields, Bitcoin wants what OpenSSL produced in 2009.  The
   conversion is at the boundary — a compact signature never goes on chain and a
   DER one never goes on the wire.  Each INTEGER is minimally encoded, with a
   leading zero only when the high bit is set; BIP66 rejects anything else."
  (flet ((int (bytes)
           (let* ((start (or (position-if-not #'zerop bytes) (1- (length bytes))))
                  (body (subseq bytes start))
                  (body (if (logbitp 7 (aref body 0)) (bytes (vector 0) body) body)))
             (bytes (vector #x02 (length body)) body))))
    (let* ((r (int (subseq sig64 0 32))) (s (int (subseq sig64 32 64)))
           (seq (bytes r s)))
      (bytes (vector #x30 (length seq)) seq (vector sighash-type)))))

(defun funding-witness (sig-a pubkey-a sig-b pubkey-b funding-script)
  "The witness that spends a funding output: an empty element for
   CHECKMULTISIG's off-by-one, the two signatures IN THE SCRIPT'S KEY ORDER, and
   the script itself.  Signatures out of order fail even when both are valid."
  (let ((pairs (sort (list (cons (c:octets pubkey-a) sig-a) (cons (c:octets pubkey-b) sig-b))
                     (lambda (x y) (string< (c:bytes->hex (car x)) (c:bytes->hex (car y)))))))
    (list (bytes) (sig->der (cdr (first pairs))) (sig->der (cdr (second pairs))) funding-script)))

(defun sign-commitment (tx funding-privkey local-funding-pubkey remote-funding-pubkey
                        funding-amount-sat)
  "Sign a commitment transaction, returning the 64-byte compact (r ‖ s) form the
   Lightning wire uses.  Bitcoin would want DER here; BOLT #1 does not, so the
   conversion happens at the boundary rather than in the message encoder."
  (let ((hash (commitment-sighash tx local-funding-pubkey remote-funding-pubkey
                                  funding-amount-sat)))
    (multiple-value-bind (r s) (secp:ecdsa-sign-raw funding-privkey hash)
      (bytes (secp:int-to-bytes32 r) (secp:int-to-bytes32 s)))))


;;; ----------------------------------------------------------------------------
;;; Second-stage HTLC transactions
;;;
;;; An HTLC output on a commitment cannot simply be swept.  Claiming it needs a
;;; SECOND transaction — HTLC-success with the preimage, HTLC-timeout after the
;;; expiry — and that transaction pays into the same delayed, revocable script
;;; the `to_local` output uses.  So an HTLC you win still sits behind
;;; `to_self_delay`, and is still punishable if the commitment it came from was
;;; revoked.
;;;
;;; Both transactions are pre-signed by the counterparty at the time the HTLC is
;;; added: you receive their signature and can only ever complete the one whose
;;; condition you can satisfy.  That is why the timeout transaction's locktime is
;;; `cltv_expiry` — the signature exists from the start, and the timelock is what
;;; stops it being used early.

(defun htlc-tx-script (revocation-pubkey to-self-delay delayed-pubkey)
  "The output script of an HTLC transaction — identical to `to_local`.  Winning
   an HTLC does not get you the money immediately; it gets you the same delayed,
   revocable output."
  (to-local-script revocation-pubkey to-self-delay delayed-pubkey))

(defun htlc-tx-fee (feerate-per-kw direction)
  "The second-stage fee, which is what makes a small HTLC not worth claiming and
   therefore trimmed from the commitment in the first place."
  (floor (* feerate-per-kw (ecase direction
                             (:offered +htlc-timeout-weight+)
                             (:received +htlc-success-weight+)))
         1000))

(defun build-htlc-tx (&key commitment-txid output-index htlc-amount-msat direction
                           cltv-expiry feerate-per-kw
                           revocation-pubkey to-self-delay delayed-pubkey anchors)
  "The HTLC-success (:received) or HTLC-timeout (:offered) transaction spending
   one HTLC output of a commitment.

   The locktime is the difference: 0 for success — the preimage is proof enough,
   there is nothing to wait for — and `cltv_expiry` for timeout, which is what
   stops the offerer reclaiming the HTLC before it has actually expired."
  ;; With anchors the second stage pays NO fee: its input and output are equal,
  ;; the peer signs it SINGLE|ANYONECANPAY, and whoever broadcasts it attaches
  ;; inputs of their own for the fee.
  (let* ((fee (if anchors 0 (htlc-tx-fee feerate-per-kw direction)))
         (amount (- (floor htlc-amount-msat 1000) fee)))
    (when (minusp amount)
      (error 'commitment-error
             :detail (format nil "HTLC of ~d msat cannot pay its ~d sat second-stage fee"
                             htlc-amount-msat fee)))
    (let ((tx (btx:make-tx
               :version 2
               :inputs (list (btx:make-txin
                              :prev-hash (c:octets commitment-txid)
                              :prev-index output-index
                              :script #()
                              ;; 0 without option_anchors; 1 with it.
                              :sequence (if anchors 1 0)))
               :outputs (list (btx:make-txout
                               :value amount
                               :script (p2wsh (htlc-tx-script revocation-pubkey
                                                              to-self-delay
                                                              delayed-pubkey))))
               :witnesses (list nil)
               :locktime (ecase direction
                           (:received 0)
                           (:offered cltv-expiry))
               :segwit-p nil)))
      (btx:parse-tx (bw:make-reader (btx:serialize-tx tx))))))

(defconstant +sighash-single-anyonecanpay+ (logior bs:+sighash-single+ bs:+sighash-anyonecanpay+))

(defun htlc-tx-sighash (tx htlc-witness-script htlc-amount-sat &key (sighash bs:+sighash-all+))
  "BIP143 digest for an HTLC transaction.  The scriptCode is the HTLC output's
   own witness script — the offered/received script from the commitment, not the
   HTLC transaction's output script.  With anchors the PEER's signature is
   SINGLE|ANYONECANPAY, so the broadcaster can add fee inputs; ours stays ALL."
  (bs:bip143-sighash tx 0 htlc-witness-script htlc-amount-sat sighash))

(defun sign-htlc-tx (tx privkey htlc-witness-script htlc-amount-sat &key (sighash bs:+sighash-all+))
  "Sign an HTLC transaction, returning the 64-byte compact form."
  (let ((hash (htlc-tx-sighash tx htlc-witness-script htlc-amount-sat :sighash sighash)))
    (multiple-value-bind (r s) (secp:ecdsa-sign-raw privkey hash)
      (bytes (secp:int-to-bytes32 r) (secp:int-to-bytes32 s)))))
