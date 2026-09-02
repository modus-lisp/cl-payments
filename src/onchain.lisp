;;;; src/onchain.lisp
;;;;
;;;; Phase 8 — BOLT #5: what to do when a commitment transaction hits the chain.
;;;;
;;;; A channel's whole security argument is made here.  Every commitment we
;;;; ever signed is a valid Bitcoin transaction the peer could publish, and the
;;;; protocol's answer is not "they won't" but "if they publish an OLD one, we
;;;; take everything".  That answer only holds if we notice the publication,
;;;; recognise which commitment it is, and get the penalty confirmed before
;;;; their CSV delay expires.  Nothing else in this system loses money faster
;;;; than being wrong here.
;;;;
;;;; Four things can spend a funding output, and each gets a different reply:
;;;;
;;;;   mutual close        — the transaction both sides signed; nothing to do.
;;;;   their commitment    — the current one: legitimate.  Our to_remote is
;;;;                         P2WPKH under our payment key and spendable at once;
;;;;                         we sweep it.
;;;;   their REVOKED one   — we hold the per-commitment secret they revealed,
;;;;                         so the revocation key of that commitment is ours.
;;;;                         Their to_local becomes ours.  Penalty.
;;;;   our commitment      — we force-closed.  Our to_local is behind the CSV
;;;;                         they demanded; we sweep after it.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/05-onchain.md

(defpackage #:cl-payments.onchain
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:k #:cl-payments.keys)
                    (#:m #:cl-payments.commitment) (#:lv #:cl-payments.live)
                    (#:btx #:cl-consensus.tx) (#:bw #:cl-consensus.wire)
                    (#:bs #:cl-consensus.script) (#:secp #:secp256k1-fast))
  (:nicknames #:ln-onchain)
  (:export
   #:classify-spend #:onchain-error
   #:sweep-to-remote #:sweep-to-local #:penalty
   #:to-remote-output #:to-local-output))

(in-package #:cl-payments.onchain)

(define-condition onchain-error (error)
  ((detail :initarg :detail :reader onchain-error-detail))
  (:report (lambda (c s) (format s "onchain: ~a" (onchain-error-detail c)))))
(defun fail (fmt &rest args) (error 'onchain-error :detail (apply #'format nil fmt args)))

;;; ----------------------------------------------------------------------------
;;; Classification
;;; ----------------------------------------------------------------------------

(defun classify-spend (lc tx)
  "What is TX, which spends our funding output?  Returns (values kind n):
   :mutual-close, :our-commitment, :their-commitment, :revoked, or :unknown."
  (let ((txid (btx:tx-txid tx)))
    (cond
      ((and (lv:live-closing-txid lc) (equalp (c:octets txid) (c:octets (lv:live-closing-txid lc))))
       (values :mutual-close nil))
      ((let ((ours (lv:local-commitment-tx lc)))
         (and ours (btx:tx-txid ours) txid
              (equalp (c:octets (btx:tx-txid ours)) (c:octets txid))))
       (values :our-commitment (lv:live-local-commit-index lc)))
      (t
       (let ((n (lv:commitment-number-of lc tx)))
         (cond ((lv:revoked-secret-for lc n) (values :revoked n))
               ((or (= n (lv:live-remote-commit-index lc))
                    (= n (1+ (lv:live-remote-commit-index lc))))
                (values :their-commitment n))
               (t (values :unknown n))))))))

;;; ----------------------------------------------------------------------------
;;; Finding outputs
;;; ----------------------------------------------------------------------------

(defun %find-output (tx script)
  (let ((idx (position script (btx:tx-outputs tx) :key #'btx:txout-script :test #'equalp)))
    (and idx (values idx (btx:txout-value (nth idx (btx:tx-outputs tx)))))))

(defun to-remote-output (lc their-tx)
  "Our money in THEIR commitment: P2WPKH under our payment basepoint (static
   remotekey — no per-commitment tweak, which is the point of the option: we
   can find and spend it without knowing which commitment this was)."
  (%find-output their-tx (m:to-remote-scriptpubkey (lv:pub (lv::live-payment-priv lc)))))

(defun to-local-output (lc tx &key theirs n)
  "The delayed output.  For OUR commitment: our delayed key, their revocation
   basepoint, the delay they demanded.  For THEIRS at commitment N: the mirror.
   Returns (values index value witness-script revocation-pubkey delayed-pubkey)."
  (multiple-value-bind (rev-base del-base delay point)
      (if theirs
          (values (lv:pub (lv::live-revocation-priv lc)) (lv::live-remote-delayed-basepoint lc)
                  (lv::live-remote-to-self-delay lc) (lv:remote-point-for lc n))
          (values (lv::live-remote-revocation-basepoint lc) (lv:pub (lv::live-delayed-priv lc))
                  (lv::live-local-to-self-delay lc) (lv:local-point lc (lv:live-local-commit-index lc))))
    (unless point (fail "no per-commitment point for commitment ~a" n))
    (let* ((rev (k:derive-revocation-pubkey rev-base point))
           (del (k:derive-pubkey del-base point))
           (script (m:to-local-script rev delay del)))
      (multiple-value-bind (idx value) (%find-output tx (m:p2wsh script))
        (values idx value script rev del delay)))))

;;; ----------------------------------------------------------------------------
;;; Building the answering transactions
;;; ----------------------------------------------------------------------------

(defun %sweep-tx (inputs outputs-script total fee)
  "A version-2 transaction spending INPUTS — each (txid vout sequence) — to one
   output.  Version 2 because CSV requires it; a version-1 sweep of a delayed
   output is simply invalid, and the error names nothing about versions."
  (when (<= total fee) (fail "sweep of ~d sat cannot pay a ~d sat fee" total fee))
  (btx:make-tx :version 2
               :inputs (mapcar (lambda (in)
                                 (destructuring-bind (txid vout sequence) in
                                   (btx:make-txin :prev-hash (c:octets txid) :prev-index vout
                                                  :script #() :sequence sequence)))
                               inputs)
               :outputs (list (btx:make-txout :value (- total fee) :script outputs-script))
               :witnesses (make-list (length inputs) :initial-element nil)
               :locktime 0 :segwit-p t))

(defun %with-witnesses (tx witnesses)
  "Attach witnesses and re-parse, so the result has a txid (see live.lisp)."
  (btx:parse-tx (bw:make-reader
                 (btx:serialize-tx
                  (btx:make-tx :version (btx:tx-version tx) :inputs (btx:tx-inputs tx) :outputs (btx:tx-outputs tx)
                               :locktime (btx:tx-locktime tx) :witnesses witnesses :segwit-p t)))))

(defun %sign (tx in-index script-code amount privkey)
  "A DER signature with SIGHASH_ALL over input IN-INDEX under BIP143."
  (let ((hash (bs:bip143-sighash tx in-index script-code amount bs:+sighash-all+)))
    (multiple-value-bind (r s) (secp:ecdsa-sign-raw privkey hash)
      (m:sig->der (c:bytes (secp:int-to-bytes32 r) (secp:int-to-bytes32 s))))))

(defun %p2wpkh-script-code (pubkey)
  "BIP143: a P2WPKH input's scriptCode is the classic P2PKH script."
  (c:bytes (vector #x76 #xa9 #x14) (bw:hash160 (c:octets pubkey)) (vector #x88 #xac)))

(defun sweep-to-remote (lc their-tx dest-script &key (fee-sat 500))
  "Claim our to_remote from THEIR commitment.  Spendable immediately: no delay
   binds it, because it is their commitment, and the delay is on THEIR side."
  (multiple-value-bind (idx value) (to-remote-output lc their-tx)
    (unless idx (fail "their commitment has no to_remote for us (below dust?)"))
    (let* ((tx (%sweep-tx (list (list (btx:tx-txid their-tx) idx #xffffffff)) dest-script value fee-sat))
           (pub (lv:pub (lv::live-payment-priv lc)))
           (sig (%sign tx 0 (%p2wpkh-script-code pub) value (lv::live-payment-priv lc))))
      (%with-witnesses tx (list (list sig (c:octets pub)))))))

(defun sweep-to-local (lc our-tx dest-script &key (fee-sat 500))
  "Claim our to_local from OUR commitment, after the CSV delay.  The input's
   nSequence carries the delay: that is how OP_CHECKSEQUENCEVERIFY learns the
   transaction is old enough, and a sweep with the wrong sequence is rejected
   by every node however long you wait."
  (multiple-value-bind (idx value script rev del delay) (to-local-output lc our-tx)
    (declare (ignore rev del))
    (unless idx (fail "our commitment has no to_local (below dust?)"))
    (let* ((tx (%sweep-tx (list (list (btx:tx-txid our-tx) idx delay)) dest-script value fee-sat))
           (point (lv:local-point lc (lv:live-local-commit-index lc)))
           (priv (k:derive-privkey (lv::live-delayed-priv lc) point))
           (sig (%sign tx 0 script value priv)))
      ;; <sig> <> <script>: the empty element takes the OP_ELSE branch.
      (%with-witnesses tx (list (list sig (c:bytes) script))))))

(defun penalty (lc their-revoked-tx n dest-script &key (fee-sat 500))
  "They published commitment N, which they revoked.  Take their to_local with
   the revocation key — and our own to_remote while we are at it, in one
   transaction.  The revocation private key exists only because they handed us
   the per-commitment secret; that handover is what made this state unsafe for
   them to publish."
  (let ((secret (or (lv:revoked-secret-for lc n) (fail "commitment ~d is not revoked" n))))
    (multiple-value-bind (lidx lvalue lscript) (to-local-output lc their-revoked-tx :theirs t :n n)
      (multiple-value-bind (ridx rvalue) (to-remote-output lc their-revoked-tx)
        (unless (or lidx ridx) (fail "nothing to claim in commitment ~d" n))
        (let* ((inputs (append (and lidx (list (list (btx:tx-txid their-revoked-tx) lidx #xffffffff)))
                               (and ridx (list (list (btx:tx-txid their-revoked-tx) ridx #xffffffff)))))
               (total (+ (or lvalue 0) (or rvalue 0)))
               (tx (%sweep-tx inputs dest-script total fee-sat))
               (rev-priv (k:derive-revocation-privkey (lv::live-revocation-priv lc) (secp:bytes-to-int secret)))
               (pay-pub (lv:pub (lv::live-payment-priv lc)))
               (witnesses '()) (i 0))
          (when lidx
            ;; <sig> 1 <script>: the OP_IF branch, guarded by the revocation key.
            (push (list (%sign tx i lscript lvalue rev-priv) (vector 1) lscript) witnesses)
            (incf i))
          (when ridx
            (push (list (%sign tx i (%p2wpkh-script-code pay-pub) rvalue (lv::live-payment-priv lc))
                        (c:octets pay-pub))
                  witnesses))
          (%with-witnesses tx (nreverse witnesses)))))))
