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
   #:to-remote-output #:to-local-output
   #:their-htlc-outputs #:claim-htlcs-from-their-commitment
   #:our-htlc-second-stage #:sweep-second-stage
   #:fee-for #:+vsize-p2wpkh-input+ #:+vsize-script-input+ #:+vsize-output+ #:+vsize-overhead+
   #:fund-second-stage #:anchor-output #:bump-with-anchor #:utxo #:make-utxo #:utxo-txid #:utxo-vout #:utxo-value #:utxo-privkey))

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
         (cond
           ;; An OLD commitment of ours — one we revoked.  Recognised by its
           ;; to_local being guarded by our delayed key at that number.  Nothing
           ;; good follows for us: the peer holds its revocation secret.
           ((and (<= n (lv:live-local-commit-index lc))
                 (ignore-errors (%own-to-local-at lc tx n)))
            (values :our-commitment n))
           ((lv:revoked-secret-for lc n) (values :revoked n))
               ((or (= n (lv:live-remote-commit-index lc))
                    (= n (1+ (lv:live-remote-commit-index lc))))
                (values :their-commitment n))
               (t (values :unknown n))))))))

;;; ----------------------------------------------------------------------------
;;; Fees
;;;
;;; Sweeps race a deadline, so their fee has to be one the network relays and
;;; mines promptly — and it has to be chosen BEFORE signing, because it changes
;;; the output value the signature covers.  So the fee comes from a vsize
;;; estimate by input kind rather than from measuring the signed transaction.
;;; The estimates are the standard ones and err a few bytes high; overpaying a
;;; few satoshi is nothing next to losing the race.
;;; ----------------------------------------------------------------------------

(defconstant +vsize-overhead+ 11 "version, counts, locktime, segwit marker.")
(defconstant +vsize-output+ 31 "one P2WPKH output.")
(defconstant +vsize-p2wpkh-input+ 68)
(defconstant +vsize-script-input+ 150
  "A P2WSH input with one signature and a to_local- or HTLC-sized script.")

(defun fee-for (feerate-per-kvb &key (p2wpkh-inputs 0) (script-inputs 0) (outputs 1))
  "Satoshis, for a transaction of that shape at FEERATE-PER-KVB."
  (let ((vsize (+ +vsize-overhead+ (* outputs +vsize-output+)
                  (* p2wpkh-inputs +vsize-p2wpkh-input+) (* script-inputs +vsize-script-input+))))
    (max 1 (ceiling (* vsize feerate-per-kvb) 1000))))

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
  (let ((pub (lv:pub (lv::live-payment-priv lc))))
    (%find-output their-tx (if (lv:live-anchors-p lc)
                               (m:p2wsh (m:to-remote-anchors-script pub))
                               (m:to-remote-scriptpubkey pub)))))

(defun %own-to-local-at (lc tx n)
  "Index of OUR to_local in TX if TX is our commitment number N."
  (let* ((point (lv:local-point lc n))
         (script (m:to-local-script (k:derive-revocation-pubkey (lv::live-remote-revocation-basepoint lc) point)
                                    (lv::live-local-to-self-delay lc)
                                    (k:derive-pubkey (lv:pub (lv::live-delayed-priv lc)) point))))
    (%find-output tx (m:p2wsh script))))

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
;;; HTLC outputs
;;;
;;; An HTLC output on a published commitment is money in dispute, and both
;;; sides have a claim on it with a deadline.  If the HTLC was ours to receive
;;; and we know the preimage, we take it — before the expiry lets the other
;;; side take it back.  If it was ours to pay and the expiry has passed, we
;;; take it back — before the other side produces a preimage.  Whoever moves
;;; first, with a valid claim, wins.  So these are built the moment they can
;;; be, and the watcher broadcasts them without waiting to be asked.
;;;
;;; On THEIR commitment the claims are direct.  On OURS they go through the
;;; second-stage HTLC-success / HTLC-timeout transactions the peer pre-signed
;;; — that is what the htlc_signatures in every commitment_signed were for —
;;; and the second stage pays to a delayed output we sweep like to_local.
;;; ----------------------------------------------------------------------------

(defun %htlc-keys (lc point ours)
  "Keys for HTLC scripts in a commitment at POINT.  OURS says whose commitment.
   Returns (values revocation-pubkey local-htlc-pubkey remote-htlc-pubkey our-htlc-priv)
   where local/remote are the commitment OWNER's view."
  (let* ((rev-base (if ours (lv::live-remote-revocation-basepoint lc) (lv:pub (lv::live-revocation-priv lc))))
         (own-base (if ours (lv:pub (lv::live-htlc-priv lc)) (lv::live-remote-htlc-basepoint lc)))
         (other-base (if ours (lv::live-remote-htlc-basepoint lc) (lv:pub (lv::live-htlc-priv lc)))))
    (values (k:derive-revocation-pubkey rev-base point)
            (k:derive-pubkey own-base point)
            (k:derive-pubkey other-base point)
            (k:derive-privkey (lv::live-htlc-priv lc) point))))

(defun their-htlc-outputs (lc tx n)
  "Every HTLC output in THEIR commitment N that we can locate: a list of
   (index value script rec) with REC in OUR view (:offered = we pay)."
  (let ((point (lv:remote-point-for lc n))
        (htlcs (lv:remote-htlcs-at lc n)))
    (when (and point htlcs)
      (multiple-value-bind (rev their-htlc our-htlc) (%htlc-keys lc point nil)
        (let ((found '()) (used '()))
          ;; Match each HTLC to an output by its exact script AND value, never
          ;; reusing one.  No ordering is re-derived: a comparator that differs
          ;; from the commitment's (value, script, cltv) silently dropped outputs.
          (dolist (rec htlcs)
            (let* ((script (ecase (lv:hr-direction rec)
                             ;; We pay: in THEIR commitment that is one they RECEIVE.
                             (:offered (m:received-htlc-script rev our-htlc their-htlc
                                                               (lv:hr-payment-hash rec) (lv:hr-cltv-expiry rec)
                                                               :anchors (lv:live-anchors-p lc)))
                             (:received (m:offered-htlc-script rev our-htlc their-htlc (lv:hr-payment-hash rec)
                                                               :anchors (lv:live-anchors-p lc)))))
                   (spk (m:p2wsh script))
                   (sat (floor (lv:hr-amount-msat rec) 1000))
                   (idx (loop for o in (btx:tx-outputs tx) for i from 0
                              when (and (not (member i used))
                                        (= (btx:txout-value o) sat)
                                        (equalp (btx:txout-script o) spk))
                                return i)))
              (when idx
                (push idx used)
                (push (list idx (btx:txout-value (nth idx (btx:tx-outputs tx))) script rec) found))))
          (sort found #'< :key #'first))))))

(defun claim-htlcs-from-their-commitment (lc tx n dest-script preimages &key height feerate (fee-sat (if feerate (fee-for feerate :script-inputs 1) 500)))
  "Direct claims on THEIR commitment's HTLC outputs.  PREIMAGES is a list of
   32-byte preimages we know.  Returns the transactions we can make right now:
   a preimage claim for each HTLC they offered us that we can settle, and a
   timeout claim for each we offered them whose expiry HEIGHT has passed."
  (let ((point (lv:remote-point-for lc n)) (out '()))
    (when point
      (multiple-value-bind (rev their-htlc our-htlc our-priv) (%htlc-keys lc point nil)
        (declare (ignore rev their-htlc our-htlc))
        (dolist (o (their-htlc-outputs lc tx n))
          (destructuring-bind (idx value script rec) o
            (ecase (lv:hr-direction rec)
              (:received
               (let ((pre (find (lv:hr-payment-hash rec) preimages
                                :key (lambda (p) (c:sha256 p)) :test #'equalp)))
                 (when pre
                   ;; <sig> <preimage>: size 32 takes the hash branch, CHECKSIG
                   ;; against remote_htlcpubkey — which, in their commitment, is us.
                   (let* ((tx2 (%sweep-tx (list (list (btx:tx-txid tx) idx (if (lv:live-anchors-p lc) 1 #xffffffff)))
                                          dest-script value fee-sat))
                          (sig (%sign tx2 0 script value our-priv)))
                     (push (%with-witnesses tx2 (list (list sig (c:octets pre) script))) out)))))
              (:offered
               (when (and height (>= height (lv:hr-cltv-expiry rec)))
                 ;; <sig> <>: an empty element is not 32 bytes, so the OP_ELSE
                 ;; branch: CLTV against the expiry, then CHECKSIG against us.
                 (let* ((tx2 (%sweep-tx (list (list (btx:tx-txid tx) idx (if (lv:live-anchors-p lc) 1 #xfffffffe)))
                                        dest-script value fee-sat))
                        (tx2 (btx:parse-tx (bw:make-reader (btx:serialize-tx
                                            (btx:make-tx :version 2 :inputs (btx:tx-inputs tx2) :outputs (btx:tx-outputs tx2)
                                                         :witnesses (list nil) :locktime (lv:hr-cltv-expiry rec) :segwit-p t)))))
                        (sig (%sign tx2 0 script value our-priv)))
                   (push (%with-witnesses tx2 (list (list sig (c:bytes) script))) out)))))))))
    (nreverse out)))

(defun our-htlc-second-stage (lc dest-script preimages &key height (fee-sat 500))
  "The pre-signed second-stage transactions on OUR published commitment:
   HTLC-success for each received HTLC whose preimage we hold, HTLC-timeout for
   each offered HTLC past its expiry.  Each spends one HTLC output to a delayed
   output; SWEEP-SECOND-STAGE takes it from there.  DEST-SCRIPT is unused here
   — the second stage's destination is fixed by the protocol — but kept for
   symmetry with the direct claims."
  (declare (ignore dest-script fee-sat))
  (let* ((built (lv:built-local lc))
         (point (lv:local-point lc (lv:live-local-commit-index lc)))
         (their-sigs (lv:live-local-commit-htlc-sigs lc))
         (out '()))
    (multiple-value-bind (rev our-htlc their-htlc our-priv) (%htlc-keys lc point t)
      (declare (ignore rev our-htlc their-htlc))
      (loop for (idx rec script) in (lv:b-htlc-outputs built)
            for their-sig in their-sigs
            do (let* ((amount (floor (lv:hr-amount-msat rec) 1000))
                      (htx (lv::%htlc-tx built t idx rec))
                      (our-sig (m:sign-htlc-tx htx our-priv script amount))
                      ;; Theirs is SINGLE|ANYONECANPAY on anchor channels; ours is ALL.
                      (der-theirs (m:sig->der their-sig (lv:peer-htlc-sighash lc)))
                      (der-ours (m:sig->der our-sig)))
                 (ecase (lv:hr-direction rec)
                   (:received
                    (let ((pre (find (lv:hr-payment-hash rec) preimages :key (lambda (p) (c:sha256 p)) :test #'equalp)))
                      (when pre
                        ;; 0 <remotehtlcsig> <localhtlcsig> <preimage> <script>
                        (push (list :success rec
                                    (%with-witnesses htx (list (list (c:bytes) der-theirs der-ours (c:octets pre) script))))
                              out))))
                   (:offered
                    (when (and height (>= height (lv:hr-cltv-expiry rec)))
                      ;; 0 <remotehtlcsig> <localhtlcsig> <> <script>, locktime = expiry
                      (push (list :timeout rec
                                  (%with-witnesses htx (list (list (c:bytes) der-theirs der-ours (c:bytes) script))))
                            out)))))))
    (nreverse out)))

(defun sweep-second-stage (lc htlc-tx dest-script &key feerate (fee-sat (if feerate (fee-for feerate :script-inputs 1) 500)))
  "Claim the delayed output of one of OUR second-stage HTLC transactions, after
   the CSV delay — the same shape as to_local, with the same keys."
  (let* ((point (lv:local-point lc (lv:live-local-commit-index lc)))
         (rev (k:derive-revocation-pubkey (lv::live-remote-revocation-basepoint lc) point))
         (del (k:derive-pubkey (lv:pub (lv::live-delayed-priv lc)) point))
         (delay (lv::live-local-to-self-delay lc))
         (script (m:htlc-tx-script rev delay del))
         (value (btx:txout-value (first (btx:tx-outputs htlc-tx)))))
    (unless (equalp (btx:txout-script (first (btx:tx-outputs htlc-tx))) (m:p2wsh script))
      (fail "not one of our second-stage HTLC transactions"))
    (let* ((tx (%sweep-tx (list (list (btx:tx-txid htlc-tx) 0 delay)) dest-script value fee-sat))
           (priv (k:derive-privkey (lv::live-delayed-priv lc) point))
           (sig (%sign tx 0 script value priv)))
      (%with-witnesses tx (list (list sig (c:bytes) script))))))


;;; ----------------------------------------------------------------------------
;;; Inputs of our own
;;;
;;; Anchor channels move the fee OFF the commitment: second-stage HTLC
;;; transactions pay nothing and a commitment may be mined at whatever rate
;;; it was built at long ago.  Both are fixed the same way — by attaching an
;;; input we control.  The peer's HTLC signature is SINGLE|ANYONECANPAY, so
;;; adding an input and a change output leaves it valid; ours is ALL and is
;;; simply made last.  A UTXO here is one of our own sweep outputs, or a
;;; deposit: a P2WPKH we hold the key for.
;;; ----------------------------------------------------------------------------

(defstruct utxo txid vout value privkey)

(defun %utxo-pub (u) (c:compressed-pubkey (c:pubkey-of (utxo-privkey u))))

(defun fund-second-stage (lc htx their-der-sig script htlc-amount-sat preimage-or-nil utxo feerate)
  "Attach UTXO to a zero-fee second-stage transaction HTX (input 0 already the
   HTLC output, output 0 already the delayed output) and sign both inputs.
   PREIMAGE-OR-NIL selects HTLC-success (preimage) or HTLC-timeout (empty)."
  (let* ((fee (fee-for feerate :script-inputs 1 :p2wpkh-inputs 1 :outputs 2))
         (change (- (utxo-value utxo) fee)))
    (when (< change 330) (fail "utxo of ~d sat cannot pay a ~d sat fee" (utxo-value utxo) fee))
    (let* ((point (lv:local-point lc (lv:live-local-commit-index lc)))
           (our-priv (k:derive-privkey (lv::live-htlc-priv lc) point))
           (tx (btx:parse-tx
                (bw:make-reader
                 (btx:serialize-tx
                  (btx:make-tx :version 2
                               :inputs (list (first (btx:tx-inputs htx))
                                             (btx:make-txin :prev-hash (c:octets (utxo-txid utxo)) :prev-index (utxo-vout utxo)
                                                            :script #() :sequence #xffffffff))
                               :outputs (list (first (btx:tx-outputs htx))
                                              (btx:make-txout :value change :script (m:p2wpkh (%utxo-pub utxo))))
                               :witnesses (list nil nil) :locktime (btx:tx-locktime htx) :segwit-p t)))))
           ;; Ours is SIGHASH_ALL over the FUNDED transaction.  Theirs covered
           ;; only input 0 and output 0, and both are unchanged.
           (our-sig (m:sign-htlc-tx tx our-priv script htlc-amount-sat))
           (fee-sig (%sign tx 1 (%p2wpkh-script-code (%utxo-pub utxo)) (utxo-value utxo) (utxo-privkey utxo))))
      (%with-witnesses tx (list (list (c:bytes) their-der-sig (m:sig->der our-sig)
                                      (if preimage-or-nil (c:octets preimage-or-nil) (c:bytes)) script)
                                (list fee-sig (c:octets (%utxo-pub utxo))))))))

(defun anchor-output (lc commitment-tx)
  "Our anchor in a published commitment — ours or theirs, it locks to OUR
   funding key either way.  Returns (values index script) or NIL."
  (let ((script (m:anchor-script (lv:pub (lv::live-funding-priv lc)))))
    (let ((idx (%find-output commitment-tx (m:p2wsh script))))
      (and idx (values idx script)))))

(defun bump-with-anchor (lc commitment-tx utxo feerate)
  "Child-pays-for-parent: spend our anchor and UTXO together, paying enough
   that parent and child reach FEERATE.  The commitment's own fee was fixed
   when it was signed; this is the only way to raise it afterwards."
  (multiple-value-bind (idx script) (anchor-output lc commitment-tx)
    (unless idx (fail "no anchor of ours in that commitment"))
    (let* ((parent-vsize (btx:tx-vsize commitment-tx))
           (child-vsize (+ +vsize-overhead+ +vsize-script-input+ +vsize-p2wpkh-input+ +vsize-output+))
           (fee (ceiling (* (+ parent-vsize child-vsize) feerate) 1000))
           (total (+ m:+anchor-sat+ (utxo-value utxo)))
           (change (- total fee)))
      (when (< change 330) (fail "utxo of ~d sat cannot bump a ~d vB commitment at ~d" (utxo-value utxo) parent-vsize feerate))
      (let* ((tx (btx:parse-tx
                  (bw:make-reader
                   (btx:serialize-tx
                    (btx:make-tx :version 2
                                 :inputs (list (btx:make-txin :prev-hash (c:octets (btx:tx-txid commitment-tx)) :prev-index idx
                                                              :script #() :sequence #xffffffff)
                                               (btx:make-txin :prev-hash (c:octets (utxo-txid utxo)) :prev-index (utxo-vout utxo)
                                                              :script #() :sequence #xffffffff))
                                 :outputs (list (btx:make-txout :value change :script (m:p2wpkh (%utxo-pub utxo))))
                                 :witnesses (list nil nil) :locktime 0 :segwit-p t)))))
             (anchor-sig (%sign tx 0 script m:+anchor-sat+ (lv::live-funding-priv lc)))
             (fee-sig (%sign tx 1 (%p2wpkh-script-code (%utxo-pub utxo)) (utxo-value utxo) (utxo-privkey utxo))))
        (%with-witnesses tx (list (list anchor-sig script)
                                  (list fee-sig (c:octets (%utxo-pub utxo)))))))))

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

(defun sweep-to-remote (lc their-tx dest-script &key feerate (fee-sat (if feerate (fee-for feerate :p2wpkh-inputs 1) 500)))
  "Claim our to_remote from THEIR commitment.  Spendable immediately: no delay
   binds it, because it is their commitment, and the delay is on THEIR side."
  (multiple-value-bind (idx value) (to-remote-output lc their-tx)
    (unless idx (fail "their commitment has no to_remote for us (below dust?)"))
    (let ((pub (lv:pub (lv::live-payment-priv lc))))
      (if (lv:live-anchors-p lc)
          ;; Anchors: a P2WSH behind one block of CSV.  Sequence 1, witness <sig>.
          (let* ((script (m:to-remote-anchors-script pub))
                 (tx (%sweep-tx (list (list (btx:tx-txid their-tx) idx 1)) dest-script value fee-sat))
                 (sig (%sign tx 0 script value (lv::live-payment-priv lc))))
            (%with-witnesses tx (list (list sig script))))
          (let* ((tx (%sweep-tx (list (list (btx:tx-txid their-tx) idx +rbf-sequence+)) dest-script value fee-sat))
                 (sig (%sign tx 0 (%p2wpkh-script-code pub) value (lv::live-payment-priv lc))))
            (%with-witnesses tx (list (list sig (c:octets pub)))))))))

(defun sweep-to-local (lc our-tx dest-script &key feerate (fee-sat (if feerate (fee-for feerate :script-inputs 1) 500)))
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

(defconstant +rbf-sequence+ #xfffffffd
  "BIP125 opt-in: a penalty or sweep that sits unconfirmed must be replaceable
   at a higher fee.  #xffffffff is final and could never be bumped.")

(defun penalty (lc their-revoked-tx n dest-script &key feerate (fee-sat nil) only)
  "They published commitment N, which they revoked.  Take their to_local with
   the revocation key — and our own to_remote while we are at it, in one
   transaction.  The revocation private key exists only because they handed us
   the per-commitment secret; that handover is what made this state unsafe for
   them to publish."
  (let ((secret (or (lv:revoked-secret-for lc n) (fail "commitment ~d is not revoked" n))))
    (multiple-value-bind (lidx lvalue lscript) (to-local-output lc their-revoked-tx :theirs t :n n)
      (multiple-value-bind (ridx rvalue) (to-remote-output lc their-revoked-tx)
        ;; ONLY, when given, is the list of output indices still unspent: an
        ;; output the cheater already took cannot be in the transaction, and
        ;; insisting on it would make the whole penalty invalid.
        (when only
          (unless (member lidx only) (setf lidx nil lvalue nil))
          (unless (member ridx only) (setf ridx nil rvalue nil)))
        (let* ((htlcs (remove-if (lambda (h) (and only (not (member (first h) only))))
                                 (their-htlc-outputs lc their-revoked-tx n)))
               (rev-pub (k:derive-revocation-pubkey (lv:pub (lv::live-revocation-priv lc)) (lv:remote-point-for lc n)))
               (inputs (append (and lidx (list (list (btx:tx-txid their-revoked-tx) lidx +rbf-sequence+)))
                               (and ridx (list (list (btx:tx-txid their-revoked-tx) ridx (if (lv:live-anchors-p lc) 1 +rbf-sequence+))))
                               (loop for (idx) in htlcs collect (list (btx:tx-txid their-revoked-tx) idx +rbf-sequence+))))
               (total (+ (or lvalue 0) (or rvalue 0) (reduce #'+ htlcs :key #'second)))
               (rev-priv (k:derive-revocation-privkey (lv::live-revocation-priv lc) (secp:bytes-to-int secret)))
               (pay-pub (lv:pub (lv::live-payment-priv lc)))
               (witnesses '()) (i 0))
          (unless inputs (fail "nothing to claim in commitment ~d" n))
          (let ((tx (%sweep-tx inputs dest-script total
                               (or fee-sat
                                   (if feerate
                                       (fee-for feerate :p2wpkh-inputs (if ridx 1 0)
                                                        :script-inputs (+ (if lidx 1 0) (length htlcs)))
                                       500)))))
            (when lidx
              ;; <sig> 1 <script>: the OP_IF branch, guarded by the revocation key.
              (push (list (%sign tx i lscript lvalue rev-priv) (vector 1) lscript) witnesses)
              (incf i))
            (when ridx
              (if (lv:live-anchors-p lc)
                  (let ((script (m:to-remote-anchors-script pay-pub)))
                    (push (list (%sign tx i script rvalue (lv::live-payment-priv lc)) script) witnesses))
                  (push (list (%sign tx i (%p2wpkh-script-code pay-pub) rvalue (lv::live-payment-priv lc))
                              (c:octets pay-pub))
                        witnesses))
              (incf i))
            ;; Every HTLC output, whichever way it pointed: <sig> <revocationpubkey>
            ;; takes the OP_DUP OP_HASH160 branch at the top of both scripts.
            (loop for (idx value script) in htlcs
                  do (push (list (%sign tx i script value rev-priv) (c:octets rev-pub) script) witnesses)
                     (incf i))
            (%with-witnesses tx (nreverse witnesses))))))))
