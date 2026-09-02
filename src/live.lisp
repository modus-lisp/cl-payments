;;;; src/live.lisp
;;;;
;;;; Phase 4d — a LIVE channel: the commitment cycle over a real connection.
;;;;
;;;; updates.lisp has the messages and a state machine tested in isolation.  What
;;;; it never had to face is the thing that makes the cycle hard: the two ends
;;;; do not share a view of the channel.  Each holds its OWN commitment, signed
;;;; by the other, and an update sent by one side is in the other's commitment
;;;; before it is in the sender's.  For the whole interval between
;;;; `commitment_signed` and the matching `revoke_and_ack`, the two commitments
;;;; legitimately disagree about what is in the channel.
;;;;
;;;; The bookkeeping that makes this tractable is the standard one: every update
;;;; is a CHANGE, and each side's changes move through stages —
;;;;
;;;;   changes we sent:      proposed -> signed -> acked
;;;;   changes we received:  proposed -> acked  -> signed
;;;;
;;;; and each commitment is built by reducing a base spec with exactly the
;;;; changes that belong in it:
;;;;
;;;;   their next commitment = their current spec
;;;;                           + our PROPOSED changes + their ACKED changes
;;;;   our next commitment   = our current spec
;;;;                           + their PROPOSED changes + our ACKED changes
;;;;
;;;; Sending `commitment_signed` moves our proposed -> signed and their
;;;; acked -> signed.  Receiving `commitment_signed` moves their proposed -> acked
;;;; and clears our acked.  Receiving `revoke_and_ack` moves our signed -> acked
;;;; and clears their signed.  Get this wrong and the two sides sign different
;;;; transactions while each believes the other's signature is over its own —
;;;; which fails as "invalid signature" with nothing pointing at the real cause.
;;;;
;;;; Everything here is a state transition that RETURNS the messages to send.
;;;; Nothing does I/O, so two channels can be run against each other in a test,
;;;; and the daemon's only job is to move bytes.

(defpackage #:cl-payments.live
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:k #:cl-payments.keys) (#:m #:cl-payments.commitment)
                    (#:u #:cl-payments.updates) (#:ch #:cl-payments.channel)
                    (#:btx #:cl-consensus.tx) (#:bw #:cl-consensus.wire)
                    (#:bs #:cl-consensus.script) (#:secp #:secp256k1-fast))
  (:nicknames #:ln-live)
  (:export
   #:live #:make-live #:live-error
   #:live-channel-id #:live-local-balance-msat #:live-remote-balance-msat
   #:live-local-commit-index #:live-remote-commit-index #:live-htlcs
   #:live-awaiting-revocation-p #:live-feerate-per-kw #:live-capacity-sat
   #:live-remote-shutdown-script #:live-local-shutdown-script #:live-closed-p
   #:live-closing-txid #:live-pending-changes-p
   #:htlc-rec #:hr-id #:hr-direction #:hr-amount-msat #:hr-payment-hash
   #:hr-cltv-expiry #:hr-resolution #:hr-preimage #:hr-onion
   #:local-spec #:remote-spec #:spec-to-local-msat #:spec-to-remote-msat #:spec-htlcs
   ;; transitions — each returns the message(s) to send, or NIL
   #:set-remote-next-point #:set-remote-current-point
   #:send-add #:receive-add
   #:send-fulfill #:receive-fulfill #:send-fail #:receive-fail #:receive-fee
   #:send-commit #:receive-commit #:receive-revocation
   #:fully-committed-received-htlcs #:can-send-commit-p
   #:reestablish-message
   ;; closing
   #:send-shutdown #:receive-shutdown #:receive-closing-signed #:propose-close
   #:build-closing-tx
   ;; persistence
   #:live->plist #:plist->live))

(in-package #:cl-payments.live)

(define-condition live-error (error)
  ((detail :initarg :detail :reader live-error-detail))
  (:report (lambda (c s) (format s "live channel: ~a" (live-error-detail c)))))

(defun fail (fmt &rest args)
  (error 'live-error :detail (apply #'format nil fmt args)))

;;; ----------------------------------------------------------------------------
;;; The channel
;;; ----------------------------------------------------------------------------

(defstruct (htlc-rec (:conc-name hr-))
  id
  direction           ; :offered (we pay) or :received (we are paid) — OUR view
  amount-msat payment-hash cltv-expiry onion
  (resolution nil)    ; nil, :fulfilled or :failed once removed
  preimage)

(defstruct (spec (:constructor %make-spec))
  "One commitment's contents, from OUR point of view: to-local is ours."
  to-local-msat to-remote-msat feerate-per-kw
  (htlcs '()))

(defun copy-spec* (s)
  (%make-spec :to-local-msat (spec-to-local-msat s)
              :to-remote-msat (spec-to-remote-msat s)
              :feerate-per-kw (spec-feerate-per-kw s)
              :htlcs (copy-list (spec-htlcs s))))

(defstruct (live (:constructor %make-live))
  ;; --- fixed parameters -----------------------------------------------------
  channel-id funding-txid funding-index capacity-sat
  opener                              ; :local or :remote — who pays the fee
  ;; our secrets: funding scalar, the four basepoint scalars, and the shachain seed
  funding-priv revocation-priv payment-priv delayed-priv htlc-priv seed
  ;; their public parameters
  remote-funding-pubkey remote-revocation-basepoint remote-payment-basepoint
  remote-delayed-basepoint remote-htlc-basepoint
  local-dust-limit remote-dust-limit
  ;; to_self_delay is set by the OTHER side: the delay in our commitment is the
  ;; one they demanded, and vice versa.
  local-to-self-delay                 ; the CSV on OUR to_local (they chose it)
  remote-to-self-delay                ; the CSV on THEIR to_local (we chose it)
  ;; --- commitment state -----------------------------------------------------
  (local-commit-index 0)              ; number of the commitment they last signed for us
  (remote-commit-index 0)             ; number of the commitment we last signed for them
  local-spec remote-spec              ; contents of those two commitments
  remote-current-point                ; their per-commitment point for remote-commit-index
  remote-next-point                   ; ... and for remote-commit-index + 1
  ;; While we wait for revoke_and_ack, the commitment we just signed for them:
  (remote-next-commit nil)            ; (index . spec) or NIL
  ;; --- changes in flight ----------------------------------------------------
  (local-proposed '()) (local-signed '()) (local-acked '())
  (remote-proposed '()) (remote-acked '()) (remote-signed '())
  (next-htlc-id 0)
  (revocations (k:make-shachain))
  last-remote-secret                  ; for channel_reestablish
  ;; --- closing --------------------------------------------------------------
  local-shutdown-script remote-shutdown-script
  (closed-p nil) closing-txid)

(defun make-live (&key channel-id funding-txid funding-index capacity-sat opener
                       funding-priv revocation-priv payment-priv delayed-priv htlc-priv seed
                       remote-funding-pubkey remote-revocation-basepoint
                       remote-payment-basepoint remote-delayed-basepoint
                       remote-htlc-basepoint
                       local-dust-limit remote-dust-limit
                       local-to-self-delay remote-to-self-delay
                       feerate-per-kw local-msat remote-msat
                       remote-first-point)
  "A channel at commitment 0, as it stands the moment the funding is signed."
  (%make-live :channel-id channel-id :funding-txid funding-txid
              :funding-index funding-index :capacity-sat capacity-sat :opener opener
              :funding-priv funding-priv :revocation-priv revocation-priv
              :payment-priv payment-priv :delayed-priv delayed-priv
              :htlc-priv htlc-priv :seed seed
              :remote-funding-pubkey remote-funding-pubkey
              :remote-revocation-basepoint remote-revocation-basepoint
              :remote-payment-basepoint remote-payment-basepoint
              :remote-delayed-basepoint remote-delayed-basepoint
              :remote-htlc-basepoint remote-htlc-basepoint
              :local-dust-limit local-dust-limit :remote-dust-limit remote-dust-limit
              :local-to-self-delay local-to-self-delay
              :remote-to-self-delay remote-to-self-delay
              :local-spec (%make-spec :to-local-msat local-msat :to-remote-msat remote-msat
                                      :feerate-per-kw feerate-per-kw)
              :remote-spec (%make-spec :to-local-msat local-msat :to-remote-msat remote-msat
                                       :feerate-per-kw feerate-per-kw)
              :remote-current-point remote-first-point))

(defun pub (scalar) (c:compressed-pubkey (c:pubkey-of scalar)))
(defun local-point (lc n) (k:per-commitment-point (live-seed lc) (- k:+max-commitment-index+ n)))
(defun local-secret (lc n) (k:per-commitment-secret (live-seed lc) (- k:+max-commitment-index+ n)))

(defun live-local-balance-msat (lc) (spec-to-local-msat (live-local-spec lc)))
(defun live-remote-balance-msat (lc) (spec-to-remote-msat (live-local-spec lc)))
(defun live-feerate-per-kw (lc) (spec-feerate-per-kw (live-local-spec lc)))
(defun live-awaiting-revocation-p (lc) (not (null (live-remote-next-commit lc))))
(defun live-htlcs (lc) (spec-htlcs (live-local-spec lc)))
(defun local-spec (lc) (live-local-spec lc))
(defun remote-spec (lc) (live-remote-spec lc))
(defun live-pending-changes-p (lc)
  (or (live-local-proposed lc) (live-remote-acked lc)))

(defun set-remote-next-point (lc point)
  "From channel_ready's second_per_commitment_point."
  (setf (live-remote-next-point lc) point))
(defun set-remote-current-point (lc point) (setf (live-remote-current-point lc) point))

;;; ----------------------------------------------------------------------------
;;; Changes and their reduction
;;;
;;; A change is one of
;;;   (:add <htlc-rec>)
;;;   (:fulfill <id> <preimage>)      (:fail <id>)      (:fee <feerate>)
;;; and the direction of an :add is from OUR point of view regardless of who
;;; sent it — a received update_add_htlc is an :add of a :received HTLC.
;;; ----------------------------------------------------------------------------

(defun reduce-spec (base changes)
  "Apply CHANGES to a copy of BASE.  Money moves here and nowhere else."
  (let ((s (copy-spec* base)))
    (dolist (ch changes s)
      (ecase (first ch)
        (:add
         (let ((h (second ch)))
           (ecase (hr-direction h)
             ;; An offered HTLC leaves OUR balance the moment it is proposed.
             ;; It is in flight — neither side's — until it resolves.
             (:offered  (decf (spec-to-local-msat s) (hr-amount-msat h)))
             (:received (decf (spec-to-remote-msat s) (hr-amount-msat h))))
           (when (or (minusp (spec-to-local-msat s)) (minusp (spec-to-remote-msat s)))
             (fail "HTLC ~d for ~d msat overdraws the channel" (hr-id h) (hr-amount-msat h)))
           (push h (spec-htlcs s))))
        ((:fulfill :fail)
         (let* ((id (second ch))
                (h (find id (spec-htlcs s) :key #'hr-id)))
           (unless h (fail "~(~a~) of unknown HTLC ~d" (first ch) id))
           (setf (spec-htlcs s) (remove h (spec-htlcs s)))
           ;; Fulfilled: the money lands with whoever was being paid.
           ;; Failed: it goes back where it came from.
           (ecase (hr-direction h)
             (:offered  (if (eq (first ch) :fulfill)
                            (incf (spec-to-remote-msat s) (hr-amount-msat h))
                            (incf (spec-to-local-msat s) (hr-amount-msat h))))
             (:received (if (eq (first ch) :fulfill)
                            (incf (spec-to-local-msat s) (hr-amount-msat h))
                            (incf (spec-to-remote-msat s) (hr-amount-msat h)))))))
        (:fee (setf (spec-feerate-per-kw s) (second ch)))))))

(defun flip-direction (d) (ecase d (:offered :received) (:received :offered)))

;;; ----------------------------------------------------------------------------
;;; Building the two commitments
;;;
;;; The same spec, seen from two sides.  OUR commitment has our balance behind
;;; a delay and their revocation key; THEIR commitment is the mirror.  Every key
;;; below is derived from the per-commitment point of the commitment's OWNER.
;;; ----------------------------------------------------------------------------

(defstruct (built (:conc-name b-))
  tx htlc-outputs   ; htlc-outputs: list of (index htlc-rec witness-script), output order
  revocation-pubkey delayed-pubkey to-self-delay feerate)

(defun %build (lc spec &key ours point)
  "Build the commitment described by SPEC.  OURS says whose commitment it is."
  (let* ((rev-base   (if ours (live-remote-revocation-basepoint lc) (pub (live-revocation-priv lc))))
         (del-base   (if ours (pub (live-delayed-priv lc)) (live-remote-delayed-basepoint lc)))
         (own-htlc-base   (if ours (pub (live-htlc-priv lc)) (live-remote-htlc-basepoint lc)))
         (other-htlc-base (if ours (live-remote-htlc-basepoint lc) (pub (live-htlc-priv lc))))
         (remote-pay (if ours (live-remote-payment-basepoint lc) (pub (live-payment-priv lc))))
         (revocation-pubkey (k:derive-revocation-pubkey rev-base point))
         (delayed-pubkey (k:derive-pubkey del-base point))
         (local-htlc-pubkey (k:derive-pubkey own-htlc-base point))
         (remote-htlc-pubkey (k:derive-pubkey other-htlc-base point))
         (to-self-delay (if ours (live-local-to-self-delay lc) (live-remote-to-self-delay lc)))
         (dust (if ours (live-local-dust-limit lc) (live-remote-dust-limit lc)))
         (opener (if ours (live-opener lc) (ecase (live-opener lc) (:local :remote) (:remote :local))))
         (htlcs (mapcar (lambda (h)
                          (m:make-htlc :direction (if ours (hr-direction h) (flip-direction (hr-direction h)))
                                       :amount-msat (hr-amount-msat h)
                                       :expiry (hr-cltv-expiry h)
                                       :payment-hash (hr-payment-hash h)))
                        (spec-htlcs spec)))
         (n (if ours (1+ (live-local-commit-index lc)) (1+ (live-remote-commit-index lc)))))
    (declare (ignorable n))
    (multiple-value-bind (tx desc order)
        (m:build-commitment
         :funding-txid (live-funding-txid lc) :funding-output-index (live-funding-index lc)
         :funding-amount-sat (live-capacity-sat lc)
         :commitment-number (if ours (1+ (live-local-commit-index lc)) (1+ (live-remote-commit-index lc)))
         :obscuring (m:obscuring-factor
                     (if (eq (live-opener lc) :local) (pub (live-payment-priv lc)) (live-remote-payment-basepoint lc))
                     (if (eq (live-opener lc) :local) (live-remote-payment-basepoint lc) (pub (live-payment-priv lc))))
         :to-local-msat (if ours (spec-to-local-msat spec) (spec-to-remote-msat spec))
         :to-remote-msat (if ours (spec-to-remote-msat spec) (spec-to-local-msat spec))
         :local-feerate-per-kw (spec-feerate-per-kw spec)
         :dust-limit-sat dust
         :revocation-pubkey revocation-pubkey :to-self-delay to-self-delay
         :delayed-pubkey delayed-pubkey :remote-pubkey remote-pay
         :opener opener
         :htlcs htlcs :local-htlc-pubkey local-htlc-pubkey :remote-htlc-pubkey remote-htlc-pubkey)
      (declare (ignore desc))
      ;; Locate each surviving HTLC's output, in output order.  ORDER holds the
      ;; m:htlc structs in that order; recompute the witness script and find the
      ;; matching P2WSH output, scanning forward so duplicates resolve in order.
      (let ((outputs (btx:tx-outputs tx)) (start 0) (found '()))
        (dolist (mh order)
          (let* ((script (ecase (m:htlc-direction mh)
                           (:offered (m:offered-htlc-script revocation-pubkey remote-htlc-pubkey
                                                            local-htlc-pubkey (m:htlc-payment-hash mh)))
                           (:received (m:received-htlc-script revocation-pubkey remote-htlc-pubkey
                                                              local-htlc-pubkey (m:htlc-payment-hash mh)
                                                              (m:htlc-expiry mh)))))
                 (spk (m:p2wsh script))
                 (idx (position spk outputs :start start :key #'btx:txout-script :test #'equalp))
                 (rec (find-if (lambda (h) (and (equalp (hr-payment-hash h) (m:htlc-payment-hash mh))
                                                (= (hr-cltv-expiry h) (m:htlc-expiry mh))
                                                (= (hr-amount-msat h) (m:htlc-amount-msat mh))
                                                (not (member h found :key #'second))))
                               (spec-htlcs spec))))
            (unless idx (fail "could not locate HTLC output in the commitment"))
            (setf start (1+ idx))
            (push (list idx rec script) found)))
        (make-built :tx tx :htlc-outputs (nreverse found)
                    :revocation-pubkey revocation-pubkey :delayed-pubkey delayed-pubkey
                    :to-self-delay to-self-delay :feerate (spec-feerate-per-kw spec))))))

(defun %htlc-tx (built ours idx rec)
  "The second-stage transaction for the HTLC at output IDX.  Direction is from
   the commitment OWNER's view: in their commitment our received HTLC is one they
   offered, and its second stage is HTLC-timeout, not HTLC-success."
  (m:build-htlc-tx :commitment-txid (btx:tx-txid (b-tx built)) :output-index idx
                   :htlc-amount-msat (hr-amount-msat rec)
                   :direction (if ours (hr-direction rec) (flip-direction (hr-direction rec)))
                   :cltv-expiry (hr-cltv-expiry rec) :feerate-per-kw (b-feerate built)
                   :revocation-pubkey (b-revocation-pubkey built)
                   :to-self-delay (b-to-self-delay built)
                   :delayed-pubkey (b-delayed-pubkey built)))

(defun %verify64 (sig hash pubkey)
  (handler-case
      (and (secp:ecdsa-verify (c:parse-pubkey pubkey) (c:octets hash)
                              (secp:bytes-to-int (subseq sig 0 32))
                              (secp:bytes-to-int (subseq sig 32 64)))
           t)
    (error () nil)))

;;; ----------------------------------------------------------------------------
;;; Updates
;;; ----------------------------------------------------------------------------

(defun send-add (lc amount-msat payment-hash cltv-expiry onion)
  "Offer an HTLC.  Returns the update_add_htlc message."
  (let* ((id (live-next-htlc-id lc))
         (h (make-htlc-rec :id id :direction :offered :amount-msat amount-msat
                           :payment-hash payment-hash :cltv-expiry cltv-expiry :onion onion)))
    ;; Check against what THEIR commitment will hold, since that is the one
    ;; this change lands in first.
    (reduce-spec (live-remote-spec lc)
                 (append (live-remote-acked lc) (live-local-proposed lc) (list (list :add h))))
    (incf (live-next-htlc-id lc))
    (setf (live-local-proposed lc) (append (live-local-proposed lc) (list (list :add h))))
    (u:encode-update-add-htlc
     (u:make-update-add-htlc :channel-id (live-channel-id lc) :id id :amount-msat amount-msat
                             :payment-hash payment-hash :cltv-expiry cltv-expiry
                             :onion-routing-packet onion))))

(defun receive-add (lc msg)
  "They offered an HTLC.  Recorded as proposed; it enters OUR commitment when
   their commitment_signed arrives, and THEIRS only after we sign."
  (let ((add (u:parse-update-add-htlc msg)))
    (unless (equalp (c:octets (u:uah-channel-id add)) (c:octets (live-channel-id lc)))
      (fail "update_add_htlc for a different channel"))
    (let ((h (make-htlc-rec :id (u:uah-id add) :direction :received
                            :amount-msat (u:uah-amount-msat add)
                            :payment-hash (u:uah-payment-hash add)
                            :cltv-expiry (u:uah-cltv-expiry add)
                            :onion (u:uah-onion-routing-packet add))))
      ;; Reject an overdraw NOW, while it is still just a proposal — accepting
      ;; it and failing at commitment_signed leaves the channel unusable.
      (reduce-spec (live-local-spec lc)
                   (append (live-local-acked lc) (live-remote-proposed lc) (list (list :add h))))
      (setf (live-remote-proposed lc) (append (live-remote-proposed lc) (list (list :add h))))
      h)))

(defun %find-received (lc id)
  "An HTLC they offered that is in OUR commitment — the only kind we can settle."
  (or (find-if (lambda (h) (and (= (hr-id h) id) (eq (hr-direction h) :received)))
               (spec-htlcs (live-local-spec lc)))
      (fail "no received HTLC ~d in our commitment" id)))

(defun %find-offered (lc id)
  (or (find-if (lambda (h) (and (= (hr-id h) id) (eq (hr-direction h) :offered)))
               (spec-htlcs (live-remote-spec lc)))
      (fail "no offered HTLC ~d in their commitment" id)))

(defun send-fulfill (lc id preimage)
  "Claim an HTLC they offered us.  The preimage is checked before it leaves:
   sending a wrong one is a protocol error the peer will fail the channel over."
  (let ((h (%find-received lc id)))
    (unless (u:preimage-matches-p preimage (hr-payment-hash h))
      (fail "preimage does not hash to HTLC ~d's payment hash" id))
    (setf (live-local-proposed lc)
          (append (live-local-proposed lc) (list (list :fulfill id preimage))))
    (u:encode-update-fulfill-htlc
     (u:make-update-fulfill-htlc :channel-id (live-channel-id lc) :id id
                                 :payment-preimage preimage))))

(defun send-fail (lc id reason)
  (%find-received lc id)
  (setf (live-local-proposed lc) (append (live-local-proposed lc) (list (list :fail id))))
  (u:encode-update-fail-htlc
   (u:make-update-fail-htlc :channel-id (live-channel-id lc) :id id :reason reason)))

(defun receive-fulfill (lc msg)
  "They claimed an HTLC we offered.  Verified before it is believed: crediting
   an unproven claim is giving money away."
  (let* ((f (u:parse-update-fulfill-htlc msg))
         (h (%find-offered lc (u:ufh-id f))))
    (unless (u:preimage-matches-p (u:ufh-payment-preimage f) (hr-payment-hash h))
      (fail "their preimage does not hash to HTLC ~d's payment hash" (u:ufh-id f)))
    (setf (hr-preimage h) (u:ufh-payment-preimage f))
    (setf (live-remote-proposed lc)
          (append (live-remote-proposed lc)
                  (list (list :fulfill (u:ufh-id f) (u:ufh-payment-preimage f)))))
    h))

(defun receive-fail (lc id)
  "update_fail_htlc or update_fail_malformed_htlc for an HTLC we offered."
  (%find-offered lc id)
  (setf (live-remote-proposed lc) (append (live-remote-proposed lc) (list (list :fail id))))
  id)

(defun receive-fee (lc feerate)
  "update_fee.  Only the opener may send it — they pay the fee — and a zero
   feerate would make every commitment unrelayable."
  (unless (eq (live-opener lc) :remote) (fail "update_fee from the non-opener"))
  (when (< feerate 253) (fail "feerate ~d per kw is below the floor" feerate))
  (setf (live-remote-proposed lc) (append (live-remote-proposed lc) (list (list :fee feerate))))
  feerate)

;;; ----------------------------------------------------------------------------
;;; The cycle
;;; ----------------------------------------------------------------------------

(defun can-send-commit-p (lc)
  (and (not (live-awaiting-revocation-p lc))
       (live-remote-next-point lc)
       (live-pending-changes-p lc)))

(defun send-commit (lc)
  "Sign their next commitment.  Returns the commitment_signed message.

   The interlock is not optional: a second commitment_signed before their
   revoke_and_ack gives them two valid commitments and no way to tell us which
   one they revoked."
  (when (live-awaiting-revocation-p lc) (fail "commitment_signed already outstanding"))
  (unless (live-remote-next-point lc) (fail "do not know their next per-commitment point"))
  (let* ((spec (reduce-spec (live-remote-spec lc)
                            (append (live-remote-acked lc) (live-local-proposed lc))))
         (built (%build lc spec :ours nil :point (live-remote-next-point lc)))
         (our-funding-pub (pub (live-funding-priv lc)))
         (sig (m:sign-commitment (b-tx built) (live-funding-priv lc) our-funding-pub
                                 (live-remote-funding-pubkey lc) (live-capacity-sat lc)))
         ;; Our HTLC key for THEIR commitment is derived with THEIR point.
         (htlc-priv (k:derive-privkey (live-htlc-priv lc) (live-remote-next-point lc)))
         (htlc-sigs (loop for (idx rec script) in (b-htlc-outputs built)
                          collect (m:sign-htlc-tx (%htlc-tx built nil idx rec) htlc-priv
                                                  script (floor (hr-amount-msat rec) 1000)))))
    (setf (live-remote-next-commit lc) (cons (1+ (live-remote-commit-index lc)) spec)
          (live-local-signed lc) (append (live-local-signed lc) (live-local-proposed lc))
          (live-local-proposed lc) '()
          (live-remote-signed lc) (append (live-remote-signed lc) (live-remote-acked lc))
          (live-remote-acked lc) '())
    (u:encode-commitment-signed
     (u:make-commitment-signed :channel-id (live-channel-id lc) :signature sig
                               :htlc-signatures htlc-sigs))))

(defun receive-commit (lc msg)
  "They signed OUR next commitment.  Verify every signature, then — and only
   then — revoke the previous one.  Returns the revoke_and_ack message.

   Revoking first would leave us holding nothing enforceable: the old state is
   punishable if published and the new one is unsigned."
  (let* ((cs (u:parse-commitment-signed msg))
         (n (1+ (live-local-commit-index lc)))
         (point (local-point lc n))
         (spec (reduce-spec (live-local-spec lc)
                            (append (live-local-acked lc) (live-remote-proposed lc))))
         (built (%build lc spec :ours t :point point))
         (our-funding-pub (pub (live-funding-priv lc))))
    (unless (m:verify-commitment (b-tx built) (u:cs-signature cs) our-funding-pub
                                 (live-remote-funding-pubkey lc) (live-capacity-sat lc)
                                 (live-remote-funding-pubkey lc))
      (fail "their signature over our commitment ~d does not verify" n))
    (unless (= (length (u:cs-htlc-signatures cs)) (length (b-htlc-outputs built)))
      (fail "expected ~d htlc_signatures, got ~d"
            (length (b-htlc-outputs built)) (length (u:cs-htlc-signatures cs))))
    ;; Their HTLC key for OUR commitment is derived with OUR point.
    (let ((their-htlc-pub (k:derive-pubkey (live-remote-htlc-basepoint lc) point)))
      (loop for (idx rec script) in (b-htlc-outputs built)
            for sig in (u:cs-htlc-signatures cs)
            do (let* ((htx (%htlc-tx built t idx rec))
                      (hash (m:htlc-tx-sighash htx script (floor (hr-amount-msat rec) 1000))))
                 (unless (%verify64 sig hash their-htlc-pub)
                   (fail "their htlc_signature for HTLC ~d does not verify" (hr-id rec))))))
    ;; Everything checks.  Adopt the new commitment and revoke the old one.
    (setf (live-local-spec lc) spec
          (live-local-commit-index lc) n
          (live-remote-acked lc) (append (live-remote-acked lc) (live-remote-proposed lc))
          (live-remote-proposed lc) '()
          (live-local-acked lc) '())
    (u:encode-revoke-and-ack
     (u:make-revoke-and-ack :channel-id (live-channel-id lc)
                            :per-commitment-secret (secp:int-to-bytes32 (local-secret lc (1- n)))
                            :next-per-commitment-point (local-point lc (1+ n))))))

(defun receive-revocation (lc msg)
  "They revoked their previous commitment.  The secret is checked against the
   point we already hold for it — a secret that does not match proves nothing
   and stores nothing punishable."
  (unless (live-awaiting-revocation-p lc) (fail "revoke_and_ack with nothing outstanding"))
  (let* ((raa (u:parse-revoke-and-ack msg))
         (secret (u:raa-per-commitment-secret raa))
         (expected (live-remote-current-point lc)))
    (unless (equalp (c:octets (c:compressed-pubkey (c:pubkey-of (secp:bytes-to-int secret))))
                    (c:octets expected))
      (fail "revoked secret does not match their commitment ~d point" (live-remote-commit-index lc)))
    (k:shachain-insert (live-revocations lc)
                       (- k:+max-commitment-index+ (live-remote-commit-index lc)) secret)
    (destructuring-bind (idx . spec) (live-remote-next-commit lc)
      (setf (live-remote-spec lc) spec
            (live-remote-commit-index lc) idx
            (live-remote-next-commit lc) nil
            (live-remote-current-point lc) (live-remote-next-point lc)
            (live-remote-next-point lc) (u:raa-next-per-commitment-point raa)
            (live-last-remote-secret lc) secret
            (live-local-acked lc) (append (live-local-acked lc) (live-local-signed lc))
            (live-local-signed lc) '()
            (live-remote-signed lc) '()))
    t))

(defun fully-committed-received-htlcs (lc)
  "HTLCs they offered that are now in BOTH commitments and unresolved — the
   only ones it is safe to settle.  Settling one that is in our commitment but
   not yet theirs would let them dispute a payment we already forwarded."
  (remove-if-not (lambda (h)
                   (and (eq (hr-direction h) :received)
                        (member h (spec-htlcs (live-remote-spec lc)))
                        (not (find (hr-id h) (append (live-local-proposed lc) (live-local-signed lc)
                                                     (live-local-acked lc))
                                   :key #'second))))
                 (spec-htlcs (live-local-spec lc))))

;;; ----------------------------------------------------------------------------
;;; channel_reestablish
;;; ----------------------------------------------------------------------------

(defun reestablish-message (lc)
  (u:encode-channel-reestablish
   (u:make-channel-reestablish
    :channel-id (live-channel-id lc)
    :next-commitment-number (1+ (live-local-commit-index lc))
    :next-revocation-number (live-remote-commit-index lc)
    :your-last-per-commitment-secret (or (live-last-remote-secret lc) (c:zeros 32))
    :my-current-per-commitment-point (local-point lc (live-local-commit-index lc)))))

;;; ----------------------------------------------------------------------------
;;; Closing (BOLT #2: shutdown, closing_signed)
;;;
;;; The cooperative close spends the funding output straight to two addresses,
;;; no delays and no revocation.  It is the only way out of a channel that does
;;; not cost a CSV wait, which is why both sides are usually happy to agree.
;;; ----------------------------------------------------------------------------

(defconstant +msg-shutdown+ 38)
(defconstant +msg-closing-signed+ 39)

(defun encode-shutdown (channel-id scriptpubkey)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr channel-id)
    (w:w-varbytes wr scriptpubkey)
    (w:encode-message +msg-shutdown+ (w:writer-bytes wr))))

(defun parse-shutdown (payload)
  (let ((r (w:make-reader payload)))
    (values (w:r-bytes r 32) (w:r-varbytes r))))

(defun encode-closing-signed (channel-id fee-sat sig &key min-fee max-fee)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr channel-id)
    (w:w-u64 wr fee-sat)
    (w:w-sig wr sig)
    (when (and min-fee max-fee)
      (let ((v (w:make-writer)))
        (w:w-u64 v min-fee) (w:w-u64 v max-fee)
        (w:w-tlv-stream wr (list (w:make-tlv-record :type 1 :value (w:writer-bytes v))))))
    (w:encode-message +msg-closing-signed+ (w:writer-bytes wr))))

(defun parse-closing-signed (payload)
  "Returns (values channel-id fee-sat sig min-fee max-fee)."
  (let* ((r (w:make-reader payload))
         (cid (w:r-bytes r 32)) (fee (w:r-u64 r)) (sig (w:r-sig r))
         (tlvs (unless (w:reader-eof-p r) (ignore-errors (w:r-tlv-stream r))))
         (range (and tlvs (w:tlv-get tlvs 1))))
    (if range
        (let ((rr (w:make-reader range)))
          (values cid fee sig (w:r-u64 rr) (w:r-u64 rr)))
        (values cid fee sig nil nil))))

(defun send-shutdown (lc scriptpubkey)
  (setf (live-local-shutdown-script lc) scriptpubkey)
  (encode-shutdown (live-channel-id lc) scriptpubkey))

(defun receive-shutdown (lc msg)
  "Record where they want their money.  Returns their scriptpubkey."
  (multiple-value-bind (cid spk) (parse-shutdown msg)
    (unless (equalp (c:octets cid) (c:octets (live-channel-id lc))) (fail "shutdown for another channel"))
    (unless (member (length spk) '(22 34 25 23))
      (fail "unusual shutdown scriptpubkey of ~d bytes" (length spk)))
    (setf (live-remote-shutdown-script lc) spk)))

(defun build-closing-tx (lc fee-sat)
  "The mutual close: funding output in, two outputs, fee from the opener's side,
   BIP69 ordered, dust dropped.  Both ends must build the identical transaction
   from the same fee or neither signature verifies."
  (let* ((spec (live-local-spec lc))
         (local-sat (floor (spec-to-local-msat spec) 1000))
         (remote-sat (floor (spec-to-remote-msat spec) 1000)))
    (when (spec-htlcs spec) (fail "cannot close with HTLCs outstanding"))
    (ecase (live-opener lc)
      (:local (decf local-sat fee-sat))
      (:remote (decf remote-sat fee-sat)))
    (when (or (minusp local-sat) (minusp remote-sat)) (fail "closing fee exceeds the opener's balance"))
    (let ((outs '()))
      (unless (m:dust-p local-sat (live-local-dust-limit lc))
        (push (btx:make-txout :value local-sat :script (live-local-shutdown-script lc)) outs))
      (unless (m:dust-p remote-sat (live-remote-dust-limit lc))
        (push (btx:make-txout :value remote-sat :script (live-remote-shutdown-script lc)) outs))
      (setf outs (sort outs (lambda (a b)
                              (or (< (btx:txout-value a) (btx:txout-value b))
                                  (and (= (btx:txout-value a) (btx:txout-value b))
                                       (let ((sa (btx:txout-script a)) (sb (btx:txout-script b)))
                                         (loop for i from 0 below (min (length sa) (length sb))
                                               when (/= (aref sa i) (aref sb i))
                                                 return (< (aref sa i) (aref sb i))
                                               finally (return (< (length sa) (length sb))))))))))
      (btx:parse-tx
       (bw:make-reader
        (btx:serialize-tx
         (btx:make-tx :version 2
                      :inputs (list (btx:make-txin :prev-hash (c:octets (live-funding-txid lc))
                                                   :prev-index (live-funding-index lc)
                                                   :script #() :sequence #xffffffff))
                      :outputs outs :witnesses (list nil) :locktime 0 :segwit-p nil)))))))

(defun propose-close (lc fee-sat)
  "The opener's side: sign the close at FEE-SAT and offer it.  Returns the
   closing_signed message and the transaction it signs."
  (unless (and (live-local-shutdown-script lc) (live-remote-shutdown-script lc))
    (fail "closing_signed before both shutdowns"))
  (let* ((tx (build-closing-tx lc fee-sat))
         (sig (m:sign-commitment tx (live-funding-priv lc) (pub (live-funding-priv lc))
                                 (live-remote-funding-pubkey lc) (live-capacity-sat lc))))
    (values (encode-closing-signed (live-channel-id lc) fee-sat sig :min-fee fee-sat :max-fee fee-sat)
            tx sig)))

(defun receive-closing-signed (lc msg)
  "They proposed a fee and signed the close at that fee.  We verify their
   signature over the transaction WE build from that fee — if the two differ,
   the signature fails and we have learned we disagree about the channel's
   contents.  Returns our closing_signed accepting the same fee, and marks the
   channel closed."
  (unless (and (live-local-shutdown-script lc) (live-remote-shutdown-script lc))
    (fail "closing_signed before both shutdowns"))
  (multiple-value-bind (cid fee sig min-fee max-fee) (parse-closing-signed msg)
    (declare (ignore min-fee max-fee))
    (unless (equalp (c:octets cid) (c:octets (live-channel-id lc))) (fail "closing_signed for another channel"))
    (let* ((tx (build-closing-tx lc fee))
           (our-funding-pub (pub (live-funding-priv lc))))
      (unless (m:verify-commitment tx sig our-funding-pub (live-remote-funding-pubkey lc)
                                   (live-capacity-sat lc) (live-remote-funding-pubkey lc))
        (fail "their closing signature does not verify at fee ~d" fee))
      (let ((ours (m:sign-commitment tx (live-funding-priv lc) our-funding-pub
                                     (live-remote-funding-pubkey lc) (live-capacity-sat lc))))
        (setf (live-closed-p lc) t
              (live-closing-txid lc) (btx:tx-txid tx))
        (values (encode-closing-signed (live-channel-id lc) fee ours :min-fee fee :max-fee fee)
                tx sig ours)))))

;;; ----------------------------------------------------------------------------
;;; Persistence — everything above, as a plist of hex strings and integers.
;;; Changes in flight are NOT persisted: a restart mid-cycle is resolved by
;;; channel_reestablish, not by replaying half a conversation.
;;; ----------------------------------------------------------------------------

(defun hx (b) (and b (c:bytes->hex (c:octets b))))
(defun uh (s) (and s (c:hex->bytes s)))

(defun htlc->plist (h)
  (list :id (hr-id h) :direction (hr-direction h) :amount-msat (hr-amount-msat h)
        :payment-hash (hx (hr-payment-hash h)) :cltv-expiry (hr-cltv-expiry h)))
(defun plist->htlc (p)
  (make-htlc-rec :id (getf p :id) :direction (getf p :direction)
                 :amount-msat (getf p :amount-msat) :payment-hash (uh (getf p :payment-hash))
                 :cltv-expiry (getf p :cltv-expiry) :onion (c:zeros u:+onion-packet-size+)))
(defun spec->plist (s)
  (list :to-local-msat (spec-to-local-msat s) :to-remote-msat (spec-to-remote-msat s)
        :feerate-per-kw (spec-feerate-per-kw s) :htlcs (mapcar #'htlc->plist (spec-htlcs s))))
(defun plist->spec (p)
  (%make-spec :to-local-msat (getf p :to-local-msat) :to-remote-msat (getf p :to-remote-msat)
              :feerate-per-kw (getf p :feerate-per-kw)
              :htlcs (mapcar #'plist->htlc (getf p :htlcs))))

(defun live->plist (lc)
  (list :channel-id (hx (live-channel-id lc)) :funding-txid (hx (live-funding-txid lc))
        :funding-index (live-funding-index lc) :capacity-sat (live-capacity-sat lc)
        :opener (live-opener lc)
        :funding-priv (live-funding-priv lc) :revocation-priv (live-revocation-priv lc)
        :payment-priv (live-payment-priv lc) :delayed-priv (live-delayed-priv lc)
        :htlc-priv (live-htlc-priv lc) :seed (hx (live-seed lc))
        :remote-funding-pubkey (hx (live-remote-funding-pubkey lc))
        :remote-revocation-basepoint (hx (live-remote-revocation-basepoint lc))
        :remote-payment-basepoint (hx (live-remote-payment-basepoint lc))
        :remote-delayed-basepoint (hx (live-remote-delayed-basepoint lc))
        :remote-htlc-basepoint (hx (live-remote-htlc-basepoint lc))
        :local-dust-limit (live-local-dust-limit lc) :remote-dust-limit (live-remote-dust-limit lc)
        :local-to-self-delay (live-local-to-self-delay lc)
        :remote-to-self-delay (live-remote-to-self-delay lc)
        :local-commit-index (live-local-commit-index lc)
        :remote-commit-index (live-remote-commit-index lc)
        :local-spec (spec->plist (live-local-spec lc))
        :remote-spec (spec->plist (live-remote-spec lc))
        :remote-current-point (hx (live-remote-current-point lc))
        :remote-next-point (hx (live-remote-next-point lc))
        :next-htlc-id (live-next-htlc-id lc)
        :last-remote-secret (hx (live-last-remote-secret lc))
        :local-shutdown-script (hx (live-local-shutdown-script lc))
        :remote-shutdown-script (hx (live-remote-shutdown-script lc))
        :closed-p (live-closed-p lc) :closing-txid (hx (live-closing-txid lc))))

(defun plist->live (p)
  (flet ((g (k) (getf p k)))
    (%make-live :channel-id (uh (g :channel-id)) :funding-txid (uh (g :funding-txid))
                :funding-index (g :funding-index) :capacity-sat (g :capacity-sat) :opener (g :opener)
                :funding-priv (g :funding-priv) :revocation-priv (g :revocation-priv)
                :payment-priv (g :payment-priv) :delayed-priv (g :delayed-priv)
                :htlc-priv (g :htlc-priv) :seed (uh (g :seed))
                :remote-funding-pubkey (uh (g :remote-funding-pubkey))
                :remote-revocation-basepoint (uh (g :remote-revocation-basepoint))
                :remote-payment-basepoint (uh (g :remote-payment-basepoint))
                :remote-delayed-basepoint (uh (g :remote-delayed-basepoint))
                :remote-htlc-basepoint (uh (g :remote-htlc-basepoint))
                :local-dust-limit (g :local-dust-limit) :remote-dust-limit (g :remote-dust-limit)
                :local-to-self-delay (g :local-to-self-delay)
                :remote-to-self-delay (g :remote-to-self-delay)
                :local-commit-index (g :local-commit-index)
                :remote-commit-index (g :remote-commit-index)
                :local-spec (plist->spec (g :local-spec)) :remote-spec (plist->spec (g :remote-spec))
                :remote-current-point (uh (g :remote-current-point))
                :remote-next-point (uh (g :remote-next-point))
                :next-htlc-id (or (g :next-htlc-id) 0)
                :last-remote-secret (uh (g :last-remote-secret))
                :local-shutdown-script (uh (g :local-shutdown-script))
                :remote-shutdown-script (uh (g :remote-shutdown-script))
                :closed-p (g :closed-p) :closing-txid (uh (g :closing-txid)))))
