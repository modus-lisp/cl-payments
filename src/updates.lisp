;;;; src/updates.lisp
;;;;
;;;; Phase 4d — BOLT #2: the HTLC lifecycle.
;;;;
;;;; Opening a channel is a handshake.  THIS is the part that moves money, and it
;;;; is where the protocol stops being a message format and becomes a state
;;;; machine.
;;;;
;;;; The central idea is that an update is not applied when it is sent.  It is
;;;; *proposed* (`update_add_htlc`), then *committed* (`commitment_signed`), then
;;;; the old state is *revoked* (`revoke_and_ack`) — and only after that
;;;; revocation is the previous commitment unusable.  Both directions run this
;;;; independently and simultaneously, so at any moment each side may hold two
;;;; valid commitments for its counterparty and one for itself, or the reverse.
;;;;
;;;; The ordering rule that makes it safe is narrow and absolute:
;;;;
;;;;   NEVER revoke a commitment before you hold a signature for its replacement.
;;;;
;;;; Revoking first would leave you with no enforceable state at all: the old
;;;; commitment is now punishable if you publish it, and the new one is not yet
;;;; signed by the counterparty, so you could publish nothing. The channel
;;;; balance would be entirely at their mercy. That is why `commitment_signed`
;;;; must arrive before `revoke_and_ack` goes out, and why this file tracks who
;;;; has signed what rather than just counting messages.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md

(defpackage #:cl-payments.updates
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:k #:cl-payments.keys) (#:m #:cl-payments.commitment)
                    (#:secp #:secp256k1-fast))
  (:nicknames #:ln-updates)
  (:export
   #:+msg-update-add-htlc+ #:+msg-update-fulfill-htlc+ #:+msg-update-fail-htlc+
   #:+msg-commitment-signed+ #:+msg-revoke-and-ack+ #:+msg-update-fee+
   #:+msg-update-fail-malformed-htlc+ #:+msg-channel-reestablish+
   #:+onion-packet-size+
   ;; messages
   #:update-add-htlc #:make-update-add-htlc #:encode-update-add-htlc #:parse-update-add-htlc
   #:uah-channel-id #:uah-id #:uah-amount-msat #:uah-payment-hash #:uah-cltv-expiry
   #:uah-onion-routing-packet
   #:update-fulfill-htlc #:make-update-fulfill-htlc
   #:encode-update-fulfill-htlc #:parse-update-fulfill-htlc
   #:ufh-channel-id #:ufh-id #:ufh-payment-preimage
   #:update-fail-htlc #:make-update-fail-htlc
   #:encode-update-fail-htlc #:parse-update-fail-htlc
   #:ufl-channel-id #:ufl-id #:ufl-reason
   #:commitment-signed #:make-commitment-signed
   #:encode-commitment-signed #:parse-commitment-signed
   #:cs-channel-id #:cs-signature #:cs-htlc-signatures
   #:revoke-and-ack #:make-revoke-and-ack #:encode-revoke-and-ack #:parse-revoke-and-ack
   #:raa-channel-id #:raa-per-commitment-secret #:raa-next-per-commitment-point
   #:update-fee #:make-update-fee #:encode-update-fee #:parse-update-fee
   #:uf-channel-id #:uf-feerate-per-kw
   #:channel-reestablish #:make-channel-reestablish
   #:encode-channel-reestablish #:parse-channel-reestablish
   #:cre-channel-id #:cre-next-commitment-number #:cre-next-revocation-number
   #:cre-your-last-per-commitment-secret #:cre-my-current-per-commitment-point
   #:reestablish-for
   ;; state machine
   #:channel-state #:make-channel-state
   #:cst-local-commitment-number #:cst-remote-commitment-number
   #:cst-offered #:cst-received #:cst-next-htlc-id
   #:cst-local-balance-msat #:cst-remote-balance-msat
   #:cst-awaiting-revocation-p #:cst-revocations
   #:offer-htlc #:receive-htlc #:fulfill-htlc #:receive-fulfill
   #:sent-commitment #:received-revocation #:receive-commitment
   #:htlc-state #:update-error #:preimage-matches-p))

(in-package #:cl-payments.updates)

(defconstant +msg-update-add-htlc+ 128)
(defconstant +msg-update-fulfill-htlc+ 130)
(defconstant +msg-update-fail-htlc+ 131)
(defconstant +msg-commitment-signed+ 132)
(defconstant +msg-revoke-and-ack+ 133)
(defconstant +msg-update-fee+ 134)
(defconstant +msg-update-fail-malformed-htlc+ 135)
(defconstant +msg-channel-reestablish+ 136)

(defconstant +onion-packet-size+ 1366
  "BOLT #4's onion is a FIXED 1366 bytes regardless of route length — a shorter
   packet for a shorter route would leak how many hops remain.")

(define-condition update-error (error)
  ((detail :initarg :detail :reader update-error-detail))
  (:report (lambda (c s) (format s "channel update: ~a" (update-error-detail c)))))

;;; ----------------------------------------------------------------------------
;;; Messages
;;; ----------------------------------------------------------------------------

(defstruct (update-add-htlc (:conc-name uah-))
  channel-id id amount-msat payment-hash cltv-expiry onion-routing-packet)

(defun encode-update-add-htlc (u)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (uah-channel-id u))
    (w:w-u64 wr (uah-id u))
    (w:w-u64 wr (uah-amount-msat u))
    (w:w-hash wr (uah-payment-hash u))
    (w:w-u32 wr (uah-cltv-expiry u))
    (let ((onion (uah-onion-routing-packet u)))
      (unless (= (length onion) +onion-packet-size+)
        (error 'update-error
               :detail (format nil "onion packet is ~d bytes, must be ~d"
                               (length onion) +onion-packet-size+)))
      (w:w-bytes wr onion))
    (w:encode-message +msg-update-add-htlc+ (w:writer-bytes wr))))

(defun parse-update-add-htlc (payload)
  (handler-case
      (let ((r (w:make-reader payload)))
        (make-update-add-htlc
         :channel-id (w:r-bytes r 32) :id (w:r-u64 r) :amount-msat (w:r-u64 r)
         :payment-hash (w:r-hash r) :cltv-expiry (w:r-u32 r)
         :onion-routing-packet (w:r-bytes r +onion-packet-size+)))
    (error (e) (error 'update-error :detail (format nil "bad update_add_htlc: ~a" e)))))

(defstruct (update-fulfill-htlc (:conc-name ufh-))
  channel-id id payment-preimage)

(defun encode-update-fulfill-htlc (u)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (ufh-channel-id u))
    (w:w-u64 wr (ufh-id u))
    (w:w-bytes wr (ufh-payment-preimage u))
    (w:encode-message +msg-update-fulfill-htlc+ (w:writer-bytes wr))))

(defun parse-update-fulfill-htlc (payload)
  (handler-case
      (let ((r (w:make-reader payload)))
        (make-update-fulfill-htlc
         :channel-id (w:r-bytes r 32) :id (w:r-u64 r)
         :payment-preimage (w:r-bytes r 32)))
    (error (e) (error 'update-error :detail (format nil "bad update_fulfill_htlc: ~a" e)))))

(defstruct (update-fail-htlc (:conc-name ufl-))
  channel-id id reason)

(defun encode-update-fail-htlc (u)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (ufl-channel-id u))
    (w:w-u64 wr (ufl-id u))
    (w:w-varbytes wr (ufl-reason u))
    (w:encode-message +msg-update-fail-htlc+ (w:writer-bytes wr))))

(defun parse-update-fail-htlc (payload)
  (handler-case
      (let ((r (w:make-reader payload)))
        (make-update-fail-htlc
         :channel-id (w:r-bytes r 32) :id (w:r-u64 r) :reason (w:r-varbytes r)))
    (error (e) (error 'update-error :detail (format nil "bad update_fail_htlc: ~a" e)))))

(defstruct (commitment-signed (:conc-name cs-))
  channel-id signature htlc-signatures)

(defun encode-commitment-signed (cs)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (cs-channel-id cs))
    (w:w-sig wr (cs-signature cs))
    (w:w-u16 wr (length (cs-htlc-signatures cs)))
    ;; One signature per untrimmed HTLC, IN OUTPUT ORDER.  The receiver matches
    ;; them positionally against its own sort of the same HTLCs, so an ordering
    ;; disagreement attaches every signature to the wrong HTLC at once.
    (dolist (sig (cs-htlc-signatures cs)) (w:w-sig wr sig))
    (w:encode-message +msg-commitment-signed+ (w:writer-bytes wr))))

(defun parse-commitment-signed (payload)
  (handler-case
      (let* ((r (w:make-reader payload))
             (cid (w:r-bytes r 32))
             (sig (w:r-sig r))
             (n (w:r-u16 r)))
        (make-commitment-signed
         :channel-id cid :signature sig
         :htlc-signatures (loop repeat n collect (w:r-sig r))))
    (error (e) (error 'update-error :detail (format nil "bad commitment_signed: ~a" e)))))

(defstruct (revoke-and-ack (:conc-name raa-))
  channel-id per-commitment-secret next-per-commitment-point)

(defun encode-revoke-and-ack (r)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (raa-channel-id r))
    ;; Handing over this secret is what makes the OLD commitment punishable.  It
    ;; is irreversible: once sent, publishing that state is theft you can be
    ;; penalised for.
    (w:w-bytes wr (raa-per-commitment-secret r))
    (w:w-point wr (raa-next-per-commitment-point r))
    (w:encode-message +msg-revoke-and-ack+ (w:writer-bytes wr))))

(defun parse-revoke-and-ack (payload)
  (handler-case
      (let ((r (w:make-reader payload)))
        (make-revoke-and-ack
         :channel-id (w:r-bytes r 32)
         :per-commitment-secret (w:r-bytes r 32)
         :next-per-commitment-point (w:r-point r)))
    (error (e) (error 'update-error :detail (format nil "bad revoke_and_ack: ~a" e)))))

(defstruct (update-fee (:conc-name uf-))
  channel-id feerate-per-kw)

(defun encode-update-fee (u)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (uf-channel-id u))
    (w:w-u32 wr (uf-feerate-per-kw u))
    (w:encode-message +msg-update-fee+ (w:writer-bytes wr))))

(defun parse-update-fee (payload)
  (handler-case
      (let ((r (w:make-reader payload)))
        (make-update-fee :channel-id (w:r-bytes r 32) :feerate-per-kw (w:r-u32 r)))
    (error (e) (error 'update-error :detail (format nil "bad update_fee: ~a" e)))))

;;; ----------------------------------------------------------------------------
;;; The state machine
;;;
;;; An HTLC moves through states, and the transitions are driven by BOTH sides'
;;; commitment/revocation cycles.  This tracks the parts that matter for
;;; correctness: what has been proposed, what is irrevocably committed, and
;;; — critically — whether we are still waiting for a signature we must have
;;; before revoking anything.
;;; ----------------------------------------------------------------------------

(defstruct (htlc-state (:conc-name hs-))
  id amount-msat payment-hash cltv-expiry
  direction              ; :offered (we pay) or :received (we are paid)
  (state :proposed)      ; :proposed -> :committed -> :fulfilled / :failed
  preimage)

(defstruct (channel-state (:conc-name cst-))
  channel-id
  ;; Commitments are numbered UP from 0 here for legibility; the on-chain
  ;; obscuring uses the same number.
  (local-commitment-number 0)
  (remote-commitment-number 0)
  (offered '())            ; HTLCs we added
  (received '())           ; HTLCs they added
  (next-htlc-id 0)
  local-balance-msat
  remote-balance-msat
  ;; The safety interlock: set when we send commitment_signed, cleared when the
  ;; matching revoke_and_ack comes back.  We must not send another
  ;; commitment_signed while it is set.
  (awaiting-revocation-p nil)
  ;; Their revoked secrets, so an old commitment of theirs can be punished.
  (revocations (k:make-shachain))
  seed)

(defun preimage-matches-p (preimage payment-hash)
  "An HTLC is claimed by revealing a preimage whose SHA256 is the payment hash.
   Checked rather than trusted: a fulfill with the wrong preimage would move
   money for a payment that was never proven."
  (equalp (c:octets (c:sha256 (c:octets preimage))) (c:octets payment-hash)))

(defun offer-htlc (state amount-msat payment-hash cltv-expiry)
  "Propose an HTLC to the peer.  Returns the new HTLC's id.

   The amount leaves our balance IMMEDIATELY, before any commitment is signed —
   it is in flight, neither ours nor theirs, and comes back only if the HTLC
   fails."
  (when (< (cst-local-balance-msat state) amount-msat)
    (error 'update-error
           :detail (format nil "cannot offer ~d msat: only ~d available"
                           amount-msat (cst-local-balance-msat state))))
  (let ((id (cst-next-htlc-id state)))
    (push (make-htlc-state :id id :amount-msat amount-msat
                           :payment-hash payment-hash :cltv-expiry cltv-expiry
                           :direction :offered :state :proposed)
          (cst-offered state))
    (incf (cst-next-htlc-id state))
    (decf (cst-local-balance-msat state) amount-msat)
    id))

(defun receive-htlc (state add)
  "Record an HTLC the peer proposed.  Their balance drops by the amount, for the
   same reason ours does when we offer one."
  (when (< (cst-remote-balance-msat state) (uah-amount-msat add))
    (error 'update-error
           :detail (format nil "peer offered ~d msat with only ~d available"
                           (uah-amount-msat add) (cst-remote-balance-msat state))))
  (push (make-htlc-state :id (uah-id add) :amount-msat (uah-amount-msat add)
                         :payment-hash (uah-payment-hash add)
                         :cltv-expiry (uah-cltv-expiry add)
                         :direction :received :state :proposed)
        (cst-received state))
  (decf (cst-remote-balance-msat state) (uah-amount-msat add))
  state)

(defun fulfill-htlc (state id preimage)
  "Claim an HTLC the peer offered us.  The money becomes ours only here — and
   only if the preimage actually hashes to the payment hash."
  (let ((h (find id (cst-received state) :key #'hs-id)))
    (unless h (error 'update-error :detail (format nil "no received HTLC with id ~d" id)))
    (unless (preimage-matches-p preimage (hs-payment-hash h))
      (error 'update-error
             :detail (format nil "preimage does not hash to HTLC ~d's payment hash" id)))
    (setf (hs-state h) :fulfilled (hs-preimage h) preimage)
    (incf (cst-local-balance-msat state) (hs-amount-msat h))
    state))

(defun receive-fulfill (state fulfill)
  "The peer claimed an HTLC we offered.  We verify the preimage before crediting
   them: accepting an unproven claim gives money away."
  (let ((h (find (ufh-id fulfill) (cst-offered state) :key #'hs-id)))
    (unless h
      (error 'update-error :detail (format nil "no offered HTLC with id ~d" (ufh-id fulfill))))
    (unless (preimage-matches-p (ufh-payment-preimage fulfill) (hs-payment-hash h))
      (error 'update-error
             :detail (format nil "peer's preimage does not hash to HTLC ~d's payment hash"
                             (ufh-id fulfill))))
    (setf (hs-state h) :fulfilled (hs-preimage h) (ufh-payment-preimage fulfill))
    (incf (cst-remote-balance-msat state) (hs-amount-msat h))
    state))

(defun sent-commitment (state)
  "Record that we sent `commitment_signed`.  Until the matching `revoke_and_ack`
   returns we must not send another — the peer would have two outstanding
   commitments and no way to tell us which it revoked."
  (when (cst-awaiting-revocation-p state)
    (error 'update-error
           :detail "cannot send commitment_signed while awaiting revoke_and_ack"))
  (setf (cst-awaiting-revocation-p state) t)
  (incf (cst-remote-commitment-number state))
  state)

(defun received-revocation (state raa)
  "The peer revoked its previous commitment.  Store the secret — it is what makes
   that old state punishable — and clear the interlock."
  (unless (cst-awaiting-revocation-p state)
    (error 'update-error :detail "unexpected revoke_and_ack: nothing was awaiting revocation"))
  (k:shachain-insert (cst-revocations state)
                     (- k:+max-commitment-index+ (1- (cst-remote-commitment-number state)))
                     (raa-per-commitment-secret raa))
  (setf (cst-awaiting-revocation-p state) nil)
  ;; Everything proposed before this commitment is now irrevocably committed.
  (dolist (h (append (cst-offered state) (cst-received state)))
    (when (eq (hs-state h) :proposed) (setf (hs-state h) :committed)))
  state)

(defun receive-commitment (state)
  "The peer signed OUR next commitment.  Only now may we revoke our previous one:
   revoking first would leave us holding no signed state at all."
  (incf (cst-local-commitment-number state))
  state)


;;; ----------------------------------------------------------------------------
;;; channel_reestablish (136)
;;;
;;; Sent by BOTH sides immediately after reconnecting, before anything else on
;;; the channel.  A Lightning connection is expected to drop — nodes restart,
;;; networks blink — and when it comes back the two ends may disagree about how
;;; far the channel got: a `commitment_signed` or a `revoke_and_ack` may have
;;; been sent but never received.
;;;
;;; The message states, in effect, "here is what I am still waiting for", and the
;;; two numbers are what let each side work out whether it must retransmit:
;;;
;;;   next_commitment_number   the commitment number of the next
;;;                            `commitment_signed` I expect FROM YOU
;;;   next_revocation_number   the number of the next `revoke_and_ack` I expect
;;;
;;; `your_last_per_commitment_secret` is the proof half.  Echoing back the last
;;; secret the peer gave us demonstrates we really are the node that held this
;;; channel — and a peer that finds we have a LATER secret than it thinks it
;;; released knows its own state is stale and that continuing would risk
;;; broadcasting a revoked commitment.
;;;
;;; Not answering at all is what cl-payments did before this existed: LND
;;; tolerates the silence and stays connected, but the channel is never resynced,
;;; so it is permanently unusable.
;;; ----------------------------------------------------------------------------

(defstruct (channel-reestablish (:conc-name cre-))
  channel-id
  next-commitment-number
  next-revocation-number
  your-last-per-commitment-secret
  my-current-per-commitment-point
  (tlvs nil))

(defun encode-channel-reestablish (r)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (cre-channel-id r))
    (w:w-u64 wr (cre-next-commitment-number r))
    (w:w-u64 wr (cre-next-revocation-number r))
    (w:w-bytes wr (cre-your-last-per-commitment-secret r))
    (w:w-point wr (cre-my-current-per-commitment-point r))
    (w:encode-message +msg-channel-reestablish+ (w:writer-bytes wr))))

(defun parse-channel-reestablish (payload)
  (handler-case
      (let ((r (w:make-reader payload)))
        (make-channel-reestablish
         :channel-id (w:r-bytes r 32)
         :next-commitment-number (w:r-u64 r)
         :next-revocation-number (w:r-u64 r)
         :your-last-per-commitment-secret (w:r-bytes r 32)
         :my-current-per-commitment-point (w:r-point r)
         :tlvs (unless (w:reader-eof-p r)
                 (handler-case (w:r-tlv-stream r) (error () nil)))))
    (error (e) (error 'update-error
                      :detail (format nil "bad channel_reestablish: ~a" e)))))

(defun reestablish-for (state)
  "Build our `channel_reestablish` from the channel's current state.

   Commitment numbers here count UP from 0, and the per-commitment SECRETS count
   DOWN from 2^48-1, so the index conversion is not decoration — getting it
   backwards hands the peer a secret for a state that was never revoked, which
   is indistinguishable from leaking a live key."
  (let* ((next-rev (cst-remote-commitment-number state))
         (last-secret
           ;; With nothing revoked yet the spec requires all zeroes rather than
           ;; some arbitrary value: there IS no previous secret to prove.
           (if (zerop next-rev)
               (c:zeros 32)
               (or (k:shachain-lookup (cst-revocations state)
                                      (- k:+max-commitment-index+ (1- next-rev)))
                   (c:zeros 32)))))
    (make-channel-reestablish
     :channel-id (cst-channel-id state)
     :next-commitment-number (cst-local-commitment-number state)
     :next-revocation-number next-rev
     :your-last-per-commitment-secret last-secret
     :my-current-per-commitment-point
     (k:per-commitment-point (cst-seed state)
                             (- k:+max-commitment-index+
                                (cst-local-commitment-number state))))))
