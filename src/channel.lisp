;;;; src/channel.lisp
;;;;
;;;; Phase 4c — BOLT #2: opening a channel.
;;;;
;;;; Five messages establish a channel, and the order matters because each one
;;;; only becomes safe once the previous is known:
;;;;
;;;;   open_channel     the opener proposes terms and offers its basepoints
;;;;   accept_channel   the accepter agrees and offers its own
;;;;   funding_created  the opener names the funding output and signs the
;;;;                    ACCEPTER's first commitment
;;;;   funding_signed   the accepter signs the OPENER's first commitment
;;;;   channel_ready    both sides confirm the funding transaction is buried
;;;;
;;;; The asymmetry in the middle is the whole safety argument.  The opener must
;;;; not broadcast the funding transaction until it holds a signature that lets
;;;; it get its money back, because the funding output is a 2-of-2 and an
;;;; uncooperative counterparty could otherwise hold the funds hostage forever.
;;;; So `funding_created` names an output that does not exist on chain yet, and
;;;; only after `funding_signed` arrives is broadcasting safe.
;;;;
;;;; Each side signs the OTHER's commitment, never its own — which is why either
;;;; party can close unilaterally but neither can do it alone.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md

(defpackage #:cl-payments.channel
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:k #:cl-payments.keys) (#:m #:cl-payments.commitment)
                    (#:f #:cl-payments.features)
                    (#:secp #:secp256k1-fast))
  (:nicknames #:ln-channel)
  (:export
   #:+msg-open-channel+ #:+msg-accept-channel+ #:+msg-funding-created+
   #:+msg-funding-signed+ #:+msg-channel-ready+
   #:open-channel #:make-open-channel #:encode-open-channel #:parse-open-channel
   #:oc-chain-hash #:oc-temporary-channel-id #:oc-funding-satoshis #:oc-push-msat
   #:oc-dust-limit-satoshis #:oc-max-htlc-value-in-flight-msat
   #:oc-channel-reserve-satoshis #:oc-htlc-minimum-msat #:oc-feerate-per-kw
   #:oc-to-self-delay #:oc-max-accepted-htlcs #:oc-funding-pubkey
   #:oc-revocation-basepoint #:oc-payment-basepoint #:oc-delayed-payment-basepoint
   #:oc-htlc-basepoint #:oc-first-per-commitment-point #:oc-channel-flags
   #:oc-channel-type #:oc-tlvs
   #:accept-channel #:make-accept-channel #:encode-accept-channel #:parse-accept-channel
   #:ac-temporary-channel-id #:ac-dust-limit-satoshis #:ac-minimum-depth
   #:ac-to-self-delay #:ac-max-accepted-htlcs #:ac-funding-pubkey
   #:ac-revocation-basepoint #:ac-payment-basepoint #:ac-delayed-payment-basepoint
   #:ac-htlc-basepoint #:ac-first-per-commitment-point
   #:ac-max-htlc-value-in-flight-msat #:ac-channel-reserve-satoshis #:ac-htlc-minimum-msat
   #:funding-created #:make-funding-created
   #:encode-funding-created #:parse-funding-created
   #:fc-temporary-channel-id #:fc-funding-txid #:fc-funding-output-index #:fc-signature
   #:funding-signed #:make-funding-signed
   #:encode-funding-signed #:parse-funding-signed #:fs-channel-id #:fs-signature
   #:channel-ready #:make-channel-ready
   #:encode-channel-ready #:parse-channel-ready
   #:cr-channel-id #:cr-second-per-commitment-point
   #:channel-id #:channel-error))

(in-package #:cl-payments.channel)

(defconstant +msg-open-channel+ 32)
(defconstant +msg-accept-channel+ 33)
(defconstant +msg-funding-created+ 34)
(defconstant +msg-funding-signed+ 35)
(defconstant +msg-channel-ready+ 36)

(define-condition channel-error (error)
  ((detail :initarg :detail :reader channel-error-detail))
  (:report (lambda (c s) (format s "channel: ~a" (channel-error-detail c)))))

;;; ----------------------------------------------------------------------------
;;; Channel id
;;; ----------------------------------------------------------------------------

(defun channel-id (funding-txid funding-output-index)
  "The permanent channel id: the funding txid with the output index XORed into
   its last two bytes.

   Before the funding output exists both sides use a `temporary_channel_id` the
   opener invents; afterwards the channel is named by WHERE ITS MONEY IS, which
   means the name is verifiable against the chain and cannot be claimed twice."
  (let ((id (copy-seq (c:octets funding-txid))))
    (setf (aref id 30) (logxor (aref id 30) (ldb (byte 8 8) funding-output-index))
          (aref id 31) (logxor (aref id 31) (ldb (byte 8 0) funding-output-index)))
    id))

;;; ----------------------------------------------------------------------------
;;; open_channel (32)
;;; ----------------------------------------------------------------------------

(defstruct (open-channel (:conc-name oc-))
  chain-hash temporary-channel-id funding-satoshis push-msat
  dust-limit-satoshis max-htlc-value-in-flight-msat channel-reserve-satoshis
  htlc-minimum-msat feerate-per-kw to-self-delay max-accepted-htlcs
  funding-pubkey revocation-basepoint payment-basepoint
  delayed-payment-basepoint htlc-basepoint first-per-commitment-point
  (channel-flags 0)
  ;; `channel_type` (TLV 1) is a feature vector naming the channel's variant.
  ;; It is not optional in practice: a peer that advertises option_channel_type —
  ;; both CLN and LND do — REJECTS an open_channel without it, with
  ;; "Did not set channel_type in open_channel message".  Defaults to
  ;; option_static_remotekey, which is what the commitment builder implements:
  ;; to_remote is the payment basepoint verbatim, with no per-commitment
  ;; blinding, so a peer can always sweep it even from an outdated state.
  (channel-type (f:features-from '((:static-remotekey . :required))))
  (tlvs nil))

(defun encode-open-channel (o)
  (let ((wr (w:make-writer)))
    (w:w-chain-hash wr (oc-chain-hash o))
    (w:w-bytes wr (oc-temporary-channel-id o))
    (w:w-u64 wr (oc-funding-satoshis o))
    (w:w-u64 wr (oc-push-msat o))
    (w:w-u64 wr (oc-dust-limit-satoshis o))
    (w:w-u64 wr (oc-max-htlc-value-in-flight-msat o))
    (w:w-u64 wr (oc-channel-reserve-satoshis o))
    (w:w-u64 wr (oc-htlc-minimum-msat o))
    (w:w-u32 wr (oc-feerate-per-kw o))
    (w:w-u16 wr (oc-to-self-delay o))
    (w:w-u16 wr (oc-max-accepted-htlcs o))
    (w:w-point wr (oc-funding-pubkey o))
    (w:w-point wr (oc-revocation-basepoint o))
    (w:w-point wr (oc-payment-basepoint o))
    (w:w-point wr (oc-delayed-payment-basepoint o))
    (w:w-point wr (oc-htlc-basepoint o))
    (w:w-point wr (oc-first-per-commitment-point o))
    (w:w-u8 wr (oc-channel-flags o))
    (when (oc-channel-type o)
      (w:w-tlv-stream wr (list (w:make-tlv-record
                                :type 1
                                :value (f:features->bytes (oc-channel-type o))))))
    (w:encode-message +msg-open-channel+ (w:writer-bytes wr))))

(defun parse-open-channel (payload)
  (handler-case
      (let ((r (w:make-reader payload)) (tlvs nil))
        (declare (ignorable tlvs))
        (make-open-channel
         :chain-hash (w:r-chain-hash r)
         :temporary-channel-id (w:r-bytes r 32)
         :funding-satoshis (w:r-u64 r) :push-msat (w:r-u64 r)
         :dust-limit-satoshis (w:r-u64 r)
         :max-htlc-value-in-flight-msat (w:r-u64 r)
         :channel-reserve-satoshis (w:r-u64 r)
         :htlc-minimum-msat (w:r-u64 r)
         :feerate-per-kw (w:r-u32 r)
         :to-self-delay (w:r-u16 r) :max-accepted-htlcs (w:r-u16 r)
         :funding-pubkey (w:r-point r)
         :revocation-basepoint (w:r-point r)
         :payment-basepoint (w:r-point r)
         :delayed-payment-basepoint (w:r-point r)
         :htlc-basepoint (w:r-point r)
         :first-per-commitment-point (w:r-point r)
         :channel-flags (w:r-u8 r)
         ;; Unknown trailing TLVs are legal and ignored — that is how the message
         ;; grows without breaking older peers.
         :tlvs (unless (w:reader-eof-p r)
                 (handler-case (w:r-tlv-stream r) (error () nil)))))
    (error (e) (error 'channel-error :detail (format nil "bad open_channel: ~a" e)))))

;;; ----------------------------------------------------------------------------
;;; accept_channel (33)
;;;
;;; The same shape minus the things only the opener decides — funding amount,
;;; push, feerate, chain — plus `minimum_depth`, which is the accepter saying how
;;; many confirmations it wants before it will believe the funding output.
;;; ----------------------------------------------------------------------------

(defstruct (accept-channel (:conc-name ac-))
  temporary-channel-id dust-limit-satoshis max-htlc-value-in-flight-msat
  channel-reserve-satoshis htlc-minimum-msat minimum-depth
  to-self-delay max-accepted-htlcs
  funding-pubkey revocation-basepoint payment-basepoint
  delayed-payment-basepoint htlc-basepoint first-per-commitment-point
  (tlvs nil))

(defun encode-accept-channel (a)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (ac-temporary-channel-id a))
    (w:w-u64 wr (ac-dust-limit-satoshis a))
    (w:w-u64 wr (ac-max-htlc-value-in-flight-msat a))
    (w:w-u64 wr (ac-channel-reserve-satoshis a))
    (w:w-u64 wr (ac-htlc-minimum-msat a))
    (w:w-u32 wr (ac-minimum-depth a))
    (w:w-u16 wr (ac-to-self-delay a))
    (w:w-u16 wr (ac-max-accepted-htlcs a))
    (w:w-point wr (ac-funding-pubkey a))
    (w:w-point wr (ac-revocation-basepoint a))
    (w:w-point wr (ac-payment-basepoint a))
    (w:w-point wr (ac-delayed-payment-basepoint a))
    (w:w-point wr (ac-htlc-basepoint a))
    (w:w-point wr (ac-first-per-commitment-point a))
    (w:encode-message +msg-accept-channel+ (w:writer-bytes wr))))

(defun parse-accept-channel (payload)
  (handler-case
      (let ((r (w:make-reader payload)))
        (make-accept-channel
         :temporary-channel-id (w:r-bytes r 32)
         :dust-limit-satoshis (w:r-u64 r)
         :max-htlc-value-in-flight-msat (w:r-u64 r)
         :channel-reserve-satoshis (w:r-u64 r)
         :htlc-minimum-msat (w:r-u64 r)
         :minimum-depth (w:r-u32 r)
         :to-self-delay (w:r-u16 r) :max-accepted-htlcs (w:r-u16 r)
         :funding-pubkey (w:r-point r)
         :revocation-basepoint (w:r-point r)
         :payment-basepoint (w:r-point r)
         :delayed-payment-basepoint (w:r-point r)
         :htlc-basepoint (w:r-point r)
         :first-per-commitment-point (w:r-point r)
         :tlvs (unless (w:reader-eof-p r)
                 (handler-case (w:r-tlv-stream r) (error () nil)))))
    (error (e) (error 'channel-error :detail (format nil "bad accept_channel: ~a" e)))))

;;; ----------------------------------------------------------------------------
;;; funding_created (34) / funding_signed (35) / channel_ready (36)
;;; ----------------------------------------------------------------------------

(defstruct (funding-created (:conc-name fc-))
  temporary-channel-id funding-txid funding-output-index signature)

(defun encode-funding-created (f)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (fc-temporary-channel-id f))
    ;; `funding_txid` goes on the wire in INTERNAL byte order, the same order a
    ;; transaction's prevout uses — not the reversed form block explorers print.
    (w:w-hash wr (fc-funding-txid f))
    (w:w-u16 wr (fc-funding-output-index f))
    (w:w-sig wr (fc-signature f))
    (w:encode-message +msg-funding-created+ (w:writer-bytes wr))))

(defun parse-funding-created (payload)
  (handler-case
      (let ((r (w:make-reader payload)))
        (make-funding-created
         :temporary-channel-id (w:r-bytes r 32)
         :funding-txid (w:r-hash r)
         :funding-output-index (w:r-u16 r)
         :signature (w:r-sig r)))
    (error (e) (error 'channel-error :detail (format nil "bad funding_created: ~a" e)))))

(defstruct (funding-signed (:conc-name fs-))
  channel-id signature)

(defun encode-funding-signed (f)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (fs-channel-id f))
    (w:w-sig wr (fs-signature f))
    (w:encode-message +msg-funding-signed+ (w:writer-bytes wr))))

(defun parse-funding-signed (payload)
  (handler-case
      (let ((r (w:make-reader payload)))
        (make-funding-signed :channel-id (w:r-bytes r 32) :signature (w:r-sig r)))
    (error (e) (error 'channel-error :detail (format nil "bad funding_signed: ~a" e)))))

(defstruct (channel-ready (:conc-name cr-))
  channel-id second-per-commitment-point (tlvs nil))

(defun encode-channel-ready (cr)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (cr-channel-id cr))
    ;; The SECOND point, not the first: the first was sent in open/accept, and by
    ;; the time the channel is ready the next commitment already needs its key.
    (w:w-point wr (cr-second-per-commitment-point cr))
    (w:encode-message +msg-channel-ready+ (w:writer-bytes wr))))

(defun parse-channel-ready (payload)
  (handler-case
      (let ((r (w:make-reader payload)))
        (make-channel-ready
         :channel-id (w:r-bytes r 32)
         :second-per-commitment-point (w:r-point r)
         :tlvs (unless (w:reader-eof-p r)
                 (handler-case (w:r-tlv-stream r) (error () nil)))))
    (error (e) (error 'channel-error :detail (format nil "bad channel_ready: ~a" e)))))
