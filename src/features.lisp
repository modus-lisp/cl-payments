;;;; src/features.lisp
;;;;
;;;; Phase 2 — BOLT #9 feature bits.
;;;;
;;;; Every feature occupies a PAIR of bits: an even one meaning "I require this,
;;;; and you must fail the connection if you don't understand it" and the odd one
;;;; above it meaning "I support this, ignore it if you don't".  The rule of thumb
;;;; the spec states as "it's ok to be odd" is the whole forward-compatibility
;;;; story of the protocol: unknown odd bits are ignored, unknown EVEN bits are
;;;; fatal.
;;;;
;;;; The wire encoding is easy to get subtly wrong and then very confusing.  Bit 0
;;;; is the least-significant bit of the LAST byte, so the vector reads
;;;; right-to-left across the byte string.  That happens to make the whole vector
;;;; exactly a big-endian integer, which is how it is represented here — an
;;;; integer, not a byte array.  Every awkward index calculation disappears and
;;;; `logbitp` is the accessor.
;;;;
;;;; Advertising nothing is not a safe default: LND closes the connection
;;;; immediately after `init` if the peer doesn't offer the features it needs.
;;;; *DEFAULT-FEATURES* below is the set that both Core Lightning and LND accept.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/09-features.md

(defpackage #:cl-payments.features
  (:use #:cl)
  (:nicknames #:ln-features)
  (:local-nicknames (#:c #:cl-payments.crypto))
  (:export
   #:+features+ #:feature-name #:feature-bit
   #:features-from #:features->bytes #:bytes->features
   #:feature-supported-p #:feature-required-p #:feature-set-p
   #:unknown-required-bits #:describe-features
   #:check-dependencies #:feature-error
   #:*default-features* #:*known-bits*))

(in-package #:cl-payments.features)

;;; ----------------------------------------------------------------------------
;;; The registry.  Each entry is (even-bit name), the odd bit being even+1.
;;; ----------------------------------------------------------------------------

(defparameter +features+
  '((0  . :data-loss-protect)
    (4  . :upfront-shutdown-script)
    (6  . :gossip-queries)
    (8  . :var-onion-optin)
    (10 . :gossip-queries-ex)
    (12 . :static-remotekey)
    (14 . :payment-secret)
    (16 . :basic-mpp)
    (18 . :support-large-channel)
    (20 . :anchor-outputs)
    (22 . :anchors-zero-fee-htlc-tx)
    (24 . :route-blinding)
    (26 . :shutdown-anysegwit)
    (28 . :dual-fund)
    (30 . :amp)
    (38 . :onion-messages)
    (44 . :channel-type)
    (46 . :scid-alias)
    (48 . :payment-metadata)
    (50 . :zeroconf))
  "Even bit → feature name.  Not exhaustive: unknown ODD bits are legal and
   ignored, which is exactly why this list doesn't have to be complete.")

(defun feature-bit (name)
  (or (car (rassoc name +features+))
      (error "unknown feature ~s" name)))

(defun feature-name (bit)
  "Name for BIT, whether the required (even) or optional (odd) half."
  (cdr (assoc (if (evenp bit) bit (1- bit)) +features+)))

(defparameter *known-bits*
  (let ((s '()))
    (dolist (f +features+ s)
      (push (car f) s) (push (1+ (car f)) s)))
  "Every bit we understand, both halves.")

;;; ----------------------------------------------------------------------------
;;; Construction and the wire form
;;;
;;; A feature vector IS an integer here (see the header): bit N of the integer is
;;; feature bit N, and the wire form is that integer big-endian.
;;; ----------------------------------------------------------------------------

(define-condition feature-error (error)
  ((detail :initarg :detail :reader feature-error-detail))
  (:report (lambda (c s) (format s "feature negotiation: ~a" (feature-error-detail c)))))

(defun features-from (spec)
  "Build a feature vector from SPEC, a list of (name . :required|:optional).
   Signals if a feature is asked for both ways — setting both bits of a pair is
   explicitly forbidden, and a peer is entitled to drop us for it."
  (let ((v 0) (seen '()))
    (dolist (entry spec v)
      (destructuring-bind (name . kind) entry
        (let ((bit (feature-bit name)))
          (when (member name seen)
            (error 'feature-error :detail (format nil "~a specified twice" name)))
          (push name seen)
          (setf v (logior v (ash 1 (ecase kind
                                     (:required bit)
                                     (:optional (1+ bit)))))))))))

(defun features->bytes (features)
  "Minimal big-endian encoding.  Length is whatever it takes; a peer reads the
   length from the enclosing field, so there is no padding to a fixed width."
  (if (zerop features)
      (c:octets #())
      (let* ((nbytes (ceiling (integer-length features) 8))
             (out (make-array nbytes :element-type '(unsigned-byte 8))))
        (loop for i from 0 below nbytes
              do (setf (aref out (- nbytes 1 i)) (ldb (byte 8 (* 8 i)) features)))
        out)))

(defun bytes->features (bytes)
  (let ((v 0))
    (loop for b across bytes do (setf v (logior (ash v 8) b)))
    v))

;;; ----------------------------------------------------------------------------
;;; Queries
;;; ----------------------------------------------------------------------------

(defun feature-set-p (features bit) (logbitp bit features))

(defun feature-supported-p (features name)
  "T if NAME is offered at all — either half of the pair.  This is what callers
   almost always want: for deciding whether a peer can do something, `required`
   versus `optional` is the sender's problem, not ours."
  (let ((bit (feature-bit name)))
    (or (logbitp bit features) (logbitp (1+ bit) features))))

(defun feature-required-p (features name)
  (logbitp (feature-bit name) features))

(defun unknown-required-bits (features)
  "The even bits set in FEATURES that we don't know.  BOLT #1 says the connection
   MUST fail if this is non-empty: the peer is telling us it depends on something
   we can't do, so continuing would mean silently misbehaving."
  (loop for bit from 0 below (integer-length features)
        when (and (evenp bit) (logbitp bit features) (not (feature-name bit)))
          collect bit))

;;; BOLT #9 states dependencies between features; advertising a feature without
;;; its prerequisite is invalid and some implementations will drop the
;;; connection for it.
(defparameter +dependencies+
  '((:payment-secret          . (:var-onion-optin))
    (:basic-mpp               . (:payment-secret))
    (:gossip-queries-ex       . (:gossip-queries))
    (:anchor-outputs          . (:static-remotekey))
    (:anchors-zero-fee-htlc-tx . (:static-remotekey))
    (:route-blinding          . (:var-onion-optin))
    (:zeroconf                . (:scid-alias))
    (:amp                     . (:payment-secret))))

(defun check-dependencies (features)
  "Signal if FEATURES advertises something without its prerequisite."
  (dolist (dep +dependencies+ t)
    (destructuring-bind (feature . requires) dep
      (when (feature-supported-p features feature)
        (dolist (r requires)
          (unless (feature-supported-p features r)
            (error 'feature-error
                   :detail (format nil "~a requires ~a" feature r))))))))

(defun describe-features (features)
  "Human-readable list of (bit name required-p) for everything set — including
   bits we don't recognise, which is the interesting part when a peer refuses us."
  (loop for bit from 0 below (integer-length features)
        when (logbitp bit features)
          collect (list bit (or (feature-name bit) :unknown) (evenp bit))))

;;; ----------------------------------------------------------------------------
;;; What we advertise
;;; ----------------------------------------------------------------------------

(defparameter *default-features*
  (features-from
   '(;; Both CLN and LND mark these five REQUIRED in their own init, and LND
     ;; hangs up on a peer that doesn't offer them.  We advertise them as
     ;; OPTIONAL (odd): honest about being able to speak them at the transport
     ;; and messaging level, without demanding the peer treat them as mandatory.
     (:data-loss-protect . :optional)
     (:var-onion-optin   . :optional)
     (:static-remotekey  . :optional)
     (:payment-secret    . :optional)
     (:channel-type      . :optional)
     ;; Needed before we can ask for the routing graph in Phase 3.
     (:gossip-queries    . :optional)
     ;; We can parse a large-channel announcement; nothing here opens one yet.
     (:support-large-channel . :optional))
   )
  "The feature vector cl-payments sends in `init`.

   Deliberately conservative: everything ODD.  An even bit is a demand that the
   peer fail the connection if it can't do the thing, and we are in no position
   to make demands — we advertise what we can genuinely participate in and let
   the peer decide.  Adding a feature here is a claim we can honour it, so this
   list grows as the BOLTs land, not before.")
