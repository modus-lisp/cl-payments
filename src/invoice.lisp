;;;; src/invoice.lisp
;;;;
;;;; Phase 7 — BOLT #11: invoices.
;;;;
;;;; An invoice is the one Lightning object a human handles.  Everything else
;;;; in this system moves between daemons; this is pasted, scanned, read aloud.
;;;; Which is why it is bech32 (human-safe alphabet, checksummed) and why the
;;;; amount lives in the human-readable part rather than the data: a person
;;;; can read "lnbc2500u" and know they are about to pay 2500 micro-bitcoin.
;;;;
;;;; The rest of it is a request: a payment hash to lock the HTLC to, a payment
;;;; secret so forwarding nodes cannot probe the recipient, the payee's node id,
;;;; an expiry, a description — and a signature over all of it, so a modified
;;;; invoice is detectable.  The signature is RECOVERABLE: the payee's key is
;;;; usually not in the invoice at all, and is instead recovered from the
;;;; signature, saving 33 bytes of something a person may have to type.
;;;;
;;;; The data part is a stream of 5-bit values, because that is what bech32
;;;; carries, and every field is measured in those.  Most of the care here is
;;;; in the bit boundaries: a 256-bit hash is 52 five-bit groups with 4 bits of
;;;; padding, a 35-bit timestamp is 7 groups, and the signature covers the data
;;;; padded to a BYTE boundary — so two invoices can differ only in padding
;;;; bits and one of them is forged.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md

(defpackage #:cl-payments.invoice
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:gs #:cl-payments.gossip) (#:f #:cl-payments.features)
                    (#:enc #:cl-consensus.encoding) (#:secp #:secp256k1-fast))
  (:nicknames #:ln-invoice)
  (:export
   #:invoice #:make-invoice #:invoice-error
   #:decode-invoice #:encode-invoice #:sign-invoice
   #:inv-network #:inv-amount-msat #:inv-timestamp #:inv-payment-hash
   #:inv-payment-secret #:inv-description #:inv-description-hash #:inv-payee
   #:inv-expiry #:inv-min-final-cltv-expiry-delta #:inv-features
   #:inv-route-hints #:inv-fallbacks #:inv-fields #:inv-signature #:inv-recovery-id
   #:inv-expired-p #:inv-metadata
   #:route-hint #:rh-node-id #:rh-scid #:rh-fee-base-msat
   #:rh-fee-proportional-millionths #:rh-cltv-expiry-delta
   #:recover-pubkey #:+default-expiry+ #:+default-min-final-cltv+))

(in-package #:cl-payments.invoice)

(define-condition invoice-error (error)
  ((detail :initarg :detail :reader invoice-error-detail))
  (:report (lambda (c s) (format s "invoice: ~a" (invoice-error-detail c)))))
(defun fail (fmt &rest args) (error 'invoice-error :detail (apply #'format nil fmt args)))

(defconstant +default-expiry+ 3600)
(defconstant +default-min-final-cltv+ 18)

(defstruct (route-hint (:conc-name rh-))
  node-id scid fee-base-msat fee-proportional-millionths cltv-expiry-delta)

(defstruct (invoice (:conc-name inv-))
  network                    ; :mainnet :testnet :signet :regtest
  amount-msat                ; NIL for "any amount"
  timestamp
  ;; FIELDS is the ordered list of (type . 5-bit-values) exactly as decoded or
  ;; as we will encode them.  The accessors below are views onto it.  Keeping
  ;; the raw groups is what lets a decoded invoice re-encode byte-for-byte,
  ;; which is the only honest round-trip test.
  (fields '())
  signature recovery-id
  payee)                     ; recovered (or read from `n`) 33-byte pubkey

;;; ----------------------------------------------------------------------------
;;; 5-bit plumbing
;;; ----------------------------------------------------------------------------

(defun groups->bytes (groups &key (pad nil))
  "5-bit groups to bytes.  With PAD nil, leftover bits (fewer than 8) are
   dropped — that is how a 52-group hash yields exactly 32 bytes."
  (let ((acc 0) (bits 0) (out '()))
    (dolist (g groups)
      (setf acc (logior (ash acc 5) g) bits (+ bits 5))
      (loop while (>= bits 8)
            do (decf bits 8) (push (ldb (byte 8 bits) acc) out)))
    (when (and pad (plusp bits)) (push (ldb (byte 8 0) (ash acc (- 8 bits))) out))
    (c:bytes (coerce (nreverse out) 'vector))))

(defun bytes->groups (bytes)
  "Bytes to 5-bit groups, padding the tail with zero bits (as bech32 does)."
  (let ((acc 0) (bits 0) (out '()))
    (loop for b across (c:octets bytes)
          do (setf acc (logior (ash acc 8) b) bits (+ bits 8))
             (loop while (>= bits 5)
                   do (decf bits 5) (push (ldb (byte 5 bits) acc) out)))
    (when (plusp bits) (push (ldb (byte 5 0) (ash acc (- 5 bits))) out))
    (nreverse out)))

(defun groups->integer (groups)
  (reduce (lambda (acc g) (logior (ash acc 5) g)) groups :initial-value 0))

(defun integer->groups (n)
  "Minimal big-endian 5-bit groups; zero is a single group."
  (if (zerop n) (list 0)
      (let ((out '()))
        (loop while (plusp n) do (push (logand n 31) out) (setf n (ash n -5)))
        out)))

;;; ----------------------------------------------------------------------------
;;; The human-readable part
;;; ----------------------------------------------------------------------------

(defparameter *prefixes* '(("bcrt" . :regtest) ("tbs" . :signet) ("tb" . :testnet) ("bc" . :mainnet)))

(defun network-prefix (network)
  (or (car (find network *prefixes* :key #'cdr)) (fail "unknown network ~a" network)))

(defun parse-hrp (hrp)
  "Returns (values network amount-msat-or-nil)."
  (unless (and (> (length hrp) 2) (string= "ln" hrp :end2 2)) (fail "hrp does not start with ln"))
  (let* ((rest (subseq hrp 2))
         ;; Longest prefix first, so `tbs` is not read as `tb` + `s`.
         (entry (find-if (lambda (e) (and (>= (length rest) (length (car e)))
                                          (string= (car e) rest :end2 (length (car e)))))
                         *prefixes*)))
    (unless entry (fail "unknown currency prefix in ~a" hrp))
    (let ((amount (subseq rest (length (car entry)))))
      (values (cdr entry)
              (if (string= amount "") nil (parse-amount amount))))))

(defun parse-amount (str)
  "The amount is in BITCOIN, with an optional multiplier, and the result is
   millisatoshi.  Pico-bitcoin is a tenth of a millisatoshi, so an amount in
   `p` must be a multiple of ten: sub-millisatoshi precision does not exist on
   the network and an invoice asking for it cannot be paid exactly."
  (let* ((last (char str (1- (length str))))
         (mult (case last (#\m 8) (#\u 5) (#\n 2) (#\p -1) (t nil)))
         (digits (if mult (subseq str 0 (1- (length str))) str)))
    (unless (and (plusp (length digits)) (every #'digit-char-p digits))
      (fail "bad amount ~s" str))
    (when (and (> (length digits) 1) (char= (char digits 0) #\0)) (fail "amount has a leading zero"))
    (let ((n (parse-integer digits)) (scale (or mult 11)))   ; 1 BTC = 10^11 msat
      (if (minusp scale)
          (progn (unless (zerop (mod n 10)) (fail "sub-millisatoshi amount ~sp" digits))
                 (/ n 10))
          (* n (expt 10 scale))))))

(defun format-amount (msat)
  "The shortest exact representation, largest multiplier first."
  (cond ((null msat) "")
        ((zerop (mod msat (expt 10 11))) (format nil "~d" (/ msat (expt 10 11))))
        ((zerop (mod msat (expt 10 8))) (format nil "~dm" (/ msat (expt 10 8))))
        ((zerop (mod msat (expt 10 5))) (format nil "~du" (/ msat (expt 10 5))))
        ((zerop (mod msat 100)) (format nil "~dn" (/ msat 100)))
        (t (format nil "~dp" (* msat 10)))))

;;; ----------------------------------------------------------------------------
;;; Tagged fields
;;; ----------------------------------------------------------------------------

(defconstant +tag-p+ 1) (defconstant +tag-r+ 3) (defconstant +tag-9+ 5) (defconstant +tag-x+ 6)
(defconstant +tag-f+ 9) (defconstant +tag-d+ 13) (defconstant +tag-s+ 16) (defconstant +tag-n+ 19)
(defconstant +tag-h+ 23) (defconstant +tag-c+ 24) (defconstant +tag-m+ 27)

(defun field (inv tag) (cdr (assoc tag (inv-fields inv))))

(defun %hash-field (inv tag)
  "A 256-bit field is exactly 52 groups; any other length is skipped, as the
   spec requires — an unexpected length means an unknown variant, not an error."
  (let ((g (field inv tag))) (and g (= 52 (length g)) (groups->bytes g))))

(defun inv-payment-hash (inv) (%hash-field inv +tag-p+))
(defun inv-payment-secret (inv) (%hash-field inv +tag-s+))
(defun inv-description-hash (inv) (%hash-field inv +tag-h+))
(defun inv-description (inv)
  (let ((g (field inv +tag-d+)))
    (and g (handler-case (sb-ext:octets-to-string (groups->bytes g) :external-format :utf-8)
             (error () (fail "description is not valid UTF-8"))))))
(defun inv-metadata (inv) (let ((g (field inv +tag-m+))) (and g (groups->bytes g))))
(defun inv-expiry (inv) (let ((g (field inv +tag-x+))) (if g (groups->integer g) +default-expiry+)))
(defun inv-min-final-cltv-expiry-delta (inv)
  (let ((g (field inv +tag-c+))) (if g (groups->integer g) +default-min-final-cltv+)))
(defun inv-features (inv) (let ((g (field inv +tag-9+))) (if g (groups->integer g) 0)))
(defun inv-expired-p (inv &optional (now (- (get-universal-time) (encode-universal-time 0 0 0 1 1 1970 0))))
  (> now (+ (inv-timestamp inv) (inv-expiry inv))))

(defun inv-route-hints (inv)
  "Every `r` field, each a list of hops: 51 bytes per hop."
  (loop for (tag . groups) in (inv-fields inv)
        when (= tag +tag-r+)
          collect (let ((bytes (groups->bytes groups)))
                    (unless (zerop (mod (length bytes) 51)) (fail "route hint is not a multiple of 51 bytes"))
                    (loop for off from 0 below (length bytes) by 51
                          collect (let ((r (w:make-reader bytes :start off)))
                                    (make-route-hint :node-id (w:r-bytes r 33)
                                                     :scid (gs:u64->scid (w:r-u64 r))
                                                     :fee-base-msat (w:r-u32 r)
                                                     :fee-proportional-millionths (w:r-u32 r)
                                                     :cltv-expiry-delta (w:r-u16 r)))))))

(defun inv-fallbacks (inv)
  "Each `f` field as (version . program-bytes).  Version 17 and 18 are the
   legacy P2PKH/P2SH hashes; 0..16 are witness versions."
  (loop for (tag . groups) in (inv-fields inv)
        when (= tag +tag-f+)
          collect (cons (first groups) (groups->bytes (rest groups)))))

;;; ----------------------------------------------------------------------------
;;; Signature and recovery
;;; ----------------------------------------------------------------------------

(defun signing-hash (hrp data-groups)
  "SHA256 of the hrp's bytes followed by the data groups packed to a BYTE
   boundary with zero bits.  The padding is part of what is signed."
  (c:sha256 (c:bytes (c:ascii->bytes hrp) (groups->bytes data-groups :pad t))))

(defun recover-pubkey (hash r s recid)
  "Public-key recovery: the point Q = r⁻¹(sR − zG) where R has x = r and the
   parity RECID says.  Returns the compressed key or NIL.  Two invoices that
   differ only in the recovery id recover to different payees, so this is not
   a convenience — it is the verification."
  (secp:secp-init)
  (let* ((n secp:*secp256k1-n*) (p secp:*secp256k1-p*)
         (x (if (logtest recid 2) (+ r n) r)))
    (when (>= x p) (return-from recover-pubkey nil))
    ;; y² = x³ + 7; p ≡ 3 mod 4, so the square root is a single exponentiation
    ;; and squaring it back tells us whether x is on the curve at all.
    (let* ((y2 (mod (+ (secp:mod-expt x 3 p) 7) p))
           (y (secp:mod-expt y2 (floor (1+ p) 4) p))
           (rpt (and (= (mod (* y y) p) y2) (cons x y))))
      (unless rpt (return-from recover-pubkey nil))
      (when (/= (logand (secp:secp-y rpt) 1) (logand recid 1))
        (setf rpt (cons (secp:secp-x rpt) (- p (secp:secp-y rpt)))))
      (let* ((z (secp:bytes-to-int (c:octets hash)))
             (rinv (secp:secp-inv-mod r n))
             (sr (secp:secp-mul-point s rpt))
             (zg (secp:secp-mul-point z (secp:secp-generator)))
             (neg-zg (cons (secp:secp-x zg) (- p (secp:secp-y zg))))
             (q (secp:secp-mul-point rinv (secp:secp-add-points sr neg-zg))))
        (and (not (secp:secp-inf-p q)) (c:compressed-pubkey q))))))

;;; ----------------------------------------------------------------------------
;;; Decoding
;;; ----------------------------------------------------------------------------

(defun decode-invoice (string)
  "Parse and VERIFY.  Returns the invoice with its payee set — recovered from
   the signature, or taken from `n` and checked against the signature, so a
   decoded invoice is always one whose signature is good."
  ;; bech32 is case-insensitive but MUST NOT be mixed-case: the checksum is
  ;; computed over one case, and a mixed string is either a typo or a trick.
  (when (and (some #'upper-case-p string) (some #'lower-case-p string))
    (fail "mixed-case invoice"))
  (multiple-value-bind (hrp data const)
      (handler-case (enc:bech32-decode string)
        (error (e) (fail "bad bech32: ~a" e)))
    (unless (= const enc::+bech32-const+) (fail "invoice uses bech32m; BOLT #11 requires bech32"))
    (unless (>= (length data) (+ 7 104)) (fail "data part too short for a timestamp and a signature"))
    (multiple-value-bind (network amount) (parse-hrp hrp)
      (let* ((timestamp (groups->integer (subseq data 0 7)))
             (sig-groups (subseq data (- (length data) 104)))
             (body (subseq data 0 (- (length data) 104)))
             (fields '()))
        ;; Tagged fields: type, 10-bit length, data.
        (let ((pos 7))
          (loop while (< pos (length body))
                do (when (> (+ pos 3) (length body)) (fail "truncated tagged field header"))
                   (let* ((type (nth pos body))
                          (len (+ (* 32 (nth (+ pos 1) body)) (nth (+ pos 2) body)))
                          (start (+ pos 3)) (end (+ start len)))
                     (when (> end (length body)) (fail "tagged field overruns the data"))
                     (push (cons type (subseq body start end)) fields)
                     (setf pos end))))
        (setf fields (nreverse fields))
        (let* ((sig (groups->bytes sig-groups))
               (r (secp:bytes-to-int (subseq sig 0 32)))
               (s (secp:bytes-to-int (subseq sig 32 64)))
               (recid (aref sig 64))
               (hash (signing-hash hrp body))
               (inv (make-invoice :network network :amount-msat amount :timestamp timestamp
                                  :fields fields :signature (subseq sig 0 64) :recovery-id recid)))
          (unless (<= recid 3) (fail "recovery id ~d out of range" recid))
          (unless (inv-payment-hash inv) (fail "no payment hash"))
          ;; The payment secret is mandatory: without it any forwarding node can
          ;; probe whether the recipient has the invoice by guessing a hash.
          (unless (inv-payment-secret inv) (fail "no payment secret (s field)"))
          (let ((n-field (let ((g (field inv +tag-n+))) (and g (= 53 (length g)) (groups->bytes g)))))
            (cond
              (n-field
               ;; When the payee says who it is, that claim is what we verify —
               ;; and, as libsecp256k1 does, only a low-S signature verifies.
               ;; Recovery below tolerates high S (the spec has a valid example
               ;; of one); explicit verification does not.
               (when (> s (floor secp:*secp256k1-n* 2)) (fail "non-canonical (high-S) signature"))
               (unless (handler-case (secp:ecdsa-verify (c:parse-pubkey n-field) (c:octets hash) r s)
                         (error () nil))
                 (fail "signature does not verify against the n field"))
               (setf (inv-payee inv) n-field))
              (t
               (let ((pk (recover-pubkey hash r s recid)))
                 (unless pk (fail "signature is not recoverable"))
                 (setf (inv-payee inv) pk)))))
          inv)))))

;;; ----------------------------------------------------------------------------
;;; Encoding
;;; ----------------------------------------------------------------------------

(defun data-groups (inv)
  "Timestamp and tagged fields as 5-bit groups — the part that gets signed."
  (let ((ts (integer->groups (inv-timestamp inv))))
    (append (make-list (- 7 (length ts)) :initial-element 0) ts
            (loop for (type . groups) in (inv-fields inv)
                  append (list* type (floor (length groups) 32) (mod (length groups) 32) groups)))))

(defun hrp-of (inv)
  (format nil "ln~a~a" (network-prefix (inv-network inv)) (format-amount (inv-amount-msat inv))))

(defun encode-invoice (inv)
  "The bech32 string.  INV must already be signed."
  (unless (inv-signature inv) (fail "invoice is not signed"))
  (enc:bech32-encode (hrp-of inv)
                     (append (data-groups inv)
                             (bytes->groups (c:bytes (inv-signature inv) (vector (inv-recovery-id inv)))))))

(defun sign-invoice (inv privkey)
  "Sign in place and return the invoice.  RFC 6979 makes this deterministic,
   which is what lets the spec's examples be reproduced exactly."
  (let ((hash (signing-hash (hrp-of inv) (data-groups inv))))
    (multiple-value-bind (r s v) (secp:ecdsa-sign-raw privkey (c:octets hash))
      (setf (inv-signature inv) (c:bytes (secp:int-to-bytes32 r) (secp:int-to-bytes32 s))
            (inv-recovery-id inv) v
            (inv-payee inv) (c:compressed-pubkey (c:pubkey-of privkey)))
      inv)))

(defun make-invoice-for (&key network amount-msat payment-hash payment-secret description
                             (timestamp (- (get-universal-time) (encode-universal-time 0 0 0 1 1 1970 0)))
                             (expiry nil) (min-final-cltv nil) (features nil) route-hints)
  "Build an unsigned invoice from the fields a recipient actually chooses.
   Field order follows the common convention (p, s, d, x, c, r, 9)."
  (let ((fields '()))
    (push (cons +tag-p+ (bytes->groups payment-hash)) fields)
    (push (cons +tag-s+ (bytes->groups payment-secret)) fields)
    (when description
      (push (cons +tag-d+ (bytes->groups (sb-ext:string-to-octets description :external-format :utf-8))) fields))
    (when expiry (push (cons +tag-x+ (integer->groups expiry)) fields))
    (when min-final-cltv (push (cons +tag-c+ (integer->groups min-final-cltv)) fields))
    (dolist (hops route-hints)
      (let ((wr (w:make-writer)))
        (dolist (h hops)
          (w:w-bytes wr (rh-node-id h)) (w:w-u64 wr (gs:scid->u64 (rh-scid h)))
          (w:w-u32 wr (rh-fee-base-msat h)) (w:w-u32 wr (rh-fee-proportional-millionths h))
          (w:w-u16 wr (rh-cltv-expiry-delta h)))
        (push (cons +tag-r+ (bytes->groups (w:writer-bytes wr))) fields)))
    (when features (push (cons +tag-9+ (integer->groups features)) fields))
    (make-invoice :network network :amount-msat amount-msat :timestamp timestamp
                  :fields (nreverse fields))))
(export 'make-invoice-for)
