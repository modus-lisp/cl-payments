;;;; src/keys.lisp
;;;;
;;;; Phase 4/5 — BOLT #3 key derivation.
;;;;
;;;; A channel does not use one key per party.  Every commitment transaction is
;;;; locked to a DIFFERENT set of keys, derived from a long-lived "basepoint"
;;;; plus a per-commitment point that changes each time the channel advances.
;;;; The reason is the penalty mechanism: when you revoke an old commitment you
;;;; hand your counterparty the secret behind that commitment's per-commitment
;;;; point, which lets them — and only them, and only for that one old state —
;;;; reconstruct a private key that sweeps your funds if you ever publish it.
;;;;
;;;; So there are two directions of derivation here and they are not symmetric:
;;;;
;;;;   DERIVE-PUBKEY / DERIVE-PRIVKEY   ordinary blinding.  Anyone holding the
;;;;     basepoint and the per-commitment point computes the public key; only
;;;;     the basepoint's owner can compute the private one.
;;;;
;;;;   DERIVE-REVOCATION-PUBKEY         deliberately requires BOTH secrets to
;;;;     invert.  It is a 2-of-2 in the exponent: the revocation basepoint's
;;;;     owner cannot spend without the per-commitment secret, and whoever holds
;;;;     the per-commitment secret cannot spend without the basepoint's secret.
;;;;     Revocation is exactly the act of releasing the second half.
;;;;
;;;; The per-commitment secrets themselves come from a single 32-byte seed via a
;;;; derivation that lets a node store only a handful of secrets and still
;;;; produce any earlier one on demand — a channel may have millions of old
;;;; states and every one of them must remain punishable.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/03-transactions.md

(defpackage #:cl-payments.keys
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:secp #:secp256k1-fast))
  (:nicknames #:ln-keys)
  (:export
   #:derive-pubkey #:derive-privkey
   #:derive-revocation-pubkey #:derive-revocation-privkey
   #:per-commitment-point #:per-commitment-secret
   #:generate-from-seed #:+max-commitment-index+
   #:shachain #:make-shachain #:shachain-insert #:shachain-lookup
   #:commitment-keys #:derive-commitment-keys
   #:ck-local #:ck-remote #:ck-delayed #:ck-revocation #:ck-local-htlc #:ck-remote-htlc
   #:key-error))

(in-package #:cl-payments.keys)

(define-condition key-error (error)
  ((detail :initarg :detail :reader key-error-detail))
  (:report (lambda (c s) (format s "BOLT #3 keys: ~a" (key-error-detail c)))))

(defun %n () secp:*secp256k1-n*)

(defun %point+ (a b) (secp:secp-add-points a b))
(defun %point* (k p) (secp:secp-mul-point (mod k (%n)) p))

;;; ----------------------------------------------------------------------------
;;; Ordinary per-commitment blinding
;;; ----------------------------------------------------------------------------

(defun derive-pubkey (basepoint per-commitment-point)
  "pubkey = basepoint + SHA256(per_commitment_point ‖ basepoint) * G

   Note the hash argument ORDER — per-commitment point first, basepoint second.
   The reverse also produces a perfectly good curve point, and a channel built
   on it fails only when the counterparty disagrees about where the money is."
  (let* ((bp (c:parse-pubkey basepoint))
         (pcp (c:parse-pubkey per-commitment-point))
         (tweak (secp:bytes-to-int
                 (c:sha256 (c:bytes per-commitment-point basepoint)))))
    (c:compressed-pubkey (%point+ bp (%point* tweak (secp:secp-generator))))))

(defun derive-privkey (basepoint-secret per-commitment-point)
  "privkey = basepoint_secret + SHA256(per_commitment_point ‖ basepoint)

   The basepoint in the hash is the PUBLIC one, so both sides hash the same
   bytes — the holder of the secret just also knows the scalar."
  (let* ((basepoint (c:compressed-pubkey (c:pubkey-of basepoint-secret)))
         (tweak (secp:bytes-to-int
                 (c:sha256 (c:bytes per-commitment-point basepoint)))))
    (mod (+ basepoint-secret tweak) (%n))))

;;; ----------------------------------------------------------------------------
;;; Revocation
;;; ----------------------------------------------------------------------------

(defun derive-revocation-pubkey (revocation-basepoint per-commitment-point)
  "revocationpubkey = revocation_basepoint * SHA256(revocation_basepoint ‖ per_commitment_point)
                    + per_commitment_point  * SHA256(per_commitment_point ‖ revocation_basepoint)

   Both terms, and both hash orderings.  This is what makes the key a 2-of-2 in
   the exponent: inverting it needs the revocation basepoint's secret AND the
   per-commitment secret.  Publishing an old commitment is punishable precisely
   because revoking it meant handing over the latter."
  (let* ((rb (c:parse-pubkey revocation-basepoint))
         (pcp (c:parse-pubkey per-commitment-point))
         (h1 (secp:bytes-to-int
              (c:sha256 (c:bytes revocation-basepoint per-commitment-point))))
         (h2 (secp:bytes-to-int
              (c:sha256 (c:bytes per-commitment-point revocation-basepoint)))))
    (c:compressed-pubkey (%point+ (%point* h1 rb) (%point* h2 pcp)))))

(defun derive-revocation-privkey (revocation-basepoint-secret per-commitment-secret)
  "The scalar for DERIVE-REVOCATION-PUBKEY — computable only with both secrets,
   which is the whole design."
  (let* ((rb (c:compressed-pubkey (c:pubkey-of revocation-basepoint-secret)))
         (pcp (c:compressed-pubkey (c:pubkey-of per-commitment-secret)))
         (h1 (secp:bytes-to-int (c:sha256 (c:bytes rb pcp))))
         (h2 (secp:bytes-to-int (c:sha256 (c:bytes pcp rb)))))
    (mod (+ (* revocation-basepoint-secret h1)
            (* per-commitment-secret h2))
         (%n))))

;;; ----------------------------------------------------------------------------
;;; Per-commitment secrets
;;;
;;; Commitments are numbered DOWNWARD from 2^48-1, and the secret for index I is
;;; derived from the seed by walking the bits of I from high to low: for each set
;;; bit, flip that bit in the running value and re-hash.  The consequence is that
;;; the secret for an index lets you compute the secret for any LATER index (any
;;; index with more bits set below), so a node can retain O(log n) secrets and
;;; still punish any of the millions of states it has revoked.
;;; ----------------------------------------------------------------------------

(defconstant +max-commitment-index+ 281474976710655   ; 2^48 - 1
  "Commitment numbers start here and count DOWN, so the first commitment's
   secret is the hardest to derive from and later ones fall out of it.")

(defun generate-from-seed (seed index)
  "BOLT #3 generate_from_seed: the per-commitment secret for INDEX."
  (let ((p (copy-seq (c:octets seed))))
    (loop for b from 47 downto 0
          when (logbitp b index)
            do (setf (aref p (floor b 8))
                     (logxor (aref p (floor b 8)) (ash 1 (mod b 8))))
               (setf p (c:sha256 p)))
    p))

(defun per-commitment-secret (seed index)
  (secp:bytes-to-int (generate-from-seed seed index)))

(defun per-commitment-point (seed index)
  (c:compressed-pubkey (c:pubkey-of (per-commitment-secret seed index))))

;;; --- shachain: storing revoked secrets in O(log n) --------------------------
;;;
;;; A channel that has advanced a million times has revoked a million secrets and
;;; must still be able to punish any of them.  Storing them all is not an option,
;;; so the derivation is arranged so at most 49 retained entries reproduce every
;;; secret received so far.
;;;
;;; Secrets arrive in DECREASING index order.  The bucket for an index is its
;;; number of trailing zero bits, and the invariant is that a newly-arrived
;;; secret can derive every secret already stored in a lower bucket.  The
;;; direction matters: you derive FROM the new secret DOWN to the old indices,
;;; never the reverse.  Getting it backwards makes the store reject perfectly
;;; valid secrets, which reads like a misbehaving peer.

(defstruct (shachain (:constructor make-shachain ()))
  (known (make-array 49 :initial-element nil))
  (indices (make-array 49 :initial-element 0)))

(defun %count-trailing-zeros (n)
  (if (zerop n) 48 (loop for i from 0 below 48 when (logbitp i n) return i finally (return 48))))

(defun %derive-secret (secret bits index)
  "Walk SECRET down through the low BITS bits of INDEX, flipping and re-hashing
   wherever INDEX has a bit set.  This is BOLT #3's derive_secret."
  (let ((p (copy-seq (c:octets secret))))
    (loop for b from (1- bits) downto 0
          when (logbitp b index)
            do (setf (aref p (floor b 8))
                     (logxor (aref p (floor b 8)) (ash 1 (mod b 8))))
               (setf p (c:sha256 p)))
    p))

(defun shachain-insert (chain index secret)
  "Store a revoked secret.  Signals if it contradicts one already held — a
   counterparty whose secrets disagree is either broken or lying, and either way
   the channel must not keep advancing on their word."
  (let ((bucket (%count-trailing-zeros index)))
    (loop for b from 0 below bucket
          for known = (aref (shachain-known chain) b)
          when known
            do (let ((expected (%derive-secret secret bucket (aref (shachain-indices chain) b))))
                 (unless (equalp (c:octets expected) (c:octets known))
                   (error 'key-error
                          :detail (format nil "revoked secret for index ~d contradicts ~
                                               the one already held for index ~d"
                                          index (aref (shachain-indices chain) b))))))
    (setf (aref (shachain-known chain) bucket) (c:octets secret)
          (aref (shachain-indices chain) bucket) index)
    chain))

(defun shachain-lookup (chain index)
  "The secret for INDEX, derived from whatever we retained, or NIL if INDEX has
   not been revoked yet."
  (loop for b from 0 below 49
        for known = (aref (shachain-known chain) b)
        when (and known
                  (zerop (ash (logxor index (aref (shachain-indices chain) b)) (- b))))
          return (%derive-secret known b index)
        finally (return nil)))

;;; ----------------------------------------------------------------------------
;;; The full key set for one commitment
;;; ----------------------------------------------------------------------------

(defstruct (commitment-keys (:conc-name ck-))
  local          ; to_local / HTLC-owner key for the holder
  remote         ; to_remote key for the counterparty
  delayed        ; to_local's delayed key (behind the CSV)
  revocation     ; the punishment key
  local-htlc
  remote-htlc)

(defun derive-commitment-keys (&key per-commitment-point
                                    payment-basepoint delayed-payment-basepoint
                                    htlc-basepoint revocation-basepoint
                                    remote-payment-basepoint remote-htlc-basepoint)
  "Every key that appears in one commitment transaction.

   REVOCATION-BASEPOINT is the COUNTERPARTY's — the revocation key in my
   commitment must be one only they can complete, since it exists to let them
   punish me."
  (make-commitment-keys
   :local (derive-pubkey payment-basepoint per-commitment-point)
   :remote (when remote-payment-basepoint
             (derive-pubkey remote-payment-basepoint per-commitment-point))
   :delayed (derive-pubkey delayed-payment-basepoint per-commitment-point)
   :revocation (derive-revocation-pubkey revocation-basepoint per-commitment-point)
   :local-htlc (derive-pubkey htlc-basepoint per-commitment-point)
   :remote-htlc (when remote-htlc-basepoint
                  (derive-pubkey remote-htlc-basepoint per-commitment-point))))
