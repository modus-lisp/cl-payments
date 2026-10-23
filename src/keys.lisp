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
   #:per-commitment-point #:per-commitment-secret #:export-per-commitment-secret
   #:generate-from-seed #:+max-commitment-index+ #:secret-point
   #:shachain #:make-shachain #:shachain-insert #:shachain-lookup #:shachain->plist #:plist->shachain
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

(defun %tweak-into (out &rest parts)
  "OUT <- SHA-256 of the concatenated PARTS (public byte vectors), streamed — the
   per-commitment tweaks.  OUT is fixed because the tweak is about to be added to
   a secret scalar, and secp256k1-fast will take it from nowhere else."
  (natrium:with-sha256 (h)
    (dolist (p parts) (natrium:sha256-update h (c:octets p)))
    (natrium:sha256-final-into h out)))

(defun %out-or-acquire (out)
  (or out (gossamer:acquire :octets 32)))

(defmacro %filling ((var out) &body body)
  "Bind VAR to OUT or a fresh pooled buffer; if BODY signals and the buffer was
   ours, return it to the pool before the error propagates."
  (let ((given (gensym "GIVEN")))
    `(let* ((,given ,out) (,var (%out-or-acquire ,given)))
       (handler-bind ((error (lambda (e) (declare (ignore e)) (unless ,given (gossamer:free ,var)))))
         ,@body)
       ,var)))

(defun derive-privkey (basepoint-secret per-commitment-point &optional out)
  "privkey = basepoint_secret + SHA256(per_commitment_point ‖ basepoint)

   The basepoint in the hash is the PUBLIC one, so both sides hash the same
   bytes — the holder of the secret just also knows the scalar.

   BASEPOINT-SECRET is a fixed 32-byte key; the result goes into OUT (fixed) or,
   when OUT is NIL, a fresh POOLED buffer the caller frees."
  (let ((basepoint (c:compressed-pubkey (c:pubkey-of basepoint-secret))))
    (%filling (k out)
      (gossamer:with-fixed-scratch ((tweak :octets 32))
        (%tweak-into tweak per-commitment-point basepoint)
        (secp:seckey-tweak-add-into basepoint-secret tweak k)))))

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

(defun derive-revocation-privkey (revocation-basepoint-secret per-commitment-secret &optional out)
  "The scalar for DERIVE-REVOCATION-PUBKEY — computable only with both secrets,
   which is the whole design.  Both are fixed 32-byte keys, and so is the result
   (OUT, or a fresh pooled buffer the caller frees): two constant-time
   multiplications by the public hashes and a sum, all in fixed scratch."
  (let ((rb (c:compressed-pubkey (c:pubkey-of revocation-basepoint-secret)))
        (pcp (c:compressed-pubkey (c:pubkey-of per-commitment-secret))))
    (%filling (k out)
      (gossamer:with-fixed-scratch ((h1 :octets 32) (h2 :octets 32) (t1 :octets 32) (t2 :octets 32))
        (%tweak-into h1 rb pcp)
        (%tweak-into h2 pcp rb)
        (secp:seckey-tweak-mul-into revocation-basepoint-secret h1 t1)
        (secp:seckey-tweak-mul-into per-commitment-secret h2 t2)
        (secp:seckey-add-into t1 t2 k)))))

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

(defun generate-from-seed (seed index &optional out)
  "BOLT #3 generate_from_seed: the per-commitment secret for INDEX.

   SEED is OUR shachain seed, a fixed 32-byte buffer: whoever holds it can produce
   every per-commitment secret of the channel, including the current one, and an
   unrevoked secret in the peer's hands lets them sweep us.  So the walk happens
   in place in OUT (fixed; a fresh POOLED buffer the caller frees when NIL), each
   step re-hashed by natrium straight back into it."
  (gossamer:check-fixed seed "shachain seed")
  (%filling (p out)
    (replace p seed)
    (loop for b from 47 downto 0
          when (logbitp b index)
            do (setf (aref p (floor b 8))
                     (logxor (aref p (floor b 8)) (ash 1 (mod b 8))))
               (natrium:sha256-into p p))))

(defun per-commitment-secret (seed index)
  "Our per-commitment secret for INDEX, in a fresh POOLED fixed buffer the caller
   frees.  (It becomes public only by EXPORT-PER-COMMITMENT-SECRET.)"
  (generate-from-seed seed index))

(defun export-per-commitment-secret (seed index)
  "EXPORT: the per-commitment secret for INDEX as ordinary heap bytes — for
   revoke_and_ack, where handing it to the peer is the whole point.  Call this only
   for an index that is being revoked; for any other it is leaking a live key."
  (gossamer:with-fixed-scratch ((s :octets 32))
    (generate-from-seed seed index s)
    (copy-seq s)))

(defun per-commitment-point (seed index)
  (gossamer:with-fixed-scratch ((s :octets 32))
    (generate-from-seed seed index s)
    (c:compressed-pubkey (c:pubkey-of s))))

(defun secret-point (secret-bytes)
  "The compressed point of a 32-byte secret that is ALREADY public to us — a
   per-commitment secret the peer revealed in revoke_and_ack.  It is carried into
   fixed scratch only because that is the one form secp256k1-fast multiplies by G
   (in constant time); nothing here keeps it."
  (gossamer:with-fixed-scratch ((s :octets 32))
    (replace s secret-bytes)
    (c:compressed-pubkey (c:pubkey-of s))))

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

(defun shachain->plist (chain)
  "The retained secrets, for persistence.  Losing these is losing the ability
   to punish: an old commitment we can no longer prove revoked is one the peer
   can publish for free."
  (loop for i from 0 below 49
        for secret = (aref (shachain-known chain) i)
        when secret collect (list :index (aref (shachain-indices chain) i)
                                  :secret (c:bytes->hex (c:octets secret)))))

(defun plist->shachain (plist)
  ;; Reconstruct each secret's BUCKET from its index instead of trusting list
  ;; position.  SHACHAIN-KNOWN is indexed by trailing-zero count; the serialized
  ;; order only *happens* to match while the occupied buckets form a contiguous
  ;; prefix (which pure count-down operation guarantees).  Recomputing the bucket
  ;; makes this a true inverse of SHACHAIN->PLIST under any gap, reordering, or
  ;; non-strict insertion path — and losing a bucket is losing the ability to
  ;; punish the states it covered.
  (let ((chain (make-shachain)))
    (loop for entry in plist
          for idx = (getf entry :index)
          for b = (%count-trailing-zeros idx)
          do (setf (aref (shachain-known chain) b) (c:hex->bytes (getf entry :secret))
                   (aref (shachain-indices chain) b) idx))
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
