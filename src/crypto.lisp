;;;; src/crypto.lisp
;;;;
;;;; Phase 0 — the cryptographic primitives BOLT #8 is built out of.
;;;;
;;;; Lightning's transport needs four things Bitcoin's does not: HKDF (RFC 5869)
;;;; to ratchet a chaining key, ChaCha20-Poly1305 (RFC 8439) as the AEAD, ECDH
;;;; over secp256k1, and a nonce discipline.  Curve arithmetic comes from
;;;; secp256k1-fast (the same crypto cl-consensus validates against Bitcoin Core);
;;;; ChaCha20, Poly1305, SHA-256, HMAC and HKDF come from natrium.  The RFC 8439
;;;; construction (one-time key from block 0, payload from block 1, padded MAC
;;;; input) is spelled out here so the BOLT #8 code reads against the RFC, and is
;;;; checked against the RFC's own vectors in inspect/crypto-test.lisp.
;;;;
;;;; Nothing in this file knows about Lightning messages or sockets.
;;;;
;;;; References: RFC 5869 (HKDF), RFC 8439 (ChaCha20-Poly1305), BOLT #8.

(defpackage #:cl-payments.crypto
  (:use #:cl)
  (:nicknames #:ln-crypto)
  (:local-nicknames (#:secp #:secp256k1-fast) (#:schnorr #:secp256k1-fast.schnorr)
                    (#:ecdh #:secp256k1-fast.ecdh))
  (:export
   ;; byte helpers
   #:bytes #:octets #:ascii->bytes #:bytes->hex #:hex->bytes #:zeros #:ct-equal
   ;; hashing
   #:sha256 #:hmac-sha256 #:hkdf #:hkdf-2
   ;; AEAD
   #:aead-encrypt #:aead-decrypt #:bolt8-nonce
   #:encrypt-with-ad #:decrypt-with-ad #:aead-auth-error
   ;; keys / ECDH
   #:compressed-pubkey #:parse-pubkey #:pubkey-of #:generate-key #:valid-privkey-p
   #:ecdh #:ecdh-into #:with-ec-scratch
   ;; secrets in fixed memory
   #:+empty+ #:hkdf-2-into #:privkey-from-bytes #:privkey-from-hex #:privkey-hex
   #:import-privkey #:export-privkey #:free-key #:copy-key))

(in-package #:cl-payments.crypto)

;;; ----------------------------------------------------------------------------
;;; Byte helpers
;;; ----------------------------------------------------------------------------

(deftype u8v () '(vector (unsigned-byte 8)))

(defun octets (x)
  "Coerce X to a simple (unsigned-byte 8) vector — natrium wants one."
  (coerce x '(simple-array (unsigned-byte 8) (*))))

(defun bytes (&rest seqs)
  (octets (apply #'concatenate '(vector (unsigned-byte 8)) seqs)))

(defun zeros (n)
  (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defun ascii->bytes (s)
  (octets (map 'vector #'char-code s)))

(defun bytes->hex (b)
  "Lower-case hex of the byte sequence B."
  (let ((out (make-string (* 2 (length b)))) (digits "0123456789abcdef"))
    (dotimes (i (length b) out)
      (let ((x (elt b i)))
        (setf (char out (* 2 i)) (char digits (ash x -4))
              (char out (1+ (* 2 i))) (char digits (logand x 15)))))))

(defun hex->bytes (s)
  "The byte vector a hex string spells.  Signals on odd length or a non-hex digit."
  (when (oddp (length s)) (error "hex->bytes: odd-length hex string ~s" s))
  (let ((out (zeros (floor (length s) 2))))
    (dotimes (i (length out) out)
      (setf (aref out i) (parse-integer s :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun ct-equal (a b)
  "Constant-time byte-vector comparison — used for AEAD tags, where an early
   return would leak how much of the tag an attacker got right."
  (and (= (length a) (length b))
       (let ((acc 0))
         (loop for i from 0 below (length a)
               do (setf acc (logior acc (logxor (aref a i) (aref b i)))))
         (zerop acc))))

;;; ----------------------------------------------------------------------------
;;; Hashing + HKDF (RFC 5869)
;;; ----------------------------------------------------------------------------

(defun sha256 (b) (natrium:sha256 (octets b)))

(defun hmac-sha256 (key data)
  (natrium:hmac-sha256 (octets key) (octets data)))

(defun hkdf (salt ikm &key (info #()) (length 64))
  "RFC 5869 HKDF-SHA256: extract-then-expand.  BOLT #8 always calls this with a
   zero-length INFO and asks for 64 bytes (two 32-byte keys)."
  (let ((prk (hmac-sha256 salt ikm))
        (out (zeros 0))
        (prev (zeros 0)))
    (loop for i from 1 to (ceiling length 32)
          do (setf prev (hmac-sha256 prk (bytes prev info (vector i)))
                   out (bytes out prev)))
    (subseq out 0 length)))

(defun hkdf-2 (salt ikm)
  "BOLT #8's HKDF: 64 bytes split into two 32-byte halves, returned as values.
   Heap output: for PUBLIC inputs only (the RFC 5869 vectors).  Anything keyed
   by a chaining key goes through HKDF-2-INTO."
  (let ((o (hkdf salt ikm)))
    (values (subseq o 0 32) (subseq o 32 64))))

(defparameter +empty+ (make-array 0 :element-type '(unsigned-byte 8)))

(defun hkdf-2-into (salt ikm out1 out2)
  "BOLT #8's HKDF over SECRET material: HKDF-SHA256(SALT, IKM, info = \"\") -> 64
   bytes, the first half into OUT1 and the second into OUT2 (both fixed 32-byte
   buffers).  The PRK and the 64-byte OKM live only in fixed scratch, and OUT1 may
   be SALT (the chaining key ratchets in place): the PRK is computed before
   anything is written."
  (gossamer:with-fixed-scratch ((okm :octets 64))
    (natrium:hkdf-into :sha256 (octets salt) (octets ikm) +empty+ okm)
    (replace out1 okm :end2 32)
    (replace out2 okm :start2 32))
  (values out1 out2))

;;; ----------------------------------------------------------------------------
;;; ChaCha20-Poly1305 AEAD (RFC 8439)
;;;
;;; RFC 8439 takes the Poly1305 one-time key from keystream block 0 and the
;;; payload keystream from block 1 onward.
;;; ----------------------------------------------------------------------------

(define-condition aead-auth-error (error) ()
  (:report "ChaCha20-Poly1305: authentication tag mismatch"))

(defun %pad16 (n)
  "Bytes of zero padding that bring N up to a 16-byte boundary."
  (if (zerop (mod n 16)) 0 (- 16 (mod n 16))))

(defun %u64le (n)
  (let ((v (zeros 8)))
    (loop for i from 0 below 8 do (setf (aref v i) (ldb (byte 8 (* 8 i)) n)))
    v))

(defun %chacha20 (key nonce payload)
  "Return (values one-time-poly1305-key, PAYLOAD xor'd with the block-1 keystream).
   XOR is its own inverse, so this serves both encryption and decryption."
  (let ((key (octets key)) (nonce (octets nonce)))
    (values (natrium:poly1305-key-gen key nonce)
            (natrium:chacha20 key nonce (octets payload) :counter 1))))

(defun %poly1305-tag (otk ad ct)
  "RFC 8439 §2.8: MAC over AAD ‖ pad16 ‖ ciphertext ‖ pad16 ‖ len(AAD) ‖ len(CT)."
  (natrium:poly1305-mac (octets otk)
                        (bytes ad (zeros (%pad16 (length ad)))
                               ct (zeros (%pad16 (length ct)))
                               (%u64le (length ad)) (%u64le (length ct)))))

(defun aead-encrypt (key nonce ad plaintext)
  "RFC 8439 AEAD_CHACHA20_POLY1305 — returns ciphertext ‖ 16-byte tag."
  (multiple-value-bind (otk ct) (%chacha20 key nonce plaintext)
    (bytes ct (%poly1305-tag otk ad ct))))

(defun aead-decrypt (key nonce ad sealed)
  "Inverse of AEAD-ENCRYPT.  Signals AEAD-AUTH-ERROR if the tag doesn't verify."
  (when (< (length sealed) 16)
    (error 'aead-auth-error))
  (let* ((split (- (length sealed) 16))
         (ct (subseq sealed 0 split))
         (tag (subseq sealed split)))
    (multiple-value-bind (otk pt) (%chacha20 key nonce ct)
      (unless (ct-equal tag (%poly1305-tag otk ad ct))
        (error 'aead-auth-error))
      pt)))

;;; --- BOLT #8's nonce discipline ----------------------------------------------

(defun bolt8-nonce (n)
  "BOLT #8 nonce: 32 bits of zeros followed by a 64-bit little-endian counter.
   (Note the endianness — Lightning differs from the big-endian counter used in
   some other Noise profiles, and getting it wrong fails only at act three.)"
  (let ((v (zeros 12)))
    (loop for i from 0 below 8 do (setf (aref v (+ 4 i)) (ldb (byte 8 (* 8 i)) n)))
    v))

(defun encrypt-with-ad (k n ad plaintext)
  "BOLT #8 encryptWithAD."
  (aead-encrypt k (bolt8-nonce n) ad plaintext))

(defun decrypt-with-ad (k n ad ciphertext)
  "BOLT #8 decryptWithAD."
  (aead-decrypt k (bolt8-nonce n) ad ciphertext))

;;; ----------------------------------------------------------------------------
;;; secp256k1 keys and ECDH
;;;
;;; Points are secp256k1-fast's representation: a (x . y) cons of integers.
;;;
;;; PRIVATE KEYS ARE FIXED 32-BYTE BUFFERS, never integers and never ordinary heap
;;; vectors (see the FIXED library): secp256k1-fast refuses anything else at every
;;; entry point that takes one.  A key that is made here (GENERATE-KEY,
;;; PRIVKEY-FROM-BYTES, ...) comes from the fixed pool and goes back with FREE-KEY;
;;; an object that holds one ties it to itself with FIXED:OWN.  The only places a
;;; key becomes heap bytes are the deliberate exports (PRIVKEY-HEX, for the state
;;; file), and the only places heap bytes become a key are the imports, which wipe
;;; the heap copy they were handed.
;;; ----------------------------------------------------------------------------

(defun compressed-pubkey (point)
  "33-byte compressed SEC encoding (02/03 by y-parity ‖ x).  Every public key on
   the Lightning wire is in this form — node ids, the ephemeral keys in the
   handshake, the keys in channel_announcement."
  (bytes (vector (if (evenp (secp:secp-y point)) 2 3))
         (secp:int-to-bytes32 (secp:secp-x point))))

(defun parse-pubkey (b)
  "Decompress a 33-byte SEC public key into a point.  Signals on anything that
   isn't a valid curve point — a peer can send us arbitrary bytes here."
  (unless (= (length b) 33)
    (error "public key must be 33 bytes, got ~d" (length b)))
  (let ((prefix (aref b 0))
        (x (secp:bytes-to-int (subseq b 1 33))))
    (unless (member prefix '(2 3))
      (error "bad compressed-pubkey prefix #x~2,'0x" prefix))
    (let ((even-pt (schnorr:lift-x x)))   ; the even-y root, or NIL if x isn't on the curve
      (unless even-pt
        (error "public key x-coordinate is not on the curve"))
      (if (= prefix 2)
          even-pt
          (cons x (- secp:*secp256k1-p* (cdr even-pt)))))))

(defun valid-privkey-p (k)
  "True iff K is a private key we can use: a FIXED 32-byte buffer holding a scalar
   in [1, n).  An integer or a heap vector is not one, whatever its value."
  (and (typep k '(simple-array (unsigned-byte 8) (32)))
       (gossamer:fixed-p k)
       (secp:seckey-valid-p k)))

(defun pubkey-of (privkey)
  "The point for PRIVKEY, a fixed 32-byte private key (constant-time k*G)."
  (secp:secp-pubkey privkey))

(defun free-key (k)
  "Wipe a pooled key buffer and return it to the pool.  NIL is ignored."
  (gossamer:free k))

(defun copy-key (k)
  "A pooled fixed copy of key buffer K (the caller frees it)."
  (gossamer:pooled-copy (gossamer:check-fixed k "private key")))

(defun privkey-from-bytes (b &key (start 0) wipe)
  "Bring 32 bytes of key material B[START,+32) into a pooled fixed buffer and
   validate it.  When WIPE, B itself is zeroed afterwards — the form for a key that
   arrived on the heap (a file, a test vector) and should not stay there.  Signals
   on 0 or >= n, after freeing the buffer."
  (let ((k (gossamer:pooled-copy b :start start :end (+ start 32))))
    (when wipe (fill b 0 :start start :end (+ start 32)))
    (unless (secp:seckey-valid-p k)
      (gossamer:free k)
      (error "invalid secp256k1 private key"))
    k))

(defun privkey-from-hex (hex)
  "IMPORT: a hex-encoded private key (from the state file) into a pooled fixed
   buffer.  The decoded heap copy is wiped before returning."
  (let ((b (hex->bytes (string-trim '(#\Newline #\Space #\Return #\Tab) hex))))
    (unwind-protect
         (progn (unless (= (length b) 32) (error "private key must be 32 bytes, got ~d" (length b)))
                (privkey-from-bytes b))
      (fill b 0))))

(defun privkey-hex (k)
  "EXPORT: K as a hex string, for the state file.  This is the one place a private
   key leaves fixed memory on purpose; the intermediate byte copy is wiped."
  (let ((b (copy-seq (octets (gossamer:check-fixed k "private key")))))
    (unwind-protect (bytes->hex b) (fill b 0))))

(defun import-privkey (x)
  "IMPORT a persisted key: a hex string (the current format), or — for state files
   written before keys lived in fixed memory — an integer.  Returns a pooled fixed
   buffer.  The integer form cannot be wiped (a bignum is immutable); it is read
   only for compatibility, and the next save writes hex."
  (etypecase x
    (string (privkey-from-hex x))
    (integer (let ((b (secp:int-to-bytes32 x)))
               (unwind-protect (privkey-from-bytes b) (fill b 0))))))

(defun export-privkey (k) (and k (privkey-hex k)))

(defun generate-key ()
  "A fresh private key, generated by natrium's CSPRNG straight into a pooled fixed
   buffer (rejection-sampled until it is in [1, n)).  Returns (values privkey
   point); FREE-KEY the key when done with it."
  (let ((k (gossamer:acquire :octets 32)))
    (handler-bind ((error (lambda (e) (declare (ignore e)) (gossamer:free k))))
      (loop (natrium:random-bytes-into k)
            (when (secp:seckey-valid-p k) (return))))
    (values k (pubkey-of k))))

(defmacro with-ec-scratch (&body body)
  "Bind secp256k1-fast's scalar-multiplication scratch space for this thread.

   The fast limb backend keeps its working buffers in GLOBAL special variables —
   fine single-threaded, and actively wrong otherwise: two threads doing point
   arithmetic at the same time overwrite each other's intermediates and the
   result comes back as the point at infinity or, worse, a valid-looking wrong
   point.  ANY thread that touches ECDH or key derivation must be inside this.

   A node talks to many peers at once, so this is not a corner case — it is the
   normal operating condition.  Expands to nothing on builds without the limb
   backend, where the portable path has no shared state."
  ;; Resolved with FIND-SYMBOL rather than written as SECP256K1-FAST:... — a
  ;; package-qualified symbol is read before the COND ever runs, so naming a
  ;; macro that an older secp256k1-fast doesn't export makes this file fail to
  ;; COMPILE rather than fall back.
  ;;
  ;; WITH-FRESH-CT-SCRATCH covers the constant-time base multiply (behind
  ;; SECP-PUBKEY and both signature schemes) AND the field arithmetic beneath it.
  ;; WITH-FRESH-SCRATCH alone covers only the latter, which is not enough — it is
  ;; accepted here so the system still builds, with a warning, but such a build
  ;; corrupts keys under concurrent load.
  (let ((ct (find-symbol "WITH-FRESH-CT-SCRATCH" "SECP256K1-FAST"))
        (fs (find-symbol "WITH-FRESH-SCRATCH" "SECP256K1-FAST")))
    (cond ((and ct (macro-function ct)) `(,ct ,@body))
          ((and fs (macro-function fs))
           (warn "secp256k1-fast has no WITH-FRESH-CT-SCRATCH: concurrent key ~
                  derivation will silently corrupt. Update the dependency.")
           `(,fs ,@body))
          (t `(progn ,@body)))))

(defun ecdh-into (point privkey out &key (start 0))
  "BOLT #8 ECDH: SHA-256 of the *compressed* shared point, written into OUT at
   START (OUT fixed: it is a shared secret).  The hash is part of the definition —
   the raw x-coordinate is not what Lightning mixes in.  PRIVKEY is a fixed key;
   the multiplication is secp256k1-fast's constant-time ladder, and the shared
   point exists only in fixed scratch."
  (gossamer:with-fixed-scratch ((pt :octets 33))
    (ecdh:ecdh-compressed-into privkey point pt)
    (natrium:sha256-into pt out :start start))
  out)

(defun ecdh (point privkey)
  "ECDH-INTO a fresh POOLED 32-byte buffer; the caller frees it (FREE-KEY)."
  (let ((out (gossamer:acquire :octets 32)))
    (handler-bind ((error (lambda (e) (declare (ignore e)) (gossamer:free out))))
      (ecdh-into point privkey out))))
