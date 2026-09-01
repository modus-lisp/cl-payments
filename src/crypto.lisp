;;;; src/crypto.lisp
;;;;
;;;; Phase 0 — the cryptographic primitives BOLT #8 is built out of.
;;;;
;;;; Lightning's transport needs four things Bitcoin's does not: HKDF (RFC 5869)
;;;; to ratchet a chaining key, ChaCha20-Poly1305 (RFC 8439) as the AEAD, ECDH
;;;; over secp256k1, and a nonce discipline.  Curve arithmetic comes from
;;;; secp256k1-fast (the same crypto cl-consensus validates against Bitcoin Core);
;;;; ChaCha20 and Poly1305 come from ironclad as *separate* primitives — ironclad
;;;; ships the stream cipher and the MAC but no packaged ChaCha20-Poly1305 AEAD,
;;;; so the RFC 8439 construction (one-time key from block 0, payload from block 1,
;;;; padded MAC input) is assembled here and checked against the RFC's own vectors
;;;; in inspect/crypto-test.lisp.
;;;;
;;;; Nothing in this file knows about Lightning messages or sockets.
;;;;
;;;; References: RFC 5869 (HKDF), RFC 8439 (ChaCha20-Poly1305), BOLT #8.

(defpackage #:cl-payments.crypto
  (:use #:cl)
  (:nicknames #:ln-crypto)
  (:local-nicknames (#:secp #:secp256k1-fast) (#:schnorr #:secp256k1-fast.schnorr)
                    (#:ic #:ironclad))
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
   #:ecdh))

(in-package #:cl-payments.crypto)

;;; ----------------------------------------------------------------------------
;;; Byte helpers
;;; ----------------------------------------------------------------------------

(deftype u8v () '(vector (unsigned-byte 8)))

(defun octets (x)
  "Coerce X to a simple (unsigned-byte 8) vector — ironclad wants one."
  (coerce x '(simple-array (unsigned-byte 8) (*))))

(defun bytes (&rest seqs)
  (octets (apply #'concatenate '(vector (unsigned-byte 8)) seqs)))

(defun zeros (n)
  (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defun ascii->bytes (s)
  (octets (map 'vector #'char-code s)))

(defun bytes->hex (b) (string-downcase (ic:byte-array-to-hex-string (octets b))))
(defun hex->bytes (s) (ic:hex-string-to-byte-array s))

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

(defun sha256 (b) (ic:digest-sequence :sha256 (octets b)))

(defun hmac-sha256 (key data)
  (let ((h (ic:make-hmac (octets key) :sha256)))
    (ic:update-hmac h (octets data))
    (ic:hmac-digest h)))

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
  "BOLT #8's HKDF: 64 bytes split into two 32-byte halves, returned as values."
  (let ((o (hkdf salt ikm)))
    (values (subseq o 0 32) (subseq o 32 64))))

;;; ----------------------------------------------------------------------------
;;; ChaCha20-Poly1305 AEAD (RFC 8439)
;;;
;;; ironclad's :chacha with a 12-byte IV is RFC 8439 ChaCha20 starting at block
;;; counter 0.  RFC 8439 wants the Poly1305 one-time key from block 0 and the
;;; payload keystream from block 1 onward — so encrypting a buffer of 64 zero
;;; bytes followed by the plaintext yields both from a single cipher instance:
;;; bytes 0..31 are the one-time key, bytes 64.. are the ciphertext.
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
  (let* ((n (length payload))
         (buf (zeros (+ 64 n)))
         (c (ic:make-cipher :chacha :key (octets key)
                                    :initialization-vector (octets nonce)
                                    :mode :stream)))
    (replace buf payload :start1 64)
    (ic:encrypt-in-place c buf)
    (values (subseq buf 0 32) (subseq buf 64))))

(defun %poly1305-tag (otk ad ct)
  "RFC 8439 §2.8: MAC over AAD ‖ pad16 ‖ ciphertext ‖ pad16 ‖ len(AAD) ‖ len(CT)."
  (let ((m (ic:make-mac :poly1305 (octets otk))))
    (ic:update-mac m (octets ad))
    (ic:update-mac m (zeros (%pad16 (length ad))))
    (ic:update-mac m (octets ct))
    (ic:update-mac m (zeros (%pad16 (length ct))))
    (ic:update-mac m (%u64le (length ad)))
    (ic:update-mac m (%u64le (length ct)))
    (ic:produce-mac m)))

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
  (and (integerp k) (< 0 k secp:*secp256k1-n*)))

(defun pubkey-of (privkey)
  "The point for a private-key integer."
  (secp:secp-pubkey privkey))

(defun generate-key ()
  "A fresh private key as an integer in [1, n).  Returns (values privkey point)."
  (loop for k = (secp:bytes-to-int (ic:random-data 32))
        when (valid-privkey-p k)
          return (values k (pubkey-of k))))

(defun ecdh (point privkey)
  "BOLT #8 ECDH: SHA-256 of the *compressed* shared point.  The hash is part of
   the definition — the raw x-coordinate is not what Lightning mixes in."
  (sha256 (compressed-pubkey (secp:secp-mul-point privkey point))))
