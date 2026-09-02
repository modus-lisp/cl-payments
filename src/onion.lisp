;;;; src/onion.lisp
;;;;
;;;; Phase 6 — BOLT #4: the Sphinx onion.
;;;;
;;;; A payment crosses several nodes, and the point of the onion is that each of
;;;; them learns exactly one thing: what to do next.  Not who sent the payment,
;;;; not where it ends, not how many hops remain — only "forward this much, with
;;;; this expiry, over that channel".  The packet is a fixed 1366 bytes at every
;;;; hop, so its size says nothing either.
;;;;
;;;; The construction is a layered stream cipher.  For each hop the sender
;;;; derives a shared secret by ECDH, encrypts the whole 1300-byte payload area
;;;; with a ChaCha20 stream keyed from it, and prepends that hop's own payload.
;;;; A hop reverses one layer: ECDH with its own key, strip its payload, and
;;;; forward the rest — which is still ciphertext to it.  The ephemeral public
;;;; key is BLINDED at each hop so two hops cannot tell they handled the same
;;;; packet.
;;;;
;;;; The subtle part is the filler.  Each hop shifts the payload area left when
;;;; it removes its own payload, and pads the end with zeros before applying its
;;;; stream — so the tail of what the next hop sees is bytes no one chose,
;;;; obfuscated by every stream so far.  The sender has to reproduce exactly
;;;; that tail in advance or the HMACs will not verify at any hop.  Get the
;;;; filler wrong and the packet is rejected at hop one with "bad HMAC", which
;;;; is also what a corrupted packet looks like.
;;;;
;;;; Errors come back the same road in reverse, wrapped once per hop with an
;;;; independent key, so only the sender can read them — and can tell which hop
;;;; spoke, by which key unwraps to a valid HMAC.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/04-onion-routing.md

(defpackage #:cl-payments.onion
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:gs #:cl-payments.gossip) (#:secp #:secp256k1-fast)
                    (#:ic #:ironclad))
  (:nicknames #:ln-onion)
  (:export
   #:+packet-size+ #:+payload-area+ #:+hmac-size+
   #:onion-error
   ;; keys
   #:generate-key #:cipher-stream #:shared-secret #:blinding-factor
   #:ephemeral-keys-and-secrets
   ;; hop payloads
   #:hop-payload #:make-hop-payload #:encode-hop-payload #:parse-hop-payload
   #:hp-amount-msat #:hp-cltv-expiry #:hp-scid #:hp-payment-secret #:hp-total-msat
   ;; the packet
   #:create-onion #:peel-onion #:generate-filler
   ;; errors
   #:encode-failure-message #:parse-failure-message
   #:create-failure-packet #:wrap-failure-packet #:decrypt-failure-packet))

(in-package #:cl-payments.onion)

(define-condition onion-error (error)
  ((detail :initarg :detail :reader onion-error-detail))
  (:report (lambda (c s) (format s "onion: ~a" (onion-error-detail c)))))
(defun fail (fmt &rest args) (error 'onion-error :detail (apply #'format nil fmt args)))

(defconstant +payload-area+ 1300)
(defconstant +hmac-size+ 32)
(defconstant +packet-size+ (+ 1 33 +payload-area+ +hmac-size+))   ; 1366
(defconstant +curve-order+ #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

;;; ----------------------------------------------------------------------------
;;; Keys
;;; ----------------------------------------------------------------------------

(defun generate-key (type secret)
  "HMAC-SHA256 keyed by the ASCII key TYPE — \"rho\", \"mu\", \"um\", \"pad\",
   \"ammag\" — over the shared secret.  The type is NOT NUL-terminated: three
   bytes for rho, not four.  A trailing zero yields a different key at every hop
   and a packet nobody can read."
  (c:hmac-sha256 (c:ascii->bytes type) (c:octets secret)))

(defun cipher-stream (key length)
  "LENGTH bytes of ChaCha20 keystream under KEY with a 96-bit zero nonce.  The
   fixed nonce is safe because no key is ever used twice."
  (let ((buf (make-array length :element-type '(unsigned-byte 8) :initial-element 0))
        (cipher (ic:make-cipher :chacha :key (c:octets key)
                                        :initialization-vector (c:zeros 12) :mode :stream)))
    (ic:encrypt-in-place cipher buf)
    buf))

(defun xor! (a b &key (start 0))
  "A[start+i] ^= B[i], in place."
  (loop for i from 0 below (length b)
        do (setf (aref a (+ start i)) (logxor (aref a (+ start i)) (aref b i))))
  a)

(defun shared-secret (privkey pubkey)
  "SHA256 of the compressed ECDH point — the same convention BOLT #8 uses."
  (c:ecdh (c:parse-pubkey pubkey) privkey))

(defun blinding-factor (ephemeral-pubkey shared-secret)
  (c:sha256 (c:bytes (c:octets ephemeral-pubkey) (c:octets shared-secret))))

(defun ephemeral-keys-and-secrets (session-key pubkeys)
  "Walk the route once, producing each hop's ephemeral public key and shared
   secret.  The ephemeral SCALAR is blinded at each hop by multiplying with the
   blinding factor; a hop blinds the POINT by the same factor and arrives at the
   same next key without ever holding the scalar."
  (let ((e session-key) (epks '()) (secrets '()))
    (dolist (pk pubkeys)
      (let* ((epk (c:compressed-pubkey (c:pubkey-of e)))
             (ss (shared-secret e pk))
             (bf (secp:bytes-to-int (blinding-factor epk ss))))
        (push epk epks) (push ss secrets)
        (setf e (mod (* e bf) +curve-order+))))
    (values (nreverse epks) (nreverse secrets))))

;;; ----------------------------------------------------------------------------
;;; Hop payloads: the TLV each hop reads
;;; ----------------------------------------------------------------------------

(defstruct (hop-payload (:conc-name hp-))
  amount-msat cltv-expiry
  scid              ; for an intermediate hop: where to forward
  payment-secret    ; for the final hop
  total-msat)

(defun encode-hop-payload (hp)
  "The TLV stream, prefixed by its bigsize length — the form that is spliced
   into the onion.  Types: 2 amt_to_forward, 4 outgoing_cltv_value,
   6 short_channel_id, 8 payment_data."
  (let ((recs '()))
    (flet ((tu (n width) (let ((wr (w:make-writer))) (w:w-tu wr n width) (w:writer-bytes wr))))
      (push (w:make-tlv-record :type 2 :value (tu (hp-amount-msat hp) 8)) recs)
      (push (w:make-tlv-record :type 4 :value (tu (hp-cltv-expiry hp) 4)) recs)
      (when (hp-scid hp)
        (let ((wr (w:make-writer))) (w:w-u64 wr (gs:scid->u64 (hp-scid hp)))
          (push (w:make-tlv-record :type 6 :value (w:writer-bytes wr)) recs)))
      (when (hp-payment-secret hp)
        (push (w:make-tlv-record
               :type 8 :value (c:bytes (c:octets (hp-payment-secret hp))
                                       (tu (or (hp-total-msat hp) (hp-amount-msat hp)) 8)))
              recs)))
    (let ((body (let ((wr (w:make-writer))) (w:w-tlv-stream wr (nreverse recs)) (w:writer-bytes wr)))
          (wr (w:make-writer)))
      (w:w-bigsize wr (length body))
      (w:w-bytes wr body)
      (w:writer-bytes wr))))

(defun parse-hop-payload (bytes)
  "BYTES is the TLV stream WITHOUT the length prefix (the peeler strips it).

   Whether a hop is final is decided by the onion — an all-zero next HMAC — not
   by the payload.  A final payload carries payment_data only when the sender
   had a payment secret to put in it; Core Lightning's `sendpay` with a bare
   payment hash sends just the amount and expiry, and that is legal.  So the
   only hard requirement here is the pair every payload must have."
  (let* ((recs (w:r-tlv-stream (w:make-reader bytes)))
         (get (lambda (ty) (w:tlv-get recs ty)))
         (amt (funcall get 2)) (cltv (funcall get 4))
         (scid (funcall get 6)) (pd (funcall get 8)))
    (unless (and amt cltv) (fail "hop payload lacks amt_to_forward or outgoing_cltv_value"))
    (make-hop-payload
     :amount-msat (w:r-tu (w:make-reader amt) 8)
     :cltv-expiry (w:r-tu (w:make-reader cltv) 4)
     :scid (and scid (gs:u64->scid (w:r-u64 (w:make-reader scid))))
     :payment-secret (and pd (subseq pd 0 32))
     :total-msat (and pd (w:r-tu (w:make-reader pd :start 32) 8)))))

;;; ----------------------------------------------------------------------------
;;; Construction
;;; ----------------------------------------------------------------------------

(defun generate-filler (secrets payloads)
  "The obfuscated padding every hop will have appended by the time the LAST hop
   reads the packet, computed in route order over all hops but the last.

   Each intermediate hop shifts the payload area left by its own payload plus
   HMAC, zero-fills the gap, and XORs the whole area with its stream.  The
   sender reproduces that: grow the filler by each hop's payload+HMAC, then XOR
   with the TAIL of that hop's stream — the part of the stream that lands on the
   bytes beyond the 1300 the hop actually holds."
  (let ((filler (c:zeros 0)))
    (loop for ss in secrets for payload in payloads
          do (let* ((grown (c:bytes filler (c:zeros (+ (length payload) +hmac-size+))))
                    (stream (cipher-stream (generate-key "rho" ss)
                                           (+ +payload-area+ (length payload) +hmac-size+)))
                    (tail (subseq stream (- (length stream) (length grown)))))
               (setf filler (xor! grown tail))))
    filler))

(defun create-onion (session-key pubkeys payloads associated-data)
  "Build the packet for a route.  PAYLOADS are length-prefixed TLV blobs, one
   per hop, in route order; the last is the final recipient's.  Returns
   (values packet shared-secrets) — the secrets are what the sender needs later
   to read a returned error."
  (unless (= (length pubkeys) (length payloads)) (fail "one payload per hop"))
  (when (> (reduce #'+ payloads :key (lambda (p) (+ (length p) +hmac-size+))) +payload-area+)
    (fail "payloads do not fit in ~d bytes" +payload-area+))
  (multiple-value-bind (epks secrets) (ephemeral-keys-and-secrets session-key pubkeys)
    (let* ((filler (generate-filler (butlast secrets) (butlast payloads)))
           ;; The initial payload area is random-looking bytes from the pad key
           ;; so the unused tail carries no structure.
           (area (cipher-stream (generate-key "pad" (secp:int-to-bytes32 session-key)) +payload-area+))
           (hmac (c:zeros +hmac-size+))
           (ad (c:octets associated-data)))
      ;; Reverse order: the last hop's layer goes on first.
      (loop for i from (1- (length pubkeys)) downto 0
            do (let* ((payload (nth i payloads)) (ss (nth i secrets))
                      (shift (+ (length payload) +hmac-size+))
                      (next (c:bytes payload hmac (subseq area 0 (- +payload-area+ shift)))))
                 (xor! next (cipher-stream (generate-key "rho" ss) +payload-area+))
                 ;; Only the last hop's layer takes the filler: it is what every
                 ;; EARLIER hop will have left behind by the time this layer is read.
                 (when (= i (1- (length pubkeys)))
                   (replace next filler :start1 (- +payload-area+ (length filler))))
                 (setf area next
                       hmac (c:hmac-sha256 (generate-key "mu" ss) (c:bytes area ad)))))
      (values (c:bytes (vector 0) (c:octets (first epks)) area hmac) secrets))))

;;; ----------------------------------------------------------------------------
;;; Peeling
;;; ----------------------------------------------------------------------------

(defun peel-onion (packet privkey associated-data)
  "Remove our layer.  Returns (values payload-bytes next-packet shared-secret),
   where NEXT-PACKET is NIL if we are the final hop.  PAYLOAD-BYTES is the TLV
   stream without its length prefix.

   The HMAC is checked BEFORE anything is decrypted or parsed.  A packet that
   fails it tells us nothing we should act on, including how long it claims to
   be."
  (unless (= (length packet) +packet-size+) (fail "packet is ~d bytes, not ~d" (length packet) +packet-size+))
  (unless (zerop (aref packet 0)) (fail "unknown onion version ~d" (aref packet 0)))
  (let* ((epk (subseq packet 1 34))
         (area (subseq packet 34 (+ 34 +payload-area+)))
         (hmac (subseq packet (+ 34 +payload-area+)))
         (ss (handler-case (shared-secret privkey epk)
               (error () (fail "ephemeral key is not a valid point"))))
         (expected (c:hmac-sha256 (generate-key "mu" ss) (c:bytes area (c:octets associated-data)))))
    (unless (c:ct-equal expected hmac) (fail "bad HMAC"))
    ;; Pad with 1300 zeros, then XOR with 2600 bytes of stream: this decrypts
    ;; our layer AND encrypts the zero tail into the filler the next hop expects.
    (let* ((unwrapped (xor! (c:bytes area (c:zeros +payload-area+))
                            (cipher-stream (generate-key "rho" ss) (* 2 +payload-area+))))
           (r (w:make-reader unwrapped))
           (len (handler-case (w:r-bigsize r) (error () (fail "malformed payload length")))))
      (when (< len 2) (fail "payload length ~d is too short" len))
      (when (> (+ (w:reader-pos r) len +hmac-size+) (length unwrapped))
        (fail "payload length ~d overruns the packet" len))
      (let* ((payload (w:r-bytes r len))
             (next-hmac (w:r-bytes r +hmac-size+))
             (consumed (w:reader-pos r)))
        (if (every #'zerop next-hmac)
            (values payload nil ss)
            (let* ((bf (secp:bytes-to-int (blinding-factor epk ss)))
                   (next-epk (c:compressed-pubkey (secp:secp-mul-point bf (c:parse-pubkey epk))))
                   (next-area (subseq unwrapped consumed (+ consumed +payload-area+))))
              (values payload
                      (c:bytes (vector 0) next-epk next-area next-hmac)
                      ss)))))))

;;; ----------------------------------------------------------------------------
;;; Errors
;;; ----------------------------------------------------------------------------

(defconstant +failure-pad-to+ 1024
  "Failure messages are padded so their length does not reveal which failure
   occurred.  The spec's vector pads a 320-byte message with 704 bytes: the
   total is 1024, not the 256 of earlier versions.  A node padding to 256 is
   distinguishable from every other node on the network by the size of its
   errors alone.")

(defun encode-failure-message (code &key channel-update extra)
  "The failuremsg: a u16 code, then whatever that code carries — for UPDATE
   failures a u16 length and the channel_update (without its message type)."
  (let ((wr (w:make-writer)))
    (w:w-u16 wr code)
    (when channel-update
      (w:w-u16 wr (length channel-update))
      (w:w-bytes wr channel-update))
    (when extra (w:w-bytes wr extra))
    (w:writer-bytes wr)))

(defun parse-failure-message (bytes)
  "Returns (values code rest)."
  (let ((r (w:make-reader bytes)))
    (values (w:r-u16 r) (w:r-rest r))))

(defun create-failure-packet (shared-secret failure-message)
  "The erring node's return packet: HMAC(um) over [len, msg, pad_len, pad],
   then the whole thing XORed with the ammag stream.  Every hop on the way back
   adds its own ammag layer; only the sender holds all of them."
  (let* ((msg (c:octets failure-message))
         (pad-len (max 0 (- +failure-pad-to+ (length msg))))
         (wr (w:make-writer)))
    (w:w-u16 wr (length msg)) (w:w-bytes wr msg)
    (w:w-u16 wr pad-len) (w:w-bytes wr (c:zeros pad-len))
    (let* ((body (w:writer-bytes wr))
           (hmac (c:hmac-sha256 (generate-key "um" shared-secret) body)))
      (wrap-failure-packet shared-secret (c:bytes hmac body)))))

(defun wrap-failure-packet (shared-secret packet)
  "One more layer, applied by the erring node and by each hop it passes."
  (let ((p (copy-seq (c:octets packet))))
    (xor! p (cipher-stream (generate-key "ammag" shared-secret) (length p)))))

(defun decrypt-failure-packet (shared-secrets packet)
  "At the origin: unwrap one hop at a time, in route order, until the HMAC
   verifies.  Returns (values hop-index failure-message), or NIL if no hop's key
   produces a valid packet — which means the reason was mangled in transit, or
   was never a failure onion at all."
  (let ((p (copy-seq (c:octets packet))))
    (loop for ss in shared-secrets for i from 0
          do (setf p (wrap-failure-packet ss p))
             (let* ((hmac (subseq p 0 +hmac-size+))
                    (body (subseq p +hmac-size+)))
               (when (c:ct-equal hmac (c:hmac-sha256 (generate-key "um" ss) body))
                 (let* ((r (w:make-reader body))
                        (len (w:r-u16 r)))
                   (when (> len (length body)) (return nil))
                   (return (values i (w:r-bytes r len)))))))))
