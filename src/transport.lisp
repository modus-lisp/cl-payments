;;;; src/transport.lisp
;;;;
;;;; Phase 1 — BOLT #8: the encrypted and authenticated transport.
;;;;
;;;; Every byte between two Lightning nodes rides inside this.  It is the Noise
;;;; Protocol Framework's `Noise_XK` handshake, instantiated over secp256k1 /
;;;; ChaCha20-Poly1305 / SHA-256, followed by a framed transport where each
;;;; message is preceded by its own separately-encrypted 2-byte length.
;;;;
;;;; XK is the right pattern for Lightning and the shape follows from it: the
;;;; initiator already Knows the responder's static key (it's the node id in the
;;;; connection string), while the responder learns the initiator's identity only
;;;; in act three — so an eavesdropper never sees who dialed, and a peer can't be
;;;; probed for its identity by a stranger.  Three acts, 50 + 50 + 66 bytes.
;;;;
;;;; The three acts are written as pure state transitions over a HANDSHAKE
;;;; struct, deliberately separate from any socket, because BOLT #8's test
;;;; vectors pin the ephemeral keys — the only way to reproduce them is to inject
;;;; `e` rather than generate it.  HANDSHAKE-AS-INITIATOR / -AS-RESPONDER drive
;;;; those transitions over a real stream; inspect/transport-test.lisp drives the
;;;; same transitions with the spec's fixed keys.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/08-transport.md

(defpackage #:cl-payments.transport
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:secp #:secp256k1-fast) (#:tr #:cl-transport))
  (:nicknames #:ln-transport)
  (:export
   ;; handshake state (exposed so the BOLT #8 vectors can drive it directly)
   #:handshake #:make-initiator-handshake #:make-responder-handshake
   #:handshake-ck #:handshake-h #:handshake-temp-k #:handshake-remote-static
   #:act-one-write #:act-one-read #:act-two-write #:act-two-read
   #:act-three-write #:act-three-read
   ;; the encrypted transport
   #:noise #:noise-p #:noise-remote-node-id #:noise-stream #:noise-closer
   #:noise-sk #:noise-rk #:noise-sn #:noise-rn
   #:noise-send #:noise-recv #:noise-close
   ;; driving it over a stream
   #:handshake-as-initiator #:handshake-as-responder
   #:connect-peer #:accept-peer
   ;; conditions
   #:transport-error #:handshake-error #:peer-closed
   ;; constants
   #:+act-one-size+ #:+act-two-size+ #:+act-three-size+ #:+key-rotation-interval+))

(in-package #:cl-payments.transport)

;;; ----------------------------------------------------------------------------
;;; Constants
;;; ----------------------------------------------------------------------------

(defparameter +protocol-name+ "Noise_XK_secp256k1_ChaChaPoly_SHA256")
(defparameter +prologue+ "lightning")

(defconstant +act-one-size+ 50)     ; version(1) + ephemeral pubkey(33) + tag(16)
(defconstant +act-two-size+ 50)     ; same shape as act one
(defconstant +act-three-size+ 66)   ; version(1) + encrypted static(33+16) + tag(16)
(defconstant +header-size+ 18)      ; encrypted u16 length + tag
(defconstant +mac-size+ 16)

(defconstant +key-rotation-interval+ 1000
  "BOLT #8 rotates each direction's key every 1000 messages, so a compromised
   key exposes a bounded window rather than the whole session.")

(define-condition transport-error (error) ())

(define-condition handshake-error (transport-error)
  ((detail :initarg :detail :reader handshake-error-detail))
  (:report (lambda (c s) (format s "BOLT #8 handshake failed: ~a"
                                 (handshake-error-detail c)))))

(define-condition peer-closed (transport-error) ()
  (:report "peer closed the connection"))

;;; ----------------------------------------------------------------------------
;;; Handshake state
;;;
;;; `ck` is the chaining key — every ECDH result is mixed into it, so by act
;;; three it commits to all three shared secrets.  `h` is the running handshake
;;; hash: every byte either party sends is folded in, and it is used as the AEAD
;;; associated data, which is what binds each act to the exact transcript that
;;; preceded it.  A man-in-the-middle who alters any earlier byte produces a
;;; different `h` and the next tag fails to verify.
;;; ----------------------------------------------------------------------------

(defstruct handshake
  ck                  ; chaining key (32 bytes)
  h                   ; handshake hash (32 bytes)
  temp-k              ; the act's temporary AEAD key (32 bytes)
  s-priv              ; our static private key (integer)
  s-pub               ; our static public key (33 bytes)
  e-priv              ; our ephemeral private key (integer)
  e-pub               ; our ephemeral public key (33 bytes)
  re                  ; their ephemeral public key (33 bytes)
  remote-static       ; their static public key (33 bytes)
  initiator-p)

(defun %mix-hash (hs data)
  (setf (handshake-h hs) (c:sha256 (c:bytes (handshake-h hs) data))))

(defun %mix-key (hs input-key-material)
  "Ratchet the chaining key with a new shared secret, yielding this act's AEAD key."
  (multiple-value-bind (ck temp-k) (c:hkdf-2 (handshake-ck hs) input-key-material)
    (setf (handshake-ck hs) ck
          (handshake-temp-k hs) temp-k)))

(defun %initialize (hs responder-static-pubkey)
  "Both sides seed `h` and `ck` from the protocol name, then fold in the prologue
   and the RESPONDER's static key — the initiator because it knows it in advance,
   the responder because it is its own."
  (let ((h (c:sha256 (c:ascii->bytes +protocol-name+))))
    (setf (handshake-ck hs) h
          (handshake-h hs) h)
    (%mix-hash hs (c:ascii->bytes +prologue+))
    (%mix-hash hs responder-static-pubkey)
    hs))

(defun make-initiator-handshake (local-privkey remote-node-id &key ephemeral)
  "REMOTE-NODE-ID is the responder's 33-byte compressed static public key.
   EPHEMERAL, when supplied, is the private key to use for `e` — production code
   leaves it NIL so a fresh key is generated; the BOLT #8 vectors supply it."
  (let ((hs (make-handshake :s-priv local-privkey
                            :s-pub (c:compressed-pubkey (c:pubkey-of local-privkey))
                            :remote-static remote-node-id
                            :e-priv ephemeral
                            :initiator-p t)))
    (%initialize hs remote-node-id)))

(defun make-responder-handshake (local-privkey &key ephemeral)
  (let* ((s-pub (c:compressed-pubkey (c:pubkey-of local-privkey)))
         (hs (make-handshake :s-priv local-privkey :s-pub s-pub
                             :e-priv ephemeral
                             :initiator-p nil)))
    (%initialize hs s-pub)))

(defun %ensure-ephemeral (hs)
  (unless (handshake-e-priv hs)
    (setf (handshake-e-priv hs) (c:generate-key)))
  (setf (handshake-e-pub hs)
        (c:compressed-pubkey (c:pubkey-of (handshake-e-priv hs))))
  hs)

(defun %check-version (byte)
  (unless (zerop byte)
    (error 'handshake-error
           :detail (format nil "unsupported handshake version ~d" byte))))

(defun %decrypt (key nonce ad ciphertext what)
  (handler-case (c:decrypt-with-ad key nonce ad ciphertext)
    (c:aead-auth-error ()
      (error 'handshake-error :detail (format nil "~a failed to authenticate" what)))))

;;; --- Act one: initiator → responder, 50 bytes --------------------------------

(defun act-one-write (hs)
  "e, es — send our ephemeral key and prove we know the responder's static key."
  (%ensure-ephemeral hs)
  (%mix-hash hs (handshake-e-pub hs))
  (%mix-key hs (c:ecdh (c:parse-pubkey (handshake-remote-static hs))
                       (handshake-e-priv hs)))
  (let ((tag (c:encrypt-with-ad (handshake-temp-k hs) 0 (handshake-h hs) #())))
    (%mix-hash hs tag)
    (c:bytes #(0) (handshake-e-pub hs) tag)))

(defun act-one-read (hs msg)
  (unless (= (length msg) +act-one-size+)
    (error 'handshake-error :detail (format nil "act one is ~d bytes, expected ~d"
                                            (length msg) +act-one-size+)))
  (%check-version (aref msg 0))
  (let ((re (subseq msg 1 34))
        (tag (subseq msg 34 50)))
    ;; PARSE-PUBKEY validates the point is on the curve before we do anything
    ;; with it — this is the first attacker-controlled value in the session.
    (let ((re-point (handler-case (c:parse-pubkey re)
                      (error () (error 'handshake-error
                                       :detail "act one ephemeral key is not a curve point")))))
      (setf (handshake-re hs) re)
      (%mix-hash hs re)
      (%mix-key hs (c:ecdh re-point (handshake-s-priv hs)))
      (%decrypt (handshake-temp-k hs) 0 (handshake-h hs) tag "act one")
      (%mix-hash hs tag)
      hs)))

;;; --- Act two: responder → initiator, 50 bytes --------------------------------

(defun act-two-write (hs)
  "e, ee — the responder's ephemeral key and the ephemeral-ephemeral secret."
  (%ensure-ephemeral hs)
  (%mix-hash hs (handshake-e-pub hs))
  (%mix-key hs (c:ecdh (c:parse-pubkey (handshake-re hs)) (handshake-e-priv hs)))
  (let ((tag (c:encrypt-with-ad (handshake-temp-k hs) 0 (handshake-h hs) #())))
    (%mix-hash hs tag)
    (c:bytes #(0) (handshake-e-pub hs) tag)))

(defun act-two-read (hs msg)
  (unless (= (length msg) +act-two-size+)
    (error 'handshake-error :detail (format nil "act two is ~d bytes, expected ~d"
                                            (length msg) +act-two-size+)))
  (%check-version (aref msg 0))
  (let* ((re (subseq msg 1 34))
         (tag (subseq msg 34 50))
         (re-point (handler-case (c:parse-pubkey re)
                     (error () (error 'handshake-error
                                      :detail "act two ephemeral key is not a curve point")))))
    (setf (handshake-re hs) re)
    (%mix-hash hs re)
    (%mix-key hs (c:ecdh re-point (handshake-e-priv hs)))
    (%decrypt (handshake-temp-k hs) 0 (handshake-h hs) tag "act two")
    (%mix-hash hs tag)
    hs))

;;; --- Act three: initiator → responder, 66 bytes ------------------------------

(defun act-three-write (hs)
  "s, se — reveal our static key (encrypted to the ephemeral secret, so only this
   responder ever learns who dialed) and prove we hold it."
  (let ((c (c:encrypt-with-ad (handshake-temp-k hs) 1 (handshake-h hs)
                              (handshake-s-pub hs))))
    (%mix-hash hs c)
    (%mix-key hs (c:ecdh (c:parse-pubkey (handshake-re hs)) (handshake-s-priv hs)))
    (let ((tag (c:encrypt-with-ad (handshake-temp-k hs) 0 (handshake-h hs) #())))
      (values (c:bytes #(0) c tag)
              ;; Initiator sends with the FIRST half, receives with the second.
              (multiple-value-bind (sk rk) (c:hkdf-2 (handshake-ck hs) #())
                (%make-session hs sk rk))))))

(defun act-three-read (hs msg)
  (unless (= (length msg) +act-three-size+)
    (error 'handshake-error :detail (format nil "act three is ~d bytes, expected ~d"
                                            (length msg) +act-three-size+)))
  (%check-version (aref msg 0))
  (let ((c (subseq msg 1 50))
        (tag (subseq msg 50 66)))
    (let ((rs (%decrypt (handshake-temp-k hs) 1 (handshake-h hs) c
                        "act three static key")))
      (%mix-hash hs c)
      (let ((rs-point (handler-case (c:parse-pubkey rs)
                        (error () (error 'handshake-error
                                         :detail "act three static key is not a curve point")))))
        (setf (handshake-remote-static hs) rs)
        (%mix-key hs (c:ecdh rs-point (handshake-e-priv hs)))
        (%decrypt (handshake-temp-k hs) 0 (handshake-h hs) tag "act three")
        ;; Responder's keys are the mirror image of the initiator's.
        (multiple-value-bind (rk sk) (c:hkdf-2 (handshake-ck hs) #())
          (values (%make-session hs sk rk) hs))))))

;;; ----------------------------------------------------------------------------
;;; The encrypted transport
;;;
;;; After the handshake each direction has an independent key, nonce counter, and
;;; chaining key.  A message goes out as two AEAD ciphertexts: an 18-byte header
;;; (the encrypted u16 length plus its tag) and the body plus its tag.  The
;;; length is encrypted rather than sent in the clear so a passive observer can't
;;; even read message sizes off the wire.
;;; ----------------------------------------------------------------------------

(defstruct (noise (:constructor %make-noise))
  stream
  closer                    ; thunk that tears the connection down
  remote-node-id            ; their 33-byte static pubkey
  sk sn s-ck                ; sending key / nonce / chaining key
  rk rn r-ck                ; receiving key / nonce / chaining key
  (lock (bordeaux-threads:make-lock "noise")))

(defun %make-session (hs sk rk)
  (%make-noise :remote-node-id (handshake-remote-static hs)
               :sk sk :sn 0 :s-ck (handshake-ck hs)
               :rk rk :rn 0 :r-ck (handshake-ck hs)))

(defmacro %maybe-rotate (ck-place key-place nonce-place)
  "BOLT #8 key rotation: at nonce 1000, ratchet this direction's chaining key and
   derive a fresh AEAD key, resetting the counter.  The two directions rotate
   independently, so this is a macro over whichever triple of places applies."
  `(when (= ,nonce-place +key-rotation-interval+)
     (multiple-value-bind (new-ck new-k) (c:hkdf-2 ,ck-place ,key-place)
       (setf ,ck-place new-ck
             ,key-place new-k
             ,nonce-place 0))))

(defun %frame (n payload)
  "Encrypt PAYLOAD into an on-the-wire frame — an 18-byte encrypted length header
   followed by the encrypted body — advancing this direction's nonce and rotating
   its key if due.  Split out from NOISE-SEND so the BOLT #8 message vectors can
   be checked without a socket; NOISE-SEND is just this plus a write."
  (when (> (length payload) w:+max-message-size+)
    (error 'transport-error))
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t
                           :fill-pointer 0)))
    (flet ((emit (bytes) (loop for b across bytes do (vector-push-extend b out))))
      ;; header
      (%maybe-rotate (noise-s-ck n) (noise-sk n) (noise-sn n))
      (let ((len (let ((lw (w:make-writer)))
                   (w:w-u16 lw (length payload))
                   (w:writer-bytes lw))))
        (emit (c:encrypt-with-ad (noise-sk n) (noise-sn n) #() len)))
      (incf (noise-sn n))
      ;; body
      (%maybe-rotate (noise-s-ck n) (noise-sk n) (noise-sn n))
      (emit (c:encrypt-with-ad (noise-sk n) (noise-sn n) #() payload))
      (incf (noise-sn n)))
    (c:octets out)))

(defun noise-send (n payload)
  "Frame and send one Lightning message.  PAYLOAD is the already-encoded message
   (type ‖ body) from the wire layer."
  (bordeaux-threads:with-lock-held ((noise-lock n))
    (let ((frame (%frame n payload)))
      (write-sequence frame (noise-stream n))
      (force-output (noise-stream n))
      (length payload))))

(defun %read-exactly (stream count)
  (let ((buf (make-array count :element-type '(unsigned-byte 8))))
    (loop with got = 0
          while (< got count)
          for n = (read-sequence buf stream :start got)
          do (when (<= n got) (error 'peer-closed))
             (setf got n))
    buf))

(defun noise-recv (n)
  "Read one Lightning message.  Returns the decrypted payload (type ‖ body)."
  (bordeaux-threads:with-lock-held ((noise-lock n))
    (%maybe-rotate (noise-r-ck n) (noise-rk n) (noise-rn n))
    (let* ((header (%read-exactly (noise-stream n) +header-size+))
           (len-bytes (handler-case
                          (c:decrypt-with-ad (noise-rk n) (noise-rn n) #() header)
                        (c:aead-auth-error ()
                          (error 'transport-error))))
           (len (w:r-u16 (w:make-reader len-bytes))))
      (incf (noise-rn n))
      (%maybe-rotate (noise-r-ck n) (noise-rk n) (noise-rn n))
      (let* ((body (%read-exactly (noise-stream n) (+ len +mac-size+)))
             (payload (handler-case
                          (c:decrypt-with-ad (noise-rk n) (noise-rn n) #() body)
                        (c:aead-auth-error ()
                          (error 'transport-error)))))
        (incf (noise-rn n))
        payload))))

(defun noise-close (n)
  (when (noise-closer n)
    (ignore-errors (funcall (noise-closer n))))
  (setf (noise-stream n) nil)
  n)

;;; ----------------------------------------------------------------------------
;;; Driving the handshake over a stream
;;; ----------------------------------------------------------------------------

(defun handshake-as-initiator (stream local-privkey remote-node-id)
  "Run acts one through three as the dialer.  Returns a NOISE session."
  (let ((hs (make-initiator-handshake local-privkey remote-node-id)))
    (write-sequence (act-one-write hs) stream)
    (force-output stream)
    (act-two-read hs (%read-exactly stream +act-two-size+))
    (multiple-value-bind (msg session) (act-three-write hs)
      (write-sequence msg stream)
      (force-output stream)
      (setf (noise-stream session) stream)
      session)))

(defun handshake-as-responder (stream local-privkey)
  "Run acts one through three as the listener.  Returns a NOISE session whose
   REMOTE-NODE-ID is the identity the initiator revealed in act three."
  (let ((hs (make-responder-handshake local-privkey)))
    (act-one-read hs (%read-exactly stream +act-one-size+))
    (write-sequence (act-two-write hs) stream)
    (force-output stream)
    (let ((session (act-three-read hs (%read-exactly stream +act-three-size+))))
      (setf (noise-stream session) stream)
      session)))

(defun connect-peer (host port remote-node-id local-privkey
                     &key (transport :direct) (timeout 10))
  "Dial HOST:PORT and complete the BOLT #8 handshake against REMOTE-NODE-ID.
   TRANSPORT is passed through to cl-transport, so :tor dials .onion peers with
   no change here — the same arrangement cl-consensus's peer layer uses."
  (multiple-value-bind (stream closer)
      (tr:dial host port :transport transport :timeout timeout)
    (handler-bind ((error (lambda (e) (declare (ignore e))
                            (ignore-errors (funcall closer)))))
      (let ((session (handshake-as-initiator stream local-privkey
                                             (c:octets remote-node-id))))
        (setf (noise-closer session) closer)
        session))))

(defun accept-peer (stream local-privkey &key closer)
  "Complete the responder side of the handshake on an already-accepted STREAM."
  (let ((session (handshake-as-responder stream local-privkey)))
    (setf (noise-closer session) closer)
    session))
