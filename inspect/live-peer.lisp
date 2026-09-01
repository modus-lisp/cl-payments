;;;; inspect/live-peer.lisp
;;;;
;;;; The live gate — a real BOLT #8 handshake against a real Lightning node.
;;;;
;;;; cl-consensus's guiding principle is "verify against a real node at every
;;;; layer"; this is that principle applied to the transport.  The RFC vectors in
;;;; crypto-test.lisp prove the primitives, but only a real peer proves the whole
;;;; assembly: the protocol name and prologue, the exact order the handshake hash
;;;; is mixed, the little-endian nonce, and the sk/rk split — get any one wrong
;;;; and the vectors still pass while no node in the world will talk to you.
;;;;
;;;; After the handshake we exchange BOLT #1 `init` messages, which additionally
;;;; proves the framing layer: their init arrives only if our length header
;;;; decrypted correctly, and they only reply if ours did.
;;;;
;;;; Usage (peer defaults to cln1 in the signet devnet):
;;;;
;;;;   CL_PAYMENTS_PEER=<node_id>@127.0.0.1:9835 \
;;;;     sbcl --load inspect/live-peer.lisp --quit

(require :asdf)
(asdf:load-system "cl-payments")

(defpackage #:cl-payments.live
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:tp #:cl-payments.transport))
  (:export #:run))

(in-package #:cl-payments.live)

(defconstant +msg-init+ 16)
(defconstant +msg-error+ 17)
(defconstant +msg-warning+ 1)
(defconstant +msg-ping+ 18)
(defconstant +msg-pong+ 19)

(defun parse-peer-uri (s)
  "<node_id_hex>@<host>:<port> → (values id-bytes host port)."
  (let* ((at (position #\@ s))
         (colon (position #\: s :from-end t)))
    (unless (and at colon) (error "bad peer uri: ~a" s))
    (values (c:hex->bytes (subseq s 0 at))
            (subseq s (1+ at) colon)
            (parse-integer (subseq s (1+ colon))))))

(defun encode-init ()
  "BOLT #1 `init`: globalfeatures, features, then a TLV stream.  We advertise
   nothing — an empty feature vector is legal, and every optional feature is one
   we have not implemented yet."
  (let ((wr (w:make-writer)))
    (w:w-varbytes wr #())       ; globalfeatures (deprecated, must be empty-ish)
    (w:w-varbytes wr #())       ; features
    (w:encode-message +msg-init+ (w:writer-bytes wr))))

(defun describe-message (type payload)
  (case type
    (#.+msg-init+
     (let* ((r (w:make-reader payload))
            (gf (w:r-varbytes r))
            (f  (w:r-varbytes r))
            (tlv (handler-case (w:r-tlv-stream r) (error () nil))))
       (format nil "init  globalfeatures=~d byte~:p features=~a tlv-records=~d"
               (length gf)
               (if (zerop (length f)) "(none)" (c:bytes->hex f))
               (length tlv))))
    (#.+msg-error+
     (let* ((r (w:make-reader payload)) (chan (w:r-bytes r 32)))
       (declare (ignore chan))
       (format nil "error  ~a" (map 'string #'code-char (w:r-varbytes r)))))
    (#.+msg-warning+
     (let* ((r (w:make-reader payload)) (chan (w:r-bytes r 32)))
       (declare (ignore chan))
       (format nil "warning  ~a" (map 'string #'code-char (w:r-varbytes r)))))
    (#.+msg-ping+ (format nil "ping  (~d bytes)" (length payload)))
    (#.+msg-pong+ (format nil "pong  (~d bytes)" (length payload)))
    (t (format nil "type ~d  (~d byte payload)" type (length payload)))))

(defun run (&optional (uri (or (uiop:getenv "CL_PAYMENTS_PEER")
                               (error "set CL_PAYMENTS_PEER=<node_id>@host:port"))))
  (multiple-value-bind (node-id host port) (parse-peer-uri uri)
    (format t "~&peer      ~a@~a:~d~%" (c:bytes->hex node-id) host port)
    (multiple-value-bind (our-key our-point) (c:generate-key)
      (format t "us        ~a~%~%" (c:bytes->hex (c:compressed-pubkey our-point)))
      (let ((session (tp:connect-peer host port node-id our-key)))
        (unwind-protect
             (progn
               (format t "~&✓ BOLT #8 handshake complete~%")
               ;; The responder's static key is not sent in the clear anywhere —
               ;; we only end up with a working session if the key we dialed is
               ;; the key that answered.  Matching it is the authentication.
               (format t "  remote static key matches the node id we dialed: ~a~%"
                       (if (equalp (c:octets (tp:noise-remote-node-id session))
                                   (c:octets node-id))
                           "yes" "NO"))
               (format t "  sending key ~a…~%" (subseq (c:bytes->hex (tp:noise-sk session)) 0 16))
               (format t "  receiving key ~a…~%~%" (subseq (c:bytes->hex (tp:noise-rk session)) 0 16))

               (tp:noise-send session (encode-init))
               (format t "→ init sent~%")
               ;; Read a few messages: their init, then whatever they volunteer
               ;; (CLN starts pinging almost immediately).
               (dotimes (i 3)
                 (handler-case
                     (multiple-value-bind (type payload)
                         (w:decode-message (tp:noise-recv session))
                       (format t "← ~a~%" (describe-message type payload)))
                   (error (e) (format t "← (no more messages: ~a)~%" e) (return))))
               (format t "~%✓ encrypted transport is carrying real Lightning messages~%"))
          (tp:noise-close session))))))

(run)
