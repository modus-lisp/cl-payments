;;;; inspect/live-peer.lisp
;;;;
;;;; The live gate — a real connection to a real Lightning node.
;;;;
;;;; cl-consensus's guiding principle is "verify against a real node at every
;;;; layer"; this is that principle applied to the peer protocol.  The offline
;;;; vectors prove the primitives, but only a real peer proves the assembly:
;;;; the protocol name and prologue, the order the handshake hash is mixed, the
;;;; little-endian nonce, the sk/rk split, and — the part the vectors say nothing
;;;; about — whether our `init` is one the other side is willing to accept.
;;;;
;;;; That last point is why this gate exists rather than being a unit test.  LND
;;;; closes the connection immediately and silently when it dislikes a peer's
;;;; feature vector, which is indistinguishable from a transport bug until you
;;;; look at the other end's logs.  Advertising nothing is NOT a safe default.
;;;;
;;;; Usage (peer defaults to $CL_PAYMENTS_PEER):
;;;;
;;;;   CL_PAYMENTS_PEER=<node_id>@127.0.0.1:9835 \
;;;;     sbcl --load inspect/live-peer.lisp --quit

(require :asdf)
(asdf:load-system "cl-payments")

(defpackage #:cl-payments.live
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:tp #:cl-payments.transport) (#:f #:cl-payments.features)
                    (#:p #:cl-payments.peer) (#:bt #:bordeaux-threads))
  (:export #:run))

(in-package #:cl-payments.live)

(defun parse-peer-uri (s)
  (let ((at (position #\@ s)) (colon (position #\: s :from-end t)))
    (unless (and at colon) (error "bad peer uri: ~a" s))
    (values (c:hex->bytes (subseq s 0 at))
            (subseq s (1+ at) colon)
            (parse-integer (subseq s (1+ colon))))))

(defun show-features (label features)
  (format t "~&  ~a (~d bit~:p set)~%" label
          (length (f:describe-features features)))
  (dolist (entry (f:describe-features features))
    (destructuring-bind (bit name required) entry
      (format t "      bit ~3d  ~9a ~a~%" bit
              (if required "REQUIRED" "optional")
              (if (eq name :unknown) "(unknown to us)" name)))))

(defun run (&optional (uri (or (uiop:getenv "CL_PAYMENTS_PEER")
                               (error "set CL_PAYMENTS_PEER=<node_id>@host:port"))))
  ;; The `networks` TLV in `init` says which chain we mean.  Get it wrong and CLN
  ;; disconnects with "No common network" — which is the TLV working as intended:
  ;; a clear rejection at init instead of a confusing failure at the first
  ;; channel.  (LND is laxer and stays connected, so testing against only one
  ;; implementation would have hidden this.)
  (w:select-network (or (and (uiop:getenv "CL_PAYMENTS_NETWORK")
                             (intern (string-upcase (uiop:getenv "CL_PAYMENTS_NETWORK"))
                                     :keyword))
                        :signet))
  (format t "~&chain  ~(~a~)~%" (w:net-name w:*network*))
  (multiple-value-bind (node-id host port) (parse-peer-uri uri)
    (format t "~&peer   ~a@~a:~d~%" (c:bytes->hex node-id) host port)
    (multiple-value-bind (our-key our-point) (c:generate-key)
      (format t "us     ~a~%~%" (c:bytes->hex (c:compressed-pubkey our-point)))
      (show-features "we advertise" f:*default-features*)
      (let* ((pongs 0)
             (others '())
             (peer (p:connect host port node-id our-key
                              :chain-hashes (list (w:chain-hash))
                              :log *standard-output* :read-loop nil)))
        (unwind-protect
             (progn
               (format t "~&~%✓ BOLT #8 handshake + BOLT #1 init exchanged~%")
               (format t "  their node id matches the one we dialed: ~a~%~%"
                       (if (equalp (c:octets (p:peer-node-id peer)) (c:octets node-id))
                           "yes" "NO"))
               (show-features "they advertise" (p:peer-features peer))
               (format t "~&~%  features we both support:~%")
               (dolist (entry f:+features+)
                 (let ((name (cdr entry)))
                   (when (and (f:feature-supported-p f:*default-features* name)
                              (f:feature-supported-p (p:peer-features peer) name))
                     (format t "      ~a~%" name))))

               ;; The connection surviving a ping/pong round trip is the real
               ;; proof that init was accepted: a peer that disliked our features
               ;; would already be gone.
               (p:on peer :pong (lambda (pr payload) (declare (ignore pr payload))
                                  (incf pongs)))
               (p:on peer :any (lambda (pr payload) (declare (ignore pr))
                                 (push (length payload) others)))
               (p:start-read-loop peer)
               (format t "~&~%→ ping (asking for 32 bytes of pong padding)~%")
               (p:ping peer :num-pong-bytes 32)
               (sleep 5)
               (format t "← pongs received: ~d~%" pongs)
               (when others
                 (format t "  (also received ~d other message~:p unprompted)~%" (length others)))

               (format t "~&~%staying connected for 20s to prove the peer keeps us…~%")
               (sleep 20)
               (format t "  still alive after 20s: ~a~%"
                       (if (p:peer-alive-p peer) "yes" "NO — peer dropped us"))
               (when (p:peer-alive-p peer)
                 (format t "~&~%✓ Phase 2: a real Lightning node accepts us as a peer.~%")))
          (ignore-errors (p:disconnect peer)))))))

(run)
