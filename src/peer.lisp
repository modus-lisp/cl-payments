;;;; src/peer.lisp
;;;;
;;;; Phase 2 — the BOLT #1 peer: `init` negotiation, ping/pong, error handling,
;;;; and the asynchronous read loop everything above this sits on.
;;;;
;;;; Shaped after cl-consensus's peer.lisp: a PEER owns a connection and a
;;;; handler table, a background thread reads messages and dispatches them, and
;;;; callers register interest with ON rather than reading the socket themselves.
;;;; The difference is what's underneath — a BOLT #8 NOISE session instead of a
;;;; raw socket, so every message in and out is encrypted and authenticated.
;;;;
;;;; `init` is the first message in both directions and must be sent before
;;;; anything else.  Getting its feature vector wrong is not a soft failure: LND
;;;; closes the connection immediately and silently, which reads like a transport
;;;; bug rather than a negotiation one.  See features.lisp.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/01-messaging.md

(defpackage #:cl-payments.peer
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:f #:cl-payments.features) (#:tp #:cl-payments.transport)
                    (#:bt #:bordeaux-threads))
  (:nicknames #:ln-peer)
  (:export
   #:peer #:peer-p #:peer-node-id #:peer-session #:peer-features
   #:peer-alive-p #:peer-connected-at #:peer-their-init #:peer-log
   #:connect #:accept #:disconnect #:send-message #:on
   #:start-read-loop #:run-read-loop
   #:ping #:send-warning #:send-error #:pong-required-p #:+max-pong-bytes+
   #:+msg-init+ #:+msg-error+ #:+msg-warning+ #:+msg-ping+ #:+msg-pong+
   #:message-name #:peer-error #:*handshake-timeout*))

(in-package #:cl-payments.peer)

;;; ----------------------------------------------------------------------------
;;; Message types (BOLT #1's "setup and control" range)
;;; ----------------------------------------------------------------------------

(defconstant +msg-warning+ 1)
(defconstant +msg-init+ 16)
(defconstant +msg-error+ 17)
(defconstant +msg-ping+ 18)
(defconstant +msg-pong+ 19)

(defparameter *message-names*
  '((1 . :warning) (16 . :init) (17 . :error) (18 . :ping) (19 . :pong)
    ;; gossip, so the log is readable before Phase 3 implements them
    (256 . :channel-announcement) (257 . :node-announcement)
    (258 . :channel-update) (259 . :announcement-signatures)
    (261 . :query-short-channel-ids) (262 . :reply-short-channel-ids-end)
    (263 . :query-channel-range) (264 . :reply-channel-range)
    (265 . :gossip-timestamp-filter)))

(defun message-name (type)
  (or (cdr (assoc type *message-names*)) type))

(defparameter *handshake-timeout* 30
  "Seconds to wait for the peer's `init`.  A peer that completes the BOLT #8
   handshake and then says nothing is a real failure mode — LND does exactly
   that when it dislikes our features — so this must not be unbounded.")

(define-condition peer-error (error)
  ((detail :initarg :detail :reader peer-error-detail))
  (:report (lambda (c s) (format s "peer: ~a" (peer-error-detail c)))))

;;; ----------------------------------------------------------------------------
;;; The peer
;;; ----------------------------------------------------------------------------

(defstruct (peer (:constructor %make-peer))
  session                    ; the BOLT #8 NOISE session
  node-id                    ; their 33-byte static key
  (features 0)               ; OUR negotiated view: what they advertised
  their-init                 ; raw init payload, for debugging
  (handlers (make-hash-table))
  (alive-p t)
  (connected-at 0)
  thread
  (log-stream *standard-output*)
  (lock (bt:make-lock "peer")))

(defun peer-log (p fmt &rest args)
  (when (peer-log-stream p)
    (format (peer-log-stream p) "~&[peer ~a] ~?~%"
            (subseq (c:bytes->hex (peer-node-id p)) 0 12) fmt args)
    (force-output (peer-log-stream p))))

(defun on (p type handler)
  "Register HANDLER (a function of (peer payload)) for message TYPE.  TYPE may be
   an integer or a keyword from *MESSAGE-NAMES*; :any catches everything else."
  (setf (gethash (if (keywordp type)
                     (or (car (rassoc type *message-names*)) type)
                     type)
                 (peer-handlers p))
        handler))

;;; ----------------------------------------------------------------------------
;;; init
;;; ----------------------------------------------------------------------------

(defun encode-init (features &key chain-hashes)
  "BOLT #1 `init`: globalfeatures, features, then a TLV stream.

   `globalfeatures` is the deprecated original vector and is sent empty; the
   spec says to treat the two as concatenated, with everything modern living in
   `features`.  The `networks` TLV (type 1) lists the chains we'll talk about —
   worth sending, because a peer on a different chain can then reject us
   immediately instead of at the first channel."
  (let ((wr (w:make-writer)))
    (w:w-varbytes wr #())                          ; globalfeatures (deprecated)
    (w:w-varbytes wr (f:features->bytes features))
    (when chain-hashes
      (let ((nets (w:make-writer)))
        (dolist (h chain-hashes) (w:w-hash nets h))
        (w:w-tlv-stream wr (list (w:make-tlv-record :type 1
                                                    :value (w:writer-bytes nets))))))
    (w:encode-message +msg-init+ (w:writer-bytes wr))))

(defun decode-init (payload)
  "Returns (values features globalfeatures tlv-records).  The two vectors are
   OR'd together per BOLT #1, so a peer using the legacy field still reads
   correctly."
  (let* ((r (w:make-reader payload))
         (global (w:r-varbytes r))
         (local (w:r-varbytes r))
         (tlv (if (w:reader-eof-p r) nil
                  (handler-case (w:r-tlv-stream r) (error () nil)))))
    (values (logior (f:bytes->features global) (f:bytes->features local))
            (f:bytes->features global)
            tlv)))

(defun negotiate-init (p our-features &key chain-hashes)
  "Exchange `init` and apply BOLT #1's compatibility rules.  Both sides send
   first and read second — init is not a request/response, and waiting for
   theirs before sending ours deadlocks against a peer doing the same."
  (tp:noise-send (peer-session p) (encode-init our-features :chain-hashes chain-hashes))
  (let ((deadline (+ (get-universal-time) *handshake-timeout*)))
    (loop
      (when (> (get-universal-time) deadline)
        (error 'peer-error :detail "timed out waiting for their init"))
      (multiple-value-bind (type payload)
          (w:decode-message (tp:noise-recv (peer-session p)))
        (cond
          ((= type +msg-init+)
           (multiple-value-bind (theirs global tlv) (decode-init payload)
             (declare (ignore global tlv))
             (setf (peer-features p) theirs
                   (peer-their-init p) payload)
             ;; The one hard rule: an even bit we don't know means they depend on
             ;; something we can't do.  Continuing would be pretending.
             (let ((unknown (f:unknown-required-bits theirs)))
               (when unknown
                 (send-error p (format nil "unknown required feature bit~p ~{~d~^, ~}"
                                       (length unknown) unknown))
                 (error 'peer-error
                        :detail (format nil "peer requires unknown feature bit~p ~{~d~^, ~}"
                                        (length unknown) unknown))))
             (return p)))
          ((= type +msg-error+)
           (error 'peer-error :detail (format nil "peer sent error before init: ~a"
                                              (decode-error payload))))
          ((= type +msg-warning+)
           (peer-log p "warning before init: ~a" (decode-error payload)))
          (t
           ;; BOLT #1: init MUST be first.  Anything else is a protocol violation.
           (error 'peer-error
                  :detail (format nil "expected init, got ~a" (message-name type)))))))))

;;; ----------------------------------------------------------------------------
;;; error / warning
;;; ----------------------------------------------------------------------------

(defun decode-error (payload)
  "Both `error` and `warning` are (channel_id, data).  An all-zero channel_id
   means the whole connection rather than one channel."
  (handler-case
      (let* ((r (w:make-reader payload))
             (chan (w:r-bytes r 32))
             (data (w:r-varbytes r)))
        (format nil "~a~a"
                (if (every #'zerop chan) "" (format nil "[chan ~a] " (c:bytes->hex chan)))
                ;; The spec warns this is attacker-controlled and may be
                ;; arbitrary bytes; render printable ASCII and drop the rest
                ;; rather than letting a peer write escape sequences to a
                ;; terminal.
                (map 'string (lambda (b) (if (<= 32 b 126) (code-char b) #\.)) data)))
    (error () "<malformed error message>")))

(defun %send-errorish (p type message channel-id)
  (let ((wr (w:make-writer)))
    (w:w-hash wr (or channel-id (make-array 32 :element-type '(unsigned-byte 8)
                                               :initial-element 0)))
    (w:w-varbytes wr (c:ascii->bytes message))
    (ignore-errors (send-message p type (w:writer-bytes wr)))))

(defun send-error (p message &optional channel-id)
  "An `error` tells the peer we are giving up — on the channel, or (with an
   all-zero channel_id) on the connection."
  (%send-errorish p +msg-error+ message channel-id))

(defun send-warning (p message &optional channel-id)
  "A `warning` reports a problem WITHOUT tearing anything down.  Preferred over
   `error` for anything recoverable: an `error` on a channel is destructive and
   can cost money."
  (%send-errorish p +msg-warning+ message channel-id))

;;; ----------------------------------------------------------------------------
;;; ping / pong
;;;
;;; The BOLT #1 rules here exist to make the connection resistant to traffic
;;; analysis (you can ask a peer for arbitrary padding) while not being a
;;; free amplification primitive.
;;; ----------------------------------------------------------------------------

(defun encode-ping (num-pong-bytes ignored-len)
  (let ((wr (w:make-writer)))
    (w:w-u16 wr num-pong-bytes)
    (w:w-varbytes wr (make-array ignored-len :element-type '(unsigned-byte 8)
                                             :initial-element 0))
    (w:encode-message +msg-ping+ (w:writer-bytes wr))))

(defconstant +max-pong-bytes+ 65532
  "BOLT #1: a ping asking for this many pong bytes or more MUST NOT be answered.
   The reply could not be framed inside BOLT #8's u16 length once the pong's own
   type and length fields are counted, so a node that answers anyway is offering
   itself as an amplifier.")

(defun pong-required-p (num-pong-bytes)
  "Whether BOLT #1 obliges us to answer a ping asking for NUM-PONG-BYTES."
  (< num-pong-bytes +max-pong-bytes+))

(defun handle-ping (p payload)
  (let* ((r (w:make-reader payload))
         (num-pong (w:r-u16 r)))
    (when (pong-required-p num-pong)
      (let ((wr (w:make-writer)))
        (w:w-varbytes wr (make-array num-pong :element-type '(unsigned-byte 8)
                                              :initial-element 0))
        (send-message p +msg-pong+ (w:writer-bytes wr))))))

(defun ping (p &key (num-pong-bytes 8) (ignored-len 8))
  "Send a ping.  Returns immediately; the pong arrives through the read loop."
  (send-message p (encode-ping num-pong-bytes ignored-len) nil))

;;; ----------------------------------------------------------------------------
;;; Sending / the read loop
;;; ----------------------------------------------------------------------------

(defun send-message (p type-or-encoded &optional payload)
  "Send a message.  Either (send-message p <already-encoded-bytes> nil) or
   (send-message p type payload)."
  (unless (peer-alive-p p) (error 'peer-error :detail "peer is not connected"))
  (tp:noise-send (peer-session p)
                 (if payload (w:encode-message type-or-encoded payload) type-or-encoded)))

(defun dispatch (p type payload)
  (let ((h (or (gethash type (peer-handlers p))
               (gethash :any (peer-handlers p)))))
    (when h
      (handler-case (funcall h p payload)
        (error (e) (peer-log p "handler for ~a errored: ~a" (message-name type) e))))))

(defun run-read-loop (p)
  "Read and dispatch IN THE CURRENT THREAD until the connection closes.  Ping, error and warning are
   handled here so every caller gets correct behaviour for free; everything else
   goes to the registered handlers."
  ;; A Lightning connection is idle most of the time; without this the
  ;; connect-time read timeout kills the loop on the first quiet gap and it looks
  ;; like the peer dropped us.
  (tp:noise-clear-timeout (peer-session p))
  (unwind-protect
       (loop while (peer-alive-p p) do
         (multiple-value-bind (type payload)
             (w:decode-message (tp:noise-recv (peer-session p)))
           (cond
             ((= type +msg-ping+) (handle-ping p payload) (dispatch p type payload))
             ((= type +msg-pong+) (dispatch p type payload))
             ((= type +msg-warning+)
              (peer-log p "warning: ~a" (decode-error payload))
              (dispatch p type payload))
             ((= type +msg-error+)
              (peer-log p "error: ~a" (decode-error payload))
              (dispatch p type payload)
              ;; An `error` with an all-zero channel_id ends the connection.
              (let ((chan (ignore-errors (w:r-bytes (w:make-reader payload) 32))))
                (when (and chan (every #'zerop chan))
                  (setf (peer-alive-p p) nil))))
             (t (dispatch p type payload)))))
    (setf (peer-alive-p p) nil)))

(defun start-read-loop (p)
  "Run the read loop on its own thread, as cl-consensus's peer layer does, so a
   caller can drive the connection without owning it.

   Call this from a LONG-LIVED thread.  In SBCL a socket opened by a thread is
   torn down when that thread exits, so spawning the loop from an ephemeral
   worker gives you a connection that dies for no visible reason."
  (tp:noise-clear-timeout (peer-session p))
  (setf (peer-thread p)
        (bt:make-thread (lambda ()
                          (handler-case (run-read-loop p)
                            (error (e) (peer-log p "read loop ended: ~a" e))))
                        :name "ln-peer-read-loop"))
  p)

;;; ----------------------------------------------------------------------------
;;; Connection lifecycle
;;; ----------------------------------------------------------------------------

(defun %wrap (session &key (features f:*default-features*) chain-hashes log)
  (let ((p (%make-peer :session session
                       :node-id (tp:noise-remote-node-id session)
                       :connected-at (get-universal-time)
                       :log-stream log)))
    (negotiate-init p features :chain-hashes chain-hashes)
    p))

(defun connect (host port node-id local-privkey
                &key (features f:*default-features*) (transport :direct)
                     (timeout 10) chain-hashes (log *standard-output*) (read-loop t))
  "Dial a Lightning node: BOLT #8 handshake, then BOLT #1 `init`.  Returns a PEER
   with its read loop running (unless READ-LOOP is NIL, for tests that want to
   drive the messages by hand)."
  (let ((session (tp:connect-peer host port node-id local-privkey
                                  :transport transport :timeout timeout)))
    (handler-bind ((error (lambda (e) (declare (ignore e))
                            (ignore-errors (tp:noise-close session)))))
      (let ((p (%wrap session :features features :chain-hashes chain-hashes :log log)))
        (when read-loop (start-read-loop p))
        p))))

(defun accept (stream local-privkey
               &key closer (features f:*default-features*) chain-hashes
                    (log *standard-output*) (read-loop t))
  "Responder side, on an already-accepted STREAM."
  (let ((session (tp:accept-peer stream local-privkey :closer closer)))
    (let ((p (%wrap session :features features :chain-hashes chain-hashes :log log)))
      (when read-loop (start-read-loop p))
      p)))

(defun disconnect (p &optional reason)
  (when (and reason (peer-alive-p p))
    (ignore-errors (send-error p reason)))
  (setf (peer-alive-p p) nil)
  (ignore-errors (tp:noise-close (peer-session p)))
  p)
