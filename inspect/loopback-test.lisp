;;;; inspect/loopback-test.lisp
;;;;
;;;; Gate 5 — the whole stack against itself, over a real socket.
;;;;
;;;; Every other gate checks one layer against fixed vectors.  This one stands up
;;;; a responder on localhost, dials it with our own initiator, and drives real
;;;; traffic through: BOLT #8 handshake in both roles, BOLT #1 `init`
;;;; negotiation, ping/pong, oversized payloads, key rotation, and error
;;;; propagation.
;;;;
;;;; It exists because the spec vectors are all one-sided.  BOLT #8's vectors pin
;;;; what an initiator SENDS; nothing in them proves our responder can read what
;;;; our initiator writes, and a symmetric mistake — a swapped sk/rk, a nonce
;;;; that increments in the wrong place — passes every vector and still cannot
;;;; hold a conversation.
;;;;
;;;; The idle test is a regression guard with a story: the connect-time socket
;;;; timeout used to leak into the read loop, so a connection died on its first
;;;; quiet gap and it looked like the peer had dropped us.  Lightning connections
;;;; are idle most of the time, so nothing but a deliberate pause catches it.

(require :asdf)
(asdf:initialize-source-registry
 (let ((here (make-pathname :name nil :type nil :defaults *load-truename*)))
   `(:source-registry (:tree ,(merge-pathnames "../" here))
                      (:tree ,(merge-pathnames "../../" here))
                      :inherit-configuration)))
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-payments"))

(defpackage #:loopback-test
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:tp #:cl-payments.transport) (#:f #:cl-payments.features)
                    (#:p #:cl-payments.peer) (#:tr #:cl-transport)
                    (#:bt #:bordeaux-threads))
  (:export #:run))

(in-package #:loopback-test)

(defvar *checks* 0)
(defvar *fails* 0)

(defun ok (label result)
  (incf *checks*)
  (if result
      (format t "~&  ok    ~a~%" label)
      (progn (incf *fails*) (format t "~&  FAIL  ~a~%" label)))
  result)

(defvar *port-cursor* 19735
  "Bumped past each pair.  Reusing a port across pairs hands back one still in
   TIME_WAIT from the previous listener — it binds fine and then never accepts,
   which surfaces as the initiator hitting EOF halfway through the handshake.")

(defun free-port (&optional (start *port-cursor*))
  "A port nothing is listening on.  Scanned rather than fixed so the gate doesn't
   fail spuriously on a box that happens to be using one."
  ;; TCP-LISTEN takes PORT positionally and returns a RAW socket, not a listener.
  (loop for port from start below (+ start 200)
        do (handler-case
               (let ((sock (cl-transport.listeners:tcp-listen port :address "127.0.0.1")))
                 (sb-bsd-sockets:socket-close sock)
                 (setf *port-cursor* (1+ port))
                 (return port))
             (error () nil))
        finally (error "no free port in ~d..~d" start (+ start 200))))

(defmacro with-pair ((client server &key (client-features 'f:*default-features*)
                                         (server-features 'f:*default-features*))
                     &body body)
  "Stand up a responder, dial it, and bind CLIENT and SERVER to the two PEERs —
   both ends of the same connection, both implemented by us."
  `(call-with-pair (lambda (,client ,server) ,@body)
                   :client-features ,client-features
                   :server-features ,server-features))

(defvar *last-server-key* nil)
(defvar *last-client-key* nil)

(defun call-with-pair (fn &key client-features server-features)
  (let* ((port (free-port))
         (server-key (setf *last-server-key* (c:generate-key)))
         (client-key (setf *last-client-key* (c:generate-key)))
         (server-peer nil)
         (server-err nil)
         (ready (bt:make-semaphore))
         closer)
    (unwind-protect
         (progn
           (setf closer
                 (tr:expose (lambda (stream peer-plist)
                              (declare (ignore peer-plist))
                              ;; This callback's thread must OWN the connection
                              ;; for its whole life.  In SBCL a socket created by
                              ;; a thread is torn down when that thread exits, so
                              ;; accepting, spawning a read loop and returning
                              ;; leaves the stream with a NIL buffer and the next
                              ;; write dies inside SB-IMPL::BUFFER-OUTPUT.
                              ;; RUN-READ-LOOP blocks here instead, exactly as
                              ;; cl-consensus's parallel dialer does.
                              (handler-case
                                  (progn
                                    (setf server-peer
                                          (p:accept stream server-key
                                                    :features server-features
                                                    :log nil :read-loop nil))
                                    (bt:signal-semaphore ready)
                                    (p:run-read-loop server-peer))
                                (error (e)
                                  (unless server-peer (setf server-err e))
                                  (bt:signal-semaphore ready))))
                            :backend :tcp :host "127.0.0.1" :port port))
           (let ((client (p:connect "127.0.0.1" port
                                    (c:compressed-pubkey (c:pubkey-of server-key))
                                    client-key
                                    :features client-features
                                    :log nil :read-loop t)))
             ;; The responder finishes its handshake on the listener's thread;
             ;; wait for it rather than racing.
             (bt:wait-on-semaphore ready :timeout 20)
             (when server-err (error "responder failed: ~a" server-err))
             (unwind-protect
                  (progn
                    ;; Surface why a read loop died; it is caught and recorded
                    ;; rather than signalled, so silence would look like success.
                    (dolist (pr (list client server-peer))
                      (when (and pr (p:peer-last-error pr))
                        (format t "~&        (read loop: ~a)~%" (p:peer-last-error pr))))
                    (funcall fn client server-peer))
               (ignore-errors (p:disconnect client)))))
      (when closer (ignore-errors (funcall closer))))))

;;; ----------------------------------------------------------------------------

(defun test-handshake-both-roles ()
  (format t "~&~%handshake + init, our initiator against our responder~%")
  (with-pair (client server)
    ;; Each side stores the OTHER's static key, so these are different values by
    ;; construction — comparing them to each other proves nothing.
    (ok "client's stored node id is the server's key"
        (equalp (c:octets (p:peer-node-id client))
                (c:octets (c:compressed-pubkey (c:pubkey-of *last-server-key*)))))
    ;; XK hides the initiator until act three; the responder must still end up
    ;; knowing exactly who dialed.
    (ok "server's stored node id is the client's key (revealed in act three)"
        (equalp (c:octets (p:peer-node-id server))
                (c:octets (c:compressed-pubkey (c:pubkey-of *last-client-key*)))))
    (ok "both sides consider the connection live"
        (and (p:peer-alive-p client) (p:peer-alive-p server)))
    ;; Each side records what the OTHER advertised.
    (ok "client sees the server's features"
        (= (p:peer-features client) f:*default-features*))
    (ok "server sees the client's features"
        (= (p:peer-features server) f:*default-features*))))

(defun test-ping-pong-both-ways ()
  (format t "~&~%ping / pong in both directions~%")
  (with-pair (client server)
    (let ((client-pongs 0) (server-pongs 0))
      (p:on client :pong (lambda (pr pl) (declare (ignore pr pl)) (incf client-pongs)))
      (p:on server :pong (lambda (pr pl) (declare (ignore pr pl)) (incf server-pongs)))
      (p:ping client :num-pong-bytes 64)
      (p:ping server :num-pong-bytes 16)
      (sleep 3)
      (ok "client got a pong from the server" (= client-pongs 1))
      (ok "server got a pong from the client" (= server-pongs 1))
      ;; Above the framing limit a pong cannot be sent, so silence is correct.
      (p:ping client :num-pong-bytes 65532)
      (sleep 2)
      (ok "a ping above the amplification limit is not answered" (= client-pongs 1)))))

(defun test-large-messages ()
  (format t "~&~%payload sizes~%")
  (with-pair (client server)
    (let ((got nil))
      (p:on server 32000 (lambda (pr pl) (declare (ignore pr)) (setf got (length pl))))
      ;; The largest payload BOLT #8 can frame is bounded by its u16 length minus
      ;; the message type and the AEAD tag.
      (let ((big (make-array 65000 :element-type '(unsigned-byte 8) :initial-element 7)))
        (p:send-message client 32000 big)
        (sleep 3)
        (ok "a 65000-byte payload arrives intact" (eql got 65000)))
      (setf got nil)
      (p:send-message client 32000 #())
      (sleep 2)
      (ok "a zero-length payload arrives" (eql got 0)))))

(defun test-key-rotation ()
  (format t "~&~%key rotation across a live session (>1000 messages each way)~%")
  (with-pair (client server)
    (let ((n 0))
      (p:on server 32001 (lambda (pr pl) (declare (ignore pr pl)) (incf n)))
      ;; BOLT #8 rotates each direction's key every 1000 messages.  The vector
      ;; gate checks the SENDING side against fixed output; only a live pairing
      ;; proves the receiver rotates in lockstep — and a desync shows up as a
      ;; decryption failure exactly at message 1000, not before.
      (dotimes (i 1100)
        (p:send-message client 32001 (c:octets (vector (mod i 256)))))
      (loop repeat 60 until (>= n 1100) do (sleep 0.5))
      (ok "all 1100 messages decrypted (rotation stayed in sync)" (= n 1100))
      (ok "sender's nonce wrapped past the rotation point"
          (< (tp:noise-sn (p:peer-session client)) 1100))
      (ok "connection still healthy afterwards"
          (and (p:peer-alive-p client) (p:peer-alive-p server))))))

(defun test-idle-survival ()
  (format t "~&~%idle connection (regression: the connect timeout used to leak)~%")
  (with-pair (client server)
    ;; The dial timeout is 10s.  If it leaks into the read loop, this kills the
    ;; connection and it presents as the peer dropping us.
    (sleep 14)
    (ok "still alive after 14s of silence"
        (and (p:peer-alive-p client) (p:peer-alive-p server)))
    (let ((pongs 0))
      (p:on client :pong (lambda (pr pl) (declare (ignore pr pl)) (incf pongs)))
      (p:ping client)
      (sleep 3)
      (ok "and still usable" (= pongs 1)))))

(defun test-error-propagation ()
  (format t "~&~%error / warning propagation~%")
  (with-pair (client server)
    (let ((seen nil))
      (p:on client :warning (lambda (pr pl) (declare (ignore pr)) (setf seen pl)))
      (p:send-warning server "just a warning")
      (sleep 2)
      (ok "a warning is delivered" (not (null seen)))
      (ok "a warning does NOT close the connection" (p:peer-alive-p client))))
  (with-pair (client server)
    ;; An `error` with an all-zero channel_id means the whole connection.
    (p:send-error server "fatal, going away")
    (sleep 3)
    (ok "an error with a zero channel_id closes the connection"
        (not (p:peer-alive-p client)))))

(defun test-feature-rejection ()
  (format t "~&~%feature negotiation failure~%")
  ;; A peer that REQUIRES something we don't know must be refused; continuing
  ;; would mean silently pretending to support it.
  (let ((exotic (logior f:*default-features* (ash 1 200))))   ; unknown EVEN bit
    (ok "an unknown required bit is rejected"
        (handler-case (progn (call-with-pair (lambda (c s) (declare (ignore c s)))
                                             :client-features f:*default-features*
                                             :server-features exotic)
                             nil)
          (error () t))))
  ;; …and an unknown ODD bit must be harmless.
  (let ((exotic (logior f:*default-features* (ash 1 201))))
    (ok "an unknown optional bit is tolerated"
        (handler-case (progn (call-with-pair
                              (lambda (c s) (declare (ignore s))
                                (unless (p:peer-alive-p c) (error "died")))
                              :client-features f:*default-features*
                              :server-features exotic)
                             t)
          (error () nil)))))

(defun run ()
  (setf *checks* 0 *fails* 0)
  (format t "~&=== loopback: the stack against itself ===~%")
  (test-handshake-both-roles)
  (test-ping-pong-both-ways)
  (test-large-messages)
  (test-key-rotation)
  (test-idle-survival)
  (test-error-propagation)
  (test-feature-rejection)
  (format t "~&~%~d check~:p, ~d failure~:p~%" *checks* *fails*)
  (zerop *fails*))
