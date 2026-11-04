;;;; src/modus-net.lisp -- cl-payments' sockets on modus.
;;;;
;;;; On SBCL a connection is a cl-transport stream owned by a thread, and every
;;;; peer has a read thread.  modus threads share no state (a worker may not store
;;;; its objects where another thread can reach them), and a peer's handlers touch
;;;; the node's channels, so on modus there is ONE owner thread and one net
;;;; thread: cl-consensus's net layer (cl-consensus.netloop), which moves bytes
;;;; over modus channels.  This file puts a Gray binary stream over one of its
;;;; connections, so everything above -- the BOLT #8 handshake, the transport, the
;;;; control socket -- runs unchanged.  A read pumps the net layer until the bytes
;;;; are there (other connections' input is delivered meanwhile); a write is handed
;;;; to the net thread and returns.
;;;;
;;;; Nothing here exists on SBCL.

(defpackage #:cl-payments.modus-net
  (:use #:cl)
  (:nicknames #:clp-mnet)
  (:export #:conn-stream #:conn-stream-p #:stream-conn #:expose #:dial))
(in-package #:cl-payments.modus-net)

#+modus
(progn

(defclass conn-stream (trivial-gray-streams:fundamental-binary-input-stream
                       trivial-gray-streams:fundamental-binary-output-stream)
  ((conn :initarg :conn :reader stream-conn)))

(defun conn-stream-p (x) (typep x 'conn-stream))

(defmethod stream-element-type ((s conn-stream)) '(unsigned-byte 8))

(defun %wait-for (c n)
  "Pump until N bytes are buffered on C or it has closed.  The bytes available."
  (loop while (and (< (cl-consensus.netloop:conn-available c) n)
                   (not (cl-consensus.netloop:netconn-eof c)))
        do (cl-consensus.netloop:pump 0.05))
  (cl-consensus.netloop:conn-available c))

(defmethod trivial-gray-streams:stream-read-byte ((s conn-stream))
  (let ((c (stream-conn s)))
    (if (plusp (%wait-for c 1))
        (aref (cl-consensus.netloop:conn-read c 1) 0)
        :eof)))

(defmethod trivial-gray-streams:stream-read-sequence ((s conn-stream) seq start end &key)
  "Fill SEQ[START,END), short only at end of stream: CL:READ-SEQUENCE's contract."
  (let* ((c (stream-conn s))
         (end (or end (length seq)))
         (have (min (- end start) (%wait-for c (- end start)))))
    (when (plusp have)
      (replace seq (cl-consensus.netloop:conn-read c have) :start1 start))
    (+ start have)))

(defmethod trivial-gray-streams:stream-write-byte ((s conn-stream) b)
  (cl-consensus.netloop:conn-write (stream-conn s)
                                   (make-array 1 :element-type '(unsigned-byte 8) :initial-element b))
  b)

(defmethod trivial-gray-streams:stream-write-sequence ((s conn-stream) seq start end &key)
  (cl-consensus.netloop:conn-write (stream-conn s) (subseq seq start (or end (length seq))))
  seq)

(defmethod trivial-gray-streams:stream-force-output ((s conn-stream)) nil)
(defmethod trivial-gray-streams:stream-finish-output ((s conn-stream)) nil)

(defmethod close ((s conn-stream) &key abort)
  (declare (ignore abort))
  (cl-consensus.netloop:net-close (stream-conn s))
  t)

(defun expose (handler &key (host "127.0.0.1") port)
  "TR:EXPOSE for modus: listen on HOST:PORT and call HANDLER with (stream nil)
   for each connection, on this thread, while it pumps.  A closer, as TR:EXPOSE
   returns (closing the listener is not supported; it lives with the process)."
  (cl-consensus.netloop:net-listen
   host port
   (lambda (conn) (funcall handler (make-instance 'conn-stream :conn conn) nil)))
  (lambda () nil))

(defun dial (host port &key (timeout 10))
  "TR:DIAL for modus: (values stream closer)."
  (let* ((conn (cl-consensus.netloop:net-connect host port :timeout timeout))
         (s (make-instance 'conn-stream :conn conn)))
    (values s (lambda () (close s)))))

) ; #+modus
