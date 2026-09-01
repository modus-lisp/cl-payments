;;;; inspect/capture-gossip.lisp
;;;;
;;;; Dump raw BOLT #7 gossip from a live peer into a vectors file.
;;;;
;;;; The BOLTs publish no gossip test vectors — unlike BOLT #8, which pins every
;;;; handshake byte — so the only ground truth available is what real
;;;; implementations actually put on the wire.  This captures that, and the
;;;; result becomes inspect/vectors/gossip-*.txt for the offline gate.
;;;;
;;;; Capturing rather than hand-writing matters here: these messages carry
;;;; signatures over an exact byte range, so a hand-built "vector" would only
;;;; ever prove our encoder agrees with our decoder.  A captured one proves we
;;;; agree with Core Lightning.
;;;;
;;;;   CL_PAYMENTS_PEER=<node_id>@127.0.0.1:9835 \
;;;;     sbcl --load inspect/capture-gossip.lisp --quit

(require :asdf)
(asdf:initialize-source-registry
 (let ((here (make-pathname :name nil :type nil :defaults *load-truename*)))
   `(:source-registry (:tree ,(merge-pathnames "../" here))
                      (:tree ,(merge-pathnames "../../" here))
                      :inherit-configuration)))
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-payments"))

(defpackage #:capture-gossip
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:f #:cl-payments.features) (#:p #:cl-payments.peer))
  (:export #:run))

(in-package #:capture-gossip)

(defparameter *out*
  (merge-pathnames "vectors/gossip.txt"
                   (make-pathname :name nil :type nil :defaults *load-truename*)))

(defun run (&optional (uri (or (uiop:getenv "CL_PAYMENTS_PEER")
                               (error "set CL_PAYMENTS_PEER=<node_id>@host:port")))
                      (seconds 25))
  (w:select-network (or (and (uiop:getenv "CL_PAYMENTS_NETWORK")
                             (intern (string-upcase (uiop:getenv "CL_PAYMENTS_NETWORK")) :keyword))
                        :signet))
  (let* ((at (position #\@ uri)) (colon (position #\: uri :from-end t))
         (node-id (c:hex->bytes (subseq uri 0 at)))
         (host (subseq uri (1+ at) colon))
         (port (parse-integer (subseq uri (1+ colon))))
         (captured '()))
    (multiple-value-bind (key point) (c:generate-key)
      (declare (ignore point))
      (let ((peer (p:connect host port node-id key
                             :chain-hashes (list (w:chain-hash))
                             :log nil :read-loop nil)))
        (unwind-protect
             (progn
               (p:on peer :any
                     (lambda (pr payload) (declare (ignore pr))
                       (push (cons :any payload) captured)))
               ;; Record every message with its type, so the gate sees exactly
               ;; the bytes that came off the wire.
               (dolist (type '(256 257 258 259 261 262 263 264 265))
                 (let ((ty type))
                   (p:on peer ty (lambda (pr payload) (declare (ignore pr))
                                   (push (cons ty payload) captured)))))
               (p:start-read-loop peer)
               ;; Ask for everything: timestamp 0, range "to the end of time".
               ;; Without this a peer may only forward NEW gossip and we would
               ;; capture nothing on a quiet devnet.
               (let ((wr (w:make-writer)))
                 (w:w-hash wr (w:chain-hash))
                 (w:w-u32 wr 0)                      ; first_timestamp
                 (w:w-u32 wr #xffffffff)             ; timestamp_range
                 (p:send-message peer 265 (w:writer-bytes wr)))
               (format t "~&asked for the full gossip stream; listening ~ds…~%" seconds)
               (sleep seconds))
          (ignore-errors (p:disconnect peer)))))
    (setf captured (nreverse captured))
    (with-open-file (o *out* :direction :output :if-exists :supersede)
      (format o "# BOLT #7 gossip captured from a live Core Lightning node on the~%")
      (format o "# cl-payments private signet devnet.  <type> <hex payload>, one per line.~%")
      (format o "# The BOLTs publish no gossip vectors; this is the ground truth we have.~%")
      (dolist (m captured)
        (when (integerp (car m))
          (format o "~d ~a~%" (car m) (c:bytes->hex (cdr m))))))
    (let ((counts (make-hash-table)))
      (dolist (m captured) (incf (gethash (car m) counts 0)))
      (format t "~&captured:~%")
      (maphash (lambda (k v) (format t "   ~a x ~d~%" (p:message-name k) v)) counts)
      (format t "~&wrote ~a~%" *out*))))

(run)
