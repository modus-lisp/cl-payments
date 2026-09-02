;;;; inspect/harness.lisp
;;;;
;;;; A minimal check/report harness shared by every gate.  Deliberately tiny and
;;;; dependency-free: the point of this suite is to be runnable with one command
;;;; and no test framework to install, matching cl-consensus's inspect/ suite.

(defpackage #:cl-payments.test
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:tp #:cl-payments.transport)
                    (#:f #:cl-payments.features) (#:p #:cl-payments.peer)
                    (#:gs #:cl-payments.gossip)
                    (#:k #:cl-payments.keys)
                    (#:m #:cl-payments.commitment)
                    (#:ch #:cl-payments.channel)
                    (#:u #:cl-payments.updates)
                    (#:n #:cl-payments.node)
                    (#:fw #:cl-payments.forward)
                    (#:lv #:cl-payments.live) (#:on #:cl-payments.onion) (#:inv #:cl-payments.invoice) (#:rt #:cl-payments.route) (#:oc #:cl-payments.onchain) (#:chn #:cl-payments.chain)
                    (#:btx #:cl-consensus.tx) (#:bs #:cl-consensus.script)
                    (#:secp #:secp256k1-fast))
  (:export #:check #:check-equal #:check-bytes #:check-signals #:check-no-signal
           #:with-gate #:run-all #:*failures* #:*checks*
           #:hx #:report))

(in-package #:cl-payments.test)

(defvar *checks* 0)
(defvar *failures* '())
(defvar *gate* "")

(defun hx (s)
  "Hex string (with optional 0x prefix and internal whitespace) to bytes."
  (let ((clean (remove-if (lambda (ch) (member ch '(#\Space #\Newline #\Tab))) s)))
    (when (and (> (length clean) 1) (string= "0x" (subseq clean 0 2)))
      (setf clean (subseq clean 2)))
    (c:hex->bytes clean)))

(defun %fail (label detail)
  (push (format nil "~a / ~a: ~a" *gate* label detail) *failures*)
  (format t "~&    FAIL  ~a — ~a~%" label detail))

(defun check (label ok &optional detail)
  (incf *checks*)
  (if ok
      (format t "~&    ok    ~a~%" label)
      (%fail label (or detail "assertion failed")))
  ok)

(defun check-equal (label actual expected)
  (incf *checks*)
  (if (equalp actual expected)
      (progn (format t "~&    ok    ~a~%" label) t)
      (progn (%fail label (format nil "~<~%          expected ~s~:@>~<~%          actual   ~s~:@>"
                                  (list expected) (list actual)))
             nil)))

(defun check-bytes (label actual expected)
  "Compare byte vectors, reporting as hex — the form every spec vector is quoted in."
  (incf *checks*)
  (let ((a (c:octets actual)) (e (c:octets expected)))
    (if (equalp a e)
        (progn (format t "~&    ok    ~a~%" label) t)
        (progn (%fail label (format nil "~%          expected ~a~%          actual   ~a"
                                    (c:bytes->hex e) (c:bytes->hex a)))
               nil))))

(defmacro check-signals (label condition-type &body body)
  "Assert BODY signals CONDITION-TYPE.  Half of wire-level correctness is
   *rejecting* malformed input, so the negative cases are first-class checks."
  `(progn
     (incf *checks*)
     (handler-case (progn ,@body
                          (%fail ,label (format nil "expected ~a, nothing signalled"
                                                ',condition-type)))
       (,condition-type () (format t "~&    ok    ~a~%" ,label) t)
       (error (e) (%fail ,label (format nil "expected ~a, got ~a: ~a"
                                        ',condition-type (type-of e) e))))))

(defmacro check-no-signal (label &body body)
  "Assert BODY completes without signalling, and return its value.

   Needed because a parser under test signals on malformed input, and a raw call
   in a gate would abort the WHOLE SUITE rather than failing one check — turning
   a one-line regression into a run with no results at all."
  (let ((v (gensym "VALUE")))
    ;; A gensym, not a literal V: the LABEL form is evaluated inside this
    ;; binding, and a caller whose own variable is named V would otherwise see
    ;; the checked value instead of its variable — a capture that surfaced as a
    ;; TYPE-ERROR pointing at a struct that had nothing to do with it.
    `(progn
       (incf *checks*)
       (handler-case (let ((,v (progn ,@body)))
                       (format t "~&    ok    ~a~%" ,label)
                       ,v)
         (error (e) (%fail ,label (format nil "signalled ~a: ~a" (type-of e) e)) nil)))))

(defmacro with-gate ((name) &body body)
  "Run a group of checks, CONTAINING any error to this gate.

   Without the handler, one unexpected signal anywhere in a gate aborts the
   entire suite and it reports NO totals at all — so a single regression hides
   every other result, including the checks that would have told you what broke.
   An error is itself a failure; it should be recorded and the remaining gates
   should still run."
  `(let ((*gate* ,name))
     (format t "~&~%  ~a~%" ,name)
     (handler-case (progn ,@body)
       (error (e)
         (%fail "gate aborted" (format nil "unexpected ~a: ~a" (type-of e) e))))))

(defun report ()
  (format t "~&~%~a~%" (make-string 62 :initial-element #\=))
  (if *failures*
      (progn
        (format t "FAILED — ~d of ~d check~:p failed~%~%" (length *failures*) *checks*)
        (dolist (f (reverse *failures*)) (format t "  · ~a~%" f))
        nil)
      (progn (format t "PASS — ~d checks~%" *checks*) t)))
