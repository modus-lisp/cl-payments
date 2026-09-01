;;;; inspect/transport-test.lisp
;;;;
;;;; Gate 3 — BOLT #8, against the spec's own test vectors.
;;;;
;;;; The handshake is driven here as pure state transitions with the ephemeral
;;;; keys INJECTED, which is the only way to reproduce fixed vectors: a real
;;;; handshake generates `e` randomly and is unreproducible by construction.
;;;; That is why src/transport.lisp keeps the three acts separate from the socket
;;;; code — testability is the reason for the shape, not an afterthought.
;;;;
;;;; The key-rotation vector matters more than it looks: rotation only kicks in
;;;; at message 1000, so a bug there is invisible in every short-lived test and
;;;; then drops a long-running node's connection an hour in.
;;;;
;;;; Vectors: https://github.com/lightning/bolts/blob/master/08-transport.md

(in-package #:cl-payments.test)

;; The spec's fixed keys, shared by the initiator and responder vectors.
(defparameter *ls-priv-initiator* #x1111111111111111111111111111111111111111111111111111111111111111)
(defparameter *ls-priv-responder* #x2121212121212121212121212121212121212121212121212121212121212121)
(defparameter *e-priv-initiator*  #x1212121212121212121212121212121212121212121212121212121212121212)
(defparameter *e-priv-responder*  #x2222222222222222222222222222222222222222222222222222222222222222)

(defparameter *rs-pub*
  "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7")
(defparameter *act-one*
  "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a")
(defparameter *act-two*
  "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae")
(defparameter *act-three*
  "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba")
(defparameter *final-sk*
  "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9")
(defparameter *final-rk*
  "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442")
(defparameter *final-ck*
  "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01")

(defun test-bolt8-initiator ()
  (with-gate ("BOLT #8 — initiator handshake")
    (let ((hs (tp:make-initiator-handshake *ls-priv-initiator* (hx *rs-pub*)
                                           :ephemeral *e-priv-initiator*)))
      (check-bytes "act one output" (tp:act-one-write hs) (hx *act-one*))
      (tp:act-two-read hs (hx *act-two*))
      (multiple-value-bind (msg session) (tp:act-three-write hs)
        (check-bytes "act three output" msg (hx *act-three*))
        ;; The initiator SENDS with the first HKDF half and RECEIVES with the
        ;; second; the responder is the mirror.  Swapping them is the classic
        ;; BOLT #8 bug — the handshake still "succeeds" and then every message
        ;; fails to decrypt.
        (check-bytes "final sk" (tp:noise-sk session) (hx *final-sk*))
        (check-bytes "final rk" (tp:noise-rk session) (hx *final-rk*))))))

(defun test-bolt8-responder ()
  (with-gate ("BOLT #8 — responder handshake")
    (let ((hs (tp:make-responder-handshake *ls-priv-responder*
                                           :ephemeral *e-priv-responder*)))
      (tp:act-one-read hs (hx *act-one*))
      (check-bytes "act two output" (tp:act-two-write hs) (hx *act-two*))
      (let ((session (tp:act-three-read hs (hx *act-three*))))
        ;; Reversed relative to the initiator — this is the whole point.
        (check-bytes "final sk (mirrored)" (tp:noise-sk session) (hx *final-rk*))
        (check-bytes "final rk (mirrored)" (tp:noise-rk session) (hx *final-sk*))
        (check-bytes "learned the initiator's static key"
                     (tp:noise-remote-node-id session)
                     (hx "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"))))))

(defun test-bolt8-handshake-rejects ()
  (with-gate ("BOLT #8 — malformed handshake input")
    ;; Everything here is attacker-controlled, so rejection is a feature.
    (let ((hs (tp:make-responder-handshake *ls-priv-responder*
                                           :ephemeral *e-priv-responder*)))
      (check-signals "wrong length rejected" tp:handshake-error
        (tp:act-one-read hs (hx "0000"))))
    (let ((hs (tp:make-responder-handshake *ls-priv-responder*
                                           :ephemeral *e-priv-responder*))
          (bad (copy-seq (hx *act-one*))))
      (setf (aref bad 0) 1)                       ; unsupported version byte
      (check-signals "bad version rejected" tp:handshake-error (tp:act-one-read hs bad)))
    (let ((hs (tp:make-responder-handshake *ls-priv-responder*
                                           :ephemeral *e-priv-responder*))
          (bad (copy-seq (hx *act-one*))))
      (setf (aref bad 49) (logxor (aref bad 49) 1))  ; corrupt the tag
      (check-signals "corrupt tag rejected" tp:handshake-error (tp:act-one-read hs bad)))))

;;; ----------------------------------------------------------------------------
;;; The transport, including key rotation at message 1000.
;;; ----------------------------------------------------------------------------

(defun test-bolt8-message-encryption ()
  ;; Encrypt "hello" 1002 times and check the spec's sampled outputs.  Messages
  ;; 1000 and 1001 are the ones that exercise the key rotation.
  (with-gate ("BOLT #8 — message encryption + key rotation")
    (let* ((session (tp::%make-noise
                     :sk (hx *final-sk*) :sn 0 :s-ck (hx *final-ck*)
                     :rk (hx *final-rk*) :rn 0 :r-ck (hx *final-ck*)
                     :stream nil))
           (expected '((0    . "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95")
                       (1    . "72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1")
                       (500  . "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8")
                       (501  . "1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd")
                       (1000 . "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09")
                       (1001 . "2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36")))
           (msg (c:ascii->bytes "hello")))
      ;; %FRAME does everything NOISE-SEND does except the write, so the frames
      ;; can be compared byte-for-byte with no socket involved.
      (dotimes (i 1002)
        (let ((out (tp::%frame session msg))
              (want (cdr (assoc i expected))))
          (when want
            (check-bytes (format nil "message ~d" i) out (hx want))))))))

(defun run-transport-tests ()
  (test-bolt8-initiator)
  (test-bolt8-responder)
  (test-bolt8-handshake-rejects)
  (test-bolt8-message-encryption))
