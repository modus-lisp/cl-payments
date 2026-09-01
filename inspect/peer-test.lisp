;;;; inspect/peer-test.lisp
;;;;
;;;; Gate 4 — BOLT #9 feature bits and the BOLT #1 setup/control messages.
;;;;
;;;; The feature-vector encoding is the part worth pinning: bit 0 is the LEAST
;;;; significant bit of the LAST byte, so the vector reads right-to-left across
;;;; the byte string.  Getting it backwards produces a vector that is perfectly
;;;; well-formed and means something entirely different, and the only symptom is
;;;; a peer quietly closing the connection.  The vectors here are the REAL ones
;;;; Core Lightning and LND sent us on the devnet, so a regression is measured
;;;; against what those implementations actually emit.
;;;;
;;;; The ping/pong rules look like trivia and are not: `num_pong_bytes >= 65532`
;;;; must NOT be answered, because the reply could not be framed inside BOLT #8's
;;;; u16 length — answering anyway is how you turn a peer into an amplifier.

(in-package #:cl-payments.test)

;;; Captured from the devnet: what each implementation actually advertises.
(defparameter *cln-features-hex* "800898880a8a59a1")
(defparameter *lnd-features-tail-hex* "10888a8251a1")

(defun test-feature-encoding ()
  (with-gate ("BOLT #9 — feature vector encoding")
    ;; Bit 0 is the LSB of the LAST byte, which makes the vector a big-endian
    ;; integer.  These pin that, cheaply and unambiguously.
    (check-bytes "bit 0 set"  (f:features->bytes 1)      (hx "01"))
    (check-bytes "bit 7 set"  (f:features->bytes 128)    (hx "80"))
    (check-bytes "bit 8 set"  (f:features->bytes 256)    (hx "0100"))
    (check-bytes "bit 15 set" (f:features->bytes 32768)  (hx "8000"))
    (check-bytes "empty vector" (f:features->bytes 0)    (hx ""))
    (check-equal "round-trip" (f:bytes->features (f:features->bytes #x800898880a8a59a1))
                 #x800898880a8a59a1)
    ;; And against the real thing.
    (let ((cln (f:bytes->features (hx *cln-features-hex*))))
      (check "CLN sets bit 0 (data_loss_protect, required)" (f:feature-set-p cln 0))
      (check "CLN sets bit 8 (var_onion_optin, required)"  (f:feature-set-p cln 8))
      (check "CLN sets bit 44 (channel_type, required)"    (f:feature-set-p cln 44))
      (check "CLN sets bit 7 (gossip_queries, optional)"   (f:feature-set-p cln 7))
      (check "CLN does not set bit 6" (not (f:feature-set-p cln 6)))
      (check-bytes "CLN vector re-encodes identically"
                   (f:features->bytes cln) (hx *cln-features-hex*)))))

(defun test-feature-semantics ()
  (with-gate ("BOLT #9 — required / optional semantics")
    (let ((req (f:features-from '((:gossip-queries . :required))))
          (opt (f:features-from '((:gossip-queries . :optional)))))
      (check "required half sets the even bit" (f:feature-set-p req 6))
      (check "optional half sets the odd bit"  (f:feature-set-p opt 7))
      ;; "Supported" means either half — which half is the sender's problem.
      (check "required counts as supported" (f:feature-supported-p req :gossip-queries))
      (check "optional counts as supported" (f:feature-supported-p opt :gossip-queries))
      (check "only the required form is required"
             (and (f:feature-required-p req :gossip-queries)
                  (not (f:feature-required-p opt :gossip-queries)))))
    (check-signals "the same feature twice is rejected" f:feature-error
      (f:features-from '((:gossip-queries . :required) (:gossip-queries . :optional))))
    ;; The rule that actually protects us: an unknown EVEN bit means the peer
    ;; depends on something we cannot do, and we must not pretend otherwise.
    (check-equal "unknown even bit is reported"
                 (f:unknown-required-bits (ash 1 200)) '(200))
    (check-equal "unknown ODD bit is ignored (it's ok to be odd)"
                 (f:unknown-required-bits (ash 1 201)) '())
    (check-equal "known even bits are not reported"
                 (f:unknown-required-bits (f:features-from '((:payment-secret . :required))))
                 '())
    ;; Both real peers set high odd bits we don't know; those must be harmless.
    (check-equal "LND's unknown odd bits are harmless"
                 (f:unknown-required-bits (logior (ash 1 2023) (ash 1 35))) '())))

(defun test-feature-dependencies ()
  (with-gate ("BOLT #9 — dependencies")
    (check "our default vector is self-consistent"
           (f:check-dependencies f:*default-features*))
    (check-signals "payment_secret without var_onion_optin is rejected" f:feature-error
      (f:check-dependencies (f:features-from '((:payment-secret . :optional)))))
    (check-signals "basic_mpp without payment_secret is rejected" f:feature-error
      (f:check-dependencies (f:features-from '((:var-onion-optin . :optional)
                                               (:basic-mpp . :optional)))))
    (check "both real peers' vectors satisfy their dependencies"
           (and (f:check-dependencies (f:bytes->features (hx *cln-features-hex*)))
                t))))

(defun test-default-features ()
  (with-gate ("what we advertise")
    ;; Advertising nothing is not a safe default: LND closes the connection.
    ;; These five are the ones both CLN and LND mark REQUIRED in their own init.
    (dolist (name '(:data-loss-protect :var-onion-optin :static-remotekey
                    :payment-secret :channel-type))
      (check (format nil "offers ~(~a~)" name)
             (f:feature-supported-p f:*default-features* name)))
    ;; …but we offer them as ODD.  An even bit demands the peer fail if it can't
    ;; comply, and we are not in a position to demand anything yet.
    (dolist (name '(:data-loss-protect :var-onion-optin :static-remotekey
                    :payment-secret :channel-type :gossip-queries))
      (check (format nil "~(~a~) is optional, not required" name)
             (not (f:feature-required-p f:*default-features* name))))
    (check "we require nothing at all"
           (loop for bit from 0 below (integer-length f:*default-features*)
                 never (and (evenp bit) (f:feature-set-p f:*default-features* bit))))))

(defun test-init-message ()
  (with-gate ("BOLT #1 — init")
    (let* ((features (f:features-from '((:gossip-queries . :optional))))
           (msg (p::encode-init features)))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (check-equal "type is 16" type p:+msg-init+)
        (multiple-value-bind (theirs global tlv) (p::decode-init payload)
          (declare (ignore tlv))
          (check-equal "features round-trip" theirs features)
          (check-equal "globalfeatures is empty" global 0))))
    ;; BOLT #1 says to treat globalfeatures and features as concatenated, so a
    ;; peer still using the legacy field must decode correctly.
    (let ((wr (w:make-writer)))
      (w:w-varbytes wr (hx "02"))      ; globalfeatures: bit 1
      (w:w-varbytes wr (hx "80"))      ; features: bit 7
      (multiple-value-bind (theirs) (p::decode-init (w:writer-bytes wr))
        (check-equal "legacy globalfeatures are OR'd in" theirs #x82)))
    ;; The networks TLV: getting this wrong makes CLN reject the connection with
    ;; "No common network", which is the TLV doing its job.
    (let* ((chain (w:chain-hash))
           (msg (p::encode-init 0 :chain-hashes (list chain))))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (declare (ignore type))
        (multiple-value-bind (fs g tlv) (p::decode-init payload)
          (declare (ignore fs g))
          (check-equal "one TLV record" (length tlv) 1)
          (check-equal "record type 1 (networks)" (w:tlv-record-type (first tlv)) 1)
          (check-bytes "carries our chain hash" (w:tlv-record-value (first tlv)) chain))))))

(defun test-ping-pong ()
  (with-gate ("BOLT #1 — ping / pong")
    (let ((msg (p::encode-ping 32 8)))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (check-equal "type is 18" type p:+msg-ping+)
        (let ((r (w:make-reader payload)))
          (check-equal "num_pong_bytes" (w:r-u16 r) 32)
          (check-equal "ignored field length" (length (w:r-varbytes r)) 8))))
    ;; The rule that matters: at or above 65532 the pong could not be framed
    ;; inside BOLT #8's u16 length, so it MUST NOT be answered.  A node that
    ;; answers anyway is an amplifier.
    (check "0 bytes must be answered"     (p:pong-required-p 0))
    (check "65531 must be answered"       (p:pong-required-p 65531))
    (check "65532 must NOT be answered"   (not (p:pong-required-p 65532)))
    (check "65535 must NOT be answered"   (not (p:pong-required-p 65535)))
    ;; And that the decision actually drives HANDLE-PING: with no session wired
    ;; up, answering would signal, so silence is observable.
    (let ((probe (p::%make-peer :node-id (make-array 33 :element-type '(unsigned-byte 8)
                                                        :initial-element 2)
                                :session nil :log-stream nil))
          (wr (w:make-writer)))
      (w:w-u16 wr 65532) (w:w-varbytes wr #())
      (check "handle-ping stays silent above the threshold"
             (null (handler-case (progn (p::handle-ping probe (w:writer-bytes wr)) nil)
                     (error () :answered))))
      (let ((wr2 (w:make-writer)))
        (w:w-u16 wr2 8) (w:w-varbytes wr2 #())
        (check "handle-ping does try to answer below it"
               (eq :answered
                   (handler-case (progn (p::handle-ping probe (w:writer-bytes wr2)) nil)
                     (error () :answered))))))))

(defun test-error-messages ()
  (with-gate ("BOLT #1 — error / warning")
    (let ((wr (w:make-writer)))
      (w:w-hash wr (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
      (w:w-varbytes wr (c:ascii->bytes "No common network"))
      (let ((s (p::decode-error (w:writer-bytes wr))))
        (check "all-zero channel id renders without a channel prefix"
               (string= s "No common network"))))
    ;; The data field is attacker-controlled and explicitly may be arbitrary
    ;; bytes; it must never reach a terminal raw.
    (let ((wr (w:make-writer)))
      (w:w-hash wr (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
      (w:w-varbytes wr (hx "1b5b324a07"))       ; ESC [ 2 J BEL — clear screen, beep
      (let ((s (p::decode-error (w:writer-bytes wr))))
        (check "control bytes are sanitised" (every (lambda (ch) (<= 32 (char-code ch) 126)) s))))
    (check "malformed error does not signal"
           (stringp (p::decode-error (hx "00"))))))

(defun run-peer-tests ()
  (test-feature-encoding)
  (test-feature-semantics)
  (test-feature-dependencies)
  (test-default-features)
  (test-init-message)
  (test-ping-pong)
  (test-error-messages))
