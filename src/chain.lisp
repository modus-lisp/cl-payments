;;;; src/chain.lisp
;;;;
;;;; Phase 8 — the chain view.
;;;;
;;;; Everything above this layer has been pretending the chain does not exist:
;;;; heights passed in by hand, fundings confirmed by fiat.  A Lightning node
;;;; that cannot see the chain is a node that cannot tell whether its channel
;;;; is still open, which is the one thing it most needs to know — a peer that
;;;; publishes a revoked commitment is stealing, and the theft succeeds if
;;;; nobody is watching for the CSV delay to run out.
;;;;
;;;; Two backends behind one small protocol: bitcoind over bitcoin-cli, and an
;;;; in-memory chain for tests.  The daemon and the gates use the same code
;;;; above this line; only the source of blocks differs.

(defpackage #:cl-payments.chain
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:btx #:cl-consensus.tx)
                    (#:bb #:cl-consensus.block) (#:bw #:cl-consensus.wire))
  (:nicknames #:ln-chain)
  (:export
   #:chain-height #:chain-block-txs #:chain-txout-unspent-p #:chain-broadcast
   #:chain-confirmations #:chain-tx-position #:chain-feerate #:chain-error
   #:bitcoind #:make-bitcoind
   #:mock-chain #:make-mock-chain #:mock-mine #:mock-mempool))

(in-package #:cl-payments.chain)

(define-condition chain-error (error)
  ((detail :initarg :detail :reader chain-error-detail))
  (:report (lambda (c s) (format s "chain: ~a" (chain-error-detail c)))))

(defgeneric chain-height (chain))
(defgeneric chain-block-txs (chain height)
  (:documentation "The parsed transactions of the block at HEIGHT."))
(defgeneric chain-txout-unspent-p (chain txid-bytes vout)
  (:documentation "T if the output is in the UTXO set — i.e. NOT yet spent."))
(defgeneric chain-broadcast (chain tx))
(defgeneric chain-confirmations (chain txid-bytes)
  (:documentation "Confirmations of a transaction, or NIL if unknown."))
(defgeneric chain-tx-position (chain txid-bytes)
  (:documentation "(values height index) of a confirmed transaction, or NIL."))
(defgeneric chain-feerate (chain)
  (:documentation "A feerate to pay, in satoshi per 1000 virtual bytes.  Never
   below the relay floor: a sweep that is cheaper than that is a sweep nobody
   relays, and the deadline it was racing does not wait."))

(defconstant +feerate-floor+ 1000 "1 sat/vB: Core's default minimum relay fee.")

;;; ----------------------------------------------------------------------------
;;; bitcoind, over bitcoin-cli
;;; ----------------------------------------------------------------------------

(defclass bitcoind ()
  ((command :initarg :command :reader bitcoind-command
            :documentation "bitcoin-cli and its fixed arguments, as a list.")))

(defun make-bitcoind (command-string)
  "COMMAND-STRING like \"/path/bitcoin-cli -signet -datadir=/x\"."
  (make-instance 'bitcoind :command (uiop:split-string command-string :separator " ")))

(defun %cli (chain &rest args)
  "Run bitcoin-cli.  On failure the error carries bitcoind's own message —
   \"non-BIP68-final\", \"bad-txns-inputs-missingorspent\" — which is the only
   thing that distinguishes a sweep sent too early from one sent too late."
  (multiple-value-bind (out err code)
      (uiop:run-program (append (bitcoind-command chain) (remove "" args :test #'string=))
                        :output :string :error-output :string :ignore-error-status t)
    (if (zerop code)
        (string-trim '(#\Newline #\Space) out)
        (error 'chain-error :detail (format nil "bitcoin-cli ~a: ~a" (first args)
                                            (string-trim '(#\Newline #\Space) err))))))

(defun %json-field (json key)
  "One string or number field out of flat JSON, without a JSON dependency."
  (let* ((k (format nil "\"~a\": " key)) (at (search k json)))
    (when at
      (let ((start (+ at (length k))))
        (if (char= (char json start) #\")
            (subseq json (1+ start) (position #\" json :start (1+ start)))
            (parse-integer json :start start :junk-allowed t))))))

(defmethod chain-height ((chain bitcoind))
  (parse-integer (%cli chain "getblockcount")))

(defmethod chain-block-txs ((chain bitcoind) height)
  (let* ((hash (%cli chain "getblockhash" (princ-to-string height)))
         (hex (%cli chain "getblock" hash "0")))
    (coerce (bb:block-txs (bb:parse-block (bw:hex->bytes hex))) 'list)))

(defmethod chain-txout-unspent-p ((chain bitcoind) txid vout)
  ;; gettxout prints nothing for a spent (or unknown) output.
  (plusp (length (%cli chain "gettxout" (bw:hash->hex txid) (princ-to-string vout)))))

(defmethod chain-broadcast ((chain bitcoind) tx)
  (%cli chain "sendrawtransaction" (c:bytes->hex (btx:serialize-tx tx))))

(defmethod chain-confirmations ((chain bitcoind) txid)
  (let ((json (handler-case (%cli chain "getrawtransaction" (bw:hash->hex txid) "true")
                (chain-error () nil))))
    (and json (%json-field json "confirmations"))))

(defun %btc->sat (str)
  "\"0.00001234\" -> 1234, exactly.  Decimal strings are not floats; reading
   them as floats and multiplying by 1e8 is how a fee ends up one satoshi off."
  (let* ((dot (position #\. str))
         (whole (parse-integer str :end (or dot (length str))))
         (frac (if dot (subseq str (1+ dot)) ""))
         (frac (subseq (concatenate 'string frac "00000000") 0 8)))
    (+ (* whole 100000000) (parse-integer frac))))

(defun %json-decimal (json key)
  "A decimal-number field as satoshis, or NIL."
  (let* ((k (format nil "\"~a\": " key)) (at (search k json)))
    (when at
      (let* ((start (+ at (length k)))
             (end (position-if-not (lambda (ch) (or (digit-char-p ch) (char= ch #\.))) json :start start)))
        (ignore-errors (%btc->sat (subseq json start end)))))))

(defmethod chain-feerate ((chain bitcoind))
  ;; estimatesmartfee answers in BTC/kvB, or with an "errors" field when it has
  ;; nothing to say — on a chain whose mempool has never been full, that is
  ;; always.  Then the node's own relay minimum is the honest number.
  (let ((est (%json-decimal (handler-case (%cli chain "estimatesmartfee" "6") (chain-error () "")) "feerate"))
        (min (%json-decimal (handler-case (%cli chain "getmempoolinfo") (chain-error () "")) "mempoolminfee")))
    (max +feerate-floor+ (or est 0) (or min 0))))

(defmethod chain-tx-position ((chain bitcoind) txid)
  (let ((json (handler-case (%cli chain "getrawtransaction" (bw:hash->hex txid) "true")
                (chain-error () nil))))
    (when json
      (let ((blockhash (%json-field json "blockhash")))
        (when blockhash
          (let* ((bjson (%cli chain "getblockheader" blockhash))
                 (height (%json-field bjson "height"))
                 (txs (chain-block-txs chain height))
                 (idx (position txid txs :key #'btx:tx-txid :test #'equalp)))
            (values height idx)))))))

;;; ----------------------------------------------------------------------------
;;; An in-memory chain, for gates
;;; ----------------------------------------------------------------------------

(defclass mock-chain ()
  ((blocks :initform (make-array 0 :adjustable t :fill-pointer t) :accessor mock-blocks)
   (mempool :initform '() :accessor mock-mempool)))

(defun make-mock-chain (&key (height 0))
  (let ((m (make-instance 'mock-chain)))
    (dotimes (i (1+ height)) (vector-push-extend '() (mock-blocks m)))
    m))

(defun mock-mine (chain &optional (n 1))
  "Confirm the mempool into the next block, then N-1 empty blocks."
  (vector-push-extend (reverse (mock-mempool chain)) (mock-blocks chain))
  (setf (mock-mempool chain) '())
  (dotimes (i (1- n)) (vector-push-extend '() (mock-blocks chain)))
  (chain-height chain))

(defmethod chain-height ((chain mock-chain)) (1- (length (mock-blocks chain))))
(defmethod chain-feerate ((chain mock-chain)) 2000)
(defmethod chain-block-txs ((chain mock-chain) height) (aref (mock-blocks chain) height))
(defmethod chain-broadcast ((chain mock-chain) tx) (push tx (mock-mempool chain)) (bw:hash->hex (btx:tx-txid tx)))

(defun %mock-all-txs (chain)
  (loop for h from 0 to (chain-height chain) append (aref (mock-blocks chain) h)))

(defmethod chain-txout-unspent-p ((chain mock-chain) txid vout)
  (notany (lambda (tx) (some (lambda (in) (and (equalp (btx:txin-prev-hash in) (c:octets txid))
                                               (= (btx:txin-prev-index in) vout)))
                             (btx:tx-inputs tx)))
          (%mock-all-txs chain)))

(defmethod chain-tx-position ((chain mock-chain) txid)
  (loop for h from 0 to (chain-height chain)
        for idx = (position txid (aref (mock-blocks chain) h) :key #'btx:tx-txid :test #'equalp)
        when idx do (return (values h idx))))

(defmethod chain-confirmations ((chain mock-chain) txid)
  (let ((h (chain-tx-position chain txid)))
    (and h (1+ (- (chain-height chain) h)))))
