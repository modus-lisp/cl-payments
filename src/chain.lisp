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
   #:bitcoind #:make-bitcoind #:make-bitcoind-rpc
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
  ((command :initarg :command :initform nil :reader bitcoind-command
            :documentation "bitcoin-cli and its fixed arguments, as a list.")
   (rpc :initarg :rpc :initform nil :reader bitcoind-rpc
        :documentation "(host port authorization) to speak JSON-RPC directly, or NIL.")))

(defun make-bitcoind (command-string)
  "COMMAND-STRING like \"/path/bitcoin-cli -signet -datadir=/x\"."
  (make-instance 'bitcoind :command (uiop:split-string command-string :separator " ")))

(defun %cli (chain &rest args)
  "Run bitcoin-cli.  On failure the error carries bitcoind's own message —
   \"non-BIP68-final\", \"bad-txns-inputs-missingorspent\" — which is the only
   thing that distinguishes a sweep sent too early from one sent too late."
  (when (bitcoind-rpc chain)
    (return-from %cli (apply #'%rpc chain args)))
  (multiple-value-bind (out err code)
      (uiop:run-program (append (bitcoind-command chain) (remove "" args :test #'string=))
                        :output :string :error-output :string :ignore-error-status t)
    (if (zerop code)
        (string-trim '(#\Newline #\Space) out)
        (error 'chain-error :detail (format nil "bitcoin-cli ~a: ~a" (first args)
                                            (string-trim '(#\Newline #\Space) err))))))

(defun %json-value-start (json key)
  "Where KEY's value starts in JSON -- after `\"key\":` and any spaces (bitcoin-cli
   pretty-prints `\"key\": v`, the RPC answers `\"key\":v`) -- or NIL."
  (let* ((k (format nil "\"~a\":" key)) (at (search k json)))
    (when at
      (position #\Space json :start (+ at (length k)) :test-not #'char=))))

(defun %json-field (json key)
  "One string or number field out of flat JSON, without a JSON dependency."
  (let ((start (%json-value-start json key)))
    (when start
      (progn
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
  (let ((start (%json-value-start json key)))
    (when start
      (let* ((end (position-if-not (lambda (ch) (or (digit-char-p ch) (char= ch #\.))) json :start start)))
        (ignore-errors (%btc->sat (subseq json start end)))))))


;;; bitcoind's JSON-RPC, spoken directly.  For a Lisp that cannot run a
;;; subprocess (modus has no fork), and one fewer moving part anywhere.  %CLI
;;; calls it with bitcoin-cli's arguments and gets bitcoin-cli's answer back: the
;;; RESULT's own text, taken out of the response unparsed, so a decimal stays the
;;; exact string %BTC->SAT expects.

(defun make-bitcoind-rpc (host port &key cookie-file user password)
  "A chain view over bitcoind's JSON-RPC at HOST:PORT, authenticated by its
   COOKIE-FILE (datadir/<chain>/.cookie) or USER and PASSWORD."
  (let ((cred (if cookie-file
                  (string-trim '(#\Newline #\Return #\Space)
                               (with-open-file (s cookie-file) (read-line s)))
                  (format nil "~a:~a" user password))))
    (make-instance 'bitcoind :rpc (list host port (%base64 (map 'vector #'char-code cred))))))

(defun %base64 (octets)
  (let ((alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        (out (make-string-output-stream)))
    (loop for i from 0 below (length octets) by 3
          for n = (min 3 (- (length octets) i))
          for w = (logior (ash (aref octets i) 16)
                          (ash (if (> n 1) (aref octets (+ i 1)) 0) 8)
                          (if (> n 2) (aref octets (+ i 2)) 0))
          do (dotimes (k 4)
               (write-char (if (<= k n) (char alphabet (ldb (byte 6 (- 18 (* 6 k))) w)) #\=) out)))
    (get-output-stream-string out)))

(defun %rpc-param (arg)
  "A bitcoin-cli argument as the JSON value the RPC wants: a short integer or a
   boolean as itself, anything else (a txid, an address, hex) as a string."
  (cond ((string= arg "true") "true")
        ((string= arg "false") "false")
        ((and (plusp (length arg)) (< (length arg) 16) (every #'digit-char-p arg)) arg)
        (t (format nil "\"~a\"" arg))))

(defun %http-post (host port authorization body)
  "POST BODY to http://HOST:PORT/ and return the response body as a string."
  (let ((sock (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
        (octets (map '(vector (unsigned-byte 8)) #'char-code body)))
    (unwind-protect
         (progn
           (sb-bsd-sockets:socket-connect sock (sb-bsd-sockets:make-inet-address host) port)
           (let* ((head (format nil "POST / HTTP/1.1~c~cHost: ~a:~d~c~cAuthorization: Basic ~a~c~cContent-Type: text/plain~c~cContent-Length: ~d~c~cConnection: close~c~c~c~c"
                                #\Return #\Newline host port #\Return #\Newline authorization #\Return #\Newline
                                #\Return #\Newline (length octets) #\Return #\Newline #\Return #\Newline #\Return #\Newline))
                  (req (concatenate '(vector (unsigned-byte 8)) (map 'vector #'char-code head) octets)))
             (let ((off 0))
               (loop while (< off (length req))
                     do (incf off (sb-bsd-sockets:socket-send sock (subseq req off) (- (length req) off))))))
           (let ((buf (make-array 65536 :element-type '(unsigned-byte 8)))
                 (out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer t)))
             (loop (let ((n (nth-value 1 (sb-bsd-sockets:socket-receive sock buf 65536))))
                     (when (or (null n) (zerop n)) (return))
                     (loop for i below n do (vector-push-extend (aref buf i) out))))
             (let* ((text (map 'string #'code-char out))
                    (split (search (format nil "~c~c~c~c" #\Return #\Newline #\Return #\Newline) text)))
               (unless split (error 'chain-error :detail "bitcoind: malformed HTTP response"))
               (subseq text (+ split 4)))))
      (ignore-errors (sb-bsd-sockets:socket-close sock)))))

(defun %rpc (chain method &rest args)
  (destructuring-bind (host port auth) (bitcoind-rpc chain)
    (let* ((body (format nil "{\"jsonrpc\":\"1.0\",\"id\":\"clp\",\"method\":\"~a\",\"params\":[~{~a~^,~}]}"
                         method (mapcar #'%rpc-param (remove "" args :test #'string=))))
           (reply (%http-post host port auth body))
           (r (search "\"result\":" reply))
           (e (search ",\"error\":" reply :from-end t)))
      (unless (and r e) (error 'chain-error :detail (format nil "bitcoind ~a: ~a" method reply)))
      (let ((err (subseq reply (+ e 9))))
        (unless (eql 0 (search "null" err))
          (error 'chain-error :detail (format nil "bitcoin-cli ~a: ~a" method
                                              (or (ignore-errors (%json-field err "message")) err)))))
      (let ((result (string-trim " " (subseq reply (+ r 9) e))))
        (cond ((string= result "null") "")
              ((and (plusp (length result)) (char= (char result 0) #\"))
               (subseq result 1 (1- (length result))))
              (t result))))))

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
