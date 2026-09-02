;;;; inspect/daemon-test.lisp
;;;;
;;;; Gate — two daemons against each other, over a real socket.
;;;;
;;;; live-test.lisp drives the commitment cycle as pure state transitions.  This
;;;; drives the DAEMON: two node instances in one process, real TCP between
;;;; them, real threads, and the whole story a channel lives — open, lock in,
;;;; pay each way, fail an unknown hash, close.  It is the check that
;;;; node.lisp's wiring (which message triggers which reply, on which thread,
;;;; under which lock) still holds, which until now only a session against
;;;; Core Lightning could say.
;;;;
;;;; No chain: the funding transaction is fabricated and "confirmed" by fiat.
;;;; Nothing in the channel protocol looks at the chain until Phase 8, and a
;;;; gate that needed bitcoind would not run in CI.

(require :asdf)
(asdf:initialize-source-registry
 (let ((here (make-pathname :name nil :type nil :defaults *load-truename*)))
   `(:source-registry (:tree ,(merge-pathnames "../" here))
                      (:tree ,(merge-pathnames "../../" here))
                      :inherit-configuration)))
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-payments"))

(defpackage #:daemon-test
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:n #:cl-payments.node) (#:lv #:cl-payments.live)
                    (#:inv #:cl-payments.invoice) (#:secp #:secp256k1-fast)
                    (#:btx #:cl-consensus.tx) (#:bt #:bordeaux-threads)
                    (#:chn #:cl-payments.chain) (#:oc #:cl-payments.onchain)
                    (#:m #:cl-payments.commitment) (#:bs #:cl-consensus.script) (#:bw #:cl-consensus.wire))
  (:export #:run))

(in-package #:daemon-test)

(defvar *checks* 0)
(defvar *fails* 0)

(defun ok (label result &optional detail)
  (incf *checks*)
  (if result
      (format t "~&    ok    ~a~%" label)
      (progn (incf *fails*) (format t "~&    FAIL  ~a~@[ — ~a~]~%" label detail)))
  result)

(defun free-port (start)
  (loop for port from start below (+ start 200)
        do (handler-case
               (let ((sock (cl-transport.listeners:tcp-listen port :address "127.0.0.1")))
                 (sb-bsd-sockets:socket-close sock)
                 (return port))
             (error () nil))
        finally (error "no free port")))

(defun wait-for (label seconds pred)
  "Poll PRED for up to SECONDS.  Everything here is asynchronous: a message
   sent is not a message handled, and the only honest check is 'did the other
   side eventually do the right thing'."
  (loop repeat (* 20 seconds)
        do (when (funcall pred) (return (ok label t)))
           (sleep 0.05)
        finally (return (ok label nil (format nil "not within ~ds" seconds)))))

(defun fresh-node (name port)
  (let ((dir (format nil "/tmp/clp-daemon-test/~a/" name)))
    (uiop:delete-directory-tree (pathname dir) :validate t :if-does-not-exist :ignore)
    (ensure-directories-exist dir)
    (with-open-file (s (merge-pathnames "node.key" dir) :direction :output)
      (write-string (c:bytes->hex (secp:int-to-bytes32 (c:generate-key))) s))
    (n:make-node :dir dir :port port :log nil)))

(defun only-channel (node)
  (let ((found nil))
    (maphash (lambda (k sc) (declare (ignore k)) (setf found sc)) (n:node-channels node))
    found))

(defun live-of (node) (let ((sc (only-channel node))) (and sc (n::sc-live sc))))

(defun fake-funding-tx (script value)
  "A transaction paying VALUE to the funding script, from nowhere.  The mock
   chain does not validate inputs, only records outputs and spends."
  (btx:parse-tx (bw:make-reader
                 (btx:serialize-tx
                  (btx:make-tx :version 2
                               :inputs (list (btx:make-txin :prev-hash (c:sha256 script) :prev-index 0 :script #() :sequence #xffffffff))
                               :outputs (list (btx:make-txout :value value :script (m:p2wsh script)))
                               :witnesses (list nil) :locktime 0 :segwit-p nil)))))

(defun spends-p (tx in prevout-script amount)
  (handler-case (bs:verify-input tx in prevout-script amount :flags '(:p2sh :witness :csv)) (error () nil)))

(defun run ()
  (setf *checks* 0 *fails* 0)
  (w:select-network :signet)
  (format t "~&=== daemon: two nodes, one channel, both directions, and a close ===~%")
  (let* ((pa (free-port 19700)) (pb (free-port (1+ pa)))
         (a (fresh-node "a" pa)) (b (fresh-node "b" pb))
         ;; ONE mock chain, seen by both: what A broadcasts, B's watcher sees.
         (chain (chn:make-mock-chain :height 100)))
    (setf (n:node-chain a) chain (n:node-chain b) chain)
    (n:start a) (n:start b)
    (unwind-protect
         (progn
           ;; ---- connect --------------------------------------------------------
           (n:connect-to a (format nil "~a@127.0.0.1:~d" (c:bytes->hex (n:node-id b)) pb) :keep-alive nil)
           (wait-for "B sees A as a peer" 5 (lambda () (plusp (n:node-peer-count b))))
           (wait-for "A sees B as a peer" 5 (lambda () (plusp (n:node-peer-count a))))

           ;; ---- open -----------------------------------------------------------
           (let ((broadcast-called nil))
             (n:open-channel-to a (n:node-id b) 1000000 :push-msat 200000000
                                :fund-fn (lambda (script)
                                           (let ((ftx (fake-funding-tx script 1000000)))
                                             (values (btx:tx-txid ftx) 0
                                                     (lambda () (setf broadcast-called t)
                                                       (chn:chain-broadcast chain ftx))))))
             (wait-for "B accepted and A recorded the channel" 5
                       (lambda () (and (live-of a) (live-of b))))
             (ok "the funding tx was 'broadcast' only after funding_signed" broadcast-called)
             (ok "both ends name the same channel"
                 (and (only-channel a) (only-channel b)
                      (equalp (n::sc-channel-id (only-channel a)) (n::sc-channel-id (only-channel b)))))
             (ok "A is the opener, B the accepter"
                 (and (eq :local (lv:live-opener (live-of a))) (eq :remote (lv:live-opener (live-of b)))))
             (ok "balances: A 800k sat, B 200k sat"
                 (and (= 800000000 (lv:live-local-balance-msat (live-of a)))
                      (= 200000000 (lv:live-local-balance-msat (live-of b)))
                      (= 200000000 (lv:live-remote-balance-msat (live-of a))))))

           ;; ---- lock in: the chain confirms the funding, the watchers notice ----
           (let ((cid (n::sc-channel-id (only-channel a))))
             (chn:mock-mine chain 1)
             (n:watch-once a) (n:watch-once b)
             (wait-for "both watchers assigned the scid from the chain" 5
                       (lambda () (and (n::sc-scid (only-channel a)) (n::sc-scid (only-channel b))
                                       (string= "101x0x0" (cl-payments.gossip:scid-string (n::sc-scid (only-channel a)))))))
             (wait-for "both ends hold the other's next per-commitment point" 5
                       (lambda () (and (lv::live-remote-next-point (live-of a))
                                       (lv::live-remote-next-point (live-of b)))))

             ;; ---- A pays B -------------------------------------------------------
             (multiple-value-bind (bolt11 hash) (n:mint-invoice b :amount-msat 50000000 :description "A pays B")
               (ok "B minted an invoice A can decode"
                   (equalp (inv:inv-payee (inv:decode-invoice bolt11)) (n:node-id b)))
               (let ((payment (n:pay-invoice a bolt11 :current-height 100)))
                 (wait-for "A's payment to B completes" 10 (lambda () (eq :complete (n:pay-status payment))))
                 (ok "A learned a preimage that hashes to the invoice"
                     (equalp (c:sha256 (n:pay-preimage payment)) hash))
                 (ok "B records the invoice as paid"
                     (eq :paid (getf (gethash (c:bytes->hex hash) (n:node-invoices b)) :status)))
                 (wait-for "both commitments settle with no HTLCs" 5
                           (lambda () (and (null (lv:live-htlcs (live-of a))) (null (lv:live-htlcs (live-of b)))
                                           (not (lv:live-pending-changes-p (live-of a)))
                                           (not (lv:live-pending-changes-p (live-of b))))))
                 (ok "A: 750k sat" (= 750000000 (lv:live-local-balance-msat (live-of a))))
                 (ok "B: 250k sat" (= 250000000 (lv:live-local-balance-msat (live-of b))))
                 (ok "the two ends agree exactly"
                     (and (= (lv:live-local-balance-msat (live-of a)) (lv:live-remote-balance-msat (live-of b)))
                          (= (lv:live-local-balance-msat (live-of b)) (lv:live-remote-balance-msat (live-of a)))))))

             ;; ---- B pays A, the other direction over the same channel ---------------
             (let* ((pre (c:sha256 (c:ascii->bytes "daemon-test/preimage-2")))
                    (bolt11 (inv:encode-invoice
                             (inv:sign-invoice
                              (inv::make-invoice-for :network :signet :amount-msat 20000000
                                                     :payment-hash (c:sha256 pre)
                                                     :payment-secret (c:sha256 (c:ascii->bytes "daemon-test/secret-2"))
                                                     :description "B pays A")
                              (n:node-privkey a)))))
               (with-open-file (s (merge-pathnames "preimages.sexp" (n:node-dir a)) :direction :output :if-exists :append :if-does-not-exist :create)
                 (format s "~s~%" (c:bytes->hex pre)))
               (let ((payment (n:pay-invoice b bolt11 :current-height 100)))
                 (wait-for "B's payment to A completes" 10 (lambda () (eq :complete (n:pay-status payment))))
                 (wait-for "settled again" 5
                           (lambda () (and (null (lv:live-htlcs (live-of a))) (null (lv:live-htlcs (live-of b))))))
                 (ok "A: 770k sat" (= 770000000 (lv:live-local-balance-msat (live-of a))))
                 (ok "B: 230k sat" (= 230000000 (lv:live-local-balance-msat (live-of b))))))

             ;; ---- a payment B cannot claim: failure onion comes back as origin ------
             (let ((bolt11 (inv:encode-invoice
                            (inv:sign-invoice
                             (inv::make-invoice-for :network :signet :amount-msat 1000000
                                                    :payment-hash (c:sha256 (c:ascii->bytes "no such preimage"))
                                                    :payment-secret (c:sha256 (c:ascii->bytes "x"))
                                                    :description "unknown")
                             (n:node-privkey b)))))
               (let ((payment (n:pay-invoice a bolt11 :current-height 100)))
                 (wait-for "A's payment for an unknown hash fails" 10 (lambda () (eq :failed (n:pay-status payment))))
                 (ok "the failure names B and the right code"
                     (and (eql 0 (getf (n:pay-failure payment) :hop))
                          (eq :incorrect-or-unknown-payment-details (getf (n:pay-failure payment) :code))))
                 (wait-for "settled after the failure" 5
                           (lambda () (and (null (lv:live-htlcs (live-of a))) (null (lv:live-htlcs (live-of b))))))
                 (ok "A's balance is restored" (= 770000000 (lv:live-local-balance-msat (live-of a))))))

             ;; ---- B publishes a REVOKED commitment; A's watcher punishes it ------
             ;; B's previous commitment is a state B revoked when it accepted the
             ;; next one.  Broadcasting it is theft; A must take everything.
             (let* ((cheat (lv:previous-commitment-tx (live-of b))))
               (ok "B holds a signed previous (revoked) commitment" (and cheat t))
               (chn:chain-broadcast chain cheat)
               (chn:mock-mine chain 1)
               (n:watch-once a) (n:watch-once b)
               (ok "A classified the spend as :revoked" (eq :revoked (n::sc-close-kind (only-channel a))))
               (ok "B knows it published its own commitment" (eq :our-commitment (n::sc-close-kind (only-channel b))))
               (let ((pen (find (n::sc-sweep-txid (only-channel a)) (chn:mock-mempool chain) :key #'btx:tx-txid :test #'equalp)))
                 (ok "A broadcast a penalty" (and pen t))
                 (when pen
                   (multiple-value-bind (lidx lvalue) (oc:to-local-output (live-of a) cheat :theirs t :n (lv::live-prev-index (live-of b)))
                     (ok "the penalty spends B's to_local with the revocation key"
                         (spends-p pen 0 (btx:txout-script (nth lidx (btx:tx-outputs cheat))) lvalue))
                     (ok "and takes it all to A's address"
                         (equalp (btx:txout-script (first (btx:tx-outputs pen))) (n::our-sweep-script a (only-channel a))))))
                 ;; B, having cheated, waits out its own delay and tries to sweep —
                 ;; but the penalty has already spent the output.
                 (chn:mock-mine chain 1)
                 (chn:mock-mine chain 200)
                 (n:watch-once b)
                 (ok "B's delayed sweep finds the output already gone"
                     (not (chn:chain-txout-unspent-p chain (btx:tx-txid cheat) 0)))))

             ;; ---- and it all survived being written to disk ------------------------
             (let ((reloaded (n:make-node :dir (n:node-dir a) :port 0 :log nil)))
               (n:load-channels reloaded)
               (ok "A's state reloads with the close recorded"
                   (let ((sc (only-channel reloaded)))
                     (and sc (eq :revoked (n::sc-close-kind sc)) (n::sc-sweep-txid sc)))))))
      (ignore-errors (n:stop a)) (ignore-errors (n:stop b))))
  (format t "~&~%~d check~:p, ~d failure~:p~%" *checks* *fails*)
  (zerop *fails*))
