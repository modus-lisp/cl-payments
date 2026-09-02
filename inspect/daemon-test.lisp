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
                    (#:btx #:cl-consensus.tx) (#:bt #:bordeaux-threads))
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

(defun run ()
  (setf *checks* 0 *fails* 0)
  (w:select-network :signet)
  (format t "~&=== daemon: two nodes, one channel, both directions, and a close ===~%")
  (let* ((pa (free-port 19700)) (pb (free-port (1+ pa)))
         (a (fresh-node "a" pa)) (b (fresh-node "b" pb)))
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
                                           ;; a funding "transaction" that is just a name
                                           (values (c:sha256 (c:bytes (c:ascii->bytes "funding") script)) 0
                                                   (lambda () (setf broadcast-called t)))))
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

           ;; ---- lock in --------------------------------------------------------
           (let ((cid (n::sc-channel-id (only-channel a))))
             ;; A short channel id names WHERE the funding confirmed; with no
             ;; chain, the test assigns one.  Routing needs it even for a direct
             ;; payment, because the first hop is looked up by scid.
             (let ((scid (cl-payments.gossip:make-scid 100 1 0)))
               (n:funding-confirmed a cid :scid scid) (n:funding-confirmed b cid :scid scid))
             (wait-for "both ends hold the other's next per-commitment point" 5
                       (lambda () (and (lv::live-remote-next-point (live-of a))
                                       (lv::live-remote-next-point (live-of b)))))

             ;; ---- A pays B -------------------------------------------------------
             (let* ((pre (c:sha256 (c:ascii->bytes "daemon-test/preimage-1")))
                    (secret (c:sha256 (c:ascii->bytes "daemon-test/secret-1")))
                    (bolt11 (inv:encode-invoice
                             (inv:sign-invoice
                              (inv::make-invoice-for :network :signet :amount-msat 50000000
                                                     :payment-hash (c:sha256 pre) :payment-secret secret
                                                     :description "A pays B" :min-final-cltv 18)
                              (n:node-privkey b)))))
               (with-open-file (s (merge-pathnames "preimages.sexp" (n:node-dir b)) :direction :output :if-exists :append :if-does-not-exist :create)
                 (format s "~s~%" (c:bytes->hex pre)))
               (let ((payment (n:pay-invoice a bolt11 :current-height 100)))
                 (wait-for "A's payment to B completes" 10 (lambda () (eq :complete (n:pay-status payment))))
                 (ok "A learned the preimage" (equalp (n:pay-preimage payment) pre))
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

             ;; ---- close, initiated by the accepter; the opener proposes the fee -----
             (n:close-channel b cid)
             (wait-for "both ends closed" 10 (lambda () (and (lv:live-closed-p (live-of a)) (lv:live-closed-p (live-of b)))))
             (ok "both ends built the same closing transaction"
                 (equalp (lv:live-closing-txid (live-of a)) (lv:live-closing-txid (live-of b))))

             ;; ---- and it all survived being written to disk ------------------------
             (let ((reloaded (n:make-node :dir (n:node-dir a) :port 0 :log nil)))
               (n:load-channels reloaded)
               (ok "A's state reloads closed, with the final balance"
                   (let ((lc (live-of reloaded)))
                     (and lc (lv:live-closed-p lc) (= 770000000 (lv:live-local-balance-msat lc))))))))
      (ignore-errors (n:stop a)) (ignore-errors (n:stop b))))
  (format t "~&~%~d check~:p, ~d failure~:p~%" *checks* *fails*)
  (zerop *fails*))
