;;;; inspect/rail-test.lisp
;;;;
;;;; The payment rail at its boundaries: what we pay is what we were told to
;;;; pay, what we accept as paid is what the invoice asked for, and both
;;;; survive a restart.  Each gate here is a bug that let value in or out
;;;; without the matching value on the other side.

(in-package #:cl-payments.test)

(defun rail-node (dir key)
  (n:make-node :dir dir :port 0 :privkey key :log nil))

(defun rail-dir (name)
  (let ((d (uiop:ensure-directory-pathname
            (format nil "/tmp/clp-rail-~a-~d/" name (random 1000000000 (make-random-state t))))))
    (ensure-directories-exist d)
    d))

(defun run-rail-tests ()
  (w:select-network :signet)
  (let* ((dir (rail-dir "a")) (a (rail-node dir 4242424242)))
    (multiple-value-bind (bolt11 hash) (n:mint-invoice a :amount-msat 50000000 :description "rail")
      (let* ((rec (gethash (n::%hex hash) (n:node-invoices a)))
             (secret (getf rec :payment-secret)))
        (with-gate ("rail: the final hop holds an HTLC to the invoice (L2)")
          (check "the invoice record keeps its payment secret" (and secret t))
          (flet ((hp (&key (secret secret) total)
                   (on:make-hop-payload :amount-msat 50000000 :cltv-expiry 800 :payment-secret secret :total-msat total)))
            (check "the invoiced amount with the right secret is accepted"
                   (null (n::final-hop-refusal a hash 50000000 (hp))))
            (check "an underpaid HTLC is refused, whatever the onion claims"
                   (n::final-hop-refusal a hash 1 (on:make-hop-payload :amount-msat 1 :cltv-expiry 800 :payment-secret secret)))
            (check "a wrong payment secret is refused"
                   (n::final-hop-refusal a hash 50000000 (hp :secret (c:sha256 (c:ascii->bytes "wrong")))))
            (check "a missing payment secret is refused"
                   (n::final-hop-refusal a hash 50000000 (on:make-hop-payload :amount-msat 50000000 :cltv-expiry 800)))
            (check "a multi-part total larger than this HTLC is refused"
                   (n::final-hop-refusal a hash 50000000 (hp :total 90000000)))
            (check "a hash with no invoice is not ours to judge"
                   (null (n::final-hop-refusal a (c:sha256 (c:ascii->bytes "bare")) 1
                                               (on:make-hop-payload :amount-msat 1 :cltv-expiry 800))))))

        (with-gate ("rail: we pay what we are told, never the invoice's larger amount (L1)")
          (let ((b (rail-node (rail-dir "b") 4343434343)))
            (handler-case (progn (n:pay-invoice b bolt11 :current-height 100 :amount-msat 1000)
                                 (check "a lock of 1000 msat against a 50000000 msat invoice is refused" nil))
              (n:node-error (e)
                (check "a lock of 1000 msat against a 50000000 msat invoice is refused"
                       (search "invoice is for" (princ-to-string e)) (princ-to-string e))))
            ;; A payment already in flight for this hash is never sent again.
            (setf (gethash (n::%hex hash) (n:node-payments b))
                  (n::make-payment :payment-hash hash :amount-msat 50000000 :status :pending))
            (handler-case (progn (n:pay-invoice b bolt11 :current-height 100 :amount-msat 50000000)
                                 (check "a second payment of an in-flight hash is refused" nil))
              (n:node-error (e)
                (check "a second payment of an in-flight hash is refused"
                       (search "already pending" (princ-to-string e)) (princ-to-string e))))))

        (with-gate ("rail: invoices, payments and the scan height survive a restart")
          (n::invoice-paid a hash 50000000)
          (setf (n::node-scanned-height a) 777)
          (setf (gethash "ab" (n:node-payments a))
                (n::make-payment :payment-hash (c:sha256 (c:ascii->bytes "p")) :amount-msat 7000 :status :pending
                                 :shared-secrets (list (c:sha256 (c:ascii->bytes "ss")))))
          (n::save-state a)
          (let ((a2 (rail-node dir 4242424242)))
            (n::load-state a2)
            (let ((r2 (gethash (n::%hex hash) (n:node-invoices a2))))
              (check-equal "the invoice comes back paid" (getf r2 :status) :paid)
              (check-equal "with what was received" (getf r2 :received-msat) 50000000)
              (check "and its payment secret" (equalp (c:octets (getf r2 :payment-secret)) (c:octets secret)))
              (check "so the final-hop check still applies after a restart"
                     (n::final-hop-refusal a2 hash 1 (on:make-hop-payload :amount-msat 1 :cltv-expiry 800 :payment-secret secret))))
            (check-equal "the scan height comes back" (n::node-scanned-height a2) 777)
            (let ((p (gethash (n::%hex (c:sha256 (c:ascii->bytes "p"))) (n:node-payments a2))))
              (check "an in-flight payment comes back pending, not unknown" (and p (eq (n::pay-status p) :pending)))
              (check "with its shared secrets, so a failure can still be read"
                     (and p (equalp (c:octets (first (n::pay-shared-secrets p))) (c:octets (c:sha256 (c:ascii->bytes "ss")))))))))))))

;;; ----------------------------------------------------------------------------
;;; The watcher.  A channel resolved on chain must be answered even if we were
;;; down when it happened (P1), even if the first answer fails (P2), and even if
;;; we cannot tell what was published (P4); a close the chain drops must put the
;;; channel back on watch.
;;; ----------------------------------------------------------------------------

(defclass flaky-chain (chn::mock-chain)
  ((refusals :initarg :refusals :initform 0 :accessor flaky-refusals)))
(defmethod chn:chain-broadcast ((chain flaky-chain) tx)
  (if (plusp (flaky-refusals chain))
      (progn (decf (flaky-refusals chain)) (error "broadcast refused (test)"))
      (call-next-method)))

(defun watcher-node (dir lc chain funding-height)
  "A node holding one channel whose live state is LC, watching CHAIN."
  (let ((nd (rail-node dir 5151515151)))
    (let ((sc (n::make-stored-channel :channel-id (c:sha256 (c:ascii->bytes "watch/cid")) :peer-id (c:zeros 33)
                                      :funding-txid (lv::live-funding-txid lc) :funding-index (lv::live-funding-index lc)
                                      :capacity-sat 1000000 :live lc
                                      :scid (gs:make-scid funding-height 0 (lv::live-funding-index lc)))))
      (setf (gethash (n::%hex (n::sc-channel-id sc)) (n::node-channels nd)) sc))
    (setf (n:node-chain nd) chain)
    nd))

(defun the-channel (nd) (loop for sc being the hash-values of (n::node-channels nd) return sc))

(defun spends-of (chain txid)
  (remove-if-not (lambda (tx) (some (lambda (in) (equalp (c:octets (btx:txin-prev-hash in)) (c:octets txid))) (btx:tx-inputs tx)))
                 (chn::mock-mempool chain)))

(defun run-watcher-tests ()
  (w:select-network :signet)
  ;; ---- P2: a penalty refused once is retried, fee-bumped, RBF-replaceable ----
  (multiple-value-bind (a b) (make-live-pair)
    (oc-cycle a b)
    (let* ((cheat (lv::b-tx (lv::%build a (lv:local-spec a) :ours t :point (lv::local-point a 1) :index 1)))
           (chain (make-instance 'flaky-chain :refusals 0))
           (dir (rail-dir "w2")) (nd nil))
      (dotimes (i 101) (vector-push-extend '() (chn::mock-blocks chain)))
      (setf nd (watcher-node dir b chain 100))
      (n:watch-once nd)
      (chn:chain-broadcast chain cheat) (chn:mock-mine chain 1)
      (setf (flaky-refusals chain) 2)   ; answer-spend tries, and the same pass retries
      (n:watch-once nd)
      (with-gate ("watcher: a penalty refused once is retried, not abandoned (P2)")
        (check "the spend is classified :revoked" (eq :revoked (n::sc-close-kind (the-channel nd))))
        (check "the refused penalty left nothing in the mempool" (null (spends-of chain (btx:tx-txid cheat))))
        (check "the penalty is still owed" (find :penalty (n::node-obligations nd) :key (lambda (o) (getf o :kind))))
        (chn:mock-mine chain 1)
        (n:watch-once nd)
        (let ((pen (first (spends-of chain (btx:tx-txid cheat)))))
          (check "the next block's retry broadcast the penalty" (and pen t))
          (check "its inputs signal BIP125, so it can be replaced at a higher fee"
                 (and pen (every (lambda (in) (< (btx:txin-sequence in) #xfffffffe)) (btx:tx-inputs pen))))
          (let ((ob (find :penalty (n::node-obligations nd) :key (lambda (o) (getf o :kind)))))
            (check "an unconfirmed penalty stays owed" (and ob t))
            (let ((rate1 (getf ob :feerate)))
              ;; Another block without it confirming (miners ignore our mempool here):
              (setf (chn::mock-mempool chain) '())
              (vector-push-extend '() (chn::mock-blocks chain))
              (n:watch-once nd)
              (check "it is rebuilt at a higher feerate and rebroadcast"
                     (and (> (getf ob :feerate) rate1) (spends-of chain (btx:tx-txid cheat)))))))
        (chn:mock-mine chain 1)
        (n:watch-once nd)
        (check "once in a block, the obligation is resolved"
               (null (find :penalty (n::node-obligations nd) :key (lambda (o) (getf o :kind))))))))

  ;; ---- P1: a close while we were down is found after the restart ------------
  (multiple-value-bind (a b) (make-live-pair)
    (oc-cycle a b)
    (let* ((cheat (lv::b-tx (lv::%build a (lv:local-spec a) :ours t :point (lv::local-point a 1) :index 1)))
           (chain (chn:make-mock-chain :height 100))
           (dir (rail-dir "w1"))
           (nd (watcher-node dir b chain 100)))
      (n:watch-once nd)
      (n::save-state nd)
      ;; Down.  Meanwhile the revoked commitment confirms, and the chain moves on.
      (chn:chain-broadcast chain cheat) (chn:mock-mine chain 1) (chn:mock-mine chain 5)
      (let ((nd2 (watcher-node dir b chain 100)))
        (n::load-state nd2)
        (n:watch-once nd2)
        (with-gate ("watcher: a close during downtime is found after restart (P1)")
          (check "the restarted watcher scanned the missed blocks and classified the spend"
                 (eq :revoked (n::sc-close-kind (the-channel nd2))))
          (check "and answered it with a penalty" (and (spends-of chain (btx:tx-txid cheat)) t))))
      ;; A node with no saved scan height starts from the channel's funding block.
      (let ((nd3 (watcher-node (rail-dir "w1b") b (chn:make-mock-chain :height 100) 100)))
        (with-gate ("watcher: the first scan starts at the funding block, not the tip")
          (check-equal "watch-start" (n::watch-start nd3 150) 100)))))

  ;; ---- P4: an unrecognised commitment still has our to_remote swept --------
  (multiple-value-bind (a b) (make-live-pair)
    (oc-cycle a b)
    (let* ((theirs (lv:local-commitment-tx a))
           (chain (chn:make-mock-chain :height 100))
           (nd (watcher-node (rail-dir "w4") b chain 100)))
      (n:watch-once nd)
      ;; Make B unable to place this commitment number (as after lost state).
      (incf (lv:live-remote-commit-index b) 7)
      (chn:chain-broadcast chain theirs) (chn:mock-mine chain 1)
      (n:watch-once nd)
      (with-gate ("watcher: an unrecognised spend still sweeps what is ours (P4)")
        (check "the spend is :unknown" (eq :unknown (n::sc-close-kind (the-channel nd))))
        (let ((sweep (first (spends-of chain (btx:tx-txid theirs)))))
          (check "our to_remote was swept anyway" (and sweep t))
          (when sweep
            (multiple-value-bind (idx value) (oc:to-remote-output b theirs)
              (check "and the sweep spends it under cl-consensus"
                     (oc-spends-p sweep (btx:txout-script (nth idx (btx:tx-outputs theirs))) value))))))))

  ;; ---- a close the chain reorgs away puts the channel back on watch --------
  (multiple-value-bind (a b) (make-live-pair)
    (oc-cycle a b)
    (let* ((theirs (lv:local-commitment-tx a))
           (chain (chn:make-mock-chain :height 100))
           (nd (watcher-node (rail-dir "w5") b chain 100)))
      (n:watch-once nd)
      (chn:chain-broadcast chain theirs) (chn:mock-mine chain 1)
      (n:watch-once nd)
      (with-gate ("watcher: a close that is reorged out is watched again")
        (check "the close is recorded" (eq :their-commitment (n::sc-close-kind (the-channel nd))))
        ;; Reorg: the block with the close is replaced by two empty ones.
        (vector-pop (chn::mock-blocks chain))
        (setf (chn::mock-mempool chain) '())
        (vector-push-extend '() (chn::mock-blocks chain)) (vector-push-extend '() (chn::mock-blocks chain))
        (n:watch-once nd)
        (check "the channel is back on watch" (null (n::sc-close-kind (the-channel nd))))
        (check "with nothing owed for the vanished close" (null (n::node-obligations nd)))
        (chn:chain-broadcast chain theirs) (chn:mock-mine chain 1)
        (n:watch-once nd)
        (check "and the close is answered when it confirms again"
               (eq :their-commitment (n::sc-close-kind (the-channel nd))))))))
