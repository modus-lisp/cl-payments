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
