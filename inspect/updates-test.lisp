;;;; inspect/updates-test.lisp
;;;;
;;;; Gate 10 — BOLT #2's HTLC lifecycle.
;;;;
;;;; The message encodings here are mostly mechanical.  What is not mechanical,
;;;; and what these tests are actually about, is the ORDERING DISCIPLINE:
;;;;
;;;;   * an HTLC's amount leaves the sender's balance when proposed, not when
;;;;     committed — it is in flight, belonging to neither side;
;;;;   * a fulfill is only honoured if the preimage really hashes to the payment
;;;;     hash, in BOTH directions;
;;;;   * `commitment_signed` may not be sent while a `revoke_and_ack` is
;;;;     outstanding;
;;;;   * and a commitment is never revoked before its replacement is signed.
;;;;
;;;; That last one is the whole safety argument of the protocol.  Revoking first
;;;; leaves you holding nothing enforceable: the old state is punishable if you
;;;; publish it, and the new one is unsigned, so your balance is entirely at the
;;;; counterparty's discretion.

(in-package #:cl-payments.test)

(defun %onion () (c:octets (make-array u:+onion-packet-size+
                                       :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
(defun %cid () (c:octets (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
(defun %sig (b) (c:octets (make-array 64 :element-type '(unsigned-byte 8) :initial-element b)))

(defun test-update-messages ()
  (with-gate ("BOLT #2 — HTLC update messages")
    (let* ((preimage (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element 42)))
           (hash (c:sha256 preimage))
           (msg (u:encode-update-add-htlc
                 (u:make-update-add-htlc :channel-id (%cid) :id 7 :amount-msat 100000
                                         :payment-hash hash :cltv-expiry 600
                                         :onion-routing-packet (%onion)))))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (check-equal "update_add_htlc is type 128" type u:+msg-update-add-htlc+)
        (let ((back (u:parse-update-add-htlc payload)))
          (check-equal "id" (u:uah-id back) 7)
          (check-equal "amount_msat" (u:uah-amount-msat back) 100000)
          (check-equal "cltv_expiry" (u:uah-cltv-expiry back) 600)
          (check-bytes "payment_hash" (u:uah-payment-hash back) hash)
          ;; The onion is a FIXED 1366 bytes whatever the route length — a
          ;; shorter packet for a shorter route would leak how many hops remain.
          (check-equal "onion is 1366 bytes"
                       (length (u:uah-onion-routing-packet back)) 1366))))
    (check-signals "a wrongly-sized onion is refused" u:update-error
      (u:encode-update-add-htlc
       (u:make-update-add-htlc :channel-id (%cid) :id 0 :amount-msat 1
                               :payment-hash (c:sha256 #()) :cltv-expiry 1
                               :onion-routing-packet (c:octets #(1 2 3)))))
    (let* ((preimage (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element 1)))
           (msg (u:encode-update-fulfill-htlc
                 (u:make-update-fulfill-htlc :channel-id (%cid) :id 3
                                             :payment-preimage preimage))))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (check-equal "update_fulfill_htlc is type 130" type u:+msg-update-fulfill-htlc+)
        (check-bytes "preimage round-trips"
                     (u:ufh-payment-preimage (u:parse-update-fulfill-htlc payload)) preimage)))
    (let ((msg (u:encode-update-fail-htlc
                (u:make-update-fail-htlc :channel-id (%cid) :id 4
                                         :reason (c:octets #(1 2 3 4))))))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (check-equal "update_fail_htlc is type 131" type u:+msg-update-fail-htlc+)
        (check-bytes "reason round-trips"
                     (u:ufl-reason (u:parse-update-fail-htlc payload)) (c:octets #(1 2 3 4)))))
    (let ((msg (u:encode-update-fee (u:make-update-fee :channel-id (%cid)
                                                      :feerate-per-kw 3000))))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (check-equal "update_fee is type 134" type u:+msg-update-fee+)
        (check-equal "feerate" (u:uf-feerate-per-kw (u:parse-update-fee payload)) 3000)))))

(defun test-commitment-signed-message ()
  (with-gate ("BOLT #2 — commitment_signed and revoke_and_ack")
    ;; One signature per untrimmed HTLC, in OUTPUT order.  The receiver matches
    ;; them positionally against its own sort of the same HTLCs, so an ordering
    ;; disagreement misattaches every signature at once.
    (let ((msg (u:encode-commitment-signed
                (u:make-commitment-signed :channel-id (%cid) :signature (%sig 1)
                                          :htlc-signatures (list (%sig 2) (%sig 3) (%sig 4))))))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (check-equal "commitment_signed is type 132" type u:+msg-commitment-signed+)
        (let ((back (u:parse-commitment-signed payload)))
          (check-bytes "commitment signature" (u:cs-signature back) (%sig 1))
          (check-equal "three htlc signatures" (length (u:cs-htlc-signatures back)) 3)
          (check-bytes "in order" (second (u:cs-htlc-signatures back)) (%sig 3)))))
    (let ((msg (u:encode-commitment-signed
                (u:make-commitment-signed :channel-id (%cid) :signature (%sig 1)
                                          :htlc-signatures '()))))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (declare (ignore type))
        (check-equal "a commitment with no HTLCs carries no htlc signatures"
                     (length (u:cs-htlc-signatures (u:parse-commitment-signed payload))) 0)))
    (let* ((secret (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                            :initial-element 7)))
           (point (c:compressed-pubkey (c:pubkey-of 12345)))
           (msg (u:encode-revoke-and-ack
                 (u:make-revoke-and-ack :channel-id (%cid) :per-commitment-secret secret
                                        :next-per-commitment-point point))))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (check-equal "revoke_and_ack is type 133" type u:+msg-revoke-and-ack+)
        (let ((back (u:parse-revoke-and-ack payload)))
          ;; Sending this secret is irreversible: it makes the old commitment
          ;; punishable, so publishing that state becomes theft you can be
          ;; penalised for.
          (check-bytes "per_commitment_secret" (u:raa-per-commitment-secret back) secret)
          (check-bytes "next_per_commitment_point"
                       (u:raa-next-per-commitment-point back) point))))))

(defun %fresh-channel ()
  (u:make-channel-state :channel-id (%cid)
                        :local-balance-msat 500000
                        :remote-balance-msat 500000
                        :seed (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                                       :initial-element 3))))

(defun test-htlc-accounting ()
  (with-gate ("BOLT #2 — HTLC balance accounting")
    (let* ((st (%fresh-channel))
           (preimage (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 5)))
           (hash (c:sha256 preimage)))
      ;; The amount leaves our balance the moment we PROPOSE, not when the
      ;; commitment is signed.  It is in flight — neither ours nor theirs — and
      ;; comes back only if the HTLC fails.
      (u:offer-htlc st 100000 hash 600)
      (check-equal "offering deducts from our balance immediately"
                   (u:cst-local-balance-msat st) 400000)
      (check-equal "and does NOT credit theirs yet" (u:cst-remote-balance-msat st) 500000)
      (check-equal "the HTLC is recorded" (length (u:cst-offered st)) 1)
      ;; Only on fulfilment does the money actually change hands.
      (u:receive-fulfill st (u:make-update-fulfill-htlc :channel-id (%cid) :id 0
                                                        :payment-preimage preimage))
      (check-equal "fulfilling credits them" (u:cst-remote-balance-msat st) 600000)
      (check-equal "our balance stays reduced" (u:cst-local-balance-msat st) 400000)
      (check-equal "the two sides still sum to the channel capacity"
                   (+ (u:cst-local-balance-msat st) (u:cst-remote-balance-msat st))
                   1000000))
    ;; You cannot offer money you do not have.
    (let ((st (%fresh-channel)))
      (check-signals "offering more than the balance is refused" u:update-error
        (u:offer-htlc st 999999999 (c:sha256 #()) 600)))
    (let ((st (%fresh-channel)))
      (check-signals "a peer offering more than ITS balance is refused" u:update-error
        (u:receive-htlc st (u:make-update-add-htlc
                            :channel-id (%cid) :id 0 :amount-msat 999999999
                            :payment-hash (c:sha256 #()) :cltv-expiry 600
                            :onion-routing-packet (%onion)))))))

(defun test-preimage-verification ()
  (with-gate ("BOLT #2 — preimages are verified, not trusted")
    (let* ((st (%fresh-channel))
           (preimage (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 5)))
           (hash (c:sha256 preimage))
           (wrong (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element 6))))
      (check "a correct preimage matches" (u:preimage-matches-p preimage hash))
      (check "a wrong preimage does not" (not (u:preimage-matches-p wrong hash)))
      ;; Accepting an unproven claim on an HTLC we offered gives money away.
      (u:offer-htlc st 100000 hash 600)
      (check-signals "a fulfill with the wrong preimage is refused" u:update-error
        (u:receive-fulfill st (u:make-update-fulfill-htlc :channel-id (%cid) :id 0
                                                          :payment-preimage wrong)))
      (check-equal "and their balance is untouched" (u:cst-remote-balance-msat st) 500000))
    ;; The same check applies when WE claim: a node that fulfils without a valid
    ;; preimage cannot actually redeem the HTLC on chain, so it would be paying
    ;; out against nothing.
    (let* ((st (%fresh-channel))
           (preimage (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 8)))
           (hash (c:sha256 preimage)))
      (u:receive-htlc st (u:make-update-add-htlc :channel-id (%cid) :id 0 :amount-msat 50000
                                                 :payment-hash hash :cltv-expiry 600
                                                 :onion-routing-packet (%onion)))
      (check-signals "claiming with the wrong preimage is refused" u:update-error
        (u:fulfill-htlc st 0 (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                                      :initial-element 99))))
      (u:fulfill-htlc st 0 preimage)
      (check-equal "the right preimage credits us" (u:cst-local-balance-msat st) 550000)
      (check-signals "an unknown HTLC id is refused" u:update-error
        (u:fulfill-htlc st 42 preimage)))))

(defun test-commitment-ordering ()
  (with-gate ("BOLT #2 — the revocation interlock")
    (let ((st (%fresh-channel)))
      (u:sent-commitment st)
      (check "sending commitment_signed sets the interlock"
             (u:cst-awaiting-revocation-p st))
      ;; Two outstanding commitments would leave the peer unable to say which it
      ;; revoked.
      (check-signals "a second commitment_signed before revoke_and_ack is refused"
          u:update-error
        (u:sent-commitment st))
      (u:received-revocation
       st (u:make-revoke-and-ack
           :channel-id (%cid)
           :per-commitment-secret (k:generate-from-seed
                                   (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                                            :initial-element 1))
                                   k:+max-commitment-index+)
           :next-per-commitment-point (c:compressed-pubkey (c:pubkey-of 999))))
      (check "the revocation clears the interlock"
             (not (u:cst-awaiting-revocation-p st)))
      (check "and another commitment may now be sent"
             (u:sent-commitment st)))
    ;; A revocation nobody was waiting for is a protocol violation, not a no-op:
    ;; it would mean the peer revoked a state we never asked it to replace.
    (let ((st (%fresh-channel)))
      (check-signals "an unexpected revoke_and_ack is refused" u:update-error
        (u:received-revocation
         st (u:make-revoke-and-ack
             :channel-id (%cid)
             :per-commitment-secret (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                                             :initial-element 1))
             :next-per-commitment-point (c:compressed-pubkey (c:pubkey-of 999))))))
    ;; Revoked secrets are retained so an old commitment of theirs stays
    ;; punishable.
    (let ((st (%fresh-channel))
          (seed (c:octets (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4))))
      (u:sent-commitment st)
      (u:received-revocation
       st (u:make-revoke-and-ack
           :channel-id (%cid)
           :per-commitment-secret (k:generate-from-seed seed k:+max-commitment-index+)
           :next-per-commitment-point (c:compressed-pubkey (c:pubkey-of 999))))
      (check "the revoked secret is retained for punishment"
             (equalp (c:octets (k:shachain-lookup (u:cst-revocations st)
                                                  k:+max-commitment-index+))
                     (c:octets (k:generate-from-seed seed k:+max-commitment-index+))))
      ;; Proposed HTLCs become irrevocably committed once the peer revokes.
      (check-equal "commitment numbers advanced" (u:cst-remote-commitment-number st) 1))))

(defun test-htlc-commitment-transition ()
  (with-gate ("BOLT #2 — proposed becomes committed")
    (let* ((st (%fresh-channel))
           (hash (c:sha256 (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                                    :initial-element 5)))))
      (u:offer-htlc st 100000 hash 600)
      (check-equal "a new HTLC starts as proposed"
                   (u::hs-state (first (u:cst-offered st))) :proposed)
      (u:sent-commitment st)
      (check-equal "still proposed after commitment_signed alone"
                   (u::hs-state (first (u:cst-offered st))) :proposed)
      (u:received-revocation
       st (u:make-revoke-and-ack
           :channel-id (%cid)
           :per-commitment-secret (k:generate-from-seed
                                   (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                                            :initial-element 2))
                                   k:+max-commitment-index+)
           :next-per-commitment-point (c:compressed-pubkey (c:pubkey-of 999))))
      ;; Only once the peer has revoked its OLD state is the HTLC irrevocably
      ;; part of the channel — before that the peer could still publish a
      ;; commitment that does not contain it.
      (check-equal "committed once the peer revokes"
                   (u::hs-state (first (u:cst-offered st))) :committed))))

(defun run-updates-tests ()
  (test-update-messages)
  (test-commitment-signed-message)
  (test-htlc-accounting)
  (test-preimage-verification)
  (test-commitment-ordering)
  (test-htlc-commitment-transition))
