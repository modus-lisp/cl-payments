;;;; inspect/channel-test.lisp
;;;;
;;;; Gate 9 — BOLT #2 channel-establishment messages.
;;;;
;;;; BOLT #2 publishes no test vectors, so these are round-trip and structure
;;;; checks plus the two rules that are easy to get wrong and expensive when you
;;;; do: the channel id derivation, and the byte order of `funding_txid`.
;;;;
;;;; The live proof is inspect/open-channel.lisp, which opens a real channel
;;;; against Core Lightning — a counterparty that verifies our commitment
;;;; signature is worth more than any amount of round-tripping against ourselves.

(in-package #:cl-payments.test)

(defun %point (n) (c:compressed-pubkey (c:pubkey-of n)))

(defun sample-open-channel ()
  (ch:make-open-channel
   :chain-hash (w:chain-hash)
   :temporary-channel-id (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                                  :initial-element 7))
   :funding-satoshis 1000000 :push-msat 0
   :dust-limit-satoshis 546 :max-htlc-value-in-flight-msat 990000000
   :channel-reserve-satoshis 10000 :htlc-minimum-msat 1
   :feerate-per-kw 5000 :to-self-delay 144 :max-accepted-htlcs 30
   :funding-pubkey (%point 1001) :revocation-basepoint (%point 1002)
   :payment-basepoint (%point 1003) :delayed-payment-basepoint (%point 1004)
   :htlc-basepoint (%point 1005) :first-per-commitment-point (%point 1006)
   :channel-flags 1))

(defun test-open-channel-message ()
  (with-gate ("BOLT #2 — open_channel")
    (let* ((o (sample-open-channel))
           (msg (ch:encode-open-channel o)))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (check-equal "type is 32" type ch:+msg-open-channel+)
        (let ((back (ch:parse-open-channel payload)))
          (check-bytes "chain_hash round-trips" (ch:oc-chain-hash back) (w:chain-hash))
          (check-equal "funding_satoshis" (ch:oc-funding-satoshis back) 1000000)
          (check-equal "feerate_per_kw" (ch:oc-feerate-per-kw back) 5000)
          (check-equal "to_self_delay" (ch:oc-to-self-delay back) 144)
          (check-equal "max_accepted_htlcs" (ch:oc-max-accepted-htlcs back) 30)
          (check-equal "channel_flags" (ch:oc-channel-flags back) 1)
          ;; Six DISTINCT points, in a fixed order.  Every one is 33 bytes, so a
          ;; transposition is invisible to the parser and shows up only as a
          ;; commitment the peer refuses to sign.
          (check-bytes "funding_pubkey" (ch:oc-funding-pubkey back) (%point 1001))
          (check-bytes "revocation_basepoint" (ch:oc-revocation-basepoint back) (%point 1002))
          (check-bytes "payment_basepoint" (ch:oc-payment-basepoint back) (%point 1003))
          (check-bytes "delayed_payment_basepoint" (ch:oc-delayed-payment-basepoint back)
                       (%point 1004))
          (check-bytes "htlc_basepoint" (ch:oc-htlc-basepoint back) (%point 1005))
          (check-bytes "first_per_commitment_point" (ch:oc-first-per-commitment-point back)
                       (%point 1006))))
      ;; Trailing TLVs we do not understand must be tolerated — that is how the
      ;; message grows without breaking older peers.
      (let* ((extended (c:bytes (nth-value 1 (w:decode-message msg))
                                (hx "fd01f4020102")))   ; type 500, 2 bytes
             (back (ch:parse-open-channel extended)))
        (check "an unknown trailing TLV does not break parsing"
               (ch:oc-funding-pubkey back)))
      (check-signals "a truncated open_channel is rejected" ch:channel-error
        (ch:parse-open-channel (hx "0011223344"))))))

(defun test-accept-channel-message ()
  (with-gate ("BOLT #2 — accept_channel")
    (let* ((a (ch:make-accept-channel
               :temporary-channel-id (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                                              :initial-element 7))
               :dust-limit-satoshis 546 :max-htlc-value-in-flight-msat 990000000
               :channel-reserve-satoshis 10000 :htlc-minimum-msat 1
               :minimum-depth 3 :to-self-delay 144 :max-accepted-htlcs 30
               :funding-pubkey (%point 2001) :revocation-basepoint (%point 2002)
               :payment-basepoint (%point 2003) :delayed-payment-basepoint (%point 2004)
               :htlc-basepoint (%point 2005) :first-per-commitment-point (%point 2006)))
           (msg (ch:encode-accept-channel a)))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (check-equal "type is 33" type ch:+msg-accept-channel+)
        (let ((back (ch:parse-accept-channel payload)))
          ;; minimum_depth is the accepter's only say over timing: how many
          ;; confirmations before it will believe the funding output exists.
          (check-equal "minimum_depth" (ch:ac-minimum-depth back) 3)
          (check-equal "to_self_delay" (ch:ac-to-self-delay back) 144)
          (check-bytes "funding_pubkey" (ch:ac-funding-pubkey back) (%point 2001))
          (check-bytes "first_per_commitment_point" (ch:ac-first-per-commitment-point back)
                       (%point 2006))
          ;; accept_channel has no chain_hash, funding amount, push or feerate —
          ;; those are the opener's to choose, and echoing them back would invite
          ;; disagreement about which value is authoritative.
          (check "accept_channel carries no funding amount"
                 (not (find-symbol "AC-FUNDING-SATOSHIS" "CL-PAYMENTS.CHANNEL"))))))))

(defun test-funding-messages ()
  (with-gate ("BOLT #2 — funding_created / funding_signed / channel_ready")
    (let* ((txid (c:octets (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
           (sig (c:octets (make-array 64 :element-type '(unsigned-byte 8) :initial-element 3)))
           (fc-msg (ch:encode-funding-created
                    (ch:make-funding-created
                     :temporary-channel-id (c:octets (make-array 32 :element-type '(unsigned-byte 8)
                                                                    :initial-element 7))
                     :funding-txid txid :funding-output-index 1 :signature sig))))
      (multiple-value-bind (type payload) (w:decode-message fc-msg)
        (check-equal "funding_created is type 34" type ch:+msg-funding-created+)
        (let ((back (ch:parse-funding-created payload)))
          (check-bytes "funding_txid round-trips" (ch:fc-funding-txid back) txid)
          (check-equal "funding_output_index" (ch:fc-funding-output-index back) 1)
          (check-bytes "signature is 64 bytes" (ch:fc-signature back) sig))))
    (let* ((cid (c:octets (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5)))
           (sig (c:octets (make-array 64 :element-type '(unsigned-byte 8) :initial-element 4)))
           (msg (ch:encode-funding-signed (ch:make-funding-signed :channel-id cid :signature sig))))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (check-equal "funding_signed is type 35" type ch:+msg-funding-signed+)
        (let ((back (ch:parse-funding-signed payload)))
          (check-bytes "channel_id" (ch:fs-channel-id back) cid)
          (check-bytes "signature" (ch:fs-signature back) sig))))
    (let* ((cid (c:octets (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5)))
           (msg (ch:encode-channel-ready
                 (ch:make-channel-ready :channel-id cid
                                        :second-per-commitment-point (%point 3001)))))
      (multiple-value-bind (type payload) (w:decode-message msg)
        (check-equal "channel_ready is type 36" type ch:+msg-channel-ready+)
        (let ((back (ch:parse-channel-ready payload)))
          ;; The SECOND point: the first went out in open/accept, and by the time
          ;; the channel is ready the next commitment already needs a key.
          (check-bytes "second_per_commitment_point"
                       (ch:cr-second-per-commitment-point back) (%point 3001)))))))

(defun test-channel-id ()
  (with-gate ("BOLT #2 — channel id derivation")
    ;; The permanent id is the funding txid with the output index XORed into the
    ;; last two bytes.  Naming the channel by WHERE ITS MONEY IS makes the name
    ;; verifiable against the chain and impossible to claim twice.
    (let* ((txid (c:octets (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
           (id0 (ch:channel-id txid 0))
           (id1 (ch:channel-id txid 1))
           (id256 (ch:channel-id txid 256)))
      (check-bytes "output 0 leaves the txid unchanged" id0 txid)
      (check-equal "output 1 flips the last byte" (aref id1 31) 1)
      (check-equal "…and leaves the second-to-last alone" (aref id1 30) 0)
      (check-equal "output 256 flips the second-to-last byte" (aref id256 30) 1)
      (check-equal "…and leaves the last alone" (aref id256 31) 0)
      (check "different outputs give different channel ids"
             (not (equalp id1 id256)))
      ;; Only the last two bytes may ever change.
      (check "the first 30 bytes are untouched"
             (equalp (subseq id256 0 30) (subseq txid 0 30))))
    ;; XOR is its own inverse, so the index is recoverable.
    (let* ((txid (c:hex->bytes
                  "ab84ff284f162cfbfef241f853b47d4368d171f9e2a1445160cd591c4c7d882b"))
           (id (ch:channel-id txid 3)))
      (check-equal "the output index can be recovered"
                   (logxor (aref id 31) (aref txid 31)) 3))))

(defun run-channel-tests ()
  (test-open-channel-message)
  (test-accept-channel-message)
  (test-funding-messages)
  (test-channel-id))
