;;;; inspect/gossip-encode-test.lisp
;;;;
;;;; Phase 4f — emitting gossip.
;;;;
;;;; Everything in gossip-test.lisp checks what we ACCEPT.  This checks what we
;;;; SEND, which fails differently and much more quietly: a malformed
;;;; announcement draws no error from anyone.  Peers drop it and move on, so the
;;;; symptom is a channel that simply never appears in the routing graph, with
;;;; nothing in any log to say why.  Both real bugs found here presented that
;;;; way.
;;;;
;;;; The property that matters throughout is that our encoders and our parsers
;;;; are inverses, and that a signature we produce over a body verifies against
;;;; the message we actually put on the wire — not against the body we meant to
;;;; send.  Those are different claims whenever the two are serialised twice.

(in-package #:cl-payments.test)

(defun ge-key (n)
  "A deterministic private key, so a failure here is reproducible."
  (secp:bytes-to-int (c:sha256 (c:ascii->bytes (format nil "gossip-encode-test/~d" n)))))

(defun ge-pub (k) (c:compressed-pubkey (c:pubkey-of k)))

(defun run-gossip-encode-tests ()
  (w:select-network :signet)
  (with-gate ("gossip: node ordering")
    (let ((a (ge-pub (ge-key 1))) (b (ge-pub (ge-key 2))))
      (multiple-value-bind (n1 n2 a-is-1) (gs:node-order a b)
        ;; Whatever the order, node_1 must be the byte-lesser of the two, and
        ;; asking with the arguments swapped must give the SAME answer.  The
        ;; direction bit in every channel_update is defined against this, so an
        ;; ordering that depended on argument order would make each end advertise
        ;; the other's policy.
        (check "node_1 is the lesser" (string< (c:bytes->hex n1) (c:bytes->hex n2)))
        (multiple-value-bind (m1 m2 b-is-1) (gs:node-order b a)
          (check "ordering is independent of argument order"
                   (and (equalp n1 m1) (equalp n2 m2)))
          (check "exactly one side is node_1" (not (eq a-is-1 b-is-1)))))))

  (with-gate ("gossip: channel_announcement round-trips and verifies")
    (let* ((node-1-key (ge-key 1)) (node-2-key (ge-key 2))
           (btc-1-key (ge-key 3)) (btc-2-key (ge-key 4))
           (scid (gs:make-scid 273 1 1)))
      (multiple-value-bind (n1 n2) (gs:node-order (ge-pub node-1-key) (ge-pub node-2-key))
        ;; Keep the bitcoin keys paired with the node keys through the reorder,
        ;; the way a real channel does.
        (let* ((one-is-first (equalp n1 (ge-pub node-1-key)))
               (b1 (if one-is-first (ge-pub btc-1-key) (ge-pub btc-2-key)))
               (b2 (if one-is-first (ge-pub btc-2-key) (ge-pub btc-1-key)))
               (bk1 (if one-is-first btc-1-key btc-2-key))
               (bk2 (if one-is-first btc-2-key btc-1-key))
               (nk1 (if one-is-first node-1-key node-2-key))
               (nk2 (if one-is-first node-2-key node-1-key))
               (body (gs:channel-announcement-body
                      :features 0 :chain-hash (w:chain-hash) :scid scid
                      :node-1 n1 :node-2 n2 :bitcoin-1 b1 :bitcoin-2 b2))
               (msg (gs:encode-channel-announcement
                     body
                     :node-sig-1 (gs:sign-gossip nk1 body)
                     :node-sig-2 (gs:sign-gossip nk2 body)
                     :bitcoin-sig-1 (gs:sign-gossip bk1 body)
                     :bitcoin-sig-2 (gs:sign-gossip bk2 body)))
               (parsed (gs:parse-channel-announcement msg)))
          (check "scid survives the round trip"
                   (string= (gs:scid-string (gs:chan-ann-scid parsed)) "273x1x1"))
          (check "node keys survive the round trip"
                   (and (equalp (gs:chan-ann-node-1 parsed) n1)
                        (equalp (gs:chan-ann-node-2 parsed) n2)))
          ;; The real assertion: the signatures verify against the bytes we would
          ;; have SENT, which is what a peer checks.  Signing one serialisation
          ;; and shipping another is the failure this catches.
          (check "all four signatures verify on the encoded message"
                   (gs:verify-channel-announcement parsed))

          ;; The signed portion of what we emit must be exactly the body we
          ;; signed — 4 signatures, then the body, with nothing in between.
          (check "the signed portion is byte-identical to the body"
                   (equalp (c:octets (gs:signed-portion msg 4)) (c:octets body)))

          ;; A single flipped bit anywhere in the body must break verification;
          ;; otherwise the signature is not actually covering the content.
          (let* ((tampered (copy-seq (c:octets msg)))
                 (at (+ (* 4 64) 3)))
            (setf (aref tampered at) (logxor (aref tampered at) 1))
            (check "a one-bit change to the body fails verification"
                     (not (gs:verify-channel-announcement
                           (gs:parse-channel-announcement tampered)))))))))

  (with-gate ("gossip: channel_update round-trips and verifies")
    (let* ((k (ge-key 5))
           (body (gs:channel-update-body
                  :chain-hash (w:chain-hash) :scid (gs:make-scid 273 1 1)
                  :timestamp 1756000000 :channel-flags 0
                  :cltv-expiry-delta 40 :htlc-minimum-msat 1000
                  :fee-base-msat 1000 :fee-proportional-millionths 1
                  :htlc-maximum-msat 200000000))
           (msg (gs:encode-channel-update k body))
           (u (gs:parse-channel-update msg)))
      (check "signature verifies against the announcing node"
               (gs:verify-channel-update u (ge-pub k)))
      (check "it does NOT verify against a different node"
               (not (gs:verify-channel-update u (ge-pub (ge-key 6)))))
      (check "direction 0 when channel_flags bit 0 is clear"
               (= 0 (gs:chan-upd-direction u)))
      (check "fees survive the round trip"
               (and (= 1000 (gs:chan-upd-fee-base-msat u))
                    (= 1 (gs:chan-upd-fee-proportional-millionths u))
                    (= 40 (gs:chan-upd-cltv-expiry-delta u))))
      (check "htlc_maximum_msat survives the round trip"
               (= 200000000 (gs:chan-upd-htlc-maximum-msat u))))

    ;; The direction bit is the one field where a wrong answer is silently
    ;; plausible: the message parses, verifies, and advertises the WRONG end's
    ;; policy.  Check the other setting explicitly rather than assuming symmetry.
    (let* ((k (ge-key 5))
           (body (gs:channel-update-body
                  :chain-hash (w:chain-hash) :scid (gs:make-scid 273 1 1)
                  :timestamp 1756000000 :channel-flags 1
                  :htlc-maximum-msat 200000000))
           (u (gs:parse-channel-update (gs:encode-channel-update k body))))
      (check "direction 1 when channel_flags bit 0 is set"
               (= 1 (gs:chan-upd-direction u))))

    ;; message_flags bit 0 promises an htlc_maximum_msat field.  Emitting the
    ;; flag without the field produces a message that parses as garbage on the
    ;; peer, so refuse to build it at all.
    (check-signals "message_flags bit 0 without htlc_maximum_msat is refused"
                     gs:gossip-error
      (gs:channel-update-body
       :chain-hash (w:chain-hash) :scid (gs:make-scid 1 1 1)
       :timestamp 1 :message-flags 1 :htlc-maximum-msat nil)))

  (with-gate ("gossip: node_announcement round-trips and verifies")
    (let* ((k (ge-key 7))
           (body (gs:node-announcement-body
                  :features 0 :timestamp 1756000000 :node-id (ge-pub k)
                  :alias "cl-payments"))
           (a (gs:parse-node-announcement (gs:encode-node-announcement k body))))
      (check "signature verifies" (gs:verify-node-announcement a))
      (check "node id survives" (equalp (gs:node-ann-node-id a) (ge-pub k)))
      (check "alias survives" (string= "cl-payments" (gs:node-ann-alias a))))

    ;; The alias is a FIXED 32-byte field.  An over-long one must be truncated,
    ;; not allowed to shift every following field — that would produce a message
    ;; which parses into nonsense rather than one that is rejected.
    (let* ((k (ge-key 7))
           (long (make-string 60 :initial-element #\x))
           (body (gs:node-announcement-body
                  :features 0 :timestamp 1756000000 :node-id (ge-pub k) :alias long))
           (a (gs:parse-node-announcement (gs:encode-node-announcement k body))))
      (check "an over-long alias is truncated, and the message still parses"
               (= 32 (length (gs:node-ann-alias a))))
      (check "an over-long alias does not corrupt the fields after it"
               (and (equalp (gs:node-ann-node-id a) (ge-pub k))
                    (= 1756000000 (gs:node-ann-timestamp a))))))

  (with-gate ("node: channel keys are deterministic and distinct")
    (let* ((priv (ge-key 8))
           (a (n:derive-channel-keys priv 0))
           (b (n:derive-channel-keys priv 0))
           (c2 (n:derive-channel-keys priv 1)))
      ;; The whole point of deriving rather than generating: the same node key
      ;; and index must give the same channel keys after a restart, or the
      ;; funding output's 2-of-2 becomes unspendable.
      (check "same index gives identical keys"
               (and (= (n:ck-funding a) (n:ck-funding b))
                    (= (n:ck-revocation a) (n:ck-revocation b))
                    (equalp (n:ck-seed a) (n:ck-seed b))))
      ;; And different indices must NOT collide: reusing a funding key across two
      ;; channels means a revocation secret leaked on one applies to the other.
      (check "different indices give different keys"
               (and (/= (n:ck-funding a) (n:ck-funding c2))
                    (/= (n:ck-revocation a) (n:ck-revocation c2))
                    (not (equalp (n:ck-seed a) (n:ck-seed c2)))))
      ;; Distinct ROLES within one channel must differ too — a funding key equal
      ;; to the revocation key would let a counterparty spend the funding output
      ;; with a revocation path signature.
      (check "roles within a channel are distinct"
               (= 5 (length (remove-duplicates
                             (list (n:ck-funding a) (n:ck-revocation a)
                                   (n:ck-payment a) (n:ck-delayed a) (n:ck-htlc a))))))
      (check "a different node key gives different channel keys"
               (/= (n:ck-funding a) (n:ck-funding (n:derive-channel-keys (ge-key 9) 0))))))

  ;; Two of the bugs this file exists to catch were the same mistake: handing a
  ;; PAYLOAD to something that wanted a full MESSAGE.  Core Lightning read the
  ;; first two bytes of a signature as a message type, found an unknown even
  ;; number, and closed the connection — which looked like an unrelated peer
  ;; problem.  The encoders return payloads by design, so the invariant worth
  ;; pinning is that they do NOT begin with their own type.
  (with-gate ("gossip: encoders return payloads, not framed messages")
    (let* ((k (ge-key 5))
           (upd (gs:encode-channel-update
                 k (gs:channel-update-body
                    :chain-hash (w:chain-hash) :scid (gs:make-scid 1 1 1)
                    :timestamp 1 :htlc-maximum-msat 1000)))
           (framed (w:encode-message gs:+msg-channel-update+ upd)))
      (check "the framed message is exactly two bytes longer"
               (= (+ 2 (length upd)) (length framed)))
      (check "the frame carries the type in the first two bytes"
               (= gs:+msg-channel-update+
                  (+ (* 256 (aref framed 0)) (aref framed 1))))
      ;; And the payload inside the frame must still parse — proving the frame is
      ;; a pure prefix rather than a re-serialisation.
      (check "the framed payload still parses"
               (gs:verify-channel-update
                (gs:parse-channel-update (subseq framed 2)) (ge-pub k))))))
