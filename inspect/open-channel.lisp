;;;; inspect/open-channel.lisp
;;;;
;;;; The Phase 4 milestone — open a real channel against a real node.
;;;;
;;;; Everything in BOLT #3 was verified against published vectors, which proves
;;;; we agree with the SPEC.  This proves we agree with an IMPLEMENTATION, and it
;;;; is a much harder thing to fake: Core Lightning verifies our signature over
;;;; the commitment transaction IT will hold.  If any of the key derivation, the
;;;; output construction, the fee, the obscured commitment number or the BIP143
;;;; digest is wrong, that signature does not verify and the channel is refused.
;;;;
;;;; The funding transaction is built but NOT broadcast until `funding_signed`
;;;; arrives.  That ordering is the opener's only protection: the funding output
;;;; is a 2-of-2, so broadcasting before holding a signature that returns the
;;;; money means an uncooperative counterparty can strand it forever.
;;;;
;;;;   CL_PAYMENTS_PEER=<node_id>@127.0.0.1:9835 sbcl --load inspect/open-channel.lisp --quit

(require :asdf)
(asdf:initialize-source-registry
 (let ((here (make-pathname :name nil :type nil :defaults *load-truename*)))
   `(:source-registry (:tree ,(merge-pathnames "../" here))
                      (:tree ,(merge-pathnames "../../" here))
                      :inherit-configuration)))
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-payments"))

(defpackage #:open-channel
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:p #:cl-payments.peer) (#:k #:cl-payments.keys)
                    (#:m #:cl-payments.commitment) (#:ch #:cl-payments.channel)
                    (#:btx #:cl-consensus.tx) (#:bw #:cl-consensus.wire)
                    (#:secp #:secp256k1-fast) (#:bt #:bordeaux-threads)
                    (#:benc #:cl-consensus.encoding))
  (:export #:run))

(in-package #:open-channel)

(defparameter *bitcoin-cli*
  "/mnt/lisp/signet/bin/bitcoin-cli -signet -datadir=/mnt/lisp/signet/bitcoin -rpcwallet=miner")

(defun bcli (&rest args)
  (string-trim '(#\Newline #\Space)
               (with-output-to-string (s)
                 (uiop:run-program (format nil "~a ~{~a ~}" *bitcoin-cli* args)
                                   :output s :error-output nil))))

(defun json-string (json field)
  "Pull a string FIELD out of bitcoin-cli's JSON.  Deliberately tiny — pulling in
   a JSON parser for two fields would add a dependency to the whole system for
   the sake of one test script."
  (let* ((key (format nil "\"~a\": \"" field))
         (at (search key json)))
    (unless at (error "no ~a in ~a" field json))
    (let ((start (+ at (length key))))
      (subseq json start (position #\" json :start start)))))

(defvar *step* 0)
(defun step! (fmt &rest args)
  (format t "~&~%~d. ~?~%" (incf *step*) fmt args)
  (force-output))
(defun note (fmt &rest args) (format t "   ~?~%" fmt args) (force-output))

;;; ----------------------------------------------------------------------------

(defstruct our-keys funding revocation payment delayed htlc seed)

(defun fresh-keys ()
  (flet ((k () (c:generate-key)))
    (make-our-keys :funding (k) :revocation (k) :payment (k)
                   :delayed (k) :htlc (k)
                   :seed (c:octets (ironclad:random-data 32)))))

(defun pub (secret) (c:compressed-pubkey (c:pubkey-of secret)))

(defun run (&optional (uri (or (uiop:getenv "CL_PAYMENTS_PEER")
                               (error "set CL_PAYMENTS_PEER=<node_id>@host:port"))))
  (w:select-network :signet)
  (let* ((at (position #\@ uri)) (colon (position #\: uri :from-end t))
         (node-id (c:hex->bytes (subseq uri 0 at)))
         (host (subseq uri (1+ at) colon))
         (port (parse-integer (subseq uri (1+ colon))))
         (keys (fresh-keys))
         (funding-sat 200000)
         (temp-id (c:octets (ironclad:random-data 32)))
         (inbox (make-hash-table))
         (lock (bt:make-lock)) (cv (bt:make-condition-variable)))
    (multiple-value-bind (our-node-key our-node-point) (c:generate-key)
      (declare (ignore our-node-point))
      (let ((peer (p:connect host port node-id our-node-key
                             :chain-hashes (list (w:chain-hash))
                             :log nil :read-loop nil)))
        (unwind-protect
             (progn
               ;; Collect every message; the flow below waits on specific types.
               (dolist (ty (list ch:+msg-accept-channel+ ch:+msg-funding-signed+
                                 ch:+msg-channel-ready+ p:+msg-error+ p:+msg-warning+))
                 (let ((type ty))
                   (p:on peer type
                         (lambda (pr payload) (declare (ignore pr))
                           (bt:with-lock-held (lock)
                             (setf (gethash type inbox) payload)
                             (bt:condition-notify cv))))))
               (p:start-read-loop peer)
               (flet ((await (type seconds what)
                        (bt:with-lock-held (lock)
                          (loop with deadline = (+ (get-universal-time) seconds)
                                until (gethash type inbox)
                                do (when (gethash p:+msg-error+ inbox)
                                     (error "peer sent an error: ~a"
                                            (p::decode-error (gethash p:+msg-error+ inbox))))
                                   (when (> (get-universal-time) deadline)
                                     (error "timed out waiting for ~a" what))
                                   (bt:condition-wait cv lock :timeout 1)))
                        (gethash type inbox)))

                 (step! "connected to ~a" (subseq (c:bytes->hex node-id) 0 16))

                 ;; ---- open_channel -------------------------------------------
                 (step! "open_channel: ~d sat, nothing pushed" funding-sat)
                 (p:send-message
                  peer
                  (ch:encode-open-channel
                   (ch:make-open-channel
                    :chain-hash (w:chain-hash)
                    :temporary-channel-id temp-id
                    :funding-satoshis funding-sat :push-msat 0
                    :dust-limit-satoshis 546
                    :max-htlc-value-in-flight-msat (* funding-sat 1000)
                    :channel-reserve-satoshis (floor funding-sat 100)
                    :htlc-minimum-msat 1
                    :feerate-per-kw 2500
                    :to-self-delay 144 :max-accepted-htlcs 30
                    :funding-pubkey (pub (our-keys-funding keys))
                    :revocation-basepoint (pub (our-keys-revocation keys))
                    :payment-basepoint (pub (our-keys-payment keys))
                    :delayed-payment-basepoint (pub (our-keys-delayed keys))
                    :htlc-basepoint (pub (our-keys-htlc keys))
                    :first-per-commitment-point
                    (k:per-commitment-point (our-keys-seed keys) k:+max-commitment-index+)
                    :channel-flags 0))
                  nil)

                 ;; ---- accept_channel -----------------------------------------
                 (let ((acc (ch:parse-accept-channel
                             (await ch:+msg-accept-channel+ 30 "accept_channel"))))
                   (step! "accept_channel received")
                   (note "minimum_depth ~d, to_self_delay ~d, dust ~d"
                         (ch:ac-minimum-depth acc) (ch:ac-to-self-delay acc)
                         (ch:ac-dust-limit-satoshis acc))

                   ;; ---- build (but do not broadcast) the funding transaction --
                   (step! "building the funding transaction")
                   (let* ((funding-script (m:funding-script (pub (our-keys-funding keys))
                                                            (ch:ac-funding-pubkey acc)))
                          ;; Compute the P2WSH address ourselves rather than
                          ;; asking bitcoind: `deriveaddresses` wants a descriptor
                          ;; CHECKSUM, and we already have bech32 in cl-consensus.
                          (address (let ((cl-consensus.encoding::*bech32-hrp* "tb"))
                                     ;; signet shares testnet's human-readable
                                     ;; part; cl-consensus defaults to mainnet.
                                     (benc:encode-p2wsh (c:sha256 funding-script))))
                          (raw (bcli "createrawtransaction" "[]"
                                     (format nil "\"[{\\\"~a\\\":~,8f}]\""
                                             address (/ funding-sat 100000000.0d0))))
                          (funded (bcli "fundrawtransaction" raw))
                          (fhex (json-string funded "hex"))
                          (signed (bcli "signrawtransactionwithwallet" fhex))
                          (shex (json-string signed "hex"))
                          (ftx (btx:parse-tx (bw:make-reader (bw:hex->bytes shex))))
                          (fidx (position (m:p2wsh funding-script) (btx:tx-outputs ftx)
                                          :key #'btx:txout-script :test #'equalp)))
                     (note "funding txid ~a output ~a"
                           (bw:hash->hex (btx:tx-txid ftx)) fidx)
                     (unless fidx (error "our 2-of-2 output is not in the funding tx"))

                     ;; ---- sign THEIR first commitment --------------------------
                     ;; Their commitment: to_local is THEIR balance behind THEIR
                     ;; delayed key and OUR revocation key; to_remote is ours.  We
                     ;; pushed nothing, so their side is empty and only our output
                     ;; exists — the fee comes out of ours, since we opened.
                     (step! "signing their first commitment")
                     (let* ((their-pcp (ch:ac-first-per-commitment-point acc))
                            (obscuring (m:obscuring-factor (pub (our-keys-payment keys))
                                                           (ch:ac-payment-basepoint acc)))
                            (their-commitment
                              (m:build-commitment
                               :funding-txid (btx:tx-txid ftx)
                               :funding-output-index fidx
                               :funding-amount-sat funding-sat
                               :commitment-number 0 :obscuring obscuring
                               :to-local-msat 0
                               :to-remote-msat (* funding-sat 1000)
                               :local-feerate-per-kw 2500
                               :dust-limit-sat (ch:ac-dust-limit-satoshis acc)
                               ;; Revocation key in THEIR commitment is built from
                               ;; OUR revocation basepoint — it exists so WE can
                               ;; punish THEM.
                               :revocation-pubkey
                               (k:derive-revocation-pubkey (pub (our-keys-revocation keys))
                                                           their-pcp)
                               :to-self-delay 144
                               :delayed-pubkey
                               (k:derive-pubkey (ch:ac-delayed-payment-basepoint acc) their-pcp)
                               ;; option_static_remotekey: to_remote is our payment
                               ;; basepoint verbatim, with no per-commitment
                               ;; blinding at all.
                               :remote-pubkey (pub (our-keys-payment keys))
                               :opener :remote)))
                       (let ((sig (m:sign-commitment their-commitment
                                                     (our-keys-funding keys)
                                                     (pub (our-keys-funding keys))
                                                     (ch:ac-funding-pubkey acc)
                                                     funding-sat)))
                         (note "signature ~a…" (subseq (c:bytes->hex sig) 0 24))

                         ;; ---- funding_created ---------------------------------
                         (step! "funding_created (the funding tx is NOT broadcast yet)")
                         (p:send-message
                          peer
                          (ch:encode-funding-created
                           (ch:make-funding-created
                            :temporary-channel-id temp-id
                            :funding-txid (btx:tx-txid ftx)
                            :funding-output-index fidx
                            :signature sig))
                          nil)

                         ;; ---- funding_signed ----------------------------------
                         (let ((fs (ch:parse-funding-signed
                                    (await ch:+msg-funding-signed+ 30 "funding_signed"))))
                           (step! "funding_signed received — THEY ACCEPTED OUR SIGNATURE")
                           (note "channel_id ~a" (c:bytes->hex (ch:fs-channel-id fs)))
                           (note "expected   ~a"
                                 (c:bytes->hex (ch:channel-id (btx:tx-txid ftx) fidx)))
                           (note "match: ~a"
                                 (equalp (c:octets (ch:fs-channel-id fs))
                                         (c:octets (ch:channel-id (btx:tx-txid ftx) fidx))))

                           ;; ---- now it is safe to broadcast ------------------
                           (step! "broadcasting the funding transaction")
                           (note "~a" (bcli "sendrawtransaction" shex))
                           (uiop:run-program "/mnt/lisp/signet/mine.sh 6"
                                             :output nil :error-output nil
                                             :ignore-error-status t)
                           (note "mined 6 blocks")

                           ;; ---- channel_ready --------------------------------
                           (step! "channel_ready")
                           (p:send-message
                            peer
                            (ch:encode-channel-ready
                             (ch:make-channel-ready
                              :channel-id (ch:channel-id (btx:tx-txid ftx) fidx)
                              :second-per-commitment-point
                              (k:per-commitment-point (our-keys-seed keys)
                                                      (1- k:+max-commitment-index+))))
                            nil)
                           (let ((cr (await ch:+msg-channel-ready+ 60 "their channel_ready")))
                             (declare (ignore cr))
                             (step! "their channel_ready received"))
                           (format t "~&~%✓ a real Lightning node opened a channel with us.~%")
                           t)))))))
          (ignore-errors (p:disconnect peer)))))))

(run)
