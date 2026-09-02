;;;; src/node.lisp
;;;;
;;;; Phase 4e — the daemon.
;;;;
;;;; Everything up to here has been a library plus scripts: dial a peer, do a
;;;; thing, exit.  That is enough to open a channel and not enough to HAVE one.
;;;; Three separate parts of the protocol need a process that stays up:
;;;;
;;;;   * `announcement_signatures` arrive once the funding transaction is buried,
;;;;     and are sent to a CONNECTED peer.  A script that exits after
;;;;     `channel_ready` is gone before the moment arrives, so its channels can
;;;;     never be announced and never enter anyone's routing graph.
;;;;   * A routing hop must be REACHABLE.  Dialling out and leaving makes you an
;;;;     endpoint by construction.
;;;;   * The HTLC cycle interleaves over time — `commitment_signed` one way,
;;;;     `revoke_and_ack` the other — and neither side controls the pacing.
;;;;
;;;; Shaped after cl-consensus's node.lisp: one long-lived process owning a peer
;;;; registry, a listener, and the persistent state, with a thread per connection.
;;;;
;;;; The thread rule is not stylistic.  In SBCL a socket is torn down when the
;;;; thread that created it exits, so an accept callback that spawns a reader and
;;;; returns leaves the stream with a NIL buffer and the next write dies deep
;;;; inside SB-IMPL with an error that says nothing about threads.  The accepting
;;;; thread BECOMES the connection's owner here, which is why ON-INBOUND ends in
;;;; RUN-READ-LOOP rather than START-READ-LOOP.

(defpackage #:cl-payments.node
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:p #:cl-payments.peer) (#:k #:cl-payments.keys)
                    (#:ch #:cl-payments.channel) (#:u #:cl-payments.updates)
                    (#:gs #:cl-payments.gossip) (#:m #:cl-payments.commitment)
                    (#:f #:cl-payments.features) (#:lv #:cl-payments.live)
                    (#:on #:cl-payments.onion) (#:fw #:cl-payments.forward)
                    (#:inv #:cl-payments.invoice) (#:rt #:cl-payments.route)
                    (#:tr #:cl-transport) (#:bt #:bordeaux-threads)
                    (#:btx #:cl-consensus.tx) (#:bw #:cl-consensus.wire)
                    (#:secp #:secp256k1-fast))
  (:nicknames #:ln-node)
  (:export
   #:node #:make-node #:start #:stop #:node-id #:node-alive-p
   #:node-peers #:node-channels #:node-dir #:node-port #:node-log-stream
   #:connect-to #:node-peer-count #:node-channel-count
   #:save-channels #:load-channels
   #:stored-channel #:make-stored-channel
   #:sc-channel-id #:sc-peer-id #:sc-funding-txid
   #:sc-funding-index #:sc-capacity-sat #:sc-announced-p
   #:sc-key-index #:sc-scid #:sc-remote-funding-pubkey
   #:sc-local-msat #:sc-remote-msat
   #:sc-local-commitment-number #:sc-remote-commitment-number
   #:channel-keys #:derive-channel-keys #:ck-pub
   #:ck-index #:ck-funding #:ck-revocation #:ck-payment #:ck-delayed #:ck-htlc #:ck-seed
   #:node-error #:pay-invoice #:node-router #:run-command-loop
   #:open-channel-to #:funding-confirmed #:close-channel #:node-privkey #:node-payments
   #:payment #:pay-status #:pay-preimage #:pay-failure #:pay-amount-msat))

(in-package #:cl-payments.node)

(define-condition node-error (error)
  ((detail :initarg :detail :reader node-error-detail))
  (:report (lambda (c s) (format s "node: ~a" (node-error-detail c)))))

;;; ----------------------------------------------------------------------------
;;; Persistent channel records
;;;
;;; A channel outlives the process, so the daemon has to remember enough to
;;; resume one after a restart: who it is with, where its money is, and how far
;;; the commitment cycle got.  Written as s-expressions rather than JSON to keep
;;; the dependency list where it is — this is a handful of fields, not a format.
;;; ----------------------------------------------------------------------------

(defstruct (stored-channel (:conc-name sc-))
  channel-id peer-id funding-txid funding-index capacity-sat
  (local-msat 0) (remote-msat 0)
  (local-commitment-number 0) (remote-commitment-number 0)
  (announced-p nil)
  ;; KEY-INDEX names the deterministic key family this channel uses; see
  ;; DERIVE-CHANNEL-KEYS.  The remaining fields are what announcing the channel
  ;; needs and nothing else knows: where the funding output landed, the peer's
  ;; funding pubkey (the other half of the 2-of-2), and the two signatures the
  ;; peer contributed.
  (key-index 0)
  scid remote-funding-pubkey remote-node-sig remote-bitcoin-sig
  ;; The commitment-cycle state, for channels the daemon accepted.  Channels
  ;; opened by inspect/open-channel.lisp predate this and have none: they are
  ;; announced and routable in the graph, but no HTLC can cross them.
  (live nil))

;;; ----------------------------------------------------------------------------
;;; Channel keys
;;;
;;; Every key a channel uses is DERIVED from the node's static key and a small
;;; integer, rather than generated randomly and stored.  The difference is
;;; whether a channel can survive the loss of its state file: with random keys,
;;; the funding output is a 2-of-2 whose other half exists nowhere but in that
;;; one file, and losing it is losing the money.  Derived keys can be
;;; regenerated from the node key alone, so the state file only has to remember
;;; WHICH index a channel used — a number that is cheap to recover by scanning
;;; a few candidates, unlike 32 bytes of entropy.
;;;
;;; The index has to be the thing keys hang off because the funding pubkey goes
;;; into `open_channel`, which is sent before the funding transaction exists —
;;; so the channel id, which is derived from the funding outpoint, is not
;;; available yet.  This is why real implementations keep a monotonic counter.
;;; ----------------------------------------------------------------------------

(defstruct (channel-keys (:conc-name ck-))
  index funding revocation payment delayed htlc seed)

(defun %derive-scalar (privkey index role)
  "One private key, as an integer, from the node key and a labelled index.
   Rejects the astronomically-unlikely out-of-range result rather than silently
   producing an invalid key."
  (let* ((salt (c:ascii->bytes "cl-payments channel keys"))
         (okm (c:hkdf salt (secp:int-to-bytes32 privkey)
                      :info (c:ascii->bytes (format nil "~a/~d" role index))
                      :length 32)))
    (let ((n (secp:bytes-to-int okm)))
      (unless (c:valid-privkey-p n)
        (error 'node-error :detail (format nil "derived invalid key for ~a/~d" role index)))
      n)))

(defun derive-channel-keys (privkey index)
  "The full key family for channel INDEX.  Same node key and index always give
   the same channel keys, on any machine, after any crash."
  (make-channel-keys
   :index index
   :funding    (%derive-scalar privkey index "funding")
   :revocation (%derive-scalar privkey index "revocation")
   :payment    (%derive-scalar privkey index "payment")
   :delayed    (%derive-scalar privkey index "delayed")
   :htlc       (%derive-scalar privkey index "htlc")
   ;; The shachain seed is bytes, not a scalar — it is hashed, never multiplied.
   :seed (c:hkdf (c:ascii->bytes "cl-payments channel keys")
                 (secp:int-to-bytes32 privkey)
                 :info (c:ascii->bytes (format nil "seed/~d" index))
                 :length 32)))

(defun ck-pub (scalar) (c:compressed-pubkey (c:pubkey-of scalar)))

(defun %hex (b) (c:bytes->hex b))
(defun %unhex (s) (c:hex->bytes s))

(defun save-channels (node)
  "Write the channel table.  Written to a temporary file and renamed, so a crash
   mid-write leaves the previous good file rather than a truncated one — losing
   channel state is losing the ability to claim your own money."
  (bt:with-lock-held ((node-save-lock node))
  (let* ((path (merge-pathnames "channels.sexp" (node-dir node)))
         (tmp (merge-pathnames "channels.sexp.tmp" (node-dir node))))
    (with-open-file (s tmp :direction :output :if-exists :supersede)
      (format s ";;; cl-payments channel state — written by the daemon, do not edit~%")
      (let ((*print-pretty* nil))
        (maphash (lambda (id sc)
                   (declare (ignore id))
                   (prin1 (list :channel-id (%hex (sc-channel-id sc))
                                :peer-id (%hex (sc-peer-id sc))
                                :funding-txid (%hex (sc-funding-txid sc))
                                :funding-index (sc-funding-index sc)
                                :capacity-sat (sc-capacity-sat sc)
                                :local-msat (sc-local-msat sc)
                                :remote-msat (sc-remote-msat sc)
                                :local-commitment-number (sc-local-commitment-number sc)
                                :remote-commitment-number (sc-remote-commitment-number sc)
                                :announced-p (sc-announced-p sc)
                                :key-index (sc-key-index sc)
                                :scid (let ((s (sc-scid sc)))
                                        (and s (gs:scid-string s)))
                                :remote-funding-pubkey
                                (let ((k (sc-remote-funding-pubkey sc)))
                                  (and k (%hex k)))
                                :remote-node-sig
                                (let ((k (sc-remote-node-sig sc))) (and k (%hex k)))
                                :remote-bitcoin-sig
                                (let ((k (sc-remote-bitcoin-sig sc))) (and k (%hex k)))
                                :live (let ((l (sc-live sc))) (and l (lv:live->plist l))))
                          s)
                   (terpri s))
                 (node-channels node))))
    (rename-file tmp path)
    path)))

(defun load-channels (node)
  (let ((path (merge-pathnames "channels.sexp" (node-dir node))))
    (when (probe-file path)
      (with-open-file (s path)
        (loop for form = (read s nil)
              while form
              do (let ((sc (make-stored-channel
                            :channel-id (%unhex (getf form :channel-id))
                            :peer-id (%unhex (getf form :peer-id))
                            :funding-txid (%unhex (getf form :funding-txid))
                            :funding-index (getf form :funding-index)
                            :capacity-sat (getf form :capacity-sat)
                            :local-msat (getf form :local-msat)
                            :remote-msat (getf form :remote-msat)
                            :local-commitment-number (getf form :local-commitment-number)
                            :remote-commitment-number (getf form :remote-commitment-number)
                            :announced-p (getf form :announced-p)
                            :key-index (or (getf form :key-index) 0)
                            :scid (let ((v (getf form :scid)))
                                    (and v (gs:parse-scid-string v)))
                            :remote-funding-pubkey
                            (let ((v (getf form :remote-funding-pubkey)))
                              (and v (%unhex v)))
                            :remote-node-sig
                            (let ((v (getf form :remote-node-sig))) (and v (%unhex v)))
                            :remote-bitcoin-sig
                            (let ((v (getf form :remote-bitcoin-sig)))
                              (and v (%unhex v)))
                            :live (let ((v (getf form :live))) (and v (lv:plist->live v))))))
                   (setf (gethash (%hex (sc-channel-id sc)) (node-channels node)) sc)))))
    (hash-table-count (node-channels node))))

;;; ----------------------------------------------------------------------------
;;; The node
;;; ----------------------------------------------------------------------------

(defstruct (node (:constructor %make-node))
  privkey                          ; our static identity (integer)
  id                               ; 33-byte compressed pubkey
  dir                              ; where state lives
  port
  (peers (make-hash-table :test 'equal))     ; hex node id -> peer
  (channels (make-hash-table :test 'equal))  ; hex channel id -> stored-channel
  (pending (make-hash-table :test 'equal))   ; hex temporary channel id -> pending-open
  ;; Forwarding state.  FORWARDS: (out-cid-hex . out-id) -> forward record, so a
  ;; resolution arriving on the outgoing channel finds its way upstream.
  ;; IN-FLIGHT: (in-cid-hex . in-id) -> t while we wait on downstream, so the
  ;; same incoming HTLC is not resolved twice.
  (forwards (make-hash-table :test 'equal))
  (in-flight (make-hash-table :test 'equal))
  ;; One lock for everything that touches live channels.  A forward spans TWO
  ;; channels, whose peers run on two threads; without this, the outgoing send
  ;; races the incoming peer's next message over the same state.
  (htlc-lock (bt:make-recursive-lock "htlc"))
  ;; The routing graph, as gossip describes it, and the payments WE originated:
  ;; payment-hash hex -> payment.  Both are what the sending half needs and
  ;; the forwarding half never did.
  (router (gs:make-router))
  (router-lock (bt:make-lock "router"))
  (payments (make-hash-table :test 'equal))
  (origin-htlcs (make-hash-table :test 'equal))    ; (cid-hex . id) -> payment
  ;; Persisting is temp-file-and-rename, which is atomic against a crash and
  ;; not at all against a second thread doing the same thing: two writers race
  ;; on the temp file and one of them renames what the other just deleted.
  (save-lock (bt:make-lock "save"))
  (alive-p nil)
  listener-closer
  (lock (bt:make-lock "node"))
  (log-stream *standard-output*)
  (features f:*default-features*))

(defun make-node (&key dir port privkey (log *standard-output*))
  "Create a node.  PRIVKEY defaults to the persistent key in DIR/node.key — a
   node that generates a fresh identity cannot reconnect to any channel it ever
   opened, because a channel is a 2-of-2 with a specific counterparty."
  (let* ((dir (uiop:ensure-directory-pathname dir))
         (key (or privkey
                  (let ((f (merge-pathnames "node.key" dir)))
                    (unless (probe-file f)
                      (error 'node-error
                             :detail (format nil "no node key at ~a" f)))
                    (secp:bytes-to-int
                     (c:hex->bytes (string-trim '(#\Newline #\Space)
                                                (uiop:read-file-string f))))))))
    (%make-node :privkey key
                :id (c:compressed-pubkey (c:pubkey-of key))
                :dir dir :port port :log-stream log)))

(defun nlog (node fmt &rest args)
  (when (node-log-stream node)
    (bt:with-lock-held ((node-lock node))
      (format (node-log-stream node) "~&[~a] ~?~%"
              (subseq (%hex (node-id node)) 0 8) fmt args)
      (force-output (node-log-stream node)))))

(defun node-peer-count (n) (hash-table-count (node-peers n)))
(defun node-channel-count (n) (hash-table-count (node-channels n)))

;;; ----------------------------------------------------------------------------
;;; Message handling
;;; ----------------------------------------------------------------------------

(defun channels-with (node peer-id)
  (let ((out '()))
    (maphash (lambda (id sc)
               (declare (ignore id))
               (when (equalp (c:octets (sc-peer-id sc)) (c:octets peer-id))
                 (push sc out)))
             (node-channels node))
    out))

(defun handle-reestablish (node peer payload)
  "Answer `channel_reestablish`.  Both sides send it before anything else on a
   reconnected channel, and a peer that never replies leaves the channel
   permanently unsynced — usable by neither end even though the connection looks
   healthy."
  (let ((re (handler-case (u:parse-channel-reestablish payload)
              (error (e) (nlog node "bad channel_reestablish: ~a" e) nil))))
    (when re
      (let* ((cid (u:cre-channel-id re))
             (sc (gethash (%hex cid) (node-channels node))))
        (nlog node "channel_reestablish for ~a: they expect commitment ~d, revocation ~d"
              (subseq (%hex cid) 0 16)
              (u:cre-next-commitment-number re) (u:cre-next-revocation-number re))
        ;; Reply even for a channel we do not know: staying silent is worse than
        ;; a wrong answer, because the peer waits forever.  The numbers below are
        ;; the "nothing has happened yet" state, which is true of a channel we
        ;; have no record of.
        (let ((ours (if (and sc (sc-live sc))
                        (lv:reestablish-message (sc-live sc))
                        (u:encode-channel-reestablish
                         (u:make-channel-reestablish
                     :channel-id cid
                     :next-commitment-number
                     (if sc (1+ (sc-local-commitment-number sc)) 1)
                     :next-revocation-number
                     (if sc (sc-remote-commitment-number sc) 0)
                     :your-last-per-commitment-secret (c:zeros 32)
                     :my-current-per-commitment-point
                     (k:per-commitment-point
                      (c:sha256 (c:bytes (secp:int-to-bytes32 (node-privkey node)) cid))
                      (- k:+max-commitment-index+
                         (if sc (sc-local-commitment-number sc) 0))))))))
          (ignore-errors (p:send-message peer ours nil)))))))

(defconstant +msg-announcement-signatures+ 259)

(defun encode-announcement-signatures (channel-id scid node-sig bitcoin-sig)
  (let ((wr (w:make-writer)))
    (w:w-bytes wr (c:octets channel-id))
    (w:w-u64 wr (gs:scid->u64 scid))
    (w:w-sig wr node-sig)
    (w:w-sig wr bitcoin-sig)
    (w:writer-bytes wr)))

(defun announcement-body-for (node sc)
  "The bytes both ends sign to announce SC.  Returns (values body we-are-node-1-p),
   or NIL if we do not know the peer's funding pubkey.

   Both ends must produce byte-identical bodies or all four signatures are over
   different messages and the announcement is simply invalid — so the BOLT #7
   ordering is applied here, once, rather than assumed anywhere."
  (let ((remote-funding (sc-remote-funding-pubkey sc))
        (scid (sc-scid sc)))
    (when (and remote-funding scid)
      (let ((local-funding (ck-pub (ck-funding (derive-channel-keys (node-privkey node)
                                                                   (sc-key-index sc))))))
        (multiple-value-bind (n1 n2 we-are-1) (gs:node-order (node-id node) (sc-peer-id sc))
          (values (gs:channel-announcement-body
                   :features 0
                   :chain-hash (w:chain-hash)
                   :scid scid
                   :node-1 n1 :node-2 n2
                   ;; The bitcoin keys follow the NODE ordering, not their own.
                   :bitcoin-1 (if we-are-1 local-funding remote-funding)
                   :bitcoin-2 (if we-are-1 remote-funding local-funding))
                  we-are-1))))))

(defun broadcast-announcement (node peer sc)
  "Assemble the four-signature `channel_announcement` and send it, followed by our
   `channel_update` for our own direction.

   The announcement alone makes the channel VISIBLE; it does not make it usable.
   Routing needs a policy — fees and a CLTV delta — per direction, and a channel
   with no update from us is one no sender will ever route through, because there
   is no way to know what we would charge."
  (multiple-value-bind (body we-are-1) (announcement-body-for node sc)
    (unless body (return-from broadcast-announcement nil))
    (let* ((keys (derive-channel-keys (node-privkey node) (sc-key-index sc)))
           (our-node-sig (gs:sign-gossip (node-privkey node) body))
           (our-btc-sig  (gs:sign-gossip (ck-funding keys) body))
           (ann (gs:encode-channel-announcement
                 body
                 :node-sig-1    (if we-are-1 our-node-sig (sc-remote-node-sig sc))
                 :node-sig-2    (if we-are-1 (sc-remote-node-sig sc) our-node-sig)
                 :bitcoin-sig-1 (if we-are-1 our-btc-sig (sc-remote-bitcoin-sig sc))
                 :bitcoin-sig-2 (if we-are-1 (sc-remote-bitcoin-sig sc) our-btc-sig))))
      ;; Verify our own work before putting it on the wire.  A malformed
      ;; announcement is not rejected with an error — it is silently dropped by
      ;; every peer, which is indistinguishable from never having sent it.
      (if (gs:verify-channel-announcement (gs:parse-channel-announcement ann))
          (progn
            (p:send-message peer gs:+msg-channel-announcement+ ann)
            (send-channel-update node peer sc we-are-1)
            (setf (sc-announced-p sc) t)
            (save-channels node)
            (nlog node "announced ~a — channel_announcement + channel_update sent"
                  (gs:scid-string (sc-scid sc)))
            t)
          (progn (nlog node "refusing to send channel_announcement for ~a: it does not verify"
                       (gs:scid-string (sc-scid sc)))
                 nil)))))

(defun send-channel-update (node peer sc we-are-1)
  "Our routing policy for our own direction of SC.

   The announcement makes the channel VISIBLE; this makes it USABLE.  A channel
   with no update from us is one no sender will route through, because there is
   no way to know what we would charge.  It is sent separately from the
   announcement because a reconnecting peer does not repeat its
   `announcement_signatures` — it already has ours — so a node that only ever
   emitted its policy alongside the announcement would advertise it exactly once
   and then go quiet forever."
  (let* ((upd-body (gs:channel-update-body
                    :chain-hash (w:chain-hash)
                    :scid (sc-scid sc)
                    :timestamp (- (get-universal-time)
                                  (encode-universal-time 0 0 0 1 1 1970 0))
                    ;; Bit 0 of channel_flags is the DIRECTION, and it must
                    ;; match our position in the node ordering.
                    :channel-flags (if we-are-1 0 1)
                    :htlc-maximum-msat (* 1000 (sc-capacity-sat sc))))
         (upd (gs:encode-channel-update (node-privkey node) upd-body)))
    (p:send-message peer gs:+msg-channel-update+ upd)))

(defun handle-announcement-signatures (node peer payload)
  "`announcement_signatures` is the peer offering to make the channel public: it
   is their half of the four signatures a `channel_announcement` needs.

   Receiving it at all is the thing a script could never do — it arrives once the
   funding is buried, to a CONNECTED peer.  We check their half, contribute ours,
   and then assemble and broadcast the announcement."
  (handler-case
      (let* ((r (w:make-reader payload))
             (cid (w:r-bytes r 32))
             (scid (gs:u64->scid (w:r-u64 r)))
             (their-node-sig (w:r-sig r))
             (their-btc-sig (w:r-sig r))
             (sc (gethash (%hex cid) (node-channels node))))
        (nlog node "announcement_signatures for ~a (scid ~a)"
              (subseq (%hex cid) 0 16) (gs:scid-string scid))
        (cond
          ((null sc)
           (nlog node "  no record of that channel — ignoring"))
          (t
           (setf (sc-scid sc) scid
                 (sc-remote-node-sig sc) their-node-sig
                 (sc-remote-bitcoin-sig sc) their-btc-sig)
           (multiple-value-bind (body we-are-1) (announcement-body-for node sc)
             (declare (ignore we-are-1))
             (cond
               ((null body)
                (nlog node "  no remote funding pubkey on record — cannot announce")
                (save-channels node))
               ;; Their signatures are checked before ours go out.  A peer whose
               ;; signatures do not verify is either buggy or trying to get us to
               ;; publish an announcement that names our key on a channel we
               ;; cannot prove — either way, do not co-sign it.
               ((not (and (gs:verify-gossip-sig their-node-sig body (sc-peer-id sc))
                          (gs:verify-gossip-sig their-btc-sig body
                                                (sc-remote-funding-pubkey sc))))
                (nlog node "  their signatures do not verify — refusing to announce"))
               (t
                (let ((keys (derive-channel-keys (node-privkey node) (sc-key-index sc))))
                  (p:send-message
                   peer +msg-announcement-signatures+
                   (encode-announcement-signatures
                    cid scid
                    (gs:sign-gossip (node-privkey node) body)
                    (gs:sign-gossip (ck-funding keys) body))))
                (nlog node "  sent our announcement_signatures")
                (broadcast-announcement node peer sc)))))))
    (error (e) (nlog node "bad announcement_signatures: ~a" e))))

(defun readvertise (node peer)
  "Re-send our policy for every already-announced channel with this peer.

   Gossip is not retained forever by anyone, and a peer that reconnects does not
   re-send `announcement_signatures` for a channel it has already announced.  So
   the only moment we would otherwise ever advertise a policy is the single
   instant the channel was first announced — after which our direction of the
   channel quietly ages out of the network and stops being routable."
  (dolist (sc (channels-with node (p:peer-node-id peer)))
    (when (and (sc-announced-p sc) (sc-scid sc) (sc-remote-funding-pubkey sc))
      (multiple-value-bind (body we-are-1) (announcement-body-for node sc)
        (declare (ignore body))
        (handler-case
            (progn (send-channel-update node peer sc we-are-1)
                   (nlog node "re-advertised our policy for ~a" (gs:scid-string (sc-scid sc))))
          (error (e) (nlog node "could not re-advertise ~a: ~a"
                           (gs:scid-string (sc-scid sc)) e)))))))


;;; ----------------------------------------------------------------------------
;;; Accepting a channel
;;;
;;; The other half of BOLT #2.  Everything so far has had us OPEN channels, which
;;; only ever tests the code paths we happen to drive.  Accepting exercises the
;;; mirror image, and the two are not symmetric in the way that matters: as the
;;; opener we choose the funding transaction and can simply refuse to broadcast
;;; if something looks wrong, whereas as the ACCEPTER we are told about a funding
;;; output that already exists and our only protection is checking their
;;; signature over our commitment before we agree to anything.
;;;
;;; It also fixes an asymmetry in liquidity.  A channel we funded is
;;; outbound-only: the peer holds nothing, so nobody can route a payment TOWARD
;;; us over it.  Channels opened toward us are the only ones we can receive over.
;;; ----------------------------------------------------------------------------

(defstruct (pending-open (:conc-name po-))
  temporary-channel-id keys open-msg
  ;; the opener's side of the handshake
  (role :accepter) funding-sat push-msat fund-fn broadcast-fn channel-id
  funding-txid funding-index accept-msg live)

(defun next-key-index (node)
  "One past the highest index in use.  Reusing an index reuses a funding key
   across two channels, so a revocation secret leaked on one would apply to the
   other."
  (let ((n 0))
    (maphash (lambda (id sc) (declare (ignore id))
               (setf n (max n (1+ (sc-key-index sc)))))
             (node-channels node))
    n))

(defun their-channel-type (oc)
  "The channel_type the peer actually put on the wire (TLV 1), or NIL."
  (let ((raw (and (ch:oc-tlvs oc) (w:tlv-get (ch:oc-tlvs oc) 1))))
    (and raw (f:bytes->features raw))))

(defun handle-open-channel (node peer payload)
  "Answer `open_channel` with `accept_channel`.

   The checks here are deliberately about OUR exposure, not about whether their
   parameters are sensible for them.  We are not putting funds in, so a large
   funding amount is their risk; what we refuse is a channel we could not
   safely hold — one on the wrong chain, or one whose to_self_delay would lock
   our own funds up for an unreasonable time if we had to force-close."
  (handler-case
      (let ((oc (ch:parse-open-channel payload)))
        (nlog node "open_channel from ~a: ~d sat, ~d msat pushed to us~@[, announce~]"
              (subseq (%hex (p:peer-node-id peer)) 0 16)
              (ch:oc-funding-satoshis oc) (ch:oc-push-msat oc)
              (logtest (ch:oc-channel-flags oc) 1))
        (cond
          ((not (equalp (c:octets (ch:oc-chain-hash oc)) (c:octets (w:chain-hash))))
           (nlog node "  wrong chain — refusing"))
          ;; to_self_delay is how long OUR funds are frozen after we force-close.
          ;; The peer chooses it, so an absurd value is an attack on us.
          ((> (ch:oc-to-self-delay oc) 2016)
           (nlog node "  to_self_delay ~d is too long — refusing" (ch:oc-to-self-delay oc)))
          (t
           (let* ((index (next-key-index node))
                  (keys (derive-channel-keys (node-privkey node) index))
                  (po (make-pending-open
                       :temporary-channel-id (ch:oc-temporary-channel-id oc)
                       :keys keys :open-msg oc)))
             (setf (gethash (%hex (ch:oc-temporary-channel-id oc)) (node-pending node)) po)
             (p:send-message
              peer
              (ch:encode-accept-channel
               (ch:make-accept-channel
                :temporary-channel-id (ch:oc-temporary-channel-id oc)
                :dust-limit-satoshis 546
                :max-htlc-value-in-flight-msat (* 1000 (ch:oc-funding-satoshis oc))
                ;; Their reserve: the amount they may never spend below, so they
                ;; always have something to lose by cheating.  1% is the usual
                ;; choice; zero would make revocation punishment worthless.
                :channel-reserve-satoshis (max 546 (floor (ch:oc-funding-satoshis oc) 100))
                :htlc-minimum-msat 1
                ;; One confirmation is fine on a devnet we mine ourselves.
                :minimum-depth 1
                :to-self-delay 144
                :max-accepted-htlcs 30
                :funding-pubkey (ck-pub (ck-funding keys))
                :revocation-basepoint (ck-pub (ck-revocation keys))
                :payment-basepoint (ck-pub (ck-payment keys))
                :delayed-payment-basepoint (ck-pub (ck-delayed keys))
                :htlc-basepoint (ck-pub (ck-htlc keys))
                :first-per-commitment-point
                (k:per-commitment-point (ck-seed keys) k:+max-commitment-index+)
                ;; Echo back exactly what they OFFERED, read off the wire.
                ;; OC-CHANNEL-TYPE would be the struct's default here, not their
                ;; choice — parse-open-channel leaves TLVs raw — and answering a
                ;; type they did not ask for is a counter-offer, which
                ;; accept_channel cannot express.  If they sent none, we send
                ;; none.
                :channel-type (their-channel-type oc)))
              nil)
             (nlog node "  accept_channel sent (key index ~d)" index)))))
    (error (e) (nlog node "bad open_channel: ~a" e))))

(defun handle-funding-created (node peer payload)
  "Verify their signature over OUR first commitment, then sign THEIRS.

   Order matters and is not a style choice.  Their signature is what lets us
   spend the funding output unilaterally; if we sent `funding_signed` first and
   theirs turned out to be invalid, they could broadcast a funding transaction
   we can never claim from.  So: check theirs, and only then produce ours."
  (handler-case
      (let* ((fc (ch:parse-funding-created payload))
             (po (gethash (%hex (ch:fc-temporary-channel-id fc)) (node-pending node))))
        (unless po
          (nlog node "funding_created for a channel we never accepted — ignoring")
          (return-from handle-funding-created nil))
        (let* ((oc (po-open-msg po))
               (keys (po-keys po))
               (funding-sat (ch:oc-funding-satoshis oc))
               (push-msat (ch:oc-push-msat oc))
               (their-pcp (ch:oc-first-per-commitment-point oc))
               (our-pcp-seed (ck-seed keys))
               (obscuring (m:obscuring-factor (ch:oc-payment-basepoint oc)
                                              (ck-pub (ck-payment keys))))
               (our-funding-pub (ck-pub (ck-funding keys)))
               (their-funding-pub (ch:oc-funding-pubkey oc))
               ;; OUR commitment: to_local is what we hold (the push), behind our
               ;; delayed key and THEIR revocation key.  They opened, so the fee
               ;; comes off their side.
               (our-pcp (k:per-commitment-point our-pcp-seed k:+max-commitment-index+))
               (our-commitment
                 (m:build-commitment
                  :funding-txid (ch:fc-funding-txid fc)
                  :funding-output-index (ch:fc-funding-output-index fc)
                  :funding-amount-sat funding-sat
                  :commitment-number 0 :obscuring obscuring
                  :to-local-msat push-msat
                  :to-remote-msat (- (* funding-sat 1000) push-msat)
                  :local-feerate-per-kw (ch:oc-feerate-per-kw oc)
                  :dust-limit-sat (ch:oc-dust-limit-satoshis oc)
                  ;; The revocation key in OUR commitment comes from THEIR
                  ;; revocation basepoint: it exists so THEY can punish US.
                  :revocation-pubkey
                  (k:derive-revocation-pubkey (ch:oc-revocation-basepoint oc) our-pcp)
                  :to-self-delay (ch:oc-to-self-delay oc)
                  :delayed-pubkey (k:derive-pubkey (ck-pub (ck-delayed keys)) our-pcp)
                  :remote-pubkey (ch:oc-payment-basepoint oc)
                  :opener :remote)))
          (unless (m:verify-commitment our-commitment (ch:fc-signature fc)
                                       our-funding-pub their-funding-pub
                                       funding-sat their-funding-pub)
            (nlog node "  their signature over OUR commitment does not verify — refusing")
            (return-from handle-funding-created nil))
          (nlog node "  their signature over our commitment verifies")

          ;; Now THEIR commitment, which we sign.  The mirror: to_local is their
          ;; balance behind their delayed key and OUR revocation key.
          (let* ((their-commitment
                   (m:build-commitment
                    :funding-txid (ch:fc-funding-txid fc)
                    :funding-output-index (ch:fc-funding-output-index fc)
                    :funding-amount-sat funding-sat
                    :commitment-number 0 :obscuring obscuring
                    :to-local-msat (- (* funding-sat 1000) push-msat)
                    :to-remote-msat push-msat
                    :local-feerate-per-kw (ch:oc-feerate-per-kw oc)
                    :dust-limit-sat (ch:oc-dust-limit-satoshis oc)
                    :revocation-pubkey
                    (k:derive-revocation-pubkey (ck-pub (ck-revocation keys)) their-pcp)
                    :to-self-delay 144
                    :delayed-pubkey
                    (k:derive-pubkey (ch:oc-delayed-payment-basepoint oc) their-pcp)
                    :remote-pubkey (ck-pub (ck-payment keys))
                    :opener :local))
                 (sig (m:sign-commitment their-commitment (ck-funding keys)
                                         our-funding-pub their-funding-pub funding-sat))
                 (cid (ch:channel-id (ch:fc-funding-txid fc)
                                     (ch:fc-funding-output-index fc))))
            (p:send-message peer
                            (ch:encode-funding-signed
                             (ch:make-funding-signed :channel-id cid :signature sig))
                            nil)
            (remhash (%hex (ch:fc-temporary-channel-id fc)) (node-pending node))
            (setf (gethash (%hex cid) (node-channels node))
                  (make-stored-channel
                   :channel-id cid
                   :peer-id (p:peer-node-id peer)
                   :funding-txid (ch:fc-funding-txid fc)
                   :funding-index (ch:fc-funding-output-index fc)
                   :capacity-sat funding-sat
                   :local-msat push-msat
                   :remote-msat (- (* funding-sat 1000) push-msat)
                   :key-index (ck-index keys)
                   :remote-funding-pubkey their-funding-pub
                   :live (lv:make-live
                          :channel-id cid :funding-txid (ch:fc-funding-txid fc)
                          :funding-index (ch:fc-funding-output-index fc)
                          :capacity-sat funding-sat :opener :remote
                          :funding-priv (ck-funding keys) :revocation-priv (ck-revocation keys)
                          :payment-priv (ck-payment keys) :delayed-priv (ck-delayed keys)
                          :htlc-priv (ck-htlc keys) :seed (ck-seed keys)
                          :remote-funding-pubkey their-funding-pub
                          :remote-revocation-basepoint (ch:oc-revocation-basepoint oc)
                          :remote-payment-basepoint (ch:oc-payment-basepoint oc)
                          :remote-delayed-basepoint (ch:oc-delayed-payment-basepoint oc)
                          :remote-htlc-basepoint (ch:oc-htlc-basepoint oc)
                          :local-dust-limit 546 :remote-dust-limit (ch:oc-dust-limit-satoshis oc)
                          ;; They chose the delay on OUR to_local; we chose theirs.
                          :local-to-self-delay (ch:oc-to-self-delay oc) :remote-to-self-delay 144
                          :feerate-per-kw (ch:oc-feerate-per-kw oc)
                          :local-msat push-msat :remote-msat (- (* funding-sat 1000) push-msat)
                          :remote-first-point their-pcp)))
            (save-channels node)
            (nlog node "  funding_signed sent — channel ~a accepted, ~d msat ours"
                  (subseq (%hex cid) 0 16) push-msat))))
    (error (e) (nlog node "bad funding_created: ~a" e))))

(defun handle-channel-ready (node peer payload)
  "Answer `channel_ready` with our own.

   Both ends must send it; a channel where only one side has is stuck in
   AWAITING_LOCKIN forever, which looks exactly like an unconfirmed funding
   transaction even though the funding has six confirmations.  There is no
   retry and no error — the peer simply waits.

   Sent unconditionally rather than once: `channel_ready` is idempotent, and a
   peer that reconnects and re-sends it needs an answer again."
  (handler-case
      (let* ((cr (ch:parse-channel-ready payload))
             (cid (ch:cr-channel-id cr))
             (sc (gethash (%hex cid) (node-channels node))))
        (nlog node "channel_ready for ~a" (subseq (%hex cid) 0 16))
        (if (null sc)
            (nlog node "  no record of that channel — not replying")
            (let ((keys (derive-channel-keys (node-privkey node) (sc-key-index sc))))
              ;; Their second per-commitment point is what we sign their FIRST
              ;; update into.  Only taken while nothing has happened yet: a peer
              ;; re-sending channel_ready after a reconnect must not rewind us.
              (when (and (sc-live sc) (zerop (lv:live-remote-commit-index (sc-live sc))))
                (lv:set-remote-next-point (sc-live sc) (ch:cr-second-per-commitment-point cr))
                (save-channels node))
              (p:send-message
               peer
               (ch:encode-channel-ready
                (ch:make-channel-ready
                 :channel-id cid
                 :second-per-commitment-point
                 (k:per-commitment-point (ck-seed keys) (1- k:+max-commitment-index+))))
               nil)
              (nlog node "  our channel_ready sent"))))
    (error (e) (nlog node "bad channel_ready: ~a" e))))


;;; ----------------------------------------------------------------------------
;;; The HTLC cycle on a live channel
;;;
;;; The daemon's part is deliberately thin: hand each message to the live
;;; channel, send back whatever it returns, and persist.  Two decisions live
;;; here rather than in live.lisp because they are POLICY, not protocol:
;;;
;;;   * when to send commitment_signed — as soon as there is something to sign
;;;     and nothing outstanding.  A node that waits for "enough" updates is a
;;;     node whose peer times out.
;;;   * when to settle a received HTLC — once it is in BOTH commitments, and
;;;     only if we hold the preimage.  Settling earlier lets the peer dispute a
;;;     payment we already treated as received.
;;; ----------------------------------------------------------------------------

(defun known-preimages (node)
  "Preimages we are willing to reveal, from <dir>/preimages.sexp: one hex string
   per line.  Re-read on every HTLC so a preimage can be added while the daemon
   runs.  This stands in for invoices (Phase 7); the payment_hash is what a
   sender puts in the onion, and knowing its preimage is what makes the payment
   ours to claim."
  (let ((path (merge-pathnames "preimages.sexp" (node-dir node))))
    (when (probe-file path)
      (with-open-file (s path)
        (loop for form = (read s nil) while form
              collect (%unhex (string form)))))))

(defun preimage-for (node payment-hash)
  (find-if (lambda (pre) (equalp (c:octets (c:sha256 pre)) (c:octets payment-hash)))
           (known-preimages node)))

(defun live-channel-for (node payload)
  "The stored channel a channel-scoped message is about, by its leading
   channel_id, or NIL (logged) if we do not have a live one."
  (let* ((cid (subseq payload 0 32))
         (sc (gethash (%hex cid) (node-channels node))))
    (cond ((null sc) (nlog node "  message for unknown channel ~a" (subseq (%hex cid) 0 16)) nil)
          ((null (sc-live sc)) (nlog node "  channel ~a has no live state" (subseq (%hex cid) 0 16)) nil)
          (t sc))))

(defun maybe-commit (node peer sc)
  "Sign their next commitment if there is anything to sign and we may."
  (let ((lc (sc-live sc)))
    (when (lv:can-send-commit-p lc)
      (p:send-message peer (lv:send-commit lc) nil)
      (nlog node "  commitment_signed sent (their commitment ~d)"
            (1+ (lv:live-remote-commit-index lc))))))

(defstruct (forward (:conc-name fwd-))
  in-sc in-id in-peer shared-secret out-sc out-id)

(defun our-channel-update-message (node sc)
  "Our current channel_update for SC as a full message (type included), for the
   UPDATE-class failures that carry one."
  (multiple-value-bind (body we-are-1) (announcement-body-for node sc)
    (declare (ignore body))
    (w:encode-message
     gs:+msg-channel-update+
     (gs:encode-channel-update
      (node-privkey node)
      (gs:channel-update-body
       :chain-hash (w:chain-hash) :scid (sc-scid sc)
       :timestamp (- (get-universal-time) (encode-universal-time 0 0 0 1 1 1970 0))
       :channel-flags (if we-are-1 0 1)
       :htlc-maximum-msat (* 1000 (sc-capacity-sat sc)))))))

(defun fail-upstream (node peer sc h ss code &key channel-update extra)
  "Fail a received HTLC with a proper BOLT #4 failure onion, encrypted to the
   sender under the shared secret we peeled it with."
  (let* ((msg (on:encode-failure-message code :channel-update channel-update :extra extra))
         (reason (on:create-failure-packet ss msg)))
    (p:send-message peer (lv:send-fail (sc-live sc) (lv:hr-id h) reason) nil)
    (nlog node "  HTLC ~d: failed with ~(~a~)" (lv:hr-id h) (fw:failure-name code))))

(defun find-outgoing (node scid)
  "The live, open channel with SCID and its connected peer, or NIL."
  (let ((found nil))
    (maphash (lambda (k sc) (declare (ignore k))
               (when (and (sc-scid sc) (sc-live sc) (not (lv:live-closed-p (sc-live sc)))
                          (= (gs:scid->u64 (sc-scid sc)) (gs:scid->u64 scid)))
                 (setf found sc)))
             (node-channels node))
    (values found (and found (gethash (%hex (sc-peer-id found)) (node-peers node))))))

(defun resolve-received (node peer sc)
  "Every received HTLC that is now committed on both sides gets exactly one of:
   fulfilled (it is ours and we hold the preimage), forwarded (the onion names a
   next channel), or failed — with a reason the sender can read."
  (let ((lc (sc-live sc)))
    (dolist (h (lv:fully-committed-received-htlcs lc))
      (let ((key (cons (%hex (sc-channel-id sc)) (lv:hr-id h))))
        (unless (gethash key (node-in-flight node))
          (setf (gethash key (node-in-flight node)) t)
          (handler-case
              (multiple-value-bind (payload next ss)
                  (on:peel-onion (lv:hr-onion h) (node-privkey node) (lv:hr-payment-hash h))
                ;; From here on we HAVE a shared secret, so every failure can be
                ;; a proper encrypted reason — including a payload we cannot
                ;; parse, which is invalid_onion_payload rather than BADONION:
                ;; the onion was fine, its contents were not.
                (let ((hp (handler-case (on:parse-hop-payload payload)
                            (error (e)
                              (nlog node "  HTLC ~d: unparseable payload (~a)" (lv:hr-id h) e)
                              (fail-upstream node peer sc h ss fw:+invalid-onion-payload+)
                              nil))))
                  (cond
                    ((null hp) nil)
                    ;; A payload naming no next channel on a non-final hop, or a
                    ;; next channel on the final hop, is the sender contradicting
                    ;; itself.
                    ((if next (null (on:hp-scid hp)) (on:hp-scid hp))
                     (fail-upstream node peer sc h ss fw:+invalid-onion-payload+))
                    ;; ---- final hop: it is for us ---------------------------------
                    ((null next)
                     (let ((pre (preimage-for node (lv:hr-payment-hash h))))
                       (cond
                         ((< (lv:hr-amount-msat h) (on:hp-amount-msat hp))
                          (fail-upstream node peer sc h ss fw:+final-incorrect-htlc-amount+
                                         :extra (let ((wr (w:make-writer))) (w:w-u64 wr (lv:hr-amount-msat h)) (w:writer-bytes wr))))
                         ((< (lv:hr-cltv-expiry h) (on:hp-cltv-expiry hp))
                          (fail-upstream node peer sc h ss fw:+final-incorrect-cltv-expiry+
                                         :extra (let ((wr (w:make-writer))) (w:w-u32 wr (lv:hr-cltv-expiry h)) (w:writer-bytes wr))))
                         (pre
                          (p:send-message peer (lv:send-fulfill lc (lv:hr-id h) pre) nil)
                          (nlog node "  HTLC ~d is for us: onion read, preimage known — fulfilled, ~d msat ours"
                                (lv:hr-id h) (lv:hr-amount-msat h)))
                         (t
                          (fail-upstream node peer sc h ss fw:+incorrect-or-unknown-payment-details+
                                         :extra (let ((wr (w:make-writer)))
                                                  (w:w-u64 wr (lv:hr-amount-msat h)) (w:w-u32 wr 0)
                                                  (w:writer-bytes wr)))))))
                    ;; ---- intermediate hop: forward it ------------------------------
                    (t
                     (multiple-value-bind (out-sc out-peer) (find-outgoing node (on:hp-scid hp))
                       (let* ((out-lc (and out-sc (sc-live out-sc)))
                              (decision
                                (fw:check-forward
                                 :incoming-amount-msat (lv:hr-amount-msat h)
                                 :incoming-cltv-expiry (lv:hr-cltv-expiry h)
                                 :amount-to-forward-msat (on:hp-amount-msat hp)
                                 :outgoing-cltv-expiry (on:hp-cltv-expiry hp)
                                 :policy (fw:make-policy)
                                 :outgoing (fw:make-outgoing
                                            :known-p (and out-sc t)
                                            :peer-connected-p (and out-peer (p:peer-alive-p out-peer) t)
                                            :available-msat (if out-lc (lv:live-local-balance-msat out-lc) 0)
                                            :pending-htlcs (if out-lc (length (lv:live-htlcs out-lc)) 0))
                                 :current-height nil)))
                         (cond
                           ((not (fw:forward-decision-ok-p decision))
                            (let ((code (fw:forward-decision-failure-code decision)))
                              (nlog node "  HTLC ~d: not forwarding to ~a — ~a" (lv:hr-id h)
                                    (gs:scid-string (on:hp-scid hp)) (fw:forward-decision-detail decision))
                              (fail-upstream node peer sc h ss code
                                             :channel-update (and (fw:failure-update-p code) out-sc
                                                                  (our-channel-update-message node out-sc)))))
                           (t
                            (let* ((out-msg (lv:send-add out-lc (on:hp-amount-msat hp) (lv:hr-payment-hash h)
                                                         (on:hp-cltv-expiry hp) next))
                                   (out-id (1- (lv:live-next-htlc-id out-lc))))
                              (setf (gethash (cons (%hex (sc-channel-id out-sc)) out-id) (node-forwards node))
                                    (make-forward :in-sc sc :in-id (lv:hr-id h) :in-peer peer
                                                  :shared-secret ss :out-sc out-sc :out-id out-id))
                              (p:send-message out-peer out-msg nil)
                              (nlog node "  HTLC ~d: forwarding ~d msat over ~a as HTLC ~d (fee ~d msat)"
                                    (lv:hr-id h) (on:hp-amount-msat hp) (gs:scid-string (sc-scid out-sc)) out-id
                                    (- (lv:hr-amount-msat h) (on:hp-amount-msat hp)))
                              (maybe-commit node out-peer out-sc)
                              (save-channels node))))))))))
            (on:onion-error (e)
              ;; We could not even open the onion: no shared secret, so no
              ;; encrypted reason.  BADONION, in the clear, with the onion's hash.
              (nlog node "  HTLC ~d: unreadable onion (~a) — update_fail_malformed_htlc" (lv:hr-id h) e)
              (p:send-message peer (lv:send-fail-malformed lc (lv:hr-id h) (lv:hr-onion h)
                                                           (logior fw:+badonion+ fw:+perm+ 5))
                              nil))))))))

(defun settle-received (node peer sc) (resolve-received node peer sc))

(defun relay-resolution (node out-sc out-id kind &key preimage reason malformed-code)
  "Something resolved an HTLC we FORWARDED.  Carry it upstream: a fulfil with the
   preimage, or a failure with one more onion layer added under the incoming
   hop's shared secret."
  (let* ((key (cons (%hex (sc-channel-id out-sc)) out-id))
         (f (gethash key (node-forwards node))))
    (when f
      (remhash key (node-forwards node))
      (let ((in-lc (sc-live (fwd-in-sc f))) (in-peer (fwd-in-peer f)))
        (ecase kind
          (:fulfill
           (p:send-message in-peer (lv:send-fulfill in-lc (fwd-in-id f) preimage) nil)
           (nlog node "  forwarded HTLC ~d settled downstream — fulfilling upstream HTLC ~d"
                 out-id (fwd-in-id f)))
          (:fail
           (p:send-message in-peer
                           (lv:send-fail in-lc (fwd-in-id f)
                                         (on:wrap-failure-packet (fwd-shared-secret f) reason))
                           nil)
           (nlog node "  forwarded HTLC ~d failed downstream — relaying the failure upstream" out-id))
          (:malformed
           ;; Downstream could not read the onion WE forwarded.  Convert into a
           ;; proper failure onion from our position, as BOLT #4 requires.
           (p:send-message in-peer
                           (lv:send-fail in-lc (fwd-in-id f)
                                         (on:create-failure-packet (fwd-shared-secret f)
                                                                   (on:encode-failure-message malformed-code)))
                           nil)
           (nlog node "  forwarded HTLC ~d: downstream reports malformed onion — failing upstream" out-id)))
        (remhash (cons (%hex (sc-channel-id (fwd-in-sc f))) (fwd-in-id f)) (node-in-flight node))
        (maybe-commit node in-peer (fwd-in-sc f))))))

(defmacro with-live-channel ((sc lc node payload what) &body body)
  `(handler-case
       (bt:with-recursive-lock-held ((node-htlc-lock ,node))
         (let ((,sc (live-channel-for ,node ,payload)))
           (when ,sc
             (let ((,lc (sc-live ,sc)))
               (declare (ignorable ,lc))
               ,@body
               (save-channels ,node)))))
     (error (e) (nlog ,node "~a: ~a" ,what e))))

(defun handle-update-add (node peer payload)
  (declare (ignore peer))
  (with-live-channel (sc lc node payload "update_add_htlc")
    (let ((h (lv:receive-add lc payload)))
      (nlog node "update_add_htlc ~d: ~d msat, hash ~a, expiry ~d"
            (lv:hr-id h) (lv:hr-amount-msat h) (subseq (%hex (lv:hr-payment-hash h)) 0 16)
            (lv:hr-cltv-expiry h)))))

(defun handle-commitment-signed (node peer payload)
  (with-live-channel (sc lc node payload "commitment_signed")
    (let ((raa (lv:receive-commit lc payload)))
      (nlog node "commitment_signed verified — our commitment ~d has ~d HTLC~:p, ~d msat ours"
            (lv:live-local-commit-index lc) (length (lv:live-htlcs lc))
            (lv:live-local-balance-msat lc))
      (p:send-message peer raa nil)
      (nlog node "  revoke_and_ack sent")
      ;; Their updates are acked now; sign them into their commitment.
      (maybe-commit node peer sc))))

(defun handle-revoke-and-ack (node peer payload)
  (with-live-channel (sc lc node payload "revoke_and_ack")
    (lv:receive-revocation lc payload)
    (nlog node "revoke_and_ack accepted — their commitment ~d is current"
          (lv:live-remote-commit-index lc))
    (settle-received node peer sc)
    (maybe-commit node peer sc)))

(defun handle-update-fulfill (node peer payload)
  (declare (ignore peer))
  (with-live-channel (sc lc node payload "update_fulfill_htlc")
    (let ((h (lv:receive-fulfill lc payload)))
      (nlog node "update_fulfill_htlc ~d: preimage verified" (lv:hr-id h))
      (relay-resolution node sc (lv:hr-id h) :fulfill :preimage (lv:hr-preimage h))
      (resolve-origin node sc (lv:hr-id h) :fulfill :preimage (lv:hr-preimage h)))))

(defun handle-update-fail (node peer payload)
  (declare (ignore peer))
  (with-live-channel (sc lc node payload "update_fail_htlc")
    (let* ((r (w:make-reader payload :start 32))
           (id (w:r-u64 r))
           (reason (w:r-varbytes r)))
      (lv:receive-fail lc id)
      (nlog node "update_fail_htlc ~d" id)
      (relay-resolution node sc id :fail :reason reason)
      (resolve-origin node sc id :fail :reason reason))))

(defun handle-update-fail-malformed (node peer payload)
  (declare (ignore peer))
  (with-live-channel (sc lc node payload "update_fail_malformed_htlc")
    (let* ((r (w:make-reader payload :start 32))
           (id (w:r-u64 r)))
      (w:r-bytes r 32)
      (let ((code (w:r-u16 r)))
        (lv:receive-fail lc id)
        (nlog node "update_fail_malformed_htlc ~d: failure code #x~x" id code)
        (relay-resolution node sc id :malformed :malformed-code code)
        (resolve-origin node sc id :malformed :malformed-code code)))))

(defun handle-update-fee (node peer payload)
  (declare (ignore peer))
  (with-live-channel (sc lc node payload "update_fee")
    (let ((fee (w:r-u32 (w:make-reader payload :start 32))))
      (lv:receive-fee lc fee)
      (nlog node "update_fee: ~d sat/kw" fee))))

;;; ----------------------------------------------------------------------------
;;; Closing
;;; ----------------------------------------------------------------------------

(defun our-shutdown-script (node sc)
  "Where our side of a close goes: P2WPKH of a key derived for this channel.
   Recoverable from the node key alone, like every other channel key."
  (m:p2wpkh (ck-pub (%derive-scalar (node-privkey node) (sc-key-index sc) "close"))))

(defun handle-shutdown (node peer payload)
  (with-live-channel (sc lc node payload "shutdown")
    (lv:receive-shutdown lc payload)
    (nlog node "shutdown received for ~a" (gs:scid-string (or (sc-scid sc) (gs:make-scid 0 0 0))))
    (unless (lv:live-local-shutdown-script lc)
      (p:send-message peer (lv:send-shutdown lc (our-shutdown-script node sc)) nil)
      (nlog node "  our shutdown sent"))
    (maybe-propose-close node peer sc)))

(defun handle-closing-signed (node peer payload)
  (with-live-channel (sc lc node payload "closing_signed")
    (let ((already (lv:live-closed-p lc)))
      (multiple-value-bind (reply tx) (lv:receive-closing-signed lc payload)
        ;; If we PROPOSED, their closing_signed is the agreement, and answering
        ;; it would start a second round.  Verify and stop.
        (unless already (p:send-message peer reply nil))
        (nlog node "closing_signed: their signature verifies — ~a, closing tx ~a"
              (if already "agreed to our proposal" "agreed") (bw:hash->hex (btx:tx-txid tx)))))))


;;; ----------------------------------------------------------------------------
;;; Gossip: keep the graph
;;;
;;; The forwarding half could ignore gossip — a forwarding node is told where
;;; to send by the onion.  A SENDING node has to choose, and can only choose
;;; among channels it has heard of.
;;; ----------------------------------------------------------------------------

(defun ingest-gossip (node type payload)
  (bt:with-lock-held ((node-router-lock node))
    (gs:ingest (node-router node) type payload)))

(defun request-gossip (node peer)
  "Ask a freshly connected peer for its whole graph.  A peer that has not been
   asked forwards only NEW gossip, and a quiet network then looks like an empty
   one."
  (declare (ignore node))
  (ignore-errors
   (p:send-message peer gs:+msg-gossip-timestamp-filter+
                   (gs:encode-gossip-timestamp-filter (w:chain-hash)))))

;;; ----------------------------------------------------------------------------
;;; Paying
;;; ----------------------------------------------------------------------------

(defstruct (payment (:conc-name pay-))
  payment-hash amount-msat decoded      ; DECODED, not INVOICE: pay-invoice is the function
  hops shared-secrets
  sc htlc-id                ; the HTLC we offered, and on which channel
  (status :pending) preimage failure
  result-path               ; where to write the outcome, if a command asked
  bolt11 height exclude attempt)   ; enough to try again around a failed channel

(defun own-edges (node)
  "Our live channels as edges FROM us.  Gossip may or may not have relayed our
   own announcements back to us; either way we know these better — the
   capacity is our actual spendable balance, not an advertised maximum."
  (let ((out '()))
    (maphash (lambda (k sc) (declare (ignore k))
               (let ((lc (sc-live sc)))
                 (when (and lc (sc-scid sc) (not (lv:live-closed-p lc))
                            (gethash (%hex (sc-peer-id sc)) (node-peers node)))
                   (push (rt:make-edge :from (node-id node) :to (sc-peer-id sc) :scid (sc-scid sc)
                                       :policy (fw:make-policy)
                                       :capacity-msat (lv:live-local-balance-msat lc))
                         out))))
             (node-channels node))
    out))

(defun all-edges (node)
  "Our own channels as WE know them, plus everyone else's as gossip describes
   them.  Gossip's edges out of our own node are dropped: they include channels
   we announced but cannot use (the script-opened ones with no live state), and
   for the rest they would only duplicate what own-edges says with less
   information."
  (append (own-edges node)
          (remove-if (lambda (e) (equalp (c:octets (rt:edge-from e)) (c:octets (node-id node))))
                     (bt:with-lock-held ((node-router-lock node))
                       (rt:router-edges (node-router node))))))

(defun write-result (payment)
  (when (pay-result-path payment)
    (ignore-errors
     (with-open-file (s (pay-result-path payment) :direction :output :if-exists :supersede)
       (let ((*print-pretty* nil))
         (prin1 (list :status (pay-status payment)
                      :payment-hash (%hex (pay-payment-hash payment))
                      :amount-msat (pay-amount-msat payment)
                      :fee-msat (and (pay-hops payment)
                                     (rt:total-fee-msat (pay-hops payment) (pay-amount-msat payment)))
                      :hops (length (pay-hops payment))
                      :preimage (and (pay-preimage payment) (%hex (pay-preimage payment)))
                      :failure (pay-failure payment))
                s)
         (terpri s))))))

(defconstant +max-payment-attempts+ 5)

(defun pay-invoice (node bolt11 &key current-height result-path (amount-msat nil))
  "Pay an invoice: decode it, find a route, build the onion, offer the HTLC.
   Returns the payment record; the outcome arrives later, on the channel the
   HTLC went out on, as a fulfil or a failure — and a TRANSIENT failure that
   names a channel leads to another attempt around it."
  (attempt-payment node bolt11 :current-height current-height :result-path result-path
                               :amount-msat amount-msat :exclude '() :attempt 1))

(defun attempt-payment (node bolt11 &key current-height result-path amount-msat exclude attempt)
  (let* ((invoice (inv:decode-invoice bolt11))
         (amount (or (inv:inv-amount-msat invoice) amount-msat
                     (error 'node-error :detail "invoice has no amount and none was given")))
         (hash (inv:inv-payment-hash invoice)))
    (unless (eq (inv:inv-network invoice) (w:net-name w:*network*))
      (error 'node-error :detail (format nil "invoice is for ~a, we are on ~a"
                                         (inv:inv-network invoice) (w:net-name w:*network*))))
    (when (inv:inv-expired-p invoice) (error 'node-error :detail "invoice has expired"))
    (unless current-height (error 'node-error :detail "need the current block height"))
    (bt:with-recursive-lock-held ((node-htlc-lock node))
      (let* ((hops (rt:find-route (all-edges node) (node-id node) (inv:inv-payee invoice) amount
                                  :final-cltv-delta (inv:inv-min-final-cltv-expiry-delta invoice)
                                  :current-height current-height :exclude exclude))
             (first-hop (first hops))
             (out-sc (find-outgoing node (rt:hop-scid first-hop)))
             (out-peer (and out-sc (gethash (%hex (sc-peer-id out-sc)) (node-peers node)))))
        (unless (and out-sc out-peer)
          (error 'node-error :detail "route's first hop is not one of our connected channels"))
        ;; One payload per hop.  Node i's payload says what node i+1 must
        ;; receive and over which channel; the last says it is the recipient.
        (let* ((payloads
                 (loop for (h next) on hops
                       collect (on:encode-hop-payload
                                (if next
                                    (on:make-hop-payload :amount-msat (rt:hop-amount-msat next)
                                                         :cltv-expiry (rt:hop-cltv-expiry next)
                                                         :scid (rt:hop-scid next))
                                    (on:make-hop-payload :amount-msat (rt:hop-amount-msat h)
                                                         :cltv-expiry (rt:hop-cltv-expiry h)
                                                         :payment-secret (inv:inv-payment-secret invoice)
                                                         :total-msat amount)))))
               (session-key (c:generate-key)))
          (multiple-value-bind (onion secrets)
              (on:create-onion session-key (mapcar #'rt:hop-node hops) payloads hash)
            (let* ((lc (sc-live out-sc))
                   (msg (lv:send-add lc (rt:hop-amount-msat first-hop) hash
                                     (rt:hop-cltv-expiry first-hop) onion))
                   (id (1- (lv:live-next-htlc-id lc)))
                   (payment (make-payment :payment-hash hash :amount-msat amount :decoded invoice
                                          :hops hops :shared-secrets secrets
                                          :sc out-sc :htlc-id id :result-path result-path
                                          :bolt11 bolt11 :height current-height
                                          :exclude exclude :attempt attempt)))
              (setf (gethash (%hex hash) (node-payments node)) payment
                    (gethash (cons (%hex (sc-channel-id out-sc)) id) (node-origin-htlcs node)) payment)
              (p:send-message out-peer msg nil)
              (nlog node "paying ~d msat to ~a (attempt ~d): ~{~a~^ -> ~}, fee ~d msat, HTLC ~d~@[, excluding ~{~a~^ ~}~]"
                    amount (subseq (%hex (inv:inv-payee invoice)) 0 16) attempt
                    (mapcar (lambda (h) (gs:scid-string (rt:hop-scid h))) hops)
                    (rt:total-fee-msat hops amount) id
                    (mapcar #'gs:scid-string exclude))
              (write-result payment)
              (maybe-commit node out-peer out-sc)
              (save-channels node)
              payment)))))))

(defun resolve-origin (node sc id kind &key preimage reason malformed-code)
  "An HTLC WE offered was resolved.  Was it a payment of ours?"
  (let* ((key (cons (%hex (sc-channel-id sc)) id))
         (payment (gethash key (node-origin-htlcs node))))
    (when payment
      (remhash key (node-origin-htlcs node))
      (ecase kind
        (:fulfill
         (setf (pay-status payment) :complete (pay-preimage payment) preimage)
         (nlog node "  PAYMENT COMPLETE: ~d msat, preimage ~a"
               (pay-amount-msat payment) (subseq (%hex preimage) 0 16)))
        (:fail
         (multiple-value-bind (hop failure) (on:decrypt-failure-packet (pay-shared-secrets payment) reason)
           (let* ((code (and failure (on:parse-failure-message failure)))
                  ;; The channel hop I was asked to forward over is hop I+1's.
                  (blamed (and hop (< (1+ hop) (length (pay-hops payment)))
                               (rt:hop-scid (nth (1+ hop) (pay-hops payment)))))
                  (retry-p (and code blamed
                                (not (fw:failure-permanent-p code))
                                (< (pay-attempt payment) +max-payment-attempts+))))
             (setf (pay-failure payment) (if hop
                                             (list :hop hop :code (and code (fw:failure-name code))
                                                   :node (%hex (rt:hop-node (nth hop (pay-hops payment)))))
                                             (list :unreadable t)))
             (cond
               (retry-p
                ;; A transient failure names a channel that would not carry the
                ;; payment right now.  Gossip could not have told us that; a
                ;; retry around it is the only way to learn it.
                (nlog node "  attempt ~d failed at hop ~d (~(~a~)) — retrying without ~a"
                      (pay-attempt payment) hop (fw:failure-name code) (gs:scid-string blamed))
                (handler-case
                    (attempt-payment node (pay-bolt11 payment)
                                     :current-height (pay-height payment)
                                     :result-path (pay-result-path payment)
                                     :amount-msat (pay-amount-msat payment)
                                     :exclude (cons blamed (pay-exclude payment))
                                     :attempt (1+ (pay-attempt payment)))
                  (error (e)
                    (setf (pay-status payment) :failed
                          (pay-failure payment) (append (pay-failure payment) (list :then (princ-to-string e))))
                    (nlog node "  PAYMENT FAILED: ~a" (pay-failure payment))
                    (write-result payment))))
               (t
                (setf (pay-status payment) :failed)
                (nlog node "  PAYMENT FAILED: ~a" (pay-failure payment)))))))
        (:malformed
         (setf (pay-status payment) :failed
               (pay-failure payment) (list :hop 0 :code :bad-onion :failure-code malformed-code))
         (nlog node "  PAYMENT FAILED: first hop could not read our onion (#x~x)" malformed-code)))
      (unless (and (eq kind :fail) (eq (pay-status payment) :pending))
        (write-result payment)))))

;;; ----------------------------------------------------------------------------
;;; Commands
;;;
;;; The daemon has no RPC.  It watches <dir>/commands/ for files containing one
;;; form and writes the outcome beside them.  Enough to drive it from a shell,
;;; without inventing a protocol before there is a need for one.
;;; ----------------------------------------------------------------------------

(defun run-command-loop (node)
  (let ((dir (merge-pathnames "commands/" (node-dir node))))
    (ensure-directories-exist dir)
    (loop
      (dolist (f (directory (merge-pathnames "*.cmd" dir)))
        (let* ((form (handler-case (with-open-file (s f) (read s)) (error () nil)))
               (result (make-pathname :type "result" :defaults f)))
          (delete-file f)
          (handler-case
              (ecase (first form)
                (:pay (pay-invoice node (getf (rest form) :bolt11)
                                   :current-height (getf (rest form) :height)
                                   :amount-msat (getf (rest form) :amount-msat)
                                   :result-path result))
                (:graph
                 (with-open-file (s result :direction :output :if-exists :supersede)
                   (bt:with-lock-held ((node-router-lock node))
                     (format s "(:channels ~d :nodes ~d :edges ~d :own ~d)~%"
                             (gs:router-channel-count (node-router node))
                             (gs:router-node-count (node-router node))
                             (length (rt:router-edges (node-router node)))
                             (length (own-edges node)))))))
            (error (e)
              (nlog node "command ~a failed: ~a" (first form) e)
              (with-open-file (s result :direction :output :if-exists :supersede)
                (format s "(:status :error :message ~s)~%" (princ-to-string e)))))))
      (sleep 0.5))))


;;; ----------------------------------------------------------------------------
;;; Opening a channel, from the daemon
;;;
;;; The script that opened channels until now ran the same handshake with
;;; bitcoind on the other end of a shell pipe.  Here the funding transaction is
;;; whatever FUND-FN returns: the daemon-to-daemon test fabricates one, and the
;;; devnet builds one with bitcoin-cli.  What the daemon insists on is the
;;; ORDER — the transaction is not broadcast until the peer has signed our
;;; first commitment — because broadcasting first hands the peer a funding
;;; output we can never spend alone.
;;; ----------------------------------------------------------------------------

(defun open-channel-to (node peer-id funding-sat &key (push-msat 0) fund-fn (announce t))
  "Start a channel with a connected peer.  FUND-FN receives the funding
   witness script and returns (values txid output-index broadcast-fn); the
   transaction must exist but must NOT be broadcast until BROADCAST-FN is
   called.  Returns the temporary channel id."
  (let* ((peer (or (gethash (%hex peer-id) (node-peers node))
                   (error 'node-error :detail "peer is not connected")))
         (index (next-key-index node))
         (keys (derive-channel-keys (node-privkey node) index))
         (temp-id (c:octets (ironclad:random-data 32))))
    (bt:with-recursive-lock-held ((node-htlc-lock node))
      (setf (gethash (%hex temp-id) (node-pending node))
            (make-pending-open :temporary-channel-id temp-id :keys keys :role :opener
                               :funding-sat funding-sat :push-msat push-msat :fund-fn fund-fn))
      (p:send-message
       peer
       (ch:encode-open-channel
        (ch:make-open-channel
         :chain-hash (w:chain-hash) :temporary-channel-id temp-id
         :funding-satoshis funding-sat :push-msat push-msat
         :dust-limit-satoshis 546 :max-htlc-value-in-flight-msat (* funding-sat 1000)
         :channel-reserve-satoshis (max 546 (floor funding-sat 100)) :htlc-minimum-msat 1
         :feerate-per-kw 2500 :to-self-delay 144 :max-accepted-htlcs 30
         :funding-pubkey (ck-pub (ck-funding keys))
         :revocation-basepoint (ck-pub (ck-revocation keys))
         :payment-basepoint (ck-pub (ck-payment keys))
         :delayed-payment-basepoint (ck-pub (ck-delayed keys))
         :htlc-basepoint (ck-pub (ck-htlc keys))
         :first-per-commitment-point (k:per-commitment-point (ck-seed keys) k:+max-commitment-index+)
         :channel-flags (if announce 1 0)))
       nil)
      (nlog node "open_channel sent to ~a: ~d sat, ~d msat pushed (key index ~d)"
            (subseq (%hex peer-id) 0 16) funding-sat push-msat index)
      temp-id)))

(defun handle-accept-channel (node peer payload)
  "They accepted.  Build the funding transaction, sign THEIR first commitment,
   send funding_created — and keep the transaction to ourselves."
  (handler-case
      (let* ((ac (ch:parse-accept-channel payload))
             (po (gethash (%hex (ch:ac-temporary-channel-id ac)) (node-pending node))))
        (unless (and po (eq (po-role po) :opener))
          (nlog node "accept_channel for a channel we did not open — ignoring")
          (return-from handle-accept-channel nil))
        (let* ((keys (po-keys po))
               (funding-sat (po-funding-sat po)) (push (po-push-msat po))
               (script (m:funding-script (ck-pub (ck-funding keys)) (ch:ac-funding-pubkey ac))))
          (multiple-value-bind (txid index broadcast-fn) (funcall (po-fund-fn po) script)
            (let* ((cid (ch:channel-id txid index))
                   (lc (lv:make-live
                        :channel-id cid :funding-txid txid :funding-index index
                        :capacity-sat funding-sat :opener :local
                        :funding-priv (ck-funding keys) :revocation-priv (ck-revocation keys)
                        :payment-priv (ck-payment keys) :delayed-priv (ck-delayed keys)
                        :htlc-priv (ck-htlc keys) :seed (ck-seed keys)
                        :remote-funding-pubkey (ch:ac-funding-pubkey ac)
                        :remote-revocation-basepoint (ch:ac-revocation-basepoint ac)
                        :remote-payment-basepoint (ch:ac-payment-basepoint ac)
                        :remote-delayed-basepoint (ch:ac-delayed-payment-basepoint ac)
                        :remote-htlc-basepoint (ch:ac-htlc-basepoint ac)
                        :local-dust-limit 546 :remote-dust-limit (ch:ac-dust-limit-satoshis ac)
                        ;; They chose the delay on OUR to_local; we chose theirs.
                        :local-to-self-delay (ch:ac-to-self-delay ac) :remote-to-self-delay 144
                        :feerate-per-kw 2500
                        :local-msat (- (* funding-sat 1000) push) :remote-msat push
                        :remote-first-point (ch:ac-first-per-commitment-point ac)))
                   (sig (lv:initial-commitment-signature lc)))
              (setf (po-accept-msg po) ac (po-live po) lc (po-channel-id po) cid
                    (po-funding-txid po) txid (po-funding-index po) index
                    (po-broadcast-fn po) broadcast-fn)
              ;; Re-key the pending entry by the real channel id: funding_signed
              ;; will name that, not the temporary one.
              (remhash (%hex (ch:ac-temporary-channel-id ac)) (node-pending node))
              (setf (gethash (%hex cid) (node-pending node)) po)
              (p:send-message
               peer
               (ch:encode-funding-created
                (ch:make-funding-created :temporary-channel-id (ch:ac-temporary-channel-id ac)
                                         :funding-txid txid :funding-output-index index
                                         :signature sig))
               nil)
              (nlog node "  accept_channel: funding ~a:~d, their commitment signed — funding_created sent"
                    (subseq (%hex txid) 0 16) index)))))
    (error (e) (nlog node "bad accept_channel: ~a" e))))

(defun handle-funding-signed (node peer payload)
  "Their signature over OUR first commitment.  Only once it verifies is the
   funding transaction allowed out of the building."
  (handler-case
      (let* ((fs (ch:parse-funding-signed payload))
             (cid (ch:fs-channel-id fs))
             (po (gethash (%hex cid) (node-pending node))))
        (unless (and po (eq (po-role po) :opener) (po-live po))
          (nlog node "funding_signed for an unknown channel — ignoring")
          (return-from handle-funding-signed nil))
        (let ((lc (po-live po)))
          (unless (lv:verify-initial-commitment lc (ch:fs-signature fs))
            (nlog node "  funding_signed: their signature over our commitment does NOT verify — abandoning")
            (remhash (%hex cid) (node-pending node))
            (return-from handle-funding-signed nil))
          (remhash (%hex cid) (node-pending node))
          (setf (gethash (%hex cid) (node-channels node))
                (make-stored-channel
                 :channel-id cid :peer-id (p:peer-node-id peer)
                 :funding-txid (po-funding-txid po) :funding-index (po-funding-index po)
                 :capacity-sat (po-funding-sat po)
                 :local-msat (lv:live-local-balance-msat lc) :remote-msat (lv:live-remote-balance-msat lc)
                 :key-index (ck-index (po-keys po))
                 :remote-funding-pubkey (ch:ac-funding-pubkey (po-accept-msg po))
                 :live lc))
          (save-channels node)
          (nlog node "  funding_signed verified — channel ~a is ours to fund" (subseq (%hex cid) 0 16))
          (when (po-broadcast-fn po)
            (funcall (po-broadcast-fn po))
            (nlog node "  funding transaction broadcast"))))
    (error (e) (nlog node "bad funding_signed: ~a" e))))

(defun funding-confirmed (node channel-id &key scid)
  "The funding transaction has enough confirmations: tell the peer with
   channel_ready.  Called by whoever watches the chain — a test, the devnet
   script, and eventually Phase 8."
  (let* ((sc (gethash (%hex channel-id) (node-channels node)))
         (peer (and sc (gethash (%hex (sc-peer-id sc)) (node-peers node)))))
    (unless (and sc peer) (error 'node-error :detail "no such live channel with a connected peer"))
    (when scid (setf (sc-scid sc) scid))
    (let ((keys (derive-channel-keys (node-privkey node) (sc-key-index sc))))
      (p:send-message
       peer
       (ch:encode-channel-ready
        (ch:make-channel-ready :channel-id channel-id
                               :second-per-commitment-point
                               (k:per-commitment-point (ck-seed keys) (1- k:+max-commitment-index+))))
       nil)
      (save-channels node)
      (nlog node "channel_ready sent for ~a" (subseq (%hex channel-id) 0 16)))))

(defun close-channel (node channel-id)
  "Begin a cooperative close: send shutdown.  The rest follows from the peer's
   shutdown — see HANDLE-SHUTDOWN — and, if we opened, our closing_signed."
  (let* ((sc (gethash (%hex channel-id) (node-channels node)))
         (peer (and sc (gethash (%hex (sc-peer-id sc)) (node-peers node)))))
    (unless (and sc (sc-live sc) peer) (error 'node-error :detail "no such live channel with a connected peer"))
    (bt:with-recursive-lock-held ((node-htlc-lock node))
      (p:send-message peer (lv:send-shutdown (sc-live sc) (our-shutdown-script node sc)) nil)
      (save-channels node)
      (nlog node "shutdown sent for ~a" (subseq (%hex channel-id) 0 16)))))

(defconstant +closing-fee-sat+ 1000)

(defun maybe-propose-close (node peer sc)
  "Both shutdowns are in.  The OPENER proposes the fee — it pays it — and the
   accepter only ever answers."
  (let ((lc (sc-live sc)))
    (when (and (eq (lv:live-opener lc) :local)
               (lv:live-local-shutdown-script lc) (lv:live-remote-shutdown-script lc)
               (not (lv:live-closed-p lc)) (null (lv:live-htlcs lc)))
      (multiple-value-bind (msg tx) (lv:propose-close lc +closing-fee-sat+)
        (p:send-message peer msg nil)
        (nlog node "  closing_signed proposed at ~d sat — closing tx ~a"
              +closing-fee-sat+ (bw:hash->hex (btx:tx-txid tx)))))))

(defun install-handlers (node peer)
  (p:on peer ch:+msg-open-channel+
        (lambda (pr payload) (handle-open-channel node pr payload)))
  (p:on peer ch:+msg-funding-created+
        (lambda (pr payload) (handle-funding-created node pr payload)))
  (p:on peer ch:+msg-accept-channel+
        (lambda (pr payload) (handle-accept-channel node pr payload)))
  (p:on peer ch:+msg-funding-signed+
        (lambda (pr payload) (handle-funding-signed node pr payload)))
  (p:on peer u:+msg-channel-reestablish+
        (lambda (pr payload) (handle-reestablish node pr payload)))
  (p:on peer +msg-announcement-signatures+
        (lambda (pr payload) (handle-announcement-signatures node pr payload)))
  (p:on peer ch:+msg-channel-ready+
        (lambda (pr payload) (handle-channel-ready node pr payload)))
  (p:on peer u:+msg-update-add-htlc+ (lambda (pr pl) (handle-update-add node pr pl)))
  (p:on peer u:+msg-commitment-signed+ (lambda (pr pl) (handle-commitment-signed node pr pl)))
  (p:on peer u:+msg-revoke-and-ack+ (lambda (pr pl) (handle-revoke-and-ack node pr pl)))
  (p:on peer u:+msg-update-fulfill-htlc+ (lambda (pr pl) (handle-update-fulfill node pr pl)))
  (p:on peer u:+msg-update-fail-htlc+ (lambda (pr pl) (handle-update-fail node pr pl)))
  (p:on peer u:+msg-update-fail-malformed-htlc+
        (lambda (pr pl) (handle-update-fail-malformed node pr pl)))
  (p:on peer u:+msg-update-fee+ (lambda (pr pl) (handle-update-fee node pr pl)))
  (p:on peer lv::+msg-shutdown+ (lambda (pr pl) (handle-shutdown node pr pl)))
  (p:on peer lv::+msg-closing-signed+ (lambda (pr pl) (handle-closing-signed node pr pl)))
  (dolist (ty (list gs:+msg-channel-announcement+ gs:+msg-channel-update+ gs:+msg-node-announcement+))
    (let ((type ty))
      (p:on peer type (lambda (pr pl) (declare (ignore pr)) (ingest-gossip node type pl))))))

;;; ----------------------------------------------------------------------------
;;; Connections
;;; ----------------------------------------------------------------------------

(defun register-peer (node peer)
  (bt:with-lock-held ((node-lock node))
    (setf (gethash (%hex (p:peer-node-id peer)) (node-peers node)) peer)))

(defun unregister-peer (node peer)
  (bt:with-lock-held ((node-lock node))
    (remhash (%hex (p:peer-node-id peer)) (node-peers node))))

(defun on-inbound (node stream closer)
  "Handle one inbound connection, IN THIS THREAD for its whole life.

   Returning here would let SBCL tear the socket down — see the file header.  So
   this blocks in RUN-READ-LOOP until the peer goes away."
  (handler-case
      (let ((peer (p:accept stream (node-privkey node) :closer closer
                            :features (node-features node)
                            :chain-hashes (list (w:chain-hash))
                            :log nil :read-loop nil)))
        (install-handlers node peer)
        (register-peer node peer)
        (nlog node "inbound peer ~a (~d channel~:p with them)"
              (subseq (%hex (p:peer-node-id peer)) 0 16)
              (length (channels-with node (p:peer-node-id peer))))
        (readvertise node peer)
        (request-gossip node peer)
        (unwind-protect (p:run-read-loop peer)
          (unregister-peer node peer)
          (nlog node "peer ~a disconnected" (subseq (%hex (p:peer-node-id peer)) 0 16))))
    (error (e) (nlog node "inbound connection failed: ~a" e))))

(defun connect-to (node uri &key (keep-alive t))
  "Dial a peer.  With KEEP-ALIVE the calling thread becomes the connection's
   owner and blocks; otherwise a reader thread is spawned and the caller must
   itself outlive the connection."
  (let* ((at (position #\@ uri)) (colon (position #\: uri :from-end t)))
    (unless (and at colon) (error 'node-error :detail (format nil "bad uri ~a" uri)))
    (let* ((node-id (c:hex->bytes (subseq uri 0 at)))
           (host (subseq uri (1+ at) colon))
           (port (parse-integer (subseq uri (1+ colon))))
           (peer (p:connect host port node-id (node-privkey node)
                            :features (node-features node)
                            :chain-hashes (list (w:chain-hash))
                            :log nil :read-loop nil)))
      (install-handlers node peer)
      (register-peer node peer)
      (nlog node "connected to ~a" (subseq (%hex node-id) 0 16))
      (readvertise node peer)
      (request-gossip node peer)
      (if keep-alive
          (unwind-protect (p:run-read-loop peer)
            (unregister-peer node peer))
          (progn (p:start-read-loop peer) peer)))))

;;; ----------------------------------------------------------------------------
;;; Lifecycle
;;; ----------------------------------------------------------------------------

(defun start (node)
  "Listen for inbound connections.  Returns immediately; the node runs until
   STOP."
  (when (node-alive-p node) (return-from start node))
  (ensure-directories-exist (node-dir node))
  (let ((n (load-channels node)))
    (nlog node "loaded ~d channel~:p from ~a" n (node-dir node)))
  (setf (node-listener-closer node)
        (tr:expose (lambda (stream peer-plist)
                     (declare (ignore peer-plist))
                     (on-inbound node stream nil))
                   :backend :tcp :host "127.0.0.1" :port (node-port node)))
  (setf (node-alive-p node) t)
  (nlog node "listening on 127.0.0.1:~d as~%           ~a"
        (node-port node) (%hex (node-id node)))
  node)

(defun stop (node)
  (when (node-listener-closer node)
    (ignore-errors (funcall (node-listener-closer node))))
  (maphash (lambda (id peer) (declare (ignore id)) (ignore-errors (p:disconnect peer)))
           (node-peers node))
  (clrhash (node-peers node))
  (setf (node-alive-p node) nil)
  (nlog node "stopped")
  node)
