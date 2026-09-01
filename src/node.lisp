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
                    (#:f #:cl-payments.features)
                    (#:tr #:cl-transport) (#:bt #:bordeaux-threads)
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
   #:node-error))

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
  scid remote-funding-pubkey remote-node-sig remote-bitcoin-sig)

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
                                (let ((k (sc-remote-bitcoin-sig sc))) (and k (%hex k))))
                          s)
                   (terpri s))
                 (node-channels node))))
    (rename-file tmp path)
    path))

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
                              (and v (%unhex v))))))
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
        (let ((ours (u:make-channel-reestablish
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
                         (if sc (sc-local-commitment-number sc) 0))))))
          (ignore-errors
           (p:send-message peer (u:encode-channel-reestablish ours) nil)))))))

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

(defun install-handlers (node peer)
  (p:on peer u:+msg-channel-reestablish+
        (lambda (pr payload) (handle-reestablish node pr payload)))
  (p:on peer +msg-announcement-signatures+
        (lambda (pr payload) (handle-announcement-signatures node pr payload)))
  (p:on peer ch:+msg-channel-ready+
        (lambda (pr payload) (declare (ignore pr))
          (handler-case
              (let ((cr (ch:parse-channel-ready payload)))
                (nlog node "channel_ready for ~a"
                      (subseq (%hex (ch:cr-channel-id cr)) 0 16)))
            (error () nil))))
  ;; Gossip is accepted and ignored for now; the point of logging it is that a
  ;; silent daemon is indistinguishable from a wedged one.
  (p:on peer gs:+msg-channel-announcement+ (lambda (pr pl) (declare (ignore pr pl)) nil))
  (p:on peer gs:+msg-channel-update+ (lambda (pr pl) (declare (ignore pr pl)) nil)))

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
