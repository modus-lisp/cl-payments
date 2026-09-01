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
   #:stored-channel #:sc-channel-id #:sc-peer-id #:sc-funding-txid
   #:sc-funding-index #:sc-capacity-sat #:sc-announced-p
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
  (announced-p nil))

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
                                :announced-p (sc-announced-p sc))
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
                            :announced-p (getf form :announced-p))))
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

(defun handle-announcement-signatures (node peer payload)
  "`announcement_signatures` is the peer offering to make the channel public.

   Receiving it at all is the thing a script could never do: it arrives once the
   funding is buried, to a CONNECTED peer.  We record that the channel is
   announceable; producing our own half needs the node and bitcoin key signatures
   over the channel announcement, which is Phase 4f."
  (declare (ignore peer))
  (handler-case
      (let* ((r (w:make-reader payload))
             (cid (w:r-bytes r 32))
             (scid (gs:u64->scid (w:r-u64 r))))
        (let ((sc (gethash (%hex cid) (node-channels node))))
          (when sc (setf (sc-announced-p sc) t) (save-channels node))
          (nlog node "announcement_signatures for ~a (scid ~a) — channel is announceable"
                (subseq (%hex cid) 0 16) (gs:scid-string scid))))
    (error (e) (nlog node "bad announcement_signatures: ~a" e))))

(defun install-handlers (node peer)
  (p:on peer u:+msg-channel-reestablish+
        (lambda (pr payload) (handle-reestablish node pr payload)))
  (p:on peer 259
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
