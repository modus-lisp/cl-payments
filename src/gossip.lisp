;;;; src/gossip.lisp
;;;;
;;;; Phase 3 — BOLT #7: the gossip messages and the routing graph.
;;;;
;;;; Three messages describe the network.  `channel_announcement` says a channel
;;;; exists and is anchored to a real funding output; `channel_update` gives one
;;;; DIRECTION's routing policy; `node_announcement` carries a node's metadata.
;;;; Every one of them is signed, and the signatures are the point: gossip
;;;; arrives from strangers, relayed by strangers, so nothing may be believed
;;;; because of who handed it to us.
;;;;
;;;; `channel_announcement` carries FOUR signatures for that reason.  Two prove
;;;; the node keys agree the channel exists; two more prove the corresponding
;;;; BITCOIN keys — the ones in the funding output's 2-of-2 — agree as well.
;;;; Without the bitcoin pair, anyone could announce a channel over someone
;;;; else's UTXO; without the node pair, anyone could announce a channel on
;;;; someone else's behalf.  Both pairs sign the same bytes.
;;;;
;;;; Each message's signature covers "everything after the signatures", hashed
;;;; with double-SHA256.  That offset is fixed per message type and getting it
;;;; wrong produces a verifier that rejects everything, or — much worse — one
;;;; that accepts anything.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md

(defpackage #:cl-payments.gossip
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:f #:cl-payments.features) (#:secp #:secp256k1-fast))
  (:nicknames #:ln-gossip)
  (:export
   ;; short channel ids
   #:scid #:make-scid #:scid-block #:scid-tx #:scid-output
   #:scid->u64 #:u64->scid #:scid-string #:parse-scid-string
   ;; messages
   #:channel-announcement #:parse-channel-announcement
   #:chan-ann-scid #:chan-ann-node-1 #:chan-ann-node-2
   #:chan-ann-bitcoin-1 #:chan-ann-bitcoin-2 #:chan-ann-features #:chan-ann-chain-hash
   #:channel-update #:parse-channel-update
   #:chan-upd-scid #:chan-upd-timestamp #:chan-upd-direction #:chan-upd-disabled-p
   #:chan-upd-cltv-expiry-delta #:chan-upd-htlc-minimum-msat #:chan-upd-htlc-maximum-msat
   #:chan-upd-fee-base-msat #:chan-upd-fee-proportional-millionths
   #:node-announcement #:parse-node-announcement
   #:node-ann-node-id #:node-ann-alias #:node-ann-rgb #:node-ann-timestamp
   #:node-ann-features #:node-ann-addresses
   ;; verification
   #:verify-channel-announcement #:verify-channel-update #:verify-node-announcement
   #:signed-portion #:gossip-error #:verify-gossip-sig
   ;; emitting
   #:sign-gossip #:node-order
   #:channel-announcement-body #:encode-channel-announcement
   #:channel-update-body #:encode-channel-update
   #:node-announcement-body #:encode-node-announcement
   ;; the graph
   #:router #:make-router #:router-channels #:router-nodes
   #:ingest #:router-channel-count #:router-node-count
   #:channel #:channel-scid #:channel-node-1 #:channel-node-2
   #:channel-policy-1 #:channel-policy-2 #:channel-policies
   #:node #:node-id #:node-alias #:node-last-seen
   ;; queries
   #:encode-gossip-timestamp-filter #:encode-query-channel-range
   #:parse-reply-channel-range #:encode-query-short-channel-ids
   #:+msg-channel-announcement+ #:+msg-node-announcement+ #:+msg-channel-update+
   #:+msg-query-channel-range+ #:+msg-reply-channel-range+
   #:+msg-query-short-channel-ids+ #:+msg-gossip-timestamp-filter+))

(in-package #:cl-payments.gossip)

(defconstant +msg-channel-announcement+ 256)
(defconstant +msg-node-announcement+ 257)
(defconstant +msg-channel-update+ 258)
(defconstant +msg-query-short-channel-ids+ 261)
(defconstant +msg-reply-short-channel-ids-end+ 262)
(defconstant +msg-query-channel-range+ 263)
(defconstant +msg-reply-channel-range+ 264)
(defconstant +msg-gossip-timestamp-filter+ 265)

(define-condition gossip-error (error)
  ((detail :initarg :detail :reader gossip-error-detail))
  (:report (lambda (c s) (format s "gossip: ~a" (gossip-error-detail c)))))

;;; ----------------------------------------------------------------------------
;;; Short channel ids
;;;
;;; A channel is named by WHERE ITS FUNDING OUTPUT IS: block height, index of the
;;; transaction within that block, index of the output within that transaction.
;;; Packed into 8 bytes as 24/24/16 bits.  That is what makes a channel
;;; announcement checkable against the chain — the name itself is the pointer.
;;; ----------------------------------------------------------------------------

(defstruct (scid (:constructor make-scid (block tx output)))
  block tx output)

(defun scid->u64 (s)
  (logior (ash (scid-block s) 40) (ash (scid-tx s) 16) (scid-output s)))

(defun u64->scid (n)
  (make-scid (ldb (byte 24 40) n) (ldb (byte 24 16) n) (ldb (byte 16 0) n)))

(defun scid-string (s)
  "The `BLOCKxTXxOUTPUT` form every implementation prints, so our output can be
   diffed directly against `lightning-cli listchannels`."
  (format nil "~dx~dx~d" (scid-block s) (scid-tx s) (scid-output s)))

(defun parse-scid-string (str)
  (let* ((a (position #\x str)) (b (position #\x str :from-end t)))
    (unless (and a b (/= a b)) (error 'gossip-error :detail (format nil "bad scid ~s" str)))
    (make-scid (parse-integer str :end a)
               (parse-integer str :start (1+ a) :end b)
               (parse-integer str :start (1+ b)))))

;;; ----------------------------------------------------------------------------
;;; Signature verification
;;;
;;; Every gossip message is signed over "the entire message following the
;;; signatures", double-SHA256'd.  The offset is fixed per type: one 64-byte
;;; signature for channel_update and node_announcement, four for
;;; channel_announcement.
;;; ----------------------------------------------------------------------------

(defun signed-portion (payload nsigs)
  "The bytes a gossip signature actually covers: everything after NSIGS 64-byte
   signatures.  Note this is the payload WITHOUT the 2-byte message type — the
   type is not signed."
  (subseq payload (* 64 nsigs)))

(defun gossip-hash (payload nsigs)
  (c:sha256 (c:sha256 (signed-portion payload nsigs))))

(defun %verify-sig (sig64 hash pubkey-bytes)
  "Check a 64-byte compact (r ‖ s) signature over HASH by PUBKEY-BYTES."
  (handler-case
      (let ((r (secp:bytes-to-int (subseq sig64 0 32)))
            (s (secp:bytes-to-int (subseq sig64 32 64)))
            (pt (c:parse-pubkey pubkey-bytes)))
        (and (secp:ecdsa-verify pt (c:octets hash) r s) t))
    (error () nil)))

;;; ----------------------------------------------------------------------------
;;; channel_announcement (256)
;;; ----------------------------------------------------------------------------

(defstruct (channel-announcement (:conc-name chan-ann-))
  node-sig-1 node-sig-2 bitcoin-sig-1 bitcoin-sig-2
  features chain-hash scid node-1 node-2 bitcoin-1 bitcoin-2
  raw)

(defun parse-channel-announcement (payload)
  (handler-case
      (let ((r (w:make-reader payload)))
        (let* ((ns1 (w:r-sig r)) (ns2 (w:r-sig r))
               (bs1 (w:r-sig r)) (bs2 (w:r-sig r))
               (features (w:r-varbytes r))
               (chain (w:r-chain-hash r))
               (scid (u64->scid (w:r-u64 r)))
               (n1 (w:r-point r)) (n2 (w:r-point r))
               (b1 (w:r-point r)) (b2 (w:r-point r)))
          (make-channel-announcement
           :node-sig-1 ns1 :node-sig-2 ns2 :bitcoin-sig-1 bs1 :bitcoin-sig-2 bs2
           :features (f:bytes->features features) :chain-hash chain :scid scid
           :node-1 n1 :node-2 n2 :bitcoin-1 b1 :bitcoin-2 b2
           :raw (c:octets payload))))
    (gossip-error (e) (error e))
    (error (e) (error 'gossip-error :detail (format nil "bad channel_announcement: ~a" e)))))

(defun verify-channel-announcement (ann)
  "All FOUR signatures must check out.  Two node keys agree the channel exists;
   two bitcoin keys — the ones in the funding output's 2-of-2 — agree too.  Drop
   either pair and the announcement becomes forgeable: without the bitcoin
   signatures anyone could announce a channel over someone else's UTXO, and
   without the node signatures anyone could announce on someone else's behalf."
  (let ((h (gossip-hash (chan-ann-raw ann) 4)))
    (and (%verify-sig (chan-ann-node-sig-1 ann)    h (chan-ann-node-1 ann))
         (%verify-sig (chan-ann-node-sig-2 ann)    h (chan-ann-node-2 ann))
         (%verify-sig (chan-ann-bitcoin-sig-1 ann) h (chan-ann-bitcoin-1 ann))
         (%verify-sig (chan-ann-bitcoin-sig-2 ann) h (chan-ann-bitcoin-2 ann)))))

;;; ----------------------------------------------------------------------------
;;; channel_update (258)
;;; ----------------------------------------------------------------------------

(defstruct (channel-update (:conc-name chan-upd-))
  signature chain-hash scid timestamp
  message-flags channel-flags
  cltv-expiry-delta htlc-minimum-msat fee-base-msat fee-proportional-millionths
  htlc-maximum-msat
  raw)

(defun chan-upd-direction (u)
  "0 if this update is from node_1, 1 if from node_2.  Channel policy is
   per-direction — the two ends charge independently — so this bit decides which
   half of the channel the update applies to."
  (logand (chan-upd-channel-flags u) 1))

(defun chan-upd-disabled-p (u)
  (logtest (chan-upd-channel-flags u) 2))

(defun parse-channel-update (payload)
  (handler-case
      (let* ((r (w:make-reader payload))
             (sig (w:r-sig r))
             (chain (w:r-chain-hash r))
             (scid (u64->scid (w:r-u64 r)))
             (ts (w:r-u32 r))
             (mflags (w:r-u8 r))
             (cflags (w:r-u8 r))
             (cltv (w:r-u16 r))
             (hmin (w:r-u64 r))
             (base (w:r-u32 r))
             (prop (w:r-u32 r))
             ;; htlc_maximum_msat is present only when message_flags bit 0 is
             ;; set.  Reading it unconditionally works on every modern peer and
             ;; then desynchronises on an old one.
             (hmax (when (logtest mflags 1) (w:r-u64 r))))
        (make-channel-update
         :signature sig :chain-hash chain :scid scid :timestamp ts
         :message-flags mflags :channel-flags cflags
         :cltv-expiry-delta cltv :htlc-minimum-msat hmin
         :fee-base-msat base :fee-proportional-millionths prop
         :htlc-maximum-msat hmax
         :raw (c:octets payload)))
    (error (e) (error 'gossip-error :detail (format nil "bad channel_update: ~a" e)))))

(defun verify-channel-update (upd node-id)
  "NODE-ID is the announcing end — node_1 or node_2 of the channel, chosen by
   the direction bit.  The caller supplies it because a channel_update alone does
   not say who signed it; that is only knowable from the channel_announcement."
  (%verify-sig (chan-upd-signature upd) (gossip-hash (chan-upd-raw upd) 1) node-id))

;;; ----------------------------------------------------------------------------
;;; node_announcement (257)
;;; ----------------------------------------------------------------------------

(defstruct (node-announcement (:conc-name node-ann-))
  signature features timestamp node-id rgb alias addresses raw)

(defun parse-node-announcement (payload)
  (handler-case
      (let* ((r (w:make-reader payload))
             (sig (w:r-sig r))
             (features (w:r-varbytes r))
             (ts (w:r-u32 r))
             (id (w:r-point r))
             (rgb (w:r-bytes r 3))
             (alias (w:r-bytes r 32))
             (addrs (w:r-varbytes r)))
        (make-node-announcement
         :signature sig :features (f:bytes->features features) :timestamp ts
         :node-id id :rgb rgb
         ;; The alias is a fixed 32-byte field, NUL-padded, and is
         ;; attacker-controlled free text.  Cut at the first NUL FIRST — mapping
         ;; bytes to printable characters before trimming turns the padding into
         ;; 28 dots — then keep only printable ASCII, so a peer cannot write
         ;; control codes into whatever renders this.
         :alias (let* ((end (or (position 0 alias) (length alias)))
                       (text (subseq alias 0 end)))
                  (map 'string (lambda (b) (if (<= 32 b 126) (code-char b) #\.)) text))
         :addresses addrs
         :raw (c:octets payload)))
    (error (e) (error 'gossip-error :detail (format nil "bad node_announcement: ~a" e)))))

(defun verify-node-announcement (ann)
  (%verify-sig (node-ann-signature ann) (gossip-hash (node-ann-raw ann) 1)
               (node-ann-node-id ann)))

;;; ----------------------------------------------------------------------------
;;; Emitting gossip
;;;
;;; Everything above this point parses and verifies what other nodes say.  To be
;;; ROUTABLE rather than merely well-informed we have to say it ourselves, and
;;; the asymmetry matters: a parser that is too lenient accepts junk, but an
;;; encoder that is too lenient gets us ignored by the entire network with no
;;; error message.  Nobody replies "your announcement was malformed"; the channel
;;; simply never appears in anyone's graph.
;;;
;;; Each message is built in two pieces — a BODY, which is what the signature
;;; covers, and the full payload, which is the signatures followed by that exact
;;; body.  Serialising twice and hoping the two agree is how you produce a
;;; signature over bytes you did not send.
;;; ----------------------------------------------------------------------------

(defun verify-gossip-sig (sig64 body pubkey-bytes)
  "Check a gossip signature against the BODY it covers, rather than against a
   pre-computed hash.  Callers that hold a body they built themselves should use
   this: hashing it here is one fewer place to get the double-SHA256 wrong."
  (%verify-sig sig64 (c:sha256 (c:sha256 body)) pubkey-bytes))

(defun sign-gossip (privkey body)
  "A 64-byte compact (r ‖ s) signature over the double-SHA256 of BODY."
  (let ((hash (c:sha256 (c:sha256 body))))
    (multiple-value-bind (r s) (secp:ecdsa-sign-raw privkey (c:octets hash))
      (c:bytes (secp:int-to-bytes32 r) (secp:int-to-bytes32 s)))))

(defun node-order (point-a point-b)
  "BOLT #7 orders the two ends of a channel by comparing their compressed node
   ids as byte strings; the lesser is node_1.  Returns (values node-1 node-2
   a-is-node-1-p).

   This is not cosmetic.  The direction bit in channel_update is defined against
   this ordering, so getting it backwards advertises our fee policy as if it were
   the other end's — and every route computed over it is wrong."
  (let ((a (c:octets point-a)) (b (c:octets point-b)))
    (let ((a<b (loop for x across a for y across b
                     when (/= x y) return (< x y)
                     finally (return t))))
      (if a<b (values a b t) (values b a nil)))))

(defun channel-announcement-body (&key features chain-hash scid
                                       node-1 node-2 bitcoin-1 bitcoin-2)
  "The signed portion of channel_announcement.  NODE-1/NODE-2 must already be in
   BOLT #7 order, with BITCOIN-1 being node_1's funding pubkey."
  (let ((wr (w:make-writer)))
    (w:w-varbytes wr (f:features->bytes (or features 0)))
    (w:w-hash wr chain-hash)
    (w:w-u64 wr (scid->u64 scid))
    (w:w-point wr node-1) (w:w-point wr node-2)
    (w:w-point wr bitcoin-1) (w:w-point wr bitcoin-2)
    (w:writer-bytes wr)))

(defun encode-channel-announcement (body &key node-sig-1 node-sig-2
                                              bitcoin-sig-1 bitcoin-sig-2)
  "The four signatures, then BODY verbatim."
  (let ((wr (w:make-writer)))
    (w:w-sig wr node-sig-1) (w:w-sig wr node-sig-2)
    (w:w-sig wr bitcoin-sig-1) (w:w-sig wr bitcoin-sig-2)
    (w:w-bytes wr body)
    (w:writer-bytes wr)))

(defun channel-update-body (&key chain-hash scid timestamp
                                 (message-flags 1) (channel-flags 0)
                                 (cltv-expiry-delta 40) (htlc-minimum-msat 1000)
                                 (fee-base-msat 1000)
                                 (fee-proportional-millionths 1)
                                 htlc-maximum-msat)
  "The signed portion of channel_update — our fee and timelock policy for ONE
   direction of the channel.

   MESSAGE-FLAGS bit 0 declares that htlc_maximum_msat follows.  Modern peers
   require it: Core Lightning rejects an update without it outright, so it
   defaults on and HTLC-MAXIMUM-MSAT must be supplied."
  (when (and (logtest message-flags 1) (null htlc-maximum-msat))
    (error 'gossip-error :detail "message_flags bit 0 set but no htlc_maximum_msat"))
  (let ((wr (w:make-writer)))
    (w:w-hash wr chain-hash)
    (w:w-u64 wr (scid->u64 scid))
    (w:w-u32 wr timestamp)
    (w:w-u8 wr message-flags)
    (w:w-u8 wr channel-flags)
    (w:w-u16 wr cltv-expiry-delta)
    (w:w-u64 wr htlc-minimum-msat)
    (w:w-u32 wr fee-base-msat)
    (w:w-u32 wr fee-proportional-millionths)
    (when (logtest message-flags 1) (w:w-u64 wr htlc-maximum-msat))
    (w:writer-bytes wr)))

(defun encode-channel-update (privkey body)
  (let ((wr (w:make-writer)))
    (w:w-sig wr (sign-gossip privkey body))
    (w:w-bytes wr body)
    (w:writer-bytes wr)))

(defun node-announcement-body (&key features timestamp node-id
                                    (rgb (c:zeros 3)) (alias "") (addresses #()))
  "The signed portion of node_announcement.  ALIAS is padded to exactly 32 bytes
   and TRUNCATED there — the field is fixed width, and an over-long alias would
   otherwise shift every following field and produce a message that parses as
   garbage rather than one that is rejected."
  (let ((wr (w:make-writer))
        (alias-bytes (let ((buf (c:zeros 32))
                           (src (c:ascii->bytes alias)))
                       (replace buf src :end2 (min 32 (length src)))
                       buf)))
    (w:w-varbytes wr (f:features->bytes (or features 0)))
    (w:w-u32 wr timestamp)
    (w:w-point wr node-id)
    (w:w-bytes wr (c:octets rgb))
    (w:w-bytes wr alias-bytes)
    (w:w-varbytes wr (c:octets addresses))
    (w:writer-bytes wr)))

(defun encode-node-announcement (privkey body)
  (let ((wr (w:make-writer)))
    (w:w-sig wr (sign-gossip privkey body))
    (w:w-bytes wr body)
    (w:writer-bytes wr)))

;;; ----------------------------------------------------------------------------
;;; The routing graph
;;; ----------------------------------------------------------------------------

(defstruct (channel (:conc-name channel-))
  scid node-1 node-2 features
  policy-1 policy-2)          ; the latest channel_update per direction

(defstruct (node (:conc-name node-))
  id alias rgb features addresses last-seen)

(defstruct router
  (channels (make-hash-table :test 'eql))    ; scid-as-u64 -> channel
  (nodes (make-hash-table :test 'equalp))    ; node-id bytes -> node
  (rejected 0))

(defun router-channel-count (r) (hash-table-count (router-channels r)))
(defun router-node-count (r) (hash-table-count (router-nodes r)))

(defun channel-policies (ch)
  (remove nil (list (channel-policy-1 ch) (channel-policy-2 ch))))

(defgeneric ingest-message (router type payload)
  (:documentation "Fold one gossip message into ROUTER.  Returns :accepted,
   :rejected (signature or structure bad) or :ignored (not gossip)."))

(defmethod ingest-message ((r router) type payload)
  (case type
    (#.+msg-channel-announcement+
     (let ((ann (handler-case (parse-channel-announcement payload)
                  (gossip-error () nil))))
       (cond ((null ann) (incf (router-rejected r)) :rejected)
             ;; UNSIGNED gossip is not gossip.  A channel we cannot verify is a
             ;; channel someone made up, and routing through it loses money.
             ((not (verify-channel-announcement ann))
              (incf (router-rejected r)) :rejected)
             (t (setf (gethash (scid->u64 (chan-ann-scid ann)) (router-channels r))
                      (or (gethash (scid->u64 (chan-ann-scid ann)) (router-channels r))
                          (make-channel :scid (chan-ann-scid ann)
                                        :node-1 (chan-ann-node-1 ann)
                                        :node-2 (chan-ann-node-2 ann)
                                        :features (chan-ann-features ann))))
                :accepted))))
    (#.+msg-channel-update+
     (let ((upd (handler-case (parse-channel-update payload) (gossip-error () nil))))
       (cond
         ((null upd) (incf (router-rejected r)) :rejected)
         (t
          (let ((ch (gethash (scid->u64 (chan-upd-scid upd)) (router-channels r))))
            (cond
              ;; An update for a channel we have never seen announced cannot be
              ;; verified — we don't know whose key should have signed it — so it
              ;; is dropped rather than stored on trust.
              ((null ch) (incf (router-rejected r)) :rejected)
              (t
               (let* ((dir (chan-upd-direction upd))
                      (signer (if (zerop dir) (channel-node-1 ch) (channel-node-2 ch))))
                 (cond
                   ((not (verify-channel-update upd signer))
                    (incf (router-rejected r)) :rejected)
                   (t
                    ;; Keep the newest per direction: gossip is replayed
                    ;; endlessly and an old update must not overwrite a new one.
                    (let ((current (if (zerop dir) (channel-policy-1 ch) (channel-policy-2 ch))))
                      (when (or (null current)
                                (> (chan-upd-timestamp upd) (chan-upd-timestamp current)))
                        (if (zerop dir)
                            (setf (channel-policy-1 ch) upd)
                            (setf (channel-policy-2 ch) upd))))
                    :accepted))))))))))
    (#.+msg-node-announcement+
     (let ((ann (handler-case (parse-node-announcement payload) (gossip-error () nil))))
       (cond ((null ann) (incf (router-rejected r)) :rejected)
             ((not (verify-node-announcement ann)) (incf (router-rejected r)) :rejected)
             (t (let ((existing (gethash (node-ann-node-id ann) (router-nodes r))))
                  (when (or (null existing)
                            (> (node-ann-timestamp ann) (node-last-seen existing)))
                    (setf (gethash (node-ann-node-id ann) (router-nodes r))
                          (make-node :id (node-ann-node-id ann)
                                     :alias (node-ann-alias ann)
                                     :rgb (node-ann-rgb ann)
                                     :features (node-ann-features ann)
                                     :addresses (node-ann-addresses ann)
                                     :last-seen (node-ann-timestamp ann)))))
                :accepted))))
    (t :ignored)))

(defun ingest (router type payload)
  (ingest-message router type payload))

;;; ----------------------------------------------------------------------------
;;; Queries
;;;
;;; The ordering rule below is not cosmetic.  LND enforces STRICTLY INCREASING
;;; short channel ids in a channel-range reply and disconnects a peer whose reply
;;; violates it — it does this to Core Lightning on our own devnet.  Anything we
;;; emit here has to be sorted, and anything we accept should be checked.
;;; ----------------------------------------------------------------------------

(defun encode-gossip-timestamp-filter (chain-hash &key (first-timestamp 0)
                                                       (timestamp-range #xffffffff))
  "Ask the peer to stream gossip.  The default range means `everything you have`;
   a peer that has already sent us its graph will otherwise forward only NEW
   messages, and a quiet network then looks like a broken implementation."
  (let ((wr (w:make-writer)))
    (w:w-hash wr chain-hash)
    (w:w-u32 wr first-timestamp)
    (w:w-u32 wr timestamp-range)
    (w:writer-bytes wr)))

(defun encode-query-channel-range (chain-hash first-block number-of-blocks)
  (let ((wr (w:make-writer)))
    (w:w-hash wr chain-hash)
    (w:w-u32 wr first-block)
    (w:w-u32 wr number-of-blocks)
    (w:writer-bytes wr)))

(defun encode-query-short-channel-ids (chain-hash scids)
  "SCIDs are sorted and de-duplicated before encoding — see the note above; an
   unsorted list is what gets a peer to hang up on you."
  (let* ((sorted (sort (remove-duplicates (mapcar #'scid->u64 scids)) #'<))
         (ids (w:make-writer)))
    (w:w-u8 ids 0)                      ; encoding_type 0 = uncompressed
    (dolist (n sorted) (w:w-u64 ids n))
    (let ((wr (w:make-writer)))
      (w:w-hash wr chain-hash)
      (w:w-varbytes wr (w:writer-bytes ids))
      (w:writer-bytes wr))))

(defun parse-reply-channel-range (payload)
  "Returns (values first-block number-of-blocks complete scids).  Signals if the
   scids are not strictly increasing: that is a protocol violation, and silently
   accepting it would hide the very bug LND drops peers over."
  (handler-case
      (let* ((r (w:make-reader payload))
             (chain (w:r-chain-hash r))
             (first-block (w:r-u32 r))
             (n-blocks (w:r-u32 r))
             (complete (w:r-u8 r))
             (encoded (w:r-varbytes r)))
        (declare (ignore chain))
        (let ((er (w:make-reader encoded)))
          (let ((encoding (w:r-u8 er))
                (scids '())
                (prev nil))
            (unless (zerop encoding)
              (error 'gossip-error
                     :detail (format nil "unsupported scid encoding ~d (zlib not implemented)"
                                     encoding)))
            (loop until (w:reader-eof-p er) do
              (let ((n (w:r-u64 er)))
                (when (and prev (<= n prev))
                  (error 'gossip-error
                         :detail (format nil "short_channel_ids not strictly increasing at ~a"
                                         (scid-string (u64->scid n)))))
                (setf prev n)
                (push (u64->scid n) scids)))
            (values first-block n-blocks (plusp complete) (nreverse scids)))))
    (gossip-error (e) (error e))
    (error (e) (error 'gossip-error :detail (format nil "bad reply_channel_range: ~a" e)))))
