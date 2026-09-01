;;;; src/wire.lisp
;;;;
;;;; Phase 0 — BOLT #1 wire primitives: readers, writers, BigSize, TLV streams,
;;;; and the message envelope.
;;;;
;;;; Every higher layer encodes and decodes through this file, exactly as
;;;; cl-consensus's wire.lisp underpins the Bitcoin node.  Two things differ
;;;; sharply from Bitcoin's wire format and are worth internalizing before
;;;; reading anything else:
;;;;
;;;;   1. Lightning is BIG-endian.  Bitcoin is little-endian almost everywhere;
;;;;      here every integer — message types, amounts, lengths — is big-endian.
;;;;   2. Lengths use BigSize, not Bitcoin's CompactSize.  Same 1/3/5/9-byte
;;;;      shape and the same 0xfd/0xfe/0xff markers, but the payload is
;;;;      big-endian, and non-minimal encodings are a protocol violation.
;;;;
;;;; Nothing here touches a socket: a WRITER accumulates into a byte vector, a
;;;; READER walks one with a cursor.  The transport layer (BOLT #8) is what turns
;;;; those byte vectors into framed, encrypted packets.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/01-messaging.md

(defpackage #:cl-payments.wire
  (:use #:cl)
  (:nicknames #:ln-wire)
  (:local-nicknames (#:c #:cl-payments.crypto))
  (:export
   ;; writer
   #:make-writer #:writer-bytes #:writer-length
   #:w-u8 #:w-u16 #:w-u32 #:w-u64 #:w-bytes #:w-bigsize #:w-tu
   #:w-point #:w-hash #:w-sig #:w-chain-hash #:w-varbytes #:w-bool
   ;; reader
   #:make-reader #:reader-pos #:reader-remaining #:reader-eof-p
   #:r-u8 #:r-u16 #:r-u32 #:r-u64 #:r-bytes #:r-bigsize #:r-tu
   #:r-point #:r-hash #:r-sig #:r-chain-hash #:r-varbytes #:r-bool #:r-rest
   ;; TLV
   #:tlv-record #:make-tlv-record #:tlv-record-type #:tlv-record-value
   #:w-tlv-stream #:r-tlv-stream #:tlv-get
   ;; message envelope
   #:encode-message #:decode-message #:+max-message-size+
   ;; conditions
   #:wire-error #:truncated-error #:non-minimal-error #:tlv-order-error
   ;; network params
   #:*network* #:select-network #:net-name #:net-chain-hash #:net-port
   #:chain-hash))

(in-package #:cl-payments.wire)

;;; ----------------------------------------------------------------------------
;;; Conditions
;;;
;;; Everything a remote peer sends is untrusted, so decode failures are a normal
;;; control-flow event (the peer gets dropped), not a bug.  They get their own
;;; condition type so the peer loop can catch WIRE-ERROR and nothing else.
;;; ----------------------------------------------------------------------------

(define-condition wire-error (error) ())

(define-condition truncated-error (wire-error)
  ((want :initarg :want :reader truncated-want)
   (have :initarg :have :reader truncated-have))
  (:report (lambda (c s) (format s "truncated: wanted ~d byte~:p, ~d remaining"
                                 (truncated-want c) (truncated-have c)))))

(define-condition non-minimal-error (wire-error)
  ((value :initarg :value :reader non-minimal-value))
  (:report (lambda (c s) (format s "non-minimal BigSize encoding of ~d"
                                 (non-minimal-value c)))))

(define-condition tlv-order-error (wire-error)
  ((type :initarg :type :reader tlv-order-type))
  (:report (lambda (c s) (format s "TLV record type ~d out of order or duplicated"
                                 (tlv-order-type c)))))

;;; ----------------------------------------------------------------------------
;;; Writer
;;; ----------------------------------------------------------------------------

(defstruct (writer (:constructor %make-writer))
  (buf (make-array 256 :element-type '(unsigned-byte 8)
                       :adjustable t :fill-pointer 0)))

(defun make-writer () (%make-writer))

(defun writer-bytes (w)
  (c:octets (writer-buf w)))

(defun writer-length (w) (fill-pointer (writer-buf w)))

(defun w-u8 (w n)
  (vector-push-extend (logand n #xff) (writer-buf w))
  w)

(defun %w-be (w n nbytes)
  "Append N as an NBYTES big-endian integer."
  (loop for i from (1- nbytes) downto 0
        do (vector-push-extend (ldb (byte 8 (* 8 i)) n) (writer-buf w)))
  w)

(defun w-u16 (w n) (%w-be w n 2))
(defun w-u32 (w n) (%w-be w n 4))
(defun w-u64 (w n) (%w-be w n 8))

(defun w-bool (w flag) (w-u8 w (if flag 1 0)))

(defun w-bytes (w seq)
  (loop for b across seq do (vector-push-extend b (writer-buf w)))
  w)

(defun w-bigsize (w n)
  "BOLT #1 BigSize: minimally encoded, big-endian payload."
  (cond ((< n #xfd) (w-u8 w n))
        ((<= n #xffff) (w-u8 w #xfd) (w-u16 w n))
        ((<= n #xffffffff) (w-u8 w #xfe) (w-u32 w n))
        (t (w-u8 w #xff) (w-u64 w n)))
  w)

(defun w-tu (w n nbytes)
  "Truncated integer (`tu16`/`tu32`/`tu64`): a big-endian integer with leading
   zero bytes stripped.  Used inside TLV values, where the record length already
   carries the size.  Zero encodes as the empty string."
  (let ((full (let ((tmp (make-writer))) (%w-be tmp n nbytes) (writer-bytes tmp))))
    (w-bytes w (subseq full (or (position-if #'plusp full) nbytes)))))

(defun w-point (w point-or-bytes)
  "A 33-byte compressed public key.  Accepts either a point or the bytes."
  (w-bytes w (if (consp point-or-bytes)
                 (c:compressed-pubkey point-or-bytes)
                 point-or-bytes)))

(defun w-hash (w h)
  (assert (= (length h) 32) () "hash must be 32 bytes")
  (w-bytes w h))

(defun w-sig (w s)
  "A 64-byte compact signature (r ‖ s).  Lightning never puts DER on the wire."
  (assert (= (length s) 64) () "signature must be 64 bytes")
  (w-bytes w s))

(defun w-chain-hash (w h) (w-hash w h))

(defun w-varbytes (w seq)
  "A byte field with a u16 big-endian length prefix (BOLT #1's `u16`-counted
   arrays, e.g. the `features` field and `error.data`)."
  (w-u16 w (length seq))
  (w-bytes w seq))

;;; ----------------------------------------------------------------------------
;;; Reader
;;; ----------------------------------------------------------------------------

(defstruct (reader (:constructor %make-reader))
  buf (pos 0) (end 0))

(defun make-reader (bytes &key (start 0) end)
  (%make-reader :buf (c:octets bytes) :pos start :end (or end (length bytes))))

(defun reader-remaining (r) (- (reader-end r) (reader-pos r)))
(defun reader-eof-p (r) (<= (reader-remaining r) 0))

(defun %need (r n)
  (when (< (reader-remaining r) n)
    (error 'truncated-error :want n :have (reader-remaining r))))

(defun r-u8 (r)
  (%need r 1)
  (prog1 (aref (reader-buf r) (reader-pos r))
    (incf (reader-pos r))))

(defun %r-be (r nbytes)
  (%need r nbytes)
  (let ((n 0))
    (loop for i from 0 below nbytes
          do (setf n (logior (ash n 8) (aref (reader-buf r) (+ (reader-pos r) i)))))
    (incf (reader-pos r) nbytes)
    n))

(defun r-u16 (r) (%r-be r 2))
(defun r-u32 (r) (%r-be r 4))
(defun r-u64 (r) (%r-be r 8))

(defun r-bool (r) (plusp (r-u8 r)))

(defun r-bytes (r n)
  (%need r n)
  (prog1 (subseq (reader-buf r) (reader-pos r) (+ (reader-pos r) n))
    (incf (reader-pos r) n)))

(defun r-rest (r) (r-bytes r (reader-remaining r)))

(defun r-bigsize (r)
  "BOLT #1 BigSize.  Rejects non-minimal encodings — the spec requires the
   shortest form, and accepting a long one would let a peer produce two distinct
   byte strings with the same meaning (a signature-malleability foothold in the
   gossip messages that get hashed)."
  (let ((first (r-u8 r)))
    (cond ((< first #xfd) first)
          ((= first #xfd)
           (let ((n (r-u16 r)))
             (when (< n #xfd) (error 'non-minimal-error :value n))
             n))
          ((= first #xfe)
           (let ((n (r-u32 r)))
             (when (<= n #xffff) (error 'non-minimal-error :value n))
             n))
          (t
           (let ((n (r-u64 r)))
             (when (<= n #xffffffff) (error 'non-minimal-error :value n))
             n)))))

(defun r-tu (r nbytes)
  "Read a truncated integer from the REST of this reader (see W-TU).  Rejects
   leading zero bytes, which would be a non-minimal encoding."
  (let ((n (reader-remaining r)))
    (when (> n nbytes)
      (error 'truncated-error :want nbytes :have n))
    (let ((b (r-bytes r n)))
      (when (and (plusp (length b)) (zerop (aref b 0)))
        (error 'non-minimal-error :value 0))
      (reduce (lambda (acc byte) (logior (ash acc 8) byte)) b :initial-value 0))))

(defun r-point (r) (r-bytes r 33))
(defun r-hash (r) (r-bytes r 32))
(defun r-sig (r) (r-bytes r 64))
(defun r-chain-hash (r) (r-bytes r 32))

(defun r-varbytes (r) (r-bytes r (r-u16 r)))

;;; ----------------------------------------------------------------------------
;;; TLV streams
;;;
;;; A TLV stream is how BOLT #1 makes messages extensible: a sequence of
;;; (BigSize type, BigSize length, value) records, strictly ascending by type
;;; with no duplicates.  The ordering rule is not cosmetic — several TLV streams
;;; are signed or hashed, so a canonical byte encoding is what makes them
;;; comparable.
;;;
;;; "It's ok to be odd": an unknown ODD type is skipped (forward compatibility),
;;; an unknown EVEN type is a fatal error (the sender required something we don't
;;; understand).  R-TLV-STREAM returns every record and leaves that judgment to
;;; the caller, which alone knows which types it understands — TLV-GET and
;;; CHECK-UNKNOWN-EVEN below are the helpers for it.
;;; ----------------------------------------------------------------------------

(defstruct tlv-record type value)

(defun w-tlv-stream (w records)
  "Write RECORDS as a TLV stream, sorted by type.  Signals on duplicates rather
   than silently emitting a stream no conformant peer will accept."
  (let ((sorted (sort (copy-list records) #'< :key #'tlv-record-type)))
    (loop for (rec next) on sorted
          do (when (and next (= (tlv-record-type rec) (tlv-record-type next)))
               (error 'tlv-order-error :type (tlv-record-type rec)))
             (w-bigsize w (tlv-record-type rec))
             (w-bigsize w (length (tlv-record-value rec)))
             (w-bytes w (tlv-record-value rec)))
    w))

(defun r-tlv-stream (r)
  "Read a TLV stream from R until it is exhausted.  Enforces strictly ascending
   types and that each record's length stays inside the stream."
  (let ((records '())
        (prev nil))
    (loop until (reader-eof-p r)
          do (let ((type (r-bigsize r)))
               (when (and prev (<= type prev))
                 (error 'tlv-order-error :type type))
               (setf prev type)
               (let ((len (r-bigsize r)))
                 (push (make-tlv-record :type type :value (r-bytes r len))
                       records))))
    (nreverse records)))

(defun tlv-get (records type)
  "The value of the record with TYPE, or NIL."
  (let ((rec (find type records :key #'tlv-record-type)))
    (and rec (tlv-record-value rec))))

;;; ----------------------------------------------------------------------------
;;; Message envelope
;;;
;;; BOLT #1: a 2-byte big-endian type followed by the payload.  There is no
;;; length prefix and no checksum here — BOLT #8's transport frames each message
;;; with an encrypted length and authenticates it, so this layer sees exactly one
;;; whole message at a time.
;;; ----------------------------------------------------------------------------

(defconstant +max-message-size+ 65535
  "The largest payload BOLT #8 can frame — its length prefix is a u16.")

(defun encode-message (type payload)
  (let ((w (make-writer)))
    (w-u16 w type)
    (w-bytes w payload)
    (writer-bytes w)))

(defun decode-message (bytes)
  "Split a decrypted message into (values type payload)."
  (let ((r (make-reader bytes)))
    (values (r-u16 r) (r-rest r))))

;;; ----------------------------------------------------------------------------
;;; Network parameters
;;;
;;; Lightning identifies a chain by its genesis block hash rather than by a magic
;;; number.  These are the internal (little-endian) hashes, matching what
;;; cl-consensus's chain layer holds — the same byte order that goes on the wire.
;;; ----------------------------------------------------------------------------

(defstruct net name chain-hash port)

(defun %genesis (display-hex)
  "Genesis hashes are quoted big-endian by convention; the wire wants internal
   byte order."
  (reverse (c:hex->bytes display-hex)))

(defparameter *networks*
  (list
   (make-net :name :mainnet :port 9735
             :chain-hash (%genesis "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"))
   (make-net :name :testnet :port 9735
             :chain-hash (%genesis "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"))
   (make-net :name :signet :port 39735
             :chain-hash (%genesis "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"))
   (make-net :name :regtest :port 19846
             :chain-hash (%genesis "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"))))

(defparameter *network* (first *networks*))

(defun select-network (name)
  (let ((n (find name *networks* :key #'net-name)))
    (unless n (error "unknown network ~s" name))
    (setf *network* n)))

(defun chain-hash () (net-chain-hash *network*))
