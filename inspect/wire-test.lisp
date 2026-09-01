;;;; inspect/wire-test.lisp
;;;;
;;;; Gate 2 — BOLT #1 wire primitives, against the spec's vectors.
;;;;
;;;; BigSize looks like Bitcoin's CompactSize and is not: the payload is
;;;; big-endian, and non-minimal encodings must be REJECTED.  That rejection is
;;;; not pedantry — several gossip messages are hashed and signed, so two byte
;;;; strings that decode to the same values would be a malleability foothold.
;;;; Half the checks here are therefore negative.
;;;;
;;;; Vectors: https://github.com/lightning/bolts/blob/master/01-messaging.md

(in-package #:cl-payments.test)

(defun %bigsize-bytes (n)
  (let ((wr (w:make-writer))) (w:w-bigsize wr n) (w:writer-bytes wr)))

(defun %read-bigsize (hex)
  (w:r-bigsize (w:make-reader (hx hex))))

(defun test-bigsize ()
  (with-gate ("BOLT #1 — BigSize encoding")
    (dolist (case '((0                    . "00")
                    (252                  . "fc")
                    (253                  . "fd00fd")
                    (65535                . "fdffff")
                    (65536                . "fe00010000")
                    (4294967295           . "feffffffff")
                    (4294967296           . "ff0000000100000000")
                    (18446744073709551615 . "ffffffffffffffffff")))
      (destructuring-bind (value . bytes) case
        (check-bytes (format nil "encode ~d" value) (%bigsize-bytes value) (hx bytes))
        (check-equal (format nil "decode ~a" bytes) (%read-bigsize bytes) value)))))

(defun test-bigsize-rejects ()
  (with-gate ("BOLT #1 — BigSize rejects non-canonical / truncated")
    ;; A value that fits in a shorter form must not be accepted in a longer one.
    (check-signals "two-byte not canonical"   w:non-minimal-error (%read-bigsize "fd00fc"))
    (check-signals "four-byte not canonical"  w:non-minimal-error (%read-bigsize "fe0000ffff"))
    (check-signals "eight-byte not canonical" w:non-minimal-error (%read-bigsize "ff00000000ffffffff"))
    (check-signals "two-byte short read"      w:truncated-error   (%read-bigsize "fd00"))
    (check-signals "four-byte short read"     w:truncated-error   (%read-bigsize "fe0000"))
    (check-signals "eight-byte short read"    w:truncated-error   (%read-bigsize "ff00000000000000"))
    (check-signals "empty input"              w:truncated-error   (%read-bigsize ""))))

(defun test-endianness ()
  (with-gate ("BOLT #1 — big-endian integers")
    ;; Lightning is big-endian throughout; Bitcoin is little-endian almost
    ;; everywhere.  Mixing them up is the single easiest mistake to make when
    ;; porting habits from cl-consensus.
    (let ((wr (w:make-writer)))
      (w:w-u16 wr #x0102) (w:w-u32 wr #x01020304) (w:w-u64 wr #x0102030405060708)
      (check-bytes "u16 ‖ u32 ‖ u64" (w:writer-bytes wr)
                   (hx "0102010203040102030405060708")))
    (let ((r (w:make-reader (hx "0102010203040102030405060708"))))
      (check-equal "r-u16" (w:r-u16 r) #x0102)
      (check-equal "r-u32" (w:r-u32 r) #x01020304)
      (check-equal "r-u64" (w:r-u64 r) #x0102030405060708))))

(defun %tu-bytes (n width)
  (let ((wr (w:make-writer))) (w:w-tu wr n width) (w:writer-bytes wr)))

(defun test-truncated-integers ()
  (with-gate ("BOLT #1 — truncated integers (tu16/tu32/tu64)")
    ;; A `tu` is a big-endian integer with LEADING ZERO BYTES STRIPPED.  It only
    ;; appears inside TLV records, where the record length already says how many
    ;; bytes there are — so the value carries no width of its own and zero
    ;; encodes as nothing at all.
    (check-bytes "zero encodes as the empty string" (%tu-bytes 0 8) (hx ""))
    (check-bytes "one byte stays one byte" (%tu-bytes 1 8) (hx "01"))
    (check-bytes "255 stays one byte" (%tu-bytes 255 8) (hx "ff"))
    (check-bytes "256 needs two" (%tu-bytes 256 8) (hx "0100"))
    (check-bytes "a tu16 at its maximum" (%tu-bytes #xffff 2) (hx "ffff"))
    (check-bytes "a tu32 strips three leading zeros" (%tu-bytes 1 4) (hx "01"))
    (check-bytes "a full-width tu64" (%tu-bytes #x0102030405060708 8) (hx "0102030405060708"))
    ;; Reading consumes the REST of the reader, since the length is external.
    (flet ((rd (hex width) (w:r-tu (w:make-reader (hx hex)) width)))
      (check-equal "empty reads as zero" (rd "" 8) 0)
      (check-equal "one byte" (rd "ff" 8) 255)
      (check-equal "two bytes" (rd "0100" 8) 256)
      (check-equal "round-trips at full width" (rd "0102030405060708" 8) #x0102030405060708)
      ;; A leading zero byte is a NON-MINIMAL encoding: the same value could have
      ;; been written shorter, so two byte strings would mean one number.  In a
      ;; TLV stream that reaches a signature, that is malleability.
      (check-signals "a leading zero byte is rejected" w:non-minimal-error (rd "0001" 8))
      ;; And a value wider than its declared type is not that type.
      (check-signals "more bytes than the width allows is rejected" w:truncated-error
        (rd "010203" 2)))
    ;; Round-trip over the range where the width boundary sits.
    (check "encode/decode round-trips across a byte boundary"
           (loop for n in '(0 1 127 128 255 256 65535 65536 16777215 16777216)
                 always (= n (w:r-tu (w:make-reader (%tu-bytes n 8)) 8))))))

(defun test-tlv ()
  (with-gate ("BOLT #1 — TLV streams")
    (let* ((recs (list (w:make-tlv-record :type 1   :value (hx "2a"))
                       (w:make-tlv-record :type 2   :value (hx "0102"))
                       (w:make-tlv-record :type 254 :value #())))
           (wr (w:make-writer)))
      (w:w-tlv-stream wr recs)
      (let ((bytes (w:writer-bytes wr)))
        (check-bytes "encoded stream" bytes (hx "01012a02020102fd00fe00"))
        (let ((back (w:r-tlv-stream (w:make-reader bytes))))
          (check-equal "record count" (length back) 3)
          (check-bytes "tlv-get 2" (w:tlv-get back 2) (hx "0102"))
          (check-equal "unknown type is nil" (w:tlv-get back 99) nil))))
    ;; Records are written sorted regardless of the order handed in — the
    ;; canonical encoding is what makes signed TLV streams comparable.
    (let ((wr (w:make-writer)))
      (w:w-tlv-stream wr (list (w:make-tlv-record :type 9 :value #())
                               (w:make-tlv-record :type 3 :value #())))
      (check-bytes "written in ascending type order" (w:writer-bytes wr) (hx "030009 00")))
    (check-signals "duplicate types rejected on write" w:tlv-order-error
      (let ((wr (w:make-writer)))
        (w:w-tlv-stream wr (list (w:make-tlv-record :type 5 :value #())
                                 (w:make-tlv-record :type 5 :value #())))))
    (check-signals "out-of-order types rejected on read" w:tlv-order-error
      (w:r-tlv-stream (w:make-reader (hx "0200 0100"))))
    (check-signals "duplicate types rejected on read" w:tlv-order-error
      (w:r-tlv-stream (w:make-reader (hx "0100 0100"))))
    (check-signals "record length past end of stream" w:truncated-error
      (w:r-tlv-stream (w:make-reader (hx "01ff"))))))

(defun test-message-envelope ()
  (with-gate ("BOLT #1 — message envelope")
    (let ((m (w:encode-message 16 (hx "0000 0000"))))
      (check-bytes "init encodes as type 16" m (hx "0010 00000000"))
      (multiple-value-bind (type payload) (w:decode-message m)
        (check-equal "type round-trips" type 16)
        (check-bytes "payload round-trips" payload (hx "00000000"))))))

(defun test-chain-hash ()
  (with-gate ("BOLT #1 — chain hashes")
    ;; Lightning identifies a chain by its genesis hash.  All signets share the
    ;; default signet genesis — it is the P2P magic that differs — so a private
    ;; signet uses the same chain hash here as any other.
    (w:select-network :mainnet)
    (check-bytes "mainnet" (w:chain-hash)
                 (reverse (hx "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")))
    (w:select-network :regtest)
    (check-bytes "regtest" (w:chain-hash)
                 (reverse (hx "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")))
    (w:select-network :signet)
    (check-bytes "signet" (w:chain-hash)
                 (reverse (hx "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")))
    (w:select-network :mainnet)))

(defun run-wire-tests ()
  (test-bigsize)
  (test-bigsize-rejects)
  (test-endianness)
  (test-truncated-integers)
  (test-tlv)
  (test-message-envelope)
  (test-chain-hash))
