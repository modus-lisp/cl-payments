;;;; inspect/gossip-test.lisp
;;;;
;;;; Gate 6 — BOLT #7 gossip, against messages captured from a real node.
;;;;
;;;; The BOLTs publish no gossip test vectors, so the ground truth here is
;;;; inspect/vectors/gossip.txt: actual `channel_announcement`,
;;;; `channel_update` and `node_announcement` bytes taken off the wire from Core
;;;; Lightning on the devnet (see inspect/capture-gossip.lisp).  Hand-written
;;;; vectors would be worthless for this — they carry signatures over an exact
;;;; byte range, so a message we built ourselves would only ever prove our
;;;; encoder agrees with our decoder.
;;;;
;;;; The negative cases carry the weight.  A verifier that accepts everything
;;;; passes every positive test and makes the node trust forged channels, which
;;;; is how you route payments into a hole.

(in-package #:cl-payments.test)

(defun gossip-vectors-path ()
  "Resolved through ASDF at RUNTIME, not from *LOAD-TRUENAME*: this file is
   compiled by ASDF, so at compile time that points into the fasl cache and the
   vectors silently appear to be missing."
  (asdf:system-relative-pathname "cl-payments" "inspect/vectors/gossip.txt"))

(defun load-gossip-vectors ()
  "List of (type . payload) captured from a live peer."
  (with-open-file (f (gossip-vectors-path) :if-does-not-exist nil)
    (unless f (return-from load-gossip-vectors nil))
    (loop for line = (read-line f nil)
          while line
          for l = (string-trim '(#\Space #\Return) line)
          unless (or (zerop (length l)) (char= (char l 0) #\#))
            collect (let ((sp (position #\Space l)))
                      (cons (parse-integer l :end sp)
                            (c:hex->bytes (subseq l (1+ sp))))))))

(defun gossip-of-type (type)
  (remove type (load-gossip-vectors) :key #'car :test #'/=))

(defun test-scid ()
  (with-gate ("BOLT #7 — short channel ids")
    ;; block(24) | tx(24) | output(16), packed big-endian into a u64.  The scid
    ;; is a POINTER to the funding output, which is what lets an announcement be
    ;; checked against the chain.
    (let ((s (gs:make-scid 143 2 0)))
      (check-equal "143x2x0 packs" (gs:scid->u64 s) (logior (ash 143 40) (ash 2 16)))
      (check-equal "round-trips" (gs:scid-string (gs:u64->scid (gs:scid->u64 s))) "143x2x0"))
    (check-equal "block 1, tx 0, out 0" (gs:scid->u64 (gs:make-scid 1 0 0)) (ash 1 40))
    (check-equal "max output index" (gs:scid-output (gs:u64->scid #xffff)) #xffff)
    (check-equal "parse from string"
                 (gs:scid->u64 (gs:parse-scid-string "700000x1234x2"))
                 (gs:scid->u64 (gs:make-scid 700000 1234 2)))
    ;; Each field must stay in its own bits — an overlap would alias two
    ;; different channels onto one id.
    (let ((s (gs:u64->scid (gs:scid->u64 (gs:make-scid #xffffff #xffffff #xffff)))))
      (check-equal "all fields at max survive"
                   (list (gs:scid-block s) (gs:scid-tx s) (gs:scid-output s))
                   (list #xffffff #xffffff #xffff)))))

(defun test-parse-real-gossip ()
  (let ((anns (gossip-of-type gs:+msg-channel-announcement+))
        (upds (gossip-of-type gs:+msg-channel-update+))
        (nodes (gossip-of-type gs:+msg-node-announcement+)))
    (with-gate ("BOLT #7 — parsing messages captured from Core Lightning")
      (unless (check "captured gossip vectors are present" anns
                     (format nil "expected ~a — it is committed, so a missing file ~
                                  means the checkout or the path is wrong, not that ~
                                  there is nothing to test"
                             (gossip-vectors-path)))
        (return-from test-parse-real-gossip))
      (check (format nil "~d channel_announcement~:p parse" (length anns))
             (every (lambda (m) (gs:parse-channel-announcement (cdr m))) anns))
      (check (format nil "~d channel_update~:p parse" (length upds))
             (every (lambda (m) (gs:parse-channel-update (cdr m))) upds))
      (check (format nil "~d node_announcement~:p parse" (length nodes))
             (every (lambda (m) (gs:parse-node-announcement (cdr m))) nodes))
      ;; Sanity on decoded content, not just "it didn't signal".
      (let ((a (gs:parse-channel-announcement (cdr (first anns)))))
        (check "announcement's chain hash is our network's"
               (equalp (c:octets (gs:chan-ann-chain-hash a)) (c:octets (w:chain-hash))))
        (check "node ids are 33-byte compressed keys"
               (and (= 33 (length (gs:chan-ann-node-1 a)))
                    (= 33 (length (gs:chan-ann-node-2 a)))))
        ;; BOLT #7 orders the two ends by public key; downstream code relies on
        ;; it to decide which end a direction bit refers to.
        (check "node_1 < node_2 lexicographically"
               (string< (c:bytes->hex (gs:chan-ann-node-1 a))
                        (c:bytes->hex (gs:chan-ann-node-2 a)))))
      (let ((u (gs:parse-channel-update (cdr (first upds)))))
        (check "update direction is 0 or 1" (member (gs:chan-upd-direction u) '(0 1)))
        (check "cltv delta is plausible" (< 0 (gs:chan-upd-cltv-expiry-delta u) 2000))))))

(defun test-signature-verification ()
  (let ((anns (gossip-of-type gs:+msg-channel-announcement+))
        (nodes (gossip-of-type gs:+msg-node-announcement+)))
    (with-gate ("BOLT #7 — signature verification")
      (unless (check "vectors present" anns) (return-from test-signature-verification))
      ;; Positive: real messages verify.  All FOUR signatures on an
      ;; announcement — two node keys and two bitcoin keys.
      (check "every captured channel_announcement verifies (4 sigs each)"
             (every (lambda (m) (gs:verify-channel-announcement
                                 (gs:parse-channel-announcement (cdr m))))
                    anns))
      (check "every captured node_announcement verifies"
             (every (lambda (m) (gs:verify-node-announcement
                                 (gs:parse-node-announcement (cdr m))))
                    nodes))

      ;; Negative: this is the part that matters.  Flip one byte of the SIGNED
      ;; region and it must stop verifying; a verifier hashing the wrong range
      ;; passes the positive test above and fails only here.
      (let* ((raw (copy-seq (cdr (first anns))))
             ;; 256 bytes of signatures, then the signed body.
             (i (+ 256 5)))
        (setf (aref raw i) (logxor (aref raw i) 1))
        (check "a flipped bit in the signed body is rejected"
               (not (gs:verify-channel-announcement (gs:parse-channel-announcement raw)))))
      ;; Corrupt a signature itself.
      (let ((raw (copy-seq (cdr (first anns)))))
        (setf (aref raw 10) (logxor (aref raw 10) 1))
        (check "a corrupted node signature is rejected"
               (not (gs:verify-channel-announcement (gs:parse-channel-announcement raw)))))
      ;; …including the BITCOIN signatures, which is what stops someone
      ;; announcing a channel over a UTXO they don't control.
      (let ((raw (copy-seq (cdr (first anns)))))
        (setf (aref raw 200) (logxor (aref raw 200) 1))   ; inside bitcoin_signature_1
        (check "a corrupted bitcoin signature is rejected"
               (not (gs:verify-channel-announcement (gs:parse-channel-announcement raw)))))
      (let ((raw (copy-seq (cdr (first nodes)))))
        (setf (aref raw 70) (logxor (aref raw 70) 1))
        (check "a tampered node_announcement is rejected"
               (not (gs:verify-node-announcement (gs:parse-node-announcement raw))))))))

(defun test-router-ingest ()
  (let ((vectors (load-gossip-vectors)))
    (with-gate ("BOLT #7 — routing graph")
      (unless (check "vectors present" vectors) (return-from test-router-ingest))
      (let ((r (gs:make-router)))
        (dolist (m vectors) (gs:ingest r (car m) (cdr m)))
        (check "nothing was rejected" (zerop (gs::router-rejected r)))
        (check "channels were learned" (plusp (gs:router-channel-count r)))
        (check "nodes were learned" (plusp (gs:router-node-count r)))
        (check "every channel has both directions' policy"
               (let ((all t))
                 (maphash (lambda (k ch) (declare (ignore k))
                            (unless (= 2 (length (gs:channel-policies ch))) (setf all nil)))
                          (gs:router-channels r))
                 all))
        (check "node aliases decoded without their NUL padding"
               (let ((ok t))
                 (maphash (lambda (k n) (declare (ignore k))
                            (when (find #\Nul (gs:node-alias n)) (setf ok nil))
                            (when (> (length (gs:node-alias n)) 32) (setf ok nil)))
                          (gs:router-nodes r))
                 ok)))
      ;; An update for a channel we never saw announced cannot be verified — we
      ;; do not know whose key should have signed it — so it must be dropped and
      ;; not stored on trust.
      (let ((r (gs:make-router))
            (upd (first (gossip-of-type gs:+msg-channel-update+))))
        (when upd
          (check-equal "an update with no announcement is rejected"
                       (gs:ingest r (car upd) (cdr upd)) :rejected)
          (check "…and creates no channel" (zerop (gs:router-channel-count r)))))
      ;; Replayed gossip must not regress a newer policy to an older one.
      (let ((r (gs:make-router)))
        (dolist (m vectors) (gs:ingest r (car m) (cdr m)))
        (let ((before (let (ts) (maphash (lambda (k ch) (declare (ignore k))
                                           (dolist (p (gs:channel-policies ch))
                                             (push (gs:chan-upd-timestamp p) ts)))
                                         (gs:router-channels r))
                        (sort ts #'<))))
          (dolist (m vectors) (gs:ingest r (car m) (cdr m)))   ; replay everything
          (let ((after (let (ts) (maphash (lambda (k ch) (declare (ignore k))
                                            (dolist (p (gs:channel-policies ch))
                                              (push (gs:chan-upd-timestamp p) ts)))
                                          (gs:router-channels r))
                         (sort ts #'<))))
            (check-equal "replaying the whole stream changes nothing" after before)))))))

(defun expected-graph ()
  "CLN's own reading of the same gossip, recorded alongside the vectors."
  (with-open-file (f (asdf:system-relative-pathname
                      "cl-payments" "inspect/vectors/graph-expected.txt")
                     :if-does-not-exist nil)
    (unless f (return-from expected-graph nil))
    (loop for line = (read-line f nil)
          while line
          for l = (string-trim '(#\Space #\Return) line)
          unless (or (zerop (length l)) (char= (char l 0) #\#))
            collect (let ((p (uiop:split-string l :separator " ")))
                      (list :scid (first p) :source (second p) :dest (third p)
                            :base (parse-integer (fourth p))
                            :ppm (parse-integer (fifth p))
                            :delay (parse-integer (sixth p))
                            :hmin (parse-integer (seventh p))
                            :hmax (parse-integer (eighth p)))))))

(defun our-graph-edges (router)
  "Our graph flattened to one entry per DIRECTION, in CLN's shape."
  (let ((out '()))
    (maphash
     (lambda (k ch)
       (declare (ignore k))
       (dolist (dir '(0 1))
         (let ((pol (if (zerop dir) (gs:channel-policy-1 ch) (gs:channel-policy-2 ch))))
           (when pol
             (push (list :scid (gs:scid-string (gs:channel-scid ch))
                         :source (c:bytes->hex (if (zerop dir) (gs:channel-node-1 ch)
                                                   (gs:channel-node-2 ch)))
                         :dest (c:bytes->hex (if (zerop dir) (gs:channel-node-2 ch)
                                                 (gs:channel-node-1 ch)))
                         :base (gs:chan-upd-fee-base-msat pol)
                         :ppm (gs:chan-upd-fee-proportional-millionths pol)
                         :delay (gs:chan-upd-cltv-expiry-delta pol)
                         :hmin (gs:chan-upd-htlc-minimum-msat pol)
                         :hmax (or (gs:chan-upd-htlc-maximum-msat pol) 0))
                   out)))))
     (gs:router-channels router))
    out))

(defun test-graph-vs-recorded ()
  "Diff our graph against Core Lightning's reading of the SAME gossip, offline.

   This is the check that would otherwise only exist in the live gate.  Every
   other offline test here is structural — it proves we parse something, not that
   we parse it CORRECTLY — and a misread field offset still yields a perfectly
   plausible fee.  Comparing against an independent implementation's values is
   the only thing that catches that without a node attached."
  (with-gate ("BOLT #7 — graph vs. Core Lightning's own reading (recorded)")
    (let ((theirs (expected-graph)))
      (unless (check "recorded expectation is present" theirs) (return-from test-graph-vs-recorded))
      (let ((r (gs:make-router)))
        (dolist (m (load-gossip-vectors)) (gs:ingest r (car m) (cdr m)))
        (let ((ours (our-graph-edges r)))
          (check-equal "same number of directed edges" (length ours) (length theirs))
          (dolist (want theirs)
            (let ((got (find-if (lambda (e)
                                  (and (string= (getf e :scid) (getf want :scid))
                                       (string-equal (getf e :source) (getf want :source))))
                                ours)))
              (if (null got)
                  (check (format nil "~a from ~a" (getf want :scid)
                                 (subseq (getf want :source) 0 12)) nil)
                  (dolist (field '(:dest :base :ppm :delay :hmin :hmax))
                    (let ((a (getf got field)) (b (getf want field)))
                      (check (format nil "~a ~a ~(~a~)" (getf want :scid)
                                     (subseq (getf want :source) 0 12) field)
                             (if (stringp b) (string-equal a b) (eql a b))
                             (format nil "ours ~a, theirs ~a" a b))))))))))))

(defun %rebuild-update (payload &key message-flags channel-flags)
  "A channel_update with its flag bytes rewritten, and htlc_maximum_msat dropped
   when MESSAGE-FLAGS clears bit 0.

   Synthetic rather than captured, deliberately: this is a test about FIELD
   OFFSETS, not signatures, and no peer on the devnet emits these variants.  The
   signature will not verify afterwards, which is fine — the parser is what is
   under test."
  (let* ((raw (copy-seq payload))
         ;; layout: sig(64) chain(32) scid(8) timestamp(4) message_flags(1) channel_flags(1)
         (mf-off (+ 64 32 8 4))
         (cf-off (1+ mf-off))
         (had-max (logtest (aref raw mf-off) 1)))
    (when message-flags (setf (aref raw mf-off) message-flags))
    (when channel-flags (setf (aref raw cf-off) channel-flags))
    (if (and had-max message-flags (not (logtest message-flags 1)))
        (subseq raw 0 (- (length raw) 8))    ; drop the now-absent htlc_maximum_msat
        raw)))

(defun test-channel-update-variants ()
  (with-gate ("BOLT #7 — channel_update field variants")
    (let ((upd (first (gossip-of-type gs:+msg-channel-update+))))
      (unless (check "a captured update to derive from" upd)
        (return-from test-channel-update-variants))
      (let ((base (cdr upd)))
        ;; Every captured update sets message_flags bit 0, so the branch where
        ;; htlc_maximum_msat is ABSENT is never exercised by real vectors.  It is
        ;; the older-peer path, and reading the field unconditionally would run
        ;; off the end of the message.
        (let ((old (check-no-signal "message_flags=0 parses (htlc_maximum absent)"
                     (gs:parse-channel-update (%rebuild-update base :message-flags 0)))))
          (check-equal "…and htlc_maximum_msat is nil"
                       (and old (gs:chan-upd-htlc-maximum-msat old)) nil)
          ;; The fields BEFORE the optional one must be unaffected — that is what
          ;; a desync would corrupt.
          (let ((new (gs:parse-channel-update base)))
            (check-equal "…fee base still reads correctly"
                         (and old (gs:chan-upd-fee-base-msat old))
                         (gs:chan-upd-fee-base-msat new))
            (check-equal "…cltv delta still reads correctly"
                         (and old (gs:chan-upd-cltv-expiry-delta old))
                         (gs:chan-upd-cltv-expiry-delta new))))
        ;; channel_flags packs direction (bit 0) and disabled (bit 1) into ONE
        ;; byte.  No captured update is disabled, so without this the predicate
        ;; that decides whether to route over a channel is never seen true.
        (let ((d0 (gs:parse-channel-update (%rebuild-update base :channel-flags 0)))
              (d1 (gs:parse-channel-update (%rebuild-update base :channel-flags 1)))
              (x0 (gs:parse-channel-update (%rebuild-update base :channel-flags 2)))
              (x1 (gs:parse-channel-update (%rebuild-update base :channel-flags 3))))
          (check-equal "flags 0 -> direction 0" (gs:chan-upd-direction d0) 0)
          (check-equal "flags 1 -> direction 1" (gs:chan-upd-direction d1) 1)
          (check "flags 0 -> enabled"  (not (gs:chan-upd-disabled-p d0)))
          (check "flags 2 -> disabled" (gs:chan-upd-disabled-p x0))
          (check-equal "flags 2 -> still direction 0" (gs:chan-upd-direction x0) 0)
          ;; Both bits at once: the two must be read independently, not as one
          ;; small integer.
          (check "flags 3 -> disabled" (gs:chan-upd-disabled-p x1))
          (check-equal "flags 3 -> direction 1" (gs:chan-upd-direction x1) 1))))))

(defun test-query-messages ()
  (with-gate ("BOLT #7 — queries and scid ordering")
    (let ((chain (w:chain-hash)))
      ;; The rule LND enforces and disconnects over: short channel ids must be
      ;; strictly increasing.  We sort on the way out…
      (let* ((msg (gs:encode-query-short-channel-ids
                   chain (list (gs:make-scid 143 2 0) (gs:make-scid 143 1 0)
                               (gs:make-scid 100 0 0))))
             (r (w:make-reader msg)))
        (w:r-chain-hash r)
        (let* ((encoded (w:r-varbytes r))
               (er (w:make-reader encoded)))
          (check-equal "encoding type 0 (uncompressed)" (w:r-u8 er) 0)
          (let ((ids (loop until (w:reader-eof-p er) collect (w:r-u64 er))))
            (check "scids are emitted strictly increasing"
                   (every #'< ids (rest ids)))
            (check-equal "lowest first"
                         (gs:scid-string (gs:u64->scid (first ids))) "100x0x0"))))
      ;; …and reject an unsorted reply on the way in, rather than silently
      ;; tolerating the thing that gets peers dropped.
      (flet ((reply (ids)
               (let ((inner (w:make-writer)))
                 (w:w-u8 inner 0)
                 (dolist (n ids) (w:w-u64 inner n))
                 (let ((wr (w:make-writer)))
                   (w:w-hash wr chain) (w:w-u32 wr 0) (w:w-u32 wr 1000) (w:w-u8 wr 1)
                   (w:w-varbytes wr (w:writer-bytes inner))
                   (w:writer-bytes wr)))))
        (multiple-value-bind (fb nb complete scids)
            (gs:parse-reply-channel-range (reply (list 100 200 300)))
          (declare (ignore fb nb))
          (check "a sorted reply parses" (and complete (= 3 (length scids)))))
        (check-signals "an out-of-order reply is rejected" gs:gossip-error
          (gs:parse-reply-channel-range (reply (list 300 100))))
        (check-signals "a duplicated scid is rejected" gs:gossip-error
          (gs:parse-reply-channel-range (reply (list 100 100))))))
    ;; gossip_timestamp_filter: the default asks for everything, because a peer
    ;; that has already sent its graph otherwise forwards only new messages.
    (let* ((msg (gs:encode-gossip-timestamp-filter (w:chain-hash)))
           (r (w:make-reader msg)))
      (w:r-chain-hash r)
      (check-equal "first_timestamp 0" (w:r-u32 r) 0)
      (check-equal "timestamp_range is the whole range" (w:r-u32 r) #xffffffff))))

(defun run-gossip-tests ()
  ;; The captured vectors are from the signet devnet, so the network must be
  ;; selected explicitly here.  Relying on whatever a previous gate left in
  ;; W:*NETWORK* makes this suite order-dependent — which it was, and which
  ;; showed up as a chain-hash mismatch that had nothing to do with gossip.
  (let ((saved w:*network*))
    (unwind-protect
         (progn
           (w:select-network :signet)
           (run-gossip-tests-1))
      (setf w:*network* saved))))

(defun run-gossip-tests-1 ()
  (test-scid)
  (test-parse-real-gossip)
  (test-signature-verification)
  (test-router-ingest)
  (test-graph-vs-recorded)
  (test-channel-update-variants)
  (test-query-messages))
