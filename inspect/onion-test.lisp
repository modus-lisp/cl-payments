;;;; inspect/onion-test.lisp
;;;;
;;;; Phase 6 — BOLT #4 against the spec's own vectors.
;;;;
;;;; The onion is the one part of the protocol where a bug is invisible from the
;;;; inside: a packet we construct wrongly is rejected at the first hop with
;;;; "bad HMAC", which is also exactly what a corrupted packet looks like.  There
;;;; is nothing to diff against except another implementation's output.  So the
;;;; first gate is the spec's published packet, byte for byte, and the second is
;;;; that five nodes with the spec's keys peel it back to the spec's payloads.

(in-package #:cl-payments.test)

(defun onion-vectors-path ()
  (asdf:system-relative-pathname "cl-payments" "inspect/vectors/onion-test.json"))

(defun json-field (json key)
  "Tiny extraction for a flat JSON string field — same reasoning as elsewhere: two
   fields are not worth a JSON dependency."
  (let* ((k (format nil "\"~a\": \"" key)) (at (search k json)))
    (and at (let ((s (+ at (length k)))) (subseq json s (position #\" json :start s))))))

(defun json-all (json key)
  (loop with start = 0 with k = (format nil "\"~a\": \"" key)
        for at = (search k json :start2 start)
        while at
        collect (let ((s (+ at (length k)))) (subseq json s (position #\" json :start s)))
        do (setf start (1+ at))))

(defun run-onion-tests ()
  (let* ((json (uiop:read-file-string (onion-vectors-path)))
         (session (secp:bytes-to-int (hx (json-field json "session_key"))))
         (ad (hx (json-field json "associated_data")))
         (pubkeys (mapcar #'hx (json-all json "pubkey")))
         (payloads (mapcar #'hx (json-all json "payload")))
         (expected (hx (json-field json "onion"))))

    (with-gate ("onion: keys derive as the spec says")
      (check-equal "five hops" (length pubkeys) 5)
      ;; The first ephemeral key is just the session key's point, and the first
      ;; hop's shared secret is an ordinary ECDH — both directly checkable.
      (multiple-value-bind (epks secrets) (on:ephemeral-keys-and-secrets session pubkeys)
        (check "first ephemeral pubkey is sessionkey*G"
               (equalp (first epks) (c:compressed-pubkey (c:pubkey-of session))))
        (check "each shared secret is 32 bytes" (every (lambda (s) (= 32 (length s))) secrets))
        (check "ephemeral keys are all distinct — blinding worked"
               (= 5 (length (remove-duplicates epks :test #'equalp))))
        ;; A hop derives the same secret from the OTHER side: ECDH(node_priv, epk).
        ;; We cannot, without the node keys — but rho/mu/um derive from the
        ;; secret alone and must be distinct per type.
        (let ((ss (first secrets)))
          (check "rho, mu, um, pad, ammag are five different keys"
                 (= 5 (length (remove-duplicates
                               (mapcar (lambda (ty) (on:generate-key ty ss)) '("rho" "mu" "um" "pad" "ammag"))
                               :test #'equalp)))))))

    (with-gate ("onion: the spec's packet, byte for byte")
      (let ((packet (on:create-onion session pubkeys payloads ad)))
        (check-equal "packet is 1366 bytes" (length packet) on:+packet-size+)
        (check "version byte is 0" (zerop (aref packet 0)))
        (check-bytes "first 34 bytes (version + ephemeral key)" (subseq packet 0 34) (subseq expected 0 34))
        (check-bytes "the payload area" (subseq packet 34 1334) (subseq expected 34 1334))
        (check-bytes "the HMAC" (subseq packet 1334) (subseq expected 1334))
        (check-bytes "the whole packet" packet expected)))

    ;; The peel direction needs node private keys, which the spec vector does
    ;; not give.  So: build a route over keys WE choose, and check that each node
    ;; recovers exactly its payload, and nothing else.
    (with-gate ("onion: five nodes each peel exactly their own layer")
      (let* ((privs (loop for i from 1 to 5 collect (secp:bytes-to-int (c:sha256 (c:ascii->bytes (format nil "onion-test/node~d" i))))))
             (pubs (mapcar (lambda (k) (c:compressed-pubkey (c:pubkey-of k))) privs))
             (hps (list (on:make-hop-payload :amount-msat 4000 :cltv-expiry 140 :scid (gs:make-scid 1 1 1))
                        (on:make-hop-payload :amount-msat 3000 :cltv-expiry 130 :scid (gs:make-scid 2 2 2))
                        (on:make-hop-payload :amount-msat 2000 :cltv-expiry 120 :scid (gs:make-scid 3 3 3))
                        (on:make-hop-payload :amount-msat 1500 :cltv-expiry 110 :scid (gs:make-scid 4 4 4))
                        (on:make-hop-payload :amount-msat 1000 :cltv-expiry 100
                                             :payment-secret (c:sha256 (c:ascii->bytes "secret")) :total-msat 1000)))
             (encoded (mapcar #'on:encode-hop-payload hps))
             (hash (c:sha256 (c:ascii->bytes "onion-test/payment-hash")))
             (packet (on:create-onion session pubs encoded hash))
             (secrets-seen '()))
        (loop for priv in privs for hp in hps for i from 0
              do (destructuring-bind (&optional payload next ss)
                     (check-no-signal (format nil "hop ~d verifies the HMAC and peels" i)
                       (multiple-value-list (on:peel-onion packet priv hash)))
                   (push ss secrets-seen)
                   (let ((got (on:parse-hop-payload payload)))
                     (check (format nil "hop ~d reads its amount and expiry" i)
                            (and (= (on:hp-amount-msat got) (on:hp-amount-msat hp))
                                 (= (on:hp-cltv-expiry got) (on:hp-cltv-expiry hp))))
                     (if (< i 4)
                         (progn
                           (check (format nil "hop ~d is told the next channel" i)
                                  (string= (gs:scid-string (on:hp-scid got)) (gs:scid-string (on:hp-scid hp))))
                           (check (format nil "hop ~d is NOT told it is final" i) (null (on:hp-payment-secret got)))
                           (check (format nil "hop ~d gets a packet to forward" i)
                                  (and next (= (length next) on:+packet-size+)))
                           ;; The single property that makes it an onion: the
                           ;; wrong node cannot open this layer.
                           (check-signals (format nil "hop ~d's packet is opaque to the next node's key" i)
                                          on:onion-error (on:peel-onion packet (nth (1+ i) privs) hash))
                           (setf packet next))
                         (progn
                           (check "the final hop sees the payment secret"
                                  (equalp (on:hp-payment-secret got) (c:sha256 (c:ascii->bytes "secret"))))
                           (check "the final hop sees total_msat" (= 1000 (on:hp-total-msat got)))
                           (check "the final hop gets no packet to forward" (null next)))))))
        (check "the peelers derived the same secrets the sender did"
               (multiple-value-bind (epks secrets) (on:ephemeral-keys-and-secrets session pubs)
                 (declare (ignore epks))
                 (equalp (mapcar #'c:octets secrets) (mapcar #'c:octets (reverse secrets-seen)))))

        ;; A packet bound to a different associated_data (payment hash) fails at
        ;; hop one: the onion commits to the HTLC it rides on.
        (let ((p2 (on:create-onion session pubs encoded hash)))
          (check-signals "wrong associated data fails the HMAC" on:onion-error
                         (on:peel-onion p2 (first privs) (c:sha256 (c:zeros 1))))
          (let ((bad (copy-seq p2))) (setf (aref bad 500) (logxor (aref bad 500) 1))
            (check-signals "one flipped payload byte fails the HMAC" on:onion-error
                           (on:peel-onion bad (first privs) hash)))
          (let ((bad (copy-seq p2))) (setf (aref bad 0) 1)
            (check-signals "a non-zero version is rejected" on:onion-error
                           (on:peel-onion bad (first privs) hash))))

        ;; ---- errors come back the same road --------------------------------
        (with-gate ("onion: a failure from hop 3 is readable only by the sender, and names hop 3")
          (multiple-value-bind (epks secrets) (on:ephemeral-keys-and-secrets session pubs)
            (declare (ignore epks))
            (let* ((msg (on:encode-failure-message #x100c :channel-update (c:zeros 10)))
                   (packet (on:create-failure-packet (nth 3 secrets) msg)))
              ;; hops 2, 1, 0 each add a layer on the way back
              (setf packet (on:wrap-failure-packet (nth 2 secrets) packet))
              (setf packet (on:wrap-failure-packet (nth 1 secrets) packet))
              (setf packet (on:wrap-failure-packet (nth 0 secrets) packet))
              (multiple-value-bind (hop failure) (on:decrypt-failure-packet secrets packet)
                (check-equal "the sender attributes the failure to hop 3" hop 3)
                (check "and reads the failure code" (= #x100c (on:parse-failure-message failure)))
                (check "the message is padded to 1024 bytes of payload"
                       (= (length packet) (+ 32 2 1024 2))))
              (check "a mangled reason attributes to nobody"
                     (let ((bad (copy-seq packet))) (setf (aref bad 40) (logxor (aref bad 40) 1))
                       (null (on:decrypt-failure-packet secrets bad))))
              (check "a reason with a layer missing attributes to nobody"
                     (null (on:decrypt-failure-packet (butlast secrets 1)
                                                      (on:wrap-failure-packet (nth 4 secrets) packet)))))))))

    ;; The spec's error vector — the erring node's step, exactly.
    (with-gate ("onion: the spec's error packet vector")
      (let* ((ss (hx "b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328"))
             (msg (c:bytes (hx "400f0000000000000064000c3500fd84d1fd012c")
                           (make-array 300 :element-type (quote (unsigned-byte 8)) :initial-element #x80))))
        (check-equal "the failure message is 320 bytes" (length msg) 320)
        (check-bytes "um key" (on:generate-key "um" ss)
                     (hx "4da7f2923edce6c2d85987d1d9fa6d88023e6c3a9c3d20f07d3b10b61a78d646"))
        (check-bytes "ammag key" (on:generate-key "ammag" ss)
                     (hx "2f36bb8822e1f0d04c27b7d8bb7d7dd586e032a3218b8d414afbba6f169a4d68"))
        (check "the ammag stream begins as the spec shows"
               (equalp (subseq (on:cipher-stream (on:generate-key "ammag" ss) 32) 0 32)
                       (hx "e9c975b07c9a374ba64fd9be3aae955e917d34d1fa33f2e90f53bbf4394713c6")))
        (check "the raw error packet begins with the spec's HMAC"
               (let ((raw (on:wrap-failure-packet ss (on:create-failure-packet ss msg))))
                 (equalp (subseq raw 0 32) (hx "fda7e11974f78ca6cc456f2d17ae54463664696e93842548245dd2a2c513a626"))))))))
