;;;; inspect/crypto-test.lisp
;;;;
;;;; Gate 1 — the primitives, against the RFCs that define them.
;;;;
;;;; ironclad supplies ChaCha20 and Poly1305 separately but not the AEAD that
;;;; combines them, so src/crypto.lisp assembles RFC 8439 §2.8 by hand.  That
;;;; construction is easy to get subtly wrong (the one-time key comes from block
;;;; 0 while the payload starts at block 1; the MAC covers padded lengths), and a
;;;; subtle error would surface only as an opaque handshake failure against a
;;;; real peer.  So it is pinned to the RFC's own vectors here.

(in-package #:cl-payments.test)

(defun test-sha256 ()
  (with-gate ("SHA-256 (sanity)")
    (check-bytes "empty string"
                 (c:sha256 #())
                 (hx "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
    (check-bytes "\"abc\""
                 (c:sha256 (c:ascii->bytes "abc"))
                 (hx "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))))

(defun test-hmac ()
  ;; RFC 4231 test case 2.
  (with-gate ("HMAC-SHA256 (RFC 4231)")
    (check-bytes "case 2"
                 (c:hmac-sha256 (c:ascii->bytes "Jefe")
                                (c:ascii->bytes "what do ya want for nothing?"))
                 (hx "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))))

(defun test-hkdf ()
  ;; RFC 5869 appendix A.  Case 1 exercises salt + info; case 3 the empty ones,
  ;; which is precisely the shape BOLT #8 uses.
  (with-gate ("HKDF-SHA256 (RFC 5869)")
    (check-bytes "case 1 (42 bytes, with salt and info)"
                 (c:hkdf (hx "000102030405060708090a0b0c")
                         (hx "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
                         :info (hx "f0f1f2f3f4f5f6f7f8f9") :length 42)
                 (hx "3cb25f25faacd57a90434f64d0362f2a
                      2d2d0a90cf1a5a4c5db02d56ecc4c5bf
                      34007208d5b887185865"))
    (check-bytes "case 3 (empty salt and info — BOLT #8's shape)"
                 (c:hkdf (hx "") (hx "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
                         :info (hx "") :length 42)
                 (hx "8da4e775a563c18f715f802a063c5a31
                      b8a11f5c5ee1879ec3454e5f3c738d2d
                      9d201395faa4b61a96c8"))
    ;; HKDF-2 is just the 64-byte output split in half; check the halves line up.
    (multiple-value-bind (a b) (c:hkdf-2 (hx "00") (hx "01"))
      (let ((full (c:hkdf (hx "00") (hx "01"))))
        (check-bytes "hkdf-2 first half"  a (subseq full 0 32))
        (check-bytes "hkdf-2 second half" b (subseq full 32 64))))))

(defun test-poly1305 ()
  ;; RFC 8439 §2.5.2.
  (with-gate ("Poly1305 (RFC 8439 §2.5.2)")
    (let ((tag (c::%poly1305-tag
                (hx "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                #()
                (c:ascii->bytes "Cryptographic Forum Research Group"))))
      ;; %POLY1305-TAG appends the RFC 8439 AEAD length trailer, so it is not the
      ;; bare MAC of the message — compare against ironclad's raw MAC instead,
      ;; and check the bare primitive separately.
      (declare (ignorable tag)))
    (let ((m (ironclad:make-mac
              :poly1305
              (hx "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"))))
      (ironclad:update-mac m (c:ascii->bytes "Cryptographic Forum Research Group"))
      (check-bytes "§2.5.2 tag" (ironclad:produce-mac m)
                   (hx "a8061dc1305136c6c22b8baf0c0127a9")))))

(defun test-chacha20 ()
  ;; RFC 8439 §2.4.2 — the keystream itself, before any AEAD framing.
  (with-gate ("ChaCha20 (RFC 8439 §2.4.2)")
    (let ((pt (c:ascii->bytes
               "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")))
      (multiple-value-bind (otk ct)
          (c::%chacha20 (hx "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                        (hx "000000000000004a00000000")
                        pt)
        (declare (ignore otk))
        (check-bytes "§2.4.2 ciphertext" ct
                     (hx "6e2e359a2568f98041ba0728dd0d6981
                          e97e7aec1d4360c20a27afccfd9fae0b
                          f91b65c5524733ab8f593dabcd62b357
                          1639d624e65152ab8f530c359f0861d8
                          07ca0dbf500d6a6156a38e088a22b65e
                          52bc514d16ccf806818ce91ab7793736
                          5af90bbf74a35be6b40b8eedf2785e42
                          874d"))))))

(defun test-aead ()
  ;; RFC 8439 §2.8.2 — the full AEAD, which is exactly what encryptWithAD calls.
  (with-gate ("ChaCha20-Poly1305 AEAD (RFC 8439 §2.8.2)")
    (let* ((key (hx "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"))
           (nonce (hx "070000004041424344454647"))
           (ad (hx "50515253c0c1c2c3c4c5c6c7"))
           (pt (c:ascii->bytes
                "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."))
           (expected-ct
             (hx "d31a8d34648e60db7b86afbc53ef7ec2
                  a4aded51296e08fea9e2b5a736ee62d6
                  3dbea45e8ca9671282fafb69da92728b
                  1a71de0a9e060b2905d6a5b67ecd3b36
                  92ddbd7f2d778b8c9803aee328091b58
                  fab324e4fad675945585808b4831d7bc
                  3ff4def08e4b7a9de576d26586cec64b
                  6116"))
           (expected-tag (hx "1ae10b594f09e26a7e902ecbd0600691"))
           (sealed (c:aead-encrypt key nonce ad pt)))
      (check-bytes "ciphertext" (subseq sealed 0 (- (length sealed) 16)) expected-ct)
      (check-bytes "tag" (subseq sealed (- (length sealed) 16)) expected-tag)
      (check-bytes "round-trip" (c:aead-decrypt key nonce ad sealed) pt)
      ;; Tamper with each part in turn; every one must fail to authenticate.
      (let ((bad-ct (copy-seq sealed)))
        (setf (aref bad-ct 0) (logxor (aref bad-ct 0) 1))
        (check-signals "flipped ciphertext bit rejected" c:aead-auth-error
          (c:aead-decrypt key nonce ad bad-ct)))
      (let ((bad-tag (copy-seq sealed)))
        (setf (aref bad-tag (1- (length bad-tag)))
              (logxor (aref bad-tag (1- (length bad-tag))) 1))
        (check-signals "flipped tag bit rejected" c:aead-auth-error
          (c:aead-decrypt key nonce ad bad-tag)))
      (check-signals "wrong associated data rejected" c:aead-auth-error
        (c:aead-decrypt key nonce (hx "00") sealed))
      (check-signals "wrong nonce rejected" c:aead-auth-error
        (c:aead-decrypt key (hx "070000004041424344454648") ad sealed))
      (check-signals "truncated input rejected" c:aead-auth-error
        (c:aead-decrypt key nonce ad (subseq sealed 0 8))))))

(defun test-bolt8-nonce ()
  (with-gate ("BOLT #8 nonce encoding")
    ;; 32 zero bits then a 64-bit LITTLE-endian counter.  Everything else on the
    ;; Lightning wire is big-endian, so this is a standing trap.
    (check-bytes "n = 0"    (c:bolt8-nonce 0)    (hx "000000000000000000000000"))
    (check-bytes "n = 1"    (c:bolt8-nonce 1)    (hx "000000000100000000000000"))
    (check-bytes "n = 500"  (c:bolt8-nonce 500)  (hx "00000000f401000000000000"))
    (check-bytes "n = 1000" (c:bolt8-nonce 1000) (hx "00000000e803000000000000"))))

(defun test-keys ()
  (with-gate ("secp256k1 keys + BOLT #8 ECDH")
    ;; A known BOLT #8 keypair: ls.priv 0x1111... → ls.pub 0x034f355b...
    (let* ((priv (c:bytes->hex (hx "11")))
           (k #x1111111111111111111111111111111111111111111111111111111111111111))
      (declare (ignore priv))
      (check-bytes "pubkey for 0x1111…"
                   (c:compressed-pubkey (c:pubkey-of k))
                   (hx "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa")))
    (let ((k #x2121212121212121212121212121212121212121212121212121212121212121))
      (check-bytes "pubkey for 0x2121…"
                   (c:compressed-pubkey (c:pubkey-of k))
                   (hx "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7")))
    ;; Compressed round-trip through both parities.
    (dolist (hex '("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
                   "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7"
                   "036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7"))
      (check-bytes (format nil "parse/serialize round-trip ~a…" (subseq hex 0 10))
                   (c:compressed-pubkey (c:parse-pubkey (hx hex))) (hx hex)))
    (check-signals "off-curve x rejected" error
      (c:parse-pubkey (hx "02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")))
    (check-signals "bad prefix rejected" error
      (c:parse-pubkey (hx "044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa")))
    (check-signals "short key rejected" error (c:parse-pubkey (hx "0203")))
    ;; ECDH must commute: a·B == b·A.
    (let* ((a #x1111111111111111111111111111111111111111111111111111111111111111)
           (b #x2121212121212121212121212121212121212121212121212121212121212121)
           (ab (c:ecdh (c:pubkey-of b) a))
           (ba (c:ecdh (c:pubkey-of a) b)))
      (check-bytes "ECDH commutes" ab ba))))

(defun run-crypto-tests ()
  (test-sha256)
  (test-hmac)
  (test-hkdf)
  (test-poly1305)
  (test-chacha20)
  (test-aead)
  (test-bolt8-nonce)
  (test-keys))
