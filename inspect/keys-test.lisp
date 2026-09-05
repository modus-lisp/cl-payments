;;;; inspect/keys-test.lisp
;;;;
;;;; Gate 7 — BOLT #3 key derivation, against the spec's published vectors.
;;;;
;;;; Unlike gossip, this part of the protocol HAS official vectors, and they pin
;;;; the exact thing that is easy to get wrong: the argument order inside the
;;;; hashes.  `SHA256(per_commitment_point ‖ basepoint)` and the reverse both
;;;; produce a perfectly good curve point, so a transposed derivation yields keys
;;;; that look entirely valid and simply do not match the counterparty's.
;;;;
;;;; The vectors are necessary but not sufficient, so this gate also checks the
;;;; ALGEBRA.  A revocation public key whose private counterpart cannot be
;;;; reconstructed is worse than useless: the channel appears to work, states get
;;;; revoked, and the punishment branch that makes revocation mean anything is
;;;; silently unspendable.  Nothing in the published vectors catches that,
;;;; because they only test the public side.

(in-package #:cl-payments.test)

;;; BOLT #3, Appendix E — "Key Derivation".
(defparameter *e-base-secret*
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
(defparameter *e-per-commitment-secret*
  "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
(defparameter *e-basepoint*
  "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2")
(defparameter *e-per-commitment-point*
  "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486")

(defun test-key-derivation-vectors ()
  (with-gate ("BOLT #3 — key derivation (Appendix E)")
    (let ((bp (hx *e-basepoint*))
          (pcp (hx *e-per-commitment-point*))
          (bs (secp256k1-fast:bytes-to-int (hx *e-base-secret*))))
      (check-bytes "localpubkey" (k:derive-pubkey bp pcp)
                   (hx "0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5"))
      (check-bytes "localprivkey"
                   (secp256k1-fast:int-to-bytes32 (k:derive-privkey bs pcp))
                   (hx "cbced912d3b21bf196a766651e436aff192362621ce317704ea2f75d87e7be0f"))
      (check-bytes "revocationpubkey" (k:derive-revocation-pubkey bp pcp)
                   (hx "02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0")))))

(defun test-generate-from-seed ()
  ;; BOLT #3, "Appendix D: Per-commitment Secret Requirements".
  (with-gate ("BOLT #3 — per-commitment secret generation (Appendix D)")
    (let ((zeros (hx (make-string 64 :initial-element #\0)))
          (ffs   (hx (make-string 64 :initial-element #\f)))
          (ones  (hx "0101010101010101010101010101010101010101010101010101010101010101")))
      (check-bytes "seed 0x00…, I = 2^48-1"
                   (k:generate-from-seed zeros 281474976710655)
                   (hx "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148"))
      (check-bytes "seed 0xFF…, I = 2^48-1"
                   (k:generate-from-seed ffs 281474976710655)
                   (hx "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc"))
      (check-bytes "seed 0xFF…, alternate bits 1"
                   (k:generate-from-seed ffs #xaaaaaaaaaaa)
                   (hx "56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528"))
      (check-bytes "seed 0xFF…, alternate bits 2"
                   (k:generate-from-seed ffs #x555555555555)
                   (hx "9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31"))
      (check-bytes "seed 0x01…, I = 1"
                   (k:generate-from-seed ones 1)
                   (hx "915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c"))
      ;; Commitments count DOWN from 2^48-1, and each index must give a
      ;; different secret — a collision would make two states equally punishable
      ;; and break the ordering the whole scheme rests on.
      (check "adjacent indices give different secrets"
             (not (equalp (k:generate-from-seed zeros 100)
                          (k:generate-from-seed zeros 101)))))))

(defun test-derivation-algebra ()
  "The vectors only pin PUBLIC values.  These check that the private halves
   actually correspond — which is what makes the keys spendable at all."
  (with-gate ("BOLT #3 — private keys match their public counterparts")
    (let* ((base-secret (secp256k1-fast:bytes-to-int (hx *e-base-secret*)))
           (basepoint (c:compressed-pubkey (c:pubkey-of base-secret)))
           (pcs (secp256k1-fast:bytes-to-int (hx *e-per-commitment-secret*)))
           (pcp (c:compressed-pubkey (c:pubkey-of pcs))))
      ;; Ordinary blinding: derive both halves and check they are a keypair.
      (check-bytes "derive-privkey inverts derive-pubkey"
                   (c:compressed-pubkey (c:pubkey-of (k:derive-privkey base-secret pcp)))
                   (k:derive-pubkey basepoint pcp))
      ;; Revocation: THE important one.  If these disagree, every revoked state
      ;; is unpunishable and the channel is only as safe as the counterparty is
      ;; honest — with no symptom until someone cheats.
      (check-bytes "derive-revocation-privkey inverts derive-revocation-pubkey"
                   (c:compressed-pubkey
                    (c:pubkey-of (k:derive-revocation-privkey base-secret pcs)))
                   (k:derive-revocation-pubkey basepoint pcp))
      ;; And it must genuinely need BOTH secrets: neither alone may reconstruct
      ;; it, or revocation would give away nothing (or everything).
      (check "revocation key is not derivable from the basepoint secret alone"
             (not (equalp (c:compressed-pubkey (c:pubkey-of base-secret))
                          (k:derive-revocation-pubkey basepoint pcp))))
      (check "revocation key is not derivable from the per-commitment secret alone"
             (not (equalp (c:compressed-pubkey (c:pubkey-of pcs))
                          (k:derive-revocation-pubkey basepoint pcp))))
      ;; Different commitments must not share keys — that is the point of
      ;; per-commitment derivation.
      (let ((seed (hx (make-string 64 :initial-element #\3))))
        (check "successive commitments derive different keys"
               (not (equalp (k:derive-pubkey basepoint (k:per-commitment-point seed 5))
                            (k:derive-pubkey basepoint (k:per-commitment-point seed 6)))))))))

(defun test-hash-argument-order ()
  "The transposition the vectors exist to catch, stated directly."
  (with-gate ("BOLT #3 — hash argument order")
    (let ((bp (hx *e-basepoint*))
          (pcp (hx *e-per-commitment-point*)))
      ;; derive-pubkey hashes (per_commitment_point ‖ basepoint).  Swapping the
      ;; two yields a different, entirely valid-looking key.
      (let* ((right (secp256k1-fast:bytes-to-int (c:sha256 (c:bytes pcp bp))))
             (wrong (secp256k1-fast:bytes-to-int (c:sha256 (c:bytes bp pcp)))))
        (check "the two orderings differ" (/= right wrong))
        (check-bytes "derive-pubkey uses (per_commitment_point ‖ basepoint)"
                     (k:derive-pubkey bp pcp)
                     (c:compressed-pubkey
                      (secp256k1-fast:secp-add-points
                       (c:parse-pubkey bp)
                       (secp256k1-fast:secp-mul-point right (secp256k1-fast:secp-generator))))))
      ;; The revocation key uses BOTH hash orderings, one per term.  That makes
      ;; it SYMMETRIC in its two arguments — swapping them swaps the two terms of
      ;; a sum — which is worth pinning precisely because it is surprising, and
      ;; because it means the argument order cannot be checked by symmetry alone.
      (check "revocation key is symmetric in its arguments (a sum of swapped terms)"
             (equalp (k:derive-revocation-pubkey bp pcp)
                     (k:derive-revocation-pubkey pcp bp)))
      ;; What DOES distinguish it: using one ordering for both terms collapses
      ;; the construction, and that must not equal the real key.
      (let* ((h (secp256k1-fast:bytes-to-int (c:sha256 (c:bytes bp pcp))))
             (collapsed (c:compressed-pubkey
                         (secp256k1-fast:secp-add-points
                          (secp256k1-fast:secp-mul-point h (c:parse-pubkey bp))
                          (secp256k1-fast:secp-mul-point h (c:parse-pubkey pcp))))))
        (check "using one hash ordering for both terms gives a different key"
               (not (equalp collapsed (k:derive-revocation-pubkey bp pcp))))))))

(defun test-shachain ()
  (with-gate ("BOLT #3 — revoked-secret storage")
    ;; A channel that has advanced a million times must still be able to punish
    ;; any of the million states it revoked, without storing a million secrets.
    (let ((seed (hx (make-string 64 :initial-element #\a)))
          (chain (k:make-shachain)))
      (loop for i from k:+max-commitment-index+ downto (- k:+max-commitment-index+ 20)
            do (k:shachain-insert chain i (k:generate-from-seed seed i)))
      (check "every inserted secret is retrievable"
             (loop for i from k:+max-commitment-index+ downto (- k:+max-commitment-index+ 20)
                   always (equalp (c:octets (k:shachain-lookup chain i))
                                  (c:octets (k:generate-from-seed seed i)))))
      (check "storage stays small (≤ 49 entries) regardless of how many arrived"
             (<= (count-if-not #'null (k::shachain-known chain)) 49)))
    ;; A counterparty whose secrets contradict each other is broken or lying;
    ;; either way the channel must not keep advancing on their word.
    (let ((seed-a (hx (make-string 64 :initial-element #\a)))
          (seed-b (hx (make-string 64 :initial-element #\b)))
          (chain (k:make-shachain)))
      (k:shachain-insert chain k:+max-commitment-index+
                         (k:generate-from-seed seed-a k:+max-commitment-index+))
      (check-signals "a contradictory revoked secret is rejected" k:key-error
        (k:shachain-insert chain (1- k:+max-commitment-index+)
                           (k:generate-from-seed seed-b (1- k:+max-commitment-index+)))))))

(defun test-commitment-key-set ()
  "DERIVE-COMMITMENT-KEYS assembles every key that appears in one commitment.
   It had no coverage at all — the individual derivations were tested and the
   function that actually calls them was not, which is the gap most likely to
   put a correct key in the wrong slot."
  (with-gate ("BOLT #3 — the full key set for a commitment")
    (let* ((seed (hx (make-string 64 :initial-element #\7)))
           (pcp (k:per-commitment-point seed 42))
           ;; Six independent basepoints, so a transposed slot cannot pass by
           ;; coincidence — with shared basepoints, swapping two fields would be
           ;; invisible.
           (payment      (c:compressed-pubkey (c:pubkey-of 11111)))
           (delayed      (c:compressed-pubkey (c:pubkey-of 22222)))
           (htlc         (c:compressed-pubkey (c:pubkey-of 33333)))
           (revocation   (c:compressed-pubkey (c:pubkey-of 44444)))
           (r-payment    (c:compressed-pubkey (c:pubkey-of 55555)))
           (r-htlc       (c:compressed-pubkey (c:pubkey-of 66666)))
           (keys (k:derive-commitment-keys
                  :per-commitment-point pcp
                  :payment-basepoint payment
                  :delayed-payment-basepoint delayed
                  :htlc-basepoint htlc
                  :revocation-basepoint revocation
                  :remote-payment-basepoint r-payment
                  :remote-htlc-basepoint r-htlc)))
      ;; Each slot must hold the key derived from ITS OWN basepoint.
      (check-bytes "local key comes from the payment basepoint"
                   (k:ck-local keys) (k:derive-pubkey payment pcp))
      (check-bytes "delayed key comes from the delayed basepoint"
                   (k:ck-delayed keys) (k:derive-pubkey delayed pcp))
      (check-bytes "local htlc key comes from the htlc basepoint"
                   (k:ck-local-htlc keys) (k:derive-pubkey htlc pcp))
      (check-bytes "remote key comes from the remote payment basepoint"
                   (k:ck-remote keys) (k:derive-pubkey r-payment pcp))
      (check-bytes "remote htlc key comes from the remote htlc basepoint"
                   (k:ck-remote-htlc keys) (k:derive-pubkey r-htlc pcp))
      ;; The revocation key is NOT an ordinary blinded key, and must not be
      ;; derived like one — that mistake yields a spendable-looking key with no
      ;; punishment property at all.
      (check-bytes "revocation key uses the revocation construction"
                   (k:ck-revocation keys) (k:derive-revocation-pubkey revocation pcp))
      (check "revocation key is not the ordinary blinding of its basepoint"
             (not (equalp (k:ck-revocation keys) (k:derive-pubkey revocation pcp))))
      ;; Every slot distinct: a duplicate means two roles share a key.
      (let ((all (list (k:ck-local keys) (k:ck-remote keys) (k:ck-delayed keys)
                       (k:ck-revocation keys) (k:ck-local-htlc keys) (k:ck-remote-htlc keys))))
        (check "all six keys are distinct"
               (= 6 (length (remove-duplicates all :test #'equalp)))))
      ;; The remote fields are optional; absent input must give NIL rather than
      ;; silently reusing a local key.
      (let ((partial (k:derive-commitment-keys
                      :per-commitment-point pcp
                      :payment-basepoint payment
                      :delayed-payment-basepoint delayed
                      :htlc-basepoint htlc
                      :revocation-basepoint revocation)))
        (check "absent remote basepoints give NIL, not a stand-in"
               (and (null (k:ck-remote partial)) (null (k:ck-remote-htlc partial))))))))

(defun test-shachain-sequence ()
  "BOLT #3's storage test walks a real revocation sequence, not one insertion."
  (with-gate ("BOLT #3 — a full revocation sequence")
    (let* ((seed (hx (make-string 64 :initial-element #\f)))
           (chain (k:make-shachain))
           (n 64))
      ;; Secrets arrive in DECREASING index order, as they do on a live channel.
      (loop for i from k:+max-commitment-index+ downto (- k:+max-commitment-index+ n)
            do (k:shachain-insert chain i (k:generate-from-seed seed i)))
      (check "every secret in the sequence is reproducible"
             (loop for i from k:+max-commitment-index+ downto (- k:+max-commitment-index+ n)
                   always (equalp (c:octets (k:shachain-lookup chain i))
                                  (c:octets (k:generate-from-seed seed i)))))
      ;; A state that has NOT been revoked must not be derivable — if it were,
      ;; we could punish a commitment the counterparty is still entitled to use.
      (check "an index that has not been revoked yet returns NIL"
             (null (k:shachain-lookup chain (- k:+max-commitment-index+ n 1))))
      (check "storage stays bounded across the whole sequence"
             (<= (count-if-not #'null (k::shachain-known chain)) 49)))))

(defun test-shachain-persistence-roundtrip ()
  "Serialising the shachain and reading it back must be a TRUE inverse.  The
   reload has to reconstruct each secret's bucket from its index, not trust list
   position — a GAP in the occupied buckets otherwise mislocates secrets and we
   silently lose the ability to punish the states they cover."
  (with-gate ("BOLT #3 — shachain persistence round-trip")
    (let* ((seed (hx (make-string 64 :initial-element #\f)))
           (chain (k:make-shachain))
           (n 64))
      (loop for i from k:+max-commitment-index+ downto (- k:+max-commitment-index+ n)
            do (k:shachain-insert chain i (k:generate-from-seed seed i)))
      (let ((reloaded (k:plist->shachain (k:shachain->plist chain))))
        (check "every revoked secret survives ->plist->shachain unchanged"
               (loop for i from k:+max-commitment-index+ downto (- k:+max-commitment-index+ n)
                     always (equalp (c:octets (k:shachain-lookup reloaded i))
                                    (c:octets (k:generate-from-seed seed i))))))
      ;; The regression: occupied buckets {0,3} with a GAP at {1,2}.  A
      ;; position-based reload drops the tz=3 secret into bucket 1; a correct
      ;; inverse recomputes the bucket from the index and puts it at 3.
      (let* ((idx-a k:+max-commitment-index+)             ; ...1111 -> bucket 0
             (idx-b (- k:+max-commitment-index+ 7))       ; ...1000 -> bucket 3
             (sec-a (k:generate-from-seed seed idx-a))
             (sec-b (k:generate-from-seed seed idx-b))
             (plist (list (list :index idx-a :secret (c:bytes->hex (c:octets sec-a)))
                          (list :index idx-b :secret (c:bytes->hex (c:octets sec-b)))))
             (reloaded (k:plist->shachain plist)))
        (check "gapped reload puts the tz=0 secret in bucket 0"
               (and (aref (k::shachain-known reloaded) 0)
                    (equalp (c:octets (aref (k::shachain-known reloaded) 0)) (c:octets sec-a))
                    (= (aref (k::shachain-indices reloaded) 0) idx-a)))
        (check "gapped reload puts the tz=3 secret in bucket 3, NOT bucket 1"
               (and (null (aref (k::shachain-known reloaded) 1))
                    (aref (k::shachain-known reloaded) 3)
                    (equalp (c:octets (aref (k::shachain-known reloaded) 3)) (c:octets sec-b))
                    (= (aref (k::shachain-indices reloaded) 3) idx-b)))
        (check "both remain retrievable by lookup after the gapped reload"
               (and (equalp (c:octets (k:shachain-lookup reloaded idx-a)) (c:octets sec-a))
                    (equalp (c:octets (k:shachain-lookup reloaded idx-b)) (c:octets sec-b))))))))

(defun run-keys-tests ()
  (test-key-derivation-vectors)
  (test-generate-from-seed)
  (test-derivation-algebra)
  (test-hash-argument-order)
  (test-shachain)
  (test-shachain-sequence)
  (test-shachain-persistence-roundtrip)
  (test-commitment-key-set))
