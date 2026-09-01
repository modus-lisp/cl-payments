;;;; cl-payments.asd

(defsystem "cl-payments"
  :description "A from-scratch, clean-room Lightning Network implementation in
                Common Lisp — the BOLT stack on top of cl-consensus's Bitcoin
                consensus engine.  Nothing wraps LND or Core Lightning."
  :version "0.0.1"
  :author "ynniv"
  :license "MIT"
  ;; cl-consensus arrives here, at BOLT #3.  Everything before this point was
  ;; Lightning's own wire format and could stand alone; a commitment transaction
  ;; is a BITCOIN transaction, and the premise of this project is that we
  ;; validate it with our own consensus engine rather than trusting that what we
  ;; built is spendable.  It brings a UTXO store and an HTTP server along with
  ;; it, which is more than this needs, but a second serializer would be a second
  ;; thing to be subtly wrong.
  :depends-on ("secp256k1-fast" "ironclad" "bordeaux-threads" "cl-transport"
               "cl-consensus")
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "crypto")      ; BOLT #8 primitives: HKDF, ChaCha20-Poly1305, ECDH
     (:file "wire")        ; BOLT #1: readers/writers, BigSize, TLV, message envelope
     (:file "transport")   ; BOLT #8: Noise_XK handshake + encrypted transport
     (:file "features")    ; BOLT #9: feature bits and their negotiation rules
     (:file "peer")        ; BOLT #1: init/ping/pong/error + the async read loop
     (:file "gossip")      ; BOLT #7: gossip messages, signatures, routing graph
     (:file "keys")        ; BOLT #3: per-commitment key derivation + revocation
     (:file "commitment"))))  ; BOLT #3: commitment transactions and their scripts
  :in-order-to ((test-op (test-op "cl-payments/test"))))

(defsystem "cl-payments/test"
  :description "The offline gate suite: RFC 5869 / RFC 8439 crypto vectors, BOLT #1
                BigSize and TLV vectors, and the BOLT #8 handshake + key-rotation
                vectors — all from the specs, no network and no peer required."
  :depends-on ("cl-payments")
  :serial t
  :components ((:module "inspect"
                :serial t
                :components ((:file "harness")
                             (:file "crypto-test")
                             (:file "wire-test")
                             (:file "transport-test")
                             (:file "peer-test")
                             (:file "gossip-test")
                             (:file "keys-test")
                             (:file "commitment-test")
                             (:file "run-all"))))
  :perform (test-op (o c) (uiop:symbol-call '#:cl-payments.test '#:run-all)))
