;;;; inspect/route-test.lisp — pathfinding on a synthetic graph.
;;;;
;;;; The arithmetic here is the arithmetic every intermediate node will CHECK
;;;; with check-forward: if a route's amounts are one millisatoshi short at any
;;;; hop, that hop fails the payment with fee_insufficient.  So the tests
;;;; assert not just that a route exists, but that every hop of it would pass
;;;; the forwarding decision of the node it asks to forward.

(in-package #:cl-payments.test)

(defun rt-node (n) (c:compressed-pubkey (c:pubkey-of (secp:bytes-to-int (c:sha256 (c:ascii->bytes (format nil "route/~a" n)))))))

(defun rt-edge (from to scid &rest policy-args)
  (rt:make-edge :from (rt-node from) :to (rt-node to) :scid (gs:make-scid scid 1 0)
                :policy (apply #'fw:make-policy policy-args)))

(defun run-route-tests ()
  ;;   A ──1── B ──2── C ──3── D        (cheap, long)
  ;;   A ──4── E ──5── D                (expensive, short)
  (let* ((edges (list (rt-edge "A" "B" 1 :fee-base-msat 0)
                      (rt-edge "B" "C" 2 :fee-base-msat 100 :fee-proportional-millionths 0 :cltv-expiry-delta 40)
                      (rt-edge "C" "D" 3 :fee-base-msat 100 :fee-proportional-millionths 0 :cltv-expiry-delta 40)
                      (rt-edge "A" "E" 4 :fee-base-msat 0)
                      (rt-edge "E" "D" 5 :fee-base-msat 5000 :fee-proportional-millionths 1000 :cltv-expiry-delta 144)))
         (a (rt-node "A")) (d (rt-node "D")))

    (with-gate ("route: amounts and expiries accumulate backwards from the destination")
      (let ((hops (rt:find-route edges a d 1000000 :final-cltv-delta 18 :current-height 500 :risk-factor 0)))
        (check-equal "three hops via B and C" (length hops) 3)
        (check "ends at D" (equalp (rt:hop-node (third hops)) d))
        ;; D must receive exactly the amount, at the final expiry.
        (check-equal "final hop: the invoice amount" (rt:hop-amount-msat (third hops)) 1000000)
        (check-equal "final hop: height + final delta" (rt:hop-cltv-expiry (third hops)) 518)
        ;; C forwards to D over edge 3 and charges 100: C must receive 1000100,
        ;; with 40 more blocks.
        (check-equal "C receives amount + C's fee" (rt:hop-amount-msat (second hops)) 1000100)
        (check-equal "C's expiry adds C's delta" (rt:hop-cltv-expiry (second hops)) 558)
        (check-equal "B receives amount + both fees" (rt:hop-amount-msat (first hops)) 1000200)
        (check-equal "B's expiry adds both deltas" (rt:hop-cltv-expiry (first hops)) 598)
        (check-equal "total fee is what the intermediates charge" (rt:total-fee-msat hops 1000000) 200)
        ;; The property that matters: every intermediate would ACCEPT this.
        (flet ((would-forward (in-hop out-hop policy)
                 (fw:forward-decision-ok-p
                  (fw:check-forward :incoming-amount-msat (rt:hop-amount-msat in-hop)
                                    :incoming-cltv-expiry (rt:hop-cltv-expiry in-hop)
                                    :amount-to-forward-msat (rt:hop-amount-msat out-hop)
                                    :outgoing-cltv-expiry (rt:hop-cltv-expiry out-hop)
                                    :policy policy
                                    :outgoing (fw:make-outgoing :available-msat 100000000)))))
          (check "B's forwarding decision accepts the route"
                 (would-forward (first hops) (second hops) (rt:edge-policy (second edges))))
          (check "C's forwarding decision accepts the route"
                 (would-forward (second hops) (third hops) (rt:edge-policy (third edges)))))))

    (with-gate ("route: choices")
      (check "with no risk weighting the cheap long path wins"
             (= 3 (length (rt:find-route edges a d 1000000 :risk-factor 0))))
      ;; Weight CLTV heavily enough and the 2-hop path is preferred despite
      ;; its fee: 80 blocks vs 144 — actually E's path is LONGER in blocks, so
      ;; it must still lose. Make E cheap in time to see the switch.
      (let ((edges2 (substitute (rt-edge "E" "D" 5 :fee-base-msat 5000 :fee-proportional-millionths 0 :cltv-expiry-delta 1)
                                (fifth edges) edges)))
        (check "a heavy risk factor prefers the short-timelock path"
               (= 2 (length (rt:find-route edges2 a d 1000000 :risk-factor 100000)))))
      (check "a disabled edge is not used"
             (let ((edges3 (substitute (rt-edge "B" "C" 2 :enabled-p nil) (second edges) edges)))
               (= 2 (length (rt:find-route edges3 a d 1000000 :risk-factor 0)))))
      (check "htlc_maximum on the cheap path diverts to the expensive one"
             (let ((edges4 (substitute (rt-edge "C" "D" 3 :htlc-maximum-msat 500000) (third edges) edges)))
               (= 2 (length (rt:find-route edges4 a d 1000000 :risk-factor 0)))))
      (check "htlc_minimum excludes a path for a tiny payment"
             (let ((edges5 (substitute (rt-edge "C" "D" 3 :htlc-minimum-msat 5000000) (third edges) edges)))
               (= 2 (length (rt:find-route edges5 a d 1000 :risk-factor 0)))))
      ;; Excluding the cheap path's middle channel is how a payer routes around
      ;; a channel that turned out to have no balance.
      (check "excluding a channel diverts around it"
             (= 2 (length (rt:find-route edges a d 1000000 :risk-factor 0
                                         :exclude (list (gs:make-scid 2 1 0))))))
      (check-signals "an unreachable destination is an error" rt:route-error
                     (rt:find-route edges a (rt-node "Z") 1000))
      (check-signals "max-hops is respected" rt:route-error
                     (let ((edges6 (remove (fifth edges) (remove (fourth edges) edges))))
                       (rt:find-route edges6 a d 1000000 :max-hops 2)))
      ;; A direction with no policy is not an edge at all: the graph is built
      ;; from channel_updates, and an unannounced direction is untraversable.
      (let ((r (gs:make-router)))
        (check "an empty router yields no edges" (null (rt:router-edges r)))))))
