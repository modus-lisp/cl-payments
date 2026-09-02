;;;; src/route.lisp
;;;;
;;;; Phase 6, the sending half — pathfinding.
;;;;
;;;; A route is computed BACKWARDS, from the destination toward us.  That is
;;;; not a stylistic choice: the amount an intermediate node must receive
;;;; depends on the fee it charges to forward what the NEXT node must receive,
;;;; so amounts are only known once everything downstream is.  Searching from
;;;; the destination lets each relaxation step compute the exact amount and
;;;; expiry a hop needs, and by the time the search reaches us, the HTLC we
;;;; must offer is fully determined.
;;;;
;;;; The graph is whatever gossip told us, plus our own channels — which we
;;;; know better than gossip does, because we hold the balance.  Every edge is
;;;; one DIRECTION of one channel with the policy its owner published; a
;;;; channel with no update from that side is not traversable that way, since
;;;; nobody knows what it would charge.

(defpackage #:cl-payments.route
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:gs #:cl-payments.gossip)
                    (#:fw #:cl-payments.forward))
  (:nicknames #:ln-route)
  (:export
   #:edge #:make-edge #:edge-from #:edge-to #:edge-scid #:edge-policy #:edge-capacity-msat
   #:hop #:hop-node #:hop-scid #:hop-amount-msat #:hop-cltv-expiry
   #:find-route #:route-error #:router-edges #:total-fee-msat))

(in-package #:cl-payments.route)

(define-condition route-error (error)
  ((detail :initarg :detail :reader route-error-detail))
  (:report (lambda (c s) (format s "route: ~a" (route-error-detail c)))))

(defstruct edge
  from to scid
  policy            ; a fw:policy — the FROM node's advertised terms for this direction
  capacity-msat)    ; an upper bound on what can cross, or NIL if unknown

(defstruct hop
  "One step of a finished route: the node we hand the HTLC to, the channel we
   use, and what THAT node must receive."
  node scid amount-msat cltv-expiry)

(defun router-edges (router)
  "Every traversable direction in a gossip router, as edges."
  (let ((out '()))
    (maphash
     (lambda (k ch) (declare (ignore k))
       (flet ((add (from to upd)
                (when upd
                  (push (make-edge :from from :to to :scid (gs:channel-scid ch)
                                   :policy (fw:policy-from-update upd)
                                   :capacity-msat (gs:chan-upd-htlc-maximum-msat upd))
                        out))))
         (add (gs:channel-node-1 ch) (gs:channel-node-2 ch) (gs:channel-policy-1 ch))
         (add (gs:channel-node-2 ch) (gs:channel-node-1 ch) (gs:channel-policy-2 ch))))
     (gs:router-channels router))
    out))

(defun total-fee-msat (hops amount-msat)
  (- (hop-amount-msat (first hops)) amount-msat))

(defun find-route (edges source destination amount-msat &key (final-cltv-delta 18)
                                                             (current-height 0)
                                                             (max-hops 20)
                                                             (risk-factor 10)
                                                             exclude)
  "Dijkstra from DESTINATION back to SOURCE.  Returns the hops in forward order,
   or signals ROUTE-ERROR.

   Cost is the amount that must arrive at a node plus a small charge per block
   of CLTV it adds: fees are what we pay, but a long timelock is what we RISK
   (funds locked if something downstream stalls), and a route that is a few
   millisatoshi cheaper at the price of days of lockup is a bad trade.

   EXCLUDE is a list of scids not to use.  Gossip says what a channel WOULD
   charge, never whether it has the balance right now; the only way to learn
   that is to try, fail, and route around it."
  (setf edges (remove-if (lambda (e) (member (gs:scid->u64 (edge-scid e)) exclude
                                             :key #'gs:scid->u64))
                         edges))
  (let ((in-edges (make-hash-table :test 'equalp))   ; node-id -> edges INTO it
        (best (make-hash-table :test 'equalp))       ; node-id -> (cost amount cltv edge hops)
        (frontier '()))
    (dolist (e edges) (push e (gethash (c:octets (edge-to e)) in-edges)))
    (setf (gethash (c:octets destination) best)
          (list 0 amount-msat (+ current-height final-cltv-delta) nil 0))
    (push (c:octets destination) frontier)
    (loop while frontier
          do (let* ((node (pop frontier))
                    (state (gethash node best))
                    (a-here (second state)) (cltv-here (third state)) (hops (fifth state)))
               (when (equalp node (c:octets source)) (return))
               (when (< hops max-hops)
                 (dolist (e (gethash node in-edges))
                   (let* ((p (edge-policy e))
                          (from (c:octets (edge-from e))))
                     ;; The FROM node forwards over this edge. Its policy decides
                     ;; the fee and delta, and whether a-here is even allowed.
                     (when (and (fw:policy-enabled-p p)
                                (>= a-here (fw:policy-htlc-minimum-msat p))
                                (or (null (fw:policy-htlc-maximum-msat p))
                                    (<= a-here (fw:policy-htlc-maximum-msat p)))
                                (or (null (edge-capacity-msat e))
                                    (<= a-here (edge-capacity-msat e))))
                       (let* ((a-from (if (equalp from (c:octets source))
                                          ;; Our own hop charges us nothing.
                                          a-here
                                          (+ a-here (fw:forwarding-fee p a-here))))
                              (cltv-from (if (equalp from (c:octets source))
                                             cltv-here
                                             (+ cltv-here (fw:policy-cltv-expiry-delta p))))
                              (cost (+ a-from (* risk-factor (- cltv-from current-height))))
                              (prev (gethash from best)))
                         (when (or (null prev) (< cost (first prev)))
                           (setf (gethash from best) (list cost a-from cltv-from e (1+ hops)))
                           (pushnew from frontier :test #'equalp))))))
                 ;; Smallest cost first.
                 (setf frontier (sort frontier #'< :key (lambda (n) (first (gethash n best))))))))
    (let ((s (gethash (c:octets source) best)))
      (unless s (error 'route-error :detail "no route"))
      ;; Walk the chosen edges forward.  Each hop records what the node we hand
      ;; the HTLC to must receive — the numbers the onion payload for the
      ;; PREVIOUS node will carry as amt_to_forward / outgoing_cltv_value.
      (let ((hops '()) (node (c:octets source)))
        (loop for st = (gethash node best)
              for e = (fourth st)
              while e
              do (let ((next (c:octets (edge-to e))))
                   (let ((nst (gethash next best)))
                     (push (make-hop :node next :scid (edge-scid e)
                                     :amount-msat (second nst) :cltv-expiry (third nst))
                           hops))
                   (setf node next)))
        (nreverse hops)))))
