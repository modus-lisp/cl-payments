;;;; src/forward.lisp
;;;;
;;;; Phase 5 — forwarding: what a node in the MIDDLE of a route owes everyone else.
;;;;
;;;; Being an endpoint is easy.  Either a payment is for us or it is not, and if
;;;; anything goes wrong the only party inconvenienced is us.  A forwarding node
;;;; is in a different position: it accepts an incoming HTLC and offers an
;;;; outgoing one, and for the interval between those two it is exposed.  If it
;;;; pays downstream and then fails to claim upstream, it loses real money — not
;;;; the sender's, its own.
;;;;
;;;; So the checks here are not politeness.  Every one of them exists because
;;;; skipping it is a way to lose funds or to be used as a free relay:
;;;;
;;;;   * The FEE check is why forwarding is not free.  A sender who underpays is
;;;;     asking us to subsidise their payment; there is no later opportunity to
;;;;     collect, because our fee is taken as the difference between the two
;;;;     HTLCs and that difference is fixed the moment we forward.
;;;;
;;;;   * The CLTV check is why forwarding is not a way to steal from us.  We must
;;;;     have strictly MORE time to claim the incoming HTLC than the recipient of
;;;;     the outgoing one has to claim theirs.  Reverse that and the downstream
;;;;     node can wait for our incoming HTLC to expire, then claim the outgoing
;;;;     one — we have paid and cannot collect.  `cltv_expiry_delta` is exactly
;;;;     that safety margin, and it is why an intermediate node advertises one.
;;;;
;;;;   * The EXPIRY checks are about the on-chain endgame.  If the incoming HTLC
;;;;     is already close to its deadline we may not have time to force-close and
;;;;     get a claim confirmed, so accepting it is accepting a loss.
;;;;
;;;; None of this needs the onion.  Peeling a layer tells us WHAT the sender
;;;; asked for — an amount and an expiry for the next hop — but whether that
;;;; request is acceptable is a policy question about our own channel, and it is
;;;; the half where the money is.  BOLT #4's onion is Phase 6; this is the
;;;; decision it feeds.
;;;;
;;;; Reference: https://github.com/lightning/bolts/blob/master/04-onion-routing.md

(defpackage #:cl-payments.forward
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:gs #:cl-payments.gossip))
  (:nicknames #:ln-forward)
  (:export
   ;; BOLT #4 failure codes
   #:+badonion+ #:+perm+ #:+node+ #:+update+
   #:+temporary-node-failure+ #:+permanent-node-failure+
   #:+temporary-channel-failure+ #:+permanent-channel-failure+
   #:+unknown-next-peer+ #:+amount-below-minimum+ #:+fee-insufficient+
   #:+incorrect-cltv-expiry+ #:+expiry-too-soon+ #:+expiry-too-far+
   #:+channel-disabled+ #:+incorrect-or-unknown-payment-details+
   #:+final-incorrect-cltv-expiry+ #:+final-incorrect-htlc-amount+
   #:+invalid-onion-payload+
   #:failure-name #:failure-permanent-p #:failure-update-p #:failure-node-p
   ;; policy and channel view
   #:policy #:make-policy #:policy-fee-base-msat #:policy-fee-proportional-millionths
   #:policy-cltv-expiry-delta #:policy-htlc-minimum-msat #:policy-htlc-maximum-msat
   #:policy-enabled-p #:policy-from-update
   #:outgoing #:make-outgoing #:outgoing-available-msat #:outgoing-pending-htlcs
   #:outgoing-max-accepted-htlcs #:outgoing-in-flight-msat
   #:outgoing-max-in-flight-msat #:outgoing-known-p #:outgoing-peer-connected-p
   ;; the decision
   #:forwarding-fee #:minimum-incoming-msat
   #:check-forward #:forward-decision #:make-forward-decision
   #:forward-decision-ok-p #:forward-decision-failure-code #:forward-decision-detail))

(in-package #:cl-payments.forward)

;;; ----------------------------------------------------------------------------
;;; BOLT #4 failure codes
;;;
;;; The high bits are flags, not part of the number, and they tell the SENDER
;;; what to do rather than what went wrong:
;;;
;;;   PERM   — do not retry this route; something is permanently wrong.
;;;   NODE   — the fault is the node's, not this particular channel's.
;;;   UPDATE — a channel_update is attached; the sender's view of our policy was
;;;            stale and it should retry with the corrected one.
;;;   BADONION — the onion itself was unreadable, so the error cannot be
;;;            encrypted the usual way.
;;;
;;; Getting a flag wrong is worse than getting the code wrong.  Marking a
;;; transient failure PERM tells every sender on the network to stop using our
;;; channel; omitting UPDATE on a fee change means senders keep retrying with the
;;; old fee and keep failing, with no way to learn why.
;;; ----------------------------------------------------------------------------

(defconstant +badonion+ #x8000)
(defconstant +perm+     #x4000)
(defconstant +node+     #x2000)
(defconstant +update+   #x1000)

(defconstant +temporary-node-failure+     (logior +node+ 2))
(defconstant +permanent-node-failure+     (logior +perm+ +node+ 2))
(defconstant +temporary-channel-failure+  (logior +update+ 7))
(defconstant +permanent-channel-failure+  (logior +perm+ 8))
(defconstant +unknown-next-peer+          (logior +perm+ 10))
(defconstant +amount-below-minimum+       (logior +update+ 11))
(defconstant +fee-insufficient+           (logior +update+ 12))
(defconstant +incorrect-cltv-expiry+      (logior +update+ 13))
(defconstant +expiry-too-soon+            (logior +update+ 14))
(defconstant +incorrect-or-unknown-payment-details+ (logior +perm+ 15))
(defconstant +final-incorrect-cltv-expiry+ 18)
(defconstant +final-incorrect-htlc-amount+ 19)
(defconstant +channel-disabled+           (logior +update+ 20))
(defconstant +expiry-too-far+             21)
(defconstant +invalid-onion-payload+      (logior +perm+ 22))

(defun failure-name (code)
  (case code
    (#.+temporary-node-failure+ :temporary-node-failure)
    (#.+permanent-node-failure+ :permanent-node-failure)
    (#.+temporary-channel-failure+ :temporary-channel-failure)
    (#.+permanent-channel-failure+ :permanent-channel-failure)
    (#.+unknown-next-peer+ :unknown-next-peer)
    (#.+amount-below-minimum+ :amount-below-minimum)
    (#.+fee-insufficient+ :fee-insufficient)
    (#.+incorrect-cltv-expiry+ :incorrect-cltv-expiry)
    (#.+expiry-too-soon+ :expiry-too-soon)
    (#.+incorrect-or-unknown-payment-details+ :incorrect-or-unknown-payment-details)
    (#.+final-incorrect-cltv-expiry+ :final-incorrect-cltv-expiry)
    (#.+final-incorrect-htlc-amount+ :final-incorrect-htlc-amount)
    (#.+channel-disabled+ :channel-disabled)
    (#.+expiry-too-far+ :expiry-too-far)
    (#.+invalid-onion-payload+ :invalid-onion-payload)
    (t :unknown)))

;;; The flags are read off the code rather than tabulated per failure, so a new
;;; code cannot accidentally be classified inconsistently with its own number.
(defun failure-permanent-p (code) (logtest code +perm+))
(defun failure-node-p (code)      (logtest code +node+))
(defun failure-update-p (code)    (logtest code +update+))

;;; ----------------------------------------------------------------------------
;;; Our policy, and the state of the outgoing channel
;;; ----------------------------------------------------------------------------

(defstruct policy
  (fee-base-msat 1000)
  (fee-proportional-millionths 1)
  (cltv-expiry-delta 40)
  (htlc-minimum-msat 1)
  (htlc-maximum-msat nil)
  (enabled-p t))

(defun policy-from-update (upd)
  "Our own advertised policy, taken from the channel_update we published.

   Derived from the message rather than kept alongside it, because the message
   is what senders actually see.  If the two drift, every sender computes fees
   from the advertised numbers and we reject on the internal ones — which
   presents as a channel that fails every payment for no visible reason."
  (make-policy :fee-base-msat (gs:chan-upd-fee-base-msat upd)
               :fee-proportional-millionths (gs:chan-upd-fee-proportional-millionths upd)
               :cltv-expiry-delta (gs:chan-upd-cltv-expiry-delta upd)
               :htlc-minimum-msat (gs:chan-upd-htlc-minimum-msat upd)
               :htlc-maximum-msat (gs:chan-upd-htlc-maximum-msat upd)
               :enabled-p (not (gs:chan-upd-disabled-p upd))))

(defstruct outgoing
  "What we know about the channel we would forward OVER."
  (known-p t)                 ; do we have a channel with that scid at all?
  (peer-connected-p t)
  (available-msat 0)          ; spendable by us, after reserve and fees
  (pending-htlcs 0)
  (max-accepted-htlcs 30)
  (in-flight-msat 0)
  (max-in-flight-msat nil))

;;; ----------------------------------------------------------------------------
;;; Fees
;;; ----------------------------------------------------------------------------

(defun forwarding-fee (policy amount-msat)
  "What we charge to forward AMOUNT-MSAT.

   BOLT #7's formula is base + amount * proportional / 1e6, with the division
   FLOORED.  Rounding up here would demand a millisatoshi more than any correct
   sender computes, and every payment across the channel would fail with
   fee_insufficient while our advertised policy looked entirely reasonable."
  (+ (policy-fee-base-msat policy)
     (floor (* amount-msat (policy-fee-proportional-millionths policy))
            1000000)))

(defun minimum-incoming-msat (policy amount-to-forward-msat)
  "The smallest incoming HTLC we will accept in order to send
   AMOUNT-TO-FORWARD-MSAT onward."
  (+ amount-to-forward-msat (forwarding-fee policy amount-to-forward-msat)))

;;; ----------------------------------------------------------------------------
;;; The decision
;;; ----------------------------------------------------------------------------

(defstruct forward-decision
  ok-p failure-code detail)

(defun %fail (code fmt &rest args)
  (make-forward-decision :ok-p nil :failure-code code
                         :detail (apply #'format nil fmt args)))

(defconstant +max-cltv-expiry-delta+ 2016
  "The furthest into the future we will accept an incoming HTLC's expiry.

   An HTLC ties up our funds until it resolves, so a sender who sets a very
   distant expiry can lock a channel's capacity for weeks at no cost — a
   griefing attack that costs the attacker nothing and does not even require
   them to complete the payment.")

(defconstant +min-final-cltv-margin+ 6
  "How much room we insist on between the current height and an incoming HTLC's
   expiry before we are willing to forward.

   If the incoming HTLC expires while we are still owed the money, our only
   recourse is to force-close and claim on-chain, and that takes confirmations.
   Accepting an HTLC that is already near its deadline is accepting the loss.")

(defun check-forward (&key incoming-amount-msat incoming-cltv-expiry
                           amount-to-forward-msat outgoing-cltv-expiry
                           policy outgoing current-height)
  "Decide whether to forward, and if not, why.

   AMOUNT-TO-FORWARD-MSAT and OUTGOING-CLTV-EXPIRY are what the SENDER asked
   for — in the real protocol they come out of the onion — while
   INCOMING-AMOUNT-MSAT and INCOMING-CLTV-EXPIRY are what we actually received.
   The whole job is checking the second pair against the first: the sender's
   instructions are not trusted, they are verified against what we hold.

   Returns a FORWARD-DECISION.  The order of the checks is deliberate; see the
   note above each group."
  (let ((policy (or policy (make-policy)))
        (outgoing (or outgoing (make-outgoing))))
    (cond
      ;; ---- Does the next hop exist at all? -----------------------------------
      ;;
      ;; unknown_next_peer is PERMANENT: the sender's map of the network is
      ;; wrong, and retrying the same route will fail identically.  Note this is
      ;; deliberately the same answer whether the channel does not exist or
      ;; merely is not ours — distinguishing them would let anyone probe our
      ;; channel table.
      ((not (outgoing-known-p outgoing))
       (%fail +unknown-next-peer+ "no channel with that short_channel_id"))

      ;; A disconnected peer is TEMPORARY and carries UPDATE, so the sender
      ;; retries elsewhere now and may come back later.  Marking it permanent
      ;; would evict our channel from every sender's graph over a reconnect.
      ((not (outgoing-peer-connected-p outgoing))
       (%fail +temporary-channel-failure+ "next peer is not connected"))

      ((not (policy-enabled-p policy))
       (%fail +channel-disabled+ "outgoing channel is disabled"))

      ;; ---- Is the request itself coherent? -----------------------------------
      ;;
      ;; Forwarding more than we were given, or a non-positive amount, is not a
      ;; policy failure — it is a malformed request, and no channel_update would
      ;; make it acceptable.
      ((or (null amount-to-forward-msat) (<= amount-to-forward-msat 0))
       (%fail +invalid-onion-payload+ "amt_to_forward is not positive"))
      ((> amount-to-forward-msat incoming-amount-msat)
       (%fail +invalid-onion-payload+
              "asked to forward ~d msat having received only ~d"
              amount-to-forward-msat incoming-amount-msat))

      ;; ---- Does it fit the outgoing channel's advertised limits? -------------
      ((< amount-to-forward-msat (policy-htlc-minimum-msat policy))
       (%fail +amount-below-minimum+ "~d msat is below our minimum of ~d"
              amount-to-forward-msat (policy-htlc-minimum-msat policy)))
      ((and (policy-htlc-maximum-msat policy)
            (> amount-to-forward-msat (policy-htlc-maximum-msat policy)))
       (%fail +temporary-channel-failure+ "~d msat is above our maximum of ~d"
              amount-to-forward-msat (policy-htlc-maximum-msat policy)))

      ;; ---- Are we being paid? ------------------------------------------------
      ;;
      ;; Our fee is the DIFFERENCE between the two HTLCs, fixed the instant we
      ;; forward.  There is no later opportunity to collect, so an underpaying
      ;; sender is asking us to subsidise them.
      ((< incoming-amount-msat (minimum-incoming-msat policy amount-to-forward-msat))
       (%fail +fee-insufficient+
              "received ~d msat but forwarding ~d needs ~d"
              incoming-amount-msat amount-to-forward-msat
              (minimum-incoming-msat policy amount-to-forward-msat)))

      ;; ---- Do we have enough time? -------------------------------------------
      ;;
      ;; This is the check that stops us being robbed.  We must have strictly
      ;; more time to claim the incoming HTLC than the downstream node has to
      ;; claim the outgoing one.  If the margin is too small, that node can sit
      ;; on the preimage until our incoming HTLC expires and only then claim the
      ;; outgoing one: we have paid and can no longer collect.
      ((< incoming-cltv-expiry (+ outgoing-cltv-expiry
                                  (policy-cltv-expiry-delta policy)))
       (%fail +incorrect-cltv-expiry+
              "incoming expiry ~d is less than outgoing ~d plus our delta ~d"
              incoming-cltv-expiry outgoing-cltv-expiry
              (policy-cltv-expiry-delta policy)))

      ;; An incoming HTLC that expires imminently cannot be safely claimed
      ;; on-chain if the downstream side misbehaves, because a force-close needs
      ;; confirmations we do not have time for.
      ((and current-height
            (<= incoming-cltv-expiry (+ current-height +min-final-cltv-margin+)))
       (%fail +expiry-too-soon+ "incoming expiry ~d is too close to height ~d"
              incoming-cltv-expiry current-height))

      ;; And one that expires absurdly far out locks our liquidity for free.
      ((and current-height
            (> incoming-cltv-expiry (+ current-height +max-cltv-expiry-delta+)))
       (%fail +expiry-too-far+ "incoming expiry ~d is too far beyond height ~d"
              incoming-cltv-expiry current-height))

      ;; ---- Can we actually afford it right now? ------------------------------
      ;;
      ;; These come LAST, and they are all temporary.  They describe our own
      ;; momentary state rather than anything the sender got wrong, and a sender
      ;; told "permanent" here would drop a perfectly good channel from its graph
      ;; because we happened to be busy.
      ((>= (outgoing-pending-htlcs outgoing) (outgoing-max-accepted-htlcs outgoing))
       (%fail +temporary-channel-failure+ "too many HTLCs in flight (~d)"
              (outgoing-pending-htlcs outgoing)))
      ((and (outgoing-max-in-flight-msat outgoing)
            (> (+ (outgoing-in-flight-msat outgoing) amount-to-forward-msat)
               (outgoing-max-in-flight-msat outgoing)))
       (%fail +temporary-channel-failure+ "would exceed max_htlc_value_in_flight"))
      ((> amount-to-forward-msat (outgoing-available-msat outgoing))
       (%fail +temporary-channel-failure+ "insufficient outgoing balance (~d msat)"
              (outgoing-available-msat outgoing)))

      (t (make-forward-decision :ok-p t)))))
