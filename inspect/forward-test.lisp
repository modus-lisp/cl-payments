;;;; inspect/forward-test.lisp
;;;;
;;;; Phase 5 — the forwarding decision.
;;;;
;;;; Every check below corresponds to a way a node in the middle of a route
;;;; loses money or is used as a free relay.  That is the reason to test them
;;;; hard: a forwarding bug does not present as a crash or a rejected message.
;;;; It presents as a channel that quietly works — right up until someone
;;;; notices they can drain it.
;;;;
;;;; Two failure modes are worth naming, because they pull in opposite
;;;; directions and a test suite that only checks one of them is comfortable and
;;;; useless:
;;;;
;;;;   TOO STRICT — we reject payments we should have forwarded.  Costs us fees
;;;;   and gets our channel skipped, but nobody loses funds.  Presents as a
;;;;   channel nobody routes through.
;;;;
;;;;   TOO LENIENT — we forward payments we should have rejected.  Presents as a
;;;;   channel that works perfectly and then is drained.  Every check here has a
;;;;   paired test on the accepting side, so a mutation that simply says "yes" to
;;;;   everything cannot survive.

(in-package #:cl-payments.test)

(defun fwd-policy (&rest args)
  (apply #'fw:make-policy args))

(defun fwd (&rest args)
  "CHECK-FORWARD with defaults that are known-good, so each test can perturb one
   thing.  A test that had to spell out every parameter would hide which one it
   was actually about.

   The defaults are not invented.  They are the real route Core Lightning
   computed through our node on the devnet — `getroute` from cln3 to cln4 with
   the direct channel excluded returns cln3 -> clp3 -> cln4, paying us 1001001
   msat to forward 1000000 and leaving a CLTV margin of 40:

       291x1x0  amount_msat=1001001  delay=49
       300x1x0  amount_msat=1000000  delay=9

   So the baseline is a payment a second implementation independently decided
   was correct, using the policy we advertised in our own channel_update.  A
   fee formula that disagreed with CLN's would show up here as a baseline that
   does not forward, rather than as silently unroutable channels in production."
  (let ((defaults (list :incoming-amount-msat 1001001
                        :incoming-cltv-expiry 700
                        :amount-to-forward-msat 1000000
                        :outgoing-cltv-expiry 660
                        :policy (fwd-policy)
                        :outgoing (fw:make-outgoing :available-msat 5000000)
                        :current-height 600)))
    (loop for (k v) on args by #'cddr do (setf (getf defaults k) v))
    (apply #'fw:check-forward defaults)))

(defun fwd-ok-p (&rest args) (fw:forward-decision-ok-p (apply #'fwd args)))
(defun fwd-code (&rest args) (fw:forward-decision-failure-code (apply #'fwd args)))

(defun run-forward-tests ()
  ;; ---------------------------------------------------------------------------
  (with-gate ("forward: the baseline forwards")
    ;; If this fails, every other test in this file is vacuous — they all check
    ;; that perturbing the baseline breaks it.
    (check "a well-formed forward is accepted" (fwd-ok-p))
    ;; 1_000_000 msat at base 1000 + 1ppm = 1000 + 1 = 1001 msat fee.
    (check-equal "the fee is base plus proportional"
                 (fw:forwarding-fee (fwd-policy) 1000000) 1001)
    ;; Exactly the required amount must be enough: a > where >= belongs rejects
    ;; every payment computed correctly by the sender.
    (check "the exact minimum incoming amount is accepted"
           (fwd-ok-p :incoming-amount-msat 1001001))
    (check "one millisatoshi under the minimum is rejected"
           (eq :fee-insufficient
               (fw:failure-name (fwd-code :incoming-amount-msat 1001000)))))

  ;; ---------------------------------------------------------------------------
  (with-gate ("forward: fees")
    ;; Underpaying is asking us to subsidise the sender.  Our fee is the
    ;; difference between the two HTLCs and is fixed the moment we forward, so
    ;; there is no later opportunity to collect.
    (check "a sender paying no fee at all is rejected"
           (eq :fee-insufficient
               (fw:failure-name (fwd-code :incoming-amount-msat 1000000))))
    (check "fee_insufficient carries UPDATE so the sender can retry"
           (fw:failure-update-p (fwd-code :incoming-amount-msat 1000000)))
    (check "fee_insufficient is NOT permanent"
           (not (fw:failure-permanent-p (fwd-code :incoming-amount-msat 1000000))))
    ;; Overpaying is fine — we keep the excess. Rejecting it would fail payments
    ;; from senders using a stale, HIGHER fee than we now charge, which is the
    ;; safe direction for them to be wrong in.
    (check "overpaying is accepted" (fwd-ok-p :incoming-amount-msat 2000000))

    ;; The proportional part must FLOOR.  Rounding up demands a millisatoshi more
    ;; than any correct sender computes, and then every payment fails while the
    ;; advertised policy looks perfectly reasonable.
    (let ((p (fwd-policy :fee-base-msat 0 :fee-proportional-millionths 1)))
      (check-equal "999_999 msat at 1ppm floors to 0" (fw:forwarding-fee p 999999) 0)
      (check-equal "1_000_000 msat at 1ppm is 1" (fw:forwarding-fee p 1000000) 1)
      (check-equal "1_999_999 msat at 1ppm floors to 1" (fw:forwarding-fee p 1999999) 1))

    ;; A zero-fee policy is legal and must not be confused with "no policy".
    (let ((free (fwd-policy :fee-base-msat 0 :fee-proportional-millionths 0)))
      (check "a zero-fee channel forwards an equal amount"
             (fwd-ok-p :policy free :incoming-amount-msat 1000000))))

  ;; ---------------------------------------------------------------------------
  (with-gate ("forward: CLTV — the check that stops us being robbed")
    ;; This is the one that matters most.  We must have strictly more time to
    ;; claim the incoming HTLC than the downstream node has to claim the
    ;; outgoing one.  If the margin is too small, they can sit on the preimage
    ;; until our incoming HTLC expires and only THEN claim the outgoing one: we
    ;; have paid and can no longer collect.
    (check "exactly the required delta is accepted"
           (fwd-ok-p :incoming-cltv-expiry 700 :outgoing-cltv-expiry 660))
    (check "one block less than the delta is rejected"
           (eq :incorrect-cltv-expiry
               (fw:failure-name (fwd-code :incoming-cltv-expiry 699
                                          :outgoing-cltv-expiry 660))))
    ;; The dangerous case stated directly: the sender asks us to hand downstream
    ;; MORE time than we have ourselves.
    (check "an outgoing expiry LATER than the incoming one is rejected"
           (eq :incorrect-cltv-expiry
               (fw:failure-name (fwd-code :incoming-cltv-expiry 660
                                          :outgoing-cltv-expiry 700))))
    (check "equal expiries are rejected — a zero margin is no margin"
           (eq :incorrect-cltv-expiry
               (fw:failure-name (fwd-code :incoming-cltv-expiry 660
                                          :outgoing-cltv-expiry 660))))
    ;; More margin than we asked for is safe: it only gives us extra time.
    (check "more margin than required is accepted"
           (fwd-ok-p :incoming-cltv-expiry 900 :outgoing-cltv-expiry 660))
    ;; A larger advertised delta must actually be enforced, or advertising one
    ;; is theatre.
    (check "a larger cltv_expiry_delta is enforced"
           (eq :incorrect-cltv-expiry
               (fw:failure-name (fwd-code :policy (fwd-policy :cltv-expiry-delta 144)
                                          :incoming-cltv-expiry 700
                                          :outgoing-cltv-expiry 660)))))

  ;; ---------------------------------------------------------------------------
  (with-gate ("forward: expiry against the current chain tip")
    ;; An incoming HTLC that expires imminently cannot be safely claimed
    ;; on-chain if the downstream side misbehaves: a force-close needs
    ;; confirmations we do not have time for.  Accepting it is accepting a loss.
    (check "an incoming expiry at the current height is rejected"
           (eq :expiry-too-soon
               (fw:failure-name (fwd-code :current-height 700
                                          :incoming-cltv-expiry 700
                                          :outgoing-cltv-expiry 660))))
    (check "an incoming expiry already in the past is rejected"
           (eq :expiry-too-soon
               (fw:failure-name (fwd-code :current-height 800
                                          :incoming-cltv-expiry 700
                                          :outgoing-cltv-expiry 660))))
    (check "an expiry just inside the safety margin is rejected"
           (eq :expiry-too-soon
               (fw:failure-name (fwd-code :current-height 695
                                          :incoming-cltv-expiry 700
                                          :outgoing-cltv-expiry 660))))
    (check "an expiry just outside the safety margin is accepted"
           (fwd-ok-p :current-height 693 :incoming-cltv-expiry 700
                     :outgoing-cltv-expiry 660))

    ;; The other end: an absurdly distant expiry locks our liquidity for weeks at
    ;; no cost to the sender, who does not even have to complete the payment.
    (check "an expiry far in the future is rejected"
           (eq :expiry-too-far
               (fw:failure-name (fwd-code :current-height 600
                                          :incoming-cltv-expiry 100000
                                          :outgoing-cltv-expiry 660))))
    ;; expiry_too_far is NOT an UPDATE failure: no channel_update would make an
    ;; absurd expiry acceptable, so telling the sender to refresh our policy
    ;; would just make it retry identically.
    (check "expiry_too_far carries no UPDATE flag"
           (not (fw:failure-update-p fw:+expiry-too-far+)))

    ;; With no height known we cannot make either judgement, and must not
    ;; invent one — guessing would reject valid payments at random.
    (check "with no current height the tip checks are skipped"
           (fwd-ok-p :current-height nil :incoming-cltv-expiry 100000
                     :outgoing-cltv-expiry 660)))

  ;; ---------------------------------------------------------------------------
  (with-gate ("forward: the next hop")
    ;; unknown_next_peer is PERMANENT — the sender's map of the network is wrong
    ;; and retrying this route will fail identically.
    (check "an unknown outgoing channel is unknown_next_peer"
           (eq :unknown-next-peer
               (fw:failure-name (fwd-code :outgoing (fw:make-outgoing :known-p nil)))))
    (check "unknown_next_peer is permanent"
           (fw:failure-permanent-p fw:+unknown-next-peer+))

    ;; A disconnected peer is TEMPORARY.  Marking it permanent would evict our
    ;; channel from every sender's graph over a brief reconnect.
    (check "a disconnected peer is a temporary failure"
           (eq :temporary-channel-failure
               (fw:failure-name
                (fwd-code :outgoing (fw:make-outgoing :peer-connected-p nil
                                                      :available-msat 5000000)))))
    (check "temporary_channel_failure is not permanent"
           (not (fw:failure-permanent-p fw:+temporary-channel-failure+)))
    (check "a disabled channel says so"
           (eq :channel-disabled
               (fw:failure-name (fwd-code :policy (fwd-policy :enabled-p nil))))))

  ;; ---------------------------------------------------------------------------
  (with-gate ("forward: amount limits")
    (check "below htlc_minimum_msat is rejected"
           (eq :amount-below-minimum
               (fw:failure-name (fwd-code :policy (fwd-policy :htlc-minimum-msat 2000000)))))
    (check "exactly htlc_minimum_msat is accepted"
           (fwd-ok-p :policy (fwd-policy :htlc-minimum-msat 1000000)))
    (check "above htlc_maximum_msat is rejected"
           (eq :temporary-channel-failure
               (fw:failure-name (fwd-code :policy (fwd-policy :htlc-maximum-msat 500000)))))
    (check "exactly htlc_maximum_msat is accepted"
           (fwd-ok-p :policy (fwd-policy :htlc-maximum-msat 1000000))))

  ;; ---------------------------------------------------------------------------
  (with-gate ("forward: a malformed request is not a policy failure")
    ;; Being asked to forward MORE than we received is the sender trying to make
    ;; us pay the difference.  No channel_update would make it acceptable, so it
    ;; is a payload error rather than a policy one.
    (check "forwarding more than we received is rejected"
           (eq :invalid-onion-payload
               (fw:failure-name (fwd-code :incoming-amount-msat 1000
                                          :amount-to-forward-msat 1000000))))
    (check "a zero forward amount is rejected"
           (eq :invalid-onion-payload
               (fw:failure-name (fwd-code :amount-to-forward-msat 0))))
    (check "a negative forward amount is rejected"
           (eq :invalid-onion-payload
               (fw:failure-name (fwd-code :amount-to-forward-msat -1))))
    (check "invalid_onion_payload is permanent"
           (fw:failure-permanent-p fw:+invalid-onion-payload+)))

  ;; ---------------------------------------------------------------------------
  (with-gate ("forward: our own capacity, which is nobody's fault")
    ;; These are all TEMPORARY.  They describe our momentary state, not anything
    ;; the sender got wrong, and a sender told "permanent" here would drop a
    ;; perfectly good channel from its graph because we happened to be busy.
    (check "insufficient outgoing balance is temporary"
           (eq :temporary-channel-failure
               (fw:failure-name
                (fwd-code :outgoing (fw:make-outgoing :available-msat 500)))))
    (check "exactly enough balance is accepted"
           (fwd-ok-p :outgoing (fw:make-outgoing :available-msat 1000000)))
    (check "one msat short is rejected"
           (eq :temporary-channel-failure
               (fw:failure-name
                (fwd-code :outgoing (fw:make-outgoing :available-msat 999999)))))
    (check "max_accepted_htlcs is enforced"
           (eq :temporary-channel-failure
               (fw:failure-name
                (fwd-code :outgoing (fw:make-outgoing :available-msat 5000000
                                                      :pending-htlcs 30
                                                      :max-accepted-htlcs 30)))))
    (check "one below max_accepted_htlcs is accepted"
           (fwd-ok-p :outgoing (fw:make-outgoing :available-msat 5000000
                                                 :pending-htlcs 29
                                                 :max-accepted-htlcs 30)))
    ;; The in-flight limit is on the SUM including this HTLC, not on the HTLC
    ;; alone — checking only the new one lets many small HTLCs blow past it.
    (check "max_htlc_value_in_flight counts the new HTLC too"
           (eq :temporary-channel-failure
               (fw:failure-name
                (fwd-code :outgoing (fw:make-outgoing :available-msat 5000000
                                                      :in-flight-msat 500000
                                                      :max-in-flight-msat 1000000)))))
    (check "in-flight room for exactly this HTLC is accepted"
           (fwd-ok-p :outgoing (fw:make-outgoing :available-msat 5000000
                                                 :in-flight-msat 0
                                                 :max-in-flight-msat 1000000))))

  ;; ---------------------------------------------------------------------------
  (with-gate ("forward: failure codes match BOLT #4")
    ;; The literal numbers, because a code that is merely self-consistent is
    ;; useless — the value is what another implementation reads.
    (check-equal "temporary_channel_failure is 0x1007" fw:+temporary-channel-failure+ #x1007)
    (check-equal "unknown_next_peer is 0x400A"         fw:+unknown-next-peer+ #x400A)
    (check-equal "amount_below_minimum is 0x100B"      fw:+amount-below-minimum+ #x100B)
    (check-equal "fee_insufficient is 0x100C"          fw:+fee-insufficient+ #x100C)
    (check-equal "incorrect_cltv_expiry is 0x100D"     fw:+incorrect-cltv-expiry+ #x100D)
    (check-equal "expiry_too_soon is 0x100E"           fw:+expiry-too-soon+ #x100E)
    (check-equal "channel_disabled is 0x1014"          fw:+channel-disabled+ #x1014)
    (check-equal "expiry_too_far is 21"                fw:+expiry-too-far+ 21)
    (check-equal "invalid_onion_payload is 0x4016"     fw:+invalid-onion-payload+ #x4016)
    (check-equal "permanent_channel_failure is 0x4008" fw:+permanent-channel-failure+ #x4008)
    (check-equal "temporary_node_failure is 0x2002"    fw:+temporary-node-failure+ #x2002)
    ;; Flags are read off the code rather than tabulated, so this also checks
    ;; that a new code cannot be classified inconsistently with its own number.
    (check "the NODE flag distinguishes node failures from channel ones"
           (and (fw:failure-node-p fw:+temporary-node-failure+)
                (not (fw:failure-node-p fw:+temporary-channel-failure+)))))

  ;; ---------------------------------------------------------------------------
  (with-gate ("forward: policy is taken from the update we advertised")
    ;; If our internal policy and our advertised channel_update drift, senders
    ;; compute fees from the advertised numbers and we reject on the internal
    ;; ones — a channel that fails every payment for no visible reason.
    (let* ((k (secp:bytes-to-int (c:sha256 (c:ascii->bytes "forward-test/policy"))))
           (body (gs:channel-update-body
                  :chain-hash (w:chain-hash) :scid (gs:make-scid 1 1 1)
                  :timestamp 1756000000
                  :cltv-expiry-delta 144 :htlc-minimum-msat 1000
                  :fee-base-msat 500 :fee-proportional-millionths 10
                  :htlc-maximum-msat 990000000))
           (upd (gs:parse-channel-update (gs:encode-channel-update k body)))
           (p (fw:policy-from-update upd)))
      (check-equal "fee base round-trips" (fw:policy-fee-base-msat p) 500)
      (check-equal "proportional fee round-trips"
                   (fw:policy-fee-proportional-millionths p) 10)
      (check-equal "cltv delta round-trips" (fw:policy-cltv-expiry-delta p) 144)
      (check-equal "htlc minimum round-trips" (fw:policy-htlc-minimum-msat p) 1000)
      (check "the channel is enabled" (fw:policy-enabled-p p))
      ;; And the derived policy must actually be USED: 500 + 1_000_000*10/1e6 = 510.
      (check-equal "fees computed from the advertised policy"
                   (fw:forwarding-fee p 1000000) 510)
      (check "a payment paying the advertised fee is accepted"
             (fwd-ok-p :policy p :incoming-amount-msat 1000510
                       :incoming-cltv-expiry 900 :outgoing-cltv-expiry 660))
      (check "a payment one msat under the advertised fee is rejected"
             (eq :fee-insufficient
                 (fw:failure-name
                  (fwd-code :policy p :incoming-amount-msat 1000509
                            :incoming-cltv-expiry 900 :outgoing-cltv-expiry 660)))))

    ;; A disabled channel must survive the round trip, or we would keep
    ;; forwarding over a channel we told the network not to use.
    (let* ((k (secp:bytes-to-int (c:sha256 (c:ascii->bytes "forward-test/disabled"))))
           (body (gs:channel-update-body
                  :chain-hash (w:chain-hash) :scid (gs:make-scid 1 1 1)
                  :timestamp 1756000000 :channel-flags 2
                  :htlc-maximum-msat 990000000))
           (upd (gs:parse-channel-update (gs:encode-channel-update k body))))
      (check "a disabled channel_update yields a disabled policy"
             (not (fw:policy-enabled-p (fw:policy-from-update upd)))))))
