;;;; inspect/graph-diff.lisp
;;;;
;;;; The Phase 3 milestone — our routing graph, diffed against a real node's.
;;;;
;;;; This is cl-consensus's "verify against a real node at every layer" applied
;;;; to BOLT #7.  We connect to a live peer, ask for its whole gossip stream,
;;;; verify every signature ourselves, build a graph, and then compare it
;;;; field-by-field with what `lightning-cli listchannels` says.
;;;;
;;;; Comparing counts would prove almost nothing — the interesting failures are
;;;; in the POLICY fields, where a misread offset still yields a plausible
;;;; number.  So this diffs the actual routing parameters: fee base, fee rate,
;;;; CLTV delta, and the HTLC bounds, per direction.
;;;;
;;;;   CL_PAYMENTS_PEER=<node_id>@127.0.0.1:9835 \
;;;;   LISTCHANNELS=/tmp/listchannels.json \
;;;;     sbcl --load inspect/graph-diff.lisp --quit

(require :asdf)
(asdf:initialize-source-registry
 (let ((here (make-pathname :name nil :type nil :defaults *load-truename*)))
   `(:source-registry (:tree ,(merge-pathnames "../" here))
                      (:tree ,(merge-pathnames "../../" here))
                      :inherit-configuration)))
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-payments"))

(defpackage #:graph-diff
  (:use #:cl)
  (:local-nicknames (#:c #:cl-payments.crypto) (#:w #:cl-payments.wire)
                    (#:p #:cl-payments.peer) (#:gs #:cl-payments.gossip))
  (:export #:run))

(in-package #:graph-diff)

(defvar *checks* 0)
(defvar *fails* 0)

(defun ok (label result &optional detail)
  (incf *checks*)
  (if result
      (format t "~&  ok    ~a~%" label)
      (progn (incf *fails*)
             (format t "~&  FAIL  ~a~@[  (~a)~]~%" label detail)))
  result)

(defun collect-graph (uri seconds)
  "Connect, ask for everything, and fold the stream into a router."
  (let* ((at (position #\@ uri)) (colon (position #\: uri :from-end t))
         (node-id (c:hex->bytes (subseq uri 0 at)))
         (host (subseq uri (1+ at) colon))
         (port (parse-integer (subseq uri (1+ colon))))
         (router (gs:make-router))
         (seen 0))
    (multiple-value-bind (key point) (c:generate-key)
      (declare (ignore point))
      (let ((peer (p:connect host port node-id key
                             :chain-hashes (list (w:chain-hash))
                             :log nil :read-loop nil)))
        (unwind-protect
             (progn
               (dolist (type (list gs:+msg-channel-announcement+
                                   gs:+msg-channel-update+
                                   gs:+msg-node-announcement+))
                 (let ((ty type))
                   (p:on peer ty
                         (lambda (pr payload) (declare (ignore pr))
                           (incf seen)
                           (gs:ingest router ty payload)))))
               (p:start-read-loop peer)
               (p:send-message peer gs:+msg-gossip-timestamp-filter+
                               (gs:encode-gossip-timestamp-filter (w:chain-hash)))
               (sleep seconds))
          (ignore-errors (p:disconnect peer)))))
    (values router seen)))

(defun read-listchannels (path)
  "CLN's `listchannels` as a list of plists, via a tiny shell-out to python —
   cl-payments has no JSON dependency and this is a test tool, not the node."
  (let ((out (with-output-to-string (s)
               (uiop:run-program
                (list "python3" "-c" "
import json,sys
d=json.load(open(sys.argv[1]))
for ch in d.get('channels',[]):
    print(ch['short_channel_id'], ch['source'], ch['destination'],
          ch['base_fee_millisatoshi'], ch['fee_per_millionth'],
          ch['delay'], ch['htlc_minimum_msat'], ch['htlc_maximum_msat'],
          str(ch['active']).lower())
" path)
                :output s))))
    (loop for line in (uiop:split-string (string-trim '(#\Newline) out) :separator '(#\Newline))
          unless (zerop (length line))
            collect (let ((parts (uiop:split-string line :separator " ")))
                      (list :scid (first parts) :source (second parts) :dest (third parts)
                            :base (parse-integer (fourth parts))
                            :ppm (parse-integer (fifth parts))
                            :delay (parse-integer (sixth parts))
                            :hmin (parse-integer (seventh parts))
                            :hmax (parse-integer (eighth parts)))))))

(defun our-directions (router)
  "Flatten our graph into the same shape CLN prints: one entry per DIRECTION."
  (let ((out '()))
    (maphash
     (lambda (k ch)
       (declare (ignore k))
       (dolist (dir '(0 1))
         (let ((pol (if (zerop dir) (gs:channel-policy-1 ch) (gs:channel-policy-2 ch))))
           (when pol
             ;; node_1/node_2 are ordered by their public keys, and the direction
             ;; bit says which of them is the SOURCE.  Getting this backwards
             ;; silently inverts every policy in the graph.
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

(defun find-dir (list scid source)
  (find-if (lambda (e) (and (string= (getf e :scid) scid)
                            (string-equal (getf e :source) source)))
           list))

(defun run (&optional (uri (or (uiop:getenv "CL_PAYMENTS_PEER")
                               (error "set CL_PAYMENTS_PEER")))
                      (listchannels (or (uiop:getenv "LISTCHANNELS")
                                        "/tmp/listchannels.json")))
  (setf *checks* 0 *fails* 0)
  (w:select-network (or (and (uiop:getenv "CL_PAYMENTS_NETWORK")
                             (intern (string-upcase (uiop:getenv "CL_PAYMENTS_NETWORK")) :keyword))
                        :signet))
  (format t "~&=== routing graph vs. Core Lightning ===~%")
  (multiple-value-bind (router seen) (collect-graph uri 25)
    (let ((theirs (read-listchannels listchannels))
          (ours (our-directions router)))
      (format t "~&~%  ingested ~d gossip messages; ~d rejected by signature check~%"
              seen (gs::router-rejected router))
      (format t "  ours:   ~d channel~:p, ~d node~:p, ~d directed edge~:p~%"
              (gs:router-channel-count router) (gs:router-node-count router) (length ours))
      (format t "  theirs: ~d directed edge~:p~%~%" (length theirs))

      ;; Nothing may enter the graph unverified, so a nonzero rejection count on
      ;; a healthy peer means WE are wrong, not the peer.
      (ok "every message the peer sent verified" (zerop (gs::router-rejected router))
          (format nil "~d rejected" (gs::router-rejected router)))
      (ok "same number of directed edges" (= (length ours) (length theirs))
          (format nil "ours ~d, theirs ~d" (length ours) (length theirs)))

      (dolist (t-edge theirs)
        (let* ((scid (getf t-edge :scid))
               (src (getf t-edge :source))
               (o-edge (find-dir ours scid src)))
          (if (null o-edge)
              (ok (format nil "~a from ~a..." scid (subseq src 0 12)) nil "missing from our graph")
              (dolist (field '(:dest :base :ppm :delay :hmin :hmax))
                (let ((a (getf o-edge field)) (b (getf t-edge field)))
                  (ok (format nil "~a ~a ~(~a~)" scid (subseq src 0 12) field)
                      (if (stringp b) (string-equal a b) (eql a b))
                      (format nil "ours ~a, theirs ~a" a b)))))))))
  (format t "~&~%~d check~:p, ~d failure~:p~%" *checks* *fails*)
  (zerop *fails*))

(unless (run) (uiop:quit 1))
