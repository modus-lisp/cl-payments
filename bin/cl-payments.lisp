;;;; bin/cl-payments.lisp — run a cl-payments node.
;;;;
;;;; All configuration comes from the environment, as cl-consensus's
;;;; bin/serve-node.lisp does, so this file is reusable across the devnet's
;;;; several node directories:
;;;;
;;;;   CLP_DIR      node directory, holding node.key and channels.sexp (required)
;;;;   CLP_PORT     port to listen on                        (default 9935)
;;;;   CLP_NETWORK  mainnet | testnet | signet | regtest     (default signet)
;;;;   CLP_BITCOIN_CLI  "bitcoin-cli -signet -datadir=..." — the chain view (optional)
;;;;   CLP_CONTROL_PORT localhost control socket, one form per line (optional)
;;;;   CLP_CONNECT  optional <node_id>@host:port to dial on startup
;;;;
;;;;   CLP_DIR=/mnt/lisp/signet/clp1 CLP_PORT=9931 \
;;;;     sbcl --load bin/cl-payments.lisp

(require :asdf)
(require :sb-posix)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-payments"))

(defun env (name &optional default) (or (uiop:getenv name) default))

(cl-payments.wire:select-network
 (intern (string-upcase (env "CLP_NETWORK" "signet")) :keyword))

(let* ((dir (or (env "CLP_DIR") (error "set CLP_DIR")))
       (port (parse-integer (env "CLP_PORT" "9935")))
       (node (cl-payments.node:make-node :dir dir :port port)))
  ;; Write our OWN pid, rather than letting the launching shell record what it
  ;; thinks it started.  `setsid nohup sbcl & echo $!` records setsid's pid, and
  ;; setsid forks — so the recorded pid belongs to a process that has already
  ;; exited, `kill` hits nothing, and the next start dies on address-in-use with
  ;; the previous daemon still holding the port.
  (with-open-file (s (merge-pathnames "clp.pid" (uiop:ensure-directory-pathname dir))
                     :direction :output :if-exists :supersede)
    (format s "~d~%" (sb-posix:getpid)))
  ;; A chain view, if we were told where bitcoind is.  Without one the daemon
  ;; still runs — it just cannot confirm fundings, see closes, or punish.
  (let ((cli (env "CLP_BITCOIN_CLI")))
    (when cli
      (setf (cl-payments.node:node-chain node) (cl-payments.chain:make-bitcoind cli))
      (format t "~&chain view: ~a~%" cli)))
  (cl-payments.node:start node)
  (when (cl-payments.node:node-chain node) (cl-payments.node:start-watcher node))
  ;; The control socket: one s-expression per line on localhost.
  (let ((cp (env "CLP_CONTROL_PORT")))
    (when cp (cl-payments.node:start-control-server node (parse-integer cp))))
  ;; Commands arrive as files; see RUN-COMMAND-LOOP.  Its own thread, so the
  ;; main one stays free to keep the process alive.
  (bordeaux-threads:make-thread (lambda () (cl-payments.node:run-command-loop node))
                                :name "clp-commands")
  (let ((uri (env "CLP_CONNECT")))
    (when uri
      ;; Dial on its OWN thread: this one has to stay free to keep the process
      ;; alive, and the dialling thread must outlive the connection it opens.
      (bordeaux-threads:make-thread
       (lambda ()
         (handler-case (cl-payments.node:connect-to node uri)
           (error (e) (format t "~&outbound to ~a failed: ~a~%" uri e))))
       :name "clp-outbound")))
  ;; The whole point of a daemon: do not exit.
  (loop (sleep 3600)))
