#lang racket/base
(require (for-syntax racket/base)
         racket/class
         racket/match
         racket/string
         racket/port
         racket/format
         crypto
         (prefix-in crypto: crypto)
         binaryio/bytes
         binaryio/integer
         binaryio/reader
         "private/interfaces.rkt"
         "private/patterns.rkt"
         "private/protocol-name.rkt"
         "protocol.rkt")
(provide (all-defined-out))

;; Reference: https://noisesocket.org/spec/noisesocket/
;;   Revision: 2draft, 2018-03-04

(define MAX-TRANSPORT-LEN (sub1 (expt 2 16)))
(define MAX-PLAINTEXT-LEN (- MAX-TRANSPORT-LEN 2))

(define (noise-plaintext-message/c x)
  (and (bytes? x) (<= (bytes-length x) MAX-PLAINTEXT-LEN)))

;; NoiseSocket handshake message:
;; - 2 byte length (unsigned, big-endian)
;; - negotiation
;; - 2 byte length
;; - Noise message

;; NoiseSocket transport message:
;; - 2 byte length
;; - Noise message

;; Payload format
;; - 2 byte length
;; - payload
;; - padding -- random, must be discarded

(define socket-base%
  (class object%
    (init-field [application-prologue #""])
    (super-new)

    (define transcript-out (open-output-bytes)) ;; #f/BytesOutputPort, mutated

    ;; connection : (U #f pre-connection% connection%), mutated
    (field [connection #f])

    ;; --------------------

    ;; initialize : (U 'init 'switch 'retry) Protocol Boolean InfoHash -> Void
    (define/public (initialize reason protocol initiator? info)
      (define transcript-prefix
        (case reason
          [(init) #"NoiseSocketInit1"]
          [(switch) #"NoiseSocketInit2"]
          [(retry) #"NoiseSocketInit3"]
          [else (error '|socket-base% initialize| "bad reason: ~e" reason)]))
      (send protocol check-info-keys '|socket-base% initialize| initiator? info)
      (set! connection
            (new pre-connection% (protocol protocol) (initiator? initiator?)
                 (prefix transcript-prefix) (suffix application-prologue)
                 (info info))))

    ;; add to transcript and complete connection if not already connected
    (define/private (do-transcript . bss)
      (when transcript-out
        (for ([bs (in-list bss)])
          (write-integer (bytes-length bs) 2 #f transcript-out)
          (write-bytes bs transcript-out))
        (when (is-a? connection pre-connection%)
          (set! connection (send connection connect (get-output-bytes transcript-out))))))

    (define/public (discard-transcript!)
      (set! transcript-out #f))

    (define/public (check-initialized who)
      (unless connection (error who "not initialized")))

    ;; --------------------

    (abstract write-frame) ;; Bytes [Boolean] -> Void
    (abstract read-frame)  ;; -> Bytes

    ;; --------------------

    ;; write-handshake-message : Bytes Bytes [Nat] -> Void
    (define/public (write-handshake-message negotiation [plaintext #""] [padded-len 0])
      (check-initialized 'write-handshake-message)
      (do-transcript negotiation)
      (write-frame negotiation #f)
      (define noise-message
        (send connection write-handshake-message
              (cond [(send connection next-payload-encrypted?)
                     (define plaintext-len (bytes-length plaintext))
                     (bytes-append (integer->integer-bytes plaintext-len 2 #f #t)
                                   plaintext
                                   (crypto-random-bytes (max 0 (- padded-len plaintext-len))))]
                    [else plaintext])))
      (do-transcript noise-message)
      (write-frame noise-message))

    ;; --------------------

    ;; read-handshake-message : -> (values Bytes (U Bytes 'bad))
    (define/public (read-handshake-message #:allow-bad-noise-message? [allow-bad? #f])
      (check-initialized 'read-handshake-message)
      (define negotiation (read-frame))
      (do-transcript negotiation)
      (define noise-message (read-frame))
      (do-transcript noise-message)
      (define encrypted? (send connection next-payload-encrypted?))
      (define payload
        (with-handlers ([auth-decrypt-exn? (lambda (e) (if allow-bad? 'bad (raise e)))])
          (send connection read-handshake-message noise-message)))
      (define message
        (cond [(eq? payload 'bad) 'bad]
              [encrypted?
               (read-frame-from-bytes 'read-handshake-message payload)]
              [else payload]))
      (values negotiation message))

    ;; --------------------

    ;; write-transport-message : Bytes -> Void
    (define/public (write-transport-message payload)
      (check-initialized 'write-transport-message)
      (write-frame (send connection write-transport-message payload)))

    ;; read-transport-message : -> Bytes
    (define/public (read-transport-message)
      (check-initialized 'read-transport-message)
      (send connection read-transport-message (read-frame)))

    ;; ----------------------------------------
    ;; Connection-state methods (forward to connection)

    (define-syntax-rule (forward m a ...) (send (or connection not-connected) m a ...))
    (define/public (in-handshake-phase?) (forward in-handshake-phase?))
    (define/public (in-transport-phase?) (forward in-transport-phase?))
    (define/public (get-handshake-hash) (forward get-handshake-hash))
    (define/public (can-write-message?) (forward can-write-message?))
    (define/public (can-read-message?) (forward can-read-message?))
    ))

(define (auth-decrypt-exn? e)
  (and (exn? e) (regexp-match? #rx"authenticated decryption failed" (exn-message e))))

;; read-frame-from-bytes : Bytes -> Bytes
(define (read-frame-from-bytes who bs)
  (when (< (bytes-length bs) 2)
    (error who "invalid frame (missing length bytes)"))
  (define len (integer-bytes->integer bs #f #t 0 2))
  (when (< (bytes-length bs) (+ 2 len))
    (error who "invalid frame"))
  (subbytes bs 2 (+ 2 len)))

(define not-connected%
  (class object%
    (super-new)
    ;; Connection-state methods
    (define/public (in-handshake-phase?) #f)
    (define/public (in-transport-phase?) #f)
    (define/public (get-handshake-hash)
      (error 'get-handshake-hash "handshake is not finished (not connected)"))
    (define/public (can-write-message?) (error 'can-write-message? "not connected"))
    (define/public (can-read-message?) (error 'can-read-messge? "not connected"))
    ))

(define not-connected (new not-connected%))

;; A pre-connection needs transcript (=> prologue) to create connection.
(define pre-connection%
  (class object%
    (init-field protocol initiator? info prefix suffix)
    (super-new)

    (define/public (connect transcript)
      (define prologue (bytes-append prefix transcript suffix))
      (new connection% (protocol protocol) (initiator? initiator?)
           (info info) (prologue prologue)))

    ;; Connection-state methods
    (define/public (in-handshake-phase?) #f)
    (define/public (in-transport-phase?) #f)
    (define/public (get-handshake-hash)
      (error 'get-handshake-hash "handshake is not finished"))
    ;; The following methods answer from the perspective of the socket, which
    ;; implicitly calls connect. That is, these answer whose turn it is, not
    ;; whether connection is initialized. (FIXME: maybe rename methods?)
    (define/public (can-write-message?) initiator?)
    (define/public (can-read-message?) (not initiator?))
    ))

;; ----------------------------------------

(define socket%
  (class socket-base%
    (init-field in out)
    (field [inr (make-binary-reader in)])
    (super-new)

    (define/override (write-frame bs [flush? #t])
      (write-integer (bytes-length bs) 2 #f out)
      (write-bytes bs out)
      (when flush? (flush-output out)))

    (define/override (read-frame)
      (define len (b-read-integer inr 2 #f))
      (b-read-bytes inr len))

    ))
