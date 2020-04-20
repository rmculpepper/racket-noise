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

    ;; connection : (U #f Connection (Bytes -> Connection)), mutated
    ;; If procedure, needs transcript (=> prologue) before connection is created.
    (field [connection #f])

    ;; --------------------

    ;; initialize : (U 'init 'switch 'retry) Protocol Boolean InfoHash -> Void
    (define/public (initialize reason protocol initiator? info)
      (define transcript-prefix
        (case reason
          [(init) #"NoiseSocketInit1"]
          [(switch) #"NoiseSocketInit2"]
          [(retry) #"NoiseSocketInit3"]
          [else (error 'initialize "bad reason: ~e" reason)]))
      (set! connection
            (lambda (transcript)
              (define prologue
                (bytes-append transcript-prefix transcript application-prologue))
              (new connection% (protocol protocol) (initiator? initiator?)
                   (info info) (prologue prologue)))))

    ;; add to transcript and initialize connection if not already initialized
    (define/private (do-transcript . bss)
      (when transcript-out
        (for ([bs (in-list bss)])
          (write-integer (bytes-length bs) 2 #f transcript-out)
          (write-bytes bs transcript-out))
        (when (procedure? connection)
          (set! connection (connection (get-output-bytes transcript-out))))))

    (define/public (discard-transcript!)
      (set! transcript-out #f))

    ;; --------------------

    (abstract write-frame) ;; Bytes [Boolean] -> Void
    (abstract read-frame)  ;; -> Bytes

    ;; --------------------

    ;; write-handshake-message : Bytes Bytes [Nat] -> Void
    (define/public (write-handshake-message negotiation [plaintext #""] [padded-len 0])
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

    ;; read-handshake-message : -> (values Bytes Bytes)
    (define/public (read-handshake-message)
      (define negotiation (read-handshake-negotiation-frame))
      (define message (read-handshake-noise-message-frame))
      (values negotiation message))

    (define/public (read-handshake-negotiation-frame)
      (define negotiation (read-frame))
      (do-transcript negotiation)
      negotiation)

    (define/public (read-handshake-noise-message-frame)
      (define noise-message (read-frame))
      (do-transcript noise-message)
      (define encrypted? (send connection next-payload-encrypted?))
      (define payload (send connection read-handshake-message noise-message))
      (if encrypted?
          (read-frame-from-bytes 'read-handshake-noise-message-frame payload)
          payload))

    ;; --------------------

    ;; write-transport-message : Bytes -> Void
    (define/public (write-transport-message payload)
      (write-frame (send connection write-transport-message payload)))

    ;; read-transport-message : -> Bytes
    (define/public (read-transport-message)
      (send connection read-transport-message (read-frame)))

    ;; ----------------------------------------
    ;; Forward to connection

    ;; FIXME: handle delayed connection construction
    (define/public (in-handshake-phase?) (send connection in-handshake-phase?))
    (define/public (in-transport-phase?) (send connection in-transport-phase?))
    (define/public (get-handshake-hash) (send connection get-handshake-hash))
    (define/public (can-write-message?) (send connection can-write-message?))
    (define/public (can-read-message?) (send connection can-read-message?))
    ))

;; read-frame-from-bytes : Bytes -> Bytes
(define (read-frame-from-bytes who bs)
  (when (< (bytes-length bs) 2)
    (error who "invalid frame (missing length bytes)"))
  (define len (integer-bytes->integer bs #f #t 0 2))
  (when (< (bytes-length bs) (+ 2 len))
    (error who "invalid frame"))
  (subbytes bs 2 (+ 2 len)))

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


;; NEW PLAN
;; add set-prologue to connection%
