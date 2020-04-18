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
         "private/interfaces.rkt"
         "private/patterns.rkt"
         "private/protocol-name.rkt")
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

(define (length->bytes n) (integer->integer-bytes n 2 #t #f))

(define socket-state%
  (class object%
    (init-field initiator?
                info
                [transcript-header #"NoiseSocketInit1"]
                [application-prologue #""])
    (super-new)

    (define transcript-prefix #"") ;; Bytes, mutated
    (define transcript-out (open-output-bytes)) ;; #f/BytesOutputPort, mutated

    ;; connection :  (U Connection (Bytes -> Connection)), mutated
    ;; If procedure, needs prologue before connection is created.
    (field [connection (reinitialize 'init protocol)])

    ;; --------------------

    ;; reinitialize : (U 'init 'switch 'retry) Protocol -> Void
    (define/public (reinitialize reason protocol)
      (define transcript-prefix
        (case reason
          [(init) #"NoiseSocketInit1"]
          [(switch) #"NoiseSocketInit2"]
          [(retry) #"NoiseSocketInit3"]
          [else (error 'initialize "bad reason: ~e" reason)]))
      (set! connection
            (lambda (prologue)
              (define prologue
                (bytes-append transcript-prefix transcript application-prologue))
              (new connection% (initiator? initiator?) (protocol protocol)
                   (info info) (prologue prologue)))))

    ;; add to transcript and initialize connection if not already initialized
    (define/private (-do-transcript . bss)
      (for ([bs (in-list bss)])
        (write-bytes bs transcript-out))
      (when (procedure? connection)
        (set! connection (connection (get-output-bytes transcript-out)))))

    ;; --------------------

    ;; write-handshake-message : Bytes Bytes [Nat] -> Bytes
    (define/public (write-handshake-message negotiation [plaintext #""] [padded-len 0])
      (define negotiation-len (length->bytes negotiation))
      (when transcript (-do-transcript negotiation-len negotiation))
      (define message
        (send connection write-handshake-message
              (cond [(send connection next-payload-encrypted?)
                     (define plaintext-len (bytes-length plaintext))
                     (bytes-append (length->bytes plaintext-len)
                                   plaintext
                                   (crypto-random-bytes (max 0 (- padded-len plaintext-len))))]
                    [else plaintext])))
      (define message-len (length->bytes (bytes-length message)))
      (when transcript (-do-transcript message-len message))
      (bytes-append negotiation-len
                    negotiation
                    message-len
                    message))

    ;; peek-handshake-message : Bytes -> Bytes
    ;; Note: does not write to transcript.
    (define/public (peek-handshake-negotiation msg)
      (define msg-in (open-input-bytes msg))
      (define negotiation-len (read-integer 2 #t msg-in))
      (define negotiation (read-bytes* negotiation-len msg-in))
      negotiation)

    ;; read-handshake-message : Bytes -> (values Bytes Bytes)
    (define/public (read-handshake-message msg)
      (define msg-in (open-input-bytes msg))
      (define negotiation-len (read-integer 2 #t msg-in))
      (define negotiation (read-bytes* negotiation-len msg-in))
      (when transcript (-do-transcript (length->bytes negotiation-len) negotiation))
      (define message-len (read-integer 2 #t msg-in))
      (define message (read-bytes* message-len msg-in))
      (unless (eof-object? (peek-byte msg-in))
        (error 'read-handshake-message "bytes left over"))
      (when transcript (-do-transcript (length->bytes message-len) message))
      (define encrypted? (send connection next-payload-encrypted?))
      (define payload (send connection read-handshake-message message))
      (values negotiation
              (cond [encrypted?
                     (define payload-in (open-input-bytes payload))
                     (define body-len (read-integer 2 #t payload-in))
                     (read-bytes* body-len payload-in)]
                    [else payload])))

    ;; write-transport-message : Bytes -> Bytes
    (define/public (write-transport-message payload)
      (send connection write-transport-message payload))

    ;; read-transport-message : Bytes -> Bytes
    (define/public (read-transport-message msg)
      (send connection read-transport-message msg))
    ))
