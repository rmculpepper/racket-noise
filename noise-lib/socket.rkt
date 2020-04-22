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

    ;; transcript-out : #f/BytesOutputPort, mutated
    (field [transcript-out (open-output-bytes)])

    ;; connection : (U pre-connection% protocol-state%), mutated
    (field [connection (new pre-connection%)])

    ;; --------------------

    (field [sema (make-semaphore 1)])

    (define-syntax-rule (with-lock . body)
      ;; FIXME: kill connection on error?
      (call-with-semaphore sema (lambda () . body)))

    ;; --------------------

    ;; initialize : (U 'init 'switch 'retry) Protocol Boolean InfoHash -> Void
    (define/public (initialize reason protocol initiator? info)
      (with-lock
        (define prefix
          (case reason
            [(init) #"NoiseSocketInit1"]
            [(switch) #"NoiseSocketInit2"]
            [(retry) #"NoiseSocketInit3"]
            [else (error '|socket-base% initialize| "bad reason: ~e" reason)]))
        (send protocol check-info-keys '|socket-base% initialize| initiator? info)
        (unless (is-a? connection pre-connection%)
          (set! connection (new pre-connection%)))
        (send connection update! protocol initiator? info prefix application-prologue)))

    (define/public (close)
      (with-lock
        (set! connection #f)
        (set! transcript-out #f)))

    (define/public (discard-transcript!)
      (with-lock (set! transcript-out #f)))

    ;; add to transcript and complete connection if not already connected
    (define/private (-do-transcript . bss)
      (when transcript-out
        (for ([bs (in-list bss)])
          (cond [(bytes? bs)
                 (write-integer (bytes-length bs) 2 #f transcript-out)
                 (write-bytes bs transcript-out)]
                [(eq? bs 'try-connect)
                 (when (and (is-a? connection pre-connection%)
                            (send connection ready-to-connect?))
                   (set! connection
                         (send connection connect (get-output-bytes transcript-out))))]))))

    ;; --------------------

    (abstract -write-frame) ;; Bytes [Boolean] -> Void
    (abstract -read-frame)  ;; -> Bytes

    ;; --------------------

    ;; write-handshake-message : Bytes Bytes/#f [Nat] -> Void
    (define/public (write-handshake-message negotiation plaintext [padded-len 0])
      (-do-transcript negotiation 'try-connect)
      (-write-frame negotiation #f)
      (define noise-message
        (cond [(eq? plaintext #f) #""]
              [(send connection next-payload-encrypted?)
               (define plaintext-len (bytes-length plaintext))
               (send connection write-handshake-message
                     (bytes-append (integer->integer-bytes plaintext-len 2 #f #t)
                                   plaintext
                                   (crypto-random-bytes (max 0 (- padded-len plaintext-len)))))]
              [else (send connection write-handshake-message plaintext)]))
      (-do-transcript noise-message)
      (-write-frame noise-message))

    ;; --------------------

    ;; read-handshake-message : -> (values Bytes Bytes)
    (define/public (read-handshake-message)
      (define negotiation (read-handshake-negotiation))
      (define noise (read-handshake-noise 'decrypt))
      (values negotiation noise))

    (define/public (read-handshake-negotiation)
      (let ([nego (-read-frame)]) (-do-transcript nego) nego))

    (define/public (read-handshake-noise mode)
      (define noise-message (-read-frame))
      (-do-transcript 'try-connect noise-message)
      (let loop ([mode mode])
        (case mode
          [(decrypt)
           (define encrypted? (send connection next-payload-encrypted?))
           (define payload (send connection read-handshake-message noise-message))
           (if encrypted? (read-frame-from-bytes 'read-handshake-message payload) payload)]
          [(try-decrypt)
           (with-handlers ([auth-decrypt-exn? (lambda (e) 'bad)])
             (loop 'decrypt))]
          [(discard) (void)])))

    ;; --------------------

    ;; write-transport-message : Bytes -> Void
    (define/public (write-transport-message payload)
      (-write-frame (send connection write-transport-message payload)))

    ;; read-transport-message : -> Bytes
    (define/public (read-transport-message)
      (send connection read-transport-message (-read-frame)))

    ;; ----------------------------------------
    ;; Protocol state methods (forward)

    (define/public (in-handshake-phase?) (send connection in-handshake-phase?))
    (define/public (in-transport-phase?) (send connection in-transport-phase?))
    (define/public (get-handshake-hash) (send connection get-handshake-hash))
    (define/public (can-write-message?) (send connection can-write-message?))
    (define/public (can-read-message?) (send connection can-read-message?))
    (define/public (get-keys-info) (send connection get-keys-info))
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

;; A pre-connection builds a connection in two stages, while implementing part
;; of the protocol-state% interface.
(define pre-connection%
  (class object%
    (super-new)

    (define connector #f)
    (define initiator? #f)

    (define/public (update! protocol initr? info prefix suffix)
      (set! initiator? initr?)
      (set! connector
            (lambda (transcript)
              (define prologue (bytes-append prefix transcript suffix))
              (new protocol-state% (protocol protocol) (initiator? initr?)
                   (info info) (prologue prologue)))))

    (define/public (ready-to-connect?) (and connector #t))

    (define/public (connect transcript)
      (cond [connector (connector transcript)]
            [else (error 'connect "internal error: missing protocol etc")]))

    ;; Dummy versions of {read,write}-handshake-message before protocol selected
    (define/public (read-handshake-message data) data)

    ;; Protocol-state methods
    (define/public (in-handshake-phase?) #t)
    (define/public (in-transport-phase?) #f)
    (define/public (get-handshake-hash)
      (error 'get-handshake-hash "handshake is not finished (not connected)"))
    (define/public (can-write-message?)
      (if connector initiator? (error 'can-write-message? "not connected")))
    (define/public (can-read-message?)
      (if connector (not initiator?) (error 'can-read-messge? "not connected")))
    ))

;; ----------------------------------------

(define socket%
  (class socket-base%
    (init-field in out)
    (field [inr (make-binary-reader in)])
    (super-new)

    (define/override (-write-frame bs [flush? #t])
      (write-integer (bytes-length bs) 2 #f out)
      (write-bytes bs out)
      (when flush? (flush-output out)))

    (define/override (-read-frame)
      (define len (b-read-integer inr 2 #f))
      (b-read-bytes inr len))

    ))
