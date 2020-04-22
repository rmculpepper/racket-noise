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
         "interfaces.rkt"
         "patterns.rkt"
         "protocol-name.rkt"
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

(define noise-socket-handshake-state%
  (class* object% (socket-handshake-state<%>)
    (init-field io [application-prologue #""])
    (super-new)

    ;; transcript-out : #f/BytesOutputPort, mutated
    (field [transcript-out (open-output-bytes)])

    ;; hstate : (U pre-handshake% noise-handshake-state%), mutated
    (field [hstate (new pre-handshake%)])

    ;; socket : (U #f noise-socket%), mutated
    (field [socket #f])

    ;; --------------------

    ;; initialize : (U 'init 'switch 'retry) Protocol Boolean InfoHash -> Void
    (define/public (initialize reason protocol initiator? info)
      (define prefix
        (case reason
          [(init) #"NoiseSocketInit1"]
          [(switch) #"NoiseSocketInit2"]
          [(retry) #"NoiseSocketInit3"]))
      (send protocol check-info-keys 'initialize initiator? info)
      (unless (is-a? hstate pre-handshake%)
        (set! hstate (new pre-handshake%)))
      (send hstate update! protocol initiator? info prefix application-prologue))

    (define/public (discard-transcript!)
      (set! transcript-out #f))

    ;; add to transcript and begin handshake if not already begun
    (define/private (-do-transcript . xs)
      (when transcript-out
        (for ([x (in-list xs)])
          (cond [(bytes? x)
                 (write-integer (bytes-length x) 2 #f transcript-out)
                 (write-bytes x transcript-out)]
                [(eq? x 'try-begin)
                 (when (and (is-a? hstate pre-handshake%) (send hstate ready?))
                   (define transcript (get-output-bytes transcript-out))
                   (set! hstate (send hstate make-handshake transcript)))]))))

    ;; --------------------

    (define/private (-write-frame buf [flush? #t]) (send io write-frame buf flush?))
    (define/private (-read-frame) (send io read-frame))

    ;; --------------------

    (define/public (get-socket)
      (cond [socket socket]
            [(send hstate get-transport)
             => (lambda (transport)
                  (set! socket (new noise-socket% (io io) (transport transport)))
                  socket)]
            [else #f]))

    ;; --------------------

    ;; write-handshake-message : Bytes Bytes/#f -> Void
    (define/public (write-handshake-message negotiation plaintext)
      (-do-transcript negotiation 'try-begin)
      (-write-frame negotiation #f)
      (define noise-message
        (cond [(eq? plaintext #f) #""]
              [else (send hstate write-handshake-message plaintext)]))
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
      (-do-transcript 'try-begin noise-message)
      (let loop ([mode mode])
        (case mode
          [(decrypt) (send hstate read-handshake-message noise-message)]
          [(try-decrypt)
           (with-handlers ([auth-decrypt-exn? (lambda (e) 'bad)])
             (loop 'decrypt))]
          [(discard) 'discarded])))

    ;; ----------------------------------------
    ;; Protocol state methods (forward)

    (define/public (can-write-message?) (send hstate can-write-message?))
    (define/public (can-read-message?) (send hstate can-read-message?))
    (define/public (get-keys-info) (send hstate get-keys-info))
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

;; ----------------------------------------

;; A pre-handshake builds a handshake in two stages, while
;; implementing part of the handshake-state% interface.
(define pre-handshake%
  (class object%
    (super-new)

    (define maker #f)
    (define initiator? #f)

    (define/public (update! protocol initr? info prefix suffix)
      (set! initiator? initr?)
      (set! maker
            (lambda (transcript)
              (define prologue (bytes-append prefix transcript suffix))
              (new noise-handshake-state% (protocol protocol) (initiator? initr?)
                   (info info) (prologue prologue)))))

    (define/public (ready?) (and maker #t))

    (define/public (make-handshake transcript)
      (cond [maker (maker transcript)]
            [else (error 'make-handshake "internal error: missing protocol etc")]))

    ;; Dummy versions of {read,write}-handshake-message before protocol selected
    (define/public (read-handshake-message data) data)

    ;; Protocol-state methods
    (define/public (get-transport) #f)
    (define/public (can-write-message?)
      (if maker initiator? (error 'can-write-message? "not ready")))
    (define/public (can-read-message?)
      (if maker (not initiator?) (error 'can-read-messge? "not ready")))
    ))

;; ----------------------------------------

(define io%
  (class* object% (#;io<%>)
    (init-field in out)
    (field [inr (make-binary-reader in)])
    (super-new)

    (define/public (write-frame bs [flush? #t])
      (write-integer (bytes-length bs) 2 #f out)
      (write-bytes bs out)
      (when flush? (flush-output out)))

    (define/public (read-frame)
      (define len (b-read-integer inr 2 #f))
      (b-read-bytes inr len))

    ))

(define (noise-socket-handshake in out)
  (define io (new io% (in in) (out out)))
  (new noise-socket-handshake-state% (io io)))

;; ============================================================

(define noise-socket%
  (class* object% (socket<%>)
    (init-field io transport)
    (super-new)

    ;; write-message : Bytes -> Void
    (define/public (write-message plaintext [padding 0])
      (send io write-frame
            (send transport write-message
                  (bytes-append (integer->integer-bytes (bytes-length plaintext) 2 #f #t)
                                plaintext
                                (crypto-random-bytes padding)))))

    ;; read-message : -> Bytes
    (define/public (read-message)
      (define payload (send transport read-message (send io read-frame)))
      (read-frame-from-bytes 'read-message payload))
    ))
