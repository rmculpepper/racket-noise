#lang racket/base
(require racket/class
         crypto
         crypto/all
         "protocol.rkt")

;;(crypto-factories (list decaf-factory nettle-factory))
(crypto-factories libcrypto-factory)

(define pattern "IK")

;; NN, NK, NNpsk0, XK, ...

(define protocol-name (format "Noise_~a_25519_ChaChaPoly_SHA512" pattern))
(define p (noise-protocol protocol-name))

(define psk (crypto-random-bytes 32))

(define alice-sk (send p generate-private-key))
(define alice-pub-bytes (send p pk->public-bytes alice-sk))

(define bob-sk (send p generate-private-key))
(define bob-pub-bytes (send p pk->public-bytes bob-sk))

(define alice-info (send p trim-info #t (hasheq 's alice-sk 'rs bob-pub-bytes)))
(define bob-info   (send p trim-info #f (hasheq 's bob-sk   'rs alice-pub-bytes)))

(define alice-h (send p new-handshake #t alice-info))
(define bob-h   (send p new-handshake #f bob-info))

(define msg1 (send alice-h write-handshake-message #"hello"))
(send bob-h read-handshake-message msg1)

(define msg2 (send bob-h write-handshake-message #"hello back"))
(send alice-h read-handshake-message msg2)

(let loop ([->? #t])
  (unless (and (send alice-h get-transport) (send bob-h get-transport))
    (define msg (send (if ->? alice-h bob-h) write-handshake-message #"..."))
    (send (if ->? bob-h alice-h) read-handshake-message msg)
    (printf "-- did another ~s handshake round\n" (if ->? '-> '<-))
    (loop (not ->?))))

(define alice-t (send alice-h get-transport))
(define bob-t (send bob-h get-transport))

(define msg3 (send alice-t write-message #"nice talking with you"))
(send bob-t read-message msg3)

(define msg4 (send bob-t write-message #"likewise"))
(send alice-t read-message msg4)
