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

(define alice (send p new-connection #t alice-info))
(define bob   (send p new-connection #f bob-info))

(define msg1 (send alice write-handshake-message #"hello"))
(send bob read-handshake-message msg1)

(define msg2 (send bob write-handshake-message #"hello back"))
(send alice read-handshake-message msg2)

(list (send alice in-handshake-phase?)
      (send bob in-handshake-phase?))

(let loop ([->? #t])
  (when (or (send alice in-handshake-phase?) (send bob in-handshake-phase?))
    (define msg (send (if ->? alice bob) write-handshake-message #"..."))
    (send (if ->? bob alice) read-handshake-message msg)
    (printf "-- did another ~s handshake round\n" (if ->? '-> '<-))
    (loop (not ->?))))

(define msg3 (send alice write-transport-message #"nice talking with you"))
(send bob read-transport-message msg3)

(define msg4 (send bob write-transport-message #"likewise"))
(send alice read-transport-message msg4)
