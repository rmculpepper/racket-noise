#lang racket/base
(require racket/class
         crypto
         crypto/all
         "main.rkt")

(crypto-factories nettle-factory)

;; (define p (noise-protocol "Noise_NN_25519_ChaChaPoly_SHA512"))
;; (define p (noise-protocol "Noise_NK_25519_ChaChaPoly_SHA512"))
;; (define p (noise-protocol "Noise_NNpsk0_25519_ChaChaPoly_SHA512"))
(define p (noise-protocol "Noise_NN_25519_ChaChaPoly_SHA512"))

(define psk (crypto-random-bytes 32))

(define alice-sk (send p generate-private-key))
(define alice-pub-bytes (send p pk->public-bytes alice-sk))

(define bob-sk (send p generate-private-key))
(define bob-pub-bytes (send p pk->public-bytes bob-sk))

(define alice (send p new-initiator #:s alice-sk #:rs bob-pub-bytes (hash 'psk psk)))
(define bob (send p new-responder #:s bob-sk (hash 'psk psk)))

(define msg1 (send alice write-handshake-message #"hello"))
(send bob read-handshake-message msg1)

(define msg2 (send bob write-handshake-message #"hello back"))
(send alice read-handshake-message msg2)

(list (send alice in-handshake-phase?)
      (send bob in-handshake-phase?))

(define msg3 (send alice write-transport-message #"nice talking with you"))
(send bob read-transport-message msg3)

(define msg4 (send bob write-transport-message #"likewise"))
(send alice read-transport-message msg4)
