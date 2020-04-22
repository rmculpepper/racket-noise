#lang racket/base
(require racket/class
         racket/promise
         crypto
         crypto/all
         "protocol.rkt"
         "lingo.rkt")

;;(crypto-factories (list decaf-factory nettle-factory))
(crypto-factories libcrypto-factory)

(define pattern "IK")

;; NN, NK, NNpsk0, XK, ...

(define init-p (noise-protocol "Noise_IK_25519_ChaChaPoly_SHA512"))
(define alt-p (noise-protocol "Noise_XX_25519_ChaChaPoly_SHA512"))

(define psk (crypto-random-bytes 32))

(define alice-sk (send init-p generate-private-key))
(define alice-pub-bytes (send init-p pk->public-bytes alice-sk))

(define bob-sk (send init-p generate-private-key))
(define bob-pub-bytes (send init-p pk->public-bytes bob-sk))
(define bob-WRONG-pub (crypto-random-bytes 32))

(define alice-info (hasheq 's alice-sk 'rs bob-WRONG-pub))
(define bob-info   (hasheq 's bob-sk))

;; ----

(define-values (->b a->) (make-pipe))
(define-values (->a b->) (make-pipe))

(define alice-config
  (hasheq 'keys-info alice-info
          'initial-protocol init-p
          'retry-protocols (list alt-p)))

(define bob-config
  (hasheq 'keys-info bob-info
          'protocols (list init-p alt-p)))

(define alice-p (delay/thread (noise-lingo-connect ->a a-> alice-config)))
(define bob (noise-lingo-accept ->b b-> bob-config))
(define alice (force alice-p))

;; ----

(send alice write-transport-message #"hello")
(send bob read-transport-message)

(send bob write-transport-message #"hello back")
(send alice read-transport-message)

(send alice write-transport-message #"nice talking with you")
(send bob read-transport-message)

(send bob write-transport-message #"likewise")
(send alice read-transport-message)
