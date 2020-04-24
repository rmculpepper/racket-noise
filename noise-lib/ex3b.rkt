#lang racket/base
(require racket/class
         racket/promise
         crypto
         crypto/all
         "protocol.rkt"
         "socket.rkt")

;;(crypto-factories (list decaf-factory nettle-factory))
(crypto-factories libcrypto-factory)

(define pattern "IK")

;; NN, NK, NNpsk0, XK, ...

(define init-p (noise-protocol "Noise_IK_25519_ChaChaPoly_SHA512"))
(define alt-p (noise-protocol "Noise_XXfallback_25519_ChaChaPoly_SHA512"))

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
          'protocols (list init-p)
          'switch-protocols (list alt-p)))

(define bob-config
  (hasheq 'keys-info bob-info
          'protocols (list init-p)
          'switch-protocols (list alt-p)))

(define alice-p (delay/thread (noise-lingo-socket 'connect ->a a-> alice-config)))
(define bob (noise-lingo-socket 'accept ->b b-> bob-config))
(define alice (force alice-p))

;; ----

(send alice write-message #"hello")
(send bob read-message)

(send bob write-message #"hello back")
(send alice read-message)

(send alice write-message #"nice talking with you")
(send bob read-message)

(send bob write-message #"likewise")
(send alice read-message)
