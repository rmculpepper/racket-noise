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

(define protocol-name (format "Noise_~a_25519_ChaChaPoly_SHA512" pattern))
(define p (noise-protocol protocol-name))

(define psk (crypto-random-bytes 32))

(define alice-sk (send p generate-private-key))
(define alice-pub-bytes (send p pk->public-bytes alice-sk))

(define bob-sk (send p generate-private-key))
(define bob-pub-bytes (send p pk->public-bytes bob-sk))

(define alice-info (send p trim-info #t (hasheq 's alice-sk 'rs bob-pub-bytes)))
(define bob-info   (send p trim-info #f (hasheq 's bob-sk   'rs alice-pub-bytes)))

;; ----

(define-values (->b a->) (make-pipe))
(define-values (->a b->) (make-pipe))

(define alice-config
  (hasheq 'keys-info alice-info
          'protocols (list p)))

(define bob-config
  (hasheq 'keys-info bob-info
          'protocols (list p)))

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
