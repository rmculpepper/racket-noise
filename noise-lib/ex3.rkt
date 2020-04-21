#lang racket/base
(require racket/class
         crypto
         crypto/all
         "protocol.rkt"
         "lingo.rkt")

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

(define alice (new lingo-socket% (in ->a) (out a->)))
(define bob (new lingo-socket% (in ->b) (out b->)))

(define alice-config
  (hasheq 'keys-info alice-info
          'initial-protocol p))

(define bob-config
  (hasheq 'keys-info bob-info
          'protocols (list p)))

(define bob-thread (thread (lambda () (send bob accept bob-config))))
(send alice connect alice-config)

(void (sync bob-thread))

;; ----

(send alice write-transport-message #"hello")
(send bob read-transport-message)

(send bob write-transport-message #"hello back")
(send alice read-transport-message)

(send alice write-transport-message #"nice talking with you")
(send bob read-transport-message)

(send bob write-transport-message #"likewise")
(send alice read-transport-message)
