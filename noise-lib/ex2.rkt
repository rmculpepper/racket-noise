#lang racket/base
(require racket/class
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

(define alice (noise-socket-handshake ->a a->))
(define bob   (noise-socket-handshake ->b b->))

(send alice initialize 'init p #t alice-info)
(send bob   initialize 'init p #f bob-info)

;; ----

(send alice write-handshake-message #"neg1" #"hello")
(send bob read-handshake-message)

(send bob write-handshake-message #"neg2" #"hello back")
(send alice read-handshake-message)

(list (send alice get-socket)
      (send bob get-socket))

(let loop ([->? #t])
  (unless (and (send alice get-socket) (send bob get-socket))
    (send (if ->? alice bob) write-handshake-message #"...")
    (send (if ->? bob alice) read-handshake-message)
    (printf "-- did another ~s handshake round\n" (if ->? '-> '<-))
    (loop (not ->?))))

(define alice-t (send alice get-socket))
(define bob-t (send bob get-socket))

(send alice-t write-message #"nice talking with you")
(send bob-t read-message)

(send bob-t write-message #"likewise")
(send alice-t read-message)
