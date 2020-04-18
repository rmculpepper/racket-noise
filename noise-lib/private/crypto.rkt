#lang racket/base
(require (for-syntax racket/base)
         racket/class
         racket/match
         racket/string
         racket/port
         racket/format
         ;; crypto
         (prefix-in crypto: crypto)
         binaryio/bytes
         "interfaces.rkt")
(provide (all-defined-out))

;; ----------------------------------------
;; Crypto support

(define KEYLEN 32)  ;; length of symmetric key
(define AUTHLEN 16) ;; length of auth tag
(define NONCELEN 8) ;; length of nonce
(define MAX-NONCE (- (expt 2 (* NONCELEN 8)) 2))
(define Z32 #"\0\0\0\0")

(define crypto%
  (class* object% (crypto<%>)
    (init-field di hkdfi ci pkp)
    (super-new)

    ;; ----

    (define/public (get-hashlen) (crypto:digest-size di))
    (define/public (digest data) (crypto:digest di data))

    (define/public (hkdf-n salt ikm n)
      (define HASHLEN (get-hashlen))
      (define km (crypto:kdf hkdfi ikm salt `((key-size ,(* n HASHLEN)))))
      (apply values
             (for/list ([i (in-range n)])
               (subbytes km (* i HASHLEN) (* (add1 i) HASHLEN)))))

    ;; ----

    (define big-endian-nonce?
      (case (car (send ci get-spec))
        [(aes) #t] [(chacha20-poly1305) #f] [else #f]))

    (define/public (nonce->bytes n)
      (bytes-append Z32 (integer->integer-bytes n 8 #f big-endian-nonce?)))

    (define/public (encrypt k n ad ptext)
      (crypto:encrypt ci k (nonce->bytes n) ptext #:aad ad #:auth-size AUTHLEN))

    (define/public (decrypt k n ad ctext)
      (crypto:decrypt ci k (nonce->bytes n) ctext #:aad ad #:auth-size AUTHLEN))

    (define/public (rekey k)
      (define nonce (make-bytes NONCELEN #xFF))
      (define zeros (make-bytes KEYLEN 0))
      (set! k (subbytes (encrypt k nonce #"" zeros) 0 KEYLEN)))

    ;; ----

    (define DHLEN ;; length of public key and shared secret
      (match (crypto:pk-parameters->datum pkp 'rkt-params)
        ['(ecx params x25519) 32]
        ['(ecx params x448) 56]
        [pk (error 'crypto% "unknown PK algorithm: ~e" pk)]))

    (define/public (get-dhlen) DHLEN)

    (define/public (generate-private-key)
      (crypto:generate-private-key pkp null))

    (define/public (dh sk pk)
      (crypto:pk-derive-secret sk pk))

    (define/public (pk->public-bytes pk)
      (match (crypto:pk-key->datum pk 'rkt-public)
        [(list 'ecx 'public _curve (? bytes? pub-bytes))
         pub-bytes]
        [_ (error 'pk->public-bytes "failed")]))

    (define/public (bytes->private-key bs)
      (define datum
        (match (crypto:pk-parameters->datum pkp 'rkt-params)
          ['(ecx params x25519)
           `(ecx private x25519 ,bs)]
          ['(ecx params x448)
           `(ecx private x448 ,bs)]
          [pk (error 'bytes->private-key "unsupported PK algorithm: ~e" pk)]))
      (crypto:datum->pk-key datum 'rkt-private))

    (define/public (datum->pk-key datum fmt)
      (crypto:datum->pk-key datum fmt (crypto:get-factory pkp)))
    ))
