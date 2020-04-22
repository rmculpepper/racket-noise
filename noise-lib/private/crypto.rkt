#lang racket/base
(require (for-syntax racket/base)
         racket/class
         racket/match
         racket/string
         racket/port
         racket/format
         (rename-in crypto
                    [digest crypto:digest]
                    [encrypt crypto:encrypt]
                    [decrypt crypto:decrypt]
                    [generate-private-key crypto:generate-private-key])
         binaryio/bytes
         "interfaces.rkt")
(provide (all-defined-out))

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

    (define/public (get-hashlen) (digest-size di))
    (define/public (digest data) (crypto:digest di data))

    (define/public (hkdf-n salt ikm n)
      (define HASHLEN (get-hashlen))
      (define km (kdf hkdfi ikm salt `((key-size ,(* n HASHLEN)))))
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
      (match (pk-parameters->datum pkp 'rkt-params)
        ['(ecx params x25519) 32]
        ['(ecx params x448) 56]
        [pk (error 'crypto% "unknown PK algorithm: ~e" pk)]))

    (define/public (get-dhlen) DHLEN)

    (define/public (generate-private-key)
      (crypto:generate-private-key pkp null))

    (define/public (dh sk pk)
      (pk-derive-secret sk pk))

    (define/public (pk->public-bytes pk)
      (match (pk-key->datum pk 'rkt-public)
        [(list 'ecx 'public _curve (? bytes? pub-bytes))
         pub-bytes]
        [_ (error 'pk->public-bytes "failed")]))
    ))

;; ----------------------------------------

(define (noise-crypto d c pk #:factories [factories (crypto-factories)])
  (define (fail what spec)
    (error 'noise-crypto "unable to get implementation\n  ~a: ~v" what spec))
  (define di
    (cond [(digest-impl? d) d]
          [(get-digest d factories) => values]
          [else (fail "digest" d)]))
  (define hkdfi
    (or (get-kdf `(hkdf ,(send di get-spec)) (get-factory di))
        (fail "KDF" `(hkdf ,(send di get-spec)))))
  (define ci
    (cond [(cipher-impl? c) c]
          [(get-cipher c factories) => values]
          [else (fail "cipher" c)]))
  (define pkp
    (match pk
      [(? pk-parameters?) pk]
      [(cons pkspec pkconfig)
       (define pki (or (get-pk pkspec factories) (fail "PK algorithm" pk)))
       (generate-pk-parameters pki pkconfig)]))
  (new crypto% (di di) (hkdfi hkdfi) (ci ci) (pkp pkp)))

(define (check-crypto who crypto0 ds cs pk)
  (define (bad what wanted got)
    (error who "crypto object contains wrong ~a implementation\n  expected: ~e\n  got: ~e"
           what wanted got))
  (let ([c-ds (send (get-field di crypto0) get-spec)])
    (unless (equal? ds c-ds) (error "digest" ds c-ds)))
  (let ([c-cs (send (get-field ci crypto0) get-spec)])
    (unless (equal? cs c-cs) (error "cipher" cs c-cs)))
  (let ([c-hkdfs (send (get-field hkdfi crypto0) get-spec)])
    (unless (equal? `(hkdf ,ds) c-hkdfs) (error "KDF" `(hkdf ,ds) c-hkdfs)))
  (let ([c-pkpd (pk-parameters->datum (get-field pkp crypto0) 'rkt-params)])
    (match pk
      [`(ecx (curve ,curve))
       (unless (equal? `(ecx params ,curve) c-pkpd)
         (bad "PK parameters" `(ecx params ,curve) c-pkpd))]))
  crypto0)
