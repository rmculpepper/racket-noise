#lang racket/base
(require racket/match racket/string racket/format)
(provide parse-protocol
         make-protocol-name)

(define noise-protocol-rx
  (let ([algs-rx "([a-zA-Z0-9/]+(?:[+][a-zA-Z0-9/]+)*)"])
    (regexp (string-append
             "Noise_"
             "([A-Z0-9]+)" ;; pattern
             "([a-z0-9]+(?:[+][a-z0-9]+)*)?" ;; pattern extensions
             "_" algs-rx ;; pk algs
             "_" algs-rx ;; cipher algs
             "_" algs-rx ;; digest algs
             ))))

(define (parse-protocol str)
  (define (split s) (string-split s #rx"[+]" #:trim? #f))
  (define (single what s mapping)
    (match (split s)
      [(list v) (noise->crypto 'noise-protocol v mapping what)]
      [_ (error 'noise-protocol "multiple ~as unsupported\n  protocol: ~e" what str)]))
  (match (regexp-match noise-protocol-rx str)
    [(list _ pattern ext pks cis dis)
     (define exts (split (or ext "")))
     (define pk (single "PK algorithm" pks pk-mapping))
     (define ci (single "cipher" cis cipher-mapping))
     (define di (single "digest algorithm" dis digest-mapping))
     (list (string->symbol pattern) (map string->symbol exts) pk ci di)]
    [v (error 'noise-protocol "bad protocol name: ~e => ~e" str v)]))

(define pk-mapping
  '(["25519" (ecx . ((curve x25519)))]
    ["448"   (ecx . ((curve x448)))]))

(define cipher-mapping
  '(["ChaChaPoly" (chacha20-poly1305 stream)]
    ["AESGCM"     (aes gcm)]))

(define digest-mapping
  '(["SHA256" sha256]
    ["SHA512" sha512]
    ["BLAKE2s" blake2s-256]
    ["BLAKE2b" blake2b-512]))

(define (noise->crypto who name mapping what)
  (cond [(assoc name mapping) => cadr]
        [else (error who "unknown Noise ~a name: ~e" what name)]))

(define (crypto->noise who spec mapping what)
  (cond [(assoc spec (map reverse mapping)) => cadr] ;; FIXME?
        [else (error who "cannot translate to Noise ~a name: ~e" what spec)]))

(define (make-protocol-name pattern exts pk ci di)
  (define who 'make-protocol-name)
  (string->immutable-string
   (format "Noise_~a~a_~a_~a_~a"
           pattern (string-join (map ~a exts) "+")
           (crypto->noise who pk pk-mapping "PK algorithm")
           (crypto->noise who ci cipher-mapping "cipher")
           (crypto->noise who di digest-mapping "digest"))))
