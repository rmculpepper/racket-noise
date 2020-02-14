#lang racket/base
(require racket/class
         racket/match
         racket/string
         racket/port
         racket/format
         crypto
         (prefix-in crypto: crypto)
         binaryio/bytes
         "private/patterns.rkt")
(provide (all-defined-out))

;; Reference: http://www.noiseprotocol.org/noise.html
;;   Revision: 34, Date: 2018-07-11

;; ----------------------------------------
;; Crypto support

(define DHLEN 32)   ;; length of public key
(define KEYLEN 32)  ;; length of symmetric key
(define AUTHLEN 16) ;; length of auth tag
(define NONCELEN 8) ;; length of nonce
(define MAX-NONCE (- (expt 2 (* NONCELEN 8)) 2))
(define Z32 #"\0\0\0\0")

(define crypto%
  (class object%
    (init ds cs pk)
    (init factories)
    (super-new)

    (field [di (or (get-digest ds factories) (fail "digest" ds))]
           [ci (or (get-cipher cs factories) (fail "cipher" cs))]
           [pkp (with-handlers ([exn:fail? (lambda () (fail "PK" pk))])
                  (generate-pk-parameters (car pk) (cdr pk)))]
           [hkdfi (or (get-kdf `(hkdf ,ds) factories) (fail "KDF" `(hkdf ,ds)))])

    (define big-endian-nonce?
      (case (car cs) [(aes) #t] [(chacha20-poly1305) #f] [else #f]))

    (define/private (fail what spec)
      (error 'crypto% "unable to get implementation\n  ~a: ~v" what spec))

    ;; ----

    (define/public (get-hashlen) (digest-size di))
    (define/public (digest data) (crypto:digest di data))

    (define/public (hkdf-n salt ikm n)
      (define HASHLEN (get-hashlen))
      (define km (kdf hkdfi ikm salt `((key-size ,(* n HASHLEN)))))
      (apply values
             (for/list ([i (in-range n)])
               (subbytes km (* i HASHLEN) (* (add1 i) HASHLEN)))))

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

    (define/public (generate-private-key)
      (crypto:generate-private-key pkp null))

    (define/public (dh sk pk)
      (pk-derive-secret sk pk))

    (define/public (pk->public-bytes pk)
      (match (pk-key->datum pk 'rkt-public)
        [(list 'ecx 'public curve (? bytes pub-bytes))
         pub-bytes]
        [_ (error 'pk->public-bytes "failed")]))
    ))

(define (make-crypto ds cs pk #:factories [factories (crypto-factories)])
  (new crypto% (ds ds) (cs cs) (pk pk) (factories factories)))

;; ----------------------------------------
;; Noise protocols by name

(define protocol%
  (class object%
    (init-field crypto)
    (super-new)

    (define/public (new-party initiator? [info #hasheq()]
                              #:s [s #f] #:e [e #f])
      (let* ([info (if s (hash-set info 's s) info)]
             [info (if e (hash-set info 'e e) info)])
        (new party% (crypto crypto) (info info))))

    (define/public (new-initiator [info #hasheq()] #:s [s #f] #:e [e #f])
      (new-party #t info #:s s #:e e))
    (define/public (new-responder [info #hasheq()] #:s [s #f] #:e [e #f])
      (new-party #f info #:s s #:e e))
    ))

(define party%
  (class object%
    (init crypto info)
    (super-new)

    (define state #f)
    (define sema (make-semaphore 1))
    (define-syntax-rule (with-lock . body)
      ;; FIXME: kill connection on error
      (call-with-semaphore sema (lambda () . body)))

    ))

;; State machine for party%
;;   -> (created with keys, initiator?)
;; 0 Init:
;;   write-prologue -> 0
;;   {write,read}-message -> 1
;; 1 Handshake: (sub-state based on handshake pattern)
;;   {write,read}-message -> 1, 2
;; 2 Transport:
;;   {write,read}-message -> 2

;; Meta: in-handshake?, can-{read,write}?
;;   next-write-security, next-read-security -- src/dest security levels?

;; Split {write,read}-message into handshake, transport versions?
;; Allow access to split cipher-states?

;; ----------------------------------------

;; 25519, 448
;; ChaChaPoly, AESGCM
;;   ChaChaPoly: 96-bit nonce is 32 zero bits + LE(n), or 64-bit nonce is LE(n)
;;   AESGCM: 96-bit nonce is 32 zero bits + BE(n)
;; SHA256, SHA512, BLAKE2s, BLAKE2b

(define (noise-protocol protocol)
  (define (mk v)
    v
    #;
    (match v
      [(list pattern-name exts pk ci di)
       '...]))
  (match protocol
    [(? string? protocol)
     (mk (parse-protocol protocol))]
    [(? symbol? protocol)
     (mk (parse-protocol (symbol->string protocol)))]))

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
  (format "Noise_~a~a_~a_~a_~a"
          pattern (string-join (map ~a exts) "+")
          (crypto->noise who pk pk-mapping "PK algorithm")
          (crypto->noise who ci cipher-mapping "cipher")
          (crypto->noise who di digest-mapping "digest")))

;; ----------------------------------------

(define cipher-state%
  (class object%
    (init-field crypto)
    (field [k #f]) ;; #f or bytes[KEYLEN]
    (field [n 0])  ;; exact-nonnegative-integer
    (super-new)

    (define/public (initialize-key key)
      (set! k key)
      (set! n 0))

    (define/public (has-key?) (and k #t))

    (define/public (set-nonce! nonce)
      (set! n nonce))

    (define/public (encrypt-with-ad ad ptext)
      (cond [k
             ;; check nonce okay
             ;; NOTE: must convert nonce from integer to bytes
             (begin0 (send crypto encrypt k n ad ptext)
               (set! n (add1 n)))]
            [else ptext]))

    (define/public (decrypt-with-ad ad ctext)
      (cond [k
             ;; check nonce okay
             ;; NOTE: must convert nonce from integer to bytes
             (begin0 (send crypto decrypt k n ad ctext)
               (set! n (add1 n)))]
            [else ctext]))

    (define/public (rekey)
      (set! k (send crypto rekey k)))
    ))

;; ----------------------------------------

(define symmetric-state%
  (class object%
    (init protocol-name) ;; Bytes
    (init-field crypto)  ;; crypto%
    (super-new)

    (field [ck #f]) ;; bytes[(send crypto get-hashlen)]
    (field [h #f])  ;; bytes[(send crypto get-hashlen)]
    (define cipher-state (new cipher-state% (crypto crypto)))

    ;; initialize
    (let ()
      (define plen (bytes-length protocol-name))
      (define HASHLEN (send crypto get-hashlen))
      (set! h
            (cond [(<= plen HASHLEN)
                   (bytes-append plen (make-bytes (- HASHLEN plen) 0))]
                  [else
                   (send crypto digest protocol-name)]))
      (set! ck h))

    (define/public (mix-key ikm)
      (define-values (new-ck new-k)
        (send crypto hkdf-n ck ikm 2))
      (set! ck new-ck)
      (send cipher-state initialize-key (subbytes new-k 0 KEYLEN)))

    (define/public (mix-hash data)
      (set! h (send crypto digest (bytes-append h data))))

    (define/public (mix-key-and-hash ikm)
      (define-values (new-ck tmp-h new-k)
        (send crypto hkdf-n ck ikm 3))
      (set! ck new-ck)
      (mix-hash tmp-h)
      (send cipher-state initialize-key (subbytes new-k 0 KEYLEN)))

    (define/public (get-handshake-hash) h)

    (define/public (encrypt-and-hash ptext)
      (define ctext (send cipher-state encrypt-with-ad h ptext))
      (mix-hash ctext)
      ctext)

    (define/public (decrypt-and-hash ctext)
      (define ptext (send cipher-state decrypt-with-ad h ctext))
      (mix-hash ctext)
      ptext)

    (define/public (split)
      (define-values (tmp-k1 tmp-k2) (send crypto hkdf-n ck #"" 2))
      (define cs1 (new cipher-state% (crypto crypto)))
      (send cs1 initialize-key (subbytes tmp-k1 0 KEYLEN))
      (define cs2 (new cipher-state% (crypto crypto)))
      (send cs2 initialize-key (subbytes tmp-k2 0 KEYLEN))
      (values cs1 cs2))

    ;; --------------------
    ;; Forwarded methods

    (define/public (has-key?)
      (send cipher-state has-key?))
    ))

;; FIXME TODO: add state machine, eg split should occur after handshake

;; ----------------------------------------

(define handshake-state%
  (class object%
    (init-field crypto)     ;; crypto%
    (init-field pattern)    ;; HandshakePattern, mutated
    (init-field initiator?) ;; Boolean
    (init protocol-name)    ;; Bytes -- FIXME: determines pattern, etc?

    ;; Static keys of self and peer
    (init-field [s  #f]) ;; private-key? or #f
    (init-field [rs #f]) ;; bytes or #f

    ;; Ephemeral keys of self and peer (rarely as init args)
    (init-field [e  #f]) ;; private-key? or #f
    (init-field [re #f]) ;; bytes or #f

    ;; Prologue
    (init [prologue #""]) ;; Bytes

    (define symmetric-state
      (new symmetric-state% (crypto crypto) (protocol-name protocol-name)))

    (super-new)

    ;; --------------------
    ;; Initialization

    (let ()
      (-mix-hash prologue)
      ;; call mix-hash for each public key in pre-messages
      (define (handle-pre-message mp)
        (for ([sym (in-list (message-pattern-tokens mp))])
          (define pk (case sym [(s) s] [(e) e] [(rs) rs] [(re) re] [else 'skip]))
          (unless (eq? pk 'skip)
            (define pk-bytes
              (cond [(private-key? pk)
                     (send crypto pk->public-bytes pk)]
                    [(bytes? pk) pk]
                    [else (error 'initialize-handshake "missing key: ~e" sym)]))
            (-mix-hash pk-bytes))))


      ;; FIXME

      (set! pattern
            (let loop ([pattern pattern])
              (cond [(eq? (car pattern) PATTERN-SEP)
                     (cdr pattern)]
                    [else
                     (handle-pre-message (car pattern))
                     (loop (cdr pattern))]))))

    ;; --------------------

    ;; FIXME: buffer so exn implies out not written to?
    (define/public (write-message payload out)
      (define-values (shape next-pattern)
        (match pattern
          [(cons (cons '-> shape) next-pattern)
           (values shape next-pattern)]
          [(cons (cons '<- shape) _)
           (error 'write-message "not your turn; pattern is ~e" pattern)]
          [_ (error 'write-mesage "pattern error: ~e" pattern)]))
      (write-message:shape shape out)
      (define enc-payload (-encrypt-and-hash payload))
      (write-bytes enc-payload out)
      (set! pattern next-pattern)
      ;; FIXME: do split if empty?
      (null? next-pattern))

    (define/public (write-message:shape shape out)
      (for ([sym (in-list shape)])
        (write-message:symbol sym out)))

    (define/public (write-message:symbol sym out)
      (define (do-dh sk pk)
        (unless sk (error 'write-message "private key not set, symbol = ~e" sym))
        (unless pk (error 'write-message "peer public key not set, symbol = ~e" sym))
        (-mix-key (send crypto dh sk pk)))
      (case sym
        [(e)
         (when e (error 'write-message "ephemeral key already set"))
         (set! e (send crypto generate-private-key))
         (define e-pub (send crypto pk->public-bytes e))
         (write-bytes e-pub out)
         (-mix-hash e-pub)]
        [(s)
         (unless s (error 'write-message "static key not set"))
         (define s-pub (send crypto pk->public-bytes s))
         (define enc-s-pub (-encrypt-and-hash s-pub))
         (write-bytes enc-s-pub out)]
        [(ee) (do-dh e re)]
        [(es) (if initiator? (do-dh e rs) (do-dh s re))]
        [(se) (if initiator? (do-dh s re) (do-dh e rs))]
        [(ss) (do-dh s rs)]
        [else (error 'write-message:symbol "unknown symbol: ~e" sym)]))

    ;; --------------------

    (define/public (read-message! msg out)
      (define-values (shape next-pattern)
        (match pattern
          [(cons (cons '<- shape) next-pattern)
           (values shape next-pattern)]
          [(cons (cons '-> shape) _)
           (error 'write-message "not your turn; pattern is ~e" pattern)]
          [_ (error 'write-mesage "pattern error: ~e" pattern)]))
      (define msg-in (open-input-bytes msg))
      (read-message:shape shape msg-in)
      (define enc-payload (port->bytes msg-in))
      (define payload (-decrypt-and-hash enc-payload))
      (write-bytes payload out)
      (set! pattern next-pattern)
      (null? next-pattern))

    (define/public (read-message:shape shape msg-in)
      (for ([sym (in-list shape)])
        (read-message:symbol sym msg-in)))

    (define/public (read-message:symbol sym msg-in)
      (define (do-dh sk pk)
        (unless sk (error 'read-message "private key not set, symbol = ~e" sym))
        (unless pk (error 'read-message "peer public key not set, symbol = ~e" sym))
        (-mix-key (send crypto dh sk pk)))
      (case sym
        [(e)
         (set! re (read-bytes* DHLEN msg-in))
         (-mix-hash re)]
        [(s)
         (when rs (error 'read-message "peer static key already set"))
         (define enc-rs
           (let ([len (+ DHLEN (if (-has-key?) AUTHLEN 0))])
             (read-bytes* len msg-in)))
         (set! rs (-decrypt-and-hash enc-rs))]
        [(ee) (do-dh e re)]
        [(es) (if initiator? (do-dh e rs) (do-dh s re))]
        [(se) (if initiator? (do-dh s re) (do-dh e rs))]
        [(ss) (do-dh s rs)]
        [else (error 'read-message "unknown handshake symbol: ~e" sym)]))

    ;; --------------------
    ;; Forwarded methods

    (define/private (-mix-hash data)
      (send symmetric-state mix-hash data))
    (define/private (-mix-key data)
      (send symmetric-state mix-key data))
    (define/private (-encrypt-and-hash ptext)
      (send symmetric-state encrypt-and-hash ptext))
    (define/private (-decrypt-and-hash ctext)
      (send symmetric-state decrypt-and-hash ctext))
    (define/private (-has-key?)
      (send symmetric-state has-key?))

    ))
