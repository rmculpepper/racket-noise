#lang racket/base
(require racket/class
         racket/match
         racket/string
         racket/port
         racket/format
         crypto
         (prefix-in crypto: crypto)
         binaryio/bytes
         "private/patterns.rkt"
         "private/protocol-name.rkt")
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
      (define cs-> (new cipher-state% (crypto crypto)))
      (send cs-> initialize-key (subbytes tmp-k1 0 KEYLEN))
      (define cs<- (new cipher-state% (crypto crypto)))
      (send cs<- initialize-key (subbytes tmp-k2 0 KEYLEN))
      (values cs-> cs<-))

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
    (init-field pattern)    ;; HandshakePattern
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

    ;; State
    (define mpatterns null) ;; (Listof MessagePattern), mutated
    (define symmetric-state
      (new symmetric-state% (crypto crypto) (protocol-name protocol-name)))
    (define tstate-w #f) ;; #f or cipher-state%, mutated
    (define tstate-r #f) ;; #f or cipher-state%, mutated
    (define hhash #f)    ;; #f or bytes, mutated

    (super-new)

    ;; --------------------
    ;; Initialization

    (-mix-hash prologue)
    (match pattern
      [(handshake-pattern pre mps _ _)
       (for ([mp (in-list pre)] #:when (eq? (message-pattern-dir mp) (direction 'read)))
         (for ([sym (in-list (message-pattern-tokens mp))])
           (define pk (case sym [(s) s] [(e) e] [(rs) rs] [(re) re] [else 'skip]))
           (unless (eq? pk 'skip)
             (define pk-bytes
               (cond [(private-key? pk)
                      (send crypto pk->public-bytes pk)]
                     [(bytes? pk) pk]
                     [else (error 'initialize-handshake "missing key: ~e" sym)]))
             (-mix-hash pk-bytes))))
       (set! mpatterns mps)])

    ;; --------------------

    (define/private (direction rw)
      (get-direction initiator? rw))

    (define/private (in-handshake?)
      (pair? mpatterns))

    (define/private (next-message-pattern who rw)
      (define dir (direction rw))
      (match mpatterns
        [(cons mp _)
         (unless (eq? (message-pattern-dir mp) dir)
           (error who "not your turn; pattern is ~e" mp))
         mp]
        ['() (handshake-pattern-t/dir pattern dir)]))

    (define/private (advance-pattern!)
      (when (pair? mpatterns)
        (set! mpatterns (cdr mpatterns))
        (when (null? mpatterns)
          (define-values (cs-> cs<-) (-split))
          (set! hhash (send symmetric-state get-handshake-hash))
          ;; FIXME: only set if protocol allows (eg, not for one-way)
          (set! tstate-w (if initiator? cs-> cs<-))
          (set! tstate-r (if initiator? cs<- cs->))
          (set! symmetric-state #f))))

    ;; --------------------

    (define/public (write-transport-message payload)
      (unless tstate-w
        (when (in-handshake?)
          (error 'write-transport-message "not in transport phase"))
        (error 'write-transport-message "not allowed to write transport messages"))
      (send tstate-w encrypt-with-ad #"" payload))

    (define/public (write-handshake-message payload)
      (define who 'write-handshake-message)
      (unless (in-handshake?)
        (error who "not in handshake phase"))
      (define mp (next-message-pattern who 'write))
      (define out (open-output-bytes))
      (-write-message:pattern who mp out)
      (define enc-payload (-encrypt-and-hash payload))
      (write-bytes enc-payload out)
      (advance-pattern!)
      (get-output-bytes out))

    (define/public (-write-message:pattern who mp out)
      (for ([sym (in-list (message-pattern-tokens mp))])
        (-write-message:token who sym out)))

    (define/public (-write-message:token who sym out)
      (define (do-dh sk pk)
        (unless sk (error who "private key not set, symbol = ~e" sym))
        (unless pk (error who "peer public key not set, symbol = ~e" sym))
        (-mix-key (send crypto dh sk pk)))
      (case sym
        [(e)
         (when e (error who "ephemeral key already set"))
         (set! e (send crypto generate-private-key))
         (define e-pub (send crypto pk->public-bytes e))
         (write-bytes e-pub out)
         (-mix-hash e-pub)]
        [(s)
         (unless s (error who "static key not set"))
         (define s-pub (send crypto pk->public-bytes s))
         (define enc-s-pub (-encrypt-and-hash s-pub))
         (write-bytes enc-s-pub out)]
        [(ee) (do-dh e re)]
        [(es) (if initiator? (do-dh e rs) (do-dh s re))]
        [(se) (if initiator? (do-dh s re) (do-dh e rs))]
        [(ss) (do-dh s rs)]
        [else (error who "internal error: unknown token: ~e" sym)]))

    ;; --------------------

    (define/public (read-transport-message msg)
      (unless tstate-r
        (when (in-handshake?)
          (error 'read-transport-message "not in transport phase"))
        (error 'read-transport-message "not allowed to receive transport messages"))
      (send tstate-r decrypt-with-ad #"" msg))

    (define/public (read-handshake-message msg)
      (define who 'read-handshake-message)
      (unless (in-handshake?)
        (error who "not in handshake phase"))
      (define mp (next-message-pattern who 'read))
      (define msg-in (open-input-bytes msg))
      (-read-message:pattern who mp msg-in)
      (define enc-payload (port->bytes msg-in))
      (define payload (-decrypt-and-hash enc-payload))
      (advance-pattern!)
      payload)

    (define/public (-read-message:pattern who mp msg-in)
      (for ([sym (in-list (message-pattern-tokens mp))])
        (-read-message:token who sym msg-in)))

    (define/public (-read-message:token who sym msg-in)
      (define (do-dh sk pk)
        (unless sk (error who "private key not set, symbol = ~e" sym))
        (unless pk (error who "peer public key not set, symbol = ~e" sym))
        (-mix-key (send crypto dh sk pk)))
      (case sym
        [(e)
         (set! re (read-bytes* DHLEN msg-in))
         (-mix-hash re)]
        [(s)
         (when rs (error who "peer static key already set"))
         (define enc-rs
           (let ([len (+ DHLEN (if (-has-key?) AUTHLEN 0))])
             (read-bytes* len msg-in)))
         (set! rs (-decrypt-and-hash enc-rs))]
        [(ee) (do-dh e re)]
        [(es) (if initiator? (do-dh e rs) (do-dh s re))]
        [(se) (if initiator? (do-dh s re) (do-dh e rs))]
        [(ss) (do-dh s rs)]
        [else (error who "internal error: unknown token: ~e" sym)]))

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
    (define/private (-split)
      (send symmetric-state split))

    ))
