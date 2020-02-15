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
    (init-field ds cs pk)
    (init factories)
    (super-new)

    (field [di (or (get-digest ds factories) (fail "digest" ds))]
           [ci (or (get-cipher cs factories) (fail "cipher" cs))]
           [pkp (with-handlers ([exn:fail? (lambda () (fail "PK" pk))])
                  (parameterize ((crypto-factories factories))
                    (generate-pk-parameters (car pk) (cdr pk))))]
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
        [(list 'ecx 'public _curve (? bytes? pub-bytes))
         pub-bytes]
        [_ (error 'pk->public-bytes "failed")]))

    (define/public (bytes->private-key bs)
      (define datum
        (cond [(equal? pk '(ecx (curve x25519)))
               `(ecx private x25519 ,bs)]
              [(equal? pk '(ecx (curve x448)))
               `(ecx private x448 ,bs)]
              [else (error 'bytes->private-key "unsupported PK algorithm: ~e" pk)]))
      (datum->pk-key datum 'rkt-private))

    (define/public (datum->pk-key datum fmt)
      (crypto:datum->pk-key datum fmt (get-factory pkp)))
    ))

(define (make-crypto ds cs pk #:factories [factories (crypto-factories)])
  (new crypto% (ds ds) (cs cs) (pk pk) (factories factories)))

;; ----------------------------------------
;; Noise protocols by name

(define protocol%
  (class object%
    (init-field crypto pattern protocol-name [extensions '()])
    (super-new)

    (define/public (get-crypto) crypto)
    (define/public (get-pattern) pattern)
    (define/public (get-protocol-name) protocol-name)
    (define/public (get-extensions) extensions)

    (define/public (using-psk?)
      (for/or ([ext (in-list extensions)])
        (regexp-match? #rx"^psk[0-9]+$" ext)))

    (define/public (new-party initiator? [info '#hash()] #:s [s #f] #:rs [rs #f])
      (let* ([s (if (bytes? s) (bytes->private-key s) s)]
             [info (if s  (hash-set info 's  s)  info)]
             [info (if rs (hash-set info 'rs rs) info)])
        (new connection% (protocol this) (initiator? initiator?) (info info))))

    (define/public (new-initiator [info #hasheq()] #:s [s #f] #:rs [rs #f])
      (new-party #t info #:s s #:rs rs))
    (define/public (new-responder [info #hasheq()] #:s [s #f] #:rs [rs #f])
      (new-party #f info #:s s #:rs rs))

    ;; --------------------

    (define/public (generate-private-key)
      (send crypto generate-private-key))
    (define/public (pk->public-bytes pk)
      (send crypto pk->public-bytes pk))
    (define/public (datum->pk-key datum fmt)
      (send crypto datum->pk-key datum))
    (define/public (bytes->private-key datum)
      (send crypto bytes->private-key datum))
    ))

;; ----------------------------------------

(define (noise-protocol name #:factories [factories (crypto-factories)])
  (define protocol-name
    (cond [(string? name) name]
          [(symbol? name) (symbol->string name)]))
  (match (parse-protocol protocol-name)
    [(list pattern-name exts pk ci di)
     (define crypto (make-crypto di ci pk #:factories factories))
     (define base-pattern
       (or (hash-ref handshake-table pattern-name #f)
           (error 'noise-protocol "unknown handshake pattern\n  protocol: ~e" name)))
     (define pattern
       (for/fold ([pattern base-pattern]) ([ext (in-list exts)])
         (handshake-pattern-apply-extension pattern ext)))
     (new protocol%
          (protocol-name (bytes->immutable-bytes (string->bytes/utf-8 protocol-name)))
          (crypto crypto) (pattern pattern) (extensions exts))]))

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
    (define cstate (new cipher-state% (crypto crypto)))

    ;; initialize
    (let ()
      (define plen (bytes-length protocol-name))
      (define HASHLEN (send crypto get-hashlen))
      (set! h
            (cond [(<= plen HASHLEN)
                   (bytes-append protocol-name (make-bytes (- HASHLEN plen) 0))]
                  [else
                   (send crypto digest protocol-name)]))
      (set! ck h))

    (define/public (mix-key ikm)
      (define-values (new-ck new-k)
        (send crypto hkdf-n ck ikm 2))
      (set! ck new-ck)
      (send cstate initialize-key (subbytes new-k 0 KEYLEN)))

    (define/public (mix-hash data)
      (set! h (send crypto digest (bytes-append h data))))

    (define/public (mix-key-and-hash ikm)
      (define-values (new-ck tmp-h new-k)
        (send crypto hkdf-n ck ikm 3))
      (set! ck new-ck)
      (mix-hash tmp-h)
      (send cstate initialize-key (subbytes new-k 0 KEYLEN)))

    (define/public (get-handshake-hash) h)

    (define/public (encrypt-and-hash ptext)
      (define ctext (send cstate encrypt-with-ad h ptext))
      (mix-hash ctext)
      ctext)

    (define/public (decrypt-and-hash ctext)
      (define ptext (send cstate decrypt-with-ad h ctext))
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
      (send cstate has-key?))
    ))

;; ----------------------------------------

(define handshake-state%
  (class object%
    (init protocol)         ;; protocol%
    (init-field initiator?) ;; Boolean
    (init-field [info '#hash()])  ;; Hash[...]

    ;; Static keys of self and peer
    (field [s  (hash-ref info 's  #f)]) ;; private-key? or #f
    (field [rs (hash-ref info 'rs #f)]) ;; bytes or #f

    ;; Ephemeral keys of self and peer (rarely as init args)
    (field [e  (hash-ref info 'e  #f)]) ;; private-key? or #f
    (field [re (hash-ref info 're #f)]) ;; bytes or #f

    (define crypto (send protocol get-crypto))
    (define mpatterns ;; (Listof MessagePattern), mutated
      (handshake-pattern-msgs (send protocol get-pattern)))
    (define sstate    ;; symmetric-state%
      (new symmetric-state% (crypto crypto)
           (protocol-name (send protocol get-protocol-name))))

    (define using-psk? (send protocol using-psk?))
    (define/private (get-psk)
      (cond [(hash-ref info 'psk #f)
             => (lambda (psk)
                  (cond [(procedure? psk) (psk rs)]
                        [else psk]))]
            [else #f]))

    (super-new)

    ;; --------------------
    ;; Initialization

    (-mix-hash (hash-ref info 'prologue #""))
    (let ([pre (handshake-pattern-pre (send protocol get-pattern))])
      (define (process-pre same-side? mp)
        (for ([sym (in-list (message-pattern-tokens mp))])
          (define pk (get-pk same-side? sym))
          (unless (eq? pk 'skip)
            (define pk-bytes
              (cond [(private-key? pk) (send crypto pk->public-bytes pk)]
                    [(bytes? pk) pk]
                    [else (error 'initialize-handshake "missing key: ~e" sym)]))
            (-mix-hash pk-bytes))))
      (define (get-pk same-side? sym)
        (if same-side?
            (case sym [(s)  s] [(e)  e] [(rs) rs] [(re) re] [else 'skip])
            (case sym [(s) rs] [(e) re] [(rs)  s] [(re)  e] [else 'skip])))
      (define ((has-dir? dir) mp) (eq? (message-pattern-dir mp) dir))
      (for ([mp (in-list (filter (has-dir? '->) pre))])
        (process-pre initiator? mp))
      (for ([mp (in-list (filter (has-dir? '<-) pre))])
        (process-pre (not initiator?) mp)))

    ;; --------------------

    (define/public (direction rw)
      (get-direction initiator? rw))

    (define/public (can-write-message?)
      (and (pair? mpatterns)
           (eq? (message-pattern-dir (car mpatterns)) (direction 'write))))
    (define/public (can-read-message?)
      (and (pair? mpatterns)
           (eq? (message-pattern-dir (car mpatterns)) (direction 'read))))

    ;; next-message-pattern : Symbol (U 'read 'write) -> MessagePattern
    (define/private (next-message-pattern who rw)
      (define dir (direction rw))
      (match mpatterns
        [(cons mp _)
         (unless (eq? (message-pattern-dir mp) dir)
           (error who "not your turn; pattern is ~e" mp))
         mp]
        [_ (error who "internal error, no next message pattern")]))

    ;; advance-pattern! : -> (U #f HandshakeEnd)
    (define/private (advance-pattern!)
      (set! mpatterns (cdr mpatterns))
      (cond [(null? mpatterns)
             (define-values (cs-> cs<-) (send sstate split))
             (define hh (send sstate get-handshake-hash))
             (list* hh (if initiator? cs-> cs<-) (if initiator? cs<- cs->))]
            [else #f]))

    ;; --------------------

    ;; write-handshake-message : Bytes -> (values Bytes (U #f HandshakeEnd))
    (define/public (write-handshake-message payload)
      (define who 'write-handshake-message)
      (define mp (next-message-pattern who 'write))
      ;; (eprintf "WRITE ~v\n" mp)
      (define out (open-output-bytes))
      (-write-message:pattern who mp out)
      (define enc-payload (-encrypt-and-hash payload))
      (write-bytes enc-payload out)
      (values (get-output-bytes out) (advance-pattern!)))

    (define/public (-write-message:pattern who mp out)
      (for ([sym (in-list (message-pattern-tokens mp))])
        (-write-message:token who sym out)))

    (define/public (-write-message:token who sym out)
      (define (do-dh sk pk)
        (unless sk (error who "private key not set, token = ~e" sym))
        (unless pk (error who "peer public key not set, token = ~e" sym))
        (-mix-key (send crypto dh sk pk)))
      (case sym
        [(e)
         (when e (error who "ephemeral key already set"))
         (set! e (send crypto generate-private-key))
         (define e-pub (send crypto pk->public-bytes e))
         (write-bytes e-pub out)
         (-mix-hash e-pub)
         (when using-psk?
           (-mix-key e-pub))]
        [(s)
         (unless s (error who "static key not set"))
         (define s-pub (send crypto pk->public-bytes s))
         (define enc-s-pub (-encrypt-and-hash s-pub))
         (write-bytes enc-s-pub out)]
        [(ee) (do-dh e re)]
        [(es) (if initiator? (do-dh e rs) (do-dh s re))]
        [(se) (if initiator? (do-dh s re) (do-dh e rs))]
        [(ss) (do-dh s rs)]
        [(psk)
         (cond [(get-psk) => (lambda (psk) (-mix-key-and-hash psk))]
               [else (error who "could not get pre-shared key")])]
        [else (error who "internal error: unknown token: ~e" sym)]))

    ;; --------------------

    ;; read-handshake-message : Bytes -> (values Bytes (U #f HandshakeEnd))
    (define/public (read-handshake-message msg)
      (define who 'read-handshake-message)
      (define mp (next-message-pattern who 'read))
      ;; (eprintf "READ  ~v\n" mp)
      (define msg-in (open-input-bytes msg))
      (-read-message:pattern who mp msg-in)
      (define enc-payload (port->bytes msg-in))
      (define payload (-decrypt-and-hash enc-payload))
      (values payload (advance-pattern!)))

    (define/public (-read-message:pattern who mp msg-in)
      (for ([sym (in-list (message-pattern-tokens mp))])
        (-read-message:token who sym msg-in)))

    (define/public (-read-message:token who sym msg-in)
      (define (do-dh sk pk)
        (unless sk (error who "private key not set, token = ~e" sym))
        (unless pk (error who "peer public key not set, token = ~e" sym))
        (-mix-key (send crypto dh sk pk)))
      (case sym
        [(e)
         (set! re (read-bytes* DHLEN msg-in))
         (-mix-hash re)
         (when using-psk?
           (-mix-key re))]
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
        [(psk)
         (cond [(get-psk) => (lambda (psk) (-mix-key-and-hash psk))]
               [else (error who "could not get pre-shared key")])]
        [else (error who "internal error: unknown token: ~e" sym)]))

    ;; --------------------
    ;; Forwarded methods

    (define/private (-mix-hash data)
      (send sstate mix-hash data))
    (define/private (-mix-key data)
      (send sstate mix-key data))
    (define/private (-mix-key-and-hash data)
      (send sstate mix-key-and-hash data))
    (define/private (-encrypt-and-hash ptext)
      (send sstate encrypt-and-hash ptext))
    (define/private (-decrypt-and-hash ctext)
      (send sstate decrypt-and-hash ctext))
    (define/private (-has-key?)
      (send sstate has-key?))

    ))

;; ----------------------------------------
;; Connection

(define connection%
  (class object%
    (init protocol initiator? info)

    (define hstate ;; #f or handshake-state%, mutated
      (new handshake-state% (protocol protocol) (initiator? initiator?) (info info)))
    (define tstate-w #f) ;; #f or cipher-state%, mutated
    (define tstate-r #f) ;; #f or cipher-state%, mutated
    (define hhash #f)    ;; #f or bytes, mutated
    (define sema (make-semaphore 1))

    (super-new)

    ;; --------------------

    (define-syntax-rule (with-lock . body)
      ;; FIXME: kill connection on error?
      (let ([go (lambda () . body)])
        (if sema (call-with-semaphore sema go) (go))))

    (define/public (in-handshake-phase?) (and hstate #t))
    (define/public (in-transport-phase?) (and (or tstate-w tstate-r) #t))

    (define/public (get-handshake-hash)
      ;; May want to get hhash even if connection is closed, so test hhash
      ;; rather than eg (in-transport-phase?).
      (or hhash (error 'get-handshake-hash "handshake is not finished")))

    (define/private (end-of-handshake! hs-end)
      (match hs-end
        [(list* hh cs-w cs-r)
         (set! hhash hh)
         (set! tstate-w cs-w)
         (set! tstate-r cs-r)
         (set! hstate #f)]))

    (define/private (kill-connection!)
      (set! tstate-w #f)
      (set! tstate-r #f)
      (set! hstate #f))

    ;; --------------------

    (define/public (can-write-message?)
      (with-lock
        (cond [hstate (send hstate can-write-message?)]
              [else (and tstate-w #t)])))

    (define/public (can-read-message?)
      (with-lock
        (cond [hstate (send hstate can-read-message?)]
              [else (and tstate-r #t)])))

    ;; --------------------

    (define/public (write-handshake-message payload)
      (with-lock
        (unless (in-handshake-phase?)
          (error 'write-handshake-message "not in handshake phase"))
        (define-values (msg hs-end)
          (send hstate write-handshake-message payload))
        (when hs-end (end-of-handshake! hs-end))
        msg))

    (define/public (read-handshake-message msg)
      (with-lock
        (unless (in-handshake-phase?)
          (error 'read-handshake-message "not in handshake phase"))
        (define-values (payload hs-end)
          (send hstate read-handshake-message msg))
        (when hs-end (end-of-handshake! hs-end))
        payload))

    ;; --------------------

    (define/public (write-transport-message payload)
      (with-lock
        (unless (in-transport-phase?)
          (error 'write-transport-message "not in transport phase"))
        (unless tstate-w
          (error 'write-transport-message "not allowed to send transport messages"))
        (send tstate-w encrypt-with-ad #"" payload)))

    (define/public (read-transport-message msg)
      (with-lock
        (unless (in-transport-phase?)
          (error 'read-transport-message "not in transport phase"))
        (unless tstate-r
          (error 'read-transport-message "not allowed to receive transport messages"))
        (send tstate-r decrypt-with-ad #"" msg)))

    ))

;; Meta: next-write-security, next-read-security -- src/dest security levels?
