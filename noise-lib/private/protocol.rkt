#lang racket/base
(require (for-syntax racket/base)
         racket/class
         racket/list
         racket/match
         racket/string
         racket/port
         racket/format
         crypto
         binaryio/bytes
         "interfaces.rkt"
         "crypto.rkt"
         "patterns.rkt"
         "protocol-name.rkt")
(provide (all-defined-out))

;; Reference: http://www.noiseprotocol.org/noise.html
;;   Revision: 34, Date: 2018-07-11

(define protocol%
  (class* object% (protocol<%>)
    (init-field crypto pattern protocol-name [extensions '()])
    (super-new)

    (define/public (get-crypto) crypto)
    (define/public (get-pattern) pattern)
    (define/public (get-message-patterns) (handshake-pattern-msgs pattern))
    (define/public (get-protocol-name) protocol-name)
    (define/public (get-extensions) extensions)

    (define/public (using-psk?)
      (for/or ([ext (in-list extensions)])
        (regexp-match? #rx"^psk[0-9]+$" ext)))

    (define/public (get-info-keys initiator?)
      (define h (make-hasheq))
      (for ([mp (in-list (handshake-pattern-pre pattern))])
        (define self? (eq? (message-pattern-dir mp) (if initiator? '-> '<-)))
        (for ([tok (in-list (message-pattern-tokens mp))])
          (define k
            (or (if self? (pre-token->self-key tok) (pre-token->peer-key tok))
                (error 'get-info-keys "INTERNAL ERROR: invalid pre-message token: ~e" tok)))
          (hash-set! h k #t)))
      (for ([mp (in-list (handshake-pattern-msgs pattern))]
            #:when (eq? (message-pattern-dir mp) (if initiator? '-> '<-))
            [tok (in-list (message-pattern-tokens mp))])
        (case tok
          [(s psk) (hash-set! h tok #t)]
          [else (void)]))
      (sort (hash-keys h) symbol<?))

    (define/public (check-info-keys who initiator? info)
      ;; PRE: info keys, if present, have correct values (see info-hash/c)
      (for ([key (in-list (get-info-keys initiator?))])
        (unless (hash-has-key? info key)
          (error who "info missing required key\n  key: ~e" key))))

    (define/public (new-handshake initiator? info #:prologue [prologue #""])
      (new noise-handshake-state% (protocol this) (initiator? initiator?)
           (info info) (prologue prologue)))

    ;; --------------------

    ;; for testing
    (define/public (trim-info initiator? info)
      (define keys (get-info-keys initiator?))
      (for/fold ([info info]) ([k (in-hash-keys info)])
        (cond [(memq k keys) info]
              [(not (memq k '(rs re))) info]
              [else (hash-remove info k)])))

    ;; --------------------

    ;; convenience
    (define/public (generate-private-key)
      (send crypto generate-private-key))
    (define/public (pk->public-bytes pk)
      (send crypto pk->public-bytes pk))
    ))

;; ----------------------------------------

(define (noise-protocol name
                        #:crypto [crypto0 #f]
                        #:factories [factories (crypto-factories)])
  (define protocol-name
    (cond [(string? name) name]
          [(symbol? name) (symbol->string name)]))
  (match (parse-protocol protocol-name)
    [(list pattern-name exts pk ci di)
     (define crypto
       (cond [crypto0 (check-crypto 'noise-protocol crypto0 di ci pk)]
             [else (noise-crypto di ci pk #:factories factories)]))
     (define base-pattern
       (or (hash-ref handshake-table pattern-name #f)
           (error 'noise-protocol "unknown handshake pattern\n  protocol: ~e" name)))
     (define pattern
       (for/fold ([pattern base-pattern]) ([ext (in-list exts)])
         (handshake-pattern-apply-extension pattern ext)))
     (new protocol%
          (protocol-name (string->immutable-string protocol-name))
          (extensions (map string->immutable-string exts))
          (crypto crypto) (pattern pattern))]))

;; ----------------------------------------

(define cipher-state%
  (class* object% (cipher-state<%>)
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
             (check-nonce 'encrypt-with-ad n)
             (begin0 (send crypto encrypt k n ad ptext)
               (set! n (add1 n)))]
            [else ptext]))

    (define/public (decrypt-with-ad ad ctext)
      (cond [k
             (check-nonce 'decrypt-with-ad n)
             (begin0 (send crypto decrypt k n ad ctext)
               (set! n (add1 n)))]
            [else ctext]))

    (define/public (rekey)
      (set! k (send crypto rekey k)))

    (define/private (check-nonce who n)
      (unless (<= n MAX-NONCE)
        (error who "nonce exhausted")))
    ))

;; ----------------------------------------

(define symmetric-state%
  (class* object% (symmetric-state<%>)
    (init protocol-name) ;; String
    (init-field crypto)  ;; crypto%
    (super-new)

    (field [ck #f]) ;; bytes[(send crypto get-hashlen)]
    (field [h #f])  ;; bytes[(send crypto get-hashlen)]
    (define cstate (new cipher-state% (crypto crypto)))

    ;; initialize
    (let ()
      (define pname (string->bytes/utf-8 protocol-name))
      (define plen (bytes-length pname))
      (define HASHLEN (send crypto get-hashlen))
      (set! h
            (cond [(<= plen HASHLEN)
                   (bytes-append pname (make-bytes (- HASHLEN plen) 0))]
                  [else (send crypto digest pname)]))
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

(begin-for-syntax
  (require syntax/transformer)
  (define (make-hash-key-transformer hash-id key-expr)
    (with-syntax ([hash-id hash-id] [key-expr key-expr])
      (make-variable-like-transformer
       #'(hash-ref hash-id key-expr #f)
       (lambda (stx)
         (syntax-case stx ()
           [(set! _ value)
            #'(set! hash-id (hash-set hash-id key-expr value))]))))))

(define (token->info-key tok from-self?)
  (if from-self?
      (case tok [(s)  's] [(e)  'e] [(rs) 'rs] [(re) 're] [else #f])
      (case tok [(s) 'rs] [(e) 're] [(rs)  's] [(re)  'e] [else #f])))

(define noise-handshake-state%
  (class* object% (handshake-state<%>)
    (init-field protocol)   ;; protocol%
    (init-field initiator?) ;; Boolean
    (init-field info)       ;; Hash[...], mutated
    (init prologue)         ;; Bytes

    (define crypto (send protocol get-crypto))
    (define mpatterns ;; (Listof MessagePattern), mutated
      (handshake-pattern-msgs (send protocol get-pattern)))
    (define sstate    ;; symmetric-state%
      (new symmetric-state% (crypto crypto)
           (protocol-name (send protocol get-protocol-name))))
    (define transport #f) ;; #f or noise-transport%, mutated
    (define using-psk? (send protocol using-psk?))

    (super-new)

    ;; --------------------
    ;; Initialization

    (begin
      (send protocol check-info-keys 'noise-handshake-state% initiator? info)
      (-mix-hash prologue)
      (let ([pre (handshake-pattern-pre (send protocol get-pattern))])
        (define (process-pre same-side? mp)
          (for ([tok (in-list (message-pattern-tokens mp))])
            (define pk-var (pre-token->info-key same-side? tok))
            (define pk (hash-ref info pk-var))
            (define pk-bytes
              (cond [(private-key? pk) (send crypto pk->public-bytes pk)]
                    [(bytes? pk) pk]))
            (-mix-hash pk-bytes)))
        (define ((has-dir? dir) mp) (eq? (message-pattern-dir mp) dir))
        (for ([mp (in-list (filter (has-dir? '->) pre))])
          (process-pre initiator? mp))
        (for ([mp (in-list (filter (has-dir? '<-) pre))])
          (process-pre (not initiator?) mp))))

    (define-syntax-rule (define-info-var var)
      (define-syntax var (make-hash-key-transformer #'info #'(quote var))))

    ;; Static and ephemeral keys of self
    (define-info-var s) ;; private-key? or #f
    (define-info-var e) ;; private-key? or #f

    ;; Static and ephemeral keys of peer
    (define-info-var rs) ;; Bytes or #f
    (define-info-var re) ;; Bytes or #f

    (define/private (get-psk)
      (cond [(hash-ref info 'psk #f)
             => (lambda (psk)
                  (cond [(procedure? psk) (psk rs)]
                        [else psk]))]
            [else #f]))

    ;; --------------------

    (define/public (get-keys-info) info)
    (define/public (get-transport) transport)

    (define/public (direction rw)
      (get-direction initiator? rw))

    (define/public (can-write-message?)
      (and (pair? mpatterns)
           (eq? (message-pattern-dir (car mpatterns)) (direction 'write))))
    (define/public (can-read-message?)
      (and (pair? mpatterns)
           (eq? (message-pattern-dir (car mpatterns)) (direction 'read))))

    (define/public (remaining-message-patterns) mpatterns)
    (define/public (next-message-pattern)
      (and (pair? mpatterns) (car mpatterns)))
    (define/public (previous-message-pattern)
      (let loop ([mps (send protocol get-message-patterns)] [result #f])
        (if (eq? mps mpatterns) result (loop (cdr mps) (car mps)))))

    ;; next-message-pattern : Symbol (U 'read 'write) -> MessagePattern
    (define/private (get/check-next-message-pattern who rw)
      (cond [(next-message-pattern)
             => (lambda (mp)
                  (unless (eq? (message-pattern-dir mp) (direction rw))
                    (error who "not your turn; pattern is ~e" mp))
                  mp)]
            [else (error who "no next message pattern")]))

    ;; advance-pattern! : -> Void
    (define/private (advance-pattern!)
      (set! mpatterns (cdr mpatterns))
      (when (null? mpatterns)
        (define-values (cs-> cs<-) (send sstate split))
        (define hh (send sstate get-handshake-hash))
        (set! transport
              (new noise-transport%
                   (handshake-hash hh)
                   (cs-w (if initiator? cs-> cs<-))
                   (cs-r (if initiator? cs<- cs->))))))

    ;; --------------------

    ;; write-handshake-message : Bytes -> Bytes
    (define/public (write-handshake-message payload)
      (define who 'write-handshake-message)
      (define mp (get/check-next-message-pattern who 'write))
      (define out (open-output-bytes))
      (-write-message:pattern who mp out)
      (define enc-payload (-encrypt-and-hash payload))
      (write-bytes enc-payload out)
      (advance-pattern!)
      (get-output-bytes out))

    (define/private (-write-message:pattern who mp out)
      (for ([sym (in-list (message-pattern-tokens mp))])
        (-write-message:token who sym out)))

    (define/private (-write-message:token who sym out)
      (define (do-dh sk pk) (-mix-key (send crypto dh sk pk)))
      (case sym
        [(e)
         (set! e (send crypto generate-private-key))
         (define e-pub (send crypto pk->public-bytes e))
         (write-bytes e-pub out)
         (-mix-hash e-pub)
         (when using-psk?
           (-mix-key e-pub))]
        [(s)
         (define s-pub (send crypto pk->public-bytes s))
         (define enc-s-pub (-encrypt-and-hash s-pub))
         (write-bytes enc-s-pub out)]
        [(ee) (do-dh e re)]
        [(es) (if initiator? (do-dh e rs) (do-dh s re))]
        [(se) (if initiator? (do-dh s re) (do-dh e rs))]
        [(ss) (do-dh s rs)]
        [(psk)
         (cond [(get-psk) => (lambda (psk) (-mix-key-and-hash psk))]
               [else (error who "could not get PSK")])]
        [else (error who "internal error: unknown token: ~e" sym)]))

    ;; --------------------

    ;; read-handshake-message : Bytes -> Bytes
    (define/public (read-handshake-message msg)
      (define who 'read-handshake-message)
      (define mp (get/check-next-message-pattern who 'read))
      (define msg-in (open-input-bytes msg))
      (-read-message:pattern who mp msg-in)
      (define enc-payload (port->bytes msg-in))
      (define payload (-decrypt-and-hash enc-payload))
      (advance-pattern!)
      payload)

    (define/private (-read-message:pattern who mp msg-in)
      (for ([sym (in-list (message-pattern-tokens mp))])
        (-read-message:token who sym msg-in)))

    (define/private (-read-message:token who sym msg-in)
      (define (do-dh sk pk) (-mix-key (send crypto dh sk pk)))
      (case sym
        [(e)
         (set! re (read-bytes* (send crypto get-dhlen) msg-in))
         (-mix-hash re)
         (when using-psk?
           (-mix-key re))]
        [(s)
         (define enc-rs
           (let ([len (+ (send crypto get-dhlen) (if (-has-key?) AUTHLEN 0))])
             (read-bytes* len msg-in)))
         (set! rs (-decrypt-and-hash enc-rs))]
        [(ee) (do-dh e re)]
        [(es) (if initiator? (do-dh e rs) (do-dh s re))]
        [(se) (if initiator? (do-dh s re) (do-dh e rs))]
        [(ss) (do-dh s rs)]
        [(psk)
         (cond [(get-psk) => (lambda (psk) (-mix-key-and-hash psk))]
               [else (error who "could not get PSK")])]
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

(define noise-transport%
  (class* object% (transport<%>)
    (init-field handshake-hash cs-w cs-r)
    (field [sema (make-semaphore 1)])
    (super-new)
    (define/public (get-handshake-hash) handshake-hash)
    (define/public (write-message payload)
      (call-with-semaphore sema (lambda () (send cs-w encrypt-with-ad #"" payload))))
    (define/public (read-message message)
      (call-with-semaphore sema (lambda () (send cs-r decrypt-with-ad #"" message))))
    ))
