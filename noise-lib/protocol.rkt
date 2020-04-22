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
         "private/interfaces.rkt"
         "private/crypto.rkt"
         "private/patterns.rkt"
         "private/protocol-name.rkt")
(provide (all-defined-out))

(provide noise-protocol?
         noise-protocol<%>
         noise-protocol-state?
         noise-protocol-state<%>)

;; Reference: http://www.noiseprotocol.org/noise.html
;;   Revision: 34, Date: 2018-07-11

;; ----------------------------------------
;; Crypto support

(provide crypto%)

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

;; ----------------------------------------
;; Noise protocols by name

(define protocol%
  (class* object% (protocol<%>)
    (init-field crypto pattern protocol-name [extensions '()])
    (super-new)

    (define/public (get-crypto) crypto)
    (define/public (get-pattern) pattern)
    (define/public (get-protocol-name) protocol-name)
    (define/public (get-extensions) extensions)

    (define/public (using-psk?)
      (for/or ([ext (in-list extensions)])
        (regexp-match? #rx"^psk[0-9]+$" ext)))

    (define/public (get-info-keys initiator?)
      (append*
       (for/list ([mp (in-list (handshake-pattern-pre pattern))])
         (define self? (eq? (message-pattern-dir mp) (if initiator? '-> '<-)))
         (for/list ([tok (in-list (message-pattern-tokens mp))])
           (or (if self? (pre-token->self-key tok) (pre-token->peer-key tok))
               (error 'get-info-keys "INTERNAL ERROR: invalid pre-message token: ~e" tok))))))

    (define/public (check-info-keys who initiator? info)
      ;; PRE: info keys, if present, have correct values (see info-hash/c)
      (for ([key (in-list (get-info-keys initiator?))])
        (unless (hash-has-key? info key)
          (error who "info missing required key\n  key: ~e" key))))

    ;; --------------------

    ;; for testing
    (define/public (new-state initiator? info #:prologue [prologue #""])
      (new protocol-state% (protocol this) (initiator? initiator?)
           (info info) (prologue prologue)))

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
          (protocol-name (bytes->immutable-bytes (string->bytes/utf-8 protocol-name)))
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

(define handshake-state%
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

    (define using-psk? (send protocol using-psk?))

    (super-new)

    ;; --------------------
    ;; Initialization

    (begin
      (send protocol check-info-keys 'handshake-state% initiator? info)
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

    (define/public (direction rw)
      (get-direction initiator? rw))

    (define/public (can-write-message?)
      (and (pair? mpatterns)
           (eq? (message-pattern-dir (car mpatterns)) (direction 'write))))
    (define/public (can-read-message?)
      (and (pair? mpatterns)
           (eq? (message-pattern-dir (car mpatterns)) (direction 'read))))

    (define/public (next-payload-encrypted?)
      (or (send sstate has-key?)
          (and (pair? mpatterns)
               (for/or ([tok (in-list (message-pattern-tokens (car mpatterns)))])
                 (memq tok '(ee es se ss psk))))))

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
      (define out (open-output-bytes))
      (-write-message:pattern who mp out)
      (define enc-payload (-encrypt-and-hash payload))
      (write-bytes enc-payload out)
      (values (get-output-bytes out) (advance-pattern!)))

    (define/public (-write-message:pattern who mp out)
      (for ([sym (in-list (message-pattern-tokens mp))])
        (-write-message:token who sym out)))

    (define/public (-write-message:token who sym out)
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

    ;; read-handshake-message : Bytes -> (values Bytes (U #f HandshakeEnd))
    (define/public (read-handshake-message msg)
      (define who 'read-handshake-message)
      (define mp (next-message-pattern who 'read))
      (define msg-in (open-input-bytes msg))
      (-read-message:pattern who mp msg-in)
      (define enc-payload (port->bytes msg-in))
      (define payload (-decrypt-and-hash enc-payload))
      (values payload (advance-pattern!)))

    (define/public (-read-message:pattern who mp msg-in)
      (for ([sym (in-list (message-pattern-tokens mp))])
        (-read-message:token who sym msg-in)))

    (define/public (-read-message:token who sym msg-in)
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
;; Protocol State

(define protocol-state%
  (class* object% (protocol-state<%>)
    (init-field protocol initiator?)
    (init info prologue)

    ;; States:
    ;; - handshake  : hstate is handshake-state%, tstate-* = #f
    ;; - transport  : hstate = #f, one or both tstate-* is cipher-state%
    ;; - dead       : hstate = tstate-* = #f
    (define hstate       ;; #f or handshake-state%, mutated
      (new handshake-state% (protocol protocol) (initiator? initiator?)
           (info info) (prologue prologue)))
    (define tstate-w #f) ;; #f or cipher-state%, mutated
    (define tstate-r #f) ;; #f or cipher-state%, mutated
    (define hhash #f)    ;; #f or Bytes, mutated
    (define sema (make-semaphore 1))

    (super-new)

    (define/public (get-protocol) protocol)
    (define/public (get-initiator?) initiator?)

    ;; --------------------

    (define-syntax-rule (with-lock . body)
      ;; FIXME: close on error?
      (call-with-semaphore sema (lambda () . body)))

    (define/public (in-handshake-phase?) (and hstate #t))
    (define/public (in-transport-phase?) (and (or tstate-w tstate-r) #t))

    (define/public (get-handshake-hash)
      ;; May want to get hhash even if closed, so test hhash rather
      ;; than eg (in-transport-phase?).
      (or hhash (error 'get-handshake-hash "handshake is not finished")))

    (define/private (end-of-handshake! hs-end)
      (match hs-end
        [(list* hh cs-w cs-r)
         (set! hhash (bytes->immutable-bytes hh))
         (set! tstate-w cs-w)
         (set! tstate-r cs-r)
         (set! hstate #f)]))

    (define/private (close)
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

    (define/public (next-payload-encrypted?)
      (with-lock
        (cond [hstate (send hstate next-payload-encrypted?)]
              [else #| transport payloads always encrypted |# #t])))

    (define/public (get-keys-info)
      (with-lock
        (cond [hstate (send hstate get-keys-info)]
              [else '#hasheq()])))

    ;; --------------------

    (define/public (write-handshake-message payload)
      (with-lock
        (unless (and hstate (send hstate can-write-message?))
          (error 'write-handshake-message "cannot write handshake message~a"
                 (describe-state)))
        (define-values (msg hs-end)
          (send hstate write-handshake-message payload))
        (when hs-end (end-of-handshake! hs-end))
        msg))

    (define/public (read-handshake-message msg)
      (with-lock
        (unless (and hstate (send hstate can-read-message?))
          (error 'read-handshake-message "cannot read handshake message~a"
                 (describe-state)))
        (define-values (payload hs-end)
          (send hstate read-handshake-message msg))
        (when hs-end (end-of-handshake! hs-end))
        payload))

    ;; --------------------

    (define/public (write-transport-message payload)
      (with-lock
        (unless tstate-w
          (error 'write-transport-message "cannot write transport message~a"
                 (describe-state)))
        (send tstate-w encrypt-with-ad #"" payload)))

    (define/public (read-transport-message msg)
      (with-lock
        (unless tstate-r
          (error 'read-transport-message "cannot read transport message~a"
                 (describe-state)))
        (send tstate-r decrypt-with-ad #"" msg)))

    ;; --------------------

    (define/private (describe-state)
      (cond [hstate
             (cond [(send hstate can-write-message?)
                    ";\n in handshake phase (expecting write)"]
                   [(send hstate can-read-message?)
                    ";\n in handshake phase (expecting read)"]
                   [else
                    ";\n INTERNAL ERROR: in handshake phase but cannot read or write"])]
            [(and tstate-w tstate-r)
             ";\n in transport phase (can read or write)"]
            [tstate-w
             ";\n in transport phase (can write, cannot read)"]
            [tstate-r
             ";\n in transport phase (can read, cannot write)"]
            [else
             ";\n not connected"]))
    ))
