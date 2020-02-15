#lang racket/base
(require racket/match
         racket/list)
(provide (all-defined-out))

;; Reference: http://www.noiseprotocol.org/noise.html (revision 34)

;; TODO: Validity checker?

;; ----------------------------------------
;; Handshake patterns

(module rep racket/base
  (provide (all-defined-out))

  ;; HandshakePattern = (handshake-pattern MsgPatterns MsgPatterns MsgPattern MsgPattern)
  ;; where pre contains at most one MsgPattern per direction.
  (struct handshake-pattern (pre msgs t-> t<-) #:transparent)

  ;; MsgPattern = (message-pattern Direction (Listof Token) (U SecProp #f))
  (struct message-pattern (dir tokens plsec) #:transparent)

  ;; Direction = (U '<- '->)

  ;; get-direction : Boolean (U 'read 'write) -> Direction
  ;; Translates party perspective on read/write into protocol direction.
  (define (get-direction initiator? rw)
    (case rw
      [(write) (if initiator? '-> '<-)]
      [(read)  (if initiator? '<- '->)]))

  ;; Token = (U 'e 's 'ee 'es 'se 'ss 'psk)

  ;; SecProp = (secprop Nat Nat)
  ;; Indicates that a payload is allowed and describes its authentication and
  ;; confidentiality properties. Numbers are specified in Section 7.7 (rev 34).
  (struct secprop (auth-level conf-level) #:transparent)

  ;; handshake-pattern-{pre,t}/dir : HandshakePattern Direction -> MessagePattern
  (define (handshake-pattern-pre/dir hp dir)
    (for/first ([mp (in-list (handshake-pattern-pre hp))]
                #:when (eq? (message-pattern-dir mp) dir))
      mp))
  (define (handshake-pattern-t/dir hp dir)
    (case dir
      [(->) (handshake-pattern-t-> hp)]
      [(<-) (handshake-pattern-t<- hp)])))

(require (submod "." rep))
(provide (all-from-out (submod "." rep)))

;; ----------------------------------------

(module parser racket/base
  (require racket/list racket/match (submod ".." rep))
  (provide (all-defined-out))

  (define valid-dirs '(<- ->))
  (define valid-tokens '(s e se es ee ss psk))
  (define (dir-symbol? x) (and (memq x valid-dirs) #t))
  (define (token? x) (and (memq x valid-tokens) #t))

  ;; parse-handshake-pattern-def : Any -> (cons Symbol HandshakePattern)
  (define (parse-handshake-pattern-def x)
    (match x
      [(cons (? symbol? pattern-name) (? list? entries))
       (cons pattern-name (parse-handshake-pattern entries))]))

  ;; parse-handshake-pattern : Any -> HandshakePattern
  (define (parse-handshake-pattern xs)
    (define (k pre-xs xs)
      (define pre (parse-message-patterns pre-xs))
      (define hst (parse-message-patterns xs))
      (define-values (hs t)
        (splitf-at hst (lambda (p) (pair? (message-pattern-tokens p)))))
      (define (get-by-dir dir ps)
        (for/last ([p (in-list ps)] #:when (eq? dir (message-pattern-dir p))) p))
      (define t-> (or (get-by-dir '-> t) (message-pattern/no-tokens (get-by-dir '-> hs))))
      (define t<- (or (get-by-dir '<- t) (message-pattern/no-tokens (get-by-dir '<- hs))))
      (handshake-pattern pre hs t-> t<-))
    (cond [(index-of xs '...)
           => (lambda (sep-index)
                (k (take xs sep-index) (drop xs (add1 sep-index))))]
          [else (k null xs)]))

  ;; parse-message-patterns : Any -> (Listof MessagePattern)
  (define (parse-message-patterns xs)
    (match xs
      [(cons (? dir-symbol? dir) rest0)
       (define-values (tokens rest1) (splitf-at rest0 token?))
       (define-values (secpropss rest2) (splitf-at rest1 list?))
       (cons (message-pattern dir tokens (parse-secprop secpropss))
             (parse-message-patterns rest2))]
      ['()
       null]
      [_ (error 'parse-message-patterns "failed to parse: ~e" xs)]))

  ;; message-pattern/no-tokens : MessagePattern/#f -> MessagePattern/#f
  (define (message-pattern/no-tokens mp)
    (match mp
      [(message-pattern dir tokens sp) (message-pattern dir null sp)]
      [#f #f]))

  ;; parse-secprop : (Listof List) -> SecProp/#f
  (define (parse-secprop xs)
    (match xs
      [(list (list (? exact-nonnegative-integer? auth-level) (? exact-nonnegative-integer? conf-level)))
       (secprop auth-level conf-level)]
      ['() #f]
      [_ (error 'parse-message-patterns "failed to parse (security properties): ~e" xs)])))

(require (submod "." parser))

;; ----------------------------------------

(define handshake-table-source
  '([N
     <- s
     ...
     -> e es                   [0  2]
     ]

    [K
     -> s
     <- s
     ...
     -> e es ss                [1  2]
     ]

    [X
     <- s
     ...
     -> e es s ss              [1  2]
     ]

    [NN
     -> e                      [0  0]
     <- e ee                   [0  1]
     ->                        [0  1]
     ]

    [NK
     <- s
     ...
     -> e es                   [0  2]
     <- e ee                   [2  1]
     ->                        [0  5]
     ]

    [NX
     -> e                      [0  0]
     <- e ee s es              [2  1]
     ->                        [0  5]
     ]

    [XN
     -> e                      [0  0]
     <- e ee                   [0  1]
     -> s se                   [2  1]
     <-                        [0  5]
     ]

    [XK
     <- s
     ...
     -> e es                   [0  2]
     <- e ee                   [2  1]
     -> s se                   [2  5]
     <-                        [2  5]
     ]

    [XX
     -> e                      [0  0]
     <- e ee s es              [2  1]
     -> s se                   [2  5]
     <-                        [2  5]
     ]

    [KN
     -> s
     ...
     -> e                      [0  0]
     <- e ee se                [0  3]
     ->                        [2  1]
     <-                        [0  5]
     ]

    [KK
     -> s
     <- s
     ...
     -> e es ss                [1  2]
     <- e ee se                [2  4]
     ->                        [2  5]
     <-                        [2  5]
     ]

    [KX
     -> s
     ...
     -> e                      [0  0]
     <- e ee se s es           [2  3]
     ->                        [2  5]
     <-                        [2  5]
     ]

    [IN
     -> e s                    [0  0]
     <- e ee se                [0  3]
     ->                        [2  1]
     <-                        [0  5]
     ]

    [IK
     <- s
     ...
     -> e es s ss              [1  2]
     <- e ee se                [2  4]
     ->                        [2  5]
     <-                        [2  5]
     ]

    [IX
     -> e s                    [0  0]
     <- e ee se s es           [2  3]
     ->                        [2  5]
     <-                        [2  5]
     ]))

(define handshake-table
  (for/hash ([def (in-list handshake-table-source)])
    (match-define (cons name pattern) (parse-handshake-pattern-def def))
    (values name pattern)))

;; ----------------------------------------
;; Extensions

;; handshake-pattern-apply-extension : HandshakePattern String -> HandshakePattern
(define (handshake-pattern-apply-extension hp ext)
  (cond [(equal? ext "fallback")
         (fallback-handshake-pattern hp)]
        [(regexp-match #rx"^psk([0-9]+)$" ext)
         => (lambda (m) (pskN-handshake-pattern (string->number (cadr m)) hp))]
        [else
         (error 'handshake-pattern-apply-extension "unknown extension: ~e" ext)]))

;; ----------------------------------------
;; PSK extension

;; pskN-handshake-pattern : Nat HandshakePattern -> HandshakePattern
(define (pskN-handshake-pattern n hp)
  ;; Can psk change security properties? Maybe, but shouldn't decrease.
  (define msg-index (if (zero? n) 0 (sub1 n)))
  (define beginning? (zero? n))
  (define (add-psk mp)
    (match-define (message-pattern dir tokens sp) mp)
    (define tokens* (if beginning? (cons 'psk tokens) (append tokens '(psk))))
    (message-pattern dir tokens* sp))
  (match-define (handshake-pattern pre msgs t-> t<-) hp)
  (define msgs* (list-update msgs msg-index add-psk))
  (handshake-pattern (map add-psk pre) msgs* t-> t<-))

;; ----------------------------------------
;; Fallback extension

;; fallback-handshake-pattern : HandshakePattern -> HandshakePattern
(define (fallback-handshake-pattern hp)
  (flip-handshake-pattern (fallback-handshake-pattern* hp)))

;; fallback-handshake-pattern* : HandshakePattern -> HandshakePattern
(define (fallback-handshake-pattern* hp)
  (define (merge-pre mp pre)
    (match-define (message-pattern m-dir m-tokens _) mp)
    (let loop ([pre pre])
      (match pre
        ['() (list (message-pattern m-dir m-tokens #f))]
        [(cons (message-pattern (== m-dir) tokens _) pre)
         (cons (message-pattern m-dir (append tokens m-tokens) #f) pre)]
        [(cons mp pre)
         (cons mp (loop pre))])))
  (match-define (handshake-pattern pre (cons msg1 msgs) t-> t<-) hp)
  (handshake-pattern (merge-pre msg1 pre) msgs t-> t<-))

;; fallback-handshake-pattern : HandshakePattern -> HandshakePattern
(define (flip-handshake-pattern hp)
  (define (flip-dir dir) (case dir [(->) '<-] [(<-) '->]))
  (define (flip-token token) (case token [(se) 'es] [(es) 'se] [else token]))
  (define (flip-msg mp)
    (match-define (message-pattern dir tokens sp) mp)
    (message-pattern (flip-dir dir) (map flip-token tokens) sp))
  (match-define (handshake-pattern pre msgs t-> t<-) hp)
  (handshake-pattern (map flip-msg pre) (map flip-msg msgs) t<- t->))
