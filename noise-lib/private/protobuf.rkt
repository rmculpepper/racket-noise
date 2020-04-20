#lang racket/base
(require racket/match
         racket/port
         racket/promise)
(provide Message
         Wrap
         Map
         Enum

         write-length-tagged-message
         write-message
         message->bytes

         read-length-tagged-message
         read-message
         bytes->message)

;; ============================================================

;; CType = Type | (t:repeat Type) | (t:wrap CType (X -> Value) (Value -> X))
;; A CType is an extended type that describes fields ("components"),
;; allowing repetitions and wrapping around repetitions (eg for Maps).
(struct t:repeat (type) #:transparent)
(struct t:wrap (type enc dec) #:transparent)

;; Type =
;; | 'int{32,64} | '{u,s}int{32,64} | 'bool | 'fixed{32,64} | 'float | 'double
;; | 'string | 'bytes
;; | (t:wrap Type (X -> Encodable[Type]) ([Encodable[Type] -> X]))
;; | (t:message (Listof Component) Value[Type])
;; | (delay MessageType) -- non-MessageType might work, but wrong wrt default value
(struct t:message (components default) #:transparent)

;; Field = (field Symbol Nat CType (Listof Symbol))
(struct field (name index type clear) #:transparent)

;; lookup-component-by-{index,name} : (Listof Field) {Nat,Symbol} -> Field/#f
(define (lookup-component-by-index cs index)
  (for/first ([c (in-list cs)] #:when (= index (field-index c))) c))
(define (lookup-component-by-name cs name)
  (for/first ([c (in-list cs)] #:when (eq? name (field-name c))) c))

;; ctype-default : CType -> Value
;; Used to create initial message with default field values.
(define (ctype-default ctype)
  (match ctype
    [(t:repeat _) null]
    ;; Don't decode default for wrapped *ctype*, to allow list merging. See finish.
    [(t:wrap ctype _ _) (type-default ctype)]
    [type (type-default type)]))

;; type-default : Type -> Value
;; Used to decide whether to encode a field (can skip if has default value).
(define (type-default type)
  (case type
    [(int32 int64 uint32 uint64 sint32 sint64) 0]
    [(bool) #f]
    [(fixed32 fixed64) 0]
    [(float double) 0.0]
    [(string) ""]
    [(bytes) #""]
    [else
     (match type
       ;; Do apply decode to default of wrapped type.
       [(t:wrap type enc dec) (dec (type-default type))]
       ;; Do *not* recur on message type (or promise thereof).
       [_ #f])]))

;; fields-default : (Listof Field) -> Hasheq[Symbol => Value]
;; Does not set fields within oneof groups; presence indicates which set.
(define (components-default cs)
  (for/fold ([h '#hasheq()]) ([c (in-list cs)])
    (match c
      [(field name index type '())
       (hash-set h name (ctype-default type))]
      [_ h])))

;; ----------------------------------------
;; Wire types

;; 0 - Varint - int32, int64, uint32, uint64, sint32, sint64, bool, enum
;; 1 - 64-bit - fixed64, sfixed64, double
;; 2 - length-delimited - string, bytes, embedded messages, packed repeated fields
;; 5 - 32-bit - fixed32, sfixed32, float

;; type->wtype : Type -> WType
(define (type->wtype type)
  (or (numeric-type->wtype type) 2))

;; numeric-type->wtype : Type -> WType/#f
;; Returns wtype or #f if the type is not a primitive numeric type.
(define (numeric-type->wtype type)
  (case type
    [(int32 int64 uint32 uint64 sint32 sint64 bool) 0]
    [(fixed64 sfixed64 double) 1]
    [(fixed32 sfixed32 float) 5]
    [else
     (match type
       [(t:wrap type _ _) (numeric-type->wtype type)]
       [_ #f])]))

;; ----------------------------------------
;; Read/write length-tagged messages

(define (write-length-tagged-message mtype value out)
  (define vbs (message->bytes mtype value))
  (write-uvarint (bytes-length vbs) out)
  (write-bytes vbs out))

(define (read-length-tagged-message mtype in)
  (define len (read-uvarint in))
  (bytes->message (read-bytes len in)))

;; ----------------------------------------
;; Field header

;; Each message field is prefixed by a Header:
;;
;;   Header = (Index << 3) + WType
;;
;; The header does *not* include the length, for variable-length
;; fields and packed repeated fields.

;; write-header : Nat WType OutputPort -> Void
(define (write-header index wtype out)
  (write-uvarint (+ (arithmetic-shift index 3) wtype) out))

;; read-header : InputPort -> (values Nat WType)
(define (read-header in)
  (define index+wtype (read-varint in))
  (values (arithmetic-shift index+wtype -3)
          (bitwise-bit-field index+wtype 0 3)))

;; ----------------------------------------
;; Write messages

(define (message->bytes mtype value)
  (call-with-output-bytes
   (lambda (out) (write-message mtype value out))))

(define (write-message mtype value out)
  (match-define (t:message cs _) mtype)
  (write-components cs value out))

(define (write-components cs h out)
  (for ([c (in-list cs)]) (write-component c h out)))

(define (write-component c h out)
  (match-define (field name index ctype clear) c)
  (define value (hash-ref h name #f))
  (let loop ([ctype ctype] [value value])
    (match ctype
      [(t:wrap ctype enc dec)
       (loop ctype (enc value))]
      [(t:repeat type)
       (cond [(and (numeric-type->wtype type) (pair? value)) ;; pack!
              (write-header index 2 out)
              (define vbss (for/list ([v (in-list (or value null))]) (value->bytes v type)))
              (write-uvarint (apply + (map bytes-length vbss)) out)
              (for ([vbs (in-list vbss)]) (write-bytes vbs out))]
             [else
              (define wtype (type->wtype type))
              (for ([v (in-list (or value null))])
                (write-header index wtype out)
                (write-value-bytes wtype (value->bytes v type) out))])]
      [type
       (let loop ([type type])
         (cond [(promise? type) (loop (force type))]
               [(or (eq? value #f) (equal? value (type-default type)))
                (void)]
               [else
                (define wtype (type->wtype type))
                (write-header index wtype out)
                (write-value-bytes wtype (value->bytes value type) out)]))])))

(define (write-value-bytes wtype vbs out)
  (when (= wtype 2) (write-uvarint (bytes-length vbs) out))
  (write-bytes vbs out))

(define (value->bytes value type)
  (case type
    [(int32 int64) (varint->bytes value)]
    [(uint32 uint64) (uvarint->bytes value)]
    [(sint32 sint64) (uvarint->bytes (zigzag value))]
    [(bool) (uvarint->bytes (if value 1 0))]
    [(fixed32) (integer->integer-bytes value 4 #f #f)]
    [(fixed64) (integer->integer-bytes value 8 #f #f)]
    [(float) (real->floating-point-bytes value 4 #f)]
    [(double) (real->floating-point-bytes value 8 #f)]
    [(string) (string->bytes/utf-8 value)]
    [(bytes) value]
    [else
     (match type
       [(t:message cs _)
        (call-with-output-bytes
         (lambda (out) (write-components cs value out)))]
       [(t:wrap type enc dec)
        (value->bytes (enc value) type)])]))

;; ----------------------------------------
;; Reading

(define (bytes->message mtype bs)
  (read-message mtype (open-input-bytes bs)))

(define (read-message mtype in)
  (match-define (t:message cs default) mtype)
  (read-components cs default in))

(define (read-components cs default in)
  (define (finish h) ;; apply decoder for all wrapped ctypes
    (for/fold ([h h]) ([c (in-list cs)])
      (match c
        [(field name index ctype _)
         (if (and (t:wrap? ctype) (hash-has-key? h name))
             (hash-set h name
                       (let loop ([ctype ctype])
                         (match ctype
                           [(t:wrap ctype enc dec) (dec (loop ctype))]
                           [_ (hash-ref h name)])))
             h)]
        [_ h])))
  (let loop ([h default])
    (cond [(eof-object? (peek-byte in)) (finish h)]
          [else
           (define-values (index wtype value) (read-component in))
           (match (lookup-component-by-index cs index)
             [(field name index ctype _)
              (define v (parse-component ctype value wtype))
              (loop (hash-set h name (if (list? v) (append (hash-ref h name null) v) v)))]
             [#f (loop h)])])))

(define (parse-component ctype value wtype)
  (let loop ([ctype ctype])
    (match ctype
      [(t:wrap ctype enc dec)
       ;; Do not apply dec here, so if ctype is rep we do list merging. See finish above.
       (loop ctype)]
      [(t:repeat type)
       (cond [(and (= wtype 2) (numeric-type->wtype type))
              => (lambda (vwtype) ;; packed
                   (define in (open-input-bytes value))
                   (let loop ()
                     (cond [(eof-object? (peek-byte in)) null]
                           [else (cons (parse-value1 (read-value vwtype in) type)
                                       (loop))])))]
             [else (list (parse-value1 value type))])]
      [type (parse-value1 value type)])))

(define (parse-value1 value type)
  ;; value is either uvarint or bytes, depending on wtype
  (case type
    [(int32 int64) (uvarint->varint value)]
    [(uint32 uint64) value]
    [(sint32 sint64) (unzigzag value)]
    [(bool) (not (zero? value))]
    [(fixed64 fixed32) (integer-bytes->integer value #f #f)]
    [(sfixed64 sfixed32) (integer-bytes->integer value #t #f)]
    [(double float) (floating-point-bytes->real value #f)]
    [(string) (string->immutable-string (bytes->string/utf-8 value))]
    [(bytes) (bytes->immutable-bytes value)]
    [else
     (match type
       [(? promise?) (parse-value1 value (force type))]
       [(t:message components default)
        (read-components components default (open-input-bytes value))]
       [(t:wrap type enc dec)
        (dec (parse-value1 value type))])]))

(define (read-component in)
  (define-values (index wtype) (read-header in))
  (values index wtype (read-value wtype in)))

(define (read-value wtype in)
  (case wtype
    [(0) (read-uvarint in)]
    [(1) (read-bytes 8 in)]
    [(2) (let ([len (read-uvarint in)]) (read-bytes len in))]
    [(5) (read-bytes 4 in)]))

;; ----------------------------------------
;; Varints and integers

;; Varint
;; Stored least-significant segment first. High bit of each byte indicates "more".

(define (read-uvarint in)
  (let loop ()
    (define next (read-byte in))
    (cond [(bitwise-bit-set? next 7)
           (+ (arithmetic-shift (read-varint in) 7)
              (bitwise-xor #x80 next))]
          [else next])))

(define (write-uvarint n out)
  (if (zero? n)
      (write-byte 0 out)
      (let loop ([n n])
        (cond [(< n (expt 2 7))
               (write-byte n out)]
              [else
               (write-byte (+ #x80 (bitwise-bit-field n 0 7)) out)
               (loop (arithmetic-shift n -7))]))))

(define (uvarint->varint n)
  (if (bitwise-bit-set? n 63)
      (bitwise-ior n (arithmetic-shift -1 64))
      n))

(define (varint->uvarint n)
  (if (< n 0) (bitwise-xor n (arithmetic-shift -1 64)) n))

(define (read-varint in)
  (uvarint->varint (read-uvarint in)))

(define (write-varint n out)
  (write-uvarint (varint->uvarint n) out))

(define (uvarint->bytes n)
  (call-with-output-bytes (lambda (out) (write-uvarint n out))))

(define (varint->bytes n)
  (call-with-output-bytes (lambda (out) (write-varint n out))))

(define (bytes->varint bs)
  (read-varint (open-input-bytes bs)))

(define (bytes->uvarint bs)
  (read-uvarint (open-input-bytes bs)))

(define (zigzag n)
  (bitwise-xor (arithmetic-shift n 1) (if (negative? n) -1 0)))

(define (unzigzag n)
  (if (bitwise-bit-set? n 0) ;; negative
      (bitwise-xor (arithmetic-shift n -1) -1)
      (arithmetic-shift n -1)))

;; ============================================================
;; Syntax for types

(require (for-syntax racket/base syntax/parse))

(begin-for-syntax
  (define-syntax-class Field
    #:attributes (name expr)
    (pattern [index:nat name:id type:expr]
             #:with expr #'(lambda (type-f clear) (field 'name 'index (type-f type) clear))))
  (define-splicing-syntax-class Component
    #:attributes (expr)
    (pattern f:Field
             #:with expr #'(list (f.expr values null)))
    (pattern (~seq #:oneof [f:Field ...])
             #:with expr #'(let ([clear '(f.name ...)]) (list (f.expr values clear) ...)))
    (pattern (~seq #:repeated f:Field)
             #:with expr #'(list (f.expr t:repeat null)))))

(define-syntax Message
  (syntax-parser
    [(_ c:Component ...)
     #'(let ([cs (append c.expr ...)])
         (t:message cs (components-default cs)))]))

(define-syntax Enum
  (syntax-parser
    [(_ [name:id n:nat] ...)
     #'(t:enum (hasheq  (~@ 'name 'n) ...)
               (hasheqv (~@ 'n 'name) ...))]))

(define (t:enum enc-h dec-h)
  (t:wrap 'int32
          (lambda (s) (or (hash-ref enc-h s #f) (error 'enum "no encoding: ~e" s)))
          (lambda (n) (or (hash-ref dec-h n #f) (error 'enum "no decoding: ~e" n)))))

(define (Wrap type enc dec) (t:wrap type enc dec))

(define (Map key-type val-type)
  (t:wrap (t:repeat (Message [1 key key-type] [2 value val-type]))
          (lambda (h) (if h (for/list ([(k v) (in-hash h)]) (hash 'key k 'value v)) null))
          (lambda (entries)
            (for/hash ([e (in-list entries)])
              (values (hash-ref e 'key) (hash-ref e 'value))))))

;; ============================================================

(module+ test
  (provide (all-defined-out))

  (define SearchRequest
    (Message
     [1 query            'string]
     [2 page_number      'int32]
     [3 results_per_page 'int32]))

  (define Result
    (Message
     [1 url 'string]
     [2 title 'string]
     #:repeated
     [3 snippets 'string]
     [4 words (Map 'string 'uint32)]))

  (define SearchResponse
    (Message
     #:repeated
     [1 results Result]))

  (define sr1
    (hash 'results
          (list (hash 'url "http://here" 'title "Here" 'snippets '("I am" "we go again")
                      'words (hash "zz" 1 "yy" 2))
                (hash 'url "http://be" 'title "Be" 'snippets '("witched")))))

  (define enc-sr1 (message->bytes SearchResponse sr1))
  (define dec-sr1 (bytes->message SearchResponse enc-sr1))

  ;; ----

  (define BranchTree
    (Message
     [1 left (delay BinTree)]
     [2 right (delay BinTree)]))
  (define BinTree
    (Message
     #:oneof
     [[1 leaf 'int32]
      [2 branch BranchTree]]))

  (define t1
    (hash 'branch (hash 'left (hash 'leaf 12)
                        'right (hash 'branch
                                     (hash 'left (hash 'leaf 17)
                                           'right (hash 'leaf 28))))))

  (define enc-t1 (message->bytes BinTree t1))
  (define dec-t1 (bytes->message BinTree enc-t1))
  )
