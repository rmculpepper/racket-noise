#lang racket/base
(require (only-in racket/base [exact-nonnegative-integer? nat?])
         racket/class
         racket/contract
         crypto
         (submod "patterns.rkt" rep))
(provide (all-defined-out))

(define ((bytes/len/c len) x) (and (bytes? x) (= (bytes-length x) len)))

(define key-bytes/c (bytes/len/c 32))
(define (pub-key-bytes/c x) (and (bytes? x) (>= (bytes-length x) 32)))
(define (priv-key-bytes/c x) (and (bytes? x) (>= (bytes-length x) 64))) ;; ???
(define (dh-bytes/c x) (and (bytes? x) (>= (bytes-length x) 32)))

(define handshake-end/c any/c) ;; FIXME

(define info-hash/c
  (hash/dc [k symbol?]
           [v (k)
              (case k
                [(s e) (or/c private-key? priv-key-bytes/c)]
                [(rs re) (or/c pub-key-bytes/c)]
                [(psk) (or/c bytes? (-> pub-key-bytes/c key-bytes/c))]
                [else none/c])]
           #:immutable #t))

(define crypto<%>
  (interface ()
    [get-hashlen (->m exact-positive-integer?)]
    [digest (->m bytes? bytes?)]
    [hkdf-n (->m bytes? bytes? nat? any)] ;; FIXME?
    [encrypt (->m key-bytes/c nat? bytes? bytes? bytes?)]
    [decrypt (->m key-bytes/c nat? bytes? bytes? bytes?)]
    [rekey  (->m key-bytes/c key-bytes/c)]
    [get-dhlen (->m exact-positive-integer?)]
    [generate-private-key (->m private-key?)]
    [dh (->m private-key? pub-key-bytes/c dh-bytes/c)]
    [pk->public-bytes (->m pk-key? pub-key-bytes/c)]
    [bytes->private-key (->m bytes? private-key?)]
    [datum->pk-key (->m any/c symbol? pk-key?)]
    ))

(define cipher-state<%>
  (interface ()
    [initialize-key (->m key-bytes/c void?)]
    [has-key? (->m boolean?)]
    [set-nonce! (->m nat? void?)]
    [encrypt-with-ad (->m bytes? bytes? bytes?)]
    [decrypt-with-ad (->m bytes? bytes? bytes?)]
    [rekey (->m void?)]
    ))

(define symmetric-state<%>
  (interface ()
    [mix-key (->m bytes? void?)]
    [mix-hash (->m bytes? void?)]
    [mix-key-and-hash (->m bytes? void?)]
    [get-handshake-hash (->m bytes?)]
    [encrypt-and-hash (->m bytes? bytes?)]
    [decrypt-and-hash (->m bytes? bytes?)]
    [split (->m (values (is-a?/c cipher-state<%>) (is-a?/c cipher-state<%>)))]
    [has-key? (->m boolean?)]
    ))

(define handshake-state<%>
  (interface ()
    [can-write-message? (->m boolean?)]
    [can-read-message? (->m boolean?)]
    [write-handshake-message (->m bytes? (values bytes? handshake-end/c))]
    [read-handshake-message (->m bytes? (values bytes? handshake-end/c))]
    ))

(define connection<%>
  (interface ()
    [in-handshake-phase? (->m boolean?)]
    [in-transport-phase? (->m boolean?)]
    [can-write-message? (->m boolean?)]
    [can-read-message? (->m boolean?)]
    [get-handshake-hash (->m bytes?)]
    [write-handshake-message (->m bytes? bytes?)]
    [write-transport-message (->m bytes? bytes?)]
    [read-handshake-message (->m bytes? bytes?)]
    [read-transport-message (->m bytes? bytes?)]
    ))

(define protocol<%>
  (interface ()
    [get-crypto (->m (is-a?/c crypto<%>))]
    [get-pattern (->m handshake-pattern?)]
    [get-protocol-name (->m bytes?)]
    [get-extensions (->m (listof string?))]
    [using-psk? (->m boolean?)]
    [new-connection
     (->*m [boolean?]
           [info-hash/c
            #:s (or/c #f private-key? bytes?)
            #:rs (or/c #f private-key? bytes?)]
           (is-a?/c connection<%>))]
    [new-initiator
     (->*m []
           [info-hash/c
            #:s (or/c #f private-key? bytes?)
            #:rs (or/c #f private-key? bytes?)]
           (is-a?/c connection<%>))]
    [new-responder
     (->*m []
           [info-hash/c
            #:s (or/c #f private-key? bytes?)
            #:rs (or/c #f private-key? bytes?)]
           (is-a?/c connection<%>))]
    [generate-private-key (->m private-key?)]
    [bytes->private-key (->m bytes? private-key?)]
    [datum->pk-key (->m any/c symbol? pk-key?)]
    ))
