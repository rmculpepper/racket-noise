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

;; info-hash/c does NOT check the following:
;; - private-keys are right kind
;; - right keys are present
;; FIXME: maybe parameterize over key type, key set?

(define info-hash/c
  (hash/dc [k symbol?]
           [v (k)
              (case k
                [(s e) private-key?]
                [(rs re) pub-key-bytes/c]
                [(psk) (or/c bytes? (-> pub-key-bytes/c key-bytes/c))]
                [else none/c])]
           #:immutable #t))

;; ----------------------------------------
;; Interfaces

(define (noise-protocol? x) (is-a? x protocol<%>))
(define (noise-handshake-state? x) (is-a? x handshake-state<%>))
(define (noise-transport? x) (is-a? x transport<%>))

;; Some interfaces come in public / internal pairs plus predicate, eg
;; - noise-protocol<%>  -- public interface
;; - protocol<%>        -- internal interface, extends noise-protocol<%>
;; - noise-protocol?    -- recognizes instances of protocol<%>, NOT noise-protocol<%>

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

(define noise-handshake-state<%>
  (interface ()
    [can-write-message? (->m boolean?)]
    [can-read-message? (->m boolean?)]
    [write-handshake-message (->m bytes? bytes?)]
    [read-handshake-message (->m bytes? bytes?)]
    [get-transport (->m (or/c #f noise-transport?))]
    ))

(define handshake-state<%>
  (interface (noise-handshake-state<%>)
    [get-keys-info (->m info-hash/c)]
    ))

(define noise-transport<%>
  (interface ()
    [get-handshake-hash (->m bytes?)]
    [write-message (->m bytes? bytes?)]
    [read-message (->m bytes? bytes?)]
    ))

(define transport<%>
  (interface (noise-transport<%>)
    ))

;; --------------------

(define noise-protocol<%>
  (interface ()
    [get-protocol-name (->m bytes?)]
    [get-extensions (->m (listof string?))]
    [get-info-keys (->m boolean? (listof symbol?))]
    [using-psk? (->m boolean?)]
    [generate-private-key (->m private-key?)]
    [pk->public-bytes (->m pk-key? bytes?)]
    ))

(define protocol<%>
  (interface ()
    [get-crypto (->m (is-a?/c crypto<%>))]
    [get-pattern (->m handshake-pattern?)]
    [new-handshake
     (->*m [boolean? info-hash/c]
           [#:prologue bytes?]
           noise-handshake-state?)]
    ))

;; --------------------

;; Mapping names to Noise specs
;; - noise-socket<%> represents a Noise Socket in transport phase
;; - noise-socket-handshake<%> handles handshake phase

(define (noise-socket? x) (is-a? x socket<%>))
(define (noise-socket-handshake-state? x) (is-a? x socket-handshake-state<%>))

(define noise-socket<%>
  (interface ()
    [write-message (->*m [bytes?] [exact-nonnegative-integer?] void?)]
    [read-message (->m bytes?)]
    ))

(define socket<%>
  (interface (noise-socket<%>)
    ))

(define noise-socket-handshake-state<%>
  (interface ()
    ))

(define socket-handshake-state<%>
  (interface (noise-socket-handshake-state<%>)
    [get-socket (->m (or/c #f noise-socket?))]
    ))

(define lingo-config/c hash?) ;; FIXME

(define lingo-handshake-state<%>
  (interface ()
    [connect (->m noise-socket?)]
    [accept (->m noise-socket?)]
    ))
