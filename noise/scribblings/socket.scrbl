#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/example
          racket/list
          racket/runtime-path
          crypto/private/common/catalog
          (for-label racket/base racket/contract racket/random racket/class
                     crypto crypto/libcrypto
                     noise/protocol noise/socket noise/lingo))

@(define-runtime-path log-file "eval-logs/socket.rktd")
@(define the-eval (make-log-based-eval log-file 'record))
@(the-eval '(require crypto crypto/libcrypto noise/protocol noise/socket noise/lingo))
@(the-eval '(crypto-factories (list libcrypto-factory)))

@title[#:tag "socket"]{Noise Sockets}

@defmodule[noise/socket]

@; ------------------------------------------------------------
@section[#:tag "intro-socket"]{Introduction to Noise Sockets}

This example shares some of the same setup as
@secref["intro-protocol"]:

@examples[#:eval the-eval #:label #f
(require racket/class noise/protocol crypto crypto/libcrypto)
(crypto-factories (list libcrypto-factory))

(define ik-proto
  (noise-protocol "Noise_IK_25519_ChaChaPoly_SHA512"))
(define xx-fallback-proto
  (noise-protocol "Noise_XXfallback_25519_ChaChaPoly_SHA512"))

(define alice-sk (send ik-proto generate-private-key))
(define alice-pub (send ik-proto pk->public-bytes alice-sk))

(define bob-sk (send ik-proto generate-private-key))
(define bob-pub (send ik-proto pk->public-bytes bob-sk))
]

@examples[#:eval the-eval #:label #f
(require noise/socket noise/lingo)
]

@examples[#:eval the-eval #:label #f
(define alice-config
  (hasheq 'keys-info (hasheq 's alice-sk 'rs bob-pub)
          'initial-protocol ik-proto
          'switch-protocols (list xx-fallback-proto)))
(define bob-config
  (hasheq 'keys-info (hasheq 's bob-sk)
          'protocols (list ik-proto)
          'switch-protocols (list xx-fallback-proto)))
]

@examples[#:eval the-eval #:label #f
(define-values (a-in b-out) (make-pipe))
(define-values (b-in a-out) (make-pipe))

(require racket/promise)
(define alice-p (delay/thread (noise-lingo-connect a-in a-out alice-config)))
(define bob (noise-lingo-accept b-in b-out bob-config))
(define alice (force alice-p))
]

@examples[#:eval the-eval #:label #f
(send alice write-message #"hello")
(send bob read-message)

(send bob write-message #"hello back")
(send alice read-message)

(send alice write-message #"nice talking with you")
(send bob read-message)

(send bob write-message #"likewise")
(send alice read-message)
]






@; ------------------------------------------------------------
@section[#:tag "socket-transport"]{Noise Sockets}

@defproc[(noise-socket? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a Noise socket in transport
phase, @racket[#f] otherwise.

See also @racket[noise-socket<%>].
}

@definterface[noise-socket<%> ()]{

@defmethod[(get-handshake-hash) bytes?]
@defmethod[(write-transport-message [plaintext bytes?]
                                    [padding exact-nonnegative-integer? 0])
           void?]
@defmethod[(read-transport-message) bytes?]

}

@; ------------------------------------------------------------
@section[#:tag "socket-handshake"]{Noise Socket Handshakes}

@defproc[(noise-socket-handshake-state? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a Noise socket handshake state,
@racket[#f] otherwise.

See also @racket[noise-socket-handshake-state<%>].
}

@definterface[noise-socket-handshake-state<%> ()]{

@defmethod[(can-write-message?) boolean?]
@defmethod[(can-read-message?) boolean?]

@defmethod[(write-handshake-message [negotiation bytes?]
                                    [noise-payload (or/c bytes? #f)])
           void?]

@defmethod[(read-handshake-message) (values bytes? bytes)]

@defmethod[(read-handshake-negotiation) bytes?]

@defmethod[(read-handshake-noise [mode (or/c 'decrypt 'try-decrypt 'discard)])
           (or/c bytes? 'bad 'discarded)]

@defmethod[(get-socket) (or/c #f noise-socket?)]

}


@; ------------------------------------------------------------
@section[#:tag "nls"]{Noise Lingo Sockets (NLS)}

@defmodule[noise/lingo]

@defproc[(noise-lingo-connect [in input-port?] [out output-port?] [config hash?])
         noise-socket?]{

}

@defproc[(noise-lingo-accept [in input-port?] [out output-port?] [config hash?])
         noise-socket?]{

}


@(close-eval the-eval)
