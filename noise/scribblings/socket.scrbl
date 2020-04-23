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

This section covers NoiseSocket @cite{NoiseSocket} and its
instantiation NoiseLingoSocket @cite{NLS}.


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
(define bob-sk (send ik-proto generate-private-key))
]

We also require the implementations of NoiseSocket and NLS:

@examples[#:eval the-eval #:label #f
(require noise/socket noise/lingo)
]

In order to potentially exercise both Noise protocols defined above,
let's say that Alice may or may not have the correct public key for
Bob:

@examples[#:eval the-eval #:label #f
(define bob-pub
  (cond [(zero? (random 2))
         (printf "Alice has Bob's real public key\n")
         (send ik-proto pk->public-bytes bob-sk)]
        [else
         (printf "Alice has the wrong public key for Bob\n")
         (crypto-random-bytes 32)]))
]

We configure Alice to try the @tt{IK} protocol first, but to allow Bob
to switch to the @tt{XXfallback} (for example, if Alice has the wrong
public key for Bob, in which case the @tt{IK} handshake will
fail). Likewise, we configure Bob to accept the @tt{IK} protocol but
to switch to the @tt{XXfallback} protocol if the @tt{IK} handshake
fails.

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

We set up IO ports for communication between Alice and Bob:

@examples[#:eval the-eval #:label #f
(define-values (a-in b-out) (make-pipe))
(define-values (b-in a-out) (make-pipe))
]

Using the IO ports created above, we attempt to create sockets for
Alice and Bob. Alice connects and Bob accepts. Note that both
@racket[noise-lingo-connect] and @racket[noise-lingo-accept] are
blocking operations, so one of them must be done in a separate thread.

@examples[#:eval the-eval #:label #f
(require racket/promise)
(define alice-p (delay/thread (noise-lingo-connect a-in a-out alice-config)))
(define bob (noise-lingo-accept b-in b-out bob-config))
(define alice (force alice-p))
]

The @racket[noise-lingo-connect] and @racket[noise-lingo-accept]
operations handle the handshake phase automatically, so once they
return Alice and Bob can exchange messages freely.

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

@; FIXME: disconnect???


@; ------------------------------------------------------------
@section[#:tag "sockets"]{Noise Sockets}

@defmodule[noise/socket]

@; ------------------------------------------------------------
@subsection[#:tag "socket-transport"]{Noise Sockets}

The @racketmodname[noise/socket] library provides an implementation
of @hyperlink["https://noisesocket.org/"]{NoiseSocket}.

Specifically, this library implements revision 2draft (2018-03-04)
@cite{NoiseSocket}.

@defproc[(noise-socket? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a Noise socket in transport
phase, @racket[#f] otherwise.

See also @racket[noise-socket<%>].
}

@definterface[noise-socket<%> ()]{

@defmethod[(get-handshake-hash) bytes?]
@defmethod[(write-message [plaintext bytes?]
                          [padding exact-nonnegative-integer? 0])
           void?]
@defmethod[(read-message) bytes?]

}

@; ------------------------------------------------------------
@subsection[#:tag "socket-handshake"]{Noise Socket Handshakes}

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


@; ------------------------------------------------------------

@bibliography[
#:tag "socket-bibliography"

@bib-entry[#:key "NoiseSocket"
           #:title "The NoiseSocket Protocol"
           #:author "Alexey Ermishkin and Trevor Perrin"
           #:url "https://noisesocket.org/spec/noisesocket/"
           #:date "2018-03-04"
           #:note " (revision 2draft)"]

@bib-entry[#:key "NLS"
           #:title "The NLS Framework"
           #:author "Trevor Perrin"
           #:url "https://noisesocket.org/spec/nls/"
           #:date "2018-03-05"
           #:note " (revision 1, unofficial/unstable)"]

@bib-entry[#:key "NLS-rev2"
           #:title "The NLS Framework"
           #:author "Trevor Perrin"
           #:url "https://github.com/noiseprotocol/nls_spec/blob/rev2/nls.md"
           #:date "2018-03-18"
           #:note " (revision 2, unofficial/unstable)"]

]

@(close-eval the-eval)
