#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/example
          racket/list
          racket/runtime-path
          crypto/private/common/catalog
          (for-label racket/base racket/contract racket/random racket/class
                     crypto crypto/libcrypto
                     noise/protocol noise/socket))

@(define-runtime-path log-file "eval-logs/socket.rktd")
@(define the-eval (make-log-based-eval log-file 'record))
@(the-eval '(require crypto crypto/libcrypto noise/protocol noise/socket))
@(the-eval '(crypto-factories (list libcrypto-factory)))

@title[#:tag "socket"]{Noise Sockets}

@defmodule[noise/socket]

This library implements NoiseLingoSocket @cite{NLS}, a combination of
NoiseSocket @cite{NoiseSocket} and the NoiseLingo negotiation
language.

Specifically, this library implements NoiseSocket revision 2draft
(2018-03-04) @cite{NoiseSocket} and NLS version 2 (2018-03-18)
@cite{NLS-rev2}.


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

We also require the Noise socket implementation:

@examples[#:eval the-eval #:label #f
(require noise/socket)
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
          'protocols (list ik-proto)
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
Alice and Bob. Alice connects and Bob accepts. Note that
@racket[noise-lingo-socket] is a blocking operation, so one of them
must be done in a separate thread.

@examples[#:eval the-eval #:label #f
(require racket/promise)
(define alice-p (delay/thread (noise-lingo-socket 'connect a-in a-out alice-config)))
(define bob (noise-lingo-socket 'accept b-in b-out bob-config))
(define alice (force alice-p))
]

The @racket[noise-lingo-socket] operation handles the handshake phase
automatically, so once the sockets are created Alice and Bob can
exchange messages freely.

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
@section[#:tag "socket-transport"]{Noise Sockets}

@defproc[(noise-socket? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a Noise socket in transport
phase, @racket[#f] otherwise.

See also @racket[noise-socket<%>].
}

@definterface[noise-socket<%> ()]{

@defmethod[(get-handshake-hash) bytes?]{

Returns a cryptographic hash of the handshake.
}

@defmethod[(write-message [plaintext bytes?]
                          [padding exact-nonnegative-integer? 0])
           void?]{

Encrypts a transport message and sends it to the socket's peer.

If @racket[padding] is non-zero, then @racket[padding] random
bytes of padding are added to the message; they are automatically
removed by @method[noise-socket<%> read-message].

The length of @racket[plaintext] and @racket[padding] must sum to at
most @racket[noise-socket-max-plaintext] bytes.

Note that each party has independent messages counters for reading and
writing. Messages written by one party must be read by the other party
in the same order; but reading does not affect the write counter, and
vice versa.
}

@defmethod[(read-message) bytes?]{

Reads a transport message from the socket's peer and decrypts it,
returning the plaintext. If the peer added padding, the padding is
automatically removed.

See the note about message ordering in @method[write-message
noise-socket<%>].

If decryption fails, an exception is raised.
}

}


@; ------------------------------------------------------------
@section[#:tag "nls"]{Noise Lingo Sockets (NLS)}

NLS @cite{NLS} defines a negotiation language for handshaking on top
of NoiseSocket.

@defproc[(noise-lingo-socket [mode (or/c 'connect 'accept)]
                             [in input-port?]
                             [out output-port?]
                             [config noise-socket-config/c])
         noise-socket?]{

Creates a Noise socket that communicates with its peer using
@racket[in] and @racket[out]. The socket attempts to perform a
handshake according to the protocols and key information in
@racket[config]. If handshaking fails, an exception is raised.

If @racket[mode] is @racket['connect], then the socket initates the
first handshake attempt. The @racket['protocols] value of
@racket[config] is filtered, discarding protocols for which the given
@racket['keys-info] value is insufficient; the first suitable protocol
is used as the initial protocol, and the remaining suitable protocols
are offered as retry protocols. The @racket['switch-protocols] are
offered as as switch options.

If @racket[mode] is @racket['accept], then the socket waits to respond
to the first handshake attempt. If the initial protocol appears in the
@racket['protocols] value of @racket[config], it is accepted and
handshaking continues. Otherwise, if the initial handshake offered a
switch protocol that appears in @racket[config]'s
@racket['switch-protocols] value, this party switches to that protocol
and initiates a new handshake. Otherwise, if the initial handshake
offered a retry protocol that appears in @racket[config]'s
@racket['protocols] value, this party sends a message advising the
initiator to retry with that protocol. Otherwise, the connection is
rejected.
}

@defthing[noise-socket-config/c contract?]{

An immutable hash with the following allowed keys:

@itemlist[

@item{@racket['keys-info] : @racket[noise-keys-info/c] --- contains
the party's cryptographic keys (and potentially other information
needed for handshaking)}

@item{@racket['protocols] : @racket[(listof noise-protocol?)] --- the
protocols that the party can use for initial or retry handshakes, in
order of preference (see @racket[noise-lingo-socket])}

@item{@racket['switch-protocols] : @racket[(listof noise-protocol?)]
--- the protocols that the party can use for switch handshakes, in
order of preference}

@; @item{@racket['transport_options] : @racket[???] --- FIXME}
@; @item{@racket['s-evidence] : @racket[???] --- FIXME}

]
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
