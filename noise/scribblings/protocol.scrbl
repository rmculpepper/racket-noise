#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/example
          racket/list
          racket/runtime-path
          crypto/private/common/catalog
          (for-label racket/base racket/contract racket/class
                     crypto crypto/libcrypto noise/protocol))

@(define-runtime-path log-file "eval-logs/protocol.rktd")
@(define the-eval (make-log-based-eval log-file 'record))

@title[#:tag "protocol"]{Noise Protocols}

@defmodule[noise/protocol]

@; ------------------------------------------------------------
@section[#:tag "intro-protocol"]{Introduction to Noise Protocols}

@examples[#:eval the-eval #:label #f
(require racket/class noise/protocol crypto crypto/libcrypto)
(crypto-factories (list libcrypto-factory))
]

@examples[#:eval the-eval #:label #f
(define ik-proto
  (noise-protocol "Noise_IK_25519_ChaChaPoly_SHA512"))
(define xx-fallback-proto
  (noise-protocol "Noise_XXfallback_25519_ChaChaPoly_SHA512"))
]

@examples[#:eval the-eval #:label #f
(define alice-sk (send ik-proto generate-private-key))
(define alice-pub (send ik-proto pk->public-bytes alice-sk))

(define bob-sk (send ik-proto generate-private-key))
(define bob-pub (send ik-proto pk->public-bytes bob-sk))
]

@examples[#:eval the-eval #:label #f
(define alice-hs
  (send ik-proto new-handshake #t (hasheq 's alice-sk 'rs bob-pub)))
(define bob-hs
  (send ik-proto new-handshake #f (hasheq 's bob-sk)))
]

@examples[#:eval the-eval #:label #f
(define msg1 (send alice-hs write-handshake-message #"hello"))
(send bob-hs read-handshake-message msg1)
(define msg2 (send bob-hs write-handshake-message #"hello back"))
(send alice-hs read-handshake-message msg2)
]

@examples[#:eval the-eval #:label #f
(define alice-t (send alice-hs get-transport))
(define bob-t (send bob-hs get-transport))
(define msg3 (send alice-t write-message #"nice talking with you"))
(send bob-t read-message msg3)
]


@; ------------------------------------------------------------
@section[#:tag "protocols"]{Protocols}

@defproc[(noise-protocol [name string?]
                         [#:factories factories (listof crypto-factory?) (crypto-factories)])
         noise-protocol?]{

Produces a Noise protocol object for the protocol described by
@racket[name], using @racket[factories] to find implementations of the
corresponding cryptographic algorithms.

If @racket[name] is not a Noise protocol name supported by this
library, or if implementations cannot be found in @racket[factories]
of the cryptographic algorithms in @racket[name], an exception is raised.
}

@defproc[(noise-protocol? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a Noise protocol object produced
by @racket[noise-protocol], @racket[#f] otherwise.

See also @racket[noise-protocol<%>].
}

@definterface[noise-protocol<%> ()]{

Public interface for Noise protocol objects.

Note that @racket[(noise-protocol? _v)] implies @racket[(is-a? _v
noise-protocol<%>)], but not vice versa. That is, a Noise protocol
object implements additional internal interfaces not exposed to users.

@defmethod[(get-protocol-name) bytes?]{

Gets the protocol name.

@examples[#:eval the-eval
(send ik-proto get-protocol-name)
]}

@defmethod[(get-extensions) (listof string?)]{

Gets a list of pattern extensions.

@examples[#:eval the-eval
(send ik-proto get-extensions)
(send xx-fallback-proto get-extensions)
]}

@defmethod[(using-psk?) boolean?]{

Returns @racket[#t] if the protocol uses the @tt{psk} extension, @racket[#f] otherwise.

Equivalent to @racket[(for/or ([ext (get-extensions)]) (regexp-match? #rx"^psk[0-9]+$"))].
}

@defmethod[(generate-private-key) private-key?]{

Convenience method for generating a private key suitable for the protocol's DH algorithm.

Equivalent to @racket[(generate-private-key _dh-impl)], where
@racket[_dh-impl] is this object's implementation of the protocol's DH algorithm.
}

@defmethod[(pk-key->public-bytes [pk pk-key?]) bytes?]{

Convenience method for converting a DH public key (or the public part
of a private key) into bytes in the same format used by the Noise
protocol. The result is suitable for use in a keys-info hash.
}

@defmethod[(new-handshake [initiator? boolean?]
                          [keys-info hash?]
                          [#:prologue prologue bytes? #""])
           noise-handshake-state?]{

Creates a new Noise protocol state, representing one party in an
execution of a Noise protocol. If @racket[initiator?] is true, then
the party is the initiator; otherwise it represents the responder. The
@racket[keys-info] hash provides the keys known to the party at the
beginning of the protocol; see @secref["keys-info"] for details. The
@racket[prologue] represents information shared between the parties; a
protocol execution fails if the two parties have different prologues.
}

}


@; ------------------------------------------------------------
@section[#:tag "handshake"]{Protocol Handshake Phase}

@defproc[(noise-handshake-state? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a Noise handshake state created
by the @method[noise-protocol<%> new-handshake] method, @racket[#f]
otherwise.

A Noise handshake state value represents the state of one party in an
execution of a Noise protocol handshake.

See also @racket[noise-handshake-state<%>].
}

@definterface[noise-handshake-state<%> ()]{

Public interface for Noise handshake state objects.

Note that @racket[(noise-handshake-state? _v)] implies @racket[(is-a?
_v noise-handshake-state<%>)], but not vice versa. That is, a Noise
handshake state object implements additional internal interfaces not
exposed to users.

@defmethod[(can-read-message?) boolean?]{

Returns @racket[#t] if the party is able to read a handshake message;
otherwise, returns @racket[#f].
}

@defmethod[(can-write-message?) boolean?]{

Returns @racket[#t] if the party is able write a handshake message;
otherwise, returns @racket[#f].
}

@defmethod[(write-handshake-message [payload bytes?]) bytes?]{

Performs the next stage of handshaking, processes @racket[payload],
and produces a handshake message. The resulting message should be
conveyed to the other party; this method does not handle
communication.

Note: whether the @racket[payload] is encrypted or plaintext depends
on the protocol and the stage of the handshake process.

If it is not this party's turn to write, an exception is raised.
}

@defmethod[(read-handshake-message [message bytes?]) bytes?]{

Performs the next state of handshaking using @racket[message] and
returns the payload extracted from @racket[message].

Note: whether the @racket[payload] was encrypted or plaintext depends
on the protocol and the stage of the handshake process.

If it is not this party's turn to read, an exception is raised.
}

@defmethod[(get-transport) (or/c #f noise-transport?)]{

If the handshake is finished, returns a Noise transport object. If the
handshake is not finished, returns @racket[#f].
}

}


@; ------------------------------------------------------------
@section[#:tag "transport"]{Protocol Transport Phase}

@defproc[(noise-transport? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a Noise transport returned by
@method[noise-handshake-state<%> get-transport], @racket[#f]
otherwise.

See also @racket[noise-transport<%>].
}

@definterface[noise-transport<%> ()]{

Public interface for Noise transport objects.

Note that @racket[(noise-transport? _v)] implies @racket[(is-a? _v
noise-transport<%>)], but not vice versa. That is, a Noise transport
object implements additional internal interfaces not exposed to users.

@defmethod[(get-handshake-hash) bytes?]{

Returns a cryptographic digest of the handshake.
}

@defmethod[(write-message [plaintext bytes?]) bytes?]{

Encrypts a transport message.

Note that each party has independent messages counters for reading and
writing. Messages written by one party must be read by the other party
in the same order; but reading does not affect the write counter, and
vice versa.
}

@defmethod[(read-message [ciphertext bytes?]) bytes?]{

Decrypts a transport message.

Note that each party has independent messages counters for reading and
writing. Messages written by one party must be read by the other party
in the same order; but reading does not affect the write counter, and
vice versa.

If decryption fails, an exception is raised.
}

}


@; ------------------------------------------------------------
@section[#:tag "keys-info"]{Keys Info}



@(close-eval the-eval)
