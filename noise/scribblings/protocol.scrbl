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
(define alice
  (send ik-proto new-state #t (hasheq 's alice-sk 'rs bob-pub)))
(define bob
  (send ik-proto new-state #f (hasheq 's bob-sk)))
]

@examples[#:eval the-eval #:label #f
(define msg1 (send alice write-handshake-message #"hello"))
(send bob read-handshake-message msg1)
(define msg2 (send bob write-handshake-message #"hello back"))
(send alice read-handshake-message msg2)
(list (send alice in-handshake-phase?)
      (send bob in-handshake-phase?))
(list (send alice in-transport-phase?)
      (send bob in-transport-phase?))
(define msg3 (send alice write-transport-message #"nice talking with you"))
(send bob read-transport-message msg3)
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

@defmethod[(new-state [initiator? boolean?]
                      [keys-info hash?]
                      [#:prologue prologue bytes? #""])
           noise-protocol-state?]{

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
@section[#:tag "protocol-states"]{Protocol States}

@defproc[(noise-protocol-state? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a Noise protocol state created by
the @method[noise-protocol<%> new-state] method, @racket[#f]
otherwise.

A protocol state represents the state of one party in an execution of
a Noise protocol.

See also @racket[noise-protocol-state<%>].
}

@definterface[noise-protocol-state<%> ()]{

Public interface for Noise protocol state objects.

Note that @racket[(noise-protocol-state? _v)] implies @racket[(is-a?
_v noise-protocol-state<%>)], but not vice versa. That is, a Noise
protocol state object implements additional internal interfaces not
exposed to users.

@defmethod[(in-handshake-phase?) boolean?]{

Returns @racket[#t] if the current protocol execution is in the
handshake phase; otherwise, returns @racket[#f].
}

@defmethod[(in-transport-phase?) boolean?]{

Returns @racket[#t] if the current protocol execution is in the
transport phase; otherwise, returns @racket[#f].
}

@defmethod[(can-read-message?) boolean?]{

Returns @racket[#t] if the party is able to read or write a message;
otherwise, returns @racket[#f].

Note that for interactive (not one-way) protocols, during the
handshake phase handshake messages are allowed in strictly alternating
order, but during the transport phase, both parties can both read and
write messages freely.
}

@defmethod[(can-write-message?) boolean?]{

Returns @racket[#t] if the party is able write a message; otherwise,
returns @racket[#f].

Note that for interactive (not one-way) protocols, during the
handshake phase handshake messages are allowed in strictly alternating
order, but during the transport phase, both parties can both read and
write messages freely.
}

@defmethod[(get-handshake-hash) bytes?]{

Returns a cryptographic digest of the entire handshake. If this method
is called before the handshake phase is finished, an exception is
raised.
}

@defmethod[(write-handshake-message [payload bytes?]) bytes?]{

Performs the next stage of handshaking, processes @racket[payload],
and produces a handshake message. The resulting message should be
conveyed to the other party; this method does not handle
communication.

Note: whether the @racket[payload] is encrypted or plaintext depends
on the protocol and the stage of the handshake process.

If the protocol execution is not currently in the handshake phase, or
if it is not this party's turn to write, an exception is raised.
}

@defmethod[(read-handshake-message [message bytes?]) bytes?]{

Performs the next state of handshaking using @racket[message] and
returns the payload extracted from @racket[message].

Note: whether the @racket[payload] was encrypted or plaintext depends
on the protocol and the stage of the handshake process.

If the protocol execution is not currently in the handshake phase, or
if it is not this party's turn to read, an exception is raised.
}

@defmethod[(write-transport-message [plaintext bytes?]) bytes?]{

Encrypts a transport message.

Note that each party has independent messages counters for reading and
writing. Messages written by one party must be read by the other party
in the same order; but reading does not affect the write counter, and
vice versa.

If the protocol execution is not currently in the transport phase, an
exception is raised.
}

@defmethod[(read-transport-message [ciphertext bytes?]) bytes?]{

Decrypts a transport message.

Note that each party has independent messages counters for reading and
writing. Messages written by one party must be read by the other party
in the same order; but reading does not affect the write counter, and
vice versa.

If the protocol execution is not currently in the transport phase, an
exception is raised. If decryption fails, an exception is raised.
}

}


@; ------------------------------------------------------------
@section[#:tag "keys-info"]{Keys Info}



@(close-eval the-eval)
