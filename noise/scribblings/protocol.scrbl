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

The @racketmodname[noise/protocol] library provides an implementation
of the @hyperlink["https://noiseprotocol.org/"]{Noise Protocol
Framework}.

Specifically, this library implements revision 34 (2018-07-11)
@cite{Noise}, including the @tt{psk} and @tt{fallback} extensions.


@; ------------------------------------------------------------
@section[#:tag "intro-protocol"]{Introduction to Noise Protocols}

First we require the necessary libraries and initialize
@racket[crypto-factories]. (Note that OpenSSL 1.1.1 or later is
required for the algorithms used below.)

@examples[#:eval the-eval #:label #f
(require racket/class noise/protocol crypto crypto/libcrypto)
(crypto-factories (list libcrypto-factory))
]

We get a protocol object by calling @racket[noise-protocol] with the
name of the protocol. A protocol name contains a handshake pattern
(eg, @tt{IK}), optional extensions, and cryptographic algorithm
names. Here are two example protocols:

@examples[#:eval the-eval #:label #f
(define ik-proto
  (noise-protocol "Noise_IK_25519_ChaChaPoly_SHA512"))
(define xx-fallback-proto
  (noise-protocol "Noise_XXfallback_25519_ChaChaPoly_SHA512"))
]

The rest of this example uses @racket[ik-proto]. The @tt{IK} handshake
pattern has the following structure:

@verbatim{
IK:
    <- s
    ...
    -> e, es, s, ss
    <- e, ee, se
}

See @cite{Noise} for an explanation of handshake patterns. The
important facts for this example are that both parties must have a
static private key, and that the initiator must already know the
responder's public key before the handshake starts. We can get this
information automatically using @method[noise-protocol<%>
get-info-keys] (@racket['s] means own static key, @racket['rs] means
remote static key):

@examples[#:eval the-eval #:label #f
(code:line (send ik-proto get-info-keys #t) (code:comment "#t = initiator"))
(code:line (send ik-proto get-info-keys #f) (code:comment "#f = responder"))
]

Let's call the initiator Alice and the responder Bob. We create
private keys for Alice and Bob, and we also extract Bob's public key
as a byte string.

@examples[#:eval the-eval #:label #f
(define alice-sk (send ik-proto generate-private-key))

(define bob-sk (send ik-proto generate-private-key))
(define bob-pub (send ik-proto pk->public-bytes bob-sk))
]

We create new handshake state objects for Alice and Bob. Alice is the
initiator (@racket[#t]) and Bob is the responder (@racket[#f]). Alice
knows her own static private key (@racket['s] has @racket[alice-sk])
and Bob's public key (@racket['rs] has @racket[bob-pub]); Bob only
knows his own static private key (@racket['s] has @racket[bob-sk]).

@examples[#:eval the-eval #:label #f
(define alice-hs
  (send ik-proto new-handshake #t (hash 's alice-sk 'rs bob-pub)))
(define bob-hs
  (send ik-proto new-handshake #f (hash 's bob-sk)))
]

An @tt{IK} handshake consists of two messages.

Alice sends the first handshake message to Bob, which consists of the
handshake elements @tt{e, s, es, s, ss} and a payload. Note that the
handshake state object do not do communication. The result of
``writing'' the first message is a byte string, @racket[msg1]. Bob
``reads'' @racket[msg1], parses and interprets the handshake elements,
and returns the payload.

@examples[#:eval the-eval #:label #f
(define msg1 (send alice-hs write-handshake-message #"hello"))
(send bob-hs read-handshake-message msg1)
]

Bob sends the second handshake message:

@examples[#:eval the-eval #:label #f
(define msg2 (send bob-hs write-handshake-message #"hello back"))
(send alice-hs read-handshake-message msg2)
]

The @tt{IK} handshake pattern consists of only two message, so the
handshake is complete, and the transport channel is established. Alice
and Bob can retrieve the transport channel objects using
@method[noise-handshake-state<%> get-transport]:

@examples[#:eval the-eval #:label #f
(define alice-t (send alice-hs get-transport))
(define bob-t (send bob-hs get-transport))
]

Now Alice and Bob can freely exchange messages. More precisely, Alice
must read Bob's messages in the order that Bob writes them, and Bob
must read Alice's messages in the order that Alice writes them. But
the two sequences of messages are independent; for example, Bob is
always free to either read a message, if one is available, or write a
message, and it makes no difference to the protocol (unless of course,
Bob's message depends on the content of Alice's).

@examples[#:eval the-eval #:label #f
(define msg3 (send alice-t write-message #"nice talking with you"))
(code:comment "Bob chooses to write a message before reading Alice's")
(define msg4 (send bob-t write-message #"same time next week?"))
(send alice-t read-message msg4)
(send bob-t read-message msg3)
]

Noise protocol conversations are never finished, only abandoned. (That
is, higher-level protocols may define a notion of termination, but
the Noise protocol layer does not.)


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

@defmethod[(get-protocol-name) string?]{

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

@defmethod[(get-info-keys [initiator? boolean?]) (listof symbol?)]{

Returns the keys that a key-info hash must have to begin an execution
of this protocol as an initiator or responder, depending on
@racket[initiator?].

@examples[#:eval the-eval
(send ik-proto get-info-keys #t)
(send xx-fallback-proto get-info-keys #t)
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
beginning of the protocol; see @racket[keys-info/c] for details. The
@racket[prologue] represents information shared between the parties; a
protocol execution fails if the two parties have different prologues.
}

}

@defthing[noise-keys-info/c contract?]{

Different Noise protocols require parties to possess different
information (mainly cryptographic keys) to perform a handshake, and
extensions can define new kinds of information. For flexibility, this
library accepts information in the form of @deftech{keys-info hash}
--- an immutable hash with the following allowed keys:

@itemlist[

@item{@racket['s] : @racket[private-key?] --- the party's private
static DH key}

@item{@racket['rs] : @racket[bytes?] --- the remote party's (aka
peer's) public static key, in bytes string form (see also
@method[noise-protocol<%> pk-key->public-bytes]).}

@item{@racket['e] : @racket[private-key?] and @racket['re] :
@racket[bytes?] --- the party's private ephemeral key and the remote
party's public ephemeral key, respectively. These are generally only
used in @tt{fallback} protocol for compound handshakes, since
ephemeral keys should not be reused for multiple conversations.}

@item{@racket['psk] : @racket[(or/c bytes? (-> noise-keys-info/c (or/c bytes? #f)))]
--- a @emph{pre-shared key} or a function that retrieves a pre-shared key
given the current keys-info hash. For example, the function might use
the remote party's static public key (@racket['rs]) as an identifier
to look up the pre-shared key. A pre-shared key must be exactly 32
bytes long. Pre-shared keys are only used in protocols with a
@tt{psk{n}} extension.}

@item{@racket['psk-id] : @racket[bytes?] --- an identifier for the
pre-shared key}

]
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

@defmethod[(can-write-message?) boolean?]{

Returns @racket[#t] if it is this party's turn to write a handshake
message; otherwise, returns @racket[#f].
}

@defmethod[(can-read-message?) boolean?]{

Returns @racket[#t] if it is this party's turn to read a handshake
message; otherwise, returns @racket[#f].
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

Returns @racket[#t] if @racket[v] is a Noise transport object returned
by @method[noise-handshake-state<%> get-transport], @racket[#f]
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

@bibliography[
#:tag "protocol-bibliography"

@bib-entry[#:key "Noise"
           #:title "The Noise Protocol Framework"
           #:author "Trevor Perrin"
           #:url "https://noiseprotocol.org/noise.html"
           #:date "2018-07-11"
           #:note " (revision 34, official/unstable)"]

]

@(close-eval the-eval)
