#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/example
          racket/list
          racket/runtime-path
          crypto/private/common/catalog
          (for-label racket/base
                     racket/contract
                     racket/random
                     crypto crypto/libcrypto
                     noise/protocol noise/socket noise/lingo))

@(define-runtime-path log-file "eval-logs/socket.rktd")
@(define the-eval (make-log-based-eval log-file 'record))
@(the-eval '(require crypto crypto/libcrypto noise/protocol noise/socket noise/lingo))
@(the-eval '(crypto-factories (list libcrypto-factory)))

@title[#:tag "socket"]{Noise Sockets}

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

(define alice (new lingo-socket% (in a-in) (out a-out)))
(define bob (new lingo-socket% (in b-in) (out b-out)))

(define bob-thread (thread (lambda () (send bob accept bob-config))))
(send alice connect alice-config)
(void (sync bob-thread))
]


@examples[#:eval the-eval #:label #f
(send alice write-transport-message #"hello")
(send bob read-transport-message)

(send bob write-transport-message #"hello back")
(send alice read-transport-message)

(send alice write-transport-message #"nice talking with you")
(send bob read-transport-message)

(send bob write-transport-message #"likewise")
(send alice read-transport-message)
]






@; ------------------------------------------------------------
@section[#:tag "noise-socket"]{Noise Sockets}

@; ------------------------------------------------------------
@section[#:tag "nls"]{Noise Lingo Sockets (NLS)}




@(close-eval the-eval)
