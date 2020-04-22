#lang scribble/manual
@(require scribble/basic)

@title[#:version "0.1"]{Noise: Cryptographic Protocols}
@author[@author+email["Ryan Culpepper" "ryanc@racket-lang.org"]]

This library provides implementations of
@itemlist[

@item{the @hyperlink["https://noiseprotocol.org/"]{Noise Protocol Framework}, and}

@item{@hyperlink["https://noisesocket.org/"]{Noise Sockets}, specificially the
@hyperlink["https://github.com/noiseprotocol/nls_spec/blob/rev2/nls.md"]{NoiseLingoSocket (NLS)}
framework.}

]

@bold{Unstable} This library is a work in progress, and it is based on
specifications that are not yet final. @bold{This library's interfaces
and behavior may change in future versions.}

@bold{Development} Development of this library is hosted by
@hyperlink["http://github.com"]{GitHub} at the following project page:

@centered{@url{https://github.com/rmculpepper/noise}}

@include-section["protocol.scrbl"]
@include-section["socket.scrbl"]
@; @include-section["misc.scrbl"]
