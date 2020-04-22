#lang racket/base
(require racket/contract/base
         "private/interfaces.rkt"
         "private/lingo.rkt")
(provide noise-lingo-socket?
         noise-lingo-socket<%>
         noise-lingo-connect
         noise-lingo-accept)
