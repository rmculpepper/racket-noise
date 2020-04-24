#lang racket/base
(require racket/contract/base
         "private/interfaces.rkt"
         "private/socket.rkt"
         "private/lingo.rkt")
(provide noise-socket?
         noise-socket<%>
         noise-lingo-socket)
