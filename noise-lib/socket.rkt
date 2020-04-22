#lang racket/base
(require racket/contract/base
         "private/interfaces.rkt"
         "private/socket.rkt")
(provide noise-socket?
         noise-socket<%>)

(provide socket%)
