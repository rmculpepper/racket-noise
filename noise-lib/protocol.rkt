#lang racket/base
(require racket/contract/base
         (only-in crypto crypto-factory?)
         "private/interfaces.rkt"
         "private/protocol.rkt")
(provide noise-protocol?
         noise-protocol<%>
         noise-protocol-state?
         noise-protocol-state<%>
         (contract-out
          [noise-protocol
           (->* [string?] [#:factories (listof crypto-factory?)]
                noise-protocol?)]))
