#lang racket/base
(require racket/contract/base
         (only-in crypto crypto-factory?)
         "private/interfaces.rkt"
         "private/protocol.rkt")
(provide noise-protocol?
         noise-protocol<%>
         noise-handshake-state?
         noise-handshake-state<%>
         noise-transport?
         noise-transport<%>
         (contract-out
          [noise-protocol
           (->* [string?] [#:factories (listof crypto-factory?)]
                noise-protocol?)]))
