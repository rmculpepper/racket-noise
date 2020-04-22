#lang info

;; pkg info

(define version "0.1")
(define collection "noise")
(define deps '("base"))
(define build-deps '("racket-doc"
                     "scribble-lib"
                     "crypto-lib"
                     "noise-lib"))
(define pkg-authors '(ryanc))

;; collection info

(define name "noise")
(define scribblings '(("scribblings/noise.scrbl" (multi-page))))

(define compile-omit-paths '("examples"))
(define test-omit-paths '("examples"))
