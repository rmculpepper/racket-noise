#lang racket/base
(require (for-syntax racket/base)
         racket/class
         racket/match
         racket/string
         racket/port
         racket/format
         crypto
         binaryio/bytes
         binaryio/integer
         "private/interfaces.rkt"
         "private/patterns.rkt"
         "private/protobuf.rkt"
         "private/protocol-name.rkt"
         "socket.rkt")
(provide (all-defined-out))

;; Reference: https://noisesocket.org/spec/nls/
;;   Revision: 1, 2018-03-05

(define NoiseLingoNegotiationDataRequest
  (Message
   [1 server_name 'bytes]
   [2 initial_protocol 'bytes]
   #:repeated [3 switch_protocol 'bytes]
   #:repeated [4 retry_protocol 'bytes]
   [5 rejected_protocol 'bytes]
   [6 psk_id 'bytes]))

(define NoiseLingoNegotiationDataResponse
  (Message
   #:oneof ;; response
   [[3 switch_protocol 'bytes]
    [4 retry_protocol 'bytes]
    [5 rejected 'bool]]))

(define NoiseLingoTransportOptions
  (Message
   [1 max_send_length 'uint32]
   [2 max_recv_length 'uint32]
   [3 continuous_rekey 'bool]
   [4 short_terminated 'bool]))

(define NoiseLingoHandshakePayload
  (Message
   #:repeated [1 evidence_request_type 'string]
   #:repeated [2 evidence_blob_type 'string]
   #:repeated [3 evidence_blob 'bytes]
   [4 psk_id 'bytes]
   [5 transport_options NoiseLingoTransportOptions]))

(define nls-v1-prologue #"NLS(revision1)")

;; ============================================================
;; Revision 2 (draft?)
;; Reference: https://github.com/noiseprotocol/nls_spec/blob/rev2/nls.md

(define nls-v2-prologue #"NLS(revision2)")

;; NoiseLink protocols:
;; - Noise_XX_25519_AESGCM_SHA256
;; - Noise_XX_25519_ChaChaPoly_SHA256
;; - Noise_XXfallback_25519_AESGCM_SHA256
;; - Noise_XXfallback_25519_ChaChaPoly_SHA256

;; NoiseZeroLink protocols:
;; - (NoiseLink protocols)
;; - Noise_IK_25519_AESGCM_SHA256
;; - Noise_IK_25519_ChaChaPoly_SHA256


#|
;; ============================================================
questions and comments about noise spec

clarifying initiator vs Alice/Bob

initiator/responder vs left/right vs Alice/Bob



Spec is wrong, I think.
- 5.3 WriteMessage says "es" means DH(initiator's ephemeral, responder's static)
  --- *not* DH(left-hand's ephemeral, right-hand's static)
- 7.1 says "The first actual handshake message is send from the initiator..."
- 7.2 says "handshake patterns can be written in Bob-initiated form by
  reversing the arrows and the DH tokens (eg, replacing "es" with "se",
  and vice versa). The DH tokens should not be reversed, because their
  interpretation does not depend on which party is on the left vs right.
- Consequently, the Bob-initiated examples in 7.2 are wrong.
- The Bob-initiated XXfallback pattern in 10.2 is wrong; changing the
  first message of XX to be a pre-message changes the initiator, which
  *should* cause the DH tokens to flip. But flipping it to canonical
  form using the incorrect rule from 7.2 produces the right result! So
  hopefully the two errors cancel out.

The sentence "All processing rules and discussions so far have assumed
canonical-form handshake patterns." is vague but alarming. It makes me
wonder if I'm supposed to derive a patch to section 5.3 somehow from
the text of section 7. I hope you just mean "All examples so far have
used canonical-form handshake patterns."

----

(check https://moderncrypto.org/mail-archive/noise/2018/001637.html)

# Alice/Bob = left/right is confusing

I find the current Alice/Bob terminology confusing, because I think of
Alice and Bob as people involved in a conversation, and their
identities remain fixed while perspectives on handshake patterns vary.

# Proposed clarifications

A *conversation* consists of one or more handshakes (cf compound
protocol, fallback, etc) followed by a transport/traffic phase.

The *initiator of a handshake* refers to the party that sends the
first message in that handshake. In this specification, the
terms "initiat{e,ed,or}" are always with respect to a handshake, not a
conversation.

A handshake pattern written in *canonical form* (aka
*left-initiated form*) puts the initiator as the "left-hand"
party. That is, the first message is a -> message.

A handshake pattern written in *right-initiated form* puts the
initiator as the "right-hand" party. That is, the first message is a
<- message.

Note that the token "es" always means DH *initiator's* ephemeral and
*responder's* static. Do not read it as "left-hand's ephemeral and
right-hand's static" --- that interpretation is correct when the
pattern is in canonical form but *not* when the pattern is in
right-initiated form. Likewise for "se". So to convert between
canonical (ie, left-initiated) form and right-initiated form, simply
change the arrow directions; do not change any tokens.

(On the other hand, deriving a fallback pattern *does* swap es/se, but
that's a consequence of moving the first handshake message into the
pre-messages, which turns a left-initiated pattern into a
right-initiated pattern.)

By convention, the initiator of the first handshake of a conversation
is called Alice, and the responder of the first handshake of a
conversation is called Bob.

In a simple protocol, Alice initiates a handshake with Bob, and if
successful then they talk (that is, then they exchange
transport/traffic messages). In a compound protocol, Alice may
initiate a handshake with Bob, but Bob might switch protocols and
initiate a fallback handshake with Alice. That is, Alice is the
initiator of the first handshake, and Bob is the initiator of the
second handshake.

IK:                   
  <- s                         
  ...
  -> e, es, s, ss          
  <- e, ee, se

XXfallback:                   
  -> e
  ...
  <- e, ee, s, se
  -> s, es



;; ============================================================
questions and comments about nls_spec (rev 2, 2018-03-18)

Prelude:

I propose the notation

  -> tok ; {payload_field_name *}

There's a special case on first message, has two "payloads"

  -> tok ; {payload_field_name *} ; {payload_field_name *}

Note: Payloads are described by field sets, not field sequences.

Is there a case where early_payload and normal first payload have
different constraints? (See psk_id question.)

Maybe possible to write elaboration rules?

Section 3.3:

"The <field> can be sent" ...
- What is behavior if sent another time? Ignore? Fatal protocol error?
- cf protocol buffer behavior (???) discard unknown fields...

"The evidence_blob{,_type} fields can be sent whenever the sender is
transmitting a public key."
- to clarify, same message?
  eg, -> e, s ; evidence_blob, evidence_blob_type

Maybe separate early_payload (eg, psk_id for psk{0,1}) from switch_retry_payload?


Section 3.5:

`server_name`: Is it a domain name? Or app-dependent? (cf SNI?)

`switch_protocol` and `retry_protocol`: Does order matter? (eg, preference?)

`psk_id`:
- "Placing the PSK identifier in the handshake payload only makes sense if this payload is
  encrypted, and the PSK isn't required to decrypt it."
  - Why? By "only makes sense" do you mean "is preferable" or "is the only viable option"?
    Or maybe say consequences, eg if not encrypted then leaks identity info?
  - in any case (IIUC), all payloads are encrypted in psk handshake patterns
  - rev2 draft does not clarify, might be inconsistent...
    - 3.5 says occurs once per handshake, either in initial nego (ie early_payload) or initial payload
    - 3.3 says early_payload used only for switch/retry!
  - what about *psk{0,1}? Just can't send psk_id?
    eg, NKpsk0 with switch to ??fallback+psk{0,1}

`evidence_*`: What does repetition mean?
- (I think for request: "please send any of the following", for
  blob_type: "all of the following are valid, pick whatever you like")
- Is it possible for a party to have more than one public
  key? (Comments in the sig extension spec make me think maybe yes.)
  Note the evidence format must make it possible to correlate evidence
  with appropriate key?

`evidence_blob_type`: Does x509* mean DER or PEM or either at sender's option?

`evidence_blob`: extra blob w/o blob_type, is that profile- or application-specified?

`short_terminated`: "maximum" refers to max_send_length value, not 2^16-1, right?

Section 5.1:

It seems out of place to require responder to support all listed Noise protocols.

--

? - When can evidence be sent?

|#

;; Config keys:
;; - keys-info : Info
;; - s-evidence: ...

(define (config->init-ndreq config)
  (define (protocol->name p) (send p get-protocol-name))
  (for/fold ([ndreq (config->base-ndreq config)])
            ([(k v) (in-hash config)])
    (case k
      [(initial-protocol)
       (hash-set ndreq 'initial_protocol (protocol->name v))]
      [(switch-protocols)
       (hash-set ndreq 'switch_protocol (map protocol->name v))]
      [(retry-protocols)
       (hash-set ndreq 'retry_protocol (map protocol->name v))]
      [(rejected-protocol)
       (if v (hash-set ndreq 'rejected-protocol (protocol->name v)) ndreq)]
      [else ndreq])))

(define (config->switch-ndreq config switch-protocol)
  (define ndreq0 (config->base-ndreq config))
  (hash-set ndreq0 'initial_protocol (send switch-protocol get-protocol-name)))

(define (config->retry-ndreq config retry-protocol)
  (define ndreq0 (config->base-ndreq config))
  (hash-set ndreq0 'initial_protocol (send retry-protocol get-protocol-name)))

(define (config->base-ndreq config)
  (for/fold ([ndreq (hasheq)]) ([(k v) (in-hash config)])
    (case k
      [(server-name)
       (if v (hash-set ndreq 'server_name v) ndreq)]
      [else ndreq])))

;; ----------------------------------------

(define lingo-socket%
  (class object%
    (init in out)
    (super-new)

    (field [socket (new socket% (application-prologue nls-v2-prologue) (in in) (out out))])

    ;; FIXME: connected?, disconnect / reset

    ;; ========================================

    (define/public (connect config)
      (define protocol (hash-ref config 'initial-protocol))
      (define ndreq (config->init-ndreq config))
      (-connect config protocol 'init ndreq))

    (define/private (-connect config protocol mode ndreq)
      (send socket initialize mode protocol #t (hash-ref config 'keys-info))
      (define mpatterns (-get-protocol-mpatterns protocol))
      ;; FIXME: early payload
      (define req-payload (-make-payload config protocol mpatterns #t))
      (eprintf "A -> ~s ~e ; ~e\n" mode ndreq req-payload)
      (send socket write-handshake-message
            (message->bytes NoiseLingoNegotiationDataRequest ndreq)
            (message->bytes NoiseLingoHandshakePayload req-payload))
      (cond [(null? (cdr mpatterns)) ;; one-way pattern
             (-connect-one-way config)]
            [else (-connect-k config protocol mode)]))

    (define/private (-connect-k config protocol mode)
      ;; FIXME: handle silent rejection better
      (define ndresp (-read-handshake-resp))
      (eprintf "A <- ~s ~e\n" mode ndresp)
      (cond [(equal? ndresp '#hasheq()) ;; ok
             (define payload (-read-handshake-noise 'decrypt))
             (define mpatterns (-get-protocol-mpatterns protocol))
             (-connect-ok config (cdr mpatterns) payload)]
            [(hash-ref ndresp 'rejected #f)
             (-read-handshake-noise 'discard)
             (-connect-rejected)]
            [(not (eq? mode 'init))
             (-read-handshake-noise 'discard)
             (error 'connect "repeated switch or retry response")]
            [(hash-ref ndresp 'switch_protocol #f)
             => (lambda (switch-protocol-name)
                  ;; Note: reading of Noise message delayed until protocol set
                  (-connect/switch config switch-protocol-name))]
            [(hash-ref ndresp 'retry_protocol #f)
             => (lambda (retry-protocol-name)
                  (-read-handshake-noise 'discard)
                  (-connect/retry config retry-protocol-name))]
            [else
             (-read-handshake-noise 'discard)
             (error 'connect "internal error: bad response: ~e" ndresp)]))

    (define/private (-connect-one-way config)
      (send socket discard-transcript!)
      (void))

    (define/private (-connect-ok config mpatterns payload)
      (send socket discard-transcript!)
      (-negotiate-k config mpatterns payload))

    (define/private (-connect-rejected)
      (send socket close)
      (error 'connect "connection failed;\n the peer rejected the connection"))

    (define/private (-connect/switch config protocol-name)
      (cond [(find-protocol-by-name protocol-name (hash-ref config 'switch-protocols null))
             => (lambda (protocol)
                  (send socket initialize 'switch protocol #f (hash-ref config 'keys-info))
                  (define payload (-read-handshake-noise 'decrypt))
                  (define mpatterns (-get-protocol-mpatterns protocol))
                  (-negotiate-k config mpatterns payload))]
            [else
             (-read-handshake-noise 'discard)
             (error 'connect "peer switched to unsupported protocol")]))

    (define/private (-connect/retry config retry-protocol-name)
      (define protocol
        (for/or ([p (in-list (hash-ref config 'retry-protocols null))])
          (and (equal? (send p get-protocol-name) retry-protocol-name) p)))
      (unless protocol
        (error 'connect "peer requested unsupported retry protocol\n  protocol: ~e"
               retry-protocol-name))
      (define ndreq (config->retry-ndreq config protocol))
      (-connect config protocol 'retry ndreq))

    ;; ========================================

    (define/public (accept config)
      (-accept config 'init))

    (define/private (-accept config mode) ;; mode is (U 'init 'switch 'retry)
      (define ndreq (-read-handshake-req))
      (eprintf "-> B ~s ~e\n" mode ndreq)
      (define protocol-name (hash-ref ndreq 'initial_protocol))
      (cond [(find-protocol-by-name protocol-name (hash-ref config 'protocols null))
             => (lambda (protocol) (-accept/protocol config protocol mode ndreq))]
            [(not (eq? mode 'init))
             (-read-handshake-noise 'discard) ;; need for transcript
             (-accept/reject config)]
            [else
             (-read-handshake-noise 'discard) ;; need for transcript
             (-accept/try-switch-or-retry config ndreq protocol-name)]))

    (define/private (-accept/protocol config protocol mode ndreq)
      (send socket initialize mode protocol #f (hash-ref config 'keys-info))
      (define payload (-read-handshake-noise 'try-decrypt))
      (eprintf "-> B ~s ... ; ~e\n" mode payload)
      (cond [(eq? payload 'bad)
             (cond [(eq? mode 'init)
                    (-accept/try-switch-or-retry config ndreq (send protocol get-protocol-name))]
                   [else (-accept/reject config)])]
            [else
             (define mpatterns (-get-protocol-mpatterns protocol))
             (-negotiate-k config mpatterns payload)]))

    (define/private (-accept/try-switch-or-retry config ndreq failed-protocol-name)
      (cond [(find-common-protocol (hash-ref ndreq 'switch_protocol null)
                                   (hash-ref config 'switch-protocols null)
                                   null)
             => (lambda (switch-protocol) (-accept/switch config ndreq switch-protocol))]
            [(find-common-protocol (hash-ref ndreq 'retry_protocol null)
                                   (hash-ref config 'protocols null)
                                   (list failed-protocol-name))
             => (lambda (retry-protocol) (-accept/retry config ndreq retry-protocol))]
            [else (-accept/reject config)]))

    (define/private (-accept/switch config ndreq protocol)
      (define ndreq (config->switch-ndreq config protocol))
      (-connect config protocol 'switch ndreq))

    (define/private (-accept/retry config ndreq retry-protocol)
      (define ndresp (hasheq 'retry_protocol (send retry-protocol get-protocol-name)))
      (define ndresp-bs (message->bytes NoiseLingoNegotiationDataResponse ndresp))
      (send socket write-handshake-message ndresp-bs #f)
      (-accept config 'retry))

    (define/private (-accept/reject config)
      (when #t ;; FIXME: option for silent reject?
        (define bye (message->bytes NoiseLingoNegotiationDataResponse (hasheq 'rejected #t)))
        (send socket write-handshake-message bye #f))
      (send socket close)
      (error 'accept "failed to accept connection"))

    ;; ========================================

    (define/private (-negotiate-k config mpatterns payload)
      ;; PRE: mpatterns is non-empty, starts with peer's message
      (define (loop-send config mpatterns)
        (when (pair? mpatterns)
          (define payload (-make-payload config #f mpatterns #f))
          (send socket write-handshake-message
                #"" (message->bytes NoiseLingoHandshakePayload payload))
          (loop-recv config (cdr mpatterns))))
      (define (loop-recv config mpatterns)
        (when (pair? mpatterns)
          (define-values (nego-bs payload-bs) (send socket read-handshake-message))
          (unless (equal? nego-bs #"") (error 'connect "unexpected negotiation data"))
          (define payload (bytes->message NoiseLingoHandshakePayload payload-bs))
          (loop-recv* config mpatterns payload)))
      (define (loop-recv* config mpatterns payload [first? #f])
        (define config* (-parse-payload config mpatterns payload first?))
        (loop-send config* (cdr mpatterns)))
      ;; ----
      (loop-recv* config mpatterns payload #t))

    ;; ----------------------------------------

    ;; Payload fields:
    ;; - Current write:
    ;;   - {s} => evidence_blob_type, evidence_blob
    ;; - Peer's next write:
    ;;   - {s} => evidence_request_type
    ;; - First payload:
    ;;   - {ext psk} => psk_id
    ;; - Last payload:
    ;;   - transport_options

    (define/private (-make-payload config protocol mpatterns [first? #f])
      (define-values (my-next-tokens peer-next-tokens rest-mpatterns)
        (split-2msg/rest mpatterns))
      (define payload-h (make-hash))
      ;; fields based on my next message
      (for ([tok (in-list my-next-tokens)])
        (case tok
          [(s) ;; evidence_blob_type, evidence_blob
           ;; FIXME: remember requested type, provide that?
           (match (hash-ref config 's-evidence #f)
             [(list (? bytes? type) (? bytes? blob))
              (hash-cons! payload-h 'evidence_blob_type type)
              (hash-cons! payload-h 'evidence_blob blob)]
             [_ (void)])]))
      ;; fields based on peer's next message
      (for/fold ([payload #hasheq()]) ([tok (in-list peer-next-tokens)])
        (case tok
          [(s) ;; FIXME: evidence_request_type
           (void)]))
      ;; fields sent on my first message
      (when first?
        (cond [(and (send protocol using-psk?)
                    (hash-ref config 'psk_id #f))
               => (lambda (v) (hash-set! payload-h 'psk_id v))]))
      ;; fields sent on my last message (note: last could also be first!)
      (when (null? rest-mpatterns)
        (cond [(hash-ref config 'transport_options #f)
               => (lambda (v) (hash-set! payload-h 'transport_options v))]))
      ;; ----
      payload-h)

    ;; ----------------------------------------

    (define/private (-parse-payload config mpatterns payload first?)
      (define-values (peer-tokens my-next-tokens rest-mpatterns)
        (split-2msg/rest mpatterns))
      ;; fields based on peer's current message
      (for ([tok (in-list peer-tokens)])
        (case tok
          [(s) ;; FIXME: evidence_blob_type, evidence_blob
           (void)]))
      ;; fields based on my next message
      (for ([tok (in-list my-next-tokens)])
        (case tok
          [(s) ;; FIXME: evidence_request_type
           (void)]))
      ;; fields sent on peer's first message
      (when first?
        (cond [(hash-ref/not-default payload 'psk_id #"")
               => (lambda (v)
                    (set! config (hash-set config 'peer:psk-id v)))]))
      ;; fields sent on peer's last message (note: last could also be first!)
      (when (null? rest-mpatterns)
        (cond [(hash-ref payload 'transport_options #f)
               => (lambda (v)
                    (set! config (hash-set config 'peer:transport-options v)))]))
      ;; ----
      config)

    ;; ----------------------------------------

    (define/private (-get-protocol-mpatterns protocol)
      (handshake-pattern-msgs (send protocol get-pattern)))

    (define/private (-read-handshake-req)
      (define bs (send socket read-handshake-negotiation))
      (bytes->message NoiseLingoNegotiationDataRequest bs))

    (define/private (-read-handshake-resp)
      (define bs (send socket read-handshake-negotiation))
      (bytes->message NoiseLingoNegotiationDataResponse bs))

    (define/private (-read-handshake-noise mode)
      (define v (send socket read-handshake-noise mode))
      (case mode
        [(decrypt try-decrypt)
         (if (bytes? v) (bytes->message NoiseLingoHandshakePayload v) v)]
        [else v]))

    (define/private (split-2msg/rest mpatterns)
      (match mpatterns
        [(list* msg1 msg2 rest)
         (values (message-pattern-tokens msg1)
                 (message-pattern-tokens msg2)
                 rest)]
        [(list msg1)
         (values (message-pattern-tokens msg1)
                 null
                 null)]))

    (define/private (find-common-protocol pnames ps avoid-pnames)
      ;; FIXME: which priority to use?
      (define ph (for/hash ([p (in-list ps)]) (values (send p get-protocol-name) p)))
      (for/or ([pname (in-list pnames)] #:when (not (member pname avoid-pnames)))
        (hash-ref ph pname #f)))

    (define/private (find-protocol-by-name protocol-name protocols)
      (for/or ([p (in-list protocols)])
        (and (equal? protocol-name (send p get-protocol-name)) p)))

    ;; ========================================
    ;; Forwarded methods

    ;; write-transport-message : Bytes -> Void
    (define/public (write-transport-message payload)
      (send socket write-transport-message payload))

    ;; read-transport-message : -> Bytes
    (define/public (read-transport-message)
      (send socket read-transport-message))

    (define/public (get-handshake-hash) (send socket get-handshake-hash))
    (define/public (can-write-message?) (send socket can-write-message?))
    (define/public (can-read-message?) (send socket can-read-message?))

    ))

(define (hash-cons! h k v) (hash-set! h k (cons v (hash-ref h k null))))

(define (hash-ref/not-default h k d)
  (let ([v (hash-ref h k d)]) (if (equal? v d) #f v)))

;; Spec should clarify what may change during negotiation, what must stay same
;; eg, change server_name on Retry?
;; eg, change evidence based on selected protocol?


;; NoiseSocket spec says Reject has error message, NLS spec says no.
