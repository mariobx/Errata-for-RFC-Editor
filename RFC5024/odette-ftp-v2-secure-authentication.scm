;;; [RFC-ID: RFC 5024]
;;; [PROTOCOL: ODETTE-FTP-v2-Secure-Authentication]
;;; [SECTIONS: 2.3, 3.2, 4, 5, 6, 10.2]
;;; [ALGEBRA: basic]
;;; [ROLES: Initiator, Responder]
;;; [QUALITY-TIER: GOLD | REALIZED-SHAPES: 4 | SECRECY: NOT_APPLICABLE_NO_LISTENER | AUTH-PROFILE: MUTUAL_MULTI_STRAND]
(herald
  "ODETTE-FTP-v2-Secure-Authentication Protocol Verification Suite")

(defprotocol ODETTE-FTP-v2-Secure-Authentication basic
  (defrole Initiator
    (vars (handshake_channel chan)
      (initiator_identification_code responder_identification_code name)
      (challenge_for_initiator challenge_for_responder text))
    (trace (send handshake_channel "SECD")
      (recv handshake_channel
        (cat "AUCH"
          (enc challenge_for_initiator
            (pubk initiator_identification_code))))
      (send handshake_channel (cat "AURP" challenge_for_initiator))
      (recv handshake_channel "SECD")
      (send handshake_channel
        (cat "AUCH"
          (enc challenge_for_responder
            (pubk responder_identification_code))))
      (recv handshake_channel (cat "AURP" challenge_for_responder)))
    (uniq-orig challenge_for_responder)
    (non-orig (privk initiator_identification_code))
    (inputs handshake_channel initiator_identification_code
      responder_identification_code
      (privk initiator_identification_code)
      (pubk responder_identification_code))
    (comment
      "Initiator holds its own private key (non-orig) to decrypt AUCH; Responder public key is public."))
  (defrole Responder
    (vars (handshake_channel chan)
      (initiator_identification_code responder_identification_code name)
      (challenge_for_initiator challenge_for_responder text))
    (trace (recv handshake_channel "SECD")
      (send handshake_channel
        (cat "AUCH"
          (enc challenge_for_initiator
            (pubk initiator_identification_code))))
      (recv handshake_channel (cat "AURP" challenge_for_initiator))
      (send handshake_channel "SECD")
      (recv handshake_channel
        (cat "AUCH"
          (enc challenge_for_responder
            (pubk responder_identification_code))))
      (send handshake_channel (cat "AURP" challenge_for_responder)))
    (uniq-orig challenge_for_initiator)
    (non-orig (privk responder_identification_code))
    (inputs handshake_channel initiator_identification_code
      responder_identification_code (pubk initiator_identification_code)
      (privk responder_identification_code))
    (comment
      "Responder holds its own private key (non-orig) to decrypt the Initiator's AUCH; the Responder's AUCH uses the Initiator's public key.")))

(defskeleton ODETTE-FTP-v2-Secure-Authentication
  (vars (handshake_channel chan)
    (initiator_identification_code responder_identification_code name)
    (challenge_for_initiator challenge_for_responder text))
  (defstrandmax Initiator (handshake_channel handshake_channel)
    (initiator_identification_code initiator_identification_code)
    (responder_identification_code responder_identification_code)
    (challenge_for_initiator challenge_for_initiator)
    (challenge_for_responder challenge_for_responder))
  (non-orig (privk initiator_identification_code)
    (privk responder_identification_code))
  (comment "Initiator POV; listeners intentionally empty."))

(defskeleton ODETTE-FTP-v2-Secure-Authentication
  (vars (handshake_channel chan)
    (initiator_identification_code responder_identification_code name)
    (challenge_for_initiator challenge_for_responder text))
  (defstrandmax Responder (handshake_channel handshake_channel)
    (initiator_identification_code initiator_identification_code)
    (responder_identification_code responder_identification_code)
    (challenge_for_initiator challenge_for_initiator)
    (challenge_for_responder challenge_for_responder))
  (non-orig (privk initiator_identification_code)
    (privk responder_identification_code))
  (comment "Responder POV; listeners intentionally empty."))

