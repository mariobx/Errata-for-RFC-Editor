;;; [RFC-ID: RFC 9799]
;;; [PROTOCOL: onion_csr_01]
;;; [SECTIONS: 3.2, 4, 5, 8.1, 8.3]
;;; [ALGEBRA: basic]
;;; [ROLES: ACME_Client, ACME_Server]
;;; [QUALITY-TIER: GOLD | REALIZED-SHAPES: 2 | SECRECY: NOT_APPLICABLE_NO_LISTENER | AUTH-PROFILE: UNILATERAL_AUTHENTICATED]
(herald "onion_csr_01 Protocol Verification Suite")

(defprotocol onion_csr_01 basic
  (defrole ACME_Client
    (vars (acme_channel chan) (onion_service_name name)
      (challenge_nonce applicant_signing_nonce text)
      (acme_auth_key data))
    (trace
      (recv acme_channel
        (cat "onion-csr-01" challenge_nonce acme_auth_key))
      (send acme_channel
        (cat "csr"
          (enc
            (cat "caSigningNonce" challenge_nonce
              "applicantSigningNonce" applicant_signing_nonce
              (pubk onion_service_name)) (privk onion_service_name)))))
    (uniq-orig applicant_signing_nonce)
    (non-orig (privk onion_service_name))
    (inputs acme_channel onion_service_name (pubk onion_service_name)
      (privk onion_service_name))
    (comment
      "Client holds the .onion private key (Tor Hidden Service key holder); the key is non-originating."))
  (defrole ACME_Server
    (vars (acme_channel chan) (onion_service_name name)
      (challenge_nonce applicant_signing_nonce text)
      (acme_auth_key data))
    (trace
      (send acme_channel
        (cat "onion-csr-01" challenge_nonce acme_auth_key))
      (recv acme_channel
        (cat "csr"
          (enc
            (cat "caSigningNonce" challenge_nonce
              "applicantSigningNonce" applicant_signing_nonce
              (pubk onion_service_name)) (privk onion_service_name)))))
    (uniq-orig challenge_nonce)
    (inputs acme_channel onion_service_name acme_auth_key
      (pubk onion_service_name))
    (comment
      "The RFC does not define a further server response flight; validation success or failure is a local decision.")))

(defskeleton onion_csr_01
  (vars (acme_channel chan) (onion_service_name name)
    (challenge_nonce applicant_signing_nonce text) (acme_auth_key data))
  (defstrandmax ACME_Client (acme_channel acme_channel)
    (onion_service_name onion_service_name)
    (challenge_nonce challenge_nonce) (acme_auth_key acme_auth_key)
    (applicant_signing_nonce applicant_signing_nonce))
  (non-orig (privk onion_service_name))
  (comment
    "Authentication-only exchange; no secrecy goals, so no deflistener."))

(defskeleton onion_csr_01
  (vars (acme_channel chan) (onion_service_name name)
    (challenge_nonce applicant_signing_nonce text) (acme_auth_key data))
  (defstrandmax ACME_Server (acme_channel acme_channel)
    (onion_service_name onion_service_name)
    (challenge_nonce challenge_nonce) (acme_auth_key acme_auth_key)
    (applicant_signing_nonce applicant_signing_nonce))
  (non-orig (privk onion_service_name))
  (comment
    "Mutual authentication view; the server verifies the CSR signature against the .onion public key."))

