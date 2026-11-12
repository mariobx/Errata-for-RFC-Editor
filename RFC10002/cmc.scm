;;; [RFC-ID: RFC 10002]
;;; [PROTOCOL: CMC]
;;; [SECTIONS: 2, 3, 4, 5, 6, App-A, App-B, App-C]
;;; [ALGEBRA: basic]
;;; [ROLES: end_entity, certification_authority]
;;; [QUALITY-TIER: GOLD | REALIZED-SHAPES: 3 | SECRECY: NOT_APPLICABLE_NO_LISTENER | AUTH-PROFILE: MUTUAL_MULTI_STRAND]
(herald
  "The exchange modeled is the explicit signing-certificate round trip in Appendix B.1. CMC also defines optional services, variants, and RA-mediated flows not instantiated in this concrete exchange.")

(defprotocol CMC basic
  (defrole end_entity
    (vars (end_entity certification_authority name)
      (handshake_channel chan) (shared_secret skey)
      (req_sequence cert_req_id subject_name issued_certificates data)
      (subject_key_identifier sender_nonce server_sender_nonce text))
    (trace
      (send handshake_channel
        (enc
          (cat "CMC_PKI_REQUEST" "id-cct-PKIData" req_sequence
            "id-cmc-identityProof"
            (hash (cat shared_secret req_sequence)) "id-cmc-senderNonce"
            sender_nonce "crm" cert_req_id "CertTemplate.subject"
            subject_name "CertTemplate.publicKey" (pubk end_entity)
            "id-ce-subjectKeyIdentifier" subject_key_identifier
            "id-ce-keyUsage" "digitalSignature") (privk end_entity)))
      (recv handshake_channel
        (enc
          (cat "CMC_PKI_RESPONSE" "id-cct-PKIResponse"
            "id-cmc-statusInfoV2" "success" cert_req_id
            "id-cmc-senderNonce" server_sender_nonce
            "id-cmc-recipientNonce" sender_nonce issued_certificates)
          (privk certification_authority))))
    (uniq-orig sender_nonce)
    (non-orig shared_secret (privk end_entity))
    (inputs handshake_channel end_entity certification_authority
      shared_secret (pubk certification_authority) req_sequence
      cert_req_id subject_name subject_key_identifier (pubk end_entity)
      (privk end_entity))
    (outputs issued_certificates)
    (comment
      "Concrete signing-certificate enrollment exchange from Appendix B.1. The RFC provides no CPSA-native MAC operator; the hash of the shared-secret and request sequence models the keyed Identity Proof witness without nesting an encryption term inside a hash."))
  (defrole certification_authority
    (vars (end_entity certification_authority name)
      (handshake_channel chan) (shared_secret skey)
      (req_sequence cert_req_id subject_name issued_certificates data)
      (subject_key_identifier sender_nonce server_sender_nonce text))
    (trace
      (recv handshake_channel
        (enc
          (cat "CMC_PKI_REQUEST" "id-cct-PKIData" req_sequence
            "id-cmc-identityProof"
            (hash (cat shared_secret req_sequence)) "id-cmc-senderNonce"
            sender_nonce "crm" cert_req_id "CertTemplate.subject"
            subject_name "CertTemplate.publicKey" (pubk end_entity)
            "id-ce-subjectKeyIdentifier" subject_key_identifier
            "id-ce-keyUsage" "digitalSignature") (privk end_entity)))
      (send handshake_channel
        (enc
          (cat "CMC_PKI_RESPONSE" "id-cct-PKIResponse"
            "id-cmc-statusInfoV2" "success" cert_req_id
            "id-cmc-senderNonce" server_sender_nonce
            "id-cmc-recipientNonce" sender_nonce issued_certificates)
          (privk certification_authority))))
    (uniq-orig server_sender_nonce issued_certificates)
    (non-orig shared_secret (privk certification_authority))
    (inputs handshake_channel end_entity certification_authority
      shared_secret (pubk end_entity) req_sequence cert_req_id
      subject_name subject_key_identifier sender_nonce
      (privk certification_authority))
    (outputs server_sender_nonce issued_certificates)
    (comment
      "Concrete signing-certificate enrollment exchange from Appendix B.1. The RFC provides no CPSA-native MAC operator; the hash of the shared-secret and request sequence models the keyed Identity Proof witness without nesting an encryption term inside a hash.")))

(defskeleton CMC
  (vars (end_entity certification_authority name)
    (handshake_channel chan) (shared_secret skey)
    (req_sequence cert_req_id subject_name issued_certificates data)
    (subject_key_identifier sender_nonce server_sender_nonce text))
  (defstrandmax end_entity (end_entity end_entity)
    (certification_authority certification_authority)
    (handshake_channel handshake_channel) (shared_secret shared_secret)
    (req_sequence req_sequence) (cert_req_id cert_req_id)
    (subject_name subject_name)
    (subject_key_identifier subject_key_identifier)
    (sender_nonce sender_nonce)
    (server_sender_nonce server_sender_nonce)
    (issued_certificates issued_certificates))
  (non-orig shared_secret (privk end_entity)
    (privk certification_authority))
  (comment
    "Role-level freshness declarations govern the Sender Nonce; the skeleton does not repeat them."))

(defskeleton CMC
  (vars (end_entity certification_authority name)
    (handshake_channel chan) (shared_secret skey)
    (req_sequence cert_req_id subject_name issued_certificates data)
    (subject_key_identifier sender_nonce server_sender_nonce text))
  (defstrandmax certification_authority (end_entity end_entity)
    (certification_authority certification_authority)
    (handshake_channel handshake_channel) (shared_secret shared_secret)
    (req_sequence req_sequence) (cert_req_id cert_req_id)
    (subject_name subject_name)
    (subject_key_identifier subject_key_identifier)
    (sender_nonce sender_nonce)
    (server_sender_nonce server_sender_nonce)
    (issued_certificates issued_certificates))
  (non-orig shared_secret (privk end_entity)
    (privk certification_authority))
  (comment
    "Role-level freshness declarations govern the server Sender Nonce; the skeleton does not repeat them."))

