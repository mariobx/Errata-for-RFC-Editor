;;; [RFC-ID: RFC 10002]
;;; [PROTOCOL: CMC-Certificate-Management-over-CMS]
;;; [SECTIONS: 2, 3, 4, 5, 6, 8, App-A, App-B]
;;; [ALGEBRA: basic]
;;; [ROLES: EndEntity, CertificationAuthority]
;;; [QUALITY-TIER: GOLD | REALIZED-SHAPES: 2 | SECRECY: NOT_APPLICABLE_NO_LISTENER | AUTH-PROFILE: MUTUAL_MULTI_STRAND]
(herald
  "CMC-Certificate-Management-over-CMS Protocol Verification Suite")

(defprotocol CMC-Certificate-Management-over-CMS basic
  (defrole EndEntity
    (vars (ee_name ca_name name)
      (shared_secret subject_dn subject_public_key_info
        issued_certificate data) (sender_nonce ca_sender_nonce text)
      (handshake_channel chan))
    (trace
      (send handshake_channel
        (enc "id-cct-PKIData" sender_nonce
          (hash shared_secret subject_dn subject_public_key_info)
          subject_dn subject_public_key_info (privk ee_name)))
      (recv handshake_channel
        (enc "id-cct-PKIResponse" "id-cmc-statusInfoV2" "success"
          sender_nonce ca_sender_nonce issued_certificate
          (privk ca_name))))
    (uniq-orig sender_nonce)
    (inputs handshake_channel ee_name ca_name shared_secret subject_dn
      subject_public_key_info (privk ee_name) (pubk ca_name))
    (outputs issued_certificate))
  (defrole CertificationAuthority
    (vars (ee_name ca_name name)
      (shared_secret subject_dn subject_public_key_info
        issued_certificate data) (sender_nonce ca_sender_nonce text)
      (handshake_channel chan))
    (trace
      (recv handshake_channel
        (enc "id-cct-PKIData" sender_nonce
          (hash shared_secret subject_dn subject_public_key_info)
          subject_dn subject_public_key_info (privk ee_name)))
      (send handshake_channel
        (enc "id-cct-PKIResponse" "id-cmc-statusInfoV2" "success"
          sender_nonce ca_sender_nonce issued_certificate
          (privk ca_name))))
    (uniq-orig ca_sender_nonce issued_certificate)
    (inputs handshake_channel ee_name ca_name shared_secret
      (pubk ee_name) subject_dn subject_public_key_info
      (privk ca_name))))

(defskeleton CMC-Certificate-Management-over-CMS
  (vars (ee_name ca_name name)
    (shared_secret subject_dn subject_public_key_info issued_certificate
      data) (sender_nonce ca_sender_nonce text)
    (handshake_channel chan))
  (defstrandmax EndEntity (ee_name ee_name) (ca_name ca_name)
    (shared_secret shared_secret) (subject_dn subject_dn)
    (subject_public_key_info subject_public_key_info)
    (sender_nonce sender_nonce) (issued_certificate issued_certificate)
    (handshake_channel handshake_channel)
    (ca_sender_nonce ca_sender_nonce))
  (non-orig (privk ee_name) (privk ca_name))
  (comment "Initiator POV; listeners intentionally empty."))

(defskeleton CMC-Certificate-Management-over-CMS
  (vars (ee_name ca_name name)
    (shared_secret subject_dn subject_public_key_info issued_certificate
      data) (sender_nonce ca_sender_nonce text)
    (handshake_channel chan))
  (defstrandmax CertificationAuthority (ee_name ee_name)
    (ca_name ca_name) (shared_secret shared_secret)
    (subject_dn subject_dn)
    (subject_public_key_info subject_public_key_info)
    (sender_nonce sender_nonce) (ca_sender_nonce ca_sender_nonce)
    (issued_certificate issued_certificate)
    (handshake_channel handshake_channel))
  (non-orig (privk ee_name) (privk ca_name))
  (comment "Responder POV; listeners intentionally empty."))

