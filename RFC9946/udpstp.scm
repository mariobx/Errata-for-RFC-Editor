;;; [RFC-ID: RFC 9946]
;;; [PROTOCOL: UDPSTP]
;;; [SECTIONS: 5.3, 5.4, 6, 7, 8, App-A]
;;; [ALGEBRA: basic]
;;; [ROLES: Client, Server]
;;; [QUALITY-TIER: GOLD | REALIZED-SHAPES: 4 | SECRECY: NOT_APPLICABLE_NO_LISTENER | AUTH-PROFILE: MUTUAL_MULTI_STRAND]
(herald
  "UDP Speed Test Protocol (UDPSTP) Control-phase Mode 1 (Required Authenticated Mode, Sections 5.3.1, 5.4, 5.4.1, 6, 7). Authentication-only: each Control PDU carries an HMAC-SHA-256 authDigest keyed by a client- or server-direction key derived from the shared key Kin. Modeled with the basic algebra: HMAC is modeled as a keyed hash over the PDU body (authDigest/checkSum zeroed) and the KDF as a keyed hash over the label UDPSTP and the authUnixTime context. The KDF direction label CLIENT/SERVER is a modeling split of the single 512-bit KDF output into its two 256-bit halves. Data-phase Status PDU authentication (Mode 2) is out of scope for this control-phase model.")

(defprotocol UDPSTP basic
  (defrole Client
    (vars (control_channel ephemeral_channel chan) (shared_key skey)
      (setup_request_fields setup_response_fields
        activation_request_fields activation_response_fields data)
      (setup_auth_unix_time setup_response_auth_unix_time
        activation_request_auth_unix_time
        activation_response_auth_unix_time text))
    (trace
      (send control_channel
        (cat "CHSR_CREQ_SETUPREQ" setup_request_fields
          setup_auth_unix_time
          (hash (hash shared_key "UDPSTP" setup_auth_unix_time "CLIENT")
            "CHSR_CREQ_SETUPREQ" setup_request_fields
            setup_auth_unix_time)))
      (recv control_channel
        (cat "CHSR_CREQ_SETUPRSP" setup_response_fields
          setup_response_auth_unix_time
          (hash (hash shared_key "UDPSTP" setup_auth_unix_time "SERVER")
            "CHSR_CREQ_SETUPRSP" setup_response_fields
            setup_response_auth_unix_time)))
      (send ephemeral_channel
        (cat "CHTA_CREQ_TESTACTUS" activation_request_fields
          activation_request_auth_unix_time
          (hash (hash shared_key "UDPSTP" setup_auth_unix_time "CLIENT")
            "CHTA_CREQ_TESTACTUS" activation_request_fields
            activation_request_auth_unix_time)))
      (recv ephemeral_channel
        (cat "CHTA_CREQ_TESTACTUS" activation_response_fields
          activation_response_auth_unix_time
          (hash (hash shared_key "UDPSTP" setup_auth_unix_time "SERVER")
            "CHTA_CREQ_TESTACTUS" activation_response_fields
            activation_response_auth_unix_time))))
    (uniq-orig setup_request_fields setup_auth_unix_time
      activation_request_fields activation_request_auth_unix_time)
    (inputs control_channel ephemeral_channel shared_key)
    (comment
      "Authentication-only: no confidential secret is transmitted."))
  (defrole Server
    (vars (control_channel ephemeral_channel chan) (shared_key skey)
      (setup_request_fields setup_response_fields
        activation_request_fields activation_response_fields data)
      (setup_auth_unix_time setup_response_auth_unix_time
        null_request_auth_unix_time activation_request_auth_unix_time
        activation_response_auth_unix_time text))
    (trace
      (recv control_channel
        (cat "CHSR_CREQ_SETUPREQ" setup_request_fields
          setup_auth_unix_time
          (hash (hash shared_key "UDPSTP" setup_auth_unix_time "CLIENT")
            "CHSR_CREQ_SETUPREQ" setup_request_fields
            setup_auth_unix_time)))
      (send control_channel
        (cat "CHSR_CREQ_SETUPRSP" setup_response_fields
          setup_response_auth_unix_time
          (hash (hash shared_key "UDPSTP" setup_auth_unix_time "SERVER")
            "CHSR_CREQ_SETUPRSP" setup_response_fields
            setup_response_auth_unix_time)))
      (send ephemeral_channel
        (cat "CHNR_CREQ_NULLREQ" null_request_auth_unix_time
          (hash (hash shared_key "UDPSTP" setup_auth_unix_time "SERVER")
            "CHNR_CREQ_NULLREQ" null_request_auth_unix_time)))
      (recv ephemeral_channel
        (cat "CHTA_CREQ_TESTACTUS" activation_request_fields
          activation_request_auth_unix_time
          (hash (hash shared_key "UDPSTP" setup_auth_unix_time "CLIENT")
            "CHTA_CREQ_TESTACTUS" activation_request_fields
            activation_request_auth_unix_time)))
      (send ephemeral_channel
        (cat "CHTA_CREQ_TESTACTUS" activation_response_fields
          activation_response_auth_unix_time
          (hash (hash shared_key "UDPSTP" setup_auth_unix_time "SERVER")
            "CHTA_CREQ_TESTACTUS" activation_response_fields
            activation_response_auth_unix_time))))
    (uniq-orig setup_response_fields setup_response_auth_unix_time
      null_request_auth_unix_time activation_response_fields
      activation_response_auth_unix_time)
    (inputs control_channel ephemeral_channel shared_key)
    (comment
      "Authentication-only: no confidential secret is transmitted.")))

(defskeleton UDPSTP
  (vars (control_channel ephemeral_channel chan) (shared_key skey)
    (setup_request_fields setup_response_fields
      activation_request_fields activation_response_fields data)
    (setup_auth_unix_time setup_response_auth_unix_time
      activation_request_auth_unix_time
      activation_response_auth_unix_time text))
  (defstrandmax Client (control_channel control_channel)
    (ephemeral_channel ephemeral_channel) (shared_key shared_key)
    (setup_request_fields setup_request_fields)
    (setup_auth_unix_time setup_auth_unix_time)
    (setup_response_fields setup_response_fields)
    (setup_response_auth_unix_time setup_response_auth_unix_time)
    (activation_request_fields activation_request_fields)
    (activation_request_auth_unix_time
      activation_request_auth_unix_time)
    (activation_response_fields activation_response_fields)
    (activation_response_auth_unix_time
      activation_response_auth_unix_time))
  (non-orig shared_key)
  (comment
    "Initiator POV; uniq-orig atoms are carried by the role declaration. No listeners because no secret is established."))

(defskeleton UDPSTP
  (vars (control_channel ephemeral_channel chan) (shared_key skey)
    (setup_request_fields setup_response_fields
      activation_request_fields activation_response_fields data)
    (setup_auth_unix_time setup_response_auth_unix_time
      null_request_auth_unix_time activation_request_auth_unix_time
      activation_response_auth_unix_time text))
  (defstrandmax Server (control_channel control_channel)
    (ephemeral_channel ephemeral_channel) (shared_key shared_key)
    (setup_request_fields setup_request_fields)
    (setup_auth_unix_time setup_auth_unix_time)
    (setup_response_fields setup_response_fields)
    (setup_response_auth_unix_time setup_response_auth_unix_time)
    (null_request_auth_unix_time null_request_auth_unix_time)
    (activation_request_fields activation_request_fields)
    (activation_request_auth_unix_time
      activation_request_auth_unix_time)
    (activation_response_fields activation_response_fields)
    (activation_response_auth_unix_time
      activation_response_auth_unix_time))
  (non-orig shared_key)
  (comment
    "Responder POV; uniq-orig atoms are carried by the role declaration. No listeners because no secret is established."))

