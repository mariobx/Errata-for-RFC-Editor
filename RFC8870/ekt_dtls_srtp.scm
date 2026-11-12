;;; [RFC-ID: RFC 8870]
;;; [PROTOCOL: EKT_DTLS_SRTP]
;;; [SECTIONS: 4, 5]
;;; [ALGEBRA: basic]
;;; [ROLES: DTLS_SRTP_Server, DTLS_SRTP_Client, EKT_Sender, EKT_Receiver]
;;; [QUALITY-TIER: GOLD | REALIZED-SHAPES: 5 | SECRECY: SECRECY_PROVED | AUTH-PROFILE: UNILATERAL_AUTHENTICATED]
(herald "EKT_DTLS_SRTP Protocol Verification Suite")

(defprotocol EKT_DTLS_SRTP basic
  (defrole DTLS_SRTP_Server
    (vars (server_name client_name name) (dtls_channel chan)
      (ekt_key_value skey) (srtp_master_salt ekt_spi ekt_ttl data))
    (trace
      (send dtls_channel
        (enc "EKTKey" ekt_key_value srtp_master_salt ekt_spi ekt_ttl
          (ltk server_name client_name)))
      (recv dtls_channel
        (enc "EKT_ACK" ekt_spi (ltk server_name client_name))))
    (uniq-orig ekt_key_value)
    (conf dtls_channel)
    (auth dtls_channel)
    (inputs dtls_channel server_name client_name srtp_master_salt
      ekt_spi ekt_ttl (ltk server_name client_name)))
  (defrole DTLS_SRTP_Client
    (vars (server_name client_name name) (dtls_channel chan)
      (ekt_key_value skey) (srtp_master_salt ekt_spi ekt_ttl data))
    (trace
      (recv dtls_channel
        (enc "EKTKey" ekt_key_value srtp_master_salt ekt_spi ekt_ttl
          (ltk server_name client_name)))
      (send dtls_channel
        (enc "EKT_ACK" ekt_spi (ltk server_name client_name))))
    (conf dtls_channel)
    (auth dtls_channel)
    (inputs dtls_channel server_name client_name
      (ltk server_name client_name))
    (outputs ekt_key_value srtp_master_salt ekt_spi))
  (defrole EKT_Sender
    (vars (srtp_channel chan) (ekt_key_value skey)
      (srtp_master_key_length srtp_master_key ekt_spi epoch
        ekt_msg_length data) (ssrc roc text))
    (trace
      (send srtp_channel
        (cat
          (enc srtp_master_key_length srtp_master_key ssrc roc
            ekt_key_value) ekt_spi epoch ekt_msg_length
          "EKTMsgTypeFull")))
    (uniq-orig srtp_master_key)
    (inputs srtp_channel ekt_key_value srtp_master_key_length ssrc roc
      ekt_spi epoch ekt_msg_length))
  (defrole EKT_Receiver
    (vars (srtp_channel chan) (ekt_key_value skey)
      (srtp_master_key_length srtp_master_key ekt_spi epoch
        ekt_msg_length data) (ssrc roc text))
    (trace
      (recv srtp_channel
        (cat
          (enc srtp_master_key_length srtp_master_key ssrc roc
            ekt_key_value) ekt_spi epoch ekt_msg_length
          "EKTMsgTypeFull")))
    (inputs srtp_channel ekt_key_value srtp_master_key_length ssrc roc
      ekt_spi epoch ekt_msg_length)
    (outputs srtp_master_key)))

(defskeleton EKT_DTLS_SRTP
  (vars (server_name client_name name) (dtls_channel chan)
    (ekt_key_value skey) (srtp_master_salt ekt_spi ekt_ttl data))
  (defstrandmax DTLS_SRTP_Server (server_name server_name)
    (client_name client_name) (dtls_channel dtls_channel)
    (ekt_key_value ekt_key_value) (srtp_master_salt srtp_master_salt)
    (ekt_spi ekt_spi) (ekt_ttl ekt_ttl))
  (non-orig (ltk server_name client_name))
  (comment "Responder/initiator POV for server; no listeners."))

(defskeleton EKT_DTLS_SRTP
  (vars (server_name client_name name) (dtls_channel chan)
    (ekt_key_value skey) (srtp_master_salt ekt_spi ekt_ttl data))
  (defstrandmax DTLS_SRTP_Client (server_name server_name)
    (client_name client_name) (dtls_channel dtls_channel)
    (ekt_key_value ekt_key_value) (srtp_master_salt srtp_master_salt)
    (ekt_spi ekt_spi) (ekt_ttl ekt_ttl))
  (non-orig (ltk server_name client_name))
  (comment "Responder POV for client; no listeners."))

(defskeleton EKT_DTLS_SRTP
  (vars (srtp_channel chan) (ekt_key_value skey)
    (srtp_master_key_length srtp_master_key ekt_spi epoch ekt_msg_length
      data) (ssrc roc text) (server_name client_name name))
  (defstrandmax EKT_Sender (srtp_channel srtp_channel)
    (ekt_key_value ekt_key_value)
    (srtp_master_key_length srtp_master_key_length)
    (srtp_master_key srtp_master_key) (ssrc ssrc) (roc roc)
    (ekt_spi ekt_spi) (epoch epoch) (ekt_msg_length ekt_msg_length))
  (non-orig ekt_key_value)
  (comment "Ekt_sender Point of View"))

(defskeleton EKT_DTLS_SRTP
  (vars (srtp_channel chan) (ekt_key_value skey)
    (srtp_master_key_length srtp_master_key ekt_spi epoch ekt_msg_length
      data) (ssrc roc text) (server_name client_name name))
  (defstrandmax EKT_Receiver (srtp_channel srtp_channel)
    (ekt_key_value ekt_key_value)
    (srtp_master_key_length srtp_master_key_length)
    (srtp_master_key srtp_master_key) (ssrc ssrc) (roc roc)
    (ekt_spi ekt_spi) (epoch epoch) (ekt_msg_length ekt_msg_length))
  (non-orig ekt_key_value)
  (comment "Ekt_receiver Point of View"))

(defskeleton EKT_DTLS_SRTP
  (vars (srtp_channel chan) (ekt_key_value skey)
    (srtp_master_key_length srtp_master_key ekt_spi epoch ekt_msg_length
      data) (ssrc roc text))
  (defstrandmax EKT_Sender (srtp_channel srtp_channel)
    (ekt_key_value ekt_key_value)
    (srtp_master_key_length srtp_master_key_length)
    (srtp_master_key srtp_master_key) (ssrc ssrc) (roc roc)
    (ekt_spi ekt_spi) (epoch epoch) (ekt_msg_length ekt_msg_length))
  (deflistener srtp_master_key)
  (non-orig ekt_key_value)
  (facts (neq srtp_master_key srtp_master_key_length)
    (neq srtp_master_key ekt_spi) (neq srtp_master_key epoch)
    (neq srtp_master_key ekt_msg_length))
  (comment
    "Confidentiality of SRTP master key transported under the EKTKey."))

