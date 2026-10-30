#include "srtp_engine.hpp"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <arpa/inet.h>
#include <utility>

namespace ddos_samurai::telecom::sip_rtp {

SrtpEngine::SrtpEngine() = default;

SrtpEngine::~SrtpEngine() {
    CleanUpContexts();
}

SrtpEngine::SrtpEngine(SrtpEngine&& other) noexcept
    : session_ctx_(other.session_ctx_),
      enc_ctx_(other.enc_ctx_),
      mac_fetch_(other.mac_fetch_),
      mac_ctx_(other.mac_ctx_) {
    other.enc_ctx_ = nullptr;
    other.mac_fetch_ = nullptr;
    other.mac_ctx_ = nullptr;
}

SrtpEngine& SrtpEngine::operator=(SrtpEngine&& other) noexcept {
    if (this != &other) {
        CleanUpContexts();
        session_ctx_ = other.session_ctx_;
        enc_ctx_ = other.enc_ctx_;
        mac_fetch_ = other.mac_fetch_;
        mac_ctx_ = other.mac_ctx_;
        other.enc_ctx_ = nullptr;
        other.mac_fetch_ = nullptr;
        other.mac_ctx_ = nullptr;
    }
    return *this;
}

void SrtpEngine::CleanUpContexts() {
    if (enc_ctx_) {
        EVP_CIPHER_CTX_free(enc_ctx_);
        enc_ctx_ = nullptr;
    }
    if (mac_ctx_) {
        EVP_MAC_CTX_free(mac_ctx_);
        mac_ctx_ = nullptr;
    }
    if (mac_fetch_) {
        EVP_MAC_free(mac_fetch_);
        mac_fetch_ = nullptr;
    }
}

bool SrtpEngine::InitKeys(const SrtpKeyConfig& /*key_cfg*/) {
    return true;
}

bool SrtpEngine::ProtectRtp(const uint8_t* /*rtp_header*/,
                            const uint8_t* /*payload*/,
                            size_t /*payload_len*/,
                            std::vector<uint8_t>& /*out_srtp_pkt*/) {
    return false;
}

bool SrtpEngine::ProtectRtpInPlace(uint8_t* /*packet_buf*/, size_t /*rtp_header_len*/, size_t /*payload_len*/, size_t /*max_buf_len*/, size_t& /*out_total_len*/) {
    return false;
}

bool SrtpEngine::UnprotectRtp(const uint8_t* /*srtp_pkt*/,
                              size_t /*srtp_len*/,
                              std::vector<uint8_t>& /*out_payload*/) {
    return false;
}

bool SrtpEngine::UnprotectRtpInPlace(uint8_t* /*packet_buf*/, size_t /*srtp_len*/, size_t& /*out_decrypted_len*/) {
    return false;
}

bool SrtpEngine::DeriveSessionKeys(const SrtpKeyConfig& /*key_cfg*/,
                                  uint8_t /*out_k_e*/[SRTP_SESSION_ENC_KEY_LEN],
                                  uint8_t /*out_k_a*/[SRTP_SESSION_AUTH_KEY_LEN],
                                  uint8_t /*out_k_s*/[SRTP_SESSION_SALT_LEN]) {
    return false;
}

void SrtpEngine::ComputeAesIcmKeystream(EVP_CIPHER_CTX* /*aes_ctx*/,
                                       const uint8_t /*salt*/[SRTP_SESSION_SALT_LEN],
                                       uint32_t /*ssrc*/,
                                       uint64_t /*packet_index*/,
                                       uint8_t* /*data*/,
                                       size_t /*len*/) {
}

void SrtpEngine::ComputeHmacSha1Tag(EVP_MAC_CTX* /*mac_ctx*/,
                                   const uint8_t* /*rtp_header*/,
                                   size_t /*header_len*/,
                                   const uint8_t* /*ciphertext*/,
                                   size_t /*cipher_len*/,
                                   uint32_t /*roc*/,
                                   uint8_t /*out_tag*/[SRTP_AUTH_TAG_LEN]) {
}

bool SrtpEngine::CheckAndProcessReplay(SrtpSessionContext& /*ctx*/, uint16_t /*seq*/, uint64_t& /*out_index*/, uint32_t& /*out_roc*/) {
    return false;
}

void SrtpEngine::CommitReplay(SrtpSessionContext& /*ctx*/, uint16_t /*seq*/, uint64_t /*index*/, uint32_t /*roc*/) {
}

} // namespace ddos_samurai::telecom::sip_rtp
