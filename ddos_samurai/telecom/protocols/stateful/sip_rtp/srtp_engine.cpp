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

bool SrtpEngine::InitKeys(const SrtpKeyConfig& key_cfg) {
    CleanUpContexts();

    if (!DeriveSessionKeys(key_cfg, session_ctx_.k_e, session_ctx_.k_a, session_ctx_.k_s)) {
        return false;
    }

    enc_ctx_ = EVP_CIPHER_CTX_new();
    if (!enc_ctx_) return false;
    if (EVP_EncryptInit_ex(enc_ctx_, EVP_aes_128_ecb(), nullptr, session_ctx_.k_e, nullptr) != 1) {
        CleanUpContexts();
        return false;
    }
    EVP_CIPHER_CTX_set_padding(enc_ctx_, 0);

    mac_fetch_ = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac_fetch_) {
        CleanUpContexts();
        return false;
    }

    mac_ctx_ = EVP_MAC_CTX_new(mac_fetch_);
    if (!mac_ctx_) {
        CleanUpContexts();
        return false;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>("SHA1"), 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(mac_ctx_, session_ctx_.k_a, SRTP_SESSION_AUTH_KEY_LEN, params) != 1) {
        CleanUpContexts();
        return false;
    }

    session_ctx_.roc = 0;
    session_ctx_.s_l = 0;
    session_ctx_.replay_bitmap = 0;
    session_ctx_.initialized = false;

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

bool SrtpEngine::DeriveSessionKeys(const SrtpKeyConfig& key_cfg,
                                   uint8_t out_k_e[SRTP_SESSION_ENC_KEY_LEN],
                                   uint8_t out_k_a[SRTP_SESSION_AUTH_KEY_LEN],
                                   uint8_t out_k_s[SRTP_SESSION_SALT_LEN]) {
    // RFC 3711 Section 4.3.1 Key Derivation Function (KDF) using AES-128-CM PRF
    // IV = (master_salt * 2^16) XOR (label * 2^48)
    // master_salt is 14 bytes (bytes 0..13) padded with 2 zero bytes (bytes 14..15).
    // label is XORed into byte index 7.
    // Keystream block i is AES_ECB(master_key, IV + i mod 2^16).

    EVP_CIPHER_CTX* kdf_ctx = EVP_CIPHER_CTX_new();
    if (!kdf_ctx) return false;

    if (EVP_EncryptInit_ex(kdf_ctx, EVP_aes_128_ecb(), nullptr, key_cfg.master_key, nullptr) != 1) {
        EVP_CIPHER_CTX_free(kdf_ctx);
        return false;
    }
    EVP_CIPHER_CTX_set_padding(kdf_ctx, 0);

    auto prf_generate = [&](uint8_t label, uint8_t* out, size_t out_len) {
        uint8_t iv[16] = {0};
        std::memcpy(iv, key_cfg.master_salt, SRTP_MASTER_SALT_LEN);
        iv[14] = 0;
        iv[15] = 0;
        iv[7] ^= label;

        uint16_t counter = 0;
        size_t written = 0;
        uint8_t block[16];
        int out_block_len = 0;

        while (written < out_len) {
            uint8_t iv_block[16];
            std::memcpy(iv_block, iv, 16);
            uint16_t val = (static_cast<uint16_t>(iv_block[14]) << 8) | iv_block[15];
            val = static_cast<uint16_t>(val + counter);
            iv_block[14] = static_cast<uint8_t>((val >> 8) & 0xFF);
            iv_block[15] = static_cast<uint8_t>(val & 0xFF);

            if (EVP_EncryptUpdate(kdf_ctx, block, &out_block_len, iv_block, 16) != 1) {
                return false;
            }

            size_t to_copy = std::min(out_len - written, static_cast<size_t>(16));
            std::memcpy(out + written, block, to_copy);
            written += to_copy;
            counter++;
        }
        return true;
    };

    // Label 0x00: SRTP Encryption Key (128 bits = 16 bytes)
    bool ok1 = prf_generate(0x00, out_k_e, SRTP_SESSION_ENC_KEY_LEN);
    // Label 0x01: SRTP Authentication Key (160 bits = 20 bytes)
    bool ok2 = prf_generate(0x01, out_k_a, SRTP_SESSION_AUTH_KEY_LEN);
    // Label 0x02: SRTP Salting Key (112 bits = 14 bytes)
    bool ok3 = prf_generate(0x02, out_k_s, SRTP_SESSION_SALT_LEN);

    EVP_CIPHER_CTX_free(kdf_ctx);
    return ok1 && ok2 && ok3;
}

void SrtpEngine::ComputeAesIcmKeystream(EVP_CIPHER_CTX* aes_ctx,
                                       const uint8_t salt[SRTP_SESSION_SALT_LEN],
                                       uint32_t ssrc,
                                       uint64_t packet_index,
                                       uint8_t* data,
                                       size_t len) {
    if (!aes_ctx || !salt || !data || len == 0) return;

    // RFC 3711 Section 4.1.1: IV = (salt * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
    uint8_t iv_base[16] = {0};
    std::memcpy(iv_base, salt, SRTP_SESSION_SALT_LEN);

    // SSRC XOR into bytes 4..7 (network byte order)
    iv_base[4] ^= static_cast<uint8_t>((ssrc >> 24) & 0xFF);
    iv_base[5] ^= static_cast<uint8_t>((ssrc >> 16) & 0xFF);
    iv_base[6] ^= static_cast<uint8_t>((ssrc >> 8) & 0xFF);
    iv_base[7] ^= static_cast<uint8_t>(ssrc & 0xFF);

    // 48-bit packet index XOR into bytes 8..13 (network byte order)
    iv_base[8]  ^= static_cast<uint8_t>((packet_index >> 40) & 0xFF);
    iv_base[9]  ^= static_cast<uint8_t>((packet_index >> 32) & 0xFF);
    iv_base[10] ^= static_cast<uint8_t>((packet_index >> 24) & 0xFF);
    iv_base[11] ^= static_cast<uint8_t>((packet_index >> 16) & 0xFF);
    iv_base[12] ^= static_cast<uint8_t>((packet_index >> 8) & 0xFF);
    iv_base[13] ^= static_cast<uint8_t>(packet_index & 0xFF);

    uint16_t block_counter = 0;
    size_t processed = 0;
    uint8_t iv_block[16];
    uint8_t keystream_block[16];
    int out_len = 0;

    // Fastpath packet loop: Zero heap allocations
    while (processed < len) {
        std::memcpy(iv_block, iv_base, 16);
        iv_block[14] = static_cast<uint8_t>((block_counter >> 8) & 0xFF);
        iv_block[15] = static_cast<uint8_t>(block_counter & 0xFF);

        EVP_EncryptUpdate(aes_ctx, keystream_block, &out_len, iv_block, 16);

        size_t to_xor = std::min(len - processed, static_cast<size_t>(16));
        for (size_t i = 0; i < to_xor; ++i) {
            data[processed + i] ^= keystream_block[i];
        }
        processed += to_xor;
        block_counter++;
    }
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
