#include "srtp_engine.hpp"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <arpa/inet.h>
#include <utility>

namespace samurai::telecom::sip_rtp {

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

bool SrtpEngine::ProtectRtp(const uint8_t* rtp_header,
                            const uint8_t* payload,
                            size_t payload_len,
                            std::vector<uint8_t>& out_srtp_pkt) {
    if (!enc_ctx_ || !mac_ctx_ || !rtp_header) return false;

    uint16_t seq = (static_cast<uint16_t>(rtp_header[2]) << 8) | rtp_header[3];
    uint32_t ssrc = (static_cast<uint32_t>(rtp_header[8]) << 24) |
                    (static_cast<uint32_t>(rtp_header[9]) << 16) |
                    (static_cast<uint32_t>(rtp_header[10]) << 8) |
                    rtp_header[11];

    if (!session_ctx_.initialized) {
        session_ctx_.initialized = true;
        session_ctx_.s_l = seq;
        session_ctx_.roc = 0;
    } else {
        if (session_ctx_.s_l > 32768 && seq < 32768 && (session_ctx_.s_l - seq > 32768)) {
            session_ctx_.roc++;
        }
        if (seq > session_ctx_.s_l || (session_ctx_.s_l > 32768 && seq < 32768)) {
            session_ctx_.s_l = seq;
        }
    }

    uint64_t packet_index = (static_cast<uint64_t>(session_ctx_.roc) << 16) | seq;

    size_t total_len = 12 + payload_len + SRTP_AUTH_TAG_LEN;
    out_srtp_pkt.resize(total_len);

    // 1. Copy plaintext RTP header (12 bytes)
    std::memcpy(out_srtp_pkt.data(), rtp_header, 12);

    // 2. Encrypt audio payload
    if (payload && payload_len > 0) {
        std::memcpy(out_srtp_pkt.data() + 12, payload, payload_len);
        ComputeAesIcmKeystream(enc_ctx_, session_ctx_.k_s, ssrc, packet_index, out_srtp_pkt.data() + 12, payload_len);
    }

    // 3. Compute HMAC-SHA1-80 auth tag over RTP header + Encrypted Payload + ROC
    ComputeHmacSha1Tag(mac_ctx_,
                       out_srtp_pkt.data(),
                       12,
                       out_srtp_pkt.data() + 12,
                       payload_len,
                       session_ctx_.roc,
                       out_srtp_pkt.data() + 12 + payload_len);

    return true;
}

bool SrtpEngine::ProtectRtpInPlace(uint8_t* packet_buf, size_t rtp_header_len, size_t payload_len, size_t max_buf_len, size_t& out_total_len) {
    if (!enc_ctx_ || !mac_ctx_ || !packet_buf || rtp_header_len < 12) return false;
    size_t required_len = rtp_header_len + payload_len + SRTP_AUTH_TAG_LEN;
    if (max_buf_len < required_len) return false;

    uint16_t seq = (static_cast<uint16_t>(packet_buf[2]) << 8) | packet_buf[3];
    uint32_t ssrc = (static_cast<uint32_t>(packet_buf[8]) << 24) |
                    (static_cast<uint32_t>(packet_buf[9]) << 16) |
                    (static_cast<uint32_t>(packet_buf[10]) << 8) |
                    packet_buf[11];

    if (!session_ctx_.initialized) {
        session_ctx_.initialized = true;
        session_ctx_.s_l = seq;
        session_ctx_.roc = 0;
    } else {
        if (session_ctx_.s_l > 32768 && seq < 32768 && (session_ctx_.s_l - seq > 32768)) {
            session_ctx_.roc++;
        }
        if (seq > session_ctx_.s_l || (session_ctx_.s_l > 32768 && seq < 32768)) {
            session_ctx_.s_l = seq;
        }
    }

    uint64_t packet_index = (static_cast<uint64_t>(session_ctx_.roc) << 16) | seq;

    if (payload_len > 0) {
        ComputeAesIcmKeystream(enc_ctx_, session_ctx_.k_s, ssrc, packet_index, packet_buf + rtp_header_len, payload_len);
    }

    ComputeHmacSha1Tag(mac_ctx_,
                       packet_buf,
                       rtp_header_len,
                       packet_buf + rtp_header_len,
                       payload_len,
                       session_ctx_.roc,
                       packet_buf + rtp_header_len + payload_len);

    out_total_len = required_len;
    return true;
}

bool SrtpEngine::UnprotectRtpBuffer(const uint8_t* srtp_pkt,
                                    size_t srtp_len,
                                    uint8_t* out_payload,
                                    size_t max_out_len,
                                    size_t& out_len) {
    if (!enc_ctx_ || !mac_ctx_ || !srtp_pkt) return false;
    if (srtp_len < 12 + SRTP_AUTH_TAG_LEN) return false;

    size_t cipher_len = srtp_len - 12 - SRTP_AUTH_TAG_LEN;
    if (max_out_len < cipher_len) return false;

    uint16_t seq = (static_cast<uint16_t>(srtp_pkt[2]) << 8) | srtp_pkt[3];
    uint32_t ssrc = (static_cast<uint32_t>(srtp_pkt[8]) << 24) |
                    (static_cast<uint32_t>(srtp_pkt[9]) << 16) |
                    (static_cast<uint32_t>(srtp_pkt[10]) << 8) |
                    srtp_pkt[11];

    uint64_t packet_index = 0;
    uint32_t est_roc = 0;
    if (!CheckAndProcessReplay(session_ctx_, seq, packet_index, est_roc)) {
        return false; // Replay check failed
    }

    // Verify HMAC-SHA1-80 auth tag
    uint8_t expected_tag[SRTP_AUTH_TAG_LEN];
    ComputeHmacSha1Tag(mac_ctx_, srtp_pkt, 12, srtp_pkt + 12, cipher_len, est_roc, expected_tag);

    const uint8_t* rx_tag = srtp_pkt + 12 + cipher_len;
    if (CRYPTO_memcmp(rx_tag, expected_tag, SRTP_AUTH_TAG_LEN) != 0) {
        return false; // Authentication tag mismatch (tampering detected)
    }

    // Auth succeeded: commit to sliding replay window
    CommitReplay(session_ctx_, seq, packet_index, est_roc);

    // Decrypt audio payload directly into buffer (Zero Heap Allocation)
    if (cipher_len > 0 && out_payload) {
        std::memcpy(out_payload, srtp_pkt + 12, cipher_len);
        ComputeAesIcmKeystream(enc_ctx_, session_ctx_.k_s, ssrc, packet_index, out_payload, cipher_len);
    }
    out_len = cipher_len;

    return true;
}

bool SrtpEngine::UnprotectRtp(const uint8_t* srtp_pkt,
                              size_t srtp_len,
                              std::vector<uint8_t>& out_payload) {
    if (!srtp_pkt || srtp_len < 12 + SRTP_AUTH_TAG_LEN) return false;
    size_t cipher_len = srtp_len - 12 - SRTP_AUTH_TAG_LEN;
    out_payload.resize(cipher_len);
    size_t out_len = 0;
    bool ok = UnprotectRtpBuffer(srtp_pkt, srtp_len, out_payload.data(), out_payload.size(), out_len);
    if (!ok) {
        out_payload.clear();
    }
    return ok;
}

bool SrtpEngine::UnprotectRtpInPlace(uint8_t* packet_buf, size_t srtp_len, size_t& out_decrypted_len) {
    if (!enc_ctx_ || !mac_ctx_ || !packet_buf) return false;
    if (srtp_len < 12 + SRTP_AUTH_TAG_LEN) return false;

    size_t cipher_len = srtp_len - 12 - SRTP_AUTH_TAG_LEN;
    uint16_t seq = (static_cast<uint16_t>(packet_buf[2]) << 8) | packet_buf[3];
    uint32_t ssrc = (static_cast<uint32_t>(packet_buf[8]) << 24) |
                    (static_cast<uint32_t>(packet_buf[9]) << 16) |
                    (static_cast<uint32_t>(packet_buf[10]) << 8) |
                    packet_buf[11];

    uint64_t packet_index = 0;
    uint32_t est_roc = 0;
    if (!CheckAndProcessReplay(session_ctx_, seq, packet_index, est_roc)) {
        return false;
    }

    uint8_t expected_tag[SRTP_AUTH_TAG_LEN];
    ComputeHmacSha1Tag(mac_ctx_, packet_buf, 12, packet_buf + 12, cipher_len, est_roc, expected_tag);

    const uint8_t* rx_tag = packet_buf + 12 + cipher_len;
    if (CRYPTO_memcmp(rx_tag, expected_tag, SRTP_AUTH_TAG_LEN) != 0) {
        return false;
    }

    CommitReplay(session_ctx_, seq, packet_index, est_roc);

    if (cipher_len > 0) {
        ComputeAesIcmKeystream(enc_ctx_, session_ctx_.k_s, ssrc, packet_index, packet_buf + 12, cipher_len);
    }
    out_decrypted_len = cipher_len;
    return true;
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

void SrtpEngine::ComputeHmacSha1Tag(EVP_MAC_CTX* mac_ctx,
                                   const uint8_t* rtp_header,
                                   size_t header_len,
                                   const uint8_t* ciphertext,
                                   size_t cipher_len,
                                   uint32_t roc,
                                   uint8_t out_tag[SRTP_AUTH_TAG_LEN]) {
    if (!mac_ctx || !out_tag) return;

    // Reset HMAC state without re-allocating or re-deriving key
    EVP_MAC_init(mac_ctx, nullptr, 0, nullptr);

    // 1. Authenticated portion: RTP header
    if (rtp_header && header_len > 0) {
        EVP_MAC_update(mac_ctx, rtp_header, header_len);
    }

    // 2. Authenticated portion: Encrypted RTP payload
    if (ciphertext && cipher_len > 0) {
        EVP_MAC_update(mac_ctx, ciphertext, cipher_len);
    }

    // 3. ROC (4 bytes network byte order, RFC 3711 Section 4.2)
    uint32_t roc_be = htonl(roc);
    EVP_MAC_update(mac_ctx, reinterpret_cast<const uint8_t*>(&roc_be), sizeof(roc_be));

    uint8_t full_digest[20];
    size_t digest_len = 0;
    EVP_MAC_final(mac_ctx, full_digest, &digest_len, sizeof(full_digest));

    // Truncate to first 10 bytes (80-bit auth tag)
    std::memcpy(out_tag, full_digest, SRTP_AUTH_TAG_LEN);
}

bool SrtpEngine::CheckAndProcessReplay(SrtpSessionContext& ctx, uint16_t seq, uint64_t& out_index, uint32_t& out_roc) {
    if (!ctx.initialized) {
        out_roc = 0;
        out_index = seq;
        return true;
    }

    // RFC 3711 Appendix A: Pseudocode for index determination
    uint32_t v = ctx.roc;
    uint16_t s_l = ctx.s_l;

    if (s_l < 32768) {
        if (static_cast<int32_t>(seq) - static_cast<int32_t>(s_l) > 32768) {
            v = (ctx.roc > 0) ? (ctx.roc - 1) : 0;
        } else {
            v = ctx.roc;
        }
    } else {
        if (static_cast<int32_t>(s_l) - 32768 > static_cast<int32_t>(seq)) {
            v = ctx.roc + 1;
        } else {
            v = ctx.roc;
        }
    }

    uint64_t index = (static_cast<uint64_t>(v) << 16) | seq;
    uint64_t highest_index = (static_cast<uint64_t>(ctx.roc) << 16) | ctx.s_l;
    int64_t diff = static_cast<int64_t>(index) - static_cast<int64_t>(highest_index);

    if (diff > 0) {
        // Ahead of highest packet received so far
        out_index = index;
        out_roc = v;
        return true;
    }

    // Behind highest received packet
    if (-diff >= static_cast<int64_t>(SRTP_REPLAY_WINDOW_SIZE)) {
        // Packet lags by >= 64, reject
        return false;
    }

    uint64_t bit_mask = 1ULL << (-diff);
    if ((ctx.replay_bitmap & bit_mask) != 0) {
        // Packet already seen (replay attack)
        return false;
    }

    out_index = index;
    out_roc = v;
    return true;
}

void SrtpEngine::CommitReplay(SrtpSessionContext& ctx, uint16_t seq, uint64_t index, uint32_t roc) {
    if (!ctx.initialized) {
        ctx.initialized = true;
        ctx.s_l = seq;
        ctx.roc = 0;
        ctx.replay_bitmap = 1ULL;
        return;
    }

    uint64_t highest_index = (static_cast<uint64_t>(ctx.roc) << 16) | ctx.s_l;
    int64_t diff = static_cast<int64_t>(index) - static_cast<int64_t>(highest_index);

    if (diff > 0) {
        if (diff < static_cast<int64_t>(SRTP_REPLAY_WINDOW_SIZE)) {
            ctx.replay_bitmap = (ctx.replay_bitmap << diff) | 1ULL;
        } else {
            ctx.replay_bitmap = 1ULL;
        }
        ctx.s_l = seq;
        ctx.roc = roc;
    } else {
        uint64_t bit_mask = 1ULL << (-diff);
        ctx.replay_bitmap |= bit_mask;
    }
}

} // namespace samurai::telecom::sip_rtp
