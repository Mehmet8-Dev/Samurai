#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <array>

// Forward declaration of OpenSSL context types
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_mac_st EVP_MAC;
typedef struct evp_mac_ctx_st EVP_MAC_CTX;

namespace ddos_samurai::telecom::sip_rtp {

constexpr size_t SRTP_MASTER_KEY_LEN       = 16;  // 128-bit master key
constexpr size_t SRTP_MASTER_SALT_LEN      = 14;  // 112-bit master salt
constexpr size_t SRTP_SESSION_ENC_KEY_LEN  = 16;  // 128-bit session encryption key
constexpr size_t SRTP_SESSION_AUTH_KEY_LEN = 20;  // 160-bit session authentication key
constexpr size_t SRTP_SESSION_SALT_LEN     = 14;  // 112-bit session salting key
constexpr size_t SRTP_AUTH_TAG_LEN         = 10;  // 80-bit / 10-byte truncated auth tag
constexpr size_t SRTP_REPLAY_WINDOW_SIZE   = 64;  // 64-packet sliding window (RFC 3711 §3.3.2)

/**
 * @brief Master key configuration for SRTP (RFC 3711 Section 4.3).
 * Cache-line aligned (64 bytes).
 */
struct alignas(64) SrtpKeyConfig {
    uint8_t master_key[SRTP_MASTER_KEY_LEN]{0};
    uint8_t master_salt[SRTP_MASTER_SALT_LEN]{0};
    uint8_t pad[34]{0}; // Aligns struct to exactly 64 bytes
};
static_assert(sizeof(SrtpKeyConfig) == 64, "SrtpKeyConfig must be exactly 64 bytes (1 cache line)");

/**
 * @brief SRTP Session state context (ROC, s_l, sliding replay window bitmap, derived session keys).
 * Cache-line aligned to 128 bytes (2 cache lines).
 */
struct alignas(64) SrtpSessionContext {
    uint32_t roc{0};                                    // Rollover counter (32-bit)
    uint16_t s_l{0};                                    // Highest received RTP sequence number
    bool     initialized{false};                        // First packet flag
    uint8_t  pad0[1]{0};
    uint64_t replay_bitmap{0};                          // 64-bit sliding replay window
    uint8_t  k_e[SRTP_SESSION_ENC_KEY_LEN]{0};          // Derived encryption key (128-bit)
    uint8_t  k_a[SRTP_SESSION_AUTH_KEY_LEN]{0};         // Derived authentication key (160-bit)
    uint8_t  k_s[SRTP_SESSION_SALT_LEN]{0};             // Derived salt key (112-bit)
    uint8_t  pad1[62]{0};                               // Pads struct to 128 bytes
};
static_assert(sizeof(SrtpSessionContext) == 128, "SrtpSessionContext must be exactly 128 bytes (2 cache lines)");

/**
 * @brief High-performance RFC 3711 Secure Real-time Transport Protocol (SRTP) Engine.
 * Features:
 * - RFC 3711 AES-128-CM PRF Key Derivation Function (KDF)
 * - AES-128-ICM Payload Keystream Encryption / Decryption
 * - HMAC-SHA1-80 Authentication Tag Generation and Verification
 * - 64-packet Sliding Replay Window Protection
 * - Zero heap allocation during fastpath packet loops
 */
class SrtpEngine {
public:
    SrtpEngine();
    ~SrtpEngine();

    SrtpEngine(const SrtpEngine&) = delete;
    SrtpEngine& operator=(const SrtpEngine&) = delete;

    SrtpEngine(SrtpEngine&& other) noexcept;
    SrtpEngine& operator=(SrtpEngine&& other) noexcept;

    /**
     * @brief Initialize session context and derive keys using RFC 3711 AES-128-CM PRF KDF.
     */
    bool InitKeys(const SrtpKeyConfig& key_cfg);

    /**
     * @brief Encrypt voice payload using AES-128-ICM and append 10-byte HMAC-SHA1-80 auth tag.
     * Zero heap allocation in packet processing.
     *
     * @param rtp_header Plaintext RTP header (12 bytes).
     * @param payload Plaintext audio payload.
     * @param payload_len Length of payload in bytes.
     * @param out_srtp_pkt Output buffer containing: RTP Header (12B) + Encrypted Payload + Auth Tag (10B).
     * @return true on success.
     */
    bool ProtectRtp(const uint8_t* rtp_header,
                    const uint8_t* payload,
                    size_t payload_len,
                    std::vector<uint8_t>& out_srtp_pkt);

    /**
     * @brief Zero-allocation in-place protect for transmission.
     */
    bool ProtectRtpInPlace(uint8_t* packet_buf, size_t rtp_header_len, size_t payload_len, size_t max_buf_len, size_t& out_total_len);

    /**
     * @brief Verify auth tag, check replay window, and decrypt SRTP payload.
     *
     * @param srtp_pkt Full received SRTP packet (RTP Header + Encrypted Payload + Auth Tag).
     * @param srtp_len Total length of srtp_pkt (must be >= 12 + 10 = 22 bytes).
     * @param out_payload Decrypted audio payload.
     * @return true if authentic, not replayed, and decrypted. false if replay or authentication fails.
     */
    bool UnprotectRtp(const uint8_t* srtp_pkt,
                      size_t srtp_len,
                      std::vector<uint8_t>& out_payload);

    bool UnprotectRtpBuffer(const uint8_t* srtp_pkt,
                            size_t srtp_len,
                            uint8_t* out_payload,
                            size_t max_out_len,
                            size_t& out_len);

    bool UnprotectRtpInPlace(uint8_t* packet_buf, size_t srtp_len, size_t& out_decrypted_len);

    // KDF and Cryptographic primitives (exposed for explicit RFC test verification)
    static bool DeriveSessionKeys(const SrtpKeyConfig& key_cfg,
                                  uint8_t out_k_e[SRTP_SESSION_ENC_KEY_LEN],
                                  uint8_t out_k_a[SRTP_SESSION_AUTH_KEY_LEN],
                                  uint8_t out_k_s[SRTP_SESSION_SALT_LEN]);

    static void ComputeAesIcmKeystream(EVP_CIPHER_CTX* aes_ctx,
                                       const uint8_t salt[SRTP_SESSION_SALT_LEN],
                                       uint32_t ssrc,
                                       uint64_t packet_index,
                                       uint8_t* data,
                                       size_t len);

    static void ComputeHmacSha1Tag(EVP_MAC_CTX* mac_ctx,
                                   const uint8_t* rtp_header,
                                   size_t header_len,
                                   const uint8_t* ciphertext,
                                   size_t cipher_len,
                                   uint32_t roc,
                                   uint8_t out_tag[SRTP_AUTH_TAG_LEN]);

    // Replay window helpers
    static bool CheckAndProcessReplay(SrtpSessionContext& ctx, uint16_t seq, uint64_t& out_index, uint32_t& out_roc);
    static void CommitReplay(SrtpSessionContext& ctx, uint16_t seq, uint64_t index, uint32_t roc);

    const SrtpSessionContext& session_ctx() const noexcept { return session_ctx_; }
    SrtpSessionContext& session_ctx() noexcept { return session_ctx_; }

private:
    SrtpSessionContext session_ctx_{};
    EVP_CIPHER_CTX* enc_ctx_{nullptr};
    EVP_MAC* mac_fetch_{nullptr};
    EVP_MAC_CTX* mac_ctx_{nullptr};

    void CleanUpContexts();
};

} // namespace ddos_samurai::telecom::sip_rtp
