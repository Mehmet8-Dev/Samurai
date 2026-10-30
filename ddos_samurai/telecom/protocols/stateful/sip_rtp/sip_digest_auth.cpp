#include "sip_digest_auth.hpp"

#include <openssl/evp.h>
#include <vector>

namespace ddos_samurai::telecom::sip_rtp {

namespace {

inline std::string ToHexLower(const uint8_t* data, size_t len) {
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string hex;
    hex.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        hex[2 * i]     = hex_chars[(data[i] >> 4) & 0x0F];
        hex[2 * i + 1] = hex_chars[data[i] & 0x0F];
    }
    return hex;
}

} // namespace

std::string ComputeMd5Hex(std::string_view data) {
    uint8_t md[16];
    size_t md_len = 0;
    if (EVP_Q_digest(nullptr, "MD5", nullptr, data.data(), data.size(), md, &md_len) != 1) {
        return "";
    }
    return ToHexLower(md, md_len);
}

std::string ComputeSha256Hex(std::string_view data) {
    uint8_t md[32];
    size_t md_len = 0;
    if (EVP_Q_digest(nullptr, "SHA256", nullptr, data.data(), data.size(), md, &md_len) != 1) {
        return "";
    }
    return ToHexLower(md, md_len);
}

} // namespace ddos_samurai::telecom::sip_rtp
