#include "sip_digest_auth.hpp"

#include <openssl/evp.h>
#include <algorithm>
#include <cctype>
#include <sstream>
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

inline std::string Trim(std::string_view sv) {
    size_t start = 0;
    while (start < sv.size() && std::isspace(static_cast<unsigned char>(sv[start]))) {
        start++;
    }
    size_t end = sv.size();
    while (end > start && std::isspace(static_cast<unsigned char>(sv[end - 1]))) {
        end--;
    }
    return std::string(sv.substr(start, end - start));
}

inline std::string ToLower(std::string_view sv) {
    std::string res;
    res.reserve(sv.size());
    for (char c : sv) {
        res.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return res;
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

bool ParseDigestChallenge(std::string_view header_val, DigestChallenge& out_challenge) {
    std::string trimmed = Trim(header_val);
    if (trimmed.empty()) return false;

    // Must start with "Digest" (case-insensitive)
    if (trimmed.size() < 6 || ToLower(trimmed.substr(0, 6)) != "digest") {
        return false;
    }

    // Skip "Digest" and whitespace
    size_t pos = 6;
    while (pos < trimmed.size() && std::isspace(static_cast<unsigned char>(trimmed[pos]))) {
        pos++;
    }

    out_challenge = DigestChallenge{};

    while (pos < trimmed.size()) {
        // Find parameter key (up to '=')
        size_t eq_pos = trimmed.find('=', pos);
        if (eq_pos == std::string::npos) break;

        std::string key = ToLower(Trim(trimmed.substr(pos, eq_pos - pos)));
        pos = eq_pos + 1;

        // Skip leading whitespace after '='
        while (pos < trimmed.size() && std::isspace(static_cast<unsigned char>(trimmed[pos]))) {
            pos++;
        }

        std::string val;
        if (pos < trimmed.size() && trimmed[pos] == '"') {
            // Quoted string
            pos++; // skip initial quote
            size_t val_start = pos;
            while (pos < trimmed.size() && trimmed[pos] != '"') {
                if (trimmed[pos] == '\\' && pos + 1 < trimmed.size()) {
                    pos += 2; // escaped character
                } else {
                    pos++;
                }
            }
            val = trimmed.substr(val_start, pos - val_start);
            if (pos < trimmed.size() && trimmed[pos] == '"') {
                pos++; // skip closing quote
            }
        } else {
            // Unquoted token (up to ',' or end)
            size_t val_start = pos;
            while (pos < trimmed.size() && trimmed[pos] != ',' && !std::isspace(static_cast<unsigned char>(trimmed[pos]))) {
                pos++;
            }
            val = trimmed.substr(val_start, pos - val_start);
        }

        // Store into appropriate challenge field
        if (key == "realm") {
            out_challenge.realm = val;
        } else if (key == "nonce") {
            out_challenge.nonce = val;
        } else if (key == "opaque") {
            out_challenge.opaque = val;
        } else if (key == "algorithm") {
            out_challenge.algorithm = val;
        } else if (key == "qop") {
            // If comma-separated, prioritize "auth"
            if (val.find("auth") != std::string::npos) {
                out_challenge.qop = "auth";
            } else {
                out_challenge.qop = val;
            }
        } else if (key == "domain") {
            out_challenge.domain = val;
        } else if (key == "stale") {
            out_challenge.stale = (ToLower(val) == "true");
        }

        // Advance to next parameter (skip ',' and whitespace)
        while (pos < trimmed.size() && (trimmed[pos] == ',' || std::isspace(static_cast<unsigned char>(trimmed[pos])))) {
            pos++;
        }
    }

    return !out_challenge.realm.empty() && !out_challenge.nonce.empty();
}

bool ExtractDigestChallengeFromSipMessage(const std::string& sip_msg, DigestChallenge& out_challenge, bool& is_proxy) {
    std::istringstream stream(sip_msg);
    std::string line;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        std::string lower_line = ToLower(line);
        static constexpr std::string_view kAuthHeader = "www-authenticate:";
        static constexpr std::string_view kProxyHeader = "proxy-authenticate:";

        if (lower_line.find(kAuthHeader) == 0) {
            std::string_view val = std::string_view(line).substr(kAuthHeader.size());
            if (ParseDigestChallenge(val, out_challenge)) {
                is_proxy = false;
                return true;
            }
        } else if (lower_line.find(kProxyHeader) == 0) {
            std::string_view val = std::string_view(line).substr(kProxyHeader.size());
            if (ParseDigestChallenge(val, out_challenge)) {
                is_proxy = true;
                return true;
            }
        }
    }

    return false;
}

} // namespace ddos_samurai::telecom::sip_rtp
