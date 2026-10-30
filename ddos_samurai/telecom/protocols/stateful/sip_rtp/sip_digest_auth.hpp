#pragma once

#include <string>
#include <string_view>
#include <cstdint>

namespace ddos_samurai::telecom::sip_rtp {

/**
 * @brief Parsed Digest challenge parameters (from WWW-Authenticate or Proxy-Authenticate).
 */
struct DigestChallenge {
    std::string realm;
    std::string nonce;
    std::string opaque;
    std::string algorithm{"MD5"};
    std::string qop; // e.g. "auth"
    std::string domain;
    bool stale{false};
};

/**
 * @brief Computes MD5 hash and returns a 32-character lowercase hex string.
 */
std::string ComputeMd5Hex(std::string_view data);

/**
 * @brief Computes SHA-256 hash and returns a 64-character lowercase hex string.
 */
std::string ComputeSha256Hex(std::string_view data);

/**
 * @brief Parses the value of a WWW-Authenticate or Proxy-Authenticate header.
 *
 * Example input:
 * Digest realm="samurai.local", nonce="4f8a9b1c", opaque="5ccc06", algorithm=MD5, qop="auth"
 *
 * @param header_val The header value string following "WWW-Authenticate:" or "Proxy-Authenticate:".
 * @param out_challenge The output challenge structure.
 * @return true if Digest scheme was found and required fields (realm, nonce) were parsed.
 */
bool ParseDigestChallenge(std::string_view header_val, DigestChallenge& out_challenge);

/**
 * @brief Searches a complete SIP message for 401 WWW-Authenticate or 407 Proxy-Authenticate headers.
 *
 * @param sip_msg Full SIP response message string.
 * @param out_challenge Output challenge structure.
 * @param is_proxy Output flag set to true if from 407 Proxy-Authenticate, false if 401 WWW-Authenticate.
 * @return true if a challenge header was found and successfully parsed.
 */
bool ExtractDigestChallengeFromSipMessage(const std::string& sip_msg, DigestChallenge& out_challenge, bool& is_proxy);

} // namespace ddos_samurai::telecom::sip_rtp
