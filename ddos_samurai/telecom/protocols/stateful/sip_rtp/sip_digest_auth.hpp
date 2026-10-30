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
 * @brief Credentials to format an Authorization or Proxy-Authorization header.
 */
struct DigestCredentials {
    std::string username;
    std::string realm;
    std::string nonce;
    std::string uri;
    std::string response;
    std::string algorithm{"MD5"};
    std::string cnonce;
    std::string opaque;
    std::string qop;
    std::string nc{"00000001"};
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

/**
 * @brief Computes RFC 2617 / RFC 3261 digest response hex string.
 *
 * HA1 = Hash(username:realm:password)
 * HA2 = Hash(method:digest_uri)
 * Response = Hash(HA1:nonce:nc:cnonce:qop:HA2) or Hash(HA1:nonce:HA2)
 */
std::string CalculateDigestResponse(
    const std::string& username,
    const std::string& realm,
    const std::string& password,
    const std::string& method,
    const std::string& digest_uri,
    const std::string& nonce,
    const std::string& nc = "00000001",
    const std::string& cnonce = "0a4f113b",
    const std::string& qop = "auth",
    const std::string& algorithm = "MD5"
);

/**
 * @brief Builds the Authorization or Proxy-Authorization header string.
 *
 * @param creds Full credentials and digest response.
 * @param is_proxy If true, produces "Proxy-Authorization: ...", else "Authorization: ...".
 * @return Formatted header line ending with "\r\n".
 */
std::string BuildAuthorizationHeader(const DigestCredentials& creds, bool is_proxy = false);

} // namespace ddos_samurai::telecom::sip_rtp
