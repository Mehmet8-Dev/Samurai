#pragma once

#include <string>
#include <string_view>
#include <cstdint>

namespace ddos_samurai::telecom::sip_rtp {

/**
 * @brief Computes MD5 hash and returns a 32-character lowercase hex string.
 */
std::string ComputeMd5Hex(std::string_view data);

/**
 * @brief Computes SHA-256 hash and returns a 64-character lowercase hex string.
 */
std::string ComputeSha256Hex(std::string_view data);

} // namespace ddos_samurai::telecom::sip_rtp
