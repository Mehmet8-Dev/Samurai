#include "target_safety.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <arpa/inet.h>

namespace samurai::core {

namespace {

// Parse a dotted-quad IPv4 into a host-order u32. std::nullopt on failure.
std::optional<std::uint32_t> ParseIpv4(const std::string& s) {
  in_addr addr{};
  if (inet_pton(AF_INET, s.c_str(), &addr) != 1) return std::nullopt;
  return ntohl(addr.s_addr);
}

struct Cidr {
  std::uint32_t network;  // host order, masked
  std::uint32_t mask;     // host order
};

// Parse "a.b.c.d/n" (or a bare address, treated as /32) into a masked network.
std::optional<Cidr> ParseCidr(const std::string& s) {
  const auto slash = s.find('/');
  const std::string addr_part = slash == std::string::npos ? s : s.substr(0, slash);
  const auto ip = ParseIpv4(addr_part);
  if (!ip) return std::nullopt;

  int prefix = 32;
  if (slash != std::string::npos) {
    const std::string bits = s.substr(slash + 1);
    if (bits.empty()) return std::nullopt;
    prefix = 0;
    for (char c : bits) {
      if (c < '0' || c > '9') return std::nullopt;
      prefix = prefix * 10 + (c - '0');
      if (prefix > 32) return std::nullopt;
    }
  }

  const std::uint32_t mask = prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));
  return Cidr{*ip & mask, mask};
}

bool InCidr(std::uint32_t ip, const Cidr& c) { return (ip & c.mask) == c.network; }

// Private/loopback policy: RFC1918 + loopback + link-local + CGNAT.
bool IsPrivateOrLoopback(std::uint32_t ip) {
  static const Cidr kRanges[] = {
      {0x0A000000u, 0xFF000000u},  // 10.0.0.0/8
      {0x7F000000u, 0xFF000000u},  // 127.0.0.0/8   (loopback)
      {0xAC100000u, 0xFFF00000u},  // 172.16.0.0/12
      {0xC0A80000u, 0xFFFF0000u},  // 192.168.0.0/16
      {0xA9FE0000u, 0xFFFF0000u},  // 169.254.0.0/16 (link-local)
      {0x64400000u, 0xFFC00000u},  // 100.64.0.0/10  (CGNAT)
  };
  for (const auto& r : kRanges) {
    if (InCidr(ip, r)) return true;
  }
  return false;
}

bool IsMulticast(std::uint32_t ip) { return (ip & 0xF0000000u) == 0xE0000000u; }  // 224.0.0.0/4

}  // namespace

TargetSafetyResult ValidateTargetSafety(const std::string& target_ip,
                                        const std::vector<std::string>& allow_targets,
                                        bool allow_public,
                                        const std::vector<std::string>& deny_targets) {
  // IPv6 addresses parse as non-IPv4 here; distinguish "contains ':'" for clarity.
  const auto ip = ParseIpv4(target_ip);
  if (!ip) {
    if (target_ip.find(':') != std::string::npos) {
      return {false, "Only IPv4 targets are currently supported."};
    }
    return {false, "Invalid target IP: '" + target_ip + "'"};
  }

  if (IsMulticast(*ip) || *ip == 0u) {
    return {false, "Invalid/unsafe target IP (multicast or unspecified)."};
  }

  // Hard deny policy: blocked targets always win. Must run BEFORE allowlist
  // matching so an allowlist match cannot bypass the denylist.
  for (const auto& entry : deny_targets) {
    if (entry.empty()) continue;
    const auto cidr = ParseCidr(entry);
    if (!cidr) {
      return {false, "Invalid denylist entry: '" + entry + "'"};
    }
    if (InCidr(*ip, *cidr)) {
      return {false, "Target IP is blocked by global denylist: " + entry};
    }
  }

  if (!allow_targets.empty()) {
    for (const auto& entry : allow_targets) {
      const auto cidr = ParseCidr(entry);
      if (!cidr) {
        return {false, "Invalid allowlist entry: '" + entry + "'"};
      }
      if (InCidr(*ip, *cidr)) {
        return {true, "ok"};
      }
    }
    return {false, "Target IP is not in allowlist. (Allow with --allow-target)"};
  }

  if (IsPrivateOrLoopback(*ip)) {
    return {true, "ok"};
  }
  if (allow_public) {
    return {true, "ok"};
  }
  return {false, "Public targets are blocked by default. (Override with --allow-public-target)"};
}

}  // namespace samurai::core
