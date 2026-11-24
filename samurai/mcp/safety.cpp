#include "safety.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace samurai::mcp {

namespace {

std::vector<std::string> SplitCsvEnv(const char* env_name) {
  std::vector<std::string> out;
  const char* raw = std::getenv(env_name);
  if (!raw || raw[0] == '\0') return out;
  std::stringstream ss(raw);
  std::string item;
  while (std::getline(ss, item, ',')) {
    std::size_t a = 0;
    while (a < item.size() && std::isspace(static_cast<unsigned char>(item[a]))) ++a;
    std::size_t b = item.size();
    while (b > a && std::isspace(static_cast<unsigned char>(item[b - 1]))) --b;
    if (b > a) out.push_back(item.substr(a, b - a));
  }
  return out;
}

}  // namespace

SafetyConfig LoadSafetyConfigFromEnv() {
  SafetyConfig cfg;
  cfg.allow_targets = SplitCsvEnv("SAMURAI_MCP_ALLOW_TARGETS");
  cfg.deny_targets = SplitCsvEnv("SAMURAI_MCP_DENY_TARGETS");
  if (const char* max_c = std::getenv("SAMURAI_MCP_MAX_COUNT")) {
    char* end = nullptr;
    const unsigned long long v = std::strtoull(max_c, &end, 10);
    if (end != max_c && *end == '\0' && v > 0) {
      cfg.max_packet_count = static_cast<std::uint64_t>(v);
    }
  }
  return cfg;
}

samurai::core::TargetSafetyResult ValidateMcpTarget(const std::string& target_ip,
                                                    const SafetyConfig& cfg) {
  // Defense-in-depth: allow_public is ALWAYS false in MCP mode.
  return samurai::core::ValidateTargetSafety(
      target_ip, cfg.allow_targets, /*allow_public=*/false, cfg.deny_targets);
}

samurai::core::TargetSafetyResult ResolveMcpTarget(const std::string& target_or_alias,
                                                   const SafetyConfig& cfg,
                                                   std::string& resolved_ip_out) {
  std::string low = target_or_alias;
  for (char& c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

  if (low == "host.docker.internal") {
    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    const int gai = ::getaddrinfo("host.docker.internal", nullptr, &hints, &res);
    if (gai != 0 || res == nullptr) {
      if (res) ::freeaddrinfo(res);
      return {false, "Unable to resolve host.docker.internal to IPv4 (pass explicit private IPv4 or --add-host host.docker.internal:host-gateway)."};
    }
    char buf[INET_ADDRSTRLEN] = {0};
    const auto* sin = reinterpret_cast<const struct sockaddr_in*>(res->ai_addr);
    const char* ok = ::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
    ::freeaddrinfo(res);
    if (!ok || buf[0] == '\0') {
      return {false, "Failed to format resolved host.docker.internal IPv4 address."};
    }
    resolved_ip_out = std::string(buf);
    return ValidateMcpTarget(resolved_ip_out, cfg);
  }

  resolved_ip_out = target_or_alias;
  return ValidateMcpTarget(resolved_ip_out, cfg);
}

const std::vector<std::string>& AllowedWorkers() {
  static const std::vector<std::string> kWorkers = {
      "cpu", "afpacket", "afxdp", "dpdk", "gpu",
      "doca", "l7", "scenario", "telco", "defense",
  };
  return kWorkers;
}

const std::vector<std::string>& AllowedProtocols() {
  static const std::vector<std::string> kProtocols = {
      "udp", "tcp", "http1", "http2", "quic", "dns",
      "pppoe", "dhcp", "gtpu", "bfd", "pfcp", "sctp", "diameter", "sip-rtp",
  };
  return kProtocols;
}

bool IsAllowedWorker(const std::string& worker) {
  const auto& w = AllowedWorkers();
  return std::find(w.begin(), w.end(), worker) != w.end();
}

bool IsAllowedProtocol(const std::string& proto) {
  const auto& p = AllowedProtocols();
  return std::find(p.begin(), p.end(), proto) != p.end();
}

}  // namespace samurai::mcp
