#include "safety.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
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
