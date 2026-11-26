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

std::string TrimCopy(const std::string& s) {
  std::size_t a = 0;
  while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  std::size_t b = s.size();
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return s.substr(a, b - a);
}

std::string LowerCopy(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::string NormalizeHostPattern(std::string s) {
  s = LowerCopy(TrimCopy(s));
  while (!s.empty() && s.back() == '.') s.pop_back();
  return s;
}

bool IsIpv4Literal(const std::string& s) {
  in_addr addr{};
  return ::inet_pton(AF_INET, s.c_str(), &addr) == 1;
}

bool IsIpv4OrCidr(const std::string& entry) {
  const std::string t = TrimCopy(entry);
  if (IsIpv4Literal(t)) return true;
  const auto slash = t.find('/');
  if (slash == std::string::npos) return false;
  const std::string ip = t.substr(0, slash);
  const std::string pref = t.substr(slash + 1);
  if (!IsIpv4Literal(ip) || pref.empty()) return false;
  char* end = nullptr;
  const long p = std::strtol(pref.c_str(), &end, 10);
  return end != pref.c_str() && *end == '\0' && p >= 0 && p <= 32;
}

bool IsWildcardBypassEntry(const std::string& entry) {
  const std::string t = LowerCopy(TrimCopy(entry));
  if (t == "*" || t == "*.*" || t == "all" || t == "any") return true;
  const auto slash = t.find('/');
  if (slash != std::string::npos) {
    const std::string pref = t.substr(slash + 1);
    char* end = nullptr;
    const long p = std::strtol(pref.c_str(), &end, 10);
    if (end != pref.c_str() && *end == '\0' && p == 0) return true;
  }
  return false;
}

bool MatchHostPattern(const std::string& host_norm, const std::string& pattern_raw) {
  const std::string pat = NormalizeHostPattern(pattern_raw);
  if (pat.empty() || IsIpv4OrCidr(pat)) return false;
  if (host_norm == pat) return true;
  if (pat.rfind("*.", 0) == 0 && pat.size() > 2) {
    const std::string suffix = pat.substr(1);  // ".example.com"
    if (host_norm.size() > suffix.size() &&
        host_norm.compare(host_norm.size() - suffix.size(), suffix.size(), suffix) == 0) {
      return true;
    }
  }
  return false;
}

bool ResolveIpv4Host(const std::string& hostname, std::string& resolved_ip_out, std::string& err_out) {
  struct addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo* res = nullptr;
  const int gai = ::getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
  if (gai != 0 || res == nullptr) {
    if (res) ::freeaddrinfo(res);
    err_out = ::gai_strerror(gai);
    return false;
  }
  char buf[INET_ADDRSTRLEN] = {0};
  const auto* sin = reinterpret_cast<const struct sockaddr_in*>(res->ai_addr);
  const char* ok = ::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
  ::freeaddrinfo(res);
  if (!ok || buf[0] == '\0') {
    err_out = "inet_ntop_failed";
    return false;
  }
  resolved_ip_out = std::string(buf);
  return true;
}

std::vector<std::string> SplitCsv(const std::string& raw) {
  std::vector<std::string> out;
  std::stringstream ss(raw);
  std::string item;
  while (std::getline(ss, item, ',')) {
    const std::string trimmed = TrimCopy(item);
    if (!trimmed.empty()) out.push_back(trimmed);
  }
  return out;
}

std::vector<std::string> SplitCsvEnv(const char* env_name) {
  const char* raw = std::getenv(env_name);
  if (!raw || raw[0] == '\0') return {};
  return SplitCsv(raw);
}

}  // namespace

SafetyConfig LoadSafetyConfigFromEnv() {
  SafetyConfig cfg;
  cfg.allow_targets = SplitCsvEnv("SAMURAI_MCP_ALLOW_TARGETS");
  cfg.deny_targets = SplitCsvEnv("SAMURAI_MCP_DENY_TARGETS");
  if (const char* max_c = std::getenv("SAMURAI_MCP_MAX_COUNT")) {
    char* end = nullptr;
    const unsigned long long v = std::strtoull(max_c, &end, 10);
    if (end != max_c && *end == '\0') {
      cfg.max_packet_count = static_cast<std::uint64_t>(v);  // 0 = unlimited
    }
  }
  if (const char* max_t = std::getenv("SAMURAI_MCP_MAX_TIMEOUT_S")) {
    char* end = nullptr;
    const long t = std::strtol(max_t, &end, 10);
    if (end != max_t && *end == '\0' && t >= 5) {
      cfg.max_timeout_s = static_cast<int>(std::min<long>(t, 604800L));  // up to 7 days
    }
  }
  return cfg;
}

SafetyConfig EffectiveSafetyConfig(const samurai::core::json::Value& args,
                                   const SafetyConfig& base,
                                   std::string* err_out) {
  SafetyConfig eff = base;
  if (!args.is_object()) return eff;

  auto push_entry = [&](const std::string& raw) {
    for (const auto& item : SplitCsv(raw)) {
      if (IsWildcardBypassEntry(item)) {
        if (err_out && err_out->empty()) {
          *err_out = "Wildcard allow_target ('" + item +
                     "') is rejected; specify explicit IPv4, CIDR (prefix >= 1), or domain/hostname.";
        }
        continue;
      }
      if (std::find(eff.allow_targets.begin(), eff.allow_targets.end(), item) == eff.allow_targets.end()) {
        eff.allow_targets.push_back(item);
      }
    }
  };

  if (const auto* single = args.find("allow_target"); single && single->is_string() && !single->as_string().empty()) {
    push_entry(single->as_string());
  }
  if (const auto* multi = args.find("allow_targets")) {
    if (multi->is_string() && !multi->as_string().empty()) {
      push_entry(multi->as_string());
    } else if (multi->is_array()) {
      for (const auto& el : multi->elements()) {
        if (el.is_string() && !el.as_string().empty()) {
          push_entry(el.as_string());
        }
      }
    }
  }
  return eff;
}

bool ValidateMcpPacketCount(std::int64_t count,
                            const SafetyConfig& cfg,
                            std::string* err_out) {
  constexpr std::uint64_t kUint32WireMax = 4294967295ULL;
  if (count < 1) {
    if (err_out) *err_out = "count must be >= 1";
    return false;
  }
  const std::uint64_t ucount = static_cast<std::uint64_t>(count);
  const std::uint64_t effective_max =
      (cfg.max_packet_count == 0) ? kUint32WireMax : std::min(cfg.max_packet_count, kUint32WireMax);
  if (ucount > effective_max) {
    if (err_out) *err_out = "count must be between 1 and " + std::to_string(effective_max);
    return false;
  }
  return true;
}

void AppendSafetyCliArgs(const SafetyConfig& cfg,
                         std::vector<std::string>& cmd,
                         const std::string& resolved_target_ip) {
  bool resolved_covered = false;
  for (const auto& allow_entry : cfg.allow_targets) {
    if (IsIpv4OrCidr(allow_entry)) {
      const std::string t = TrimCopy(allow_entry);
      cmd.push_back("--allow-target");
      cmd.push_back(t);
      if (t == resolved_target_ip) resolved_covered = true;
    }
  }
  if (!resolved_target_ip.empty() && !resolved_covered && !cfg.allow_targets.empty() &&
      IsIpv4Literal(resolved_target_ip)) {
    cmd.push_back("--allow-target");
    cmd.push_back(resolved_target_ip);
  }
  for (const auto& deny_entry : cfg.deny_targets) {
    if (IsIpv4OrCidr(deny_entry)) {
      cmd.push_back("--deny-target");
      cmd.push_back(TrimCopy(deny_entry));
    }
  }
}

samurai::core::TargetSafetyResult ValidateMcpTarget(const std::string& target_ip,
                                                    const SafetyConfig& cfg) {
  // Defense-in-depth: allow_public is ALWAYS false in MCP mode unless explicitly
  // listed in cfg.allow_targets (env or per-call allow_target/allow_targets).
  return samurai::core::ValidateTargetSafety(
      target_ip, cfg.allow_targets, /*allow_public=*/false, cfg.deny_targets);
}

samurai::core::TargetSafetyResult ResolveMcpTarget(const std::string& target_or_alias,
                                                   const SafetyConfig& cfg,
                                                   std::string& resolved_ip_out) {
  const std::string trimmed = TrimCopy(target_or_alias);
  const std::string norm = NormalizeHostPattern(trimmed);

  if (IsIpv4Literal(trimmed)) {
    resolved_ip_out = trimmed;
    return ValidateMcpTarget(resolved_ip_out, cfg);
  }

  if (norm == "host.docker.internal") {
    std::string gai_err;
    if (!ResolveIpv4Host("host.docker.internal", resolved_ip_out, gai_err)) {
      return {false, "Unable to resolve host.docker.internal to IPv4 (pass explicit private IPv4 or --add-host host.docker.internal:host-gateway)."};
    }
    return ValidateMcpTarget(resolved_ip_out, cfg);
  }

  // Denylist always wins, including hostname patterns.
  for (const auto& deny_pat : cfg.deny_targets) {
    if (MatchHostPattern(norm, deny_pat)) {
      return {false, "Target hostname blocked by denylist: " + trimmed};
    }
  }

  // Only resolve external domains via DNS when explicitly permitted by allow_targets.
  bool host_allowed = false;
  for (const auto& allow_pat : cfg.allow_targets) {
    if (MatchHostPattern(norm, allow_pat)) {
      host_allowed = true;
      break;
    }
  }
  if (host_allowed) {
    std::string gai_err;
    if (!ResolveIpv4Host(trimmed, resolved_ip_out, gai_err)) {
      return {false, "Failed to resolve authorized allow_target hostname '" + trimmed + "' to IPv4: " + gai_err};
    }
    SafetyConfig tmp_cfg = cfg;
    tmp_cfg.allow_targets.push_back(resolved_ip_out);
    return ValidateMcpTarget(resolved_ip_out, tmp_cfg);
  }

  resolved_ip_out = trimmed;
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
