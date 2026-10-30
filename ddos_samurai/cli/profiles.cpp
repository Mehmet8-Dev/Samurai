#include "profiles.hpp"

#include <cstdint>
#include <cstdio>
#include <string>

namespace samurai::cli {

namespace {

// One corporate test profile. Sentinel values (nullptr / negative) mean "leave
// the option at its current/default value", restricted to fields the wire
// JobEnvelopeV1 carries.
struct ProfileDef {
  const char* name;
  const char* description;
  const char* attack_vector;  // nullptr = unset
  const char* protocol;       // nullptr = unset
  int port;                   // < 0 = unset
  long count;                 // < 0 = unset
  int size;                   // < 0 = unset
  int spoof;                  // < 0 = unset, else 0/1
  const char* spoof_mode;     // nullptr = unset
  const char* dns_name;       // nullptr = unset
  uint32_t sctp_rate;         // 0 = unset
  uint32_t diameter_rate;     // 0 = unset
  uint32_t sip_rate;          // 0 = unset
  int enable_srtp;            // -1 = unset, 0 = false, 1 = true
};

constexpr ProfileDef kProfiles[] = {
    {"web-stress", "Standard Web Server Stress Test (HTTP/1.1 GET Flood)",
     "http", "http1", 80, 100000, -1, -1, nullptr, nullptr, 0, 0, 0, -1},
    {"web-bypass", "Advanced WAF/CDN Evasion Test (Polymorphic HTTP/2 & Ninja Mode)",
     "http2", "http2", 443, 50000, -1, -1, nullptr, nullptr, 0, 0, 0, -1},
    {"stateful-exhaustion", "Stateful Firewall & Load Balancer Exhaustion (TCP SYN Flood)",
     "basic", "tcp", -1, 500000, -1, 1, "realistic", nullptr, 0, 0, 0, -1},
    {"volumetric-udp", "Raw Volumetric Pipe Saturation (UDP Flood)",
     "basic", "udp", -1, 1000000, 1400, 1, "random", nullptr, 0, 0, 0, -1},
    {"dns-infrastructure", "DNS Server Stress Test (Randomized DNS Queries)",
     "dns", "udp", 53, 200000, -1, 1, "realistic", "random.example.com", 0, 0, 0, -1},
    {"slow-exhaustion", "Low & Slow Application Layer Exhaustion (Slowloris/Slow-Read)",
     "slowloris", "tcp", 443, 10000, -1, -1, nullptr, nullptr, 0, 0, 0, -1},
    {"amplification-simulation", "Reflective Amplification Simulation (Memcached/NTP/DNS)",
     "dns-amp", "udp", -1, 50000, -1, 1, nullptr, nullptr, 0, 0, 0, -1},
    {"telco-sctp-flood", "Carrier-Grade SCTP Multi-Homed Association Flood (S1-AP / NG-AP)",
     "sctp-flood", "sctp", 38412, 100000, 64, 1, "random", nullptr, 5000, 0, 0, 0},
    {"telco-diameter-billing", "3GPP Ro/Gx Diameter CCR Billing Storm Simulation",
     "diameter-ccr", "diameter", 3868, 100000, 128, 1, "realistic", nullptr, 0, 5000, 0, 0},
    {"telco-sip-storm", "VoLTE/IMS SIP INVITE Storm & SRTP Media Flood",
     "sip-storm", "sip", 5060, 50000, 256, 0, nullptr, nullptr, 0, 0, 2000, 1},
    {"telco-full-carrier", "Full Carrier Multi-Protocol Simulation (SCTP + Diameter + SIP/SRTP)",
     "carrier-storm", "telco-full", 0, 200000, 128, 1, "realistic", nullptr, 5000, 5000, 2000, 1},
    {"custom", "Custom user-defined profile (no overrides)",
     nullptr, nullptr, -1, -1, -1, -1, nullptr, nullptr, 0, 0, 0, -1},
};

}  // namespace

std::optional<std::string> ApplyProfile(const std::string& name, CliOptions& opt) {
  for (const auto& p : kProfiles) {
    if (name != p.name) {
      continue;
    }
    if (p.attack_vector != nullptr) opt.job.attack_vector = p.attack_vector;
    if (p.protocol != nullptr) opt.job.protocol = p.protocol;
    if (p.port >= 0) opt.job.target_port = static_cast<std::uint16_t>(p.port);
    if (p.count >= 0) opt.job.packet_count = static_cast<std::uint32_t>(p.count);
    if (p.size >= 0) opt.job.packet_size = static_cast<std::uint32_t>(p.size);
    if (p.spoof >= 0) opt.job.spoof = (p.spoof != 0);
    if (p.spoof_mode != nullptr) opt.job.spoof_mode = p.spoof_mode;
    if (p.dns_name != nullptr) opt.job.dns_name = p.dns_name;
    if (p.sctp_rate > 0) opt.sctp_rate = p.sctp_rate;
    if (p.diameter_rate > 0) opt.diameter_rate = p.diameter_rate;
    if (p.sip_rate > 0) opt.sip_rate = p.sip_rate;
    if (p.enable_srtp >= 0) opt.enable_srtp = (p.enable_srtp != 0);
    return std::nullopt;
  }
  return "unknown profile: " + name;
}

void ListProfiles() {
  std::printf("\n%s\n", std::string(80, '=').c_str());
  std::printf("%s\n", "                       Samurai - Corporate Test Profiles");
  std::printf("%s\n", std::string(80, '=').c_str());
  std::printf(" %-25s | %s\n", "PROFILE NAME", "DESCRIPTION");
  std::printf("%s\n", std::string(80, '-').c_str());
  for (const auto& p : kProfiles) {
    if (std::string(p.name) == "custom") {
      continue;
    }
    std::printf(" %-25s | %s\n", p.name, p.description);
  }
  std::printf("%s\n", std::string(80, '=').c_str());
  std::printf("\nUse a profile with: --profile <profile_name>\n\n");
}

}  // namespace samurai::cli
