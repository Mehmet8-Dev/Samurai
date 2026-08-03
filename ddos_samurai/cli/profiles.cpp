#include "profiles.hpp"

#include <cstdint>
#include <cstdio>
#include <string>

namespace samurai::cli {

namespace {

// One corporate test profile. Sentinel values (nullptr / negative) mean "leave
// the option at its current/default value". Mirrors TEST_PROFILES in the former
// workload_profiles.py, restricted to fields the wire JobEnvelopeV1 carries.
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
};

constexpr ProfileDef kProfiles[] = {
    {"web-stress", "Standard Web Server Stress Test (HTTP/1.1 GET Flood)",
     "http", "tcp", 80, 100000, -1, -1, nullptr, nullptr},
    {"web-bypass", "Advanced WAF/CDN Evasion Test (Polymorphic HTTP/2 & Ninja Mode)",
     "http2", "tcp", 443, 50000, -1, -1, nullptr, nullptr},
    {"stateful-exhaustion", "Stateful Firewall & Load Balancer Exhaustion (TCP SYN Flood)",
     "basic", "tcp", -1, 500000, -1, 1, "realistic", nullptr},
    {"volumetric-udp", "Raw Volumetric Pipe Saturation (UDP Flood)",
     "basic", "udp", -1, 1000000, 1400, 1, "random", nullptr},
    {"dns-infrastructure", "DNS Server Stress Test (Randomized DNS Queries)",
     "dns", "udp", 53, 200000, -1, 1, "realistic", "random.example.com"},
    {"slow-exhaustion", "Low & Slow Application Layer Exhaustion (Slowloris/Slow-Read)",
     "slowloris", "tcp", 443, 10000, -1, -1, nullptr, nullptr},
    {"amplification-simulation", "Reflective Amplification Simulation (Memcached/NTP/DNS)",
     "dns-amp", "udp", -1, 50000, -1, 1, nullptr, nullptr},
    {"custom", "Custom user-defined profile (no overrides)",
     nullptr, nullptr, -1, -1, -1, -1, nullptr, nullptr},
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
