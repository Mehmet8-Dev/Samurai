#include "validation.hpp"

#include <string>

#include <arpa/inet.h>

#include "target_safety.hpp"
#include "worker_registry.hpp"

namespace samurai::cli {

namespace {

bool IsValidIpv4(const std::string& s) {
  in_addr addr{};
  return inet_pton(AF_INET, s.c_str(), &addr) == 1;
}

}  // namespace

std::optional<std::string> Validate(const CliOptions& opt) {
  if (opt.worker_name.empty()) {
    return "--worker is required";
  }
  if (!samurai::orchestrator::LookupWorker(opt.worker_name)) {
    return "unknown worker: " + opt.worker_name;
  }
  if (!IsValidIpv4(opt.job.target_ip)) {
    return "invalid --target IPv4 address: " + opt.job.target_ip;
  }
  // Safety gate: private/loopback by default; allowlist/denylist and
  // --allow-public-target relax/tighten the policy (core::ValidateTargetSafety).
  const auto safety = samurai::core::ValidateTargetSafety(
      opt.job.target_ip, opt.allow_targets, opt.allow_public, opt.deny_targets);
  if (!safety.ok) {
    return safety.reason;
  }
  if (opt.job.target_port == 0) {
    return "--port must be between 1 and 65535";
  }
  if (opt.job.packet_count == 0 && !(opt.worker_name == "telco" && opt.job.telco_duration_ms > 0)) {
    return "--count must be >= 1";
  }
  if (opt.job.packet_size < 1 || opt.job.packet_size > 65535) {
    return "--size must be between 1 and 65535";
  }
  if (opt.job.target_rps < 0.0) {
    return "--rps must be >= 0";
  }
  if (opt.timeout_ms <= 0) {
    return "--timeout-ms must be > 0";
  }
  return std::nullopt;
}

}  // namespace samurai::cli
