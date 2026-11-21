#pragma once

// Fail-closed MCP safety policy wrapping samurai::core::ValidateTargetSafety.
// Never exposes `--allow-public-target` to MCP callers.

#include <cstdint>
#include <string>
#include <vector>

#include "target_safety.hpp"

namespace samurai::mcp {

struct SafetyConfig {
  std::vector<std::string> allow_targets;  // optional SAMURAI_MCP_ALLOW_TARGETS CSV
  std::vector<std::string> deny_targets;   // optional SAMURAI_MCP_DENY_TARGETS CSV
  std::uint64_t max_packet_count = 500000; // SAMURAI_MCP_MAX_COUNT
  int max_timeout_s = 120;
};

SafetyConfig LoadSafetyConfigFromEnv();

// Validates an IPv4 target using samurai::core::ValidateTargetSafety with
// allow_public strictly forced to false.
samurai::core::TargetSafetyResult ValidateMcpTarget(const std::string& target_ip,
                                                    const SafetyConfig& cfg);

bool IsAllowedWorker(const std::string& worker);
bool IsAllowedProtocol(const std::string& proto);

const std::vector<std::string>& AllowedWorkers();
const std::vector<std::string>& AllowedProtocols();

}  // namespace samurai::mcp
