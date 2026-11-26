#pragma once

// Fail-closed MCP safety policy wrapping samurai::core::ValidateTargetSafety.
// Never exposes `--allow-public-target` to MCP callers.

#include <cstdint>
#include <string>
#include <vector>

#include "json.hpp"
#include "target_safety.hpp"

namespace samurai::mcp {

struct SafetyConfig {
  std::vector<std::string> allow_targets;       // optional SAMURAI_MCP_ALLOW_TARGETS CSV + per-call allow_target(s)
  std::vector<std::string> deny_targets;        // optional SAMURAI_MCP_DENY_TARGETS CSV (always wins)
  std::uint64_t max_packet_count = 100000000ULL; // SAMURAI_MCP_MAX_COUNT (0 = unlimited up to uint32 max)
  int max_timeout_s = 86400;                    // SAMURAI_MCP_MAX_TIMEOUT_S (24h default for enterprise soak)
};

SafetyConfig LoadSafetyConfigFromEnv();

// Merges optional per-call `allow_target` (string/CSV) and `allow_targets`
// (array of strings/CSV) into a copy of `base`. Rejects wildcard bypasses
// such as `*` or `0.0.0.0/0` (recorded in `err_out` if provided).
SafetyConfig EffectiveSafetyConfig(const samurai::core::json::Value& args,
                                   const SafetyConfig& base,
                                   std::string* err_out = nullptr);

// Validates `count` against `[1, cfg.max_packet_count]` (or uint32 max when
// `cfg.max_packet_count == 0`). Returns true if valid, else sets `err_out`.
bool ValidateMcpPacketCount(std::int64_t count,
                            const SafetyConfig& cfg,
                            std::string* err_out = nullptr);

// Appends `--allow-target` (valid IPv4/CIDR entries + resolved hostname IPv4
// when non-empty) and `--deny-target` flags onto a `samurai` subprocess argv.
void AppendSafetyCliArgs(const SafetyConfig& cfg,
                         std::vector<std::string>& cmd,
                         const std::string& resolved_target_ip = "");

// Validates an IPv4 target using samurai::core::ValidateTargetSafety with
// allow_public strictly forced to false.
samurai::core::TargetSafetyResult ValidateMcpTarget(const std::string& target_ip,
                                                    const SafetyConfig& cfg);

// Resolves "host.docker.internal" or an explicitly allowlisted domain/hostname
// (matched against `cfg.allow_targets` and not in `cfg.deny_targets`) via DNS
// to an IPv4 address, then applies ValidateMcpTarget fail-closed on the
// resulting IPv4. Unauthorized hostnames and public IPs fail closed.
samurai::core::TargetSafetyResult ResolveMcpTarget(const std::string& target_or_alias,
                                                   const SafetyConfig& cfg,
                                                   std::string& resolved_ip_out);

bool IsAllowedWorker(const std::string& worker);
bool IsAllowedProtocol(const std::string& proto);

const std::vector<std::string>& AllowedWorkers();
const std::vector<std::string>& AllowedProtocols();

}  // namespace samurai::mcp
