#pragma once

// Native target-safety gate — the C++ replacement for
// utils.validate_target_safety(). Enforces the same policy the Python CLI did:
//
//   * IPv4 only; multicast / unspecified always rejected.
//   * With an allowlist: the target must match an allowlisted address or CIDR.
//   * A denylist always wins (blocks even when public targets are allowed).
//   * Default policy: only private/loopback targets, unless allow_public.
//
// Reason strings are kept identical to the Python implementation so callers and
// tests observe the same messages.

#include <string>
#include <vector>

namespace samurai::core {

struct TargetSafetyResult {
  bool ok = false;
  std::string reason;
};

// `allow_targets` / `deny_targets` accept bare IPv4 addresses ("a.b.c.d") and
// CIDR networks ("a.b.c.d/n"). An empty allowlist selects the default policy.
TargetSafetyResult ValidateTargetSafety(const std::string& target_ip,
                                        const std::vector<std::string>& allow_targets = {},
                                        bool allow_public = false,
                                        const std::vector<std::string>& deny_targets = {});

}  // namespace samurai::core
