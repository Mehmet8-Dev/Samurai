#pragma once

// Native C++17 Fail-Closed API & Docker Service Discovery for Samurai MCP.
//
// Provides pure POSIX (zero curl/Python/shell) discovery of:
//   - Running Docker containers, networks, private IPv4s, and exposed ports
//     via `/var/run/docker.sock` (when `discover_docker` is enabled)
//   - Non-blocking TCP port reachability (`poll()` + `SO_ERROR`)
//   - HTTP/1.1 service fingerprinting, OpenAPI/Swagger route extraction, and
//     health/metadata endpoint probing
//   - Ready-to-run `samurai_scenario_worker` JSON skeleton synthesis
//
// All target IPv4 addresses (explicit or Docker-discovered) are enforced
// fail-closed through `ValidateMcpTarget` / `ResolveMcpTarget`.

#include "protocol.hpp"
#include "safety.hpp"

namespace samurai::mcp {

ToolResult HandleDiscoverApis(const samurai::core::json::Value& args, const SafetyConfig& safety);

}  // namespace samurai::mcp
