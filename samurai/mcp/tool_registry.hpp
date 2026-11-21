#pragma once

// Registers all native C++17 Samurai MCP tools (runtime dataplane, benchmarks,
// RFC suites, cluster management, and Closed-Loop Autopilot / Mahoraga RL) onto
// an McpServer instance.

#include "autopilot_tools.hpp"
#include "protocol.hpp"
#include "safety.hpp"

namespace samurai::mcp {

void RegisterAllTools(McpServer& server, AutopilotManager& autopilot, const SafetyConfig& safety);

}  // namespace samurai::mcp
