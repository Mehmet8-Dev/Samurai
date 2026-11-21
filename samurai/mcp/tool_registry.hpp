#pragma once

// Registers all native C++17 Samurai MCP tools (runtime dataplane, benchmarks,
// RFC suites, distributed cluster orchestration, Scenario Engine, and
// Closed-Loop Autopilot / Mahoraga RL) plus portable Skill Resources and
// Workflow Prompts onto an McpServer instance.

#include "autopilot_tools.hpp"
#include "cluster_tools.hpp"
#include "protocol.hpp"
#include "safety.hpp"

namespace samurai::mcp {

void RegisterAllTools(McpServer& server,
                      AutopilotManager& autopilot,
                      ClusterManager& cluster,
                      const SafetyConfig& safety);

void RegisterSkillsAndPrompts(McpServer& server);

}  // namespace samurai::mcp
