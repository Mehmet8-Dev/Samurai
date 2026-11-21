#pragma once

// Native C++17 Closed-Loop Autopilot & Mahoraga RL Agent MCP Subsystem.
//
// Directly integrates Samurai's in-process C++17 control-plane primitives:
//   - samurai::control::ClosedLoopController (AIMD, Binary Search, RL+Shield)
//   - samurai::control::RlPolicy             (SRLP MLP + RL^2 GRU recurrent)
//   - samurai::control::LeverShield          (WAF path-block reflex)
//   - samurai::control::RlExploreConfig      (deterministic 7-D lever exploration)
//
// Enables both LLM agents (Claude Code / Cursor / Codex) and autonomous RL
// agents to create closed-loop sessions, evaluate policy proposals under the
// native safety shield, or drive live safety-gated dataplane windows via MCP.

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "closed_loop.hpp"
#include "json.hpp"
#include "lever_shield.hpp"
#include "protocol.hpp"
#include "rl_explore.hpp"
#include "rl_policy.hpp"
#include "safety.hpp"

namespace samurai::mcp {

class AutopilotManager {
 public:
  AutopilotManager() = default;

  ToolResult HandleCreate(const samurai::core::json::Value& args);
  ToolResult HandleStep(const samurai::core::json::Value& args);
  ToolResult HandleRunWindow(const samurai::core::json::Value& args, const SafetyConfig& safety);
  ToolResult HandleStatus(const samurai::core::json::Value& args);
  ToolResult HandleReset(const samurai::core::json::Value& args);

 private:
  struct Session {
    std::string id;
    std::string strategy_name;
    samurai::control::ClosedLoopConfig config;
    std::unique_ptr<samurai::control::ClosedLoopController> controller;
    samurai::control::RlPolicy policy;
    std::string policy_path;
    samurai::control::LeverShield lever_shield;
    bool lever_shield_enabled = true;
    samurai::control::RlExploreConfig explore;
    double step_horizon = 32.0;
    double ban_pressure = -1.0;
    bool has_last_decision = false;
    samurai::control::ClosedLoopDecision last_decision;
  };

  samurai::core::json::Value StepSessionLocked(
      Session& sess,
      samurai::control::LoadSample sample,
      const samurai::core::json::Value& extra_signals);

  samurai::core::json::Value SessionSummaryJson(const Session& sess) const;

  mutable std::mutex mu_;
  std::uint64_t next_id_ = 1;
  std::map<std::string, std::unique_ptr<Session>> sessions_;
};

}  // namespace samurai::mcp
