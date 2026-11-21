#pragma once

// Native C++17 Scenario Engine MCP Subsystem.
//
// Links directly against `samurai_scenario` (`compiler.hpp`, `scheduler.hpp`,
// `sla.hpp`) for in-process persona -> flow -> step compilation, multi-worker
// weighted session scheduling, and microsecond SLA evaluation, plus fail-closed
// live execution via `samurai --worker scenario --l7-profile-file ...`.

#include "json.hpp"
#include "protocol.hpp"
#include "safety.hpp"

namespace samurai::mcp {

// Parse & compile a Scenario JSON document (inline object or file path) using
// samurai::scenario_native::parse_spec + build_worker_session_plans_native.
ToolResult HandleScenarioCompile(const samurai::core::json::Value& args);

// Validate and execute a live fail-closed Scenario Engine run against a
// loopback/RFC1918 lab target via `samurai --worker scenario`.
ToolResult HandleScenarioRun(const samurai::core::json::Value& args, const SafetyConfig& safety);

// Evaluate a Scenario SLA specification in-process via evaluate_sla_native().
ToolResult HandleScenarioEvaluateSla(const samurai::core::json::Value& args);

}  // namespace samurai::mcp
