#include "tool_registry.hpp"

#include "runtime_tools.hpp"
#include "scenario_tools.hpp"

namespace samurai::mcp {

namespace {

using samurai::core::json::Value;

Value EmptyObjectSchema() {
  Value s = Value::Object();
  s.set("type", Value::Str("object"));
  s.set("properties", Value::Object());
  return s;
}

Value PropStr(const char* desc, const std::vector<std::string>& enum_vals = {}) {
  Value p = Value::Object();
  p.set("type", Value::Str("string"));
  if (desc && desc[0]) p.set("description", Value::Str(desc));
  if (!enum_vals.empty()) {
    Value e = Value::Array();
    for (const auto& v : enum_vals) e.push_back(Value::Str(v));
    p.set("enum", std::move(e));
  }
  return p;
}

Value PropInt(const char* desc) {
  Value p = Value::Object();
  p.set("type", Value::Str("integer"));
  if (desc && desc[0]) p.set("description", Value::Str(desc));
  return p;
}

Value PropNum(const char* desc) {
  Value p = Value::Object();
  p.set("type", Value::Str("number"));
  if (desc && desc[0]) p.set("description", Value::Str(desc));
  return p;
}

Value PropBool(const char* desc) {
  Value p = Value::Object();
  p.set("type", Value::Str("boolean"));
  if (desc && desc[0]) p.set("description", Value::Str(desc));
  return p;
}

Value SchemaWithProps(Value props, const std::vector<std::string>& required = {}) {
  Value s = Value::Object();
  s.set("type", Value::Str("object"));
  s.set("properties", std::move(props));
  if (!required.empty()) {
    Value req = Value::Array();
    for (const auto& r : required) req.push_back(Value::Str(r));
    s.set("required", std::move(req));
  }
  return s;
}

}  // namespace

void RegisterAllTools(McpServer& server, AutopilotManager& autopilot, const SafetyConfig& safety) {
  // 1. Worker & binary discovery
  server.RegisterTool({
      "samurai_list_workers",
      "Discover compiled native C++17 Samurai dataplane workers (cpu, afpacket, afxdp, dpdk, gpu, doca, l7, scenario, telco, defense), daemons, and benchmark binaries.",
      EmptyObjectSchema(),
      [](const Value& a) { return HandleListWorkers(a); },
  });

  // 2. Profile catalog
  server.RegisterTool({
      "samurai_list_profiles",
      "List Samurai's built-in corporate L4, L7, and 4G/5G carrier-telecom workload profiles.",
      EmptyObjectSchema(),
      [](const Value& a) { return HandleListProfiles(a); },
  });

  // 3. Safety-gated benchmark runner
  {
    Value props = Value::Object();
    props.set("worker", PropStr("Dataplane worker backend (default: cpu).", AllowedWorkers()));
    props.set("target", PropStr("Private/loopback IPv4 target (fail-closed; public IPs blocked)."));
    props.set("port", PropInt("Target TCP/UDP port (1-65535)."));
    props.set("protocol", PropStr("L4/L7/Telco protocol (default: udp).", AllowedProtocols()));
    props.set("count", PropInt("Bounded packet/request count."));
    props.set("size", PropInt("Packet size in bytes (1-65535)."));
    props.set("rps", PropNum("Target rate in packets/requests per second (0 = max speed)."));
    props.set("profile", PropStr("Optional built-in profile name."));
    props.set("l7_protocol", PropStr("L7 protocol override.", {"http1", "http2", "quic", "dns"}));
    props.set("l7_profile_file", PropStr("Optional L7/Scenario JSON profile file path (--l7-profile-file)."));
    props.set("concurrency", PropInt("L7 parallel lanes/threads."));
    props.set("keepalive", PropBool("Reuse L7 connections across requests."));
    props.set("kpi_max_errors", PropInt("Fail KPI gate if errors exceed this threshold."));
    props.set("kpi_max_loss_pct", PropNum("Fail KPI gate if estimated wire loss % exceeds this threshold."));
    props.set("timeout_s", PropInt("Subprocess wall-clock timeout in seconds (5-120)."));
    server.RegisterTool({
        "samurai_run_benchmark",
        "Run a bounded, fail-closed native C++17 Samurai benchmark against a loopback/RFC1918 lab target and return structured JSON telemetry + KPI gate results.",
        SchemaWithProps(std::move(props)),
        [safety](const Value& a) { return HandleRunBenchmark(a, safety); },
    });
  }

  // 4. RFC 2544 / 3511 / 8219 compliance suite
  {
    Value props = Value::Object();
    props.set("suite", PropStr("RFC suite to run.", {"all", "rfc2544", "rfc3511", "rfc8219"}));
    props.set("target", PropStr("Optional private/loopback IPv4 target."));
    props.set("live_dataplane", PropBool("When true with a private target, run live dataplane trials."));
    server.RegisterTool({
        "samurai_run_rfc_suite",
        "Execute Samurai's native RFC 2544 (throughput), RFC 3511 (firewall CPS), and RFC 8219 (IPv6) compliance benchmark suite.",
        SchemaWithProps(std::move(props)),
        [safety](const Value& a) { return HandleRunRfcSuite(a, safety); },
    });
  }

  // 5. Reproducible L4 userspace TCP flow scaling benchmark
  {
    Value props = Value::Object();
    props.set("scale", PropStr("Benchmark scale: '100k' (~0.1s sanity check) or '1m' (1M active TCP flows @ 605 B/flow).", {"100k", "1m"}));
    server.RegisterTool({
        "samurai_bench_tcp_flows",
        "Reproduce Samurai's 64-shard userspace TCP flow benchmark (100k quick check or full 1,000,000 active flows @ ~605 B/flow).",
        SchemaWithProps(std::move(props)),
        [](const Value& a) { return HandleBenchTcpFlows(a); },
    });
  }

  // 6. Reproducible L7 Shared-Nothing userspace benchmark
  {
    Value props = Value::Object();
    props.set("proto", PropStr("Userspace L7 protocol.", {"h1", "h2"}));
    props.set("flows", PropInt("Number of flows (100-200000, default: 5000)."));
    server.RegisterTool({
        "samurai_bench_l7_userspace",
        "Run Samurai's Shared-Nothing L7 userspace benchmark (HTTP/1.1 RFC 7230 or HTTP/2 nghttp2) and report CPS, RPS, P50/P95/P99 latency, and VmRSS.",
        SchemaWithProps(std::move(props)),
        [](const Value& a) { return HandleBenchL7Userspace(a); },
    });
  }

  // 7. Distributed cluster status via POSIX HTTP
  {
    Value props = Value::Object();
    props.set("host", PropStr("Private/loopback IPv4 address of samurai_master (default: 127.0.0.1)."));
    props.set("port", PropInt("Management API HTTP port (default: 8089)."));
    server.RegisterTool({
        "samurai_cluster_status",
        "Query a running samurai_master distributed cluster via its native HTTP Management API (/healthz and /v1/state).",
        SchemaWithProps(std::move(props)),
        [safety](const Value& a) { return HandleClusterStatus(a, safety); },
    });
  }

  // 8. Autopilot / Mahoraga RL: Create session
  {
    Value props = Value::Object();
    props.set("strategy", PropStr("Closed-loop strategy: aimd, binsearch, or rl (Mahoraga RL + safety shield).", {"aimd", "binsearch", "rl"}));
    props.set("min_rps", PropNum("Minimum RPS floor (default: 10)."));
    props.set("max_rps", PropNum("Maximum RPS ceiling (default: 100000)."));
    props.set("initial_rps", PropNum("Optional initial RPS setpoint (0 = min_rps)."));
    props.set("slo_max_error_pct", PropNum("SLO max error % (0 = disabled)."));
    props.set("slo_max_loss_pct", PropNum("SLO max wire loss % (0 = disabled)."));
    props.set("slo_min_rate_accuracy_pct", PropNum("SLO min pacing accuracy % (0 = disabled)."));
    props.set("slo_max_latency_ms", PropNum("SLO max P99 latency in ms (0 = disabled)."));
    props.set("slo_max_pushback_pct", PropNum("SLO max 4xx/5xx defense pushback % (0 = disabled)."));
    props.set("aimd_increase_rps", PropNum("AIMD additive step in RPS."));
    props.set("aimd_backoff", PropNum("Multiplicative decrease factor in (0, 1), default: 0.5."));
    props.set("aimd_max_windows", PropInt("Optional max windows for AIMD (0 = unbounded)."));
    props.set("binsearch_tolerance_rps", PropNum("Binary search convergence tolerance in RPS."));
    props.set("binsearch_max_windows", PropInt("Binary search max windows (default: 24)."));
    props.set("rl_max_jump_factor", PropNum("RL safety shield max upward jump multiplier (default: 2.0)."));
    props.set("policy_path", PropStr("Optional path to exported SRLP native RL policy weights (MLP or RL^2 GRU)."));
    props.set("lever_shield", PropBool("Enable Mahoraga LeverShield WAF path-block reflex (default: true)."));
    props.set("honored_success_floor", PropNum("LeverShield 2xx floor below which a variant is marked path-blocked (default: 0.10)."));
    props.set("variant_count", PropInt("Categorical request_mix variant count (default: 5)."));
    props.set("explore", PropBool("Enable deterministic Mahoraga RL lever exploration across extra shaping dimensions."));
    props.set("explore_seed", PropInt("Deterministic seed for RL exploration (default: 42)."));
    server.RegisterTool({
        "samurai_autopilot_create",
        "Create a native C++17 Closed-Loop Autopilot / Mahoraga RL Agent session (AIMD, Binary Search, or RL+Shield with optional SRLP MLP/RL^2 GRU policy and LeverShield).",
        SchemaWithProps(std::move(props)),
        [&autopilot](const Value& a) { return autopilot.HandleCreate(a); },
    });
  }

  // 9. Autopilot / Mahoraga RL: Step with telemetry sample
  {
    Value props = Value::Object();
    props.set("session_id", PropStr("Autopilot session ID returned by samurai_autopilot_create."));
    props.set("valid", PropBool("Whether the measured window sample is valid (default: true)."));
    props.set("actual_rps", PropNum("Achieved RPS in the measured window."));
    props.set("attempted", PropNum("Total attempted requests/packets in the window."));
    props.set("errors", PropNum("Total errors observed in the window."));
    props.set("error_pct", PropNum("Explicit error % (negative = derive from errors/attempted)."));
    props.set("loss_pct", PropNum("Wire loss % (negative = unknown)."));
    props.set("rate_accuracy_pct", PropNum("Pacing accuracy % (negative = unknown)."));
    props.set("latency_p99_ms", PropNum("Measured P99 latency in ms (negative = unknown)."));
    props.set("pushback_pct", PropNum("Defense 429/503 pushback % (negative = unknown)."));
    props.set("rl_action_rps", PropNum("Optional external RL agent proposed RPS setpoint (governed by the native safety shield)."));
    props.set("rate_limited_ratio", PropNum("Mahoraga defense signal: 429 ratio in [0,1]."));
    props.set("overload_ratio", PropNum("Mahoraga defense signal: 503 ratio in [0,1]."));
    props.set("conn_drop_ratio", PropNum("Mahoraga defense signal: connection drop ratio in [0,1] (updates ban EWMA)."));
    props.set("reset_pressure", PropNum("Mahoraga defense signal: TCP RST / H2 reset ratio."));
    props.set("challenge_rate", PropNum("Mahoraga defense signal: WAF challenge ratio."));
    props.set("variant_applied", PropInt("request_mix variant index applied during this window (feeds LeverShield)."));
    props.set("success_ratio", PropNum("2xx success ratio in [0,1] for variant_applied (feeds LeverShield)."));
    Value rl_levers = Value::Object();
    rl_levers.set("type", Value::Str("object"));
    rl_levers.set("description", Value::Str("Optional external RL proposals for extra kActionFields (concurrency, request_mix, source_rotation, pacing_mode, auth_mode, evasion_tactic)."));
    props.set("rl_levers", std::move(rl_levers));
    server.RegisterTool({
        "samurai_autopilot_step",
        "Advance a Closed-Loop Autopilot / Mahoraga RL session by one measured window; runs SRLP policy inference (or external RL proposal), applies the native SLO & LeverShield safety guards, and returns the shielded 7-D action.",
        SchemaWithProps(std::move(props), {"session_id"}),
        [&autopilot](const Value& a) { return autopilot.HandleStep(a); },
    });
  }

  // 10. Autopilot / Mahoraga RL: Live closed-loop window execution
  {
    Value props = Value::Object();
    props.set("session_id", PropStr("Autopilot session ID."));
    props.set("worker", PropStr("Dataplane worker backend (default: l7).", AllowedWorkers()));
    props.set("target", PropStr("Private/loopback IPv4 target (fail-closed)."));
    props.set("port", PropInt("Target port (default: 8080)."));
    props.set("protocol", PropStr("Protocol (default: http1).", AllowedProtocols()));
    props.set("l7_protocol", PropStr("Optional L7 protocol override.", {"http1", "http2", "quic", "dns"}));
    props.set("window_s", PropNum("Window duration in seconds used to compute packet count from setpoint_rps (0.2-15s, default: 1.0)."));
    props.set("count", PropInt("Optional explicit packet/request count override."));
    props.set("concurrency", PropInt("L7 concurrency."));
    props.set("keepalive", PropBool("L7 keepalive."));
    props.set("rl_action_rps", PropNum("Optional external RL agent proposed next RPS."));
    props.set("timeout_s", PropInt("Subprocess timeout in seconds."));
    server.RegisterTool({
        "samurai_autopilot_run_window",
        "Execute one live, safety-gated Samurai dataplane window at the session's current setpoint_rps, feed the measured JSON telemetry into ClosedLoopController + RL/LeverShield, and return both live metrics and the next shielded setpoint.",
        SchemaWithProps(std::move(props), {"session_id"}),
        [&autopilot, safety](const Value& a) { return autopilot.HandleRunWindow(a, safety); },
    });
  }

  // 11. Autopilot status
  {
    Value props = Value::Object();
    props.set("session_id", PropStr("Optional session ID (omit to list all active sessions)."));
    server.RegisterTool({
        "samurai_autopilot_status",
        "Inspect active Closed-Loop Autopilot / RL sessions, current setpoints, best SLO-green RPS, and LeverShield memory.",
        SchemaWithProps(std::move(props)),
        [&autopilot](const Value& a) { return autopilot.HandleStatus(a); },
    });
  }

  // 12. Autopilot reset / delete
  {
    Value props = Value::Object();
    props.set("session_id", PropStr("Autopilot session ID to reset or delete."));
    props.set("delete", PropBool("When true, permanently remove the session instead of resetting episode state."));
    server.RegisterTool({
        "samurai_autopilot_reset",
        "Reset an Autopilot / RL episode (clearing controller state, RL^2 GRU hidden context, and LeverShield memory) or delete the session.",
        SchemaWithProps(std::move(props), {"session_id"}),
        [&autopilot](const Value& a) { return autopilot.HandleReset(a); },
    });
  }

  // 13. Scenario Engine: Compile & validate multi-step persona JSON in-process
  {
    Value props = Value::Object();
    Value sc_obj = Value::Object();
    sc_obj.set("type", Value::Str("object"));
    sc_obj.set("description", Value::Str("Inline Scenario Engine JSON spec (personas, flows, load_model, sla)."));
    props.set("scenario", std::move(sc_obj));
    props.set("scenario_file", PropStr("Path to a Scenario Engine JSON file (alternative to inline 'scenario')."));
    props.set("workers", PropInt("Number of virtual workers to schedule sessions across (1-64, default: 1)."));
    props.set("sessions_per_worker", PropInt("Sessions compiled per worker (1-256, default: 2)."));
    props.set("seed", PropInt("Deterministic RNG seed for weighted persona/flow scheduling (default: 42)."));
    props.set("include_plans", PropBool("Include full compiled packed session event arrays in the response (default: false)."));
    server.RegisterTool({
        "samurai_scenario_compile",
        "Parse, validate, and compile a multi-step Scenario Engine JSON specification (personas, flows, steps, token capture, think-time, L4/L7 primitives) in-process via native samurai_scenario.",
        SchemaWithProps(std::move(props)),
        [](const Value& a) { return HandleScenarioCompile(a); },
    });
  }

  // 14. Scenario Engine: Execute live fail-closed multi-step scenario
  {
    Value props = Value::Object();
    Value sc_obj = Value::Object();
    sc_obj.set("type", Value::Str("object"));
    sc_obj.set("description", Value::Str("Inline Scenario Engine JSON spec to validate and run live."));
    props.set("scenario", std::move(sc_obj));
    props.set("scenario_file", PropStr("Path to a Scenario Engine JSON file."));
    props.set("target", PropStr("Private/loopback IPv4 target (fail-closed; public IPs blocked)."));
    props.set("port", PropInt("Target port (default: 8080)."));
    props.set("count", PropInt("Bounded request/session budget (default: 100)."));
    props.set("rps", PropNum("Optional target RPS pacing cap."));
    props.set("concurrency", PropInt("Optional concurrency override."));
    props.set("timeout_s", PropInt("Subprocess wall-clock timeout in seconds (5-120)."));
    server.RegisterTool({
        "samurai_scenario_run",
        "Validate in-process and execute a live multi-step persona Scenario (HTTP/1.1, HTTP/2, QUIC/H3, cookie/JWT token binding, SLA checks) via samurai_scenario_worker against a loopback/RFC1918 lab target.",
        SchemaWithProps(std::move(props)),
        [safety](const Value& a) { return HandleScenarioRun(a, safety); },
    });
  }

  // 15. Scenario Engine: Evaluate SLA document in-process
  {
    Value props = Value::Object();
    Value sla_obj = Value::Object();
    sla_obj.set("type", Value::Str("object"));
    sla_obj.set("description", Value::Str("Scenario SLA object (min_completion_rate, max_step_fail_ratio, max_latency_p95_ms, max_connect_timeout_ratio, max_retransmit_ratio)."));
    props.set("sla", std::move(sla_obj));
    props.set("sessions_started", PropInt("Total started virtual user sessions."));
    props.set("sessions_completed", PropInt("Total completed virtual user sessions."));
    props.set("step_attempted", PropInt("Total executed scenario steps."));
    props.set("step_failed", PropInt("Total failed scenario steps."));
    props.set("latency_p95_ms", PropNum("Observed P95 latency in ms (omit or negative if unavailable)."));
    props.set("tcp_connect_attempts", PropInt("TCP connect attempts (L4 scenarios)."));
    props.set("tcp_connect_established", PropInt("TCP established connections."));
    props.set("tcp_retransmit_count", PropInt("TCP retransmit count."));
    props.set("tcp_timeout_close_count", PropInt("TCP timeout-closed connections."));
    server.RegisterTool({
        "samurai_scenario_evaluate_sla",
        "Evaluate a Scenario Engine SLA contract against observed session/step/latency/TCP counters in-process via native evaluate_sla_native().",
        SchemaWithProps(std::move(props), {"sla"}),
        [](const Value& a) { return HandleScenarioEvaluateSla(a); },
    });
  }
}

}  // namespace samurai::mcp
