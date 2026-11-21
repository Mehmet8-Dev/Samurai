#include "tool_registry.hpp"

#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

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

std::string ReadSkillMarkdown(const std::string& rel_path, const std::string& fallback_text) {
  std::vector<std::string> prefixes = {"."};
  char buf[4096] = {0};
  const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n > 0) {
    std::string p(buf, static_cast<std::size_t>(n));
    const auto slash = p.find_last_of('/');
    if (slash != std::string::npos) {
      const std::string dir = p.substr(0, slash);
      prefixes.push_back(dir + "/../..");
      prefixes.push_back(dir + "/..");
      prefixes.push_back("/usr/local/share/samurai");
    }
  }
  for (const auto& pre : prefixes) {
    std::ifstream in(pre + "/" + rel_path);
    if (in.is_open()) {
      std::ostringstream oss;
      oss << in.rdbuf();
      return oss.str();
    }
  }
  return fallback_text;
}

}  // namespace

void RegisterAllTools(McpServer& server,
                      AutopilotManager& autopilot,
                      ClusterManager& cluster,
                      const SafetyConfig& safety) {
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

  // 7. Cluster service/node/worker/shard discovery (real samurai_master endpoints)
  {
    Value props = Value::Object();
    props.set("host", PropStr("Private/loopback IPv4 address of samurai_master (default: 127.0.0.1)."));
    props.set("port", PropInt("Management API HTTP port (default: 8089)."));
    props.set("auth_token", PropStr("Optional Bearer token (falls back to SAMURAI_MANAGEMENT_API_*_TOKEN)."));
    props.set("include_events", PropBool("Include /v1/cluster/events log (default: false)."));
    props.set("include_metrics", PropBool("Include Prometheus /metrics scrape (default: false)."));
    server.RegisterTool({
        "samurai_cluster_discover",
        "Discover live cluster topology, registered worker nodes, heartbeats, regions, active shards, and optional Prometheus metrics from samurai_master (:8089).",
        SchemaWithProps(std::move(props)),
        [&cluster, safety](const Value& a) { return cluster.HandleDiscover(a, safety); },
    });
    // Backwards-compatible alias
    server.RegisterTool({
        "samurai_cluster_status",
        "Alias for samurai_cluster_discover: inspect samurai_master /healthz, /v1/cluster/summary, /v1/cluster/workers, and /v1/cluster/shards.",
        SchemaWithProps(Value::Object()),
        [&cluster, safety](const Value& a) { return cluster.HandleDiscover(a, safety); },
    });
  }

  // 8. Provision new worker nodes into the cluster
  {
    Value props = Value::Object();
    props.set("host", PropStr("samurai_master private/loopback IPv4 (default: 127.0.0.1)."));
    props.set("port", PropInt("Management API HTTP port (default: 8089)."));
    props.set("node_hosts", PropStr("Comma-separated private/RFC1918 IPv4 addresses of new nodes to provision."));
    props.set("ssh_user", PropStr("SSH username on target lab nodes (default: root)."));
    props.set("ssh_key_path", PropStr("Optional SSH private key path on the master host."));
    props.set("worker_kind", PropStr("Dataplane worker kind to deploy ('bundle' for all workers, or specific worker name)."));
    props.set("worker_region", PropStr("Optional region tag for the newly joined nodes (e.g. eu-central, tr-ist)."));
    props.set("auth_token", PropStr("Optional Operator/Admin Bearer token."));
    props.set("timeout_s", PropInt("Provisioning timeout per host in seconds (2-60, default: 10)."));
    server.RegisterTool({
        "samurai_cluster_provision_node",
        "Add new worker nodes to a running Samurai cluster via POST /v1/cluster/provision (fail-closed: only private/RFC1918 node IPs permitted).",
        SchemaWithProps(std::move(props), {"node_hosts"}),
        [&cluster, safety](const Value& a) { return cluster.HandleProvisionNode(a, safety); },
    });
  }

  // 9. Live multi-worker shard reconfiguration
  {
    Value props = Value::Object();
    props.set("host", PropStr("samurai_master private/loopback IPv4 (default: 127.0.0.1)."));
    props.set("port", PropInt("Management API HTTP port (default: 8089)."));
    props.set("shard_id", PropStr("Optional active shard ID to reconfigure (omit for cluster-wide update)."));
    props.set("worker_id", PropStr("Optional worker ID filter."));
    props.set("target_rps", PropNum("New target RPS setpoint."));
    props.set("concurrency", PropInt("New L7 concurrency level."));
    props.set("request_mix", PropInt("New Mahoraga request_mix variant index."));
    props.set("source_rotation", PropInt("New source rotation mode."));
    props.set("pacing_mode", PropInt("New pacing mode."));
    Value p_obj = Value::Object();
    p_obj.set("type", Value::Str("object"));
    p_obj.set("description", Value::Str("Optional raw params object forwarded to /v1/shards/reconfigure."));
    props.set("params", std::move(p_obj));
    props.set("auth_token", PropStr("Optional Operator/Admin Bearer token."));
    server.RegisterTool({
        "samurai_cluster_reconfigure",
        "Coordinate multiple active worker shards in real time via POST /v1/shards/reconfigure (live RPS, concurrency, and Mahoraga shaping updates).",
        SchemaWithProps(std::move(props)),
        [&cluster, safety](const Value& a) { return cluster.HandleReconfigure(a, safety); },
    });
  }

  // 10. Emergency cluster-wide abort
  {
    Value props = Value::Object();
    props.set("host", PropStr("samurai_master private/loopback IPv4 (default: 127.0.0.1)."));
    props.set("port", PropInt("Management API HTTP port (default: 8089)."));
    props.set("auth_token", PropStr("Optional Operator/Admin Bearer token."));
    server.RegisterTool({
        "samurai_cluster_abort",
        "Safely abort active distributed jobs across all cluster workers via POST /v1/jobs/abort.",
        SchemaWithProps(std::move(props)),
        [&cluster, safety](const Value& a) { return cluster.HandleAbort(a, safety); },
    });
  }

  // 11. In-process multi-worker sharding & autoscale planner
  {
    Value props = Value::Object();
    props.set("mode", PropStr("Sharding mode: 'packets' (L4/L7) or 'telco' (subscriber/CGNAT/BNG partitioning).", {"packets", "telco"}));
    props.set("strategy", PropStr("Assignment strategy: 'equal', 'capability', or 'region'.", {"equal", "capability", "region"}));
    props.set("target_region", PropStr("Target PoP/region for locality-aware sharding (e.g. 'eu-central', 'tr-ist')."));
    props.set("total_count", PropInt("Total packet/request budget (packets mode)."));
    props.set("total_subscribers", PropInt("Total subscriber count (telco mode)."));
    props.set("protocol", PropStr("Telco protocol (telco mode, e.g. gtpu, pppoe, dhcp, sctp, diameter, sip-rtp)."));
    props.set("target_cps", PropInt("Telco subscriber setup CPS (telco mode)."));
    props.set("pool_profile", PropStr("Isolated CGNAT/BNG lab pool preset.", {"linear", "regional-bng", "national-cgnat"}));
    Value w_arr = Value::Object();
    w_arr.set("type", Value::Str("array"));
    w_arr.set("description", Value::Str("Array of worker IDs or objects {worker_id, region, capacity_score, gpu_available, xdp_available}."));
    props.set("workers", std::move(w_arr));
    props.set("min_replicas", PropInt("Autoscale minimum worker replicas (default: 1)."));
    props.set("max_replicas", PropInt("Autoscale maximum worker replicas (default: 32)."));
    props.set("shards_per_worker", PropInt("Target shards per worker for autoscale calculation (default: 2)."));
    server.RegisterTool({
        "samurai_cluster_plan_shards",
        "Plan multi-worker shard distribution (equal/capability/region or 4G/5G telco CGNAT/BNG subscriber pools) and compute native AutoscaleController replica recommendations in-process.",
        SchemaWithProps(std::move(props), {"workers"}),
        [&cluster](const Value& a) { return cluster.HandlePlanShards(a); },
    });
  }

  // 12. Local loopback multi-worker mesh lifecycle (start / scale / status / stop)
  {
    Value props = Value::Object();
    props.set("action", PropStr("Lifecycle action: start, scale, status, or stop.", {"start", "scale", "status", "stop"}));
    props.set("slaves", PropInt("Desired number of local samurai_slave worker nodes (0-16, default: 2)."));
    props.set("worker_kind", PropStr("Worker flavor for local slaves ('bundle' for all workers, or specific worker name)."));
    props.set("worker_region", PropStr("Region label for local slave nodes (default: local-lab)."));
    props.set("control_port", PropInt("Loopback ZMQ control port for samurai_master (default: 5099)."));
    props.set("management_port", PropInt("Loopback HTTP Management API port (default: 8089)."));
    server.RegisterTool({
        "samurai_cluster_local_mesh",
        "Spin up, dynamically scale (add/remove slave nodes), inspect, or tear down a loopback-only (127.0.0.1) distributed samurai_master + N samurai_slave cluster for multi-worker coordination.",
        SchemaWithProps(std::move(props)),
        [&cluster](const Value& a) { return cluster.HandleLocalMesh(a); },
    });
  }

  // 13-17. Autopilot / Mahoraga RL tools
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

  // 18-20. Scenario Engine tools
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

void RegisterSkillsAndPrompts(McpServer& server) {
  struct SkillDef {
    const char* slug;
    const char* rel_path;
    const char* desc;
  };
  static const SkillDef kSkills[] = {
      {"samurai-netbench", "skills/samurai-netbench/SKILL.md",
       "Core Samurai L4/L7/RFC benchmarking, host discovery, and evidence-boundary workflow."},
      {"samurai-cluster-orchestrator", "skills/samurai-cluster-orchestrator/SKILL.md",
       "Distributed cluster discovery, node provisioning, multi-worker sharding, autoscaling, and live shard coordination."},
      {"samurai-autopilot-rl", "skills/samurai-autopilot-rl/SKILL.md",
       "Closed-Loop Autopilot (AIMD/BinSearch/Mahoraga RL), SRLP MLP/RL^2 GRU inference, and LeverShield WAF reflex."},
      {"samurai-scenario-author", "skills/samurai-scenario-author/SKILL.md",
       "Multi-step Web/Mobile persona scenario authoring, JWT/cookie binding, in-process compilation, and SLA verification."},
      {"samurai-hardware-dataplane", "skills/samurai-hardware-dataplane/SKILL.md",
       "Complete catalog & orchestration playbook for all 10 native dataplane workers (cpu, afpacket, afxdp, dpdk, gpu CUDA/BAR1 P2P, doca, l7, scenario, telco 4G/5G CUPS, defense VAE)."},
  };

  for (const auto& s : kSkills) {
    const std::string uri = std::string("samurai://skills/") + s.slug;
    const std::string rel = s.rel_path;
    const std::string desc = s.desc;
    server.RegisterResource({
        uri,
        s.slug,
        desc,
        "text/markdown",
        [rel, desc]() { return ReadSkillMarkdown(rel, "# " + rel + "\n\n" + desc + "\n"); },
    });
    server.RegisterPrompt({
        s.slug,
        desc,
        [rel, desc](const Value&) { return ReadSkillMarkdown(rel, "# " + rel + "\n\n" + desc + "\n"); },
    });
  }
}

}  // namespace samurai::mcp
