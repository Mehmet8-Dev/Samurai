// Native C++17 verification suite for samurai_mcp (protocol, fail-closed safety,
// tool registry, and Closed-Loop Autopilot / Mahoraga RL Agent shield stepping).

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "autopilot_tools.hpp"
#include "cluster_tools.hpp"
#include "json.hpp"
#include "protocol.hpp"
#include "runtime_tools.hpp"
#include "safety.hpp"
#include "setup_tools.hpp"
#include "tool_registry.hpp"

namespace {

using samurai::core::json::Parse;
using samurai::core::json::Value;

int g_failures = 0;

void Check(bool cond, const char* msg) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", msg);
    ++g_failures;
  }
}

Value CallTool(const samurai::mcp::McpServer& server,
               int id,
               const std::string& name,
               Value args = Value::Object()) {
  Value params = Value::Object();
  params.set("name", Value::Str(name));
  params.set("arguments", std::move(args));

  Value req = Value::Object();
  req.set("jsonrpc", Value::Str("2.0"));
  req.set("id", Value::Int(id));
  req.set("method", Value::Str("tools/call"));
  req.set("params", std::move(params));

  const auto resp = server.HandleRequest(req);
  Check(resp.has_value(), "tools/call returned response");
  return resp.value_or(Value::Null());
}

Value ParseToolPayload(const Value& rpc_resp, bool* out_is_error = nullptr) {
  const Value* res = rpc_resp.find("result");
  Check(res != nullptr && res->is_object(), "RPC response contains result object");
  if (!res || !res->is_object()) return Value::Null();
  if (out_is_error) {
    *out_is_error = res->find("isError") ? res->find("isError")->as_bool(false) : false;
  }
  const Value* content = res->find("content");
  Check(content != nullptr && content->is_array() && !content->elements().empty(),
        "result.content is non-empty array");
  if (!content || !content->is_array() || content->elements().empty()) return Value::Null();
  const Value* text = content->elements()[0].find("text");
  Check(text != nullptr && text->is_string(), "content[0].text is string");
  if (!text) return Value::Null();
  const auto parsed = Parse(text->as_string());
  Check(parsed.ok, "content[0].text parses as JSON");
  return parsed.value;
}

}  // namespace

int main() {
  samurai::mcp::SafetyConfig safety;
  samurai::mcp::AutopilotManager autopilot;
  samurai::mcp::ClusterManager cluster;
  samurai::mcp::McpServer server;
  samurai::mcp::RegisterAllTools(server, autopilot, cluster, safety);
  samurai::mcp::RegisterSkillsAndPrompts(server);

  // 1. Initialize handshake (protocolVersion 2024-11-05) + tools/resources/prompts capabilities
  {
    const auto line = server.HandleLine(
        R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}})");
    Check(line.has_value(), "initialize returns JSON");
    const auto p = Parse(*line);
    Check(p.ok, "initialize JSON valid");
    const Value* res = p.value.find("result");
    Check(res && res->find("protocolVersion")->as_string() == "2024-11-05",
          "protocolVersion is 2024-11-05");
    Check(res && res->find("serverInfo")->find("name")->as_string() == "samurai-mcp",
          "serverInfo.name is samurai-mcp");
    const Value* caps = res ? res->find("capabilities") : nullptr;
    Check(caps && caps->find("tools") && caps->find("resources") && caps->find("prompts"),
          "capabilities advertise tools, resources, and prompts");
  }

  // 2. Notification produces no response
  {
    const auto notif = server.HandleLine(
        R"({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})");
    Check(!notif.has_value(), "notifications/initialized emits no response");
  }

  // 3. tools/list, resources/list, and prompts/list
  {
    const auto line = server.HandleLine(
        R"({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})");
    Check(line.has_value(), "tools/list returns response");
    const auto p = Parse(*line);
    const Value* tools = p.value.find("result")->find("tools");
    Check(tools && tools->is_array() && tools->elements().size() == 22,
          "tools/list returns 22 registered tools");

    const auto rline = server.HandleLine(
        R"({"jsonrpc":"2.0","id":201,"method":"resources/list","params":{}})");
    const auto rp = Parse(*rline);
    const Value* resources = rp.value.find("result")->find("resources");
    Check(resources && resources->is_array() && resources->elements().size() == 5,
          "resources/list returns 5 skill resources");

    const auto rread = server.HandleLine(
        R"({"jsonrpc":"2.0","id":202,"method":"resources/read","params":{"uri":"samurai://skills/samurai-cluster-orchestrator"}})");
    const auto rrp = Parse(*rread);
    const Value* contents = rrp.value.find("result")->find("contents");
    Check(contents && contents->is_array() && !contents->elements().empty() &&
              !contents->elements()[0].find("text")->as_string().empty(),
          "resources/read returns samurai-cluster-orchestrator skill text");

    const auto pline = server.HandleLine(
        R"({"jsonrpc":"2.0","id":203,"method":"prompts/list","params":{}})");
    const auto pp = Parse(*pline);
    const Value* prompts = pp.value.find("result")->find("prompts");
    Check(prompts && prompts->is_array() && prompts->elements().size() == 5,
          "prompts/list returns 5 skill prompts");
  }

  // 4. Fail-closed safety blocks public targets
  {
    Value args = Value::Object();
    args.set("worker", Value::Str("cpu"));
    args.set("target", Value::Str("8.8.8.8"));
    args.set("port", Value::Int(53));
    args.set("count", Value::Int(10));
    bool is_err = false;
    const Value payload = ParseToolPayload(CallTool(server, 3, "samurai_run_benchmark", std::move(args)), &is_err);
    Check(is_err, "public IP target is rejected with isError=true");
    Check(payload.find("error") != nullptr, "error payload explains safety rejection");
  }

  // 5. Autopilot RL session: safety shield jump-cap + forced SLO backoff + LeverShield WAF reflex
  {
    Value create_args = Value::Object();
    create_args.set("strategy", Value::Str("rl"));
    create_args.set("min_rps", Value::Double(100.0));
    create_args.set("max_rps", Value::Double(10000.0));
    create_args.set("initial_rps", Value::Double(200.0));
    create_args.set("slo_max_error_pct", Value::Double(1.0));
    create_args.set("slo_max_pushback_pct", Value::Double(5.0));
    create_args.set("rl_max_jump_factor", Value::Double(2.0));
    create_args.set("aimd_backoff", Value::Double(0.5));
    create_args.set("explore", Value::Bool(true));
    create_args.set("explore_seed", Value::Int(7));

    bool is_err = false;
    const Value created = ParseToolPayload(
        CallTool(server, 10, "samurai_autopilot_create", std::move(create_args)), &is_err);
    Check(!is_err, "samurai_autopilot_create succeeds");
    const std::string sid = created.find("session_id")->as_string();
    Check(!sid.empty(), "session_id assigned");
    Check(std::fabs(created.find("initial_setpoint_rps")->as_double() - 200.0) < 1e-6,
          "initial setpoint is 200 RPS");

    // Step 1: SLO-green window where external RL agent proposes 5000 RPS -> shield MUST cap at 2x (400 RPS).
    // Also mark variant 2 as WAF path-blocked (success_ratio = 0.0) while requesting variant 2 -> LeverShield intervenes!
    Value step1 = Value::Object();
    step1.set("session_id", Value::Str(sid));
    step1.set("actual_rps", Value::Double(200.0));
    step1.set("attempted", Value::Double(1000.0));
    step1.set("errors", Value::Double(0.0));
    step1.set("pushback_pct", Value::Double(0.0));
    step1.set("rl_action_rps", Value::Double(5000.0));
    step1.set("variant_applied", Value::Int(2));
    step1.set("success_ratio", Value::Double(0.0));
    Value levers = Value::Object();
    levers.set("request_mix", Value::Double(2.0));
    step1.set("rl_levers", std::move(levers));

    const Value res1 = ParseToolPayload(
        CallTool(server, 11, "samurai_autopilot_step", std::move(step1)), &is_err);
    Check(!is_err, "autopilot step 1 succeeds");
    const Value* dec1 = res1.find("decision");
    Check(dec1 && dec1->find("last_healthy")->as_bool() == true, "step 1 SLO-green");
    Check(dec1 && std::fabs(dec1->find("setpoint_rps")->as_double() - 400.0) < 1e-6,
          "RL jump-cap shield clamps 5000 RPS proposal to 2x (400 RPS)");
    Check(res1.find("lever_shield_intervened")->as_bool() == true,
          "LeverShield intercepts WAF path-blocked variant 2");

    // Step 2: SLO-red pushback window (20% 429s) where RL agent still proposes 1000 RPS -> shield MUST force 0.5x backoff to 200 RPS.
    Value step2 = Value::Object();
    step2.set("session_id", Value::Str(sid));
    step2.set("actual_rps", Value::Double(400.0));
    step2.set("attempted", Value::Double(1000.0));
    step2.set("errors", Value::Double(0.0));
    step2.set("pushback_pct", Value::Double(20.0));
    step2.set("conn_drop_ratio", Value::Double(0.4));
    step2.set("rl_action_rps", Value::Double(1000.0));

    const Value res2 = ParseToolPayload(
        CallTool(server, 12, "samurai_autopilot_step", std::move(step2)), &is_err);
    Check(!is_err, "autopilot step 2 succeeds");
    const Value* dec2 = res2.find("decision");
    Check(dec2 && dec2->find("last_healthy")->as_bool() == false, "step 2 SLO-red on pushback");
    Check(dec2 && std::fabs(dec2->find("setpoint_rps")->as_double() - 200.0) < 1e-6,
          "RL SLO shield forces 0.5x backoff to 200 RPS");
    Check(std::fabs(res2.find("ban_pressure")->as_double() - 0.4) < 1e-6,
          "ban_pressure EWMA tracks conn_drop_ratio");

    // Status & Reset
    Value st_args = Value::Object();
    st_args.set("session_id", Value::Str(sid));
    const Value st = ParseToolPayload(
        CallTool(server, 13, "samurai_autopilot_status", std::move(st_args)), &is_err);
    Check(!is_err && st.find("session_id")->as_string() == sid, "autopilot status reports session");

    Value rst_args = Value::Object();
    rst_args.set("session_id", Value::Str(sid));
    rst_args.set("delete", Value::Bool(true));
    const Value rst = ParseToolPayload(
        CallTool(server, 14, "samurai_autopilot_reset", std::move(rst_args)), &is_err);
    Check(!is_err && rst.find("deleted")->as_bool() == true, "autopilot reset deletes session");
  }

  // 6. Scenario Engine: in-process compile + SLA evaluation + fail-closed run gate
  {
    const auto sc_parsed = Parse(R"({
      "scenario": {
        "schema_version": 1,
        "protocol": "http2",
        "personas": {
          "web_user": {"device_profile": "web", "weight": 0.7, "headers": {"User-Agent": "SamuraiTest/3.0"}},
          "mobile_user": {"device_profile": "mobile", "weight": 0.3}
        },
        "flows": {
          "checkout_flow": {
            "persona": "web_user",
            "steps": [
              {"type": "request", "method": "POST", "path": "/api/login", "token_source": "body_json", "token_path": "token", "token_variable_name": "jwt"},
              {"type": "pause", "think_time": {"min_ms": 50, "max_ms": 150, "distribution": "uniform"}},
              {"type": "request", "method": "GET", "path": "/api/cart"},
              {"type": "end_session"}
            ]
          }
        },
        "load_model": {"backend": "http2", "concurrent_vus": 8}
      },
      "workers": 2,
      "sessions_per_worker": 3,
      "seed": 99
    })");
    Check(sc_parsed.ok, "test scenario args parse");

    bool is_err = false;
    const Value compiled = ParseToolPayload(
        CallTool(server, 20, "samurai_scenario_compile", sc_parsed.value), &is_err);
    Check(!is_err, "samurai_scenario_compile succeeds");
    Check(compiled.find("valid") && compiled.find("valid")->as_bool() == true,
          "compiled scenario marked valid");
    const Value* summary = compiled.find("summary");
    Check(summary && summary->find("persona_count")->as_int() == 2, "2 personas parsed");
    Check(summary && summary->find("flow_count")->as_int() == 1, "1 flow parsed");
    Check(summary && summary->find("total_steps")->as_int() == 4, "4 steps parsed");

    // SLA evaluation (passing & failing)
    const auto sla_ok_args = Parse(R"({
      "sla": {"min_completion_rate": 0.95, "max_step_fail_ratio": 0.05, "max_latency_p95_ms": 50.0},
      "sessions_started": 100,
      "sessions_completed": 99,
      "step_attempted": 400,
      "step_failed": 2,
      "latency_p95_ms": 18.5
    })");
    const Value sla_pass = ParseToolPayload(
        CallTool(server, 21, "samurai_scenario_evaluate_sla", sla_ok_args.value), &is_err);
    Check(!is_err && sla_pass.find("passed")->as_bool() == true, "SLA pass verified");

    const auto sla_bad_args = Parse(R"({
      "sla": {"min_completion_rate": 0.95, "max_latency_p95_ms": 20.0},
      "sessions_started": 100,
      "sessions_completed": 70,
      "step_attempted": 400,
      "step_failed": 50,
      "latency_p95_ms": 85.0
    })");
    const Value sla_fail = ParseToolPayload(
        CallTool(server, 22, "samurai_scenario_evaluate_sla", sla_bad_args.value), &is_err);
    Check(!is_err && sla_fail.find("passed")->as_bool() == false, "SLA failure detected");

    // Public target blocked on scenario_run
    Value bad_run = sc_parsed.value;
    bad_run.set("target", Value::Str("1.1.1.1"));
    bad_run.set("port", Value::Int(443));
    const Value blocked = ParseToolPayload(
        CallTool(server, 23, "samurai_scenario_run", std::move(bad_run)), &is_err);
    Check(is_err && blocked.find("error") != nullptr,
          "samurai_scenario_run blocks public IP fail-closed");
  }

  // 7. Cluster Orchestration: multi-worker sharding, 5G telco CGNAT split, autoscale & provision safety
  {
    const auto plan_args = Parse(R"({
      "mode": "packets",
      "strategy": "capability",
      "total_count": 100000,
      "workers": [
        {"worker_id": "node-gpu-1", "region": "eu-central", "gpu_available": true, "capacity_score": 4},
        {"worker_id": "node-xdp-2", "region": "eu-central", "xdp_available": true, "capacity_score": 2}
      ],
      "shards_per_worker": 1,
      "max_replicas": 16
    })");
    bool is_err = false;
    const Value plan = ParseToolPayload(
        CallTool(server, 30, "samurai_cluster_plan_shards", plan_args.value), &is_err);
    Check(!is_err, "samurai_cluster_plan_shards (packets) succeeds");
    const Value* shards = plan.find("shards");
    Check(shards && shards->is_array() && shards->elements().size() == 2,
          "2 weighted shards planned across heterogeneous workers");
    Check(plan.find("autoscale_recommendation") != nullptr,
          "autoscale recommendation included");

    const auto telco_plan_args = Parse(R"({
      "mode": "telco",
      "strategy": "region",
      "target_region": "tr-ist",
      "total_subscribers": 4000,
      "protocol": "gtpu",
      "pool_profile": "regional-bng",
      "workers": [
        {"worker_id": "bng-ist-1", "region": "tr-ist", "capacity_score": 3},
        {"worker_id": "bng-ank-1", "region": "tr-ank", "capacity_score": 1}
      ]
    })");
    const Value tplan = ParseToolPayload(
        CallTool(server, 31, "samurai_cluster_plan_shards", telco_plan_args.value), &is_err);
    Check(!is_err && tplan.find("shards")->elements().size() == 2,
          "5G telco subscriber sharding with regional-bng pool succeeds");

    // Fail-closed safety blocks provisioning public IPs
    const auto bad_prov = Parse(R"({"host":"127.0.0.1","node_hosts":"10.0.0.5,8.8.8.8","worker_kind":"bundle"})");
    const Value prov_err = ParseToolPayload(
        CallTool(server, 32, "samurai_cluster_provision_node", bad_prov.value), &is_err);
    Check(is_err && prov_err.find("error") != nullptr,
          "samurai_cluster_provision_node blocks public node IP fail-closed");

    // Fail-closed safety blocks public targets on distributed cluster_run_job & ipfix_collector
    const auto bad_job = Parse(R"({"worker":"l7","target":"8.8.8.8","port":443,"count":100})");
    const Value job_err = ParseToolPayload(
        CallTool(server, 33, "samurai_cluster_run_job", bad_job.value), &is_err);
    Check(is_err && job_err.find("error") != nullptr,
          "samurai_cluster_run_job blocks public IP fail-closed");

    const auto bad_ipfix = Parse(R"({"worker":"cpu","target":"127.0.0.1","port":9999,"count":10,"ipfix_enabled":true,"ipfix_collector":"1.1.1.1"})");
    const Value ipfix_err = ParseToolPayload(
        CallTool(server, 34, "samurai_run_benchmark", bad_ipfix.value), &is_err);
    Check(is_err && ipfix_err.find("error") != nullptr,
          "samurai_run_benchmark blocks public ipfix_collector fail-closed");
  }

  // 8. Custom TCP / AF_XDP SKB copy mode auto-env & schema exposure
  {
    const auto auto_args = Parse(R"({"target":"127.0.0.1","port":3455})");
    const auto resolved = samurai::mcp::ResolveCustomTcpEnv(auto_args.value, "127.0.0.1", 3455, true);
    Check(resolved.active && resolved.error.empty(), "ResolveCustomTcpEnv activates for custom_tcp");
    Check(resolved.wire == "af_xdp", "custom_tcp defaults wire to af_xdp");
    Check(resolved.xdp_mode == "0", "custom_tcp defaults AF_XDP mode to 0 (SKB/copy)");
    Check(resolved.iface == "lo" && resolved.src_ip == "127.0.0.1",
          "auto-discovery resolves loopback iface and src_ip");

    const auto override_args = Parse(R"({
      "custom_tcp_wire": "af_xdp",
      "xdp_mode": "skb",
      "custom_tcp_iface": "eth0",
      "custom_tcp_src_ip": "10.0.0.5",
      "custom_tcp_src_mac": "02:00:00:00:00:01",
      "custom_tcp_dst_mac": "02:00:00:00:00:02",
      "xdp_queue_id": 2
    })");
    const auto ov = samurai::mcp::ResolveCustomTcpEnv(override_args.value, "10.0.0.1", 80, false);
    Check(ov.active && ov.error.empty(), "explicit custom_tcp_* args activate resolution");
    Check(ov.wire == "af_xdp" && ov.xdp_mode == "0" && ov.iface == "eth0" &&
              ov.src_ip == "10.0.0.5" && ov.dst_mac == "02:00:00:00:00:02" && ov.queue_id == "2",
          "explicit custom_tcp_* overrides propagate accurately");

    const auto bad_wire = Parse(R"({"custom_tcp_wire":"invalid_wire"})");
    const auto bw = samurai::mcp::ResolveCustomTcpEnv(bad_wire.value, "127.0.0.1", 80, true);
    Check(!bw.error.empty(), "invalid custom_tcp_wire rejected with clear error");

    const auto list_line = server.HandleLine(
        R"({"jsonrpc":"2.0","id":35,"method":"tools/list","params":{}})");
    const auto list_parsed = list_line.has_value() ? Parse(*list_line) : samurai::core::json::ParseResult{};
    const Value* list_result = list_parsed.ok ? list_parsed.value.find("result") : nullptr;
    const Value* tools = list_result ? list_result->find("tools") : nullptr;
    auto has_prop = [&](const std::string& tool_name, const std::string& prop_name) -> bool {
      if (!tools || !tools->is_array()) return false;
      for (const auto& t : tools->elements()) {
        const Value* n = t.find("name");
        if (!n || n->as_string() != tool_name) continue;
        const Value* schema = t.find("inputSchema");
        const Value* props = schema ? schema->find("properties") : nullptr;
        return props && props->find(prop_name) != nullptr;
      }
      return false;
    };
    Check(has_prop("samurai_scenario_run", "custom_tcp_wire") &&
              has_prop("samurai_scenario_run", "xdp_mode") &&
              has_prop("samurai_scenario_run", "custom_tcp_iface") &&
              has_prop("samurai_scenario_run", "custom_tcp_dst_mac"),
          "samurai_scenario_run schema exposes custom_tcp/AF_XDP params");
    Check(has_prop("samurai_run_benchmark", "custom_tcp_wire") &&
              has_prop("samurai_run_benchmark", "xdp_mode") &&
              has_prop("samurai_run_benchmark", "custom_tcp_iface") &&
              has_prop("samurai_run_benchmark", "custom_tcp_dst_mac") &&
              has_prop("samurai_run_benchmark", "iface") &&
              has_prop("samurai_run_benchmark", "transport") &&
              has_prop("samurai_run_benchmark", "config") &&
              has_prop("samurai_run_benchmark", "dpdk_port"),
          "samurai_run_benchmark schema exposes custom_tcp, iface, transport, config, dpdk_port");
    Check(has_prop("samurai_cluster_run_job", "scenario") &&
              has_prop("samurai_cluster_run_job", "scenario_file") &&
              has_prop("samurai_cluster_run_job", "l7_profile_file") &&
              has_prop("samurai_cluster_run_job", "iface") &&
              has_prop("samurai_cluster_run_job", "transport"),
          "samurai_cluster_run_job schema exposes distributed scenario, iface, transport");
    Check(has_prop("samurai_autopilot_run_window", "scenario") &&
              has_prop("samurai_autopilot_run_window", "scenario_file") &&
              has_prop("samurai_autopilot_run_window", "iface") &&
              has_prop("samurai_autopilot_run_window", "transport"),
          "samurai_autopilot_run_window schema exposes scenario, iface, transport");
  }

  // 8b. ResolveMcpTarget fail-closed safety & bundled Mahoraga RL policy resolution
  {
    std::string resolved;
    const auto r_loop = samurai::mcp::ResolveMcpTarget("127.0.0.1", safety, resolved);
    Check(r_loop.ok && resolved == "127.0.0.1", "ResolveMcpTarget passes 127.0.0.1");

    const auto r_pub = samurai::mcp::ResolveMcpTarget("8.8.8.8", safety, resolved);
    Check(!r_pub.ok, "ResolveMcpTarget blocks public IPv4");

    const auto r_host = samurai::mcp::ResolveMcpTarget("example.com", safety, resolved);
    Check(!r_host.ok, "ResolveMcpTarget blocks arbitrary hostnames fail-closed");

    Value pol_args = Value::Object();
    pol_args.set("strategy", Value::Str("rl"));
    pol_args.set("min_rps", Value::Double(50.0));
    pol_args.set("max_rps", Value::Double(5000.0));
    pol_args.set("policy_path", Value::Str("mahoraga-rl2.srlp"));
    bool is_err = false;
    const Value pol_res = ParseToolPayload(
        CallTool(server, 39, "samurai_autopilot_create", std::move(pol_args)), &is_err);
    Check(!is_err && pol_res.find("policy_loaded")->as_bool(false) == true &&
              pol_res.find("policy_recurrent")->as_bool(false) == true,
          "samurai_autopilot_create resolves and loads bundled mahoraga-rl2.srlp");
    if (!is_err && pol_res.find("session_id")) {
      Value del = Value::Object();
      del.set("session_id", Value::Str(pol_res.find("session_id")->as_string()));
      del.set("delete", Value::Bool(true));
      (void)CallTool(server, 40, "samurai_autopilot_reset", std::move(del));
    }
  }

  // 8. MCP setup/doctor client diagnostics & safe JSON/TOML registration
  {
    namespace fs = std::filesystem;
    const fs::path tmp_root = fs::temp_directory_path() / "samurai_mcp_setup_test";
    std::error_code ec;
    fs::remove_all(tmp_root, ec);
    fs::create_directories(tmp_root / ".codex", ec);

    // Seed an existing ~/.claude.json with another MCP server and verify default check vs --yes + backup
    {
      std::ofstream out(tmp_root / ".claude.json");
      out << "{\"mcpServers\":{\"other\":{\"command\":\"/bin/true\"}}}\n";
    }
    samurai::mcp::SetupOptions check_opts;
    check_opts.client = "claude-code";
    check_opts.yes = false;
    check_opts.binary_override = "/usr/local/bin/samurai_mcp";
    check_opts.home_override = tmp_root.string();
    check_opts.project_override = tmp_root.string();
    const auto check_res = samurai::mcp::ExecuteSetup(check_opts);
    const Value* applied_flag = check_res.report.find("applied");
    Check(check_res.ok && applied_flag && !applied_flag->as_bool(true),
          "setup without --yes does not mutate config");
    Check(!fs::exists(tmp_root / ".claude.json.bak"), "setup without --yes does not create backup file");

    samurai::mcp::SetupOptions apply_opts = check_opts;
    apply_opts.yes = true;
    const auto apply_res = samurai::mcp::ExecuteSetup(apply_opts);
    Check(apply_res.ok && apply_res.report.find("applied")->as_bool(false) &&
              apply_res.report.find("backup_created")->as_bool(false),
          "setup --yes applies config and creates .bak backup");
    Check(fs::exists(tmp_root / ".claude.json.bak"), "backup file created for existing config");
    {
      std::ifstream in(tmp_root / ".claude.json");
      std::ostringstream ss;
      ss << in.rdbuf();
      const auto parsed = Parse(ss.str());
      Check(parsed.ok, "updated claude.json is valid JSON");
      const Value* servers = parsed.value.find("mcpServers");
      Check(servers && servers->find("other") != nullptr && servers->find("samurai") != nullptr,
            "setup preserves sibling MCP servers while adding samurai");
    }

    // Verify Codex TOML upsert + Doctor detection
    samurai::mcp::SetupOptions codex_opts;
    codex_opts.client = "codex";
    codex_opts.yes = true;
    codex_opts.docker = true;
    codex_opts.home_override = tmp_root.string();
    codex_opts.project_override = tmp_root.string();
    const auto codex_res = samurai::mcp::ExecuteSetup(codex_opts);
    Check(codex_res.ok && codex_res.report.find("transport_mode")->as_string() == "docker",
          "setup --docker configures docker transport for codex");

    samurai::mcp::DoctorOptions doc_opts;
    doc_opts.client = "codex";
    doc_opts.home_override = tmp_root.string();
    doc_opts.project_override = tmp_root.string();
    const Value doc = samurai::mcp::BuildDoctorReport(doc_opts);
    const Value* clients = doc.find("clients");
    Check(clients && clients->is_array() && clients->elements().size() == 1 &&
              clients->elements()[0].find("registered")->as_bool(false),
          "doctor detects registered codex MCP entry");

    // Verify malformed JSON is never overwritten
    fs::create_directories(tmp_root / ".cursor", ec);
    {
      std::ofstream bad(tmp_root / ".cursor" / "mcp.json");
      bad << "{not-valid-json";
    }
    samurai::mcp::SetupOptions bad_opts;
    bad_opts.client = "cursor";
    bad_opts.yes = true;
    bad_opts.home_override = tmp_root.string();
    bad_opts.project_override = tmp_root.string();
    const auto bad_res = samurai::mcp::ExecuteSetup(bad_opts);
    Check(!bad_res.ok && bad_res.exit_code == 2,
          "setup refuses to overwrite malformed existing JSON config");

    samurai::mcp::SetupOptions npx_opts;
    npx_opts.client = "antigravity";
    npx_opts.npx = true;
    npx_opts.yes = false;
    npx_opts.home_override = tmp_root.string();
    npx_opts.project_override = tmp_root.string();
    const auto npx_res = samurai::mcp::ExecuteSetup(npx_opts);
    Check(npx_res.ok && npx_res.report.find("transport_mode")->as_string() == "npx" &&
              npx_res.report.find("proposed_entry")->find("command")->as_string() == "npx",
          "setup --npx generates npx samurai-net transport entry");
    Check(npx_res.report.find("config_path")->as_string() ==
              (tmp_root / ".gemini" / "config" / "mcp_config.json").string(),
          "antigravity setup defaults to ~/.gemini/config/mcp_config.json");
    Check(samurai::mcp::NormalizeClientId("agy") == "antigravity" &&
              samurai::mcp::NormalizeClientId("antigravity-cli") == "antigravity",
          "NormalizeClientId supports agy and antigravity-cli aliases");

    // Verify agy CLI global config (~/.gemini/config/mcp_config.json) overrides empty legacy IDE file
    fs::create_directories(tmp_root / ".gemini" / "antigravity", ec);
    fs::create_directories(tmp_root / ".gemini" / "config", ec);
    {
      std::ofstream legacy_empty(tmp_root / ".gemini" / "antigravity" / "mcp_config.json");
      (void)legacy_empty;
      std::ofstream agy_cfg(tmp_root / ".gemini" / "config" / "mcp_config.json");
      agy_cfg << "{\"mcpServers\":{\"samurai\":{\"command\":\"/usr/local/bin/samurai_mcp\"}}}\n";
    }
    samurai::mcp::DoctorOptions agy_doc_opts;
    agy_doc_opts.client = "agy";
    agy_doc_opts.home_override = tmp_root.string();
    agy_doc_opts.project_override = tmp_root.string();
    const Value agy_doc = samurai::mcp::BuildDoctorReport(agy_doc_opts);
    const Value* agy_clients = agy_doc.find("clients");
    Check(agy_clients && agy_clients->is_array() && agy_clients->elements().size() == 1 &&
              agy_clients->elements()[0].find("registered")->as_bool(false) &&
              agy_clients->elements()[0].find("config_path")->as_string() ==
                  (tmp_root / ".gemini" / "config" / "mcp_config.json").string(),
          "doctor detects registered samurai entry in ~/.gemini/config/mcp_config.json despite empty legacy file");

    // Verify legacy ~/.gemini/antigravity/mcp_config.json fallback when ~/.gemini/config/mcp_config.json has no samurai
    fs::remove_all(tmp_root / ".gemini", ec);
    fs::create_directories(tmp_root / ".gemini" / "antigravity", ec);
    {
      std::ofstream legacy_cfg(tmp_root / ".gemini" / "antigravity" / "mcp_config.json");
      legacy_cfg << "{\"mcpServers\":{\"other\":{\"command\":\"/bin/true\"}}}\n";
    }
    samurai::mcp::SetupOptions legacy_antigravity_opts;
    legacy_antigravity_opts.client = "antigravity";
    legacy_antigravity_opts.binary_override = "/usr/local/bin/samurai_mcp";
    legacy_antigravity_opts.yes = true;
    legacy_antigravity_opts.home_override = tmp_root.string();
    legacy_antigravity_opts.project_override = tmp_root.string();
    const auto legacy_antigravity_res = samurai::mcp::ExecuteSetup(legacy_antigravity_opts);
    Check(legacy_antigravity_res.ok &&
              legacy_antigravity_res.report.find("config_path")->as_string() ==
                  (tmp_root / ".gemini" / "antigravity" / "mcp_config.json").string(),
          "setup falls back to populated legacy ~/.gemini/antigravity/mcp_config.json when ~/.gemini/config/mcp_config.json is absent");

    // Verify Windows host setup resolves APPDATA paths, npx.cmd, and host-gateway Docker args
    samurai::mcp::SetupOptions win_opts;
    win_opts.client = "vscode";
    win_opts.host_os = "windows";
    win_opts.yes = true;
    win_opts.image = "samurai:local-v3.4.0";
    win_opts.home_override = tmp_root.string();
    win_opts.project_override = tmp_root.string();
    win_opts.appdata_override = (tmp_root / "AppData" / "Roaming").string();
    const auto win_res = samurai::mcp::ExecuteSetup(win_opts);
    const Value* win_mode = win_res.report.find("transport_mode");
    const Value* win_os = win_res.report.find("host_os");
    const Value* win_cfg_path = win_res.report.find("config_path");
    const Value* win_entry = win_res.report.find("proposed_entry");
    Check(win_res.ok && win_mode && win_mode->as_string() == "docker" &&
              win_os && win_os->as_string() == "windows",
          "setup --host-os windows defaults to docker transport");
    Check(win_cfg_path &&
              win_cfg_path->as_string() ==
                  (tmp_root / "AppData" / "Roaming" / "Code" / "User" / "mcp.json").string(),
          "setup --host-os windows resolves APPDATA VS Code config path");
    {
      const Value* args_val = win_entry ? win_entry->find("args") : nullptr;
      bool has_gateway = false;
      bool has_local_img = false;
      bool has_cache_vol = false;
      if (args_val && args_val->is_array()) {
        for (const auto& el : args_val->elements()) {
          if (el.as_string() == "host.docker.internal:host-gateway") has_gateway = true;
          if (el.as_string() == "samurai:local-v3.4.0") has_local_img = true;
          if (el.as_string() == "samurai-build-cache:/var/cache/samurai") has_cache_vol = true;
        }
      }
      Check(has_gateway && has_local_img && has_cache_vol,
            "setup --host-os windows injects cache volume, host-gateway, and image tag");
    }

    samurai::mcp::DoctorOptions win_doc_opts;
    win_doc_opts.client = "vscode";
    win_doc_opts.host_os = "windows";
    win_doc_opts.home_override = tmp_root.string();
    win_doc_opts.project_override = tmp_root.string();
    win_doc_opts.appdata_override = (tmp_root / "AppData" / "Roaming").string();
    const Value win_doc = samurai::mcp::BuildDoctorReport(win_doc_opts);
    const Value* win_clients = win_doc.find("clients");
    Check(win_clients && win_clients->is_array() && win_clients->elements().size() == 1 &&
              win_clients->elements()[0].find("registered") &&
              win_clients->elements()[0].find("registered")->as_bool(false),
          "doctor --host-os windows detects APPDATA-registered vscode entry");

    samurai::mcp::SetupOptions win_npx_opts = win_opts;
    win_npx_opts.npx = true;
    win_npx_opts.yes = false;
    win_npx_opts.client = "windsurf";
    const auto win_npx_res = samurai::mcp::ExecuteSetup(win_npx_opts);
    const Value* win_npx_entry = win_npx_res.report.find("proposed_entry");
    const Value* win_npx_cmd = win_npx_entry ? win_npx_entry->find("command") : nullptr;
    Check(win_npx_res.ok && win_npx_cmd && win_npx_cmd->as_string() == "npx.cmd",
          "setup --host-os windows --npx uses npx.cmd");

    fs::remove_all(tmp_root, ec);
  }

  if (g_failures > 0) {
    std::fprintf(stderr, "samurai_mcp selftest: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("samurai_mcp selftest: all checks passed (protocolVersion=%s, tools=%zu, resources=%zu, prompts=%zu)\n",
              samurai::mcp::kProtocolVersion,
              server.ToolCount(),
              server.ResourceCount(),
              server.PromptCount());
  return 0;
}
