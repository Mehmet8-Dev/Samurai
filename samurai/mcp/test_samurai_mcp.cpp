// Native C++17 verification suite for samurai_mcp (protocol, fail-closed safety,
// tool registry, and Closed-Loop Autopilot / Mahoraga RL Agent shield stepping).

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

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
    Check(tools && tools->is_array() && tools->elements().size() == 25,
          "tools/list returns 25 registered tools");

    const auto rline = server.HandleLine(
        R"({"jsonrpc":"2.0","id":201,"method":"resources/list","params":{}})");
    const auto rp = Parse(*rline);
    const Value* resources = rp.value.find("result")->find("resources");
    Check(resources && resources->is_array() && resources->elements().size() == 5,
          "resources/list returns 5 skill resources");

    const struct SkillCheck {
      const char* slug;
      const char* marker;
    } kSkillChecks[] = {
        {"samurai-netbench", "25 native C++17 tools"},
        {"samurai-cluster-orchestrator", "samurai_cluster_run_job"},
        {"samurai-autopilot-rl", "0.2–3600s"},
        {"samurai-scenario-author", "expected_status"},
        {"samurai-hardware-dataplane", "custom_tcp_wire"},
    };
    for (const auto& sc : kSkillChecks) {
      const std::string req = std::string(
          R"({"jsonrpc":"2.0","id":202,"method":"resources/read","params":{"uri":"samurai://skills/)") +
          sc.slug + R"("}})";
      const auto rread = server.HandleLine(req);
      const auto rrp = Parse(*rread);
      const Value* contents = rrp.value.find("result")->find("contents");
      const std::string text = (contents && contents->is_array() && !contents->elements().empty())
                                   ? contents->elements()[0].find("text")->as_string()
                                   : "";
      const std::string msg = std::string("resources/read serves full up-to-date markdown for ") + sc.slug;
      Check(text.size() > 500 && text.find(sc.marker) != std::string::npos, msg.c_str());
    }

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

  // 9. API discovery: fail-closed public rejection + loopback HTTP/OpenAPI discovery + scenario synthesis
  {
    Value bad_disc = Value::Object();
    bad_disc.set("target", Value::Str("8.8.8.8"));
    bool bad_err = false;
    const Value bad_payload = ParseToolPayload(
        CallTool(server, 90, "samurai_discover_apis", std::move(bad_disc)), &bad_err);
    Check(bad_err && bad_payload.find("error") != nullptr,
          "samurai_discover_apis blocks public IPv4 targets fail-closed");

    // Spin up an ephemeral loopback HTTP/1.1 + OpenAPI server on 127.0.0.1:0.
    const int srv_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    Check(srv_fd >= 0, "ephemeral loopback test socket created");
    int yes = 1;
    ::setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in srv_addr{};
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = 0;
    ::inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);
    Check(::bind(srv_fd, reinterpret_cast<sockaddr*>(&srv_addr), sizeof(srv_addr)) == 0,
          "ephemeral loopback test socket bound");
    socklen_t alen = sizeof(srv_addr);
    ::getsockname(srv_fd, reinterpret_cast<sockaddr*>(&srv_addr), &alen);
    const int open_port = ntohs(srv_addr.sin_port);
    Check(::listen(srv_fd, 16) == 0, "ephemeral loopback test socket listening");

    // Reserve a closed port by binding and closing another ephemeral socket.
    int closed_port = 1;
    {
      const int cfd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
      sockaddr_in caddr{};
      caddr.sin_family = AF_INET;
      caddr.sin_port = 0;
      ::inet_pton(AF_INET, "127.0.0.1", &caddr.sin_addr);
      if (cfd >= 0 && ::bind(cfd, reinterpret_cast<sockaddr*>(&caddr), sizeof(caddr)) == 0) {
        socklen_t clen = sizeof(caddr);
        ::getsockname(cfd, reinterpret_cast<sockaddr*>(&caddr), &clen);
        closed_port = ntohs(caddr.sin_port);
      }
      if (cfd >= 0) ::close(cfd);
    }

    std::atomic<bool> stop_srv{false};
    std::thread srv_thread([&]() {
      while (!stop_srv.load()) {
        const int cli = ::accept(srv_fd, nullptr, nullptr);
        if (cli < 0) break;
        char rbuf[2048];
        const ssize_t n = ::recv(cli, rbuf, sizeof(rbuf) - 1, 0);
        if (n > 0) {
          rbuf[n] = '\0';
          const std::string req(rbuf, static_cast<std::size_t>(n));
          std::string resp;
          if (req.find("GET /openapi.json ") != std::string::npos) {
            const std::string body =
                R"({"openapi":"3.0.3","info":{"title":"MockLoopAPI","version":"1.0"},"paths":{"/items":{"get":{"summary":"List items"}},"/orders":{"post":{"summary":"Create order"}}}})";
            resp = "HTTP/1.1 200 OK\r\nServer: SamuraiTest/1.0\r\nContent-Type: application/json\r\nContent-Length: " +
                   std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
          } else if (req.find("GET /health ") != std::string::npos) {
            const std::string body = R"({"status":"ok","service":"mock"})";
            resp = "HTTP/1.1 200 OK\r\nServer: SamuraiTest/1.0\r\nContent-Type: application/json\r\nContent-Length: " +
                   std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
          } else {
            const std::string body = R"({"error":"not found"})";
            resp = "HTTP/1.1 404 Not Found\r\nServer: SamuraiTest/1.0\r\nContent-Type: application/json\r\nContent-Length: " +
                   std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
          }
          (void)::send(cli, resp.data(), resp.size(), MSG_NOSIGNAL);
        }
        ::close(cli);
      }
    });

    Value disc_args = Value::Object();
    disc_args.set("target", Value::Str("127.0.0.1"));
    Value ports_arr = Value::Array();
    ports_arr.push_back(Value::Int(open_port));
    ports_arr.push_back(Value::Int(closed_port));
    disc_args.set("ports", std::move(ports_arr));
    Value paths_arr = Value::Array();
    paths_arr.push_back(Value::Str("/health"));
    disc_args.set("probe_paths", std::move(paths_arr));
    disc_args.set("replace_default_paths", Value::Bool(true));

    bool disc_err = false;
    const Value disc_res = ParseToolPayload(
        CallTool(server, 91, "samurai_discover_apis", std::move(disc_args)), &disc_err);

    stop_srv.store(true);
    ::shutdown(srv_fd, SHUT_RDWR);
    ::close(srv_fd);
    if (srv_thread.joinable()) srv_thread.join();

    Check(!disc_err, "samurai_discover_apis succeeds on loopback target");
    Check(disc_res.find("endpoints_checked")->as_int() == 2 &&
              disc_res.find("tcp_open_count")->as_int() == 1,
          "samurai_discover_apis distinguishes open vs closed ports");
    const Value* svcs = disc_res.find("services");
    Check(svcs && svcs->is_array() && svcs->elements().size() == 2,
          "services array has 2 entries");
    if (svcs && svcs->elements().size() == 2) {
      const Value& open_svc = svcs->elements()[0];
      const Value& closed_svc = svcs->elements()[1];
      Check(open_svc.find("tcp_open")->as_bool() == true &&
                closed_svc.find("tcp_open")->as_bool() == false,
            "open and closed TCP status reported accurately");
      const Value* oa = open_svc.find("openapi");
      Check(oa && oa->find("title")->as_string() == "MockLoopAPI" &&
                oa->find("endpoint_count")->as_int() == 2,
            "OpenAPI spec parsed and 2 endpoints extracted");
      const Value* rec_sc = open_svc.find("recommended_scenario");
      Check(rec_sc && rec_sc->is_object(), "recommended_scenario generated");
      if (rec_sc && rec_sc->is_object()) {
        Value comp_args = Value::Object();
        comp_args.set("scenario", *rec_sc);
        bool comp_err = false;
        const Value comp_res = ParseToolPayload(
            CallTool(server, 92, "samurai_scenario_compile", std::move(comp_args)), &comp_err);
        Check(!comp_err && comp_res.find("valid")->as_bool() == true,
              "generated recommended_scenario compiles cleanly via samurai_scenario_compile");
      }
    }

    // Verify fingerprinting avoids MinIO/OSRM false positives on whoami/echo and HTTPS plain-HTTP rejection.
    const int fp_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    Check(fp_fd >= 0, "fingerprint test socket created");
    int fp_yes = 1;
    ::setsockopt(fp_fd, SOL_SOCKET, SO_REUSEADDR, &fp_yes, sizeof(fp_yes));
    sockaddr_in fp_addr{};
    fp_addr.sin_family = AF_INET;
    fp_addr.sin_port = 0;
    ::inet_pton(AF_INET, "127.0.0.1", &fp_addr.sin_addr);
    Check(::bind(fp_fd, reinterpret_cast<sockaddr*>(&fp_addr), sizeof(fp_addr)) == 0 && ::listen(fp_fd, 16) == 0,
          "fingerprint test socket bound and listening");
    socklen_t fp_alen = sizeof(fp_addr);
    ::getsockname(fp_fd, reinterpret_cast<sockaddr*>(&fp_addr), &fp_alen);
    const int fp_port = ntohs(fp_addr.sin_port);

    std::atomic<bool> stop_fp{false};
    std::thread fp_thread([&]() {
      while (!stop_fp.load()) {
        const int cli = ::accept(fp_fd, nullptr, nullptr);
        if (cli < 0) break;
        char rbuf[2048];
        const ssize_t n = ::recv(cli, rbuf, sizeof(rbuf) - 1, 0);
        if (n > 0) {
          rbuf[n] = '\0';
          const std::string req(rbuf, static_cast<std::size_t>(n));
          std::string resp;
          if (req.find("GET /nearest/") != std::string::npos || req.find("GET / ") != std::string::npos) {
            const std::string body = "Hostname: abc123\nIP: 127.0.0.1\nRemoteAddr: 127.0.0.1:9999\nGET / HTTP/1.1\r\n\r\n";
            resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: " +
                   std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
          } else {
            const std::string body = "Hostname: abc123\nIP: 127.0.0.1\nRemoteAddr: 127.0.0.1:9999\n";
            resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: " +
                   std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
          }
          (void)::send(cli, resp.data(), resp.size(), MSG_NOSIGNAL);
        }
        ::close(cli);
      }
    });

    Value fp_args = Value::Object();
    fp_args.set("target", Value::Str("127.0.0.1"));
    Value fp_ports = Value::Array();
    fp_ports.push_back(Value::Int(fp_port));
    fp_args.set("ports", std::move(fp_ports));
    fp_args.set("probe_openapi", Value::Bool(false));
    fp_args.set("generate_scenario", Value::Bool(false));
    fp_args.set("include_body_preview", Value::Bool(false));
    bool fp_err = false;
    const Value fp_res = ParseToolPayload(
        CallTool(server, 93, "samurai_discover_apis", std::move(fp_args)), &fp_err);
    stop_fp.store(true);
    ::shutdown(fp_fd, SHUT_RDWR);
    ::close(fp_fd);
    if (fp_thread.joinable()) fp_thread.join();

    Check(!fp_err, "fingerprint loopback discovery succeeds");
    const Value* fp_svcs = fp_res.find("services");
    if (fp_svcs && fp_svcs->is_array() && !fp_svcs->elements().empty()) {
      const std::string fp_label = fp_svcs->elements()[0].find("service_fingerprint")->as_string();
      Check(fp_label == "HTTP Echo / whoami Service",
            "whoami catch-all 200 on /minio/health/live not mislabeled as MinIO");
    }
  }

  // 10. Scenario compile fidelity: kind=end_session, token metadata, expect_status in plans_by_worker
  {
    const auto sc_plan = Parse(R"JSON({
      "scenario": {
        "schema_version": 1,
        "protocol": "http1",
        "personas": {"u": {"device_profile": "web", "weight": 1}},
        "flows": {
          "f": {
            "persona": "u",
            "steps": [
              {"kind": "request", "method": "POST", "path": "/login", "extract_token_regex": "(eyJ[A-Za-z0-9._-]+)", "token_variable_name": "jwt", "expected_status": 200},
              {"kind": "request", "method": "GET", "path": "/me", "expected_status": [200, 299]},
              {"kind": "end_session"}
            ]
          }
        },
        "load_model": {"backend": "l7", "concurrent_vus": 1}
      },
      "workers": 1,
      "sessions_per_worker": 1,
      "include_plans": true
    })JSON");
    bool err = false;
    const Value out = ParseToolPayload(
        CallTool(server, 94, "samurai_scenario_compile", sc_plan.value), &err);
    Check(!err && out.find("valid")->as_bool() == true, "compile with kind/expected_status/regex succeeds");
    const Value* pbw = out.find("plans_by_worker");
    Check(pbw && pbw->is_array() && !pbw->elements().empty(), "plans_by_worker returned");
    if (pbw && pbw->is_array() && !pbw->elements().empty() &&
        pbw->elements()[0].is_array() && !pbw->elements()[0].elements().empty()) {
      const Value& w0 = pbw->elements()[0].elements()[0];
      const Value* paths = w0.find("path");
      Check(paths && paths->is_array() && paths->elements().size() == 2,
            "kind=end_session terminates flow without emitting spurious GET /");
      const Value* regs = w0.find("extract_token_regex");
      const Value* tvars = w0.find("token_variable_name");
      const Value* emin = w0.find("expect_status_min");
      const Value* emax = w0.find("expect_status_max");
      Check(regs && regs->is_array() && regs->elements().size() == 2 &&
                regs->elements()[0].as_string() == "(eyJ[A-Za-z0-9._-]+)",
            "extract_token_regex surfaced in compiled plan");
      Check(tvars && tvars->is_array() && tvars->elements()[0].as_string() == "jwt",
            "token_variable_name surfaced in compiled plan");
      Check(emin && emax && emin->elements()[0].as_int() == 200 && emax->elements()[1].as_int() == 299,
            "expect_status_min/max surfaced in compiled plan");
    }
  }

  // 11. Live scenario_run e2e: HTTP status telemetry, expected_status assertion failure,
  //     extract_token_regex JWT carry, report schema labels, and L4 raw TCP execution.
  {
    const int e2e_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    Check(e2e_fd >= 0, "e2e loopback socket created");
    int e2e_yes = 1;
    ::setsockopt(e2e_fd, SOL_SOCKET, SO_REUSEADDR, &e2e_yes, sizeof(e2e_yes));
    sockaddr_in e2e_addr{};
    e2e_addr.sin_family = AF_INET;
    e2e_addr.sin_port = 0;
    ::inet_pton(AF_INET, "127.0.0.1", &e2e_addr.sin_addr);
    Check(::bind(e2e_fd, reinterpret_cast<sockaddr*>(&e2e_addr), sizeof(e2e_addr)) == 0 && ::listen(e2e_fd, 16) == 0,
          "e2e loopback socket bound and listening");
    socklen_t e2e_alen = sizeof(e2e_addr);
    ::getsockname(e2e_fd, reinterpret_cast<sockaddr*>(&e2e_addr), &e2e_alen);
    const int e2e_port = ntohs(e2e_addr.sin_port);

    std::atomic<bool> saw_bearer{false};
    std::atomic<bool> stop_e2e{false};
    std::thread e2e_thread([&]() {
      while (!stop_e2e.load()) {
        const int cli = ::accept(e2e_fd, nullptr, nullptr);
        if (cli < 0) break;
        char rbuf[4096];
        while (true) {
          const ssize_t n = ::recv(cli, rbuf, sizeof(rbuf) - 1, 0);
          if (n <= 0) break;
          rbuf[n] = '\0';
          const std::string req(rbuf, static_cast<std::size_t>(n));
          std::string resp;
          if (req.rfind("PING", 0) == 0) {
            resp = "+PONG\r\n";
          } else if (req.find("POST /login ") != std::string::npos) {
            const std::string body = R"({"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"})";
            resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                   std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
          } else if (req.find("GET /me ") != std::string::npos) {
            if (req.find("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig") != std::string::npos) {
              saw_bearer.store(true);
              const std::string body = R"({"ok":true})";
              resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                     std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
            } else {
              const std::string body = R"({"error":"unauthorized"})";
              resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: " +
                     std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
            }
          } else {
            const std::string body = R"({"error":"denied"})";
            resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: " +
                   std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
          }
          (void)::send(cli, resp.data(), resp.size(), MSG_NOSIGNAL);
          if (req.rfind("PING", 0) != 0) break;
        }
        ::close(cli);
      }
    });

    // 11a. Regex token extraction + expected_status=200 passing + report target protocol/vector
    const auto regex_run = Parse(std::string(R"JSON({
      "target": "127.0.0.1",
      "port": )JSON") + std::to_string(e2e_port) + R"JSON(,
      "count": 4,
      "timeout_s": 10,
      "scenario": {
        "schema_version": 1,
        "protocol": "http1",
        "personas": {"u": {"device_profile": "web", "weight": 1}},
        "flows": {
          "auth": {
            "persona": "u",
            "steps": [
              {"kind": "request", "method": "POST", "path": "/login", "body_template": "{}", "extract_token_regex": "(eyJ[A-Za-z0-9_.-]+)", "token_variable_name": "jwt", "expected_status": 200},
              {"kind": "request", "method": "GET", "path": "/me", "headers": {"Authorization": "Bearer {{jwt}}"}, "expected_status": 200},
              {"kind": "end_session"}
            ]
          }
        },
        "load_model": {"backend": "l7", "concurrent_vus": 1},
        "sla": {"min_completion_rate": 0.95, "max_step_fail_ratio": 0.05, "max_latency_p95_ms": 500}
      }
    })JSON");
    bool err_a = false;
    const Value res_a = ParseToolPayload(
        CallTool(server, 95, "samurai_scenario_run", regex_run.value), &err_a);
    Check(!err_a && res_a.find("exit_code")->as_int() == 0, "regex JWT scenario_run exits 0");
    Check(saw_bearer.load(), "extract_token_regex extracted JWT and carried Bearer header on wire");
    if (const Value* rep = res_a.find("report"); rep && rep->is_object()) {
      const Value* tgt = rep->find("target");
      Check(tgt && tgt->find("protocol")->as_string() == "http1" &&
                tgt->find("attack_vector")->as_string() == "scenario",
            "report.target reports protocol=http1 and attack_vector=scenario");
    }
    if (const Value* tel = res_a.find("scenario_telemetry"); tel && tel->is_object()) {
      Check(tel->find("status_2xx")->as_int() == 2 &&
                tel->find("expectation_failures")->as_int() == 0 &&
                tel->find("scenario_sla_passed")->as_int() == 1,
            "scenario_telemetry reports status_2xx=2, expectation_failures=0, sla_passed=1");
    } else {
      Check(false, "scenario_telemetry object present on HTTP scenario_run");
    }

    // 11b. expected_status=200 on 401 endpoint must fail assertion and SLA
    const auto fail_run = Parse(std::string(R"({
      "target": "127.0.0.1",
      "port": )") + std::to_string(e2e_port) + R"(,
      "count": 2,
      "timeout_s": 10,
      "scenario": {
        "schema_version": 1,
        "protocol": "http1",
        "personas": {"u": {"device_profile": "web", "weight": 1}},
        "flows": {
          "unauth": {
            "persona": "u",
            "steps": [
              {"kind": "request", "method": "GET", "path": "/me", "expected_status": 200}
            ]
          }
        },
        "load_model": {"backend": "l7", "concurrent_vus": 1},
        "sla": {"min_completion_rate": 0.95, "max_step_fail_ratio": 0.05, "max_latency_p95_ms": 500}
      }
    })");
    bool err_b = false;
    const Value res_b = ParseToolPayload(
        CallTool(server, 96, "samurai_scenario_run", fail_run.value), &err_b);
    Check(!err_b, "401 assertion scenario_run completes");
    if (const Value* tel = res_b.find("scenario_telemetry"); tel && tel->is_object()) {
      Check(tel->find("status_4xx")->as_int() == 1 &&
                tel->find("expectation_failures")->as_int() >= 1 &&
                tel->find("step_failed")->as_int() >= 1 &&
                tel->find("scenario_sla_passed")->as_int() == 0,
            "401 with expected_status=200 reports status_4xx=1, expectation_failures>=1, sla_passed=0");
    } else {
      Check(false, "scenario_telemetry present on 401 assertion test");
    }

    // 11c. L4 TCP scenario execution (tcp_connect -> tcp_send -> tcp_expect -> tcp_close)
    const auto l4_run = Parse(std::string(R"({
      "target": "127.0.0.1",
      "port": )") + std::to_string(e2e_port) + R"(,
      "count": 10,
      "timeout_s": 10,
      "scenario": {
        "schema_version": 1,
        "protocol": "tcp",
        "personas": {"tcp_u": {"device_profile": "web", "weight": 1}},
        "flows": {
          "ping": {
            "persona": "tcp_u",
            "steps": [
              {"kind": "tcp_connect"},
              {"kind": "tcp_send", "payload_template": "PING\r\n"},
              {"kind": "tcp_expect", "condition": "+PONG"},
              {"kind": "tcp_close"}
            ]
          }
        },
        "load_model": {"backend": "l7", "concurrent_vus": 2},
        "sla": {"min_completion_rate": 0.95, "max_step_fail_ratio": 0.05, "max_latency_p95_ms": 500}
      }
    })");
    bool err_c = false;
    const Value res_c = ParseToolPayload(
        CallTool(server, 97, "samurai_scenario_run", l4_run.value), &err_c);
    Check(!err_c && res_c.find("exit_code")->as_int() == 0, "L4 TCP scenario_run exits 0");
    if (const Value* rep = res_c.find("report"); rep && rep->is_object()) {
      const Value* tgt = rep->find("target");
      Check(tgt && tgt->find("protocol")->as_string() == "tcp" &&
                tgt->find("attack_vector")->as_string() == "scenario",
            "L4 TCP report.target reports protocol=tcp and attack_vector=scenario");
    }
    if (const Value* tel = res_c.find("scenario_telemetry"); tel && tel->is_object()) {
      Check(tel->find("scenario_dataplane")->as_string() == "l4_tcp_native_real_socket" &&
                tel->find("tcp_connect_attempts")->as_int() == 2 &&
                tel->find("tcp_connect_established")->as_int() == 2 &&
                tel->find("step_failed")->as_int() == 0 &&
                tel->find("scenario_sla_passed")->as_int() == 1,
            "L4 TCP scenario_telemetry reports 2/2 connects, 0 failed, sla_passed=1");
    } else {
      Check(false, "scenario_telemetry present on L4 TCP scenario_run");
    }

    // 11d. Time-based enterprise soak execution (duration_s loops rounds cleanly)
    const auto soak_run = Parse(std::string(R"JSON({
      "target": "127.0.0.1",
      "port": )JSON") + std::to_string(e2e_port) + R"JSON(,
      "count": 1000000,
      "duration_s": 0.6,
      "timeout_s": 15,
      "scenario": {
        "schema_version": 1,
        "protocol": "http1",
        "personas": {"u": {"device_profile": "web", "weight": 1}},
        "flows": {
          "soak_ping": {
            "persona": "u",
            "steps": [
              {"kind": "request", "method": "POST", "path": "/login", "body_template": "{}", "extract_token_regex": "(eyJ[A-Za-z0-9_.-]+)", "token_variable_name": "jwt", "expected_status": 200},
              {"kind": "request", "method": "GET", "path": "/me", "headers": {"Authorization": "Bearer {{jwt}}"}, "expected_status": 200}
            ]
          }
        },
        "load_model": {"backend": "l7", "concurrent_vus": 1, "duration_s": 0.6},
        "sla": {"min_completion_rate": 0.95, "max_step_fail_ratio": 0.05, "max_latency_p95_ms": 500}
      }
    })JSON");
    bool err_d = false;
    const Value res_d = ParseToolPayload(
        CallTool(server, 98, "samurai_scenario_run", soak_run.value), &err_d);
    Check(!err_d && res_d.find("exit_code")->as_int() == 0, "duration_s soak scenario_run exits 0");
    if (const Value* tel = res_d.find("scenario_telemetry"); tel && tel->is_object()) {
      Check(tel->find("soak_rounds") && tel->find("soak_rounds")->as_int() >= 2 &&
                tel->find("status_2xx")->as_int() >= 4 &&
                tel->find("elapsed_s") && tel->find("elapsed_s")->as_double() >= 0.45 &&
                tel->find("scenario_sla_passed")->as_int() == 1,
            "duration_s soak executed multiple rounds with aggregated 2xx telemetry and passing SLA");
    } else {
      Check(false, "scenario_telemetry present on duration_s soak run");
    }

    // 11e. Async background soak job launch + status + graceful stop
    const auto async_run = Parse(std::string(R"JSON({
      "target": "127.0.0.1",
      "port": )JSON") + std::to_string(e2e_port) + R"JSON(,
      "count": 1000000,
      "duration_s": 8.0,
      "timeout_s": 30,
      "async": true,
      "scenario": {
        "schema_version": 1,
        "protocol": "http1",
        "personas": {"u": {"device_profile": "web", "weight": 1}},
        "flows": {
          "long_soak": {
            "persona": "u",
            "steps": [
              {"kind": "request", "method": "POST", "path": "/login", "body_template": "{}", "expected_status": 200},
              {"kind": "pause", "think_time": {"min_ms": 50, "max_ms": 50}}
            ]
          }
        },
        "load_model": {"backend": "l7", "concurrent_vus": 1}
      }
    })JSON");
    bool err_async = false;
    const Value async_start = ParseToolPayload(
        CallTool(server, 99, "samurai_scenario_run", async_run.value), &err_async);
    const std::string job_id = async_start.find("job_id") ? async_start.find("job_id")->as_string() : "";
    Check(!err_async && async_start.find("async")->as_bool(false) &&
              async_start.find("status")->as_string() == "running" && !job_id.empty(),
          "async=true scenario_run starts background job immediately");
    if (!job_id.empty()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(150));
      Value st_args = Value::Object();
      st_args.set("job_id", Value::Str(job_id));
      bool err_st = false;
      const Value st_res = ParseToolPayload(
          CallTool(server, 100, "samurai_job_status", std::move(st_args)), &err_st);
      Check(!err_st && st_res.find("job_id")->as_string() == job_id,
            "samurai_job_status reports active async job");

      Value stop_args = Value::Object();
      stop_args.set("job_id", Value::Str(job_id));
      bool err_stop = false;
      const Value stop_res = ParseToolPayload(
          CallTool(server, 101, "samurai_job_stop", std::move(stop_args)), &err_stop);
      Check(!err_stop && stop_res.find("status")->as_string() == "stopped",
            "samurai_job_stop terminates background soak job cleanly");
    }

    stop_e2e.store(true);
    ::shutdown(e2e_fd, SHUT_RDWR);
    ::close(e2e_fd);
    if (e2e_thread.joinable()) e2e_thread.join();
  }

  // 12. Per-call allow_target / allow_targets, denylist precedence & enterprise soak limits
  {
    samurai::mcp::SafetyConfig base;
    Check(base.max_timeout_s == 86400 && base.max_packet_count == 100000000ULL,
          "Default MCP SafetyConfig supports 24h timeout and 100M count");

    // Still fail-closed without allow_target
    std::string resolved;
    Check(!samurai::mcp::ResolveMcpTarget("203.0.113.10", base, resolved).ok,
          "Public IP remains fail-closed without allow_target");
    Check(!samurai::mcp::ResolveMcpTarget("api.example.com", base, resolved).ok,
          "Public domain remains fail-closed without allow_target");

    // Per-call allow_target + allow_targets authorize explicit IP/CIDR
    const auto auth_args = Parse(R"({"allow_target":"203.0.113.10","allow_targets":["198.51.100.0/24","*.corp.example.com"]})");
    std::string eff_err;
    const auto eff = samurai::mcp::EffectiveSafetyConfig(auth_args.value, base, &eff_err);
    Check(eff_err.empty(), "Valid per-call allow_target/allow_targets accepted cleanly");
    Check(samurai::mcp::ResolveMcpTarget("203.0.113.10", eff, resolved).ok && resolved == "203.0.113.10",
          "Explicit allow_target IPv4 succeeds");
    Check(samurai::mcp::ResolveMcpTarget("198.51.100.42", eff, resolved).ok && resolved == "198.51.100.42",
          "Explicit allow_targets CIDR succeeds");
    Check(!samurai::mcp::ResolveMcpTarget("8.8.8.8", eff, resolved).ok,
          "Unlisted public IP still blocked even when other allow_target is given");

    // Wildcard bypasses must be rejected
    const auto wild_args = Parse(R"({"allow_target":"0.0.0.0/0"})");
    std::string wild_err;
    (void)samurai::mcp::EffectiveSafetyConfig(wild_args.value, base, &wild_err);
    Check(!wild_err.empty(), "Wildcard 0.0.0.0/0 allow_target is rejected");

    // Denylist always wins over per-call allow_target
    samurai::mcp::SafetyConfig denied_base = base;
    denied_base.deny_targets.push_back("203.0.113.10");
    denied_base.deny_targets.push_back("*.blocked.example");
    const auto deny_test_args = Parse(R"({"allow_target":"203.0.113.10","allow_targets":["app.blocked.example"]})");
    const auto eff_denied = samurai::mcp::EffectiveSafetyConfig(deny_test_args.value, denied_base);
    Check(!samurai::mcp::ResolveMcpTarget("203.0.113.10", eff_denied, resolved).ok,
          "SAMURAI_MCP_DENY_TARGETS overrides per-call allow_target IP");
    Check(!samurai::mcp::ResolveMcpTarget("app.blocked.example", eff_denied, resolved).ok,
          "SAMURAI_MCP_DENY_TARGETS overrides per-call allow_target domain");

    // AppendSafetyCliArgs forwards IPv4/CIDR and resolved hostname IPv4 without raw domain strings
    std::vector<std::string> cli_cmd;
    samurai::mcp::AppendSafetyCliArgs(eff, cli_cmd, "93.184.216.34");
    bool has_cidr = false, has_resolved = false, has_wildcard_domain = false;
    for (std::size_t i = 0; i + 1 < cli_cmd.size(); ++i) {
      if (cli_cmd[i] == "--allow-target") {
        if (cli_cmd[i + 1] == "198.51.100.0/24") has_cidr = true;
        if (cli_cmd[i + 1] == "93.184.216.34") has_resolved = true;
        if (cli_cmd[i + 1] == "*.corp.example.com") has_wildcard_domain = true;
      }
    }
    Check(has_cidr && has_resolved && !has_wildcard_domain,
          "AppendSafetyCliArgs emits valid IPv4/CIDR + resolved IPv4 only");

    // High/unlimited packet count validation
    std::string cerr;
    Check(samurai::mcp::ValidateMcpPacketCount(5000000, base, &cerr),
          "ValidateMcpPacketCount permits >500k requests cleanly");
    samurai::mcp::SafetyConfig unlimited = base;
    unlimited.max_packet_count = 0;
    Check(samurai::mcp::ValidateMcpPacketCount(4294967295LL, unlimited, &cerr),
          "max_packet_count=0 permits full uint32 count");
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
