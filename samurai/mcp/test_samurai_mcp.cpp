// Native C++17 verification suite for samurai_mcp (protocol, fail-closed safety,
// tool registry, and Closed-Loop Autopilot / Mahoraga RL Agent shield stepping).

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#include "autopilot_tools.hpp"
#include "json.hpp"
#include "protocol.hpp"
#include "safety.hpp"
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
  samurai::mcp::McpServer server;
  samurai::mcp::RegisterAllTools(server, autopilot, safety);

  // 1. Initialize handshake (protocolVersion 2024-11-05)
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
  }

  // 2. Notification produces no response
  {
    const auto notif = server.HandleLine(
        R"({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})");
    Check(!notif.has_value(), "notifications/initialized emits no response");
  }

  // 3. tools/list exposes all 15 modular tools (runtime + Autopilot RL + Scenario Engine)
  {
    const auto line = server.HandleLine(
        R"({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})");
    Check(line.has_value(), "tools/list returns response");
    const auto p = Parse(*line);
    const Value* tools = p.value.find("result")->find("tools");
    Check(tools && tools->is_array() && tools->elements().size() == 15,
          "tools/list returns 15 registered tools");
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

  if (g_failures > 0) {
    std::fprintf(stderr, "samurai_mcp selftest: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("samurai_mcp selftest: all checks passed (protocolVersion=%s, tools=%zu)\n",
              samurai::mcp::kProtocolVersion, server.ToolCount());
  return 0;
}
