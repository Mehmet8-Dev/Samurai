#include "scenario_tools.hpp"

#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "compiler.hpp"
#include "runtime_tools.hpp"
#include "scheduler.hpp"
#include "sla.hpp"

namespace samurai::mcp {

namespace {

using samurai::core::json::Parse;
using samurai::core::json::Value;

std::string ReadFileToString(const std::string& path, bool* ok = nullptr) {
  std::ifstream in(path);
  if (!in.is_open()) {
    if (ok) *ok = false;
    return "";
  }
  std::ostringstream oss;
  oss << in.rdbuf();
  if (ok) *ok = true;
  return oss.str();
}

// Loads a scenario JSON Value from either `args.scenario` (object/JSON string)
// or `args.scenario_file` (path). Returns error string on failure.
std::string LoadScenarioDoc(const Value& args, Value& out_doc, std::string* out_raw_json = nullptr) {
  if (const Value* sc = args.find("scenario"); sc && sc->is_object()) {
    out_doc = *sc;
    if (out_raw_json) *out_raw_json = sc->dump();
    return "";
  }
  if (const Value* sc_str = args.find("scenario"); sc_str && sc_str->is_string()) {
    const auto parsed = Parse(sc_str->as_string());
    if (!parsed.ok || !parsed.value.is_object()) {
      return "Invalid inline scenario JSON string: " + parsed.error;
    }
    out_doc = parsed.value;
    if (out_raw_json) *out_raw_json = sc_str->as_string();
    return "";
  }
  if (const Value* sf = args.find("scenario_file"); sf && sf->is_string() && !sf->as_string().empty()) {
    bool ok = false;
    const std::string raw = ReadFileToString(sf->as_string(), &ok);
    if (!ok) {
      return "Unable to read scenario_file: " + sf->as_string();
    }
    const auto parsed = Parse(raw);
    if (!parsed.ok || !parsed.value.is_object()) {
      return "Invalid JSON in scenario_file '" + sf->as_string() + "': " + parsed.error;
    }
    out_doc = parsed.value;
    if (out_raw_json) *out_raw_json = raw;
    return "";
  }
  return "Either 'scenario' (JSON object) or 'scenario_file' (path) is required.";
}

Value SummarizeSpec(const samurai::scenario_native::ScenarioSpecNative& spec) {
  Value personas = Value::Array();
  for (const auto& kv : spec.personas) {
    Value p = Value::Object();
    p.set("name", Value::Str(kv.first));
    p.set("device_profile", Value::Str(kv.second.device_profile));
    p.set("weight", Value::Double(kv.second.weight));
    p.set("request_timeout_ms", Value::Int(kv.second.request_timeout_ms));
    p.set("max_retries", Value::Int(kv.second.max_retries));
    personas.push_back(std::move(p));
  }

  Value flows = Value::Array();
  std::size_t total_steps = 0;
  for (const auto& f : spec.flows) {
    Value fo = Value::Object();
    fo.set("name", Value::Str(f.name));
    fo.set("persona", Value::Str(f.persona));
    fo.set("step_count", Value::Int(static_cast<std::int64_t>(f.steps.size())));
    total_steps += f.steps.size();
    flows.push_back(std::move(fo));
  }

  Value lm = Value::Object();
  lm.set("backend", Value::Str(spec.load_model.backend));
  lm.set("concurrent_vus", Value::Int(spec.load_model.concurrent_vus));
  lm.set("ramp_seconds", Value::Int(spec.load_model.ramp_seconds));

  Value summary = Value::Object();
  summary.set("persona_count", Value::Int(static_cast<std::int64_t>(spec.personas.size())));
  summary.set("flow_count", Value::Int(static_cast<std::int64_t>(spec.flows.size())));
  summary.set("total_steps", Value::Int(static_cast<std::int64_t>(total_steps)));
  summary.set("load_model", std::move(lm));
  summary.set("personas", std::move(personas));
  summary.set("flows", std::move(flows));
  return summary;
}

}  // namespace

ToolResult HandleScenarioCompile(const Value& args) {
  Value doc;
  const std::string load_err = LoadScenarioDoc(args, doc);
  if (!load_err.empty()) {
    return MakeToolError(load_err);
  }

  try {
    const auto spec = samurai::scenario_native::parse_spec(doc);
    if (spec.flows.empty()) {
      return MakeToolError("Scenario spec parsed with 0 flows. Provide a non-empty 'flows' map.");
    }

    const int workers = std::clamp(
        static_cast<int>(args.find("workers") ? args.find("workers")->as_int(1) : 1), 1, 64);
    const int sessions_per_worker = std::clamp(
        static_cast<int>(args.find("sessions_per_worker") ? args.find("sessions_per_worker")->as_int(2) : 2),
        1, 256);
    const std::uint64_t seed = static_cast<std::uint64_t>(
        args.find("seed") ? args.find("seed")->as_int(42) : 42);
    const bool include_plans = args.find("include_plans") ? args.find("include_plans")->as_bool(false) : false;

    std::vector<int> counts(static_cast<std::size_t>(workers), sessions_per_worker);
    const Value compiled = samurai::scenario_native::build_worker_session_plans_native(spec, counts, seed);

    Value out = Value::Object();
    out.set("valid", Value::Bool(true));
    out.set("summary", SummarizeSpec(spec));
    out.set("workers", Value::Int(workers));
    out.set("sessions_per_worker", Value::Int(sessions_per_worker));
    out.set("seed", Value::Int(static_cast<std::int64_t>(seed)));
    if (const Value* m = compiled.find("metrics")) {
      out.set("compiler_metrics", *m);
    }
    if (include_plans) {
      if (const Value* plans = compiled.find("plans_by_worker")) {
        out.set("plans_by_worker", *plans);
      }
    }
    return MakeToolSuccess(std::move(out));
  } catch (const std::exception& ex) {
    return MakeToolError(std::string("Scenario compilation failed: ") + ex.what());
  }
}

ToolResult HandleScenarioRun(const Value& args, const SafetyConfig& safety) {
  const std::string bin = FindNativeBinary({"samurai"});
  if (bin.empty()) {
    return MakeToolError("samurai CLI binary not found. Build via CMake first.");
  }

  const std::string target = args.find("target") ? args.find("target")->as_string("127.0.0.1") : "127.0.0.1";
  const auto chk = ValidateMcpTarget(target, safety);
  if (!chk.ok) {
    return MakeToolError("Target blocked by fail-closed MCP safety gate: " + chk.reason);
  }

  const std::int64_t port = args.find("port") ? args.find("port")->as_int(8080) : 8080;
  if (port < 1 || port > 65535) {
    return MakeToolError("port must be between 1 and 65535");
  }

  const std::int64_t count = args.find("count") ? args.find("count")->as_int(100) : 100;
  if (count < 1 || static_cast<std::uint64_t>(count) > safety.max_packet_count) {
    return MakeToolError("count must be between 1 and " + std::to_string(safety.max_packet_count));
  }

  const int timeout_s = std::clamp(
      static_cast<int>(args.find("timeout_s") ? args.find("timeout_s")->as_int(30) : 30),
      5, safety.max_timeout_s);

  Value doc;
  std::string raw_json;
  const std::string load_err = LoadScenarioDoc(args, doc, &raw_json);
  if (!load_err.empty()) {
    return MakeToolError(load_err);
  }

  // Validate spec in-process via native compiler before launching dataplane worker.
  Value spec_summary;
  try {
    const auto spec = samurai::scenario_native::parse_spec(doc);
    if (spec.flows.empty()) {
      return MakeToolError("Scenario spec has 0 flows.");
    }
    spec_summary = SummarizeSpec(spec);
  } catch (const std::exception& ex) {
    return MakeToolError(std::string("Scenario validation failed before run: ") + ex.what());
  }

  std::string scenario_path;
  bool remove_temp_scenario = false;
  if (const Value* sf = args.find("scenario_file");
      sf && sf->is_string() && !sf->as_string().empty() && !args.find("scenario")) {
    scenario_path = sf->as_string();
  } else {
    char stm[] = "/tmp/samurai_mcp_scenario_XXXXXX";
    const int sfd = ::mkstemp(stm);
    if (sfd < 0) return MakeToolError("Failed to create temporary scenario file");
    ::close(sfd);
    scenario_path = stm;
    remove_temp_scenario = true;
    std::ofstream out_f(scenario_path, std::ios::binary);
    out_f << raw_json;
    out_f.close();
  }

  char rtm[] = "/tmp/samurai_mcp_scn_report_XXXXXX";
  const int rfd = ::mkstemp(rtm);
  if (rfd < 0) {
    if (remove_temp_scenario) ::unlink(scenario_path.c_str());
    return MakeToolError("Failed to create temporary report file");
  }
  ::close(rfd);
  const std::string report_path(rtm);

  std::vector<std::string> cmd = {
      bin,
      "--worker", "scenario",
      "--target", target,
      "--port", std::to_string(port),
      "--count", std::to_string(count),
      "--l7-profile-file", scenario_path,
      "--report-json", report_path,
      "--confirm",
  };

  if (const Value* rps = args.find("rps"); rps && rps->is_number() && rps->as_double(0.0) > 0.0) {
    cmd.push_back("--rps");
    cmd.push_back(std::to_string(rps->as_double(0.0)));
  }
  if (const Value* conc = args.find("concurrency"); conc && conc->is_number() && conc->as_int(0) > 0) {
    cmd.push_back("--concurrency");
    cmd.push_back(std::to_string(conc->as_int(1)));
  }

  const auto res = RunSubprocess(cmd, timeout_s);
  const std::string report_raw = ReadFileToString(report_path);
  ::unlink(report_path.c_str());
  if (remove_temp_scenario) ::unlink(scenario_path.c_str());

  Value out = Value::Object();
  out.set("host", HostMetadataJson());
  out.set("scenario_summary", std::move(spec_summary));
  out.set("exit_code", Value::Int(res.exit_code));
  out.set("timed_out", Value::Bool(res.timed_out));
  if (!report_raw.empty()) {
    const auto parsed = Parse(report_raw);
    out.set("report", parsed.ok ? parsed.value : Value::Str(report_raw));
  } else {
    out.set("report", Value::Null());
  }
  out.set("stdout", Value::Str(res.stdout_text));
  out.set("stderr", Value::Str(res.stderr_text));
  return MakeToolSuccess(std::move(out));
}

ToolResult HandleScenarioEvaluateSla(const Value& args) {
  const Value* sla = args.find("sla");
  if (!sla || !sla->is_object()) {
    return MakeToolError("'sla' JSON object is required (e.g. min_completion_rate, max_step_fail_ratio, max_latency_p95_ms).");
  }

  const int sessions_started = static_cast<int>(args.find("sessions_started") ? args.find("sessions_started")->as_int(0) : 0);
  const int sessions_completed = static_cast<int>(args.find("sessions_completed") ? args.find("sessions_completed")->as_int(0) : 0);
  const int step_attempted = static_cast<int>(args.find("step_attempted") ? args.find("step_attempted")->as_int(0) : 0);
  const int step_failed = static_cast<int>(args.find("step_failed") ? args.find("step_failed")->as_int(0) : 0);

  const Value* p95_val = args.find("latency_p95_ms");
  const bool has_latency = (p95_val && p95_val->is_number() && p95_val->as_double(-1.0) >= 0.0);
  const double latency_p95_ms = has_latency ? p95_val->as_double(0.0) : 0.0;

  const int tcp_connect_attempts = static_cast<int>(args.find("tcp_connect_attempts") ? args.find("tcp_connect_attempts")->as_int(0) : 0);
  const int tcp_connect_established = static_cast<int>(args.find("tcp_connect_established") ? args.find("tcp_connect_established")->as_int(0) : 0);
  const int tcp_retransmit_count = static_cast<int>(args.find("tcp_retransmit_count") ? args.find("tcp_retransmit_count")->as_int(0) : 0);
  const int tcp_timeout_close_count = static_cast<int>(args.find("tcp_timeout_close_count") ? args.find("tcp_timeout_close_count")->as_int(0) : 0);

  const Value eval = samurai::scenario_native::evaluate_sla_native(
      *sla,
      sessions_started,
      sessions_completed,
      step_attempted,
      step_failed,
      latency_p95_ms,
      has_latency,
      tcp_connect_attempts,
      tcp_connect_established,
      tcp_retransmit_count,
      tcp_timeout_close_count);

  return MakeToolSuccess(eval);
}

}  // namespace samurai::mcp
