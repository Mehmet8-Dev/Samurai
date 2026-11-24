#include "autopilot_tools.hpp"

#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <sstream>

#include "runtime_tools.hpp"
#include "scenario_tools.hpp"

namespace samurai::mcp {

namespace {

using samurai::control::ClosedLoopConfig;
using samurai::control::ClosedLoopController;
using samurai::control::ClosedLoopDecision;
using samurai::control::ClosedLoopStrategy;
using samurai::control::kActionFields;
using samurai::control::kBanEwmaAlpha;
using samurai::control::LeverShield;
using samurai::control::LoadSample;
using samurai::control::RlPolicy;
using samurai::control::RlStateInputs;
using samurai::core::json::Value;

constexpr std::size_t kActionFieldCount = sizeof(kActionFields) / sizeof(kActionFields[0]);

std::string LowerCopy(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

double OptDouble(const Value& obj, const char* key, double def) {
  if (const Value* v = obj.find(key); v && v->is_number()) return v->as_double(def);
  return def;
}

std::int64_t OptInt(const Value& obj, const char* key, std::int64_t def) {
  if (const Value* v = obj.find(key); v && v->is_number()) return v->as_int(def);
  return def;
}

bool OptBool(const Value& obj, const char* key, bool def) {
  if (const Value* v = obj.find(key); v && v->is_bool()) return v->as_bool(def);
  return def;
}

std::string OptStr(const Value& obj, const char* key, const std::string& def = "") {
  if (const Value* v = obj.find(key); v && v->is_string()) return v->as_string(def);
  return def;
}

Value DecisionJson(const ClosedLoopDecision& d) {
  Value obj = Value::Object();
  obj.set("enabled", Value::Bool(d.enabled));
  obj.set("done", Value::Bool(d.done));
  obj.set("setpoint_rps", Value::Double(d.setpoint_rps));
  obj.set("best_good_rps", Value::Double(d.best_good_rps));
  obj.set("last_healthy", Value::Bool(d.last_healthy));
  obj.set("error_pct", Value::Double(d.error_pct));
  obj.set("phase", Value::Str(d.phase));
  obj.set("reason", Value::Str(d.reason));
  obj.set("window", Value::Int(d.window));
  return obj;
}

Value ActionFieldsArray() {
  Value arr = Value::Array();
  for (std::size_t i = 0; i < kActionFieldCount; ++i) {
    arr.push_back(Value::Str(kActionFields[i]));
  }
  return arr;
}

}  // namespace

Value AutopilotManager::SessionSummaryJson(const Session& sess) const {
  Value obj = Value::Object();
  obj.set("session_id", Value::Str(sess.id));
  obj.set("strategy", Value::Str(sess.strategy_name));
  obj.set("current_setpoint_rps", Value::Double(sess.controller->current_setpoint()));
  obj.set("best_good_rps", Value::Double(sess.controller->best_good_rps()));
  obj.set("done", Value::Bool(sess.controller->done()));
  obj.set("min_rps", Value::Double(sess.config.min_rps));
  obj.set("max_rps", Value::Double(sess.config.max_rps));
  obj.set("policy_loaded", Value::Bool(sess.policy.loaded()));
  if (sess.policy.loaded()) {
    obj.set("policy_path", Value::Str(sess.policy_path));
    obj.set("policy_recurrent", Value::Bool(sess.policy.recurrent()));
    obj.set("policy_state_dim", Value::Int(sess.policy.state_dim()));
    obj.set("policy_action_dim", Value::Int(sess.policy.action_dim()));
  }
  obj.set("explore_enabled", Value::Bool(sess.explore.enabled));
  obj.set("lever_shield_enabled", Value::Bool(sess.lever_shield_enabled));
  obj.set("ban_pressure", Value::Double(sess.ban_pressure));

  Value shield_arr = Value::Array();
  for (double v : sess.lever_shield.snapshot()) shield_arr.push_back(Value::Double(v));
  obj.set("lever_shield_best_success", std::move(shield_arr));

  if (sess.has_last_decision) {
    obj.set("last_decision", DecisionJson(sess.last_decision));
  }
  return obj;
}

ToolResult AutopilotManager::HandleCreate(const Value& args) {
  auto sess = std::make_unique<Session>();
  sess->config.enabled = true;

  const std::string strat = LowerCopy(OptStr(args, "strategy", "aimd"));
  if (strat == "binsearch" || strat == "binary" || strat == "bisect") {
    sess->config.strategy = ClosedLoopStrategy::kBinSearch;
    sess->strategy_name = "binsearch";
  } else if (strat == "rl" || strat == "policy" || strat == "mahoraga") {
    sess->config.strategy = ClosedLoopStrategy::kRl;
    sess->strategy_name = "rl";
  } else if (strat == "aimd") {
    sess->config.strategy = ClosedLoopStrategy::kAimd;
    sess->strategy_name = "aimd";
  } else {
    return MakeToolError("Invalid strategy '" + strat + "'. Expected: aimd, binsearch, or rl.");
  }

  sess->config.min_rps = std::max(1.0, OptDouble(args, "min_rps", 10.0));
  sess->config.max_rps = std::max(sess->config.min_rps, OptDouble(args, "max_rps", 100000.0));
  sess->config.initial_rps = OptDouble(args, "initial_rps", 0.0);

  sess->config.slo_max_error_pct = std::max(0.0, OptDouble(args, "slo_max_error_pct", 0.0));
  sess->config.slo_max_loss_pct = std::max(0.0, OptDouble(args, "slo_max_loss_pct", 0.0));
  sess->config.slo_min_rate_accuracy_pct =
      std::max(0.0, OptDouble(args, "slo_min_rate_accuracy_pct", 0.0));
  sess->config.slo_max_latency_ms = std::max(0.0, OptDouble(args, "slo_max_latency_ms", 0.0));
  sess->config.slo_max_pushback_pct = std::max(0.0, OptDouble(args, "slo_max_pushback_pct", 0.0));

  sess->config.aimd_increase_rps = std::max(0.0, OptDouble(args, "aimd_increase_rps", 0.0));
  sess->config.aimd_backoff = OptDouble(args, "aimd_backoff", 0.5);
  sess->config.aimd_max_windows = static_cast<int>(std::max<std::int64_t>(0, OptInt(args, "aimd_max_windows", 0)));

  sess->config.binsearch_tolerance_rps = std::max(0.0, OptDouble(args, "binsearch_tolerance_rps", 0.0));
  sess->config.binsearch_max_windows =
      static_cast<int>(std::clamp<std::int64_t>(OptInt(args, "binsearch_max_windows", 24), 1, 256));

  sess->config.rl_max_jump_factor = std::max(1.0, OptDouble(args, "rl_max_jump_factor", 2.0));
  sess->step_horizon = std::max(1.0, OptDouble(args, "step_horizon", 32.0));

  // Optional SRLP native RL policy (MLP or RL^2 GRU).
  const std::string raw_policy_path = OptStr(args, "policy_path", "");
  if (!raw_policy_path.empty()) {
    const std::string resolved_policy = samurai::control::ResolveRlPolicyPath(raw_policy_path);
    std::string load_err;
    if (!sess->policy.Load(resolved_policy, &load_err)) {
      return MakeToolError("Failed to load SRLP RL policy '" + raw_policy_path + "': " + load_err);
    }
    sess->policy_path = resolved_policy;
    sess->policy.ResetContext();
  }

  // Optional Mahoraga LeverShield (WAF path-block reflex).
  sess->lever_shield_enabled = OptBool(args, "lever_shield", true);
  LeverShield::Config shield_cfg;
  shield_cfg.honored_success_floor = OptDouble(args, "honored_success_floor", 0.10);
  shield_cfg.variant_count = static_cast<int>(std::clamp<std::int64_t>(OptInt(args, "variant_count", 5), 1, 32));
  sess->lever_shield = LeverShield(shield_cfg);

  // Optional deterministic Mahoraga lever exploration.
  if (OptBool(args, "explore", false)) {
    const auto seed = static_cast<std::uint64_t>(OptInt(args, "explore_seed", 42));
    sess->explore = samurai::control::DefaultExploreConfig(seed);
  }

  sess->controller = std::make_unique<ClosedLoopController>(sess->config);

  std::lock_guard<std::mutex> lock(mu_);
  const std::string id = "ap-" + std::to_string(next_id_++);
  sess->id = id;

  Value out = SessionSummaryJson(*sess);
  out.set("initial_setpoint_rps", Value::Double(sess->controller->initial_setpoint()));
  out.set("action_fields", ActionFieldsArray());
  sessions_[id] = std::move(sess);
  return MakeToolSuccess(std::move(out));
}

Value AutopilotManager::StepSessionLocked(Session& sess,
                                          LoadSample sample,
                                          const Value& extra_signals) {
  const int win_idx = sess.has_last_decision ? sess.last_decision.window : 0;

  // Update LeverShield if the caller reports which request_mix variant ran and its 2xx share.
  const int applied_variant = static_cast<int>(OptInt(extra_signals, "variant_applied", -1));
  const double success_ratio = OptDouble(extra_signals, "success_ratio", -1.0);
  if (applied_variant >= 0 && success_ratio >= 0.0) {
    sess.lever_shield.Observe(applied_variant, success_ratio);
  }

  // Update EWMA ban pressure from conn_drop_ratio if reported.
  const double conn_drop = OptDouble(extra_signals, "conn_drop_ratio", -1.0);
  if (conn_drop >= 0.0) {
    sess.ban_pressure = (sess.ban_pressure < 0.0)
                            ? conn_drop
                            : (kBanEwmaAlpha * conn_drop + (1.0 - kBanEwmaAlpha) * sess.ban_pressure);
  }

  // Build governed 7-D Mahoraga action vector (from SRLP policy, external RL agent, or exploration).
  std::vector<double> proposed_action(kActionFieldCount, -1.0);
  std::string action_source = "controller";

  if (sess.policy.loaded()) {
    RlStateInputs in;
    in.rps = sample.actual_rps > 0.0 ? sample.actual_rps : sess.controller->current_setpoint();
    double derived_err = sample.error_pct;
    if (derived_err < 0.0 && sample.attempted > 0.0) {
      derived_err = (sample.errors / sample.attempted) * 100.0;
    }
    in.error_pct = derived_err;
    in.loss_pct = sample.loss_pct;
    in.rate_accuracy_pct = sample.rate_accuracy_pct;
    in.p99_ms = sample.latency_p99_ms;
    in.win = win_idx;
    in.rate_limited_ratio = OptDouble(extra_signals, "rate_limited_ratio", -1.0);
    in.overload_ratio = OptDouble(extra_signals, "overload_ratio", -1.0);
    in.conn_drop_ratio = conn_drop;
    in.reset_pressure = OptDouble(extra_signals, "reset_pressure", -1.0);
    in.challenge_rate = OptDouble(extra_signals, "challenge_rate", -1.0);
    in.max_rps = sess.config.max_rps;
    in.step_horizon = sess.step_horizon;

    // Match extended feature widths if the loaded policy expects block/ban features.
    const int sdim = sess.policy.state_dim();
    if (sdim > 20) {
      in.variant_block_success = sess.lever_shield.snapshot();
    }
    if (sdim > static_cast<int>(20 + 2 * in.variant_block_success.size())) {
      in.ban_features = true;
      in.ban_pressure = sess.ban_pressure;
    }

    const std::vector<double> act = sess.policy.ProposeFor(in);
    if (!act.empty()) {
      for (std::size_t k = 0; k < std::min(act.size(), kActionFieldCount); ++k) {
        proposed_action[k] = act[k];
      }
      if (sample.rl_action_rps < 0.0 && proposed_action[0] >= 0.0) {
        sample.rl_action_rps = proposed_action[0];
      }
      action_source = sess.policy.recurrent() ? "srlp_rl2_gru" : "srlp_mlp";
    }
  } else if (sample.rl_action_rps >= 0.0) {
    proposed_action[0] = sample.rl_action_rps;
    action_source = "external_rl_agent";
  }

  // Optional deterministic exploration on extra shaping levers (k >= 1).
  if (sess.explore.enabled && !sess.policy.loaded()) {
    const auto exp = samurai::control::ExploreLevers(win_idx, sess.explore);
    for (std::size_t k = 1; k < std::min(exp.size(), kActionFieldCount); ++k) {
      if (exp[k] >= 0.0) proposed_action[k] = exp[k];
    }
    if (action_source == "controller") action_source = "controller+rl_explore";
  }

  // Allow external RL agent to supply extra levers explicitly via `rl_levers`.
  if (const Value* levers = extra_signals.find("rl_levers"); levers && levers->is_object()) {
    for (std::size_t k = 1; k < kActionFieldCount; ++k) {
      if (const Value* lv = levers->find(kActionFields[k]); lv && lv->is_number()) {
        proposed_action[k] = lv->as_double(-1.0);
      }
    }
  }

  // Step the native ClosedLoopController (enforces SLO shield & jump cap).
  const ClosedLoopDecision dec = sess.controller->Step(sample);
  sess.last_decision = dec;
  sess.has_last_decision = true;

  // Apply LeverShield reflex to request_mix (index 2) if active.
  bool lever_shield_intervened = false;
  int raw_request_mix = static_cast<int>(std::llround(proposed_action[2]));
  if (sess.lever_shield_enabled && proposed_action[2] >= 0.0) {
    const int governed = sess.lever_shield.Govern(raw_request_mix);
    if (governed != raw_request_mix) {
      lever_shield_intervened = true;
      proposed_action[2] = static_cast<double>(governed);
    }
  }

  // Shielded RPS always comes from ClosedLoopController::Step().
  proposed_action[0] = dec.setpoint_rps;

  Value action_map = Value::Object();
  for (std::size_t k = 0; k < kActionFieldCount; ++k) {
    if (proposed_action[k] >= 0.0) {
      action_map.set(kActionFields[k], Value::Double(proposed_action[k]));
    }
  }

  Value shield_arr = Value::Array();
  for (double v : sess.lever_shield.snapshot()) shield_arr.push_back(Value::Double(v));

  Value out = Value::Object();
  out.set("session_id", Value::Str(sess.id));
  out.set("strategy", Value::Str(sess.strategy_name));
  out.set("action_source", Value::Str(action_source));
  out.set("decision", DecisionJson(dec));
  out.set("shielded_action", std::move(action_map));
  out.set("lever_shield_intervened", Value::Bool(lever_shield_intervened));
  out.set("lever_shield_best_success", std::move(shield_arr));
  out.set("ban_pressure", Value::Double(sess.ban_pressure));
  return out;
}

ToolResult AutopilotManager::HandleStep(const Value& args) {
  const std::string sid = OptStr(args, "session_id", "");
  if (sid.empty()) return MakeToolError("session_id is required");

  std::lock_guard<std::mutex> lock(mu_);
  auto it = sessions_.find(sid);
  if (it == sessions_.end()) {
    return MakeToolError("Unknown autopilot session_id: " + sid);
  }

  LoadSample sample;
  sample.valid = OptBool(args, "valid", true);
  sample.actual_rps = OptDouble(args, "actual_rps", it->second->controller->current_setpoint());
  sample.attempted = OptDouble(args, "attempted", 0.0);
  sample.errors = OptDouble(args, "errors", 0.0);
  sample.error_pct = OptDouble(args, "error_pct", -1.0);
  sample.loss_pct = OptDouble(args, "loss_pct", -1.0);
  sample.rate_accuracy_pct = OptDouble(args, "rate_accuracy_pct", -1.0);
  sample.latency_p99_ms = OptDouble(args, "latency_p99_ms", -1.0);
  sample.pushback_pct = OptDouble(args, "pushback_pct", -1.0);
  sample.rl_action_rps = OptDouble(args, "rl_action_rps", -1.0);

  return MakeToolSuccess(StepSessionLocked(*it->second, sample, args));
}

ToolResult AutopilotManager::HandleRunWindow(const Value& args, const SafetyConfig& safety) {
  const std::string sid = OptStr(args, "session_id", "");
  if (sid.empty()) return MakeToolError("session_id is required");

  double target_rps = 0.0;
  {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = sessions_.find(sid);
    if (it == sessions_.end()) {
      return MakeToolError("Unknown autopilot session_id: " + sid);
    }
    if (it->second->controller->done()) {
      Value out = SessionSummaryJson(*it->second);
      out.set("note", Value::Str("Session already converged/done; reset or create a new session."));
      return MakeToolSuccess(std::move(out));
    }
    target_rps = it->second->controller->current_setpoint();
  }

  const double window_s = std::clamp(OptDouble(args, "window_s", 1.0), 0.2, 15.0);
  const std::int64_t computed_count = std::clamp<std::int64_t>(
      static_cast<std::int64_t>(std::llround(target_rps * window_s)),
      1,
      static_cast<std::int64_t>(safety.max_packet_count));

  const bool has_scenario_input =
      args.find("scenario") != nullptr ||
      !OptStr(args, "scenario_file", "").empty() ||
      !OptStr(args, "l7_profile_file", "").empty();

  std::string temp_scenario_path;
  std::string effective_worker = OptStr(args, "worker", has_scenario_input ? "scenario" : "l7");

  Value bench_args = Value::Object();
  bench_args.set("worker", Value::Str(effective_worker));
  bench_args.set("target", Value::Str(OptStr(args, "target", "127.0.0.1")));
  bench_args.set("port", Value::Int(OptInt(args, "port", 8080)));
  bench_args.set("protocol", Value::Str(OptStr(args, "protocol", "http1")));
  bench_args.set("count", Value::Int(OptInt(args, "count", computed_count)));
  bench_args.set("size", Value::Int(OptInt(args, "size", 64)));
  bench_args.set("rps", Value::Double(target_rps));
  if (has_scenario_input) {
    std::string raw_json;
    std::string src_path;
    const std::string serr = LoadAndValidateScenarioJson(args, raw_json, src_path);
    if (!serr.empty()) {
      return MakeToolError(serr);
    }
    if (!src_path.empty()) {
      bench_args.set("l7_profile_file", Value::Str(src_path));
    } else {
      temp_scenario_path = WriteTempScenarioFile(raw_json);
      if (temp_scenario_path.empty()) {
        return MakeToolError("Failed to materialize inline scenario JSON for autopilot window");
      }
      bench_args.set("l7_profile_file", Value::Str(temp_scenario_path));
    }
  }
  for (const char* k : {"l7_protocol", "iface", "transport"}) {
    if (const Value* v = args.find(k); v && v->is_string() && !v->as_string().empty()) {
      bench_args.set(k, *v);
    }
  }
  if (const Value* conc = args.find("concurrency"); conc && conc->is_number()) {
    bench_args.set("concurrency", *conc);
  }
  if (const Value* ka = args.find("keepalive"); ka && ka->is_bool()) {
    bench_args.set("keepalive", *ka);
  }
  bench_args.set("timeout_s", Value::Int(OptInt(args, "timeout_s", 30)));

  const ToolResult run_res = HandleRunBenchmark(bench_args, safety);
  if (!temp_scenario_path.empty()) {
    ::unlink(temp_scenario_path.c_str());
  }
  if (run_res.is_error) return run_res;

  // Derive LoadSample from the structured JSON report returned by samurai CLI.
  LoadSample sample;
  const int rc = static_cast<int>(OptInt(run_res.payload, "exit_code", -1));
  sample.valid = (rc == 0);
  sample.actual_rps = target_rps;
  sample.rl_action_rps = OptDouble(args, "rl_action_rps", -1.0);

  if (const Value* report = run_res.payload.find("report"); report && report->is_object()) {
    const Value* stats = report->find("stats");
    const Value& src = (stats && stats->is_object()) ? *stats : *report;
    sample.attempted = OptDouble(src, "attempted", 0.0);
    sample.errors = OptDouble(src, "errors", 0.0);
    if (sample.attempted > 0.0) {
      sample.valid = true;
      sample.actual_rps = OptDouble(src, "actual_rps", target_rps);
      sample.rate_accuracy_pct = OptDouble(src, "rate_accuracy_pct", -1.0);
      sample.loss_pct = OptDouble(src, "wire_loss_est_pct", -1.0);
    }
    if (const Value* l7 = src.find("l7_telemetry"); l7 && l7->is_object()) {
      const double p99 = OptDouble(*l7, "request_latency_p99_ms", -1.0);
      if (p99 >= 0.0) sample.latency_p99_ms = p99;
    }
  }

  std::lock_guard<std::mutex> lock(mu_);
  auto it = sessions_.find(sid);
  if (it == sessions_.end()) {
    return MakeToolError("Session was removed while window was running: " + sid);
  }
  Value step_out = StepSessionLocked(*it->second, sample, args);
  step_out.set("window_run", run_res.payload);
  return MakeToolSuccess(std::move(step_out));
}

ToolResult AutopilotManager::HandleStatus(const Value& args) {
  const std::string sid = OptStr(args, "session_id", "");
  std::lock_guard<std::mutex> lock(mu_);
  if (!sid.empty()) {
    auto it = sessions_.find(sid);
    if (it == sessions_.end()) {
      return MakeToolError("Unknown autopilot session_id: " + sid);
    }
    return MakeToolSuccess(SessionSummaryJson(*it->second));
  }

  Value arr = Value::Array();
  for (const auto& kv : sessions_) {
    arr.push_back(SessionSummaryJson(*kv.second));
  }
  Value out = Value::Object();
  out.set("active_sessions", Value::Int(static_cast<std::int64_t>(sessions_.size())));
  out.set("sessions", std::move(arr));
  return MakeToolSuccess(std::move(out));
}

ToolResult AutopilotManager::HandleReset(const Value& args) {
  const std::string sid = OptStr(args, "session_id", "");
  if (sid.empty()) return MakeToolError("session_id is required");
  const bool remove = OptBool(args, "delete", false);

  std::lock_guard<std::mutex> lock(mu_);
  auto it = sessions_.find(sid);
  if (it == sessions_.end()) {
    return MakeToolError("Unknown autopilot session_id: " + sid);
  }
  if (remove) {
    sessions_.erase(it);
    Value out = Value::Object();
    out.set("session_id", Value::Str(sid));
    out.set("deleted", Value::Bool(true));
    return MakeToolSuccess(std::move(out));
  }

  Session& sess = *it->second;
  sess.controller = std::make_unique<ClosedLoopController>(sess.config);
  sess.policy.ResetContext();
  sess.lever_shield.Reset();
  sess.ban_pressure = -1.0;
  sess.has_last_decision = false;

  Value out = SessionSummaryJson(sess);
  out.set("reset", Value::Bool(true));
  return MakeToolSuccess(std::move(out));
}

}  // namespace samurai::mcp
