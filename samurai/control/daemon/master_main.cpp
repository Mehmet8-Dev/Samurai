// samurai_master — distributed master daemon.
//
// Native replacement for the run_distributed_master entrypoint: optionally win
// HA leadership, serve the control server (workers register/heartbeat/report),
// optionally expose the HTTP management API, wait for workers, then split and
// dispatch one job across the cluster and print the aggregated snapshot.

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "autoscale.hpp"
#include "closed_loop.hpp"
#include "lever_shield.hpp"
#include "variant_memory.hpp"
#include "ban_memory.hpp"
#include "online_adapter.hpp"
#include "novelty_detector.hpp"
#include "rl_explore.hpp"
#include "rl_policy.hpp"
#include "control_auth.hpp"
#include "control_server.hpp"
#include "curve.hpp"
#include "daemon_args.hpp"
#include "ha.hpp"
#include "json.hpp"
#include "k8s_client.hpp"
#include "management_api.hpp"
#include "provisioner.hpp"
#include "master_adapters.hpp"
#include "master_coordinator.hpp"
#include "multimaster.hpp"
#include "redis_kvstore.hpp"
#include "servicer.hpp"
#include "sut_probe.hpp"
#include "target_safety.hpp"

#include "anti_tamper.hpp"
#include "cache.hpp"
#include "client.hpp"
#include "constants.hpp"
#include "gates.hpp"
#include "hwid.hpp"
#include "license_types.hpp"

namespace {
std::atomic<bool> g_stop{false};
void OnSignal(int) { g_stop.store(true); }

using samurai::core::json::Value;

std::string LowerCopy(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return s;
}

bool OptBoolFlag(int argc, char** argv, const char* flag, bool def = false) {
  for (int i = 1; i < argc; ++i) {
    if (flag == std::string(argv[i])) {
      if (i + 1 < argc && argv[i + 1][0] != '-') {
        const std::string val = LowerCopy(argv[i + 1]);
        if (val == "0" || val == "false" || val == "no" || val == "off") return false;
        if (val == "1" || val == "true" || val == "yes" || val == "on") return true;
      }
      return true;
    }
  }
  return def;
}

std::uint32_t ParseIpv4HostOrder(const std::string& s, std::uint32_t def_val) {
  if (s.empty()) return def_val;
  struct in_addr addr{};
  if (::inet_pton(AF_INET, s.c_str(), &addr) == 1) {
    return ntohl(addr.s_addr);
  }
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(s.c_str(), &end, 0);
  if (end != s.c_str() && *end == '\0') {
    return static_cast<std::uint32_t>(parsed);
  }
  return def_val;
}

// `mm` (nullable) surfaces the federated region snapshots for the management API
// `multi_master_regions` field; nullptr / inactive => the field is omitted.
// `autoscale_json` (nullable) is the latest autoscale decision object; when set
// it is attached as the `autoscale` field.
Value BuildState(samurai::control::Servicer* svc,
                 samurai::control::RedisMultiMasterCoordinator* mm = nullptr,
                 const Value* autoscale_json = nullptr,
                 const Value* closed_loop_json = nullptr) {
  Value st = Value::Object();
  Value workers = Value::Array();
  for (const auto& w : svc->SnapshotWorkers()) {
    Value o = Value::Object();
    o.set("worker_id", Value::Str(w.worker_id));
    o.set("last_heartbeat_ms", Value::Int(w.last_heartbeat_ms));
    auto rit = w.capabilities.find("region");
    if (rit != w.capabilities.end()) o.set("region", Value::Str(rit->second));
    auto tit = w.capabilities.find("tenant_namespace");
    if (tit != w.capabilities.end()) o.set("tenant_namespace", Value::Str(tit->second));
    workers.push_back(std::move(o));
  }
  st.set("workers", std::move(workers));
  if (mm && mm->active()) {
    Value regions = Value::Array();
    for (auto& snap : mm->LatestRegionSnapshots()) regions.push_back(std::move(snap));
    st.set("multi_master_regions", std::move(regions));
  }
  if (autoscale_json && autoscale_json->is_object()) {
    st.set("autoscale", *autoscale_json);
  }
  if (closed_loop_json && closed_loop_json->is_object()) {
    st.set("closed_loop", *closed_loop_json);
  }
  return st;
}

// Serialize an autoscale decision (+ its static target identity) into the JSON
// object surfaced by the management API.
Value AutoscaleStateJson(const samurai::control::AutoscaleDecision& d,
                         const std::string& target_name, const std::string& target_kind,
                         const std::string& backend) {
  Value o = Value::Object();
  o.set("enabled", Value::Bool(d.enabled));
  o.set("changed", Value::Bool(d.changed));
  o.set("reason", Value::Str(d.reason));
  o.set("has_values", Value::Bool(d.has_values));
  o.set("current", Value::Int(d.current));
  o.set("desired", Value::Int(d.desired));
  o.set("applied", Value::Int(d.applied));
  o.set("target_name", Value::Str(target_name));
  o.set("target_kind", Value::Str(target_kind));
  // "kubernetes" => current/applied reflect the cluster scale subresource;
  // "in-memory" => the controller's internal model (no cluster backend resolved).
  o.set("backend", Value::Str(backend));
  return o;
}

// Parse the closed-loop (autopilot) knobs off the CLI into a ClosedLoopConfig.
samurai::control::ClosedLoopConfig BuildClosedLoopConfig(int argc, char** argv) {
  using namespace samurai::control;
  using namespace samurai::control::daemon;
  ClosedLoopConfig cl;
  cl.enabled = Flag(argc, argv, "--closed-loop");
  const std::string strat = LowerCopy(Opt(argc, argv, "--cl-strategy", "aimd"));
  if (strat == "binsearch" || strat == "binary" || strat == "bisect") {
    cl.strategy = ClosedLoopStrategy::kBinSearch;
  } else if (strat == "rl" || strat == "policy") {
    cl.strategy = ClosedLoopStrategy::kRl;
  } else {
    cl.strategy = ClosedLoopStrategy::kAimd;
  }
  cl.rl_max_jump_factor = OptDouble(argc, argv, "--cl-rl-max-jump-factor", 2.0);
  cl.min_rps = static_cast<double>(OptInt(argc, argv, "--cl-min-rps", 1));
  cl.max_rps = static_cast<double>(OptInt(argc, argv, "--cl-max-rps", 1000000));
  cl.initial_rps = static_cast<double>(OptInt(argc, argv, "--cl-initial-rps", 0));
  cl.slo_max_error_pct = OptDouble(argc, argv, "--cl-slo-max-error-pct", 0.0);
  cl.slo_max_loss_pct = OptDouble(argc, argv, "--cl-slo-max-loss-pct", 0.0);
  cl.slo_min_rate_accuracy_pct = OptDouble(argc, argv, "--cl-slo-min-rate-accuracy-pct", 0.0);
  cl.slo_max_latency_ms = OptDouble(argc, argv, "--cl-slo-max-latency-ms", 0.0);
  cl.slo_max_pushback_pct = OptDouble(argc, argv, "--cl-slo-max-pushback-pct", 0.0);
  cl.aimd_increase_rps = static_cast<double>(OptInt(argc, argv, "--cl-aimd-increase-rps", 0));
  cl.aimd_backoff = OptDouble(argc, argv, "--cl-aimd-backoff", 0.5);
  cl.aimd_max_windows = static_cast<int>(OptInt(argc, argv, "--cl-aimd-max-windows", 0));
  cl.binsearch_tolerance_rps =
      static_cast<double>(OptInt(argc, argv, "--cl-binsearch-tolerance-rps", 0));
  cl.binsearch_max_windows = static_cast<int>(OptInt(argc, argv, "--cl-binsearch-max-windows", 24));
  return cl;
}

// Parse the RL exploration knobs off the CLI. `--rl-explore` turns on the
// default WAF-lab schedule; `--rl-explore-seed N` makes the perturbation
// reproducible; `--rl-explore-<field> lo:hi` overrides one lever's range (field
// is a kActionFields name other than rps, e.g. concurrency/request_mix/
// source_rotation/pacing_mode). Exploration only fires during corpus capture
// when a policy is NOT driving the extra levers.
samurai::control::RlExploreConfig BuildExploreConfig(int argc, char** argv) {
  using namespace samurai::control;
  using namespace samurai::control::daemon;
  if (!Flag(argc, argv, "--rl-explore")) return RlExploreConfig{};  // disabled
  const auto seed = static_cast<std::uint64_t>(OptInt(argc, argv, "--rl-explore-seed", 0));
  RlExploreConfig cfg = DefaultExploreConfig(seed);
  // Per-lever "lo:hi" range overrides. Absent flags keep the lab defaults.
  for (std::size_t k = 1; k < sizeof(kActionFields) / sizeof(kActionFields[0]); ++k) {
    const std::string flag = std::string("--rl-explore-") + kActionFields[k];
    const std::string range = Opt(argc, argv, flag.c_str(), "");
    if (range.empty()) continue;
    const std::size_t colon = range.find(':');
    if (colon == std::string::npos) continue;
    try {
      const long lo = std::stol(range.substr(0, colon));
      const long hi = std::stol(range.substr(colon + 1));
      cfg.SetLever(kActionFields[k], lo, hi);
    } catch (...) {
      // Malformed range -> keep the default for this lever.
    }
  }
  return cfg;
}

// Parse the SUT-correlation (Prometheus) knobs off the CLI. Extra queries are
// given as a ';'-separated list of name=promql pairs.
samurai::control::SutProbeConfig BuildSutProbeConfig(int argc, char** argv) {
  using namespace samurai::control;
  using namespace samurai::control::daemon;
  SutProbeConfig cfg;
  cfg.prometheus_url = Opt(argc, argv, "--sut-prometheus-url", "");
  cfg.latency_p99_query = Opt(argc, argv, "--sut-latency-p99-query", "");
  cfg.insecure = Flag(argc, argv, "--sut-insecure");
  cfg.timeout_s = static_cast<int>(OptInt(argc, argv, "--sut-timeout-s", 5));
  cfg.enabled = !cfg.prometheus_url.empty();
  const std::string extra = Opt(argc, argv, "--sut-extra-queries", "");
  std::size_t pos = 0;
  while (pos < extra.size()) {
    const std::size_t semi = extra.find(';', pos);
    const std::string pair = extra.substr(pos, semi == std::string::npos ? std::string::npos
                                                                          : semi - pos);
    const std::size_t eq = pair.find('=');
    if (eq != std::string::npos) {
      SutQuery q;
      q.name = pair.substr(0, eq);
      q.promql = pair.substr(eq + 1);
      if (!q.name.empty() && !q.promql.empty()) cfg.extra.push_back(std::move(q));
    }
    if (semi == std::string::npos) break;
    pos = semi + 1;
  }
  return cfg;
}

// Derive one closed-loop LoadSample from an aggregated run snapshot. Today the
// honest SLO signal is the error rate (sent/errors are always present); rps is
// the cross-shard aggregate. rate-accuracy/loss/latency are left unknown (-1) so
// their rules stay inert until real per-window signals (and #3 SUT p99) feed them.
samurai::control::LoadSample DeriveSample(const Value& snap) {
  samurai::control::LoadSample s;
  const Value* sent = snap.find("sent");
  const Value* errs = snap.find("errors");
  const double sent_v = sent ? static_cast<double>(sent->as_int(0)) : 0.0;
  const double err_v = errs ? static_cast<double>(errs->as_int(0)) : 0.0;
  s.attempted = sent_v + err_v;
  s.errors = err_v;
  if (const Value* nt = snap.find("numeric_totals")) {
    if (const Value* rps = nt->find("actual_rps")) s.actual_rps = rps->as_double(0.0);
    // Defense pushback share: (4xx rate-limit + 5xx overload) / responses_total, %.
    // This is the honest "target rejected our load" signal the error_pct rule misses
    // (a 429 is not a client/server error), so the SLO can flag ramping into a rate
    // wall. Left unknown (-1) when the SUT emits no HTTP status telemetry.
    const Value* resp = nt->find("responses_total");
    const double resp_v = resp ? resp->as_double(0.0) : 0.0;
    if (resp_v > 0.0) {
      const Value* x4 = nt->find("status_4xx");
      const Value* x5 = nt->find("status_5xx");
      const double pb = (x4 ? x4->as_double(0.0) : 0.0) + (x5 ? x5->as_double(0.0) : 0.0);
      s.pushback_pct = 100.0 * pb / resp_v;
    }
  }
  s.valid = true;
  return s;
}

const char* StrategyName(samurai::control::ClosedLoopStrategy s) {
  switch (s) {
    case samurai::control::ClosedLoopStrategy::kBinSearch:
      return "binsearch";
    case samurai::control::ClosedLoopStrategy::kRl:
      return "rl";
    case samurai::control::ClosedLoopStrategy::kAimd:
    default:
      return "aimd";
  }
}

// Serialize a closed-loop decision into the JSON object surfaced by the
// management API (/v1/cluster/summary -> "closed_loop").
Value ClosedLoopStateJson(const samurai::control::ClosedLoopDecision& d,
                          const samurai::control::ClosedLoopConfig& cfg) {
  Value o = Value::Object();
  o.set("enabled", Value::Bool(d.enabled));
  o.set("strategy", Value::Str(StrategyName(cfg.strategy)));
  o.set("done", Value::Bool(d.done));
  o.set("phase", Value::Str(d.phase));
  o.set("reason", Value::Str(d.reason));
  o.set("window", Value::Int(d.window));
  o.set("setpoint_rps", Value::Double(d.setpoint_rps));
  o.set("best_good_rps", Value::Double(d.best_good_rps));
  o.set("last_healthy", Value::Bool(d.last_healthy));
  o.set("error_pct", Value::Double(d.error_pct));
  o.set("slo_max_error_pct", Value::Double(cfg.slo_max_error_pct));
  return o;
}

// Defense-reaction signals: how the SUT's WAF/IPS/rate-limiter/overload handling
// pushed back on the load this window. Extracted raw from the aggregated snapshot
// (numeric_totals) so the offline pipeline can derive the Mahoraga features it
// wants (rate-limited ratio = status_4xx/responses, overload ratio = status_5xx,
// conn-drop ratio = 1 - established/attempted, reset/goaway pressure, challenge
// rate = expectation_failures). Only keys present in the snapshot are emitted;
// absent ones stay unknown so the dataset builder masks them per run.
Value RlDefenseJson(const Value& snap) {
  Value o = Value::Object();
  const Value* nt = snap.find("numeric_totals");
  if (!nt || !nt->is_object()) return o;
  static const char* kKeys[] = {
      "responses_total",        "status_2xx",
      "status_3xx",             "status_4xx",
      "status_5xx",             "l7_conn_attempted",
      "l7_conn_established",    "l7_expectation_failures",
      "l7_scheduler_backpressure_count", "h2_goaway_count",
      "h2_stream_reset_ratio",  "l7_request_latency_p99_ms",
      "l7_tls_handshake_p99_ms",
      // Flow / connection-level signals for the fingerprint layer. These enrich
      // the corpus defense block but are NOT added to RlInputsFrom, so the RL
      // feature vector (and the SRLP serving contract) stays frozen at 20.
      "tcp_peer_rst_count",     "tcp_connect_timeout_count",
      "tcp_retransmit_count",   "tcp_timeout_close_count",
  };
  for (const char* k : kKeys) {
    if (const Value* v = nt->find(k)) o.set(k, Value::Double(v->as_double(0.0)));
  }
  return o;
}

// Structured action: today the controller only drives rps (+ a fixed pacing
// mode), but the RL policy's action space is the richer Mahoraga vector. The
// columns are logged now so the corpus schema is stable — the not-yet-driven
// levers carry their current spec value (or -1 = "not a controlled dimension in
// this run") and start varying the moment a policy drives them, no migration.
Value RlActionJson(double rps, const Value& base_args) {
  Value a = Value::Object();
  a.set("rps", Value::Double(rps));
  const Value* pm = base_args.find("pacing_mode");
  a.set("pacing_mode", Value::Int(pm ? pm->as_int(0) : -1));
  const Value* cc = base_args.find("concurrency");
  a.set("concurrency", cc ? Value::Int(cc->as_int(0)) : Value::Int(-1));
  const Value* conns = base_args.find("connections");
  a.set("connections", conns ? Value::Int(conns->as_int(0)) : Value::Int(-1));
  // Mahoraga shaping levers: -1 until a policy or exploration schedule drives
  // them into base_args, at which point the captured value reflects what the
  // dataplane was actually told to do this window.
  const Value* rm = base_args.find("request_mix");
  a.set("request_mix", rm ? Value::Int(rm->as_int(-1)) : Value::Int(-1));
  const Value* sr = base_args.find("source_rotation");
  a.set("source_rotation", sr ? Value::Int(sr->as_int(-1)) : Value::Int(-1));
  return a;
}

// Build the policy's raw state inputs from a measured window + its defense
// signals. The derived ratios MUST match samurai/models/rl DefenseSignals
// (rate_limited = 4xx/responses, overload = 5xx/responses, conn_drop =
// 1 - established/attempted, reset_pressure = h2_stream_reset_ratio, challenge =
// expectation_failures/responses); an input missing from `defense` stays -1
// (unknown) so BuildFeatures masks it, exactly like the offline pipeline.
samurai::control::RlStateInputs RlInputsFrom(const samurai::control::LoadSample& s,
                                             const Value& defense, int win,
                                             const samurai::control::ClosedLoopConfig& cfg) {
  samurai::control::RlStateInputs in;
  in.rps = s.actual_rps;
  in.error_pct = s.error_pct >= 0.0
                     ? s.error_pct
                     : (s.attempted > 0.0 ? 100.0 * s.errors / s.attempted : -1.0);
  in.loss_pct = s.loss_pct;
  in.rate_accuracy_pct = s.rate_accuracy_pct;
  in.p99_ms = s.latency_p99_ms;
  in.win = win;
  in.max_rps = cfg.max_rps;
  in.step_horizon = 32.0;  // must match RLConfig.step_horizon

  auto get = [&](const char* k, double* out) -> bool {
    if (const Value* v = defense.find(k)) {
      *out = v->as_double(0.0);
      return true;
    }
    return false;
  };
  double responses = 0.0, v = 0.0;
  const bool have_resp = get("responses_total", &responses) && responses > 0.0;
  if (have_resp && get("status_4xx", &v)) in.rate_limited_ratio = v / responses;
  if (have_resp && get("status_5xx", &v)) in.overload_ratio = v / responses;
  if (have_resp && get("l7_expectation_failures", &v)) in.challenge_rate = v / responses;
  double att = 0.0, est = 0.0;
  if (get("l7_conn_attempted", &att) && att > 0.0 && get("l7_conn_established", &est)) {
    in.conn_drop_ratio = std::max(0.0, 1.0 - est / att);
  }
  if (get("h2_stream_reset_ratio", &v)) in.reset_pressure = v;
  // Flow-level (IPS/NSM) rates, normalized per connection-attempt — mirror
  // DefenseSignals._flow_rate. Left -1 (masked) when att<=0 or the counter is
  // absent (kernel-socket path). flow_features / flow_capable are set by the caller
  // from the loaded policy + the run's transport.
  double flow_ct = 0.0;
  if (att > 0.0) {
    if (get("tcp_peer_rst_count", &flow_ct)) in.rst_rate = flow_ct / att;
    if (get("tcp_connect_timeout_count", &flow_ct)) in.connect_timeout_rate = flow_ct / att;
    if (get("tcp_retransmit_count", &flow_ct)) in.retransmit_rate = flow_ct / att;
    if (get("tcp_timeout_close_count", &flow_ct)) in.timeout_close_rate = flow_ct / att;
  }
  return in;
}

// Serialize one measured window (LoadSample folded with the SUT scrape and the
// defense-reaction signals) into the raw state object logged to the RL corpus.
// Fields left < 0 by the caller stay "unknown" and are carried through verbatim —
// the offline pipeline decides how to impute/mask them. No reward is computed
// here on purpose: reward shaping lives in Python so it can be retuned without
// recapturing.
Value RlStateJson(const samurai::control::LoadSample& s, const Value& defense) {
  Value o = Value::Object();
  o.set("valid", Value::Bool(s.valid));
  o.set("rps", Value::Double(s.actual_rps));
  o.set("attempted", Value::Double(s.attempted));
  o.set("errors", Value::Double(s.errors));
  o.set("error_pct", Value::Double(s.error_pct));
  o.set("loss_pct", Value::Double(s.loss_pct));
  o.set("rate_accuracy_pct", Value::Double(s.rate_accuracy_pct));
  o.set("p99_ms", Value::Double(s.latency_p99_ms));
  o.set("defense", defense);
  return o;
}

// One RL corpus transition: state that produced the action (prev window), the
// action (setpoint sent), the resulting next state (this window), and enough run
// context for the offline dataset builder to compute reward and group episodes.
Value RlTransitionJson(const std::string& run_id, int win, double action_rps,
                       const Value& action, const samurai::control::LoadSample& s_prev,
                       const Value& def_prev, const samurai::control::LoadSample& s_next,
                       const Value& def_next,
                       const samurai::control::ClosedLoopDecision& dec,
                       const samurai::control::ClosedLoopConfig& cfg, int window_s,
                       bool first, const std::string& transport) {
  using samurai::control::ClosedLoopStrategy;
  Value o = Value::Object();
  o.set("run_id", Value::Str(run_id));
  o.set("win", Value::Int(win));
  o.set("ts_ms", Value::Int(std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count()));
  // Dataplane transport for this run — lets the offline pipeline gate the
  // flow-level IPS features (only meaningful on a flow-capable transport).
  o.set("transport", Value::Str(transport));
  o.set("strategy", Value::Str(StrategyName(cfg.strategy)));
  o.set("min_rps", Value::Double(cfg.min_rps));
  o.set("max_rps", Value::Double(cfg.max_rps));
  o.set("window_s", Value::Int(window_s));
  Value slo = Value::Object();
  slo.set("max_error_pct", Value::Double(cfg.slo_max_error_pct));
  slo.set("max_loss_pct", Value::Double(cfg.slo_max_loss_pct));
  slo.set("min_rate_accuracy_pct", Value::Double(cfg.slo_min_rate_accuracy_pct));
  slo.set("max_latency_ms", Value::Double(cfg.slo_max_latency_ms));
  slo.set("max_pushback_pct", Value::Double(cfg.slo_max_pushback_pct));
  o.set("slo", slo);
  // Scalar action_rps kept for back-compat; `action` is the full Mahoraga vector.
  o.set("action_rps", Value::Double(action_rps));
  o.set("action", action);
  // s is undefined on the first window (no prior measured state) — mark it so the
  // dataset builder drops the leading transition instead of learning from a stub.
  o.set("s_valid", Value::Bool(!first));
  o.set("s", RlStateJson(s_prev, def_prev));
  o.set("s2", RlStateJson(s_next, def_next));
  o.set("healthy", Value::Bool(dec.last_healthy));
  o.set("phase", Value::Str(dec.phase));
  o.set("done", Value::Bool(dec.done));
  return o;
}

bool LoadJsonFileValue(const std::string& path, Value& out, std::string& err) {
  std::ifstream f(path);
  if (!f) {
    err = "cannot open file: " + path;
    return false;
  }
  std::stringstream ss;
  ss << f.rdbuf();
  const auto parsed = samurai::core::json::Parse(ss.str());
  if (!parsed.ok) {
    err = "invalid JSON in " + path + ": " + parsed.error;
    return false;
  }
  out = parsed.value;
  return true;
}

bool ResolveRegionTopologyArg(const std::string& path,
                              samurai::control::RegionTopology& out,
                              std::string& err) {
  if (path.empty()) return true;
  Value j;
  if (!LoadJsonFileValue(path, j, err)) return false;
  return samurai::control::RegionTopology::FromJson(j, out, err);
}

bool ResolveTelcoPoolProfileArg(const std::string& spec,
                                samurai::control::TelcoLabSizingProfile& out,
                                std::string& err) {
  if (spec.empty()) return true;
  const std::string low = LowerCopy(spec);
  if (low == "linear" || low == "regional-bng" || low == "national-cgnat") {
    out = samurai::control::TelcoLabSizingProfile::Preset(low);
    return true;
  }
  Value j;
  if (!LoadJsonFileValue(spec, j, err)) return false;
  return samurai::control::TelcoLabSizingProfile::FromJson(j, out, err);
}

// Collect the job parameters (CLI or delegated) into a single JSON spec so both
// the local and cross-region delegated paths build a JobConfig the same way.
Value JobSpecFromArgs(int argc, char** argv,
                      const samurai::control::RegionTopology* preloaded_topo = nullptr,
                      const samurai::control::TelcoLabSizingProfile* preloaded_pool = nullptr) {
  using namespace samurai::control::daemon;
  Value s = Value::Object();
  s.set("count", Value::Int(OptInt(argc, argv, "--count", 0)));
  s.set("target", Value::Str(Opt(argc, argv, "--target", "127.0.0.1")));
  s.set("port", Value::Int(OptInt(argc, argv, "--port", 80)));
  s.set("protocol", Value::Str(Opt(argc, argv, "--protocol", "udp")));
  s.set("size", Value::Int(OptInt(argc, argv, "--size", 64)));
  s.set("worker", Value::Str(Opt(argc, argv, "--worker", "cpu")));
  s.set("transport", Value::Str(Opt(argc, argv, "--transport", "")));
  s.set("target_region", Value::Str(Opt(argc, argv, "--target-region", "")));
  s.set("target_asn", Value::Int(OptInt(argc, argv, "--target-asn", 0)));
  s.set("shard_strategy", Value::Str(Opt(argc, argv, "--shard-strategy", "")));
  if (preloaded_topo && (!preloaded_topo->asn_to_region.empty() || !preloaded_topo->region_aliases.empty())) {
    s.set("region_topology", preloaded_topo->ToJson());
  }
  s.set("job_timeout_s", Value::Int(OptInt(argc, argv, "--job-timeout-s", 0)));
  s.set("shard_unit_count", Value::Int(OptInt(argc, argv, "--shard-unit-count", 0)));
  s.set("poll_interval_ms", Value::Int(OptInt(argc, argv, "--poll-interval-ms", 250)));
  s.set("heartbeat_timeout_ms", Value::Int(OptInt(argc, argv, "--heartbeat-timeout-ms", 2000)));
  s.set("max_shard_retries", Value::Int(OptInt(argc, argv, "--max-shard-retries", 3)));
  s.set("on_worker_loss", Value::Str(Opt(argc, argv, "--on-worker-loss", "continue")));
  s.set("worker_status_probe", Value::Int(OptInt(argc, argv, "--worker-status-probe", 1)));
  s.set("target_rps", Value::Double(OptDouble(argc, argv, "--rps", 0.0)));
  s.set("db_port", Value::Int(OptInt(argc, argv, "--db-port", 5099)));

  // Telco distributed worker fields
  s.set("telco_subscribers", Value::Int(OptInt(argc, argv, "--telco-subscribers", 0)));
  s.set("telco_cps", Value::Int(OptInt(argc, argv, "--telco-cps", 5000)));
  s.set("telco_duration_ms", Value::Int(OptInt(argc, argv, "--telco-duration-ms", 0)));
  s.set("vlan_s", Value::Int(OptInt(argc, argv, "--vlan-s", 100)));
  s.set("vlan_c", Value::Int(OptInt(argc, argv, "--vlan-c", 10)));
  s.set("telco_base_ip", Value::Str(Opt(argc, argv, "--telco-base-ip", "10.0.0.1")));
  s.set("telco_gateway_ip", Value::Str(Opt(argc, argv, "--telco-gateway-ip", "10.0.0.254")));
  s.set("sctp_rate", Value::Int(OptInt(argc, argv, "--sctp-rate", 0)));
  const long diam_rate = OptInt(argc, argv, "--diameter-rate", 0);
  const long diam_ccr = OptInt(argc, argv, "--diameter-ccr-rate", 0);
  s.set("diameter_rate", Value::Int(diam_rate > 0 ? diam_rate : diam_ccr));
  s.set("sip_rate", Value::Int(OptInt(argc, argv, "--sip-rate", 0)));
  s.set("enable_srtp", Value::Bool(OptBoolFlag(argc, argv, "--enable-srtp", false)));
  s.set("teid_start", Value::Int(OptInt(argc, argv, "--teid-start", 1)));
  s.set("teid_count", Value::Int(OptInt(argc, argv, "--teid-count", 1)));
  s.set("qfi", Value::Int(OptInt(argc, argv, "--qfi", 9)));
  if (preloaded_pool && !preloaded_pool->buckets.empty()) {
    s.set("telco_pool_profile", preloaded_pool->ToJson());
  } else {
    const std::string p = Opt(argc, argv, "--telco-pool-profile", "");
    if (!p.empty()) s.set("telco_pool_profile", Value::Str(p));
  }

  // Production IPFIX / NetFlow v9 telemetry fields
  s.set("ipfix_enabled", Value::Bool(OptBoolFlag(argc, argv, "--ipfix-enabled", false)));
  s.set("ipfix_collector", Value::Str(Opt(argc, argv, "--ipfix-collector", "127.0.0.1")));
  s.set("ipfix_port", Value::Int(OptInt(argc, argv, "--ipfix-port", 4739)));
  s.set("ipfix_sample_rate", Value::Int(OptInt(argc, argv, "--ipfix-sample-rate", 1000)));
  s.set("ipfix_netflow_v9", Value::Bool(OptBoolFlag(argc, argv, "--ipfix-netflow-v9", false)));
  s.set("ipfix_domain_id", Value::Int(OptInt(argc, argv, "--ipfix-domain-id", 1)));
  s.set("ipfix_export_interval_ms", Value::Int(OptInt(argc, argv, "--ipfix-export-interval-ms", 1000)));
  return s;
}

samurai::control::JobConfig BuildJobConfig(const Value& spec, std::int64_t leader_epoch,
                                           const std::string& tenant,
                                           const std::string& master_region) {
  auto geti = [&](const char* k, std::int64_t d) {
    const Value* v = spec.find(k);
    return v ? v->as_int(d) : d;
  };
  auto getd = [&](const char* k, double d) {
    const Value* v = spec.find(k);
    return v ? v->as_double(d) : d;
  };
  auto getb = [&](const char* k, bool d) {
    const Value* v = spec.find(k);
    return v ? v->as_bool(d) : d;
  };
  auto gets = [&](const char* k, const char* d) {
    const Value* v = spec.find(k);
    return v ? v->as_string(d) : std::string(d);
  };
  auto get_ip_host = [&](const char* k, std::uint32_t d) -> std::uint32_t {
    const Value* v = spec.find(k);
    if (!v) return d;
    if (v->is_int()) return static_cast<std::uint32_t>(v->as_int(d));
    if (v->is_string()) return ParseIpv4HostOrder(v->as_string(""), d);
    return d;
  };
  samurai::control::JobConfig job;
  job.count = geti("count", 0);
  job.job_timeout_s = geti("job_timeout_s", 0);
  job.shard_unit_count = geti("shard_unit_count", 0);
  job.master_poll_interval_ms = static_cast<int>(geti("poll_interval_ms", 250));
  job.heartbeat_timeout_ms = geti("heartbeat_timeout_ms", 2000);
  job.max_shard_retries = static_cast<int>(geti("max_shard_retries", 3));
  job.on_worker_loss = gets("on_worker_loss", "continue");
  job.worker_status_probe = geti("worker_status_probe", 1) != 0;
  job.db_port = static_cast<int>(geti("db_port", 5099));
  job.tenant_namespace = tenant;
  job.leader_epoch = leader_epoch;
  const std::string tr = LowerCopy(gets("target_region", ""));
  job.target_region = tr;
  job.target_asn = static_cast<std::uint32_t>(std::max<std::int64_t>(0, geti("target_asn", 0)));
  if (const Value* rt = spec.find("region_topology"); rt && rt->is_object()) {
    std::string ignored_err;
    samurai::control::RegionTopology::FromJson(*rt, job.region_topology, ignored_err);
  }
  const std::string strat = LowerCopy(gets("shard_strategy", ""));
  job.worker_region = master_region;
  const std::string eff_region = job.region_topology.ResolveRegion(job.target_asn, tr);
  job.region_aware_routing = !eff_region.empty() || strat == "region";
  if (!strat.empty()) {
    job.shard_strategy = strat;
  } else if (!eff_region.empty()) {
    job.shard_strategy = "region";
  }

  const std::string wk = LowerCopy(gets("worker", "cpu"));
  const std::string proto = gets("protocol", "udp");
  const std::uint32_t tsubs =
      static_cast<std::uint32_t>(std::max<std::int64_t>(0, geti("telco_subscribers", 0)));
  job.is_telco_job = (wk == "telco" || tsubs > 0);
  job.telco_protocol = (!proto.empty() && LowerCopy(proto) != "udp") ? proto : "pppoe";
  job.telco_subscribers =
      tsubs > 0 ? tsubs : static_cast<std::uint32_t>(std::max<std::int64_t>(0, job.count));
  job.telco_rate_cps =
      static_cast<std::uint32_t>(std::max<std::int64_t>(1, geti("telco_cps", 5000)));
  job.telco_base_vlan_s =
      static_cast<std::uint16_t>(std::max<std::int64_t>(0, geti("vlan_s", 100)));
  job.telco_base_vlan_c =
      static_cast<std::uint16_t>(std::max<std::int64_t>(0, geti("vlan_c", 10)));
  job.telco_base_ip = get_ip_host("telco_base_ip", 0x0A000001u);
  job.telco_gateway_ip = get_ip_host("telco_gateway_ip", 0x0A0000FEu);
  job.telco_duration_ms =
      static_cast<std::uint32_t>(std::max<std::int64_t>(0, geti("telco_duration_ms", 0)));
  job.sctp_rate =
      static_cast<std::uint32_t>(std::max<std::int64_t>(0, geti("sctp_rate", 0)));
  job.diameter_rate =
      static_cast<std::uint32_t>(std::max<std::int64_t>(0, geti("diameter_rate", 0)));
  job.sip_rate =
      static_cast<std::uint32_t>(std::max<std::int64_t>(0, geti("sip_rate", 0)));
  job.enable_srtp = getb("enable_srtp", false);
  job.teid_start =
      static_cast<std::uint32_t>(std::max<std::int64_t>(0, geti("teid_start", 1)));
  job.teid_count =
      static_cast<std::uint32_t>(std::max<std::int64_t>(1, geti("teid_count", 1)));
  job.qfi = static_cast<std::uint8_t>(std::clamp<std::int64_t>(geti("qfi", 9), 0, 255));
  if (const Value* tp = spec.find("telco_pool_profile")) {
    if (tp->is_string()) {
      job.telco_pool_profile = samurai::control::TelcoLabSizingProfile::Preset(tp->as_string(""));
    } else if (tp->is_object()) {
      std::string ignored_err;
      samurai::control::TelcoLabSizingProfile::FromJson(*tp, job.telco_pool_profile, ignored_err);
    }
  }

  job.ipfix_enabled = getb("ipfix_enabled", false);
  job.ipfix_collector = gets("ipfix_collector", "127.0.0.1");
  job.ipfix_port = static_cast<std::uint16_t>(std::max<std::int64_t>(0, geti("ipfix_port", 4739)));
  job.ipfix_sample_rate =
      static_cast<std::uint32_t>(std::max<std::int64_t>(1, geti("ipfix_sample_rate", 1000)));
  job.ipfix_netflow_v9 = getb("ipfix_netflow_v9", false);
  job.ipfix_domain_id =
      static_cast<std::uint32_t>(std::max<std::int64_t>(0, geti("ipfix_domain_id", 1)));
  job.ipfix_export_interval_ms =
      static_cast<std::uint32_t>(std::max<std::int64_t>(50, geti("ipfix_export_interval_ms", 1000)));

  job.base_args = Value::Object();
  job.base_args.set("target", Value::Str(gets("target", "127.0.0.1")));
  job.base_args.set("port", Value::Int(geti("port", 80)));
  job.base_args.set("protocol", Value::Str(proto));
  job.base_args.set("size", Value::Int(geti("size", 64)));
  job.base_args.set("worker", Value::Str(gets("worker", "cpu")));
  job.base_args.set("db_port", Value::Int(job.db_port));
  const double trps = getd("target_rps", 0.0);
  if (trps > 0.0) {
    job.base_args.set("target_rps", Value::Double(trps));
  }
  job.base_args.set("ipfix_enabled", Value::Bool(job.ipfix_enabled));
  job.base_args.set("ipfix_collector", Value::Str(job.ipfix_collector));
  job.base_args.set("ipfix_port", Value::Int(job.ipfix_port));
  job.base_args.set("ipfix_sample_rate", Value::Int(job.ipfix_sample_rate));
  job.base_args.set("ipfix_netflow_v9", Value::Bool(job.ipfix_netflow_v9));
  job.base_args.set("ipfix_domain_id", Value::Int(job.ipfix_domain_id));
  job.base_args.set("ipfix_export_interval_ms", Value::Int(job.ipfix_export_interval_ms));
  if (job.is_telco_job) {
    job.base_args.set("telco_protocol", Value::Str(job.telco_protocol));
    job.base_args.set("telco_subscribers", Value::Int(job.telco_subscribers));
    job.base_args.set("telco_cps", Value::Int(job.telco_rate_cps));
    job.base_args.set("telco_duration_ms", Value::Int(job.telco_duration_ms));
    job.base_args.set("vlan_s", Value::Int(job.telco_base_vlan_s));
    job.base_args.set("vlan_c", Value::Int(job.telco_base_vlan_c));
    job.base_args.set("telco_base_ip", Value::Int(job.telco_base_ip));
    job.base_args.set("telco_gateway_ip", Value::Int(job.telco_gateway_ip));
    job.base_args.set("sctp_rate", Value::Int(job.sctp_rate));
    job.base_args.set("diameter_rate", Value::Int(job.diameter_rate));
    job.base_args.set("sip_rate", Value::Int(job.sip_rate));
    job.base_args.set("enable_srtp", Value::Bool(job.enable_srtp));
    job.base_args.set("teid_start", Value::Int(job.teid_start));
    job.base_args.set("teid_count", Value::Int(job.teid_count));
    job.base_args.set("qfi", Value::Int(job.qfi));
  }
  // Dataplane transport for L7 workers. Made explicit here (rather than relying on
  // the worker's SAMURAI_L7_TRANSPORT env) so master and worker agree on a single
  // source of truth and the RL corpus can record it — the flow-level IPS features
  // are only meaningful on a flow-capable (userspace-TCP) transport.
  const std::string transport = gets("transport", "");
  if (!transport.empty()) {
    Value conn = Value::Object();
    conn.set("transport_backend", Value::Str(transport));
    job.base_args.set("connection_template", conn);
  }
  return job;
}

void Usage(const char* argv0) {
  std::printf(
      "usage: %s --count N [options]\n"
      "  --control-listen EP       control server bind (default tcp://0.0.0.0:5099)\n"
      "  --cluster-secret S        cluster secret (or env SAMURAI_CLUSTER_SECRET)\n"
      "  --tenant-namespace T      tenant namespace\n"
      "  --curve-server-secret K   enable CURVE encryption (Z85 server secret key;\n"
      "                            or env SAMURAI_CURVE_SERVER_SECRET)\n"
      "  --gen-curve-keys          print a fresh CURVE keypair and exit\n"
      "  --insecure-control        allow a non-loopback control bind without CURVE\n"
      "                            (cluster secret sent in cleartext — unsafe)\n"
      "  --count N                 total packets for the job (required, > 0)\n"
      "  --target IP               target ipv4 (default 127.0.0.1)\n"
      "  --port N                  target port (default 80)\n"
      "  Target consent gate (private/loopback only by default):\n"
      "  --allow-target IP|CIDR    allowlist a target (repeatable); required to\n"
      "                            drive a non-private target\n"
      "  --allow-public-target     permit any public target (use with care; a\n"
      "                            --deny-target still wins)\n"
      "  --deny-target IP|CIDR     denylist a target (repeatable; always wins)\n"
      "  --protocol P              l4/telco protocol (default udp; telco: pppoe|dhcp|gtpu|bfd|pfcp|sctp|diameter|sip-rtp|multi)\n"
      "  --size N                  packet size (default 64)\n"
      "  --worker NAME             worker flavor this job needs (default cpu; includes telco); only\n"
      "                            dispatched to workers advertising that kind\n"
      "  --db-port N               telemetry/state DB port (default 5099)\n"
      "  Telco distributed workload flags:\n"
      "  --telco-subscribers N     subscriber count across cluster\n"
      "  --telco-cps N             subscriber setup rate CPS (default 5000)\n"
      "  --telco-duration-ms N     bounded run duration in ms (allows --count 0 with --worker telco)\n"
      "  --vlan-s N / --vlan-c N   QinQ S-VLAN / C-VLAN base (defaults 100 / 10)\n"
      "  --telco-base-ip IP        subscriber base IP (default 10.0.0.1)\n"
      "  --telco-gateway-ip IP     BNG/UPF gateway IP (default 10.0.0.254)\n"
      "  --sctp-rate N / --diameter-rate N / --sip-rate N / --enable-srtp\n"
      "  --teid-start N / --teid-count N / --qfi N\n"
      "  --telco-pool-profile X    isolated CGNAT/BNG pool layout (linear|regional-bng|\n"
      "                            national-cgnat|PATH_JSON within RFC1918/6598/2544)\n"
      "  Production IPFIX / NetFlow v9 telemetry:\n"
      "  --ipfix-enabled [0|1]     enable live UDP IPFIX/NetFlow v9 flow export\n"
      "  --ipfix-collector IP      collector host (default 127.0.0.1)\n"
      "  --ipfix-port N            collector UDP port (default 4739)\n"
      "  --ipfix-sample-rate N     1:N flow sampling rate (default 1000)\n"
      "  --ipfix-netflow-v9 [0|1]  use NetFlow v9 instead of IPFIX v10\n"
      "  --ipfix-domain-id N       observation domain id (default 1)\n"
      "  --ipfix-export-interval-ms N  export cadence in ms (default 1000)\n"
      "  --transport T             L7 dataplane transport (kernel_socket|custom_tcp|\n"
      "                            dpdk|af_xdp|af_packet); recorded in the RL corpus\n"
      "                            and gates the flow-level IPS features (custom_tcp\n"
      "                            et al. expose the flow counters; kernel_socket does not)\n"
      "  --shard-unit-count N      packets per shard (0 = auto)\n"
      "  --job-timeout-s N         wait cap for the job (default 120)\n"
      "  --poll-interval-ms N      master dispatch poll (default 250)\n"
      "  --heartbeat-timeout-ms N  worker heartbeat timeout in ms (default 2000)\n"
      "  --max-shard-retries N     maximum retries for lost shards (default 3)\n"
      "  --on-worker-loss continue|abort (default continue)\n"
      "  --worker-status-probe 0|1 actively probe worker status (default 1)\n"
      "  --rpc-timeout-ms N        RPC timeout toward workers (default 2000)\n"
      "  --expect-workers N        wait for this many workers first (default 1)\n"
      "  --wait-workers-s N        how long to wait for workers (default 30)\n"
      "  --management-listen EP    also serve the HTTP management API (host:port)\n"
      "  --mgmt-tls                serve the management API over TLS (https)\n"
      "  --mgmt-tls-cert PATH      PEM cert chain (self-signed if cert/key omitted)\n"
      "  --mgmt-tls-key PATH       PEM private key\n"
      "  --agent-join-token T      enable zero-install agent join on the mgmt API\n"
      "                            (curl .../v1/agent/install?token=T | sh); the\n"
      "                            token is also the manifest HMAC key\n"
      "  --agent-artifact-dir DIR  dir with samurai_slave + worker binaries to serve\n"
      "  --agent-advertise EP      public control endpoint agents connect to\n"
      "                            (default: --control-listen value)\n"
      "  --agent-worker NAME       worker kind agents run, or 'bundle' to ship all\n"
      "                            worker binaries and pick per shard (default cpu)\n"
      "  --agent-dispatch-mode M   reverse | auto for agents (default reverse)\n"
      "  --agent-insecure-http     allow agent bootstrap on a non-loopback mgmt\n"
      "                            bind (join token + secret sent in cleartext)\n"
      "  Agent push provisioner (trigger connections to remote nodes):\n"
      "  --provision-hosts CSV     host[:port] list to trigger over SSH and auto-join\n"
      "  --provision-ssh-user U    SSH username on target nodes (default root)\n"
      "  --provision-ssh-key PATH  SSH private key for targets (default system default)\n"
      "  --provision-worker NAME   worker kind to deploy (default agent-worker)\n"
      "  --provision-timeout-s N   wait up to N seconds for heartbeat (default 10)\n"
      "  --target-region R         route/delegate this job to region R (region-\n"
      "                            aware shard routing; cross-region delegation)\n"
      "  --target-asn N            resolve target region via --region-map-file\n"
      "  --region-map-file PATH    JSON ASN->region and alias topology file\n"
      "  --shard-strategy S        equal | capability | region (default auto)\n"
      "  --ha-mode MODE            static | file-lock | redis (default off)\n"
      "  --ha-node-id ID           this node's id\n"
      "  --ha-peers CSV            peer node ids (static mode)\n"
      "  --ha-lease-path PATH      lease file (file-lock mode)\n"
      "  --ha-lease-key KEY        Redis lease key (redis mode;\n"
      "                            default samurai:ha:<tenant|default>:lease)\n"
      "  Multi-master (region federation):\n"
      "  --multi-master-enable     coordinate with peer-region masters over Redis;\n"
      "                            delegate/serve cross-region jobs. With this set,\n"
      "                            --count 0 means serve-only (no local job)\n"
      "  --multi-master-region-id R  this master's region (default: --target-region\n"
      "                            unset -> required when enabled)\n"
      "  --multi-master-redis-url U  default redis://127.0.0.1:6379/0\n"
      "  --multi-master-namespace N  key-prefix isolation (default 'default')\n"
      "  --multi-master-heartbeat-ttl-s N  region heartbeat TTL (default 15)\n"
      "  --multi-master-dequeue-max N  delegated jobs pulled per poll (default 3)\n"
      "  Autoscale (worker replica controller; live k8s scale patch or in-memory):\n"
      "  --autoscale-enable        evaluate desired worker replicas from live load\n"
      "                            and surface it (log + management API). Keeps the\n"
      "                            master running as a persistent controller\n"
      "  --autoscale-target-name N  scale target name (required to activate)\n"
      "  --autoscale-target-kind K  deployment | statefulset (default deployment)\n"
      "  --autoscale-namespace N   target namespace (default 'default')\n"
      "  --autoscale-min N         min replicas (default 1)\n"
      "  --autoscale-max N         max replicas (default 100)\n"
      "  --autoscale-step N        max replica delta per step (default 1)\n"
      "  --autoscale-cooldown-s N  min seconds between scale steps (default 15)\n"
      "  --autoscale-shards-per-worker N  target shards per worker (default 4)\n"
      "  --autoscale-idle-scale-down-s N  idle secs before scaling to min (default 60)\n"
      "  --autoscale-k8s-api URL   scale via this API base (e.g. http://127.0.0.1:8001\n"
      "                            from `kubectl proxy`); omit to auto-detect the\n"
      "                            in-cluster service account, else in-memory only\n"
      "  --autoscale-k8s-insecure  skip TLS verification for the k8s API (dev only)\n"
      "  Autopilot (closed-loop load controller; find/hold the SUT's SLO ceiling):\n"
      "  --closed-loop             drive target_rps across measured windows to find\n"
      "                            and hold the max load that stays SLO-green\n"
      "  --cl-strategy S           aimd | binsearch | rl (default aimd)\n"
      "  --cl-window-s N           seconds per measured window (default 5)\n"
      "  --cl-live-reconfigure     drive closed-loop transitions via live ReconfigureShard RPCs\n"
      "  --cl-min-rps N            setpoint floor (default 1)\n"
      "  --cl-max-rps N            setpoint ceiling (default 1000000)\n"
      "  --cl-initial-rps N        first setpoint (0 => min)\n"
      "  --cl-slo-max-error-pct X  SLO: errors/attempted*100 <= X (0 = rule off)\n"
      "  --cl-slo-max-loss-pct X   SLO: wire loss %% <= X (0 = off)\n"
      "  --cl-slo-min-rate-accuracy-pct X  SLO: rate accuracy %% >= X (0 = off)\n"
      "  --cl-slo-max-latency-ms X SLO: SUT p99 ms <= X (needs --sut-*; 0 = off)\n"
      "  --cl-slo-max-pushback-pct X  SLO: (4xx+5xx)/responses*100 <= X (0 = off);\n"
      "                            flags ramping into a rate wall so the loop settles\n"
      "                            at the honored ceiling instead of maxing into 429s\n"
      "  --cl-aimd-increase-rps N  AIMD additive step (0 => 10%% of range)\n"
      "  --cl-aimd-backoff X       AIMD multiplicative decrease, (0,1) (default 0.5)\n"
      "  --cl-aimd-max-windows N   AIMD window budget (0 => unbounded soak)\n"
      "  --cl-binsearch-tolerance-rps N  binsearch stop width (0 => 1%% of range)\n"
      "  --cl-binsearch-max-windows N    binsearch window cap (default 24)\n"
      "  SUT correlation (feed target-side p99 into the latency SLO):\n"
      "  --sut-prometheus-url U    Prometheus base to scrape per window\n"
      "  --sut-latency-p99-query Q PromQL returning the SUT p99 latency (ms)\n"
      "  --sut-extra-queries L     ';'-separated name=promql pairs to record\n"
      "  --sut-timeout-s N         scrape timeout (default 5)\n"
      "  --sut-insecure            skip TLS verification for the Prometheus scrape\n"
      "  RL layer (offline-RL corpus + learned-policy serving for the autopilot):\n"
      "  --rl-corpus PATH          append one (s,a,s') NDJSON record per closed-loop\n"
      "                            window to PATH (training data; reward computed\n"
      "                            offline in samurai/models/rl). Needs\n"
      "                            --closed-loop; off => zero overhead\n"
      "  --rl-policy PATH          SRLP weight file to serve with --cl-strategy rl\n"
      "                            (or env SAMURAI_RL_POLICY). Exported by\n"
      "                            samurai/models/rl/export.py; load failure\n"
      "                            degrades kRl to the AIMD safety fallback\n"
      "  --cl-rl-max-jump-factor X kRl shield: cap the upward setpoint jump to X x\n"
      "                            the last setpoint per window (default 2.0)\n"
      "  --cl-lever-shield 0|1     kRl lever shield: veto a request_mix the target\n"
      "                            path-blocks online, substituting an honored one\n"
      "                            (default 1; only active when a policy is loaded)\n"
      "  --cl-lever-variants N     request_mix cardinality for the shield (default 5)\n"
      "  --cl-variant-memory FILE  persist per-target block memory (JSON) across runs:\n"
      "                            warm-start the shield + block state feature from what\n"
      "                            a prior run learned about this target (default off)\n"
      "  --cl-online-adapt 0|1     serving-time continual fine-tuning: a bounded online\n"
      "                            setpoint correction learned from the served-throughput\n"
      "                            reward, with a champion-challenger rollback guard\n"
      "  --cl-online-adapt-lr X    online adapter ES step size (default 0.10)\n"
      "  --cl-online-adapt-max-dev X  clamp |correction| so applied rps stays in\n"
      "                            [1-X, 1+X]*proposed (default 0.30)\n"
      "  --cl-online-adapt-memory FILE  persist the learned correction (JSON) per target\n"
      "  --cl-novelty 0|1          open-vocabulary detection of an un-modelled defense\n"
      "                            (success failing with no known signal); names it and\n"
      "                            damps the kRl setpoint while the novel regime holds. A\n"
      "                            recurring signature GRADUATES to its own learned lever,\n"
      "                            tuned by outcome (a new response axis for that defense)\n"
      "  --cl-novelty-threshold X  unexplained-loss to flag a window novel (default 0.35)\n"
      "  --cl-novelty-backoff X    default lever for an un-graduated signature (default 0.85)\n"
      "  --cl-novelty-min-damping X floor on a learned per-signature lever (default 0.50)\n"
      "  --cl-novelty-promote N    novel windows before a signature graduates (default 3)\n"
      "  --cl-novelty-memory FILE  persist the discovered signatures + learned levers per target\n"
      "  --cl-ban-memory FILE      persist per-target ban pressure (JSON) across runs:\n"
      "                            warm-start the persistent-ban state feature so a run\n"
      "                            against an already-banned target starts armed (a\n"
      "                            ban-aware policy, in_dim +2; default off)\n"
      "  --rl-explore              perturb the shaping levers (concurrency/\n"
      "                            request_mix/source_rotation/pacing_mode) per\n"
      "                            window during --rl-corpus capture so they vary\n"
      "                            and become learnable offline (no policy needed)\n"
      "  --rl-explore-seed N       reproducible exploration schedule (default 0)\n"
      "  --rl-explore-<lever> lo:hi  override one lever's range, e.g.\n"
      "                            --rl-explore-concurrency 1:32\n"
      "  -h, --help\n",
      argv0);
}
}  // namespace

int main(int argc, char** argv) {
  using namespace samurai::control;
  using namespace samurai::control::daemon;

  if (Flag(argc, argv, "-h") || Flag(argc, argv, "--help")) {
    Usage(argv[0]);
    return 0;
  }
  if (Flag(argc, argv, "--gen-curve-keys")) {
    const CurveKeypair kp = GenerateCurveKeypair();
    if (!kp.ok) {
      std::fprintf(stderr, "samurai_master: CURVE not supported by this libzmq build\n");
      return 1;
    }
    std::printf("curve_public=%s\ncurve_secret=%s\n", kp.public_key.c_str(), kp.secret_key.c_str());
    return 0;
  }

  // 1. Anti-tamper & binary self-integrity verification (deferred past diagnostic flags)
  const samurai::licensing::IntegrityResult integrity = samurai::licensing::VerifySelfIntegrity();
  if (!integrity.ok) {
    std::fprintf(stderr, "samurai_master security violation: %s\n", integrity.reason.c_str());
    return 126;
  }

  // 2. License resolution and feature-gate enforcement
  std::string license_key = Opt(argc, argv, "--license-key", "");
  const std::string license_file = Opt(argc, argv, "--license-file", "");
  if (license_key.empty() && !license_file.empty()) {
    std::ifstream f(license_file);
    if (f) {
      std::stringstream ss;
      ss << f.rdbuf();
      license_key = ss.str();
      const auto first = license_key.find_first_not_of(" \t\r\n");
      const auto last = license_key.find_last_not_of(" \t\r\n");
      license_key = (first == std::string::npos) ? "" : license_key.substr(first, last - first + 1);
    }
  }
  if (license_key.empty()) {
    license_key = samurai::licensing::EnvOr("SAMURAI_LICENSE_KEY", "");
  }
  if (license_key.empty()) {
    std::ifstream f(samurai::licensing::LicenseKeyFile());
    if (f) {
      std::stringstream ss;
      ss << f.rdbuf();
      license_key = ss.str();
      const auto first = license_key.find_first_not_of(" \t\r\n");
      const auto last = license_key.find_last_not_of(" \t\r\n");
      license_key = (first == std::string::npos) ? "" : license_key.substr(first, last - first + 1);
    }
  }

  const std::string hwid = samurai::licensing::GetHardwareId();
  samurai::licensing::LicenseResult lr;
  samurai::licensing::HttpLicenseClient license_client(samurai::licensing::LicenseServerUrl(),
                                                       samurai::licensing::RequestTimeoutS());

  if (samurai::licensing::IsDevMode()) {
    lr.valid = true;
    lr.tier = samurai::licensing::Tier::kEnterprise;
    lr.features = samurai::licensing::TierFeatures(samurai::licensing::Tier::kEnterprise);
  } else if (!license_key.empty()) {
    lr = license_client.Validate(license_key, hwid);
    if (lr.valid) {
      samurai::licensing::SaveCache(lr, hwid);
    } else {
      samurai::licensing::LicenseResult cached;
      if (samurai::licensing::LoadCache(hwid, cached) && cached.valid) {
        lr = cached;
      } else {
        std::fprintf(stderr, "samurai_master license error: license validation failed: %s\n",
                     lr.reason.empty() ? "invalid license key" : lr.reason.c_str());
        return 2;
      }
    }
  } else {
    if (!samurai::licensing::LoadCache(hwid, lr) || !lr.valid) {
      lr.valid = true;
      lr.tier = samurai::licensing::Tier::kCommunity;
      lr.features = samurai::licensing::TierFeatures(samurai::licensing::Tier::kCommunity);
      lr.limits = samurai::licensing::TierLimitsFor(samurai::licensing::Tier::kCommunity);
    }
  }

  const long count = OptInt(argc, argv, "--count", 0);
  const long telco_subs = OptInt(argc, argv, "--telco-subscribers", 0);
  const long telco_dur_ms = OptInt(argc, argv, "--telco-duration-ms", 0);
  const bool mm_enabled = Flag(argc, argv, "--multi-master-enable");

  // Feature gate check for Master parameters
  const std::string worker_kind = Opt(argc, argv, "--worker", "cpu");
  const bool has_telco_job =
      (LowerCopy(worker_kind) == "telco" && (telco_subs > 0 || telco_dur_ms > 0));
  const bool has_local_job = (count > 0) || has_telco_job;
  const long effective_count = count > 0 ? count : telco_subs;
  // Multi-master masters may be serve-only (they run delegated jobs pulled from
  // peer regions), so --count 0 is allowed then; otherwise a job needs a count
  // (or --worker telco with subscribers/duration).
  if (!has_local_job && !mm_enabled) {
    std::fprintf(stderr, "samurai_master: --count must be > 0\n");
    return 2;
  }
  const std::string shard_strategy = LowerCopy(Opt(argc, argv, "--shard-strategy", ""));
  if (!shard_strategy.empty() && shard_strategy != "equal" &&
      shard_strategy != "capability" && shard_strategy != "region") {
    std::fprintf(stderr,
                 "samurai_master: invalid --shard-strategy '%s' (equal|capability|region)\n",
                 shard_strategy.c_str());
    return 2;
  }
  samurai::control::RegionTopology cli_region_topo;
  {
    const std::string rmf = Opt(argc, argv, "--region-map-file", "");
    std::string rerr;
    if (!ResolveRegionTopologyArg(rmf, cli_region_topo, rerr)) {
      std::fprintf(stderr, "samurai_master: --region-map-file error: %s\n", rerr.c_str());
      return 2;
    }
  }
  samurai::control::TelcoLabSizingProfile cli_telco_pool;
  {
    const std::string tpp = Opt(argc, argv, "--telco-pool-profile", "");
    std::string perr;
    if (!ResolveTelcoPoolProfileArg(tpp, cli_telco_pool, perr)) {
      std::fprintf(stderr, "samurai_master: --telco-pool-profile error: %s\n", perr.c_str());
      return 2;
    }
  }
  const std::uint32_t cli_target_asn =
      static_cast<std::uint32_t>(std::max<long>(0, OptInt(argc, argv, "--target-asn", 0)));

  const std::string vector = Opt(argc, argv, "--vector", "basic");
  const double rps = std::strtod(Opt(argc, argv, "--rps", "0").c_str(), nullptr);
  const int expected_workers = OptInt(argc, argv, "--workers", 1);

  samurai::licensing::GateInput gate_in;
  gate_in.attack_vector = vector;
  gate_in.compute_backend = worker_kind;
  gate_in.rps = rps;
  gate_in.has_role = true;
  gate_in.role = "master";
  gate_in.license_key = license_key;
  gate_in.license_file = license_file;
  if (effective_count > 0 && rps > 0.0) {
    gate_in.duration = static_cast<long>(effective_count / rps);
  } else if (telco_dur_ms > 0) {
    gate_in.duration = std::max<long>(1, telco_dur_ms / 1000);
  } else if (effective_count > 0) {
    gate_in.duration = 1;
  }

  samurai::licensing::GateResult gate_res =
      samurai::licensing::EnforceFeatureGates(gate_in, lr, &license_client);
  if (!gate_res.ok) {
    std::fprintf(stderr, "samurai_master license error: %s\n%s\n", gate_res.error.c_str(),
                 gate_res.upgrade_hint.c_str());
    return 2;
  }
  for (const auto& w : gate_res.warnings) {
    std::fprintf(stderr, "samurai_master license warning: %s\n", w.c_str());
  }

  if (lr.limits.has_value && lr.limits.max_workers > 0 && expected_workers > lr.limits.max_workers) {
    std::fprintf(stderr,
                 "samurai_master license error: requested %d workers exceeds tier limit of %d (tier: %s)\n",
                 expected_workers, lr.limits.max_workers, samurai::licensing::TierName(lr.tier).c_str());
    return 2;
  }

  // Consent gate for the local job's target. The closed-loop / RL serving path
  // never went through cli::Validate, so it previously skipped the same safety
  // check the one-shot CLI enforces. Apply core::ValidateTargetSafety here so
  // autopilot can only be pointed at user-controlled infrastructure: private /
  // loopback by default, or an explicit --allow-target / --allow-public-target
  // allowlist (a --deny-target always wins). Serve-only masters (count<=0,
  // multi-master) carry no local target; delegated jobs are gated at their
  // originating master, so only validate when there is a local job to run.
  if (has_local_job) {
    const std::string tgt = Opt(argc, argv, "--target", "127.0.0.1");
    const auto safety = samurai::core::ValidateTargetSafety(
        tgt, OptAll(argc, argv, "--allow-target"),
        Flag(argc, argv, "--allow-public-target"),
        OptAll(argc, argv, "--deny-target"));
    if (!safety.ok) {
      std::fprintf(stderr, "samurai_master: refusing target %s: %s\n",
                   tgt.c_str(), safety.reason.c_str());
      return 2;
    }
  }

  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);

  const std::string ha_mode = Opt(argc, argv, "--ha-mode", "off");

  // Shared Redis KvStore, backing both cross-region multi-master coordination
  // and (optionally) the Redis-lease HA elector. Unreachable/absent Redis is not
  // fatal: the master degrades to a single, standalone region.
  std::unique_ptr<KvStore> kv;
  if (mm_enabled || ha_mode == "redis") {
    const std::string url = Opt(argc, argv, "--multi-master-redis-url", "redis://127.0.0.1:6379/0");
    std::string kverr;
    kv = MakeKvStore(url, kverr);
    if (!kv) {
      std::fprintf(stderr,
          "samurai_master: Redis backend unavailable (%s); multi-master / redis-HA\n"
          "  disabled — running as a single standalone region.\n",
          kverr.c_str());
    } else {
      std::printf("samurai_master: Redis backend connected (%s)\n", url.c_str());
    }
  }

  // HA leadership (optional).
  std::unique_ptr<LeaderElector> elector;
  if (ha_mode == "static") {
    elector = std::make_unique<StaticLeaderElector>(Opt(argc, argv, "--ha-node-id", ""),
                                                    Opt(argc, argv, "--ha-peers", ""));
  } else if (ha_mode == "file-lock") {
    elector = std::make_unique<FileLeaseLeaderElector>(
        Opt(argc, argv, "--ha-node-id", ""),
        Opt(argc, argv, "--ha-lease-path", "/tmp/samurai_master_lease.json"), 15.0);
  } else if (ha_mode == "redis") {
    if (kv) {
      const std::string tenant0 = Opt(argc, argv, "--tenant-namespace", "");
      const std::string lease_key = Opt(argc, argv, "--ha-lease-key",
          "samurai:ha:" + (tenant0.empty() ? std::string("default") : tenant0) + ":lease");
      elector = std::make_unique<RedisLeaseLeaderElector>(
          Opt(argc, argv, "--ha-node-id", ""), lease_key, kv.get(), 15.0);
    } else {
      std::fprintf(stderr,
          "samurai_master: --ha-mode redis requires a reachable Redis; skipping HA\n");
    }
  }
  if (elector) {
    if (!elector->TryAcquire() || !elector->IsLeader()) {
      std::printf("samurai_master: not leader (%s); skipping master run\n",
                  elector->Snapshot().dump().c_str());
      return 0;
    }
    elector->StartRenewLoop(5.0);
  }
  // Fencing token, read live at each dispatch. The elector bumps its epoch on a
  // fresh re-acquire (lose+regain lease), so a cached value would let a briefly
  // re-elected leader keep stamping a stale epoch and get its own work fenced.
  auto* elector_ptr = elector.get();
  const auto current_leader_epoch = [elector_ptr]() -> std::int64_t {
    return elector_ptr ? elector_ptr->LeaderEpoch() : 0;
  };

  // Cross-region multi-master coordinator (region federation). Active only with
  // a reachable Redis backend; otherwise a harmless no-op (single region).
  std::unique_ptr<RedisMultiMasterCoordinator> mm;
  std::string master_region;
  if (mm_enabled) {
    MultiMasterConfig mmcfg;
    mmcfg.enabled = true;
    mmcfg.namespace_ = Opt(argc, argv, "--multi-master-namespace", "default");
    mmcfg.region_id =
        Opt(argc, argv, "--multi-master-region-id", Opt(argc, argv, "--target-region", ""));
    mmcfg.node_id = Opt(argc, argv, "--ha-node-id", "master");
    mmcfg.heartbeat_ttl_s =
        static_cast<int>(OptInt(argc, argv, "--multi-master-heartbeat-ttl-s", 15));
    master_region = LowerCopy(mmcfg.region_id);
    mm = std::make_unique<RedisMultiMasterCoordinator>(mmcfg, kv.get());
    if (mm->active()) {
      std::printf("samurai_master: multi-master active (region=%s namespace=%s)\n",
                  master_region.c_str(), mmcfg.namespace_.c_str());
      if (master_region.empty()) {
        std::fprintf(stderr,
            "samurai_master: WARNING: multi-master enabled with an empty region id;\n"
            "  heartbeat/dequeue are disabled. Set --multi-master-region-id.\n");
      }
    } else {
      std::fprintf(stderr,
          "samurai_master: multi-master enabled but coordinator inactive (no Redis);\n"
          "  running as a single standalone region.\n");
    }
  }

  // Autoscale controller (optional). The scaling *decision* state machine is
  // native and driven by live cluster load; the K8s read/patch backend is
  // deferred, so it runs in in-memory mode — it computes and surfaces desired
  // worker replica counts (log + management API) but does not patch a cluster.
  AutoscaleConfig ascfg;
  ascfg.enabled = Flag(argc, argv, "--autoscale-enable");
  ascfg.namespace_ = Opt(argc, argv, "--autoscale-namespace", "default");
  ascfg.target_kind = Opt(argc, argv, "--autoscale-target-kind", "deployment");
  ascfg.target_name = Opt(argc, argv, "--autoscale-target-name", "");
  ascfg.min_replicas = static_cast<int>(OptInt(argc, argv, "--autoscale-min", 1));
  ascfg.max_replicas = static_cast<int>(OptInt(argc, argv, "--autoscale-max", 100));
  ascfg.step = static_cast<int>(OptInt(argc, argv, "--autoscale-step", 1));
  ascfg.cooldown_s = static_cast<double>(OptInt(argc, argv, "--autoscale-cooldown-s", 15));
  ascfg.shards_per_worker = static_cast<int>(OptInt(argc, argv, "--autoscale-shards-per-worker", 4));
  ascfg.idle_scale_down_s =
      static_cast<double>(OptInt(argc, argv, "--autoscale-idle-scale-down-s", 60));
  const bool autoscale_on = ascfg.enabled && !ascfg.target_name.empty();
  std::unique_ptr<AutoscaleController> autoscaler;
  if (ascfg.enabled) {
    if (ascfg.target_name.empty()) {
      std::fprintf(stderr,
          "samurai_master: WARNING: --autoscale-enable without --autoscale-target-name;\n"
          "  the controller stays disabled (no target to scale).\n");
    } else {
      autoscaler = std::make_unique<AutoscaleController>(ascfg);
      std::printf("samurai_master: autoscale enabled (target=%s/%s ns=%s min=%d max=%d spw=%d)\n",
                  ascfg.target_kind.c_str(), ascfg.target_name.c_str(), ascfg.namespace_.c_str(),
                  ascfg.min_replicas, ascfg.max_replicas, ascfg.shards_per_worker);
      // Resolve a live Kubernetes backend: an explicit --autoscale-k8s-api (e.g.
      // `kubectl proxy`) wins, else in-cluster service-account auto-detect. When
      // none resolves the controller stays in in-memory decision-only mode.
      const K8sConfig k8scfg = ResolveK8sConfig(Opt(argc, argv, "--autoscale-k8s-api", ""),
                                                Flag(argc, argv, "--autoscale-k8s-insecure"));
      if (k8scfg.active) {
        const std::string kind = ascfg.target_kind;
        const std::string ns = ascfg.namespace_;
        const std::string name = ascfg.target_name;
        AutoscaleBackend backend;
        backend.read_replicas = [k8scfg, kind, ns, name](int& out) {
          const ScaleResult r = GetScale(k8scfg, kind, ns, name);
          if (!r.ok) {
            std::fprintf(stderr, "samurai_master: autoscale k8s read failed: %s\n", r.error.c_str());
            return false;
          }
          out = r.replicas;
          return true;
        };
        backend.patch_replicas = [k8scfg, kind, ns, name](int desired, int& applied) {
          const ScaleResult r = PatchScale(k8scfg, kind, ns, name, desired);
          if (!r.ok) {
            std::fprintf(stderr, "samurai_master: autoscale k8s patch failed: %s\n",
                         r.error.c_str());
            return false;
          }
          applied = r.replicas;
          return true;
        };
        autoscaler->set_backend(std::move(backend));
        std::printf("samurai_master: autoscale backend=kubernetes (source=%s api=%s)\n",
                    k8scfg.source.c_str(), k8scfg.api_base.c_str());
      } else {
        std::printf("samurai_master: autoscale backend=in-memory "
                    "(no k8s config; decision-only)\n");
      }
    }
  }
  // Live load signals fed by the coordinator's progress_cb; the autoscale thread
  // reads them and publishes its latest decision under as_mu.
  std::atomic<int> as_pending{0};
  std::atomic<int> as_inflight{0};
  std::mutex as_mu;
  Value as_json = Value::Object();

  // Closed-loop (autopilot) load controller. The setpoint-search decision state
  // machine is native; master drives it by running one RunSingleJob window per
  // step at the current target_rps and folding the aggregated snapshot back into
  // a LoadSample. Latest decision is published under cl_mu for the mgmt API.
  const samurai::control::ClosedLoopConfig clcfg = BuildClosedLoopConfig(argc, argv);
  std::mutex cl_mu;
  Value cl_json = Value::Object();

  // Control server.
  const std::string cluster_secret =
      OptOrEnv(argc, argv, "--cluster-secret", "SAMURAI_CLUSTER_SECRET");
  const std::string tenant = Opt(argc, argv, "--tenant-namespace", "");
  ServicerConfig scfg;
  scfg.tenant_namespace = tenant;
  Servicer servicer(scfg);
  AuthConfig auth;
  auth.expected_secret = cluster_secret;
  const std::string control_listen = Opt(argc, argv, "--control-listen", "tcp://0.0.0.0:5099");
  ControlServer server(control_listen, &servicer, auth);
  const std::string curve_secret =
      OptOrEnv(argc, argv, "--curve-server-secret", "SAMURAI_CURVE_SERVER_SECRET");
  std::string curve_public;
  if (!curve_secret.empty()) {
    server.set_curve_server(curve_secret);
    curve_public = CurvePublicFromSecret(curve_secret);
    std::printf("samurai_master: CURVE encryption enabled on the control server\n");
  }
  // Public-exposure safety: on a non-loopback bind the cluster secret travels
  // the control channel app-layer, so refuse plaintext unless explicitly forced.
  if (!IsLoopbackEndpoint(control_listen) && curve_secret.empty()) {
    if (!Flag(argc, argv, "--insecure-control")) {
      std::fprintf(stderr,
          "samurai_master: refusing to bind the control server to a non-loopback\n"
          "  address (%s) without CURVE — the cluster secret would travel in\n"
          "  cleartext. Enable --curve-server-secret, bind to loopback behind a\n"
          "  tunnel, or pass --insecure-control to override.\n",
          control_listen.c_str());
      return 2;
    }
    std::fprintf(stderr,
        "samurai_master: WARNING: control server on %s is plaintext "
        "(--insecure-control); the cluster secret is exposed.\n",
        control_listen.c_str());
  }
  if (!server.Start()) {
    std::fprintf(stderr, "samurai_master: failed to bind control server\n");
    return 1;
  }
  std::printf("samurai_master: control server on %s\n", server.endpoint().c_str());

  // Coordinator & client commander declared before optional Management API so
  // live reconfigure callbacks never dangle during shutdown.
  ServicerMasterView view(&servicer);
  const int rpc_timeout_ms = static_cast<int>(OptInt(argc, argv, "--rpc-timeout-ms", 2000));
  ClientWorkerCommander commander(cluster_secret, tenant, rpc_timeout_ms, &servicer);
  MasterCoordinator coord(&view, &commander);
  auto guard = [&elector]() { return !elector || elector->IsLeader(); };

  // Management API (optional).
  std::unique_ptr<ManagementApiServer> mgmt;
  const std::string mgmt_listen = Opt(argc, argv, "--management-listen", "");
  if (!mgmt_listen.empty()) {
    ManagementConfig mcfg;
    mcfg.tenant_namespace = tenant;

    // TLS for the management HTTP API. Enabled by --mgmt-tls; uses the given
    // cert/key files or an ephemeral self-signed cert when none are provided.
    ManagementTlsConfig tls;
    tls.enabled = Flag(argc, argv, "--mgmt-tls");
    tls.cert_path = Opt(argc, argv, "--mgmt-tls-cert", "");
    tls.key_path = Opt(argc, argv, "--mgmt-tls-key", "");
    mcfg.agent_public_scheme = tls.enabled ? "https" : "http";
    // Self-signed TLS (no cert files): the agent can't verify the cert, so its
    // install-script curls must use -k (the manifest HMAC still authenticates).
    mcfg.agent_tls_skip_verify = tls.enabled && tls.cert_path.empty();

    // Self-bootstrapping agent join (zero-install slave). Opt-in via a join token;
    // agents pull the slave + worker binaries and register in reverse mode.
    mcfg.agent_join_token = Opt(argc, argv, "--agent-join-token", "");
    if (!mcfg.agent_join_token.empty()) {
      // On a non-loopback bind the join token + cluster secret leave the host, so
      // require a secured channel: TLS on the API, or an explicit plaintext opt-in.
      if (!IsLoopbackEndpoint(mgmt_listen) && !tls.enabled &&
          !Flag(argc, argv, "--agent-insecure-http")) {
        std::fprintf(stderr,
            "samurai_master: refusing to enable agent bootstrap on a non-loopback\n"
            "  mgmt address (%s) without TLS: the join token and cluster secret\n"
            "  would travel in cleartext. Enable --mgmt-tls, bind --management-listen\n"
            "  to loopback behind a TLS proxy / tunnel, or pass --agent-insecure-http.\n",
            mgmt_listen.c_str());
        return 2;
      }
      if (!IsLoopbackEndpoint(mgmt_listen) && !tls.enabled) {
        std::fprintf(stderr,
            "samurai_master: WARNING: agent bootstrap served plaintext on %s "
            "(--agent-insecure-http); join token + secret are exposed.\n",
            mgmt_listen.c_str());
      }
      mcfg.agent_artifact_dir = Opt(argc, argv, "--agent-artifact-dir", ".");
      mcfg.agent_advertise_endpoint = Opt(argc, argv, "--agent-advertise", control_listen);
      mcfg.agent_dispatch_mode = Opt(argc, argv, "--agent-dispatch-mode", "reverse");
      mcfg.agent_worker = Opt(argc, argv, "--agent-worker", "cpu");
      mcfg.agent_cluster_secret = cluster_secret;  // agent presents this for app-layer auth
      mcfg.agent_curve_public = curve_public;  // empty unless --curve-server-secret set
      std::printf("samurai_master: agent bootstrap enabled (worker=%s advertise=%s curve=%s tls=%s)\n",
                  mcfg.agent_worker.c_str(), mcfg.agent_advertise_endpoint.c_str(),
                  curve_public.empty() ? "off" : "on", tls.enabled ? "on" : "off");
    }
    ManagementProviders providers;
    const bool closed_loop_on = clcfg.enabled;
    providers.state_provider = [&servicer, &mm, &as_mu, &as_json, autoscale_on, &cl_mu, &cl_json,
                                closed_loop_on]() {
      Value asj;
      bool has_as = false;
      if (autoscale_on) {
        std::lock_guard<std::mutex> lk(as_mu);
        asj = as_json;
        has_as = asj.find("enabled") != nullptr;  // populated once the thread ran
      }
      Value clj;
      bool has_cl = false;
      if (closed_loop_on) {
        std::lock_guard<std::mutex> lk(cl_mu);
        clj = cl_json;
        has_cl = clj.find("enabled") != nullptr;  // populated once the first window ran
      }
      return BuildState(&servicer, mm.get(), has_as ? &asj : nullptr,
                        has_cl ? &clj : nullptr);
    };
    providers.abort_callback = []() {
      Value r = Value::Object();
      r.set("aborted", Value::Bool(true));
      return r;
    };
    providers.reconfigure_callback = [&coord, &commander, &servicer, &current_leader_epoch](
                                         const Value& body) {
      std::string shard_id;
      if (const Value* v = body.find("shard_id")) shard_id = v->as_string("");
      if (shard_id.empty()) {
        if (const Value* v = body.find("active_shard_id")) shard_id = v->as_string("");
      }
      std::string worker_id;
      if (const Value* v = body.find("worker_id")) worker_id = v->as_string("");

      std::string args_json;
      if (const Value* a = body.find("args_json")) {
        args_json = a->is_string() ? a->as_string("") : a->dump();
      } else if (const Value* p = body.find("params"); p && p->is_object()) {
        args_json = p->dump();
      } else {
        Value fwd = Value::Object();
        for (const auto& kv : body.members()) {
          if (kv.first == "shard_id" || kv.first == "active_shard_id" || kv.first == "worker_id") {
            continue;
          }
          fwd.set(kv.first, kv.second);
        }
        args_json = fwd.dump();
      }

      const std::int64_t ep = current_leader_epoch();
      int applied = coord.ReconfigureActiveShards(args_json, ep, shard_id, worker_id);
      if (applied == 0 && (!worker_id.empty() || !shard_id.empty())) {
        for (const auto& w : servicer.SnapshotWorkers()) {
          if (!worker_id.empty() && w.worker_id != worker_id) continue;
          const std::string sid = !shard_id.empty() ? shard_id : w.active_shard_id;
          if (sid.empty()) continue;
          auto cit = w.capabilities.find("control_endpoint");
          auto mit = w.capabilities.find("dispatch_mode");
          const std::string dep = (cit != w.capabilities.end()) ? cit->second : "";
          const std::string dmode = (mit != w.capabilities.end()) ? LowerCopy(mit->second) : "";
          bool ok = false;
          if (dmode == "reverse") {
            ok = commander.ReconfigureShardReverse(w.worker_id, sid, args_json, ep);
          } else {
            if (!dep.empty()) ok = commander.ReconfigureShard(dep, sid, args_json, ep);
            if (!ok && dmode == "auto") {
              ok = commander.ReconfigureShardReverse(w.worker_id, sid, args_json, ep);
            }
          }
          if (ok) ++applied;
        }
      }

      Value resp = Value::Object();
      resp.set("reconfigured", Value::Bool(applied > 0));
      resp.set("applied", Value::Int(applied));
      if (!shard_id.empty()) resp.set("shard_id", Value::Str(shard_id));
      if (!worker_id.empty()) resp.set("worker_id", Value::Str(worker_id));
      return resp;
    };

    auto provisioner = std::make_shared<samurai::control::NodeProvisioner>();
    provisioner->SetWorkerChecker([&servicer](const std::string& host) {
      for (const auto& w : servicer.SnapshotWorkers()) {
        if (w.worker_id.find(host) != std::string::npos) return true;
        auto it = w.capabilities.find("hostname");
        if (it != w.capabilities.end() && it->second.find(host) != std::string::npos) return true;
        auto ip_it = w.capabilities.find("ip");
        if (ip_it != w.capabilities.end() && ip_it->second.find(host) != std::string::npos) return true;
      }
      return false;
    });

    std::string mgmt_h = "127.0.0.1";
    std::string mgmt_p = "8089";
    const auto colon = mgmt_listen.rfind(':');
    if (colon != std::string::npos) {
      mgmt_h = mgmt_listen.substr(0, colon);
      mgmt_p = mgmt_listen.substr(colon + 1);
    }
    if (mgmt_h.empty() || mgmt_h == "0.0.0.0") mgmt_h = "127.0.0.1";
    const std::string default_install_url = (tls.enabled ? "https://" : "http://") +
        mgmt_h + ":" + mgmt_p + "/v1/agent/install?token=" + mcfg.agent_join_token;

    providers.provision_callback = [provisioner, default_install_url, tls_skip = mcfg.agent_tls_skip_verify](
        const samurai::core::json::Value& b) {
      return provisioner->ProvisionJson(b, default_install_url, tls_skip);
    };

    mgmt = std::make_unique<ManagementApiServer>(mgmt_listen, mcfg, providers, tls);
    if (mgmt->Start()) {
      std::printf("samurai_master: management api on %s (%s)\n", mgmt->endpoint().c_str(),
                  tls.enabled ? "https" : "http");

      const std::string prov_hosts = Opt(argc, argv, "--provision-hosts", "");
      const std::string prov_user = Opt(argc, argv, "--provision-ssh-user", "root");
      const std::string prov_key = Opt(argc, argv, "--provision-ssh-key", "");
      const std::string prov_worker =
          Opt(argc, argv, "--provision-worker", mcfg.agent_worker.empty() ? "cpu" : mcfg.agent_worker);
      const int prov_timeout_s = static_cast<int>(OptInt(argc, argv, "--provision-timeout-s", 10));

      if (!prov_hosts.empty()) {
        if (mcfg.agent_join_token.empty()) {
          std::fprintf(stderr,
                       "samurai_master: --provision-hosts requires --agent-join-token to be set\n");
        } else {
          std::printf("samurai_master: provisioning remote nodes via SSH trigger (%s)...\n",
                      prov_hosts.c_str());
          Value req = Value::Object();
          req.set("hosts", Value::Str(prov_hosts));
          req.set("ssh_user", Value::Str(prov_user));
          req.set("ssh_key_path", Value::Str(prov_key));
          req.set("worker_kind", Value::Str(prov_worker));
          req.set("timeout_s", Value::Int(prov_timeout_s));

          Value res =
              provisioner->ProvisionJson(req, default_install_url, mcfg.agent_tls_skip_verify);
          std::int64_t total = res.find("total") ? res.find("total")->as_int(0) : 0;
          std::int64_t triggered = res.find("triggered") ? res.find("triggered")->as_int(0) : 0;
          std::int64_t joined = res.find("joined") ? res.find("joined")->as_int(0) : 0;
          std::printf(
              "samurai_master: provisioning results: %ld total, %ld triggered, %ld joined cluster\n",
              static_cast<long>(total), static_cast<long>(triggered), static_cast<long>(joined));
        }
      }
    } else {
      std::fprintf(stderr, "samurai_master: failed to start management api%s\n",
                   tls.enabled ? " (TLS cert/key load or self-signed generation failed)" : "");
    }
  }

  // Wait for workers.
  const long expect = OptInt(argc, argv, "--expect-workers", 1);
  const double wait_deadline =
      std::chrono::duration_cast<std::chrono::duration<double>>(
          std::chrono::system_clock::now().time_since_epoch())
          .count() +
      static_cast<double>(OptInt(argc, argv, "--wait-workers-s", 30));
  while (!g_stop.load() && static_cast<long>(servicer.worker_count()) < expect) {
    const double now = std::chrono::duration_cast<std::chrono::duration<double>>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
    if (now >= wait_deadline) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (static_cast<long>(servicer.worker_count()) < expect) {
    std::fprintf(stderr, "samurai_master: only %zu/%ld workers registered; proceeding\n",
                 servicer.worker_count(), expect);
  }

  // The coordinator dispatches shards to workers advertising the requested flavor.
  // `view`, `commander`, `coord`, `guard` are initialized above Management API.

  // Feed the autoscale controller live shard backlog/in-flight counts from the
  // coordinator (no-op when autoscale is off).
  auto attach_progress = [&](JobConfig& job) {
    if (!autoscaler) return;
    job.progress_cb = [&as_pending, &as_inflight](int p, int i) {
      as_pending.store(p);
      as_inflight.store(i);
    };
  };

  int rc = 0;

  // Background region heartbeat + snapshot publisher (leader only). Runs
  // alongside the primary job and the serve loop; the store is thread-safe.
  std::thread hb_thread;
  if (mm && mm->active() && !master_region.empty()) {
    const int hb_interval_ms = std::max(
        1000,
        static_cast<int>(OptInt(argc, argv, "--multi-master-heartbeat-ttl-s", 15) * 1000 / 3));
    hb_thread = std::thread([&]() {
      while (!g_stop.load()) {
        if (!elector || elector->IsLeader()) {
          Value hb = Value::Object();
          hb.set("workers", Value::Int(static_cast<std::int64_t>(servicer.worker_count())));
          mm->Heartbeat(hb);
          mm->PublishSnapshot(BuildState(&servicer, nullptr));
        }
        for (int slept = 0; slept < hb_interval_ms && !g_stop.load(); slept += 100) {
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
      }
    });
  }

  // Background autoscale evaluator (leader only). Reads the live load signals the
  // coordinator publishes via progress_cb, evaluates one scaling step (the
  // controller enforces its own cooldown), publishes the decision for the
  // management API, and logs actual changes. In-memory backend: no K8s patch.
  std::thread as_thread;
  if (autoscaler) {
    const int tick_ms = std::max(1000, static_cast<int>(ascfg.cooldown_s * 1000.0 / 3.0));
    as_thread = std::thread([&]() {
      while (!g_stop.load()) {
        if (!elector || elector->IsLeader()) {
          const int p = as_pending.load();
          const int i = as_inflight.load();
          const AutoscaleDecision d =
              autoscaler->MaybeScale(p, i, static_cast<int>(servicer.worker_count()));
          const std::string backend = autoscaler->backend_mode();
          {
            std::lock_guard<std::mutex> lk(as_mu);
            as_json = AutoscaleStateJson(d, ascfg.target_name, ascfg.target_kind, backend);
          }
          if (d.changed) {
            std::printf(
                "samurai_master: autoscale scaled current=%d desired=%d applied=%d "
                "(pending=%d inflight=%d workers=%zu) [backend=%s]\n",
                d.current, d.desired, d.applied, p, i, servicer.worker_count(), backend.c_str());
          } else if (!d.reason.empty() && d.reason != "cooldown" && d.reason != "disabled") {
            std::fprintf(stderr, "samurai_master: autoscale no change (%s)\n", d.reason.c_str());
          }
        }
        for (int slept = 0; slept < tick_ms && !g_stop.load(); slept += 100) {
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
      }
    });
  }

  // Primary job: run it on this region's workers, or delegate the whole job to a
  // peer region when --target-region names a different region.
  if (has_local_job) {
    const Value spec = JobSpecFromArgs(argc, argv, &cli_region_topo, &cli_telco_pool);
    const std::string tr = cli_region_topo.ResolveRegion(
        cli_target_asn, Opt(argc, argv, "--target-region", ""));
    if (mm && mm->active() && !tr.empty() && tr != master_region) {
      if (mm->EnqueueJob(tr, spec)) {
        std::printf("samurai_master: delegated job (count=%ld) to region %s\n", effective_count, tr.c_str());
      } else {
        std::fprintf(stderr, "samurai_master: delegation to region %s failed\n", tr.c_str());
        rc = 1;
      }
    } else {
      const std::int64_t ep_now = current_leader_epoch();
      servicer.set_leader_epoch_min(ep_now);
      if (clcfg.enabled) {
        // Autopilot: repeatedly run a measured window at the controller's current
        // setpoint (target_rps), fold the snapshot into a LoadSample, and let the
        // controller pick the next setpoint until it converges / exhausts budget.
        const int window_s = std::max(1, static_cast<int>(OptInt(argc, argv, "--cl-window-s", 5)));
        samurai::control::ClosedLoopController ctl(clcfg);
        const samurai::control::SutProbe sut(BuildSutProbeConfig(argc, argv));
        if (sut.enabled()) {
          std::printf("samurai_master: SUT-correlation on (prometheus=%s latency_query=%s)\n",
                      sut.config().prometheus_url.c_str(),
                      sut.config().latency_p99_query.empty() ? "<none>" : "set");
        }
        const char* strat_name = StrategyName(clcfg.strategy);
        std::printf(
            "samurai_master: closed-loop enabled (strategy=%s window=%ds min=%.0f max=%.0f "
            "initial=%.0f slo_max_error_pct=%.2f)\n",
            strat_name, window_s, clcfg.min_rps, clcfg.max_rps, ctl.initial_setpoint(),
            clcfg.slo_max_error_pct);
        // RL policy serving (kRl): load the SRLP weight file once. The policy only
        // proposes; ClosedLoopController::StepRl shields the proposal. If it fails
        // to load, kRl degrades to the AIMD fallback baked into the shield.
        samurai::control::RlPolicy rl_policy;
        if (clcfg.strategy == samurai::control::ClosedLoopStrategy::kRl) {
          std::string rl_path = Opt(argc, argv, "--rl-policy", "");
          if (rl_path.empty()) {
            if (const char* env = std::getenv("SAMURAI_RL_POLICY")) rl_path = env;
          }
          std::string rl_err;
          if (rl_path.empty()) {
            std::fprintf(stderr,
                         "samurai_master: --cl-strategy rl but no --rl-policy / "
                         "SAMURAI_RL_POLICY; falling back to AIMD shield behavior\n");
          } else if (!rl_policy.Load(rl_path, &rl_err)) {
            std::fprintf(stderr, "samurai_master: RL policy load failed (%s): %s — AIMD fallback\n",
                         rl_path.c_str(), rl_err.c_str());
          } else {
            std::printf("samurai_master: RL policy loaded (path=%s in_dim=%d jump<=%.2fx)\n",
                        rl_path.c_str(), rl_policy.input_dim(), clcfg.rl_max_jump_factor);
            if (rl_policy.recurrent()) {
              std::printf("samurai_master: RL² recurrent policy — the GRU context "
                          "(hidden=%d) adapts within the episode; resetting context\n",
                          rl_policy.hidden_dim());
              rl_policy.ResetContext();
            }
          }
        }
        // RL corpus capture: opt-in per-window (s,a,s') transition log for the
        // offline-RL training pipeline. Append-only NDJSON (crash-safe); reward is
        // computed downstream in Python. Disabled => zero overhead.
        const std::string rl_corpus_path = Opt(argc, argv, "--rl-corpus", "");
        std::ofstream rl_corpus;
        if (!rl_corpus_path.empty()) {
          rl_corpus.open(rl_corpus_path, std::ios::app);
          if (!rl_corpus.is_open()) {
            std::fprintf(stderr, "samurai_master: --rl-corpus: cannot open %s for append\n",
                         rl_corpus_path.c_str());
          } else {
            std::printf("samurai_master: RL corpus capture on (path=%s)\n",
                        rl_corpus_path.c_str());
          }
        }
        // RL exploration: when capturing a corpus without a policy driving the
        // extra levers, perturb concurrency/request_mix/source_rotation/pacing
        // per window so those columns vary and become learnable offline. A loaded
        // policy takes precedence (it drives the levers itself).
        const samurai::control::RlExploreConfig rl_explore = BuildExploreConfig(argc, argv);
        if (rl_explore.enabled) {
          std::printf("samurai_master: RL exploration on (seed=%llu) — perturbing shaping "
                      "levers for corpus coverage\n",
                      static_cast<unsigned long long>(rl_explore.seed));
        }
        const std::string rl_run_id =
            "cl-" + std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count());
        samurai::control::LoadSample rl_prev_sample;  // state that produced this window's action
        Value rl_prev_defense = Value::Object();       // its defense-reaction signals
        // kRl Mahoraga levers (dims >=1: concurrency/request_mix/...) proposed last
        // window, applied to THIS window's job spec. Empty => policy drives only rps.
        std::vector<double> rl_next_levers;
        // Online lever shield (request_mix): active only when serving a policy — pure
        // capture must let exploration record blocked variants. --cl-lever-shield 0
        // disables it for A/B; --cl-lever-variants sets the categorical cardinality.
        const int variant_count = static_cast<int>(OptInt(argc, argv, "--cl-lever-variants", 5));
        const bool lever_shield_on =
            rl_policy.loaded() && OptInt(argc, argv, "--cl-lever-shield", 1) != 0;
        samurai::control::LeverShield lever_shield(
            samurai::control::LeverShield::Config{0.10, variant_count});
        constexpr int kRequestMixDim = 2;  // index of "request_mix" in kActionFields
        if (lever_shield_on) {
          std::printf("samurai_master: lever shield on — vetoing path-blocked "
                      "request_mix variants online\n");
        }
        // Path-aware state: when the loaded policy's input width includes the block
        // features (base 20 + 2 per variant), feed it the per-variant block memory as
        // state so it can *learn* to avoid a path-blocked variant (the shield is then
        // just the safety net). Keep the memory whenever serving, independent of the
        // veto toggle, so an A/B run with the veto off still populates the feature.
        constexpr int kBaseFeatures = 20;
        // Decode which extra state features the loaded policy was trained on from its
        // input width: block adds 2*V dims, ban adds 2, and they compose. (V defaults
        // to 5 so 2*V != 2; a custom --cl-lever-variants 1 would be ambiguous.)
        constexpr int kBanFeatures = 2;
        // Decode from the STATE width, not input_dim: an RL² recurrent policy's
        // input_dim includes the GRU hidden vector, but its state is the base 20
        // (block/ban memory is subsumed by the GRU), so state_dim()-20 == 0 there.
        const int rl_extra = rl_policy.loaded() ? rl_policy.state_dim() - kBaseFeatures : 0;
        // Flow-level IPS/NSM group adds 5 dims (4 rates + 1 shared known bit); with
        // V=5 its size collides with no block/ban combo, so peel it off first, then
        // decode block/ban from the remainder exactly as before.
        constexpr int kFlowFeatures = 5;
        const bool flow_state_on =
            rl_policy.loaded() &&
            (rl_extra == kFlowFeatures || rl_extra == kFlowFeatures + kBanFeatures ||
             rl_extra == kFlowFeatures + 2 * variant_count ||
             rl_extra == kFlowFeatures + 2 * variant_count + kBanFeatures);
        const int rl_extra_wo_flow = rl_extra - (flow_state_on ? kFlowFeatures : 0);
        const bool block_state_on =
            rl_policy.loaded() &&
            (rl_extra_wo_flow == 2 * variant_count ||
             rl_extra_wo_flow == 2 * variant_count + kBanFeatures);
        const bool ban_state_on =
            rl_policy.loaded() &&
            (rl_extra_wo_flow == kBanFeatures ||
             rl_extra_wo_flow == 2 * variant_count + kBanFeatures);
        // The run's transport determines whether the flow counters are real. Must
        // match the flow-capable set in RLConfig.flow_capable_transports (Python).
        const std::string rl_transport = Opt(argc, argv, "--transport", "kernel_socket");
        const bool rl_transport_flow_capable =
            rl_transport == "custom_tcp" || rl_transport == "dpdk" ||
            rl_transport == "af_xdp" || rl_transport == "af_packet";
        if (flow_state_on) {
          std::printf("samurai_master: flow-level IPS state on (in_dim=%d, transport=%s%s) — "
                      "policy conditions on the connection-layer flow rates\n",
                      rl_policy.input_dim(), rl_transport.c_str(),
                      rl_transport_flow_capable ? "" : ", MASKED: kernel-socket exposes no flow signal");
        }
        const bool track_variants = rl_policy.loaded();  // Observe/snapshot while serving
        // Cross-episode persistence: warm-start the memory from what a prior run
        // learned about THIS target, and write it back so the next run starts armed.
        const std::string variant_mem_path = Opt(argc, argv, "--cl-variant-memory", "");
        const std::string target_key = Opt(argc, argv, "--target", "127.0.0.1") + ":" +
                                        std::to_string(OptInt(argc, argv, "--port", 80));
        samurai::control::VariantMemory variant_mem;
        if (track_variants && !variant_mem_path.empty()) {
          variant_mem = samurai::control::VariantMemory::Load(variant_mem_path);
          const std::vector<double> warm = variant_mem.Get(target_key);
          if (!warm.empty()) {
            lever_shield.Warm(warm);
            std::printf("samurai_master: variant memory warm-started for %s (%zu variants)\n",
                        target_key.c_str(), warm.size());
          }
        }
        if (block_state_on) {
          std::printf("samurai_master: path-aware block state on (in_dim=%d) — policy "
                      "conditions on the per-variant block memory\n",
                      rl_policy.input_dim());
        }
        // Persistent-ban state: a causal EWMA of conn_drop folded across windows, so a
        // ban-aware policy conditions on a fail2ban/IPS ban that persists. Warm-started
        // (and persisted) per target like the variant memory, so a fresh run against an
        // already-banned target does not restart from "no ban known".
        const std::string ban_mem_path = Opt(argc, argv, "--cl-ban-memory", "");
        samurai::control::BanMemory ban_mem;
        double ban_ewma = -1.0;  // -1 = no conn_drop folded yet
        if (ban_state_on && !ban_mem_path.empty()) {
          ban_mem = samurai::control::BanMemory::Load(ban_mem_path);
          const double warm = ban_mem.Get(target_key);
          if (warm >= 0.0) {
            ban_ewma = warm;
            std::printf("samurai_master: ban memory warm-started for %s (pressure=%.3f)\n",
                        target_key.c_str(), warm);
          }
        }
        if (ban_state_on) {
          std::printf("samurai_master: persistent-ban state on (in_dim=%d) — policy "
                      "conditions on the folded conn_drop ban pressure\n",
                      rl_policy.input_dim());
        }
        // Serving-time continual fine-tuning (the slow Mahoraga wheel): a bounded,
        // state-conditioned online correction on the policy's setpoint, learned by
        // an ES gradient from the served-throughput reward and guarded by a champion-
        // challenger rollback that reverts to the frozen policy on any regression. It
        // only scales the proposal (StepRl still bounds it), so it cannot overdrive.
        constexpr int kAdaptFeatures = 4;  // [bias, rps_norm, rate_limited, overload]
        const bool adapt_on =
            rl_policy.loaded() && OptInt(argc, argv, "--cl-online-adapt", 0) != 0;
        samurai::control::OnlineAdapter::Config acfg;
        acfg.enabled = adapt_on;
        acfg.lr = OptDouble(argc, argv, "--cl-online-adapt-lr", 0.10);
        acfg.max_dev = OptDouble(argc, argv, "--cl-online-adapt-max-dev", 0.30);
        samurai::control::OnlineAdapter online_adapter(
            acfg, kAdaptFeatures,
            static_cast<std::uint64_t>(OptInt(argc, argv, "--cl-online-adapt-seed", 0)));
        const std::string adapt_mem_path = Opt(argc, argv, "--cl-online-adapt-memory", "");
        samurai::control::AdapterMemory adapt_mem;
        if (adapt_on && !adapt_mem_path.empty()) {
          adapt_mem = samurai::control::AdapterMemory::Load(adapt_mem_path);
          const auto e = adapt_mem.Get(target_key);
          if (!e.w.empty() || e.has_baseline) {
            online_adapter.Warm(e.w, e.has_baseline ? e.baseline
                                                    : std::numeric_limits<double>::quiet_NaN());
            std::printf("samurai_master: online adapter warm-started for %s (%zu weights)\n",
                        target_key.c_str(), e.w.size());
          }
        }
        bool adapt_pending = false;
        if (adapt_on) {
          std::printf("samurai_master: online adapter on — bounded setpoint correction "
                      "(lr=%.3f max_dev=%.2f) with rollback guard\n",
                      acfg.lr, acfg.max_dev);
        }
        // Open-vocabulary novelty detection: notice a defense the frozen feature space
        // cannot represent (success failing with no known signal to explain it), name
        // it, and damp the kRl setpoint while the un-modelled regime holds. Passive
        // for every strategy; the cautious backoff is kRl-only. Vocabulary persists.
        samurai::control::NoveltyDetector::Config nvcfg;
        nvcfg.enabled = OptInt(argc, argv, "--cl-novelty", 0) != 0;
        nvcfg.residual_threshold = OptDouble(argc, argv, "--cl-novelty-threshold", 0.35);
        nvcfg.backoff = OptDouble(argc, argv, "--cl-novelty-backoff", 0.85);
        nvcfg.min_damping = OptDouble(argc, argv, "--cl-novelty-min-damping", 0.50);
        nvcfg.promotion_count = OptInt(argc, argv, "--cl-novelty-promote", 3);
        samurai::control::NoveltyDetector novelty(nvcfg);
        const std::string novelty_mem_path = Opt(argc, argv, "--cl-novelty-memory", "");
        samurai::control::NoveltyMemory novelty_mem;
        if (nvcfg.enabled && !novelty_mem_path.empty()) {
          novelty_mem = samurai::control::NoveltyMemory::Load(novelty_mem_path);
          const auto vocab = novelty_mem.Get(target_key);
          if (!vocab.empty()) {
            novelty.Warm(vocab);
            std::printf("samurai_master: novelty vocabulary warm-started for %s (%zu known)\n",
                        target_key.c_str(), vocab.size());
          }
        }
        if (nvcfg.enabled) {
          std::printf("samurai_master: open-vocabulary novelty detection on "
                      "(threshold=%.2f backoff=%.2f)\n",
                      nvcfg.residual_threshold, nvcfg.backoff);
        }
        bool rl_have_prev = false;
        int win = 0;
        bool cl_aborted = false;
        // Warmup/transient dispatch race: the slave registers before its shard
        // workers are spawned+ready, and the aggregated result of a window can
        // occasionally miss a shard's late reply. Both surface as a zero-traffic
        // window that is NOT a real "no workers" failure. Tolerate a bounded number
        // of such windows by re-running the SAME setpoint (no ramp, no corpus row)
        // before giving up — a genuinely dead worker still exhausts the budget and
        // aborts with the same error.
        int no_traffic_retries = 0;
        const int kNoTrafficRetryBudget = OptInt(argc, argv, "--cl-no-traffic-retries", 8);
        samurai::control::ClosedLoopDecision dec;

        auto prepare_job_levers = [&](Value& base_args, int win_idx, int& applied_variant) {
          for (std::size_t k = 1;
               k < rl_next_levers.size() &&
               k < sizeof(samurai::control::kActionFields) /
                       sizeof(samurai::control::kActionFields[0]);
               ++k) {
            base_args.set(samurai::control::kActionFields[k],
                          Value::Int(static_cast<std::int64_t>(
                              std::llround(rl_next_levers[k]))));
          }
          if (rl_explore.enabled && rl_next_levers.empty()) {
            const std::vector<double> ex = samurai::control::ExploreLevers(win_idx, rl_explore);
            for (std::size_t k = 1; k < ex.size(); ++k) {
              if (ex[k] < 0.0) continue;
              base_args.set(samurai::control::kActionFields[k],
                            Value::Int(static_cast<std::int64_t>(std::llround(ex[k]))));
            }
          }
          applied_variant = -1;
          if (const Value* rm =
                  base_args.find(samurai::control::kActionFields[kRequestMixDim])) {
            applied_variant = static_cast<int>(rm->as_int(-1));
          }
          if (lever_shield_on && applied_variant >= 0) {
            const int governed = lever_shield.Govern(applied_variant);
            if (governed != applied_variant) {
              base_args.set(samurai::control::kActionFields[kRequestMixDim],
                            Value::Int(static_cast<std::int64_t>(governed)));
              applied_variant = governed;
            }
          }
        };

        enum class WindowStatus { kContinue, kRetryNoTraffic, kDone, kAbortNoTraffic };
        auto evaluate_window = [&](double setpoint, const Value& applied_base_args,
                                   int applied_variant, const Value& snap, int job_rc) -> WindowStatus {
          samurai::control::LoadSample sample = DeriveSample(snap);
          if (sample.actual_rps <= 0.0 && window_s > 0) {
            sample.actual_rps = sample.attempted / static_cast<double>(window_s);
          }
          samurai::control::SutSample sut_sample;
          if (sut.enabled()) {
            sut_sample = sut.Scrape();
            if (sut_sample.latency_p99_ms >= 0.0) {
              sample.latency_p99_ms = sut_sample.latency_p99_ms;
            }
          }
          if (sample.attempted <= 0.0) {
            if (no_traffic_retries < kNoTrafficRetryBudget) {
              ++no_traffic_retries;
              std::fprintf(stderr,
                           "samurai_master: closed-loop window=%d produced no traffic "
                           "(rc=%d); retrying same setpoint (%d/%d) — workers may still "
                           "be warming up.\n",
                           win, job_rc, no_traffic_retries, kNoTrafficRetryBudget);
              return WindowStatus::kRetryNoTraffic;
            }
            std::fprintf(stderr,
                         "samurai_master: closed-loop window=%d produced no traffic "
                         "(rc=%d); aborting search after %d retries — check "
                         "workers/dispatch.\n",
                         win, job_rc, no_traffic_retries);
            rc = 1;
            Value clj = Value::Object();
            clj.set("enabled", Value::Bool(true));
            clj.set("done", Value::Bool(true));
            clj.set("phase", Value::Str("aborted"));
            clj.set("reason", Value::Str("no traffic in window"));
            clj.set("window", Value::Int(win));
            {
              std::lock_guard<std::mutex> lk(cl_mu);
              cl_json = clj;
            }
            cl_aborted = true;
            return WindowStatus::kAbortNoTraffic;
          }

          const Value rl_defense = RlDefenseJson(snap);
          if (nvcfg.enabled) {
            samurai::control::NoveltySignals ns;
            auto ratio = [&](const char* num, const char* den) -> double {
              const Value* n = rl_defense.find(num);
              const Value* d = rl_defense.find(den);
              if (!n || !d || d->as_double(0.0) <= 0.0) return -1.0;
              return n->as_double(0.0) / d->as_double(0.0);
            };
            ns.success_ratio = ratio("status_2xx", "responses_total");
            ns.rate_limited = ratio("status_4xx", "responses_total");
            ns.overload = ratio("status_5xx", "responses_total");
            ns.challenge = ratio("l7_expectation_failures", "responses_total");
            if (const Value* v = rl_defense.find("h2_stream_reset_ratio")) ns.reset = v->as_double(-1.0);
            const Value* att = rl_defense.find("l7_conn_attempted");
            const Value* est = rl_defense.find("l7_conn_established");
            if (att && est && att->as_double(0.0) > 0.0) {
              ns.conn_drop = std::max(0.0, 1.0 - est->as_double(0.0) / att->as_double(0.0));
            }
            novelty.Observe(ns);
          }
          if (track_variants && applied_variant >= 0) {
            double resp = 0.0, s2xx = 0.0;
            if (const Value* v = rl_defense.find("responses_total")) resp = v->as_double(0.0);
            if (const Value* v = rl_defense.find("status_2xx")) s2xx = v->as_double(0.0);
            if (resp > 0.0) lever_shield.Observe(applied_variant, s2xx / resp);
          }
          if (rl_policy.loaded()) {
            samurai::control::RlStateInputs rin =
                RlInputsFrom(sample, rl_defense, win, clcfg);
            if (block_state_on) rin.variant_block_success = lever_shield.snapshot();
            if (ban_state_on) {
              const double cd = rin.conn_drop_ratio;
              if (cd >= 0.0) {
                ban_ewma = (ban_ewma < 0.0)
                               ? cd
                               : samurai::control::kBanEwmaAlpha * cd +
                                     (1.0 - samurai::control::kBanEwmaAlpha) * ban_ewma;
              }
              rin.ban_features = true;
              rin.ban_pressure = ban_ewma;
            }
            if (flow_state_on) {
              rin.flow_features = true;
              rin.flow_capable = rl_transport_flow_capable;
            }
            if (adapt_on && adapt_pending) {
              constexpr double kLambdaDefense = 1.0;
              constexpr double kLambdaFlow = 1.0;
              constexpr double kLambdaSlo = 2.0;
              constexpr double kStepCost = 0.02;
              const double max_rps = clcfg.max_rps > 0.0 ? clcfg.max_rps : 1.0;
              double resp = 0.0, s2xx = 0.0;
              if (const Value* v = rl_defense.find("responses_total")) resp = v->as_double(0.0);
              if (const Value* v = rl_defense.find("status_2xx")) s2xx = v->as_double(0.0);
              auto pos = [](double x) { return x > 0.0 ? x : 0.0; };
              double err = sample.error_pct;
              if (err < 0.0 && sample.attempted > 0.0) err = 100.0 * sample.errors / sample.attempted;
              double overshoot = 0.0;
              if (clcfg.slo_max_error_pct > 0.0 && err >= 0.0) {
                overshoot = std::max(0.0, (err - clcfg.slo_max_error_pct) / clcfg.slo_max_error_pct);
              }
              double served;
              if (resp > 0.0 && window_s > 0) {
                served = (s2xx / window_s) / max_rps;
              } else {
                const double prev_rps = rl_have_prev ? rl_prev_sample.actual_rps : sample.actual_rps;
                served = (overshoot <= 0.0)
                             ? std::max(0.0, (sample.actual_rps - prev_rps) / max_rps)
                             : 0.0;
              }
              const double reward =
                  served -
                  kLambdaDefense * (pos(rin.rate_limited_ratio) + pos(rin.overload_ratio)) -
                  kLambdaFlow * (pos(rin.conn_drop_ratio) + pos(rin.reset_pressure)) -
                  kLambdaSlo * overshoot - kStepCost;
              online_adapter.Observe(reward);
            }
            const std::vector<double> action = rl_policy.ProposeFor(rin);
            if (!action.empty()) {
              double rps = action[0];
              if (adapt_on) {
                const double max_rps = clcfg.max_rps > 0.0 ? clcfg.max_rps : 1.0;
                auto pos = [](double x) { return x > 0.0 ? x : 0.0; };
                const std::vector<double> phi = {1.0, sample.actual_rps / max_rps,
                                                 pos(rin.rate_limited_ratio),
                                                 pos(rin.overload_ratio)};
                rps = online_adapter.Apply(rps, phi);
                adapt_pending = true;
              }
              if (nvcfg.enabled) rps = novelty.DampSetpoint(rps);
              sample.rl_action_rps = rps;
              rl_next_levers = action;
            }
          }
          dec = ctl.Step(sample);
          {
            std::lock_guard<std::mutex> lk(cl_mu);
            cl_json = ClosedLoopStateJson(dec, clcfg);
            if (sut.enabled()) cl_json.set("sut", samurai::control::SutProbe::SampleJson(sut_sample));
            if (nvcfg.enabled) cl_json.set("novelty", novelty.ToJson());
          }
          if (nvcfg.enabled && novelty.novel()) {
            std::printf("samurai_master: NOVEL defense at window=%d — unexplained "
                        "success-loss=%.2f (score=%.2f) signature=%s; damping setpoint\n",
                        win, novelty.last_unexplained(), novelty.score(),
                        novelty.last_signature().c_str());
          }
          if (rl_corpus.is_open()) {
            const Value action = RlActionJson(setpoint, applied_base_args);
            std::string cap_transport = "kernel_socket";
            if (const Value* ct = applied_base_args.find("connection_template"))
              if (const Value* tb = ct->find("transport_backend"))
                cap_transport = tb->as_string("kernel_socket");
            const Value tr =
                RlTransitionJson(rl_run_id, win, setpoint, action, rl_prev_sample,
                                 rl_prev_defense, sample, rl_defense, dec, clcfg, window_s,
                                 !rl_have_prev, cap_transport);
            rl_corpus << tr.dump() << '\n';
            rl_corpus.flush();
          }
          rl_prev_sample = sample;
          rl_prev_defense = rl_defense;
          rl_have_prev = true;
          std::printf(
              "samurai_master: closed-loop window=%d ran_rps=%.0f healthy=%d error_pct=%.3f "
              "p99_ms=%.1f next_setpoint=%.0f best_good=%.0f phase=%s\n",
              dec.window, setpoint, dec.last_healthy ? 1 : 0, dec.error_pct,
              sut_sample.latency_p99_ms, dec.setpoint_rps, dec.best_good_rps, dec.phase.c_str());
          return dec.done ? WindowStatus::kDone : WindowStatus::kContinue;
        };

        const bool cl_live_reconfigure = Flag(argc, argv, "--cl-live-reconfigure");
        if (cl_live_reconfigure) {
          double cur_setpoint = ctl.current_setpoint();
          const int max_wins =
              clcfg.strategy == samurai::control::ClosedLoopStrategy::kBinSearch
                  ? std::max(1, clcfg.binsearch_max_windows)
                  : (clcfg.aimd_max_windows > 0 ? clcfg.aimd_max_windows : 64);
          const double est_packets =
              std::max(clcfg.max_rps, cur_setpoint) * static_cast<double>(window_s) *
              static_cast<double>(max_wins + kNoTrafficRetryBudget + 2);
          const std::int64_t live_budget = static_cast<std::int64_t>(std::min<double>(
              est_packets, static_cast<double>(std::numeric_limits<std::int64_t>::max() / 2)));
          Value wspec = spec;
          wspec.set("count", Value::Int(std::max<std::int64_t>(1, live_budget)));
          wspec.set("target_rps", Value::Double(cur_setpoint));
          if (LowerCopy(worker_kind) == "telco" || telco_subs > 0) {
            wspec.set("telco_duration_ms", Value::Int(window_s * (max_wins + 4) * 1000LL));
            wspec.set("telco_cps", Value::Int(std::max<std::int64_t>(1, std::llround(cur_setpoint))));
          }
          JobConfig job = BuildJobConfig(wspec, ep_now, tenant, master_region);
          if (job.job_timeout_s < window_s * (max_wins + 4)) {
            job.job_timeout_s = static_cast<std::int64_t>(window_s) * (max_wins + 4);
          }
          job.base_args.set("target_rps", Value::Double(cur_setpoint));
          job.base_args.set("pacing_mode", Value::Int(1));
          int active_variant = -1;
          prepare_job_levers(job.base_args, 0, active_variant);
          Value active_base_args = job.base_args;
          attach_progress(job);

          std::map<std::string, std::int64_t> prev_sent_by_shard;
          std::map<std::string, std::int64_t> prev_err_by_shard;
          std::map<std::string, std::map<std::string, double>> prev_totals_by_shard;

          job.window_tick_interval_ms = static_cast<std::int64_t>(window_s) * 1000;
          job.window_tick_cb = [&](int /*tick_idx*/,
                                   const std::vector<samurai::control::ProbeOutcome>& live_probes,
                                   bool& should_stop) -> std::string {
            std::int64_t delta_sent = 0;
            std::int64_t delta_err = 0;
            double total_actual_rps = 0.0;
            std::map<std::string, double> delta_totals;
            std::size_t probe_idx = 0;
            for (const auto& p : live_probes) {
              ++probe_idx;
              if (p.stats_json.empty()) continue;
              const auto parsed = samurai::core::json::Parse(p.stats_json);
              if (!parsed.ok || !parsed.value.is_object()) continue;
              const std::string sid = p.active_shard_id.empty()
                                          ? ("probe-" + std::to_string(probe_idx))
                                          : p.active_shard_id;
              const Value& st = parsed.value;
              const std::int64_t s_now = st.find("sent") ? st.find("sent")->as_int(0) : 0;
              const std::int64_t e_now = st.find("errors") ? st.find("errors")->as_int(0) : 0;
              delta_sent += std::max<std::int64_t>(0, s_now - prev_sent_by_shard[sid]);
              delta_err += std::max<std::int64_t>(0, e_now - prev_err_by_shard[sid]);
              prev_sent_by_shard[sid] = s_now;
              prev_err_by_shard[sid] = e_now;

              const Value* nt = st.find("numeric_totals");
              const Value& src = (nt && nt->is_object()) ? *nt : st;
              for (const auto& kv : src.members()) {
                if (!kv.second.is_number()) continue;
                const double val = kv.second.as_double(0.0);
                if (kv.first == "actual_rps") {
                  total_actual_rps += val;
                  continue;
                }
                const double dval = std::max(0.0, val - prev_totals_by_shard[sid][kv.first]);
                prev_totals_by_shard[sid][kv.first] = val;
                delta_totals[kv.first] += dval;
              }
            }

            Value win_snap = Value::Object();
            win_snap.set("sent", Value::Int(delta_sent));
            win_snap.set("errors", Value::Int(delta_err));
            Value nt_obj = Value::Object();
            for (const auto& kv : delta_totals) {
              nt_obj.set(kv.first, Value::Double(kv.second));
            }
            if (total_actual_rps > 0.0) {
              nt_obj.set("actual_rps", Value::Double(total_actual_rps));
            }
            win_snap.set("numeric_totals", std::move(nt_obj));

            ++win;
            const WindowStatus ws =
                evaluate_window(cur_setpoint, active_base_args, active_variant, win_snap, 0);
            if (ws == WindowStatus::kRetryNoTraffic) {
              if (g_stop.load() || !guard()) should_stop = true;
              return "";
            }
            if (ws == WindowStatus::kAbortNoTraffic || ws == WindowStatus::kDone ||
                g_stop.load() || !guard()) {
              should_stop = true;
              return "";
            }

            cur_setpoint = dec.setpoint_rps;
            active_base_args.set("target_rps", Value::Double(cur_setpoint));
            active_base_args.set("pacing_mode", Value::Int(1));
            prepare_job_levers(active_base_args, win, active_variant);

            Value reconf = Value::Object();
            reconf.set("target_rps", Value::Double(cur_setpoint));
            reconf.set("rps", Value::Double(cur_setpoint));
            reconf.set("pacing_mode", Value::Int(1));
            if (LowerCopy(worker_kind) == "telco" || telco_subs > 0) {
              reconf.set("telco_cps", Value::Int(std::max<std::int64_t>(1, std::llround(cur_setpoint))));
            }
            for (std::size_t k = 1;
                 k < sizeof(samurai::control::kActionFields) /
                         sizeof(samurai::control::kActionFields[0]);
                 ++k) {
              if (const Value* fv = active_base_args.find(samurai::control::kActionFields[k])) {
                reconf.set(samurai::control::kActionFields[k], *fv);
              }
            }
            return reconf.dump();
          };

          const JobResult res = coord.RunSingleJob(job, "cl-live-1", guard);
          if (win == 0 && !cl_aborted) {
            ++win;
            (void)evaluate_window(cur_setpoint, active_base_args, active_variant, res.snapshot, res.rc);
          }
        } else {
          while (!g_stop.load() && guard()) {
            const double setpoint = ctl.current_setpoint();
            const std::int64_t win_count =
                std::max<std::int64_t>(1, static_cast<std::int64_t>(setpoint * window_s));
            Value wspec = spec;
            wspec.set("count", Value::Int(win_count));
            wspec.set("target_rps", Value::Double(setpoint));
            if (LowerCopy(worker_kind) == "telco" || telco_subs > 0) {
              wspec.set("telco_duration_ms", Value::Int(window_s * 1000));
              wspec.set("telco_cps", Value::Int(std::max<std::int64_t>(1, std::llround(setpoint))));
            }
            JobConfig job = BuildJobConfig(wspec, ep_now, tenant, master_region);
            job.base_args.set("target_rps", Value::Double(setpoint));
            job.base_args.set("pacing_mode", Value::Int(1));
            int applied_variant = -1;
            prepare_job_levers(job.base_args, win, applied_variant);
            attach_progress(job);
            const JobResult res =
                coord.RunSingleJob(job, "cl-" + std::to_string(++win), guard);
            const WindowStatus ws =
                evaluate_window(setpoint, job.base_args, applied_variant, res.snapshot, res.rc);
            if (ws == WindowStatus::kRetryNoTraffic) {
              std::this_thread::sleep_for(std::chrono::milliseconds(500));
              continue;
            }
            if (ws == WindowStatus::kAbortNoTraffic || ws == WindowStatus::kDone) {
              break;
            }
          }
        }
        // Persist what this run learned about the target so the next run warm-starts
        // instead of rediscovering the same path-blocks (cross-episode memory).
        if (track_variants && !variant_mem_path.empty()) {
          variant_mem.Put(target_key, lever_shield.snapshot());
          if (!variant_mem.Save(variant_mem_path)) {
            std::fprintf(stderr, "samurai_master: could not persist variant memory to %s\n",
                         variant_mem_path.c_str());
          } else {
            std::printf("samurai_master: variant memory saved for %s -> %s\n",
                        target_key.c_str(), variant_mem_path.c_str());
          }
        }
        // Persist the folded ban pressure so the next run warm-starts armed.
        if (ban_state_on && !ban_mem_path.empty() && ban_ewma >= 0.0) {
          ban_mem.Put(target_key, ban_ewma);
          if (!ban_mem.Save(ban_mem_path)) {
            std::fprintf(stderr, "samurai_master: could not persist ban memory to %s\n",
                         ban_mem_path.c_str());
          } else {
            std::printf("samurai_master: ban memory saved for %s -> %s (pressure=%.3f)\n",
                        target_key.c_str(), ban_mem_path.c_str(), ban_ewma);
          }
        }
        // Persist the online adapter's learned correction so the next run continues
        // improving instead of relearning from scratch (continual learning).
        if (adapt_on) {
          if (online_adapter.rollbacks() > 0) {
            std::printf("samurai_master: online adapter rolled back %d time(s) this run "
                        "(a regression was detected and reverted)\n",
                        online_adapter.rollbacks());
          }
          if (!adapt_mem_path.empty()) {
            adapt_mem.Put(target_key, online_adapter.weights(),
                          online_adapter.frozen_baseline());
            if (!adapt_mem.Save(adapt_mem_path)) {
              std::fprintf(stderr, "samurai_master: could not persist adapter memory to %s\n",
                           adapt_mem_path.c_str());
            } else {
              std::printf("samurai_master: online adapter saved for %s -> %s\n",
                          target_key.c_str(), adapt_mem_path.c_str());
            }
          }
        }
        // Persist the discovered novelty vocabulary so the next run recognizes the
        // out-of-dictionary phenomena this run learned about the target.
        if (nvcfg.enabled && !novelty.axes().empty()) {
          std::printf("samurai_master: novelty vocabulary discovered for %s: %zu signature(s)\n",
                      target_key.c_str(), novelty.axes().size());
          for (const auto& ax : novelty.axes()) {
            if (ax.graduated) {
              std::printf("samurai_master:   graduated axis '%s' -> learned damping=%.2f "
                          "(seen %ld)\n",
                          ax.signature.c_str(), ax.damping, ax.count);
            }
          }
          if (!novelty_mem_path.empty()) {
            novelty_mem.Put(target_key, novelty.axes());
            if (!novelty_mem.Save(novelty_mem_path)) {
              std::fprintf(stderr, "samurai_master: could not persist novelty memory to %s\n",
                           novelty_mem_path.c_str());
            } else {
              std::printf("samurai_master: novelty memory saved for %s -> %s\n",
                          target_key.c_str(), novelty_mem_path.c_str());
            }
          }
        }
        Value clsummary = Value::Object();
        clsummary.set("event", Value::Str("closed_loop_result"));
        clsummary.set("strategy", Value::Str(StrategyName(clcfg.strategy)));
        clsummary.set("windows", Value::Int(dec.window));
        clsummary.set("best_good_rps", Value::Double(dec.best_good_rps));
        clsummary.set("final_phase", Value::Str(dec.phase));
        std::printf("%s\n", clsummary.dump().c_str());
        if (!cl_aborted) rc = dec.best_good_rps > 0.0 ? 0 : 1;
      } else {
        JobConfig job = BuildJobConfig(spec, ep_now, tenant, master_region);
        attach_progress(job);
        const JobResult res = coord.RunSingleJob(job, "job-1", guard);
        std::printf("%s\n", res.snapshot.dump().c_str());
        rc = res.rc;
      }
    }
  }

  // Serve loop: pull delegated jobs from peer regions and run them locally until
  // signalled. This is what makes a region a live participant in the federation.
  if (mm && mm->active() && !master_region.empty()) {
    const int dequeue_max =
        static_cast<int>(OptInt(argc, argv, "--multi-master-dequeue-max", 3));
    std::printf("samurai_master: serving delegated jobs for region %s (Ctrl-C to stop)\n",
                master_region.c_str());
    long deleg_seq = 0;
    while (!g_stop.load()) {
      if (!elector || elector->IsLeader()) {
        for (auto& j : mm->DequeueJobs(dequeue_max)) {
          const std::int64_t ep_now = current_leader_epoch();
          servicer.set_leader_epoch_min(ep_now);
          JobConfig job = BuildJobConfig(j, ep_now, tenant, master_region);
          attach_progress(job);
          const Value* from = j.find("_mmr_delegated_from");
          const std::string from_region = from ? from->as_string("") : "";
          std::printf("samurai_master: running delegated job from '%s' (count=%lld)\n",
                      from_region.c_str(), static_cast<long long>(job.count));
          const JobResult res =
              coord.RunSingleJob(job, "deleg-" + std::to_string(++deleg_seq), guard);
          Value ev = Value::Object();
          ev.set("type", Value::Str("delegated_job_done"));
          ev.set("rc", Value::Int(res.rc));
          ev.set("from_region", Value::Str(from_region));
          mm->PublishEvent(ev);
          std::printf("%s\n", res.snapshot.dump().c_str());
        }
      }
      for (int slept = 0; slept < 500 && !g_stop.load(); slept += 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
  }

  if (hb_thread.joinable()) hb_thread.join();
  if (as_thread.joinable()) as_thread.join();
  if (mgmt) mgmt->Stop();
  server.Stop();
  if (elector) elector->Stop();
  return rc;
}
