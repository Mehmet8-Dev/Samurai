#include "supervisor_shard_runner.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unistd.h>

namespace samurai::control::daemon {

namespace {
using samurai::core::json::Value;
using samurai::orchestrator::JobOptions;

std::string StrArg(const Value& a, const char* k, const std::string& def) {
  const Value* v = a.find(k);
  return (v && v->is_string()) ? v->as_string(def) : def;
}
std::int64_t IntArg(const Value& a, const char* k, std::int64_t def) {
  const Value* v = a.find(k);
  return v ? v->as_int(def) : def;
}
double DblArg(const Value& a, const char* k, double def) {
  const Value* v = a.find(k);
  return v ? v->as_double(def) : def;
}
bool BoolArg(const Value& a, const char* k, bool def) {
  const Value* v = a.find(k);
  if (!v) return def;
  if (v->is_bool()) return v->as_bool(def);
  return v->as_int(def ? 1 : 0) != 0;
}

const Value* FindTelcoField(const Value& a, const Value* telco, const Value* range, const char* k) {
  if (const Value* v = a.find(k)) return v;
  if (telco && telco->is_object()) {
    if (const Value* v = telco->find(k)) return v;
  }
  if (range && range->is_object()) {
    if (const Value* v = range->find(k)) return v;
  }
  return nullptr;
}

std::int64_t TelcoInt(
    const Value& a, const Value* telco, const Value* range, const char* k, std::int64_t def) {
  const Value* v = FindTelcoField(a, telco, range, k);
  return v ? v->as_int(def) : def;
}

std::string FormatHostIpv4(std::uint32_t ip) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                (ip >> 24) & 0xFFu,
                (ip >> 16) & 0xFFu,
                (ip >> 8) & 0xFFu,
                ip & 0xFFu);
  return std::string(buf);
}

std::string TelcoIpv4(
    const Value& a, const Value* telco, const Value* range, const char* k, const std::string& def) {
  const Value* v = FindTelcoField(a, telco, range, k);
  if (!v) return def;
  if (v->is_string()) {
    const std::string s = v->as_string("");
    return s.empty() ? def : s;
  }
  const std::int64_t raw = v->as_int(0);
  if (raw <= 0) return def;
  return FormatHostIpv4(static_cast<std::uint32_t>(raw));
}

// Map a shard's args JSON onto a JobOptions. Accepts both CLI-style ("target",
// "count", "size", "vector") and envelope-style ("target_ip", "packet_count")
// field names, as well as TelcoShardSpec and IPFIX telemetry fields.
JobOptions JobFromArgs(const Value& a) {
  JobOptions j;
  std::string ip = StrArg(a, "target_ip", "");
  if (ip.empty()) ip = StrArg(a, "target", "127.0.0.1");
  j.target_ip = ip;
  j.target_port = static_cast<std::uint16_t>(IntArg(a, "target_port", IntArg(a, "port", 80)));
  j.packet_count = static_cast<std::uint32_t>(IntArg(a, "packet_count", IntArg(a, "count", 1000)));
  j.packet_size = static_cast<std::uint32_t>(IntArg(a, "packet_size", IntArg(a, "size", 64)));
  j.target_rps = DblArg(a, "target_rps", DblArg(a, "rps", 0.0));
  j.pacing_mode = j.target_rps > 0.0 ? 1u : 0u;
  j.pin_cpu = static_cast<std::int32_t>(IntArg(a, "pin_cpu", -1));
  j.protocol = StrArg(a, "protocol", "udp");
  j.attack_vector = StrArg(a, "attack_vector", StrArg(a, "vector", "flood"));
  j.ttl = static_cast<std::uint8_t>(IntArg(a, "ttl", 64));
  j.spoof = BoolArg(a, "spoof", false);
  j.spoof_mode = StrArg(a, "spoof_mode", "");
  j.l7_profile_file = StrArg(a, "l7_profile_file", StrArg(a, "scenario_payload_ref", ""));
  j.l7_payload_file = StrArg(a, "l7_payload_file", StrArg(a, "payload_ref", ""));
  j.concurrency = static_cast<std::uint32_t>(std::max<int64_t>(1, IntArg(a, "concurrency", 1)));
  // The emu clamps effective parallelism to min(concurrency, max_connections), so
  // a pool of 1 pins concurrency to 1 no matter what the lever says. Default the
  // pool to the concurrency so the lever actually opens that many connections
  // (and can push a per-IP conn limit into 503). An explicit max_connections
  // still wins.
  j.max_connections = static_cast<std::uint32_t>(
      std::max<int64_t>(1, IntArg(a, "max_connections", static_cast<std::int64_t>(j.concurrency))));
  j.max_streams_per_connection =
      static_cast<std::uint32_t>(std::max<int64_t>(1, IntArg(a, "max_streams_per_connection", 1)));
  j.scheme = StrArg(a, "scheme", "");
  j.host_header = StrArg(a, "host_header", "");
  j.verify_tls = BoolArg(a, "verify_tls", false) ? 1u : 0u;
  j.keepalive = BoolArg(a, "keepalive", false) ? 1u : 0u;
  j.l7_timeout_ms = static_cast<std::uint32_t>(std::max<int64_t>(1, IntArg(a, "l7_timeout_ms", 5000)));
  // Mahoraga shaping levers set by the RL policy / exploration schedule.
  j.request_mix = static_cast<std::uint32_t>(std::max<int64_t>(0, IntArg(a, "request_mix", 0)));
  j.source_rotation = static_cast<std::uint32_t>(std::max<int64_t>(0, IntArg(a, "source_rotation", 0)));
  j.auth_mode = static_cast<std::uint32_t>(std::max<int64_t>(0, IntArg(a, "auth_mode", 0)));
  j.evasion_tactic = static_cast<std::uint32_t>(std::max<int64_t>(0, IntArg(a, "evasion_tactic", 0)));
  j.auth_payload = StrArg(a, "auth_payload", "");

  // Production IPFIX / NetFlow telemetry config
  j.ipfix_enabled = BoolArg(a, "ipfix_enabled", false);
  j.ipfix_collector = StrArg(a, "ipfix_collector", "127.0.0.1");
  j.ipfix_port = static_cast<std::uint16_t>(
      std::max<int64_t>(1, IntArg(a, "ipfix_port", 4739)));
  j.ipfix_sample_rate = static_cast<std::uint32_t>(
      std::max<int64_t>(1, IntArg(a, "ipfix_sample_rate", 1000)));
  j.ipfix_netflow_v9 = BoolArg(a, "ipfix_netflow_v9", false);
  j.ipfix_domain_id = static_cast<std::uint32_t>(
      std::max<int64_t>(0, IntArg(a, "ipfix_domain_id", 1)));
  j.ipfix_export_interval_ms = static_cast<std::uint32_t>(
      std::max<int64_t>(50, IntArg(a, "ipfix_export_interval_ms", 1000)));

  // Distributed Telco control & user plane options (top-level or nested `telco`)
  const Value* telco = a.find("telco");
  const Value* range = (telco && telco->is_object()) ? telco->find("range") : nullptr;

  j.telco_subscriber_start = static_cast<std::uint32_t>(std::max<int64_t>(
      0, TelcoInt(a, telco, range, "start_idx", IntArg(a, "telco_subscriber_start", 0))));
  const std::int64_t range_subs =
      (range && range->is_object() && range->find("count")) ? range->find("count")->as_int(100) : 100;
  j.telco_subscribers = static_cast<std::uint32_t>(std::max<int64_t>(
      1, TelcoInt(a, telco, nullptr, "sub_count",
                  IntArg(a, "telco_subscribers", range_subs))));
  j.telco_rate_cps = static_cast<std::uint32_t>(std::max<int64_t>(
      1, TelcoInt(a, telco, range, "target_cps", IntArg(a, "telco_rate_cps", 50))));
  j.telco_base_vlan_s = static_cast<std::uint16_t>(std::max<int64_t>(
      0, TelcoInt(a, telco, range, "base_vlan_s", IntArg(a, "vlan_s", 100))));
  j.telco_base_vlan_c = static_cast<std::uint16_t>(std::max<int64_t>(
      0, TelcoInt(a, telco, range, "base_vlan_c", IntArg(a, "vlan_c", 100))));
  j.telco_base_ip = TelcoIpv4(a, telco, range, "base_ip",
                              StrArg(a, "telco_base_ip", "10.0.0.1"));
  j.telco_gateway_ip = TelcoIpv4(a, telco, range, "gateway_ip",
                                 StrArg(a, "telco_gateway_ip", ""));
  const std::int64_t default_dur = IntArg(a, "window_s", 0) > 0 ? IntArg(a, "window_s", 5) * 1000 : 5000;
  j.telco_duration_ms = static_cast<std::uint32_t>(std::max<int64_t>(
      0, IntArg(a, "telco_duration_ms", IntArg(a, "duration_ms", default_dur))));
  j.sctp_rate = static_cast<std::uint32_t>(std::max<int64_t>(0, IntArg(a, "sctp_rate", 0)));
  j.diameter_rate = static_cast<std::uint32_t>(std::max<int64_t>(0, IntArg(a, "diameter_rate", 0)));
  j.sip_rate = static_cast<std::uint32_t>(std::max<int64_t>(0, IntArg(a, "sip_rate", 0)));
  j.enable_srtp = BoolArg(a, "enable_srtp", false);
  j.teid_start = static_cast<std::uint32_t>(std::max<int64_t>(0, IntArg(a, "teid_start", 1)));
  j.teid_count = static_cast<std::uint32_t>(std::max<int64_t>(1, IntArg(a, "teid_count", 1)));
  j.qfi = static_cast<std::uint8_t>(std::clamp<int64_t>(IntArg(a, "qfi", 9), 0, 63));
  j.inner_proto = static_cast<std::uint8_t>(std::clamp<int64_t>(IntArg(a, "inner_proto", 17), 0, 255));
  j.telco_db_port = static_cast<std::uint16_t>(std::max<int64_t>(
      1, TelcoInt(a, telco, nullptr, "db_port", IntArg(a, "telco_db_port", 5099))));
  const std::string un = StrArg(a, "telco_username", "");
  if (!un.empty()) j.telco_username = un;
  const std::string pw = StrArg(a, "telco_password", "");
  if (!pw.empty()) j.telco_password = pw;
  if (const Value* mv = FindTelcoField(a, telco, range, "base_mac")) {
    if (mv->is_string()) {
      unsigned int m[6] = {};
      if (std::sscanf(mv->as_string("").c_str(), "%x:%x:%x:%x:%x:%x",
                      &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
        for (int idx = 0; idx < 6; ++idx) {
          j.telco_base_mac[static_cast<std::size_t>(idx)] = static_cast<std::uint8_t>(m[idx]);
        }
      }
    }
  }
  return j;
}

samurai::wire::ReconfigureWindowV1 ReconfigureWindowFromJson(const Value& a) {
  samurai::wire::ReconfigureWindowV1 w{};
  if (!a.is_object()) return w;
  if (const Value* v = a.find("target_rps") ? a.find("target_rps") : a.find("rps")) {
    w.flags |= samurai::wire::ReconfigureFlag::kRps;
    w.target_rps = std::max(0.0, v->as_double(0.0));
    if (!a.find("pacing_mode")) {
      w.flags |= samurai::wire::ReconfigureFlag::kPacingMode;
      w.pacing_mode = w.target_rps > 0.0 ? 1u : 0u;
    }
  }
  if (const Value* v = a.find("pacing_mode")) {
    w.flags |= samurai::wire::ReconfigureFlag::kPacingMode;
    w.pacing_mode = static_cast<std::uint8_t>(std::max<std::int64_t>(0, v->as_int(0)));
  }
  if (const Value* v = a.find("jitter_model")) {
    w.flags |= samurai::wire::ReconfigureFlag::kJitter;
    w.jitter_model = static_cast<std::uint8_t>(std::max<std::int64_t>(0, v->as_int(0)));
  }
  if (const Value* v = a.find("jitter_pct")) {
    w.flags |= samurai::wire::ReconfigureFlag::kJitter;
    w.jitter_pct = std::max(0.0, v->as_double(0.0));
  }
  if (const Value* v = a.find("ipg_ns")) {
    w.flags |= samurai::wire::ReconfigureFlag::kIpg;
    w.ipg_ns = static_cast<std::uint64_t>(std::max<std::int64_t>(0, v->as_int(0)));
  }
  if (const Value* v = a.find("burst_size")) {
    w.flags |= samurai::wire::ReconfigureFlag::kBurst;
    w.burst_size = static_cast<std::uint32_t>(std::max<std::int64_t>(1, v->as_int(1)));
  }
  if (const Value* v = a.find("request_mix")) {
    w.flags |= samurai::wire::ReconfigureFlag::kRequestMix;
    w.request_mix = static_cast<std::uint32_t>(std::max<std::int64_t>(0, v->as_int(0)));
  }
  if (const Value* v = a.find("source_rotation")) {
    w.flags |= samurai::wire::ReconfigureFlag::kSourceRotation;
    w.source_rotation = static_cast<std::uint32_t>(std::max<std::int64_t>(0, v->as_int(0)));
  }
  if (const Value* v = a.find("telco_cps") ? a.find("telco_cps") : a.find("telco_rate_cps")) {
    w.flags |= samurai::wire::ReconfigureFlag::kTelcoCps;
    w.telco_rate_cps = static_cast<std::uint32_t>(std::max<std::int64_t>(0, v->as_int(0)));
  }
  return w;
}
}  // namespace

SupervisorShardRun::SupervisorShardRun(samurai::orchestrator::SupervisorConfig cfg,
                                       samurai::orchestrator::JobOptions job,
                                       std::shared_ptr<samurai::orchestrator::WarmWorkerPool> pool,
                                       std::string shard_id)
    : cfg_(std::move(cfg)),
      job_(std::move(job)),
      pool_(std::move(pool)),
      shard_id_(std::move(shard_id)) {
  thread_ = std::thread([this]() {
    exit_code_ = samurai::orchestrator::RunJob(
        cfg_, job_, stats_, pool_.get(), &terminated_, shard_id_);
    done_.store(true);
  });
}

SupervisorShardRun::~SupervisorShardRun() {
  if (thread_.joinable()) thread_.join();
}

void SupervisorShardRun::Join() {
  if (thread_.joinable()) thread_.join();
}

bool SupervisorShardRun::Reconfigure(const samurai::wire::ReconfigureWindowV1& window) {
  if (!pool_ || shard_id_.empty()) return false;
  return pool_->ReconfigureActiveShard(shard_id_, window);
}

bool SupervisorShardRun::Reconfigure(const samurai::core::json::Value& params) {
  const samurai::wire::ReconfigureWindowV1 window = ReconfigureWindowFromJson(params);
  if (window.flags == 0u) return false;
  return Reconfigure(window);
}

samurai::core::json::Value SupervisorShardRun::MetricsJson() const {
  using samurai::core::json::Value;
  Value o = Value::Object();
  // Keep this key set in lockstep with run_summary.hpp RunStats + RlDefenseJson.
  o.set("responses_total", Value::Int(static_cast<std::int64_t>(stats_.responses_total)));
  o.set("status_2xx", Value::Int(static_cast<std::int64_t>(stats_.status_2xx)));
  o.set("status_3xx", Value::Int(static_cast<std::int64_t>(stats_.status_3xx)));
  o.set("status_4xx", Value::Int(static_cast<std::int64_t>(stats_.status_4xx)));
  o.set("status_5xx", Value::Int(static_cast<std::int64_t>(stats_.status_5xx)));
  o.set("l7_conn_attempted", Value::Int(static_cast<std::int64_t>(stats_.l7_conn_attempted)));
  o.set("l7_conn_established", Value::Int(static_cast<std::int64_t>(stats_.l7_conn_established)));
  o.set("l7_expectation_failures",
        Value::Int(static_cast<std::int64_t>(stats_.l7_expectation_failures)));
  o.set("l7_scheduler_backpressure_count",
        Value::Int(static_cast<std::int64_t>(stats_.l7_scheduler_backpressure_count)));
  o.set("h2_goaway_count", Value::Int(static_cast<std::int64_t>(stats_.h2_goaway_count)));
  o.set("h2_stream_reset_ratio", Value::Double(stats_.h2_stream_reset_ratio));
  o.set("l7_request_latency_p99_ms", Value::Double(stats_.l7_request_latency_p99_ms));
  o.set("l7_tls_handshake_p99_ms", Value::Double(stats_.l7_tls_handshake_p99_ms));
  o.set("tcp_peer_rst_count", Value::Int(static_cast<std::int64_t>(stats_.tcp_peer_rst_count)));
  o.set("tcp_connect_timeout_count",
        Value::Int(static_cast<std::int64_t>(stats_.tcp_connect_timeout_count)));
  o.set("tcp_retransmit_count", Value::Int(static_cast<std::int64_t>(stats_.tcp_retransmit_count)));
  o.set("tcp_timeout_close_count",
        Value::Int(static_cast<std::int64_t>(stats_.tcp_timeout_close_count)));

  // IPFIX / NetFlow export totals
  o.set("ipfix_exported_packets",
        Value::Int(static_cast<std::int64_t>(stats_.ipfix_exported_packets)));
  o.set("ipfix_exported_records",
        Value::Int(static_cast<std::int64_t>(stats_.ipfix_exported_records)));

  // Telco control & user plane telemetry
  o.set("telco_active_sessions",
        Value::Int(static_cast<std::int64_t>(stats_.telco_active_sessions)));
  o.set("telco_established_sessions",
        Value::Int(static_cast<std::int64_t>(stats_.telco_established_sessions)));
  o.set("telco_failed_sessions",
        Value::Int(static_cast<std::int64_t>(stats_.telco_failed_sessions)));
  o.set("telco_current_cps", Value::Int(static_cast<std::int64_t>(stats_.telco_current_cps)));
  o.set("telco_avg_setup_latency_us",
        Value::Int(static_cast<std::int64_t>(stats_.telco_avg_setup_latency_us)));
  o.set("telco_p99_setup_latency_us",
        Value::Int(static_cast<std::int64_t>(stats_.telco_p99_setup_latency_us)));
  o.set("telco_retransmit_count",
        Value::Int(static_cast<std::int64_t>(stats_.telco_retransmit_count)));
  return o;
}

samurai::orchestrator::WorkerEntry SupervisorShardRunner::ResolveWorker(
    const samurai::core::json::Value& args) const {
  if (!bundle_) {
    return fixed_;
  }
  // Bundle: the job's `worker` field names the flavor for this shard.
  const std::string name = StrArg(args, "worker", "");
  if (!name.empty()) {
    if (auto e = samurai::orchestrator::LookupWorker(name); e) {
      return *e;
    }
  }
  return fallback_;
}

std::shared_ptr<samurai::control::ShardRun> SupervisorShardRunner::Start(
    const std::string& shard_id, const samurai::core::json::Value& args) {
  samurai::orchestrator::SupervisorConfig cfg;
  cfg.worker = ResolveWorker(args);
  cfg.worker_dir = worker_dir_;
  const std::string suffix = shard_id + "_" + std::to_string(static_cast<long>(::getpid()));
  cfg.jobs_endpoint = "ipc:///tmp/samurai_jobs_" + suffix;
  cfg.events_endpoint = "ipc:///tmp/samurai_events_" + suffix;
  cfg.recv_timeout_ms = 5000;
  return std::make_shared<SupervisorShardRun>(std::move(cfg), JobFromArgs(args), pool_, shard_id);
}

bool SupervisorShardRunner::ReconfigureShard(
    const std::string& shard_id,
    const samurai::wire::ReconfigureWindowV1& window) {
  if (!pool_) return false;
  return pool_->ReconfigureActiveShard(shard_id, window);
}

bool SupervisorShardRunner::ReconfigureShard(
    const std::string& shard_id,
    const samurai::core::json::Value& params) {
  const samurai::wire::ReconfigureWindowV1 window = ReconfigureWindowFromJson(params);
  if (window.flags == 0u) return false;
  return ReconfigureShard(shard_id, window);
}

}  // namespace samurai::control::daemon
