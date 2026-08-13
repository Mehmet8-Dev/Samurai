#include "supervisor_shard_runner.hpp"

#include <cstdint>
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
  return v ? v->as_bool(def) : def;
}

// Map a shard's args JSON onto a JobOptions. Accepts both CLI-style ("target",
// "count", "size", "vector") and envelope-style ("target_ip", "packet_count")
// field names.
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
  j.max_connections = static_cast<std::uint32_t>(std::max<int64_t>(1, IntArg(a, "max_connections", 1)));
  j.max_streams_per_connection =
      static_cast<std::uint32_t>(std::max<int64_t>(1, IntArg(a, "max_streams_per_connection", 1)));
  j.scheme = StrArg(a, "scheme", "");
  j.host_header = StrArg(a, "host_header", "");
  j.verify_tls = BoolArg(a, "verify_tls", false) ? 1u : 0u;
  j.keepalive = BoolArg(a, "keepalive", false) ? 1u : 0u;
  j.l7_timeout_ms = static_cast<std::uint32_t>(std::max<int64_t>(1, IntArg(a, "l7_timeout_ms", 5000)));
  return j;
}
}  // namespace

SupervisorShardRun::SupervisorShardRun(samurai::orchestrator::SupervisorConfig cfg,
                                       samurai::orchestrator::JobOptions job)
    : cfg_(std::move(cfg)), job_(std::move(job)) {
  thread_ = std::thread([this]() {
    exit_code_ = samurai::orchestrator::RunJob(cfg_, job_, stats_);
    done_.store(true);
  });
}

SupervisorShardRun::~SupervisorShardRun() {
  if (thread_.joinable()) thread_.join();
}

void SupervisorShardRun::Join() {
  if (thread_.joinable()) thread_.join();
}

std::shared_ptr<samurai::control::ShardRun> SupervisorShardRunner::Start(
    const std::string& shard_id, const samurai::core::json::Value& args) {
  samurai::orchestrator::SupervisorConfig cfg;
  cfg.worker = worker_;
  cfg.worker_dir = worker_dir_;
  const std::string suffix = shard_id + "_" + std::to_string(static_cast<long>(::getpid()));
  cfg.jobs_endpoint = "ipc:///tmp/samurai_jobs_" + suffix;
  cfg.events_endpoint = "ipc:///tmp/samurai_events_" + suffix;
  cfg.recv_timeout_ms = 5000;
  return std::make_shared<SupervisorShardRun>(std::move(cfg), JobFromArgs(args));
}

}  // namespace samurai::control::daemon
