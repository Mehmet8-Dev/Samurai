#pragma once

// Master job dispatch coordinator — native C++ port of master.py's
// _run_single_job. Splits a job into shards, dispatches them to free workers
// (region-aware scoring), detects lost workers by heartbeat timeout and
// rebalances/retries their shards, tracks completion via reported stats or a
// worker status probe, stops any stragglers, and aggregates the result via the
// DistributedAggregator into a snapshot.
//
// The master's own state (worker registry + reported shard stats) and the
// outbound worker RPCs are abstracted behind MasterView / WorkerCommander so the
// state machine is transport-agnostic and testable; the ZMQ-backed
// implementations live alongside the transport.

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "json.hpp"

namespace samurai::control {

struct WorkerInfo {
  std::string worker_id;
  std::map<std::string, std::string> capabilities;
  std::int64_t last_heartbeat_ms = 0;
};

// The master's authoritative state: the worker registry and reported shard
// stats (what workers push via ReportStats). Servicer adapts to this in the
// real wiring; tests use an in-memory fake.
class MasterView {
 public:
  virtual ~MasterView() = default;
  virtual std::vector<WorkerInfo> Workers() = 0;
  virtual bool ShardReported(const std::string& shard_id) = 0;
  virtual std::string GetShardStats(const std::string& shard_id) = 0;  // raw JSON ("{}" if none)
  virtual void SetShardStats(const std::string& shard_id, const std::string& stats_json) = 0;
};

// Outbound master->worker RPCs.
struct DispatchOutcome {
  bool started = false;
  std::string message;  // human-readable success/failure detail
};
struct ProbeOutcome {
  std::string state;           // "", "running", "done", "error", ...
  std::string active_shard_id;
  std::string stats_json = "{}";
};
class WorkerCommander {
 public:
  virtual ~WorkerCommander() = default;
  virtual DispatchOutcome Dispatch(const std::string& endpoint, const std::string& shard_id,
                                   const std::string& job_id, const std::string& args_json,
                                   std::int64_t packet_count, std::int64_t timeout_ms) = 0;
  virtual ProbeOutcome Probe(const std::string& endpoint, const std::string& worker_id) = 0;
  virtual bool StopShard(const std::string& endpoint, const std::string& shard_id) = 0;
};

struct JobConfig {
  std::int64_t count = 0;
  std::int64_t job_timeout_s = 0;         // 0 => default 120s wait cap
  std::int64_t heartbeat_timeout_ms = 6000;
  int master_poll_interval_ms = 250;
  bool worker_status_probe = true;
  std::string on_worker_loss = "continue";  // or "abort"
  std::int64_t shard_unit_count = 0;         // 0 => auto from worker count
  bool region_aware_routing = false;
  std::string shard_strategy = "equal";      // "region" also enables region routing
  std::string target_region;
  std::string worker_region;                 // the master's region
  double cross_region_heartbeat_factor = 1.6;
  std::string tenant_namespace;
  std::int64_t leader_epoch = 0;
  int stop_shard_retries = 3;
  int db_port = 5099;                        // Default DB persistence port (user memory standard)
  // Base shard args (JSON object) cloned per shard; the coordinator injects
  // count/_worker_id/_leader_epoch/role.
  samurai::core::json::Value base_args = samurai::core::json::Value::Object();
};

struct JobResult {
  int rc = 0;
  samurai::core::json::Value snapshot;
};

class MasterCoordinator {
 public:
  // now_ms / sleep_ms are injectable for tests (default: wall clock + real sleep).
  MasterCoordinator(MasterView* view, WorkerCommander* commander,
                    std::function<std::int64_t()> now_ms = {},
                    std::function<void(int)> sleep_ms = {});

  // leadership_guard, when set, aborts the job if it returns false (leadership
  // lost). Empty => always leader.
  JobResult RunSingleJob(const JobConfig& job, const std::string& job_id,
                         std::function<bool()> leadership_guard = {});

 private:
  MasterView* view_;
  WorkerCommander* commander_;
  std::function<std::int64_t()> now_ms_;
  std::function<void(int)> sleep_ms_;
};

}  // namespace samurai::control
