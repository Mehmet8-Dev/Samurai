#pragma once

// Master job dispatch coordinator. Splits a job into shards, dispatches them to
// free workers
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
#include <mutex>
#include <string>
#include <vector>

#include "json.hpp"

namespace samurai::control {

struct WorkerInfo {
  std::string worker_id;
  std::map<std::string, std::string> capabilities;
  std::int64_t last_heartbeat_ms = 0;
  std::string active_shard_id;  // shard the worker reports running (reverse echo)
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
  virtual bool StopShard(const std::string& endpoint, const std::string& shard_id,
                         std::int64_t leader_epoch) = 0;

  // Reverse-mode delivery (NAT'd workers with no inbound endpoint): keyed by
  // worker_id, the command is queued on the master and pulled by the worker on
  // its next heartbeat. Default no-ops so direct-only commanders/tests are
  // unaffected.
  virtual DispatchOutcome DispatchReverse(const std::string& worker_id, const std::string& shard_id,
                                          const std::string& job_id, const std::string& args_json,
                                          std::int64_t packet_count, std::int64_t timeout_ms) {
    (void)worker_id; (void)shard_id; (void)job_id; (void)args_json;
    (void)packet_count; (void)timeout_ms;
    return {false, "reverse dispatch not supported"};
  }
  virtual bool StopShardReverse(const std::string& worker_id, const std::string& shard_id,
                                std::int64_t leader_epoch) {
    (void)worker_id; (void)shard_id; (void)leader_epoch;
    return false;
  }
  virtual bool ReconfigureShard(const std::string& endpoint, const std::string& shard_id,
                                const std::string& args_json, std::int64_t leader_epoch) {
    (void)endpoint; (void)shard_id; (void)args_json; (void)leader_epoch;
    return false;
  }
  virtual bool ReconfigureShardReverse(const std::string& worker_id, const std::string& shard_id,
                                       const std::string& args_json, std::int64_t leader_epoch) {
    (void)worker_id; (void)shard_id; (void)args_json; (void)leader_epoch;
    return false;
  }
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
  int max_shard_retries = 3;
  // Reverse-mode pickup grace: if a reverse worker hasn't echoed the dispatched
  // shard (nor reported it) within this window, the enqueue is deemed lost and
  // the shard is rebalanced. 0 => 2 x heartbeat_timeout_ms.
  std::int64_t reverse_pickup_grace_ms = 0;
  int db_port = 5099;                        // Default DB persistence port (user memory standard)

  // Telecom cluster job configuration
  bool is_telco_job = false;
  std::string telco_protocol = "pppoe";      // "pppoe", "dhcp", "gtpu", "bfd", "pfcp", "sctp", "diameter", "sip-rtp", "multi"
  std::uint32_t telco_subscribers = 0;       // Total subscriber pool size across cluster
  std::uint32_t telco_rate_cps = 5000;       // New subscriber setup rate (CPS)
  std::uint16_t telco_base_vlan_s = 100;     // 802.1ad Service Outer VLAN base
  std::uint16_t telco_base_vlan_c = 10;      // 802.1Q Customer Inner VLAN base
  std::uint32_t telco_base_ip = 0x0A000001;  // 10.0.0.1
  std::uint32_t telco_gateway_ip = 0x0A0000FE; // 10.0.0.254
  std::uint32_t telco_duration_ms = 0;       // 0 = worker default / bounded by count
  std::uint32_t sctp_rate = 0;
  std::uint32_t diameter_rate = 0;
  std::uint32_t sip_rate = 0;
  bool enable_srtp = false;
  std::uint32_t teid_start = 1;
  std::uint32_t teid_count = 1;
  std::uint8_t qfi = 9;

  // Production IPFIX / NetFlow telemetry propagation
  bool ipfix_enabled = false;
  std::string ipfix_collector = "127.0.0.1";
  std::uint16_t ipfix_port = 4739;
  std::uint32_t ipfix_sample_rate = 1000;
  bool ipfix_netflow_v9 = false;
  std::uint32_t ipfix_domain_id = 1;
  std::uint32_t ipfix_export_interval_ms = 1000;

  // Base shard args (JSON object) cloned per shard; the coordinator injects
  // count/_worker_id/_leader_epoch/role.
  samurai::core::json::Value base_args = samurai::core::json::Value::Object();
  // Optional live progress reporter: invoked once per dispatch poll with the
  // current (pending, inflight) shard counts. Empty => no-op (the default; all
  // existing callers and tests are unaffected). Feeds the autoscale controller.
  std::function<void(int pending_shards, int inflight_shards)> progress_cb;

  // Optional live window tick callback invoked every `window_tick_interval_ms`
  // while shards are in flight. Returning non-empty JSON triggers live
  // ReconfigureShard RPCs across active shards without tearing down workers.
  std::int64_t window_tick_interval_ms = 0;
  std::function<std::string(int tick_index,
                            const std::vector<ProbeOutcome>& live_probes,
                            bool& should_stop)>
      window_tick_cb;
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

  // Push a live ReconfigureShard RPC to currently active shards (matching
  // filter_shard_id / filter_worker_id when non-empty; all active when empty).
  // Returns count of shards that accepted or queued the reconfiguration.
  int ReconfigureActiveShards(const std::string& args_json,
                              std::int64_t leader_epoch = -1,
                              const std::string& filter_shard_id = "",
                              const std::string& filter_worker_id = "");

  std::map<std::string, std::string> ActiveShardWorkers() const;

 private:
  struct ActiveShardTarget {
    std::string worker_id;
    std::string endpoint;
    bool via_reverse = false;
    bool is_auto = false;
    std::int64_t leader_epoch = 0;
  };

  MasterView* view_;
  WorkerCommander* commander_;
  std::function<std::int64_t()> now_ms_;
  std::function<void(int)> sleep_ms_;
  mutable std::mutex active_mu_;
  std::map<std::string, ActiveShardTarget> active_shards_;
};

}  // namespace samurai::control
