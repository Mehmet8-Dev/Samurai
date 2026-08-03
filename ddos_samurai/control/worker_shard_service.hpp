#pragma once

// Worker-side control service — native C++ port of slave.py's _WorkerServicer.
// The distributed slave serves this so the master can drive shards directly:
// StartShard (with leader-epoch fencing + duplicate guard), StopShard, and
// GetWorkerStatus. Shard execution goes through the ShardRunner abstraction; a
// per-shard monitor thread finalizes stats on completion.
//
// The other five RPCs are not the worker's role and return inert responses.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "servicer.hpp"      // ControlService, RpcContext
#include "shard_runner.hpp"

namespace samurai::control {

class WorkerShardService : public ControlService {
 public:
  // `runner` is non-owning and must outlive the service.
  WorkerShardService(const std::string& worker_id, ShardRunner* runner);
  ~WorkerShardService() override;

  samurai::core::json::Value StartShard(const samurai::core::json::Value& body, const RpcContext& ctx) override;
  samurai::core::json::Value StopShard(const samurai::core::json::Value& body, const RpcContext& ctx) override;
  samurai::core::json::Value GetWorkerStatus(const samurai::core::json::Value& body, const RpcContext& ctx) override;

  // Not served worker-side; inert responses (mirrors _WorkerServicer scope).
  samurai::core::json::Value RegisterWorker(const samurai::core::json::Value&, const RpcContext&) override;
  samurai::core::json::Value Heartbeat(const samurai::core::json::Value&, const RpcContext&) override;
  samurai::core::json::Value ReportStats(const samurai::core::json::Value&, const RpcContext&) override;
  samurai::core::json::Value AbortJob(const samurai::core::json::Value&, const RpcContext&) override;
  samurai::core::json::Value ForceSync(const samurai::core::json::Value&, const RpcContext&) override;

  // Block until any monitor threads for a shard finish (test helper).
  void WaitForShardIdle(const std::string& shard_id);

 private:
  struct ShardRec {
    std::shared_ptr<ShardRun> run;
    std::int64_t runtime_id = 0;
    bool running = false;
    std::string job_id;
    std::int64_t leader_epoch = 0;
    double started_ts = 0.0;
  };
  struct StatusRec {
    std::string state = "idle";
    std::string active_shard_id;
    double updated_ts = 0.0;
    std::string stats_json = "{}";
  };

  void MonitorRuntime(const std::string& shard_id, std::int64_t runtime_id);
  void RefreshWorkerStateLocked();
  std::string FinalizeStats(const std::string& shard_id, const ShardRec& rec, double started_ts,
                            int exitcode, const char* status_override) const;

  std::string worker_id_;
  ShardRunner* runner_;
  mutable std::mutex mu_;
  std::map<std::string, ShardRec> shard_runs_;
  std::map<std::string, StatusRec> shard_status_;
  std::string worker_state_ = "idle";
  std::string worker_active_shard_;
  std::int64_t leader_epoch_max_seen_ = 0;

  std::vector<std::thread> monitors_;      // joined in the destructor
  std::atomic<int> active_monitors_{0};
  std::condition_variable idle_cv_;
};

}  // namespace samurai::control
