#pragma once

// Master-side control service. Holds the worker registry + shard stats and
// implements the eight control RPCs
// as pure request-body -> response-body transforms (JSON), independent of the
// transport. ControlServer drives it over ZMQ; it is equally testable directly.

#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "json.hpp"

namespace samurai::control {

// Per-call context resolved by the server before dispatch.
struct RpcContext {
  const samurai::core::json::Value* meta = nullptr;  // request meta object
  std::string role;                                  // resolved RBAC role
};

// A command the master wants a reverse-mode (NAT'd) worker to execute. The
// worker never exposes an inbound control endpoint, so the master cannot push a
// StartShard/StopShard RPC to it; instead the command is queued here and
// piggybacked onto the worker's next Heartbeat response (agent-initiated pull).
struct PendingCommand {
  std::string type;          // "start" | "stop"
  std::string shard_id;
  std::string job_id;
  std::string args_json = "{}";
  std::int64_t packet_count = 0;
  std::int64_t timeout_ms = 0;
  std::int64_t leader_epoch = 0;  // fences reverse-delivered "stop" against zombies
};

// Transport-agnostic control service interface (one method per proto RPC).
class ControlService {
 public:
  virtual ~ControlService() = default;
  virtual samurai::core::json::Value RegisterWorker(const samurai::core::json::Value& body, const RpcContext& ctx) = 0;
  virtual samurai::core::json::Value Heartbeat(const samurai::core::json::Value& body, const RpcContext& ctx) = 0;
  virtual samurai::core::json::Value StartShard(const samurai::core::json::Value& body, const RpcContext& ctx) = 0;
  virtual samurai::core::json::Value StopShard(const samurai::core::json::Value& body, const RpcContext& ctx) = 0;
  virtual samurai::core::json::Value ReportStats(const samurai::core::json::Value& body, const RpcContext& ctx) = 0;
  virtual samurai::core::json::Value AbortJob(const samurai::core::json::Value& body, const RpcContext& ctx) = 0;
  virtual samurai::core::json::Value GetWorkerStatus(const samurai::core::json::Value& body, const RpcContext& ctx) = 0;
  virtual samurai::core::json::Value ForceSync(const samurai::core::json::Value& body, const RpcContext& ctx) = 0;
};

struct ServicerConfig {
  std::string cluster_id = "cluster-v1";
  std::string tenant_namespace;
  std::string jwt_secret;
  std::string jwt_tenant_claim = "tenant_namespace";
};

class Servicer : public ControlService {
 public:
  explicit Servicer(const ServicerConfig& cfg = {});

  samurai::core::json::Value RegisterWorker(const samurai::core::json::Value& body, const RpcContext& ctx) override;
  samurai::core::json::Value Heartbeat(const samurai::core::json::Value& body, const RpcContext& ctx) override;
  samurai::core::json::Value StartShard(const samurai::core::json::Value& body, const RpcContext& ctx) override;
  samurai::core::json::Value StopShard(const samurai::core::json::Value& body, const RpcContext& ctx) override;
  samurai::core::json::Value ReportStats(const samurai::core::json::Value& body, const RpcContext& ctx) override;
  samurai::core::json::Value AbortJob(const samurai::core::json::Value& body, const RpcContext& ctx) override;
  samurai::core::json::Value GetWorkerStatus(const samurai::core::json::Value& body, const RpcContext& ctx) override;
  samurai::core::json::Value ForceSync(const samurai::core::json::Value& body, const RpcContext& ctx) override;

  // Reject ReportStats carrying a stale leader epoch (< min). 0 disables.
  void set_leader_epoch_min(std::int64_t epoch);
  std::size_t worker_count() const;

  // Read-side accessors used by the master coordinator's MasterView adapter.
  struct WorkerSnapshot {
    std::string worker_id;
    std::map<std::string, std::string> capabilities;
    std::int64_t last_heartbeat_ms = 0;
    std::string active_shard_id;  // ground truth echoed by the worker (reverse)
  };
  std::vector<WorkerSnapshot> SnapshotWorkers() const;
  bool HasShardStats(const std::string& shard_id) const;
  std::string GetShardStatsRaw(const std::string& shard_id) const;  // "{}" if none
  void SetShardStatsRaw(const std::string& shard_id, const std::string& stats_json);

  // Reverse-mode dispatch: queue a command for a worker; the next Heartbeat
  // response drains one command into its body (see Heartbeat). Thread-safe.
  void EnqueueCommand(const std::string& worker_id, const PendingCommand& cmd);

 private:
  struct WorkerRec {
    std::string worker_id;
    std::string hostname;
    std::string tenant_namespace;
    std::string state = "idle";
    std::string active_shard_id;
    std::map<std::string, std::string> capabilities;
    std::int64_t last_heartbeat_ms = 0;
    std::string stats_json = "{}";  // raw JSON text
  };

  std::string TenantFromContext(const RpcContext& ctx) const;
  bool TenantGuard(const RpcContext& ctx) const;

  ServicerConfig cfg_;
  std::int64_t leader_epoch_min_ = 0;
  mutable std::mutex mu_;
  std::map<std::string, WorkerRec> workers_;
  std::map<std::string, std::string> shard_stats_;  // shard_id -> raw JSON
  std::map<std::string, std::deque<PendingCommand>> pending_cmds_;  // worker_id -> queue
};

}  // namespace samurai::control
