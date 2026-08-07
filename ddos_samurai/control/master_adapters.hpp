#pragma once

// Real adapters wiring the transport-agnostic MasterCoordinator to the live
// pieces: the Servicer's worker registry / reported stats (MasterView) and the
// ZMQ WorkerControlClient (WorkerCommander). Built only with libzmq.

#include <string>

#include "master_coordinator.hpp"
#include "servicer.hpp"

namespace samurai::control {

// MasterView backed by a live Servicer.
class ServicerMasterView : public MasterView {
 public:
  explicit ServicerMasterView(Servicer* servicer) : servicer_(servicer) {}
  std::vector<WorkerInfo> Workers() override;
  bool ShardReported(const std::string& shard_id) override;
  std::string GetShardStats(const std::string& shard_id) override;
  void SetShardStats(const std::string& shard_id, const std::string& stats_json) override;

 private:
  Servicer* servicer_;
};

// WorkerCommander that issues real StartShard/GetWorkerStatus/StopShard RPCs to
// a worker endpoint over ZMQ (a WorkerControlClient is created per call, as the
// Python master did).
class ClientWorkerCommander : public WorkerCommander {
 public:
  ClientWorkerCommander(const std::string& cluster_secret = "",
                        const std::string& tenant_namespace = "", int timeout_ms = 5000)
      : cluster_secret_(cluster_secret), tenant_namespace_(tenant_namespace),
        timeout_ms_(timeout_ms) {}

  DispatchOutcome Dispatch(const std::string& endpoint, const std::string& shard_id,
                           const std::string& job_id, const std::string& args_json,
                           std::int64_t packet_count, std::int64_t timeout_ms) override;
  ProbeOutcome Probe(const std::string& endpoint, const std::string& worker_id) override;
  bool StopShard(const std::string& endpoint, const std::string& shard_id) override;

 private:
  std::string cluster_secret_;
  std::string tenant_namespace_;
  int timeout_ms_;
};

}  // namespace samurai::control
