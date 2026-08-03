#pragma once

// ZMQ control clients — native transport replacing the gRPC SlaveControlClient
// and WorkerControlClient. Requests are control_wire envelopes sent on a ZMQ_REQ
// socket (created per call for robustness); cluster-secret / tenant metadata is
// attached to every call. SlaveControlClient fails over across endpoints.
//
// TLS is deferred to a later increment.

#include <map>
#include <string>
#include <vector>

#include "control_wire.hpp"

namespace samurai::control {

// Worker (slave) side: register / heartbeat / report stats, with endpoint
// failover — port of client.py SlaveControlClient.
class SlaveControlClient {
 public:
  SlaveControlClient(const std::string& endpoints, const std::string& cluster_secret = "",
                     const std::string& tenant_namespace = "", int timeout_ms = 3000);
  ~SlaveControlClient();

  bool ok() const { return ctx_ != nullptr && !endpoints_.empty(); }
  const std::vector<std::string>& endpoints() const { return endpoints_; }

  wire::Response RegisterWorker(const std::string& worker_id, const std::string& hostname,
                                const std::map<std::string, std::string>& capabilities);
  wire::Response Heartbeat(const std::string& worker_id, long long uptime_ms,
                           double cpu_pct = 0.0, double mem_pct = 0.0, double gpu_util_pct = 0.0);
  wire::Response ReportStats(const std::string& worker_id, const std::string& shard_id,
                             const std::string& stats_json, long long timestamp_ms);

 private:
  wire::Response CallWithFailover(const std::string& method,
                                  const samurai::core::json::Value& body);

  std::vector<std::string> endpoints_;
  std::string cluster_secret_;
  std::string tenant_namespace_;
  int timeout_ms_;
  std::size_t last_idx_ = 0;
  void* ctx_ = nullptr;  // shared zmq context (opaque)
};

// Master side: command a single worker/master endpoint directly — port of
// client.py WorkerControlClient.
class WorkerControlClient {
 public:
  WorkerControlClient(const std::string& endpoint, const std::string& cluster_secret = "",
                      const std::string& tenant_namespace = "", int timeout_ms = 5000);
  ~WorkerControlClient();

  bool ok() const { return ctx_ != nullptr && !endpoint_.empty(); }

  wire::Response StartShard(const std::string& shard_id, const std::string& job_id,
                            const std::string& args_json, long long packet_count,
                            long long timeout_ms);
  wire::Response StopShard(const std::string& shard_id, bool graceful = true);
  wire::Response GetWorkerStatus(const std::string& worker_id);
  wire::Response AbortJob(const std::string& job_id, const std::string& reason);
  wire::Response ForceSync(const std::string& worker_id);

 private:
  wire::Response Call(const std::string& method, const samurai::core::json::Value& body);

  std::string endpoint_;
  std::string cluster_secret_;
  std::string tenant_namespace_;
  int timeout_ms_;
  void* ctx_ = nullptr;
};

}  // namespace samurai::control
