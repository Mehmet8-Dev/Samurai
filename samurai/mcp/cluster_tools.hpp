#pragma once

// Native C++17 Distributed Cluster Orchestration, Service/Node Discovery,
// Provisioning, Multi-Worker Sharding & Scaling Subsystem for Samurai MCP.
//
// Speaks directly to samurai_master's real POSIX HTTP Management API (:8089):
//   GET  /healthz, /v1/cluster/{summary,workers,shards,events}, /metrics
//   POST /v1/cluster/provision    (add remote worker nodes via SSH/zero-install)
//   POST /v1/shards/reconfigure   (coordinate live worker shards mid-flight)
//   POST /v1/jobs/abort           (emergency cluster-wide abort)
//
// Plus in-process C++17 cluster planning (`SplitJobToShards`,
// `SplitTelcoSubscribers`, `AutoscaleController`) and a loopback-only local
// multi-worker mesh lifecycle manager (`samurai_master` + N `samurai_slave`
// nodes) so an AI agent can discover, add nodes, scale, and coordinate
// multiple workers end-to-end.

#include <sys/types.h>

#include <mutex>
#include <string>
#include <vector>

#include "json.hpp"
#include "protocol.hpp"
#include "safety.hpp"

namespace samurai::mcp {

class ClusterManager {
 public:
  ClusterManager() = default;
  ~ClusterManager();

  ClusterManager(const ClusterManager&) = delete;
  ClusterManager& operator=(const ClusterManager&) = delete;

  // Live service/node/worker/shard discovery against samurai_master (:8089).
  ToolResult HandleDiscover(const samurai::core::json::Value& args, const SafetyConfig& safety) const;

  // Add new worker node(s) to the cluster via POST /v1/cluster/provision.
  ToolResult HandleProvisionNode(const samurai::core::json::Value& args, const SafetyConfig& safety) const;

  // Reconfigure active distributed worker shards in real time via POST /v1/shards/reconfigure.
  ToolResult HandleReconfigure(const samurai::core::json::Value& args, const SafetyConfig& safety) const;

  // Abort active distributed jobs across all workers via POST /v1/jobs/abort.
  ToolResult HandleAbort(const samurai::core::json::Value& args, const SafetyConfig& safety) const;

  // In-process multi-worker sharding (equal/capability/region/telco CGNAT-BNG)
  // and AutoscaleController replica scaling planner.
  ToolResult HandlePlanShards(const samurai::core::json::Value& args) const;

  // Manage a local loopback-only (127.0.0.1) distributed lab mesh:
  //   action = "start" | "scale" | "status" | "stop"
  ToolResult HandleLocalMesh(const samurai::core::json::Value& args);

 private:
  struct LocalSlave {
    std::string worker_id;
    std::string worker_kind;
    std::string region;
    pid_t pid = -1;
  };

  void StopLocalMeshLocked();
  void ReapExitedLocked();
  pid_t SpawnLocalSlaveLocked(const std::string& slave_bin,
                              const std::string& worker_id,
                              const std::string& worker_kind,
                              const std::string& region);
  samurai::core::json::Value LocalMeshSummaryLocked() const;

  mutable std::mutex mu_;
  pid_t master_pid_ = -1;
  int control_port_ = 5099;
  int mgmt_port_ = 8089;
  std::string cluster_secret_;
  std::string admin_token_;
  int next_slave_seq_ = 1;
  std::vector<LocalSlave> slaves_;
};

}  // namespace samurai::mcp
