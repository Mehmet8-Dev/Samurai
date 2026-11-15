#pragma once

// Bridges the control-plane ShardRunner abstraction to the native ZMQ worker
// supervisor: a shard's args JSON becomes a JobOptions, and the shard runs on a
// background thread via orchestrator::RunJob (spawn worker -> drive job ->
// collect stats). Lives in the slave daemon, keeping the control library free of
// an orchestrator dependency.

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include "job_builder.hpp"       // orchestrator::JobOptions
#include "run_summary.hpp"       // orchestrator::RunStats
#include "shard_runner.hpp"      // control::ShardRunner / ShardRun
#include "supervisor.hpp"        // orchestrator::RunJob / SupervisorConfig
#include "worker_registry.hpp"   // orchestrator::WorkerEntry

namespace samurai::control::daemon {

class SupervisorShardRun : public samurai::control::ShardRun {
 public:
  SupervisorShardRun(samurai::orchestrator::SupervisorConfig cfg,
                     samurai::orchestrator::JobOptions job,
                     std::shared_ptr<samurai::orchestrator::WarmWorkerPool> pool = nullptr,
                     std::string shard_id = "");
  ~SupervisorShardRun() override;

  bool IsAlive() override { return !done_.load(); }
  std::int64_t Progress() const override { return static_cast<std::int64_t>(stats_.attempted); }
  std::int64_t Sent() const override { return static_cast<std::int64_t>(stats_.sent); }
  std::int64_t Errors() const override { return static_cast<std::int64_t>(stats_.errors); }
  int ExitCode() const override { return terminated_.load() ? -15 : exit_code_; }
  void Terminate() override { terminated_.store(true); }
  void Join() override;

  // Sends a live RECONFIGURE_JOB window frame through the warm pool while this
  // shard is active.
  bool Reconfigure(const samurai::wire::ReconfigureWindowV1& window);
  bool Reconfigure(const samurai::core::json::Value& params) override;

  // L7 defense-reaction, IPFIX export, and Telco signals emitted as top-level
  // numeric fields so MasterCoordinator's aggregator folds them across shards.
  samurai::core::json::Value MetricsJson() const override;

 private:
  samurai::orchestrator::SupervisorConfig cfg_;
  samurai::orchestrator::JobOptions job_;
  std::shared_ptr<samurai::orchestrator::WarmWorkerPool> pool_;
  std::string shard_id_;
  samurai::orchestrator::RunStats stats_{};
  int exit_code_ = 0;
  std::atomic<bool> done_{false};
  std::atomic<bool> terminated_{false};
  std::thread thread_;
};

class SupervisorShardRunner : public samurai::control::ShardRunner {
 public:
  // Fixed-flavor: every shard runs `worker`.
  SupervisorShardRunner(samurai::orchestrator::WorkerEntry worker, std::string worker_dir)
      : fixed_(worker),
        worker_dir_(std::move(worker_dir)),
        pool_(std::make_shared<samurai::orchestrator::WarmWorkerPool>()) {}

  // Bundle: resolve the worker binary per shard from the job's `worker` field
  // (falls back to `fallback` when the field is missing or unknown). The node is
  // expected to hold every worker binary in `worker_dir`.
  SupervisorShardRunner(std::string worker_dir, samurai::orchestrator::WorkerEntry fallback)
      : fallback_(fallback),
        worker_dir_(std::move(worker_dir)),
        bundle_(true),
        pool_(std::make_shared<samurai::orchestrator::WarmWorkerPool>()) {}

  std::shared_ptr<samurai::control::ShardRun> Start(
      const std::string& shard_id, const samurai::core::json::Value& args) override;

  bool ReconfigureShard(const std::string& shard_id,
                        const samurai::wire::ReconfigureWindowV1& window);
  bool ReconfigureShard(const std::string& shard_id,
                        const samurai::core::json::Value& params) override;

  std::shared_ptr<samurai::orchestrator::WarmWorkerPool> warm_pool() const { return pool_; }

 private:
  // Which worker binary to spawn for this shard's args (bundle: from args).
  samurai::orchestrator::WorkerEntry ResolveWorker(const samurai::core::json::Value& args) const;

  samurai::orchestrator::WorkerEntry fixed_{};     // used when !bundle_
  samurai::orchestrator::WorkerEntry fallback_{};  // used in bundle_ when unresolved
  std::string worker_dir_;
  bool bundle_ = false;
  std::shared_ptr<samurai::orchestrator::WarmWorkerPool> pool_;
};

}  // namespace samurai::control::daemon
