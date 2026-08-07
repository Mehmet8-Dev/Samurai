#pragma once

// Bridges the control-plane ShardRunner abstraction to the native ZMQ worker
// supervisor: a shard's args JSON becomes a JobOptions, and the shard runs on a
// background thread via orchestrator::RunJob (spawn worker -> drive job ->
// collect stats). Lives in the slave daemon, keeping the control library free of
// an orchestrator dependency.

#include <atomic>
#include <cstdint>
#include <memory>
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
                     samurai::orchestrator::JobOptions job);
  ~SupervisorShardRun() override;

  bool IsAlive() override { return !done_.load(); }
  std::int64_t Progress() const override { return static_cast<std::int64_t>(stats_.attempted); }
  std::int64_t Sent() const override { return static_cast<std::int64_t>(stats_.sent); }
  std::int64_t Errors() const override { return static_cast<std::int64_t>(stats_.errors); }
  int ExitCode() const override { return terminated_.load() ? -15 : exit_code_; }
  void Terminate() override { terminated_.store(true); }  // best-effort; RunJob isn't cancellable
  void Join() override;

 private:
  samurai::orchestrator::SupervisorConfig cfg_;
  samurai::orchestrator::JobOptions job_;
  samurai::orchestrator::RunStats stats_{};
  int exit_code_ = 0;
  std::atomic<bool> done_{false};
  std::atomic<bool> terminated_{false};
  std::thread thread_;
};

class SupervisorShardRunner : public samurai::control::ShardRunner {
 public:
  SupervisorShardRunner(samurai::orchestrator::WorkerEntry worker, std::string worker_dir)
      : worker_(worker), worker_dir_(std::move(worker_dir)) {}

  std::shared_ptr<samurai::control::ShardRun> Start(
      const std::string& shard_id, const samurai::core::json::Value& args) override;

 private:
  samurai::orchestrator::WorkerEntry worker_;
  std::string worker_dir_;
};

}  // namespace samurai::control::daemon
