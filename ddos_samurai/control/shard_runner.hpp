#pragma once

// Shard execution abstraction for the distributed slave. In the Python slave a
// shard runs orchestrator.start_worker_zmq on a thread; natively that maps to the
// ZMQ orchestrator/supervisor. WorkerShardService depends only on this
// interface, so the lifecycle state machine is testable without a real
// dataplane. A real supervisor-backed runner is wired when distributed mode
// lands in the CLI; InMemoryShardRunner backs tests/offline use.

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "json.hpp"

namespace samurai::control {

// A single in-flight shard execution. Counters are read live by the monitor.
class ShardRun {
 public:
  virtual ~ShardRun() = default;
  virtual bool IsAlive() = 0;
  virtual std::int64_t Progress() const = 0;
  virtual std::int64_t Sent() const = 0;
  virtual std::int64_t Errors() const = 0;
  virtual int ExitCode() const = 0;  // meaningful once !IsAlive(); -15 if terminated
  virtual void Terminate() = 0;
  virtual void Join() = 0;
};

class ShardRunner {
 public:
  virtual ~ShardRunner() = default;
  // Start a shard from its args (JSON object); nullptr on failure.
  virtual std::shared_ptr<ShardRun> Start(const std::string& shard_id,
                                          const samurai::core::json::Value& args) = 0;
};

// Test/offline runner: a shard "completes" immediately with preset counters,
// keyed by an optional per-shard override on the args ("_test_sent", etc.).
class InMemoryShardRun : public ShardRun {
 public:
  InMemoryShardRun(std::int64_t sent, std::int64_t errors, int exitcode)
      : sent_(sent), errors_(errors), exitcode_(exitcode) {}
  bool IsAlive() override { return alive_.load(); }
  std::int64_t Progress() const override { return sent_ + errors_; }
  std::int64_t Sent() const override { return sent_; }
  std::int64_t Errors() const override { return errors_; }
  int ExitCode() const override { return terminated_.load() ? -15 : exitcode_; }
  void Terminate() override {
    terminated_.store(true);
    alive_.store(false);
  }
  void Join() override { alive_.store(false); }

 private:
  std::atomic<bool> alive_{false};  // completes immediately
  std::atomic<bool> terminated_{false};
  std::int64_t sent_;
  std::int64_t errors_;
  int exitcode_;
};

class InMemoryShardRunner : public ShardRunner {
 public:
  std::shared_ptr<ShardRun> Start(const std::string& /*shard_id*/,
                                  const samurai::core::json::Value& args) override {
    auto get = [&args](const char* k, std::int64_t d) -> std::int64_t {
      const auto* v = args.find(k);
      return v ? v->as_int(d) : d;
    };
    const std::int64_t sent = get("_test_sent", get("count", 0));
    const std::int64_t errors = get("_test_errors", 0);
    const int exitcode = static_cast<int>(get("_test_exitcode", 0));
    return std::make_shared<InMemoryShardRun>(sent, errors, exitcode);
  }
};

}  // namespace samurai::control
