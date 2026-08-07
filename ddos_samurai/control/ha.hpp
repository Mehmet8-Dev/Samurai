#pragma once

// HA leader election — native C++ port of ha.py. This increment covers the two
// backends that need no external service:
//   * StaticLeaderElector    — deterministic lexical-min node id (bootstrap HA)
//   * FileLeaseLeaderElector — file-backed lease with flock + atomic rename,
//                              renew loop, and release
//
// The Redis/etcd lease electors (external services) and the native Raft elector
// (a full consensus implementation, ~600 lines) are deferred to later
// increments, consistent with how the Redis-backed multimaster was handled.

#include <atomic>
#include <cstdint>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "json.hpp"

namespace samurai::control {

class LeaderElector {
 public:
  virtual ~LeaderElector() = default;
  virtual bool TryAcquire() = 0;
  virtual bool RenewOnce() = 0;
  virtual bool IsLeader() const = 0;
  virtual std::int64_t LeaderEpoch() const { return 0; }
  virtual samurai::core::json::Value Snapshot() const = 0;
  virtual void StartRenewLoop(double /*interval_s*/) {}
  virtual void Stop() {}
};

// Lexical-min node id among {self} ∪ peers. Bootstrap HA, not consensus.
class StaticLeaderElector : public LeaderElector {
 public:
  StaticLeaderElector(const std::string& node_id, const std::string& peers_csv = "");
  bool TryAcquire() override { return IsLeader(); }
  bool RenewOnce() override { return IsLeader(); }
  bool IsLeader() const override { return node_id_ == leader_id_; }
  samurai::core::json::Value Snapshot() const override;

 private:
  std::string node_id_;
  std::vector<std::string> peers_;
  std::vector<std::string> candidates_;
  std::string leader_id_;
};

// File-backed lease: {"owner":<node>,"expires_at":<epoch_s>} guarded by flock on
// "<lease_path>.lock", written atomically via temp + rename.
class FileLeaseLeaderElector : public LeaderElector {
 public:
  FileLeaseLeaderElector(const std::string& node_id, const std::string& lease_path,
                         double lease_seconds = 15.0);
  ~FileLeaseLeaderElector() override;

  bool TryAcquire() override;
  bool RenewOnce() override;
  bool IsLeader() const override { return leader_.load(); }
  samurai::core::json::Value Snapshot() const override;
  void StartRenewLoop(double interval_s) override;
  void Stop() override;
  void Release();

 private:
  bool ReadLease(std::string& owner, double& expires_at) const;
  bool WriteLease(const std::string& owner, double expires_at) const;

  std::string node_id_;
  std::string lease_path_;
  double lease_seconds_;
  std::atomic<bool> leader_{false};

  std::atomic<bool> stop_{false};
  std::thread renew_thread_;
  std::mutex cv_mu_;
  std::condition_variable cv_;
};

}  // namespace samurai::control
