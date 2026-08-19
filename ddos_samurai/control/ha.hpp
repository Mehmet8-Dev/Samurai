#pragma once

// HA leader election. This increment covers the two backends that need no
// external service:
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
#include "multimaster.hpp"  // KvStore

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

// Redis-backed lease elector with a fencing epoch — native C++ port of ha.py's
// RedisLeaseLeaderElector. The Redis protocol operations are expressed against
// the KvStore abstraction (SET NX PX / INCR / compare-and-PEXPIRE /
// compare-and-DEL / PTTL), so the election logic is native and testable with the
// in-memory store; a real hiredis-backed KvStore is deferred (as elsewhere).
class RedisLeaseLeaderElector : public LeaderElector {
 public:
  // `store` is non-owning and may be null (offline/inactive).
  RedisLeaseLeaderElector(const std::string& node_id, const std::string& lease_key,
                          KvStore* store, double lease_seconds = 15.0);
  ~RedisLeaseLeaderElector() override;

  bool TryAcquire() override;
  bool RenewOnce() override;
  bool IsLeader() const override { return leader_.load(); }
  std::int64_t LeaderEpoch() const override { return leader_epoch_.load(); }
  samurai::core::json::Value Snapshot() const override;
  void StartRenewLoop(double interval_s) override;
  void Stop() override;
  void Release();

 private:
  std::string EpochKey() const { return lease_key_ + ":epoch"; }

  std::string node_id_;
  std::string lease_key_;
  std::string owner_token_;
  double lease_seconds_;
  KvStore* store_;
  std::atomic<bool> leader_{false};
  std::atomic<std::int64_t> leader_epoch_{0};

  std::atomic<bool> stop_{false};
  std::thread renew_thread_;
  std::mutex cv_mu_;
  std::condition_variable cv_;
};

}  // namespace samurai::control
