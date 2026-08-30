#pragma once

// Cross-region multi-master coordination (RedisMultiMasterCoordinator).
//
// The coordination logic (key scheme, JSON envelopes, heartbeat/snapshot/event
// publication, cross-region job enqueue/dequeue, region scans) is native and
// testable. The Redis transport is abstracted behind KvStore; an in-memory
// backend is provided here for tests/offline use, and a real hiredis-backed
// KvStore is provided by redis_kvstore.{hpp,cpp} (optional, gated on
// SAMURAI_CONTROL_HAVE_HIREDIS; absent hiredis falls back to a single region).

#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "json.hpp"  // samurai::core::json::Value

namespace samurai::control {

// Redis-like key/value + list operations used by the coordinator. A real
// backend maps these onto SETEX / SET EX / LPUSH / RPUSH / LTRIM / LPOP / GET /
// SCAN. TTLs are advisory (honoured by a real backend; ignored in-memory).
class KvStore {
 public:
  virtual ~KvStore() = default;
  virtual void SetEx(const std::string& key, const std::string& value, int ttl_s) = 0;
  virtual void SetWithTtl(const std::string& key, const std::string& value, int ttl_s) = 0;
  virtual void LPush(const std::string& key, const std::string& value) = 0;  // prepend (head)
  virtual void RPush(const std::string& key, const std::string& value) = 0;  // append (tail)
  virtual void LTrim(const std::string& key, long long start, long long stop) = 0;
  virtual bool LPop(const std::string& key, std::string& out) = 0;  // pop head; false if empty
  virtual bool Get(const std::string& key, std::string& out) = 0;   // false if missing
  virtual std::vector<std::string> ScanMatch(const std::string& pattern, int count) = 0;

  // Lease/atomic ops used by the Redis lease leader elector (SET NX PX / INCR /
  // compare-and-PEXPIRE / compare-and-DEL / PTTL). Defaulted so existing
  // KvStore implementations need not change.
  virtual bool SetNx(const std::string& key, const std::string& value, long long ttl_ms) {
    (void)key; (void)value; (void)ttl_ms; return false;
  }
  virtual std::int64_t Incr(const std::string& key) { (void)key; return 0; }
  virtual bool CompareAndPExpire(const std::string& key, const std::string& expected, long long ttl_ms) {
    (void)key; (void)expected; (void)ttl_ms; return false;
  }
  virtual bool CompareAndDel(const std::string& key, const std::string& expected) {
    (void)key; (void)expected; return false;
  }
  virtual long long Pttl(const std::string& key) { (void)key; return -1; }
};

// Non-persistent, single-process KvStore for tests and offline operation.
class InMemoryKvStore : public KvStore {
 public:
  void SetEx(const std::string& key, const std::string& value, int ttl_s) override;
  void SetWithTtl(const std::string& key, const std::string& value, int ttl_s) override;
  void LPush(const std::string& key, const std::string& value) override;
  void RPush(const std::string& key, const std::string& value) override;
  void LTrim(const std::string& key, long long start, long long stop) override;
  bool LPop(const std::string& key, std::string& out) override;
  bool Get(const std::string& key, std::string& out) override;
  std::vector<std::string> ScanMatch(const std::string& pattern, int count) override;
  bool SetNx(const std::string& key, const std::string& value, long long ttl_ms) override;
  std::int64_t Incr(const std::string& key) override;
  bool CompareAndPExpire(const std::string& key, const std::string& expected, long long ttl_ms) override;
  bool CompareAndDel(const std::string& key, const std::string& expected) override;
  long long Pttl(const std::string& key) override;

 private:
  std::unordered_map<std::string, std::string> strings_;
  std::unordered_map<std::string, std::deque<std::string>> lists_;
  std::unordered_map<std::string, long long> ttls_;  // advisory, not expired in-memory
};

struct MultiMasterConfig {
  bool enabled = false;
  std::string namespace_ = "default";
  std::string region_id;
  std::string node_id = "master";
  int heartbeat_ttl_s = 15;
};

class RedisMultiMasterCoordinator {
 public:
  // `store` is non-owning and may be null (mirrors Python's `_redis is None`
  // offline mode). now_ms_fn is injectable for tests; defaults to wall clock ms.
  RedisMultiMasterCoordinator(const MultiMasterConfig& cfg, KvStore* store,
                              std::function<std::int64_t()> now_ms_fn = {});

  bool Heartbeat(const samurai::core::json::Value& payload = samurai::core::json::Value::Object());
  bool PublishSnapshot(const samurai::core::json::Value& snapshot);
  bool PublishEvent(const samurai::core::json::Value& event);
  bool EnqueueJob(const std::string& region_id, const samurai::core::json::Value& job);
  // Pops up to max_count delegated jobs for this region; each carries
  // "_mmr_delegated_from".
  std::vector<samurai::core::json::Value> DequeueJobs(int max_count = 3);
  std::vector<samurai::core::json::Value> RegionsState();
  std::vector<samurai::core::json::Value> LatestRegionSnapshots();
  samurai::core::json::Value Snapshot() const;

  bool active() const { return active_; }

 private:
  std::string KRegionHb(const std::string& region_id, const std::string& node_id) const;
  std::string KRegionLatest(const std::string& region_id) const;
  std::string KEvents() const;
  std::string KRegionJobs(const std::string& region_id) const;

  bool enabled_;
  std::string namespace_;
  std::string region_id_;
  std::string node_id_;
  int heartbeat_ttl_s_;
  std::string error_;

  KvStore* store_;
  bool active_;  // enabled_ && store_ != nullptr
  std::function<std::int64_t()> now_ms_fn_;
};

}  // namespace samurai::control
