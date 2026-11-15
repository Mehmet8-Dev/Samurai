#pragma once

// Real Redis-backed KvStore (hiredis). Implements the KvStore abstraction from
// multimaster.hpp so RedisMultiMasterCoordinator and RedisLeaseLeaderElector run
// against a live Redis, giving cross-process / cross-region coordination instead
// of the single-process InMemoryKvStore.
//
// Built only when hiredis is available (SAMURAI_CONTROL_HAVE_HIREDIS). The
// MakeKvStore factory is always declared; when hiredis is absent it returns
// nullptr (the coordinator then reports itself inactive, and the master keeps
// running as a single region).

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "multimaster.hpp"  // KvStore

struct redisContext;  // fwd (hiredis)

namespace samurai::control {

#ifdef SAMURAI_CONTROL_HAVE_HIREDIS

// Thread-safe (coarse mutex) hiredis-backed KvStore. Reconnects lazily on a
// dropped connection; on any transport failure the operation degrades to a
// no-op / miss so the coordinator behaves as if offline rather than crashing.
class HiredisKvStore : public KvStore {
 public:
  HiredisKvStore(std::string host, int port, int db, int connect_timeout_ms = 2000);
  ~HiredisKvStore() override;

  bool connected() const { return ctx_ != nullptr; }
  const std::string& error() const { return error_; }

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
  bool CompareAndPExpire(const std::string& key, const std::string& expected,
                         long long ttl_ms) override;
  bool CompareAndDel(const std::string& key, const std::string& expected) override;
  long long Pttl(const std::string& key) override;

 private:
  bool EnsureConnected();  // caller holds mu_
  void Disconnect();       // caller holds mu_

  std::string host_;
  int port_;
  int db_;
  int connect_timeout_ms_;
  std::string error_;

  std::mutex mu_;
  redisContext* ctx_ = nullptr;  // guarded by mu_
};

#endif  // SAMURAI_CONTROL_HAVE_HIREDIS

// Parsed redis://[:password@]host:port/db URL. password is accepted but the
// coordinator paths used here assume an unauthenticated/ACL-less Redis; AUTH can
// be layered later if needed.
struct RedisUrl {
  bool ok = false;
  std::string host = "127.0.0.1";
  int port = 6379;
  int db = 0;
  std::string error;
};
RedisUrl ParseRedisUrl(const std::string& url);

// Build a live KvStore for `redis_url`. Returns an owning pointer on success, or
// nullptr with `err` set when hiredis is unavailable or the connection fails.
std::unique_ptr<KvStore> MakeKvStore(const std::string& redis_url, std::string& err);

}  // namespace samurai::control
