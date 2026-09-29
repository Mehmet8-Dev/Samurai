#include "redis_kvstore.hpp"

#include <cstdlib>
#include <functional>
#include <string>

#ifdef SAMURAI_CONTROL_HAVE_HIREDIS
#include <hiredis/hiredis.h>
#endif

namespace samurai::control {

// --- redis:// URL parsing --------------------------------------------------

RedisUrl ParseRedisUrl(const std::string& url) {
  RedisUrl out;
  std::string s = url;
  const std::string scheme = "redis://";
  if (s.rfind(scheme, 0) == 0) {
    s = s.substr(scheme.size());
  } else if (s.rfind("rediss://", 0) == 0) {
    out.error = "rediss:// (TLS) not supported";
    return out;
  }
  // Optional [user][:password]@ credentials — accepted and skipped.
  const auto at = s.find('@');
  if (at != std::string::npos) s = s.substr(at + 1);
  // host[:port][/db]
  std::string db_part;
  const auto slash = s.find('/');
  if (slash != std::string::npos) {
    db_part = s.substr(slash + 1);
    s = s.substr(0, slash);
  }
  std::string host = s;
  std::string port_part;
  if (!s.empty() && s.front() == '[') {  // [ipv6]:port
    const auto rb = s.find(']');
    if (rb == std::string::npos) {
      out.error = "malformed ipv6 host";
      return out;
    }
    host = s.substr(1, rb - 1);
    if (rb + 1 < s.size() && s[rb + 1] == ':') port_part = s.substr(rb + 2);
  } else {
    const auto colon = s.rfind(':');
    if (colon != std::string::npos) {
      host = s.substr(0, colon);
      port_part = s.substr(colon + 1);
    }
  }
  if (host.empty()) host = "127.0.0.1";
  out.host = host;
  try {
    if (!port_part.empty()) out.port = std::stoi(port_part);
    if (!db_part.empty()) out.db = std::stoi(db_part);
  } catch (...) {
    out.error = "malformed port/db in redis url";
    return out;
  }
  if (out.port <= 0 || out.port > 65535) {
    out.error = "port out of range";
    return out;
  }
  out.ok = true;
  return out;
}

#ifdef SAMURAI_CONTROL_HAVE_HIREDIS

namespace {

// EVAL scripts for atomic compare-and-X (no MULTI/WATCH round trips).
constexpr const char* kCasPExpire =
    "if redis.call('GET', KEYS[1]) == ARGV[1] then "
    "return redis.call('PEXPIRE', KEYS[1], ARGV[2]) else return 0 end";
constexpr const char* kCasDel =
    "if redis.call('GET', KEYS[1]) == ARGV[1] then "
    "return redis.call('DEL', KEYS[1]) else return 0 end";

}  // namespace

HiredisKvStore::HiredisKvStore(std::string host, int port, int db, int connect_timeout_ms)
    : host_(std::move(host)), port_(port), db_(db), connect_timeout_ms_(connect_timeout_ms) {
  std::lock_guard<std::mutex> lk(mu_);
  EnsureConnected();
}

HiredisKvStore::~HiredisKvStore() {
  std::lock_guard<std::mutex> lk(mu_);
  Disconnect();
}

void HiredisKvStore::Disconnect() {
  if (ctx_) {
    redisFree(ctx_);
    ctx_ = nullptr;
  }
}

bool HiredisKvStore::EnsureConnected() {
  if (ctx_ && ctx_->err == 0) return true;
  Disconnect();
  struct timeval tv;
  tv.tv_sec = connect_timeout_ms_ / 1000;
  tv.tv_usec = (connect_timeout_ms_ % 1000) * 1000;
  redisContext* c = redisConnectWithTimeout(host_.c_str(), port_, tv);
  if (!c || c->err) {
    error_ = c ? std::string("redis connect: ") + c->errstr : "redis connect: alloc failed";
    if (c) redisFree(c);
    ctx_ = nullptr;
    return false;
  }
  redisSetTimeout(c, tv);
  ctx_ = c;
  // Select the target logical DB; ignore reply object (best effort).
  if (db_ != 0) {
    redisReply* r = static_cast<redisReply*>(redisCommand(ctx_, "SELECT %d", db_));
    if (r) freeReplyObject(r);
  }
  error_.clear();
  return true;
}

namespace {

// Run one command as an argv vector (fully binary-safe). Returns the reply (the
// caller frees it) or nullptr on transport failure. Reconnects once on a
// connection-level error. `store` mutex is held by the caller.
redisReply* RunArgv(redisContext*& ctx, std::string& error,
                    const std::function<bool()>& reconnect,
                    const std::vector<std::string>& args) {
  if (!ctx && !reconnect()) return nullptr;
  std::vector<const char*> argv(args.size());
  std::vector<size_t> lens(args.size());
  for (size_t i = 0; i < args.size(); ++i) {
    argv[i] = args[i].data();
    lens[i] = args[i].size();
  }
  redisReply* r = static_cast<redisReply*>(
      redisCommandArgv(ctx, static_cast<int>(args.size()), argv.data(), lens.data()));
  if (!r) {  // connection dropped — reconnect once and retry
    error = ctx ? ctx->errstr : "null context";
    if (!reconnect()) return nullptr;
    r = static_cast<redisReply*>(
        redisCommandArgv(ctx, static_cast<int>(args.size()), argv.data(), lens.data()));
  }
  return r;
}

}  // namespace

void HiredisKvStore::SetEx(const std::string& key, const std::string& value, int ttl_s) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  redisReply* r = RunArgv(ctx_, error_, reconnect,
                          {"SETEX", key, std::to_string(ttl_s > 0 ? ttl_s : 1), value});
  if (r) freeReplyObject(r);
}

void HiredisKvStore::SetWithTtl(const std::string& key, const std::string& value, int ttl_s) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  redisReply* r;
  if (ttl_s > 0) {
    r = RunArgv(ctx_, error_, reconnect, {"SET", key, value, "EX", std::to_string(ttl_s)});
  } else {
    r = RunArgv(ctx_, error_, reconnect, {"SET", key, value});
  }
  if (r) freeReplyObject(r);
}

void HiredisKvStore::LPush(const std::string& key, const std::string& value) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  redisReply* r = RunArgv(ctx_, error_, reconnect, {"LPUSH", key, value});
  if (r) freeReplyObject(r);
}

void HiredisKvStore::RPush(const std::string& key, const std::string& value) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  redisReply* r = RunArgv(ctx_, error_, reconnect, {"RPUSH", key, value});
  if (r) freeReplyObject(r);
}

void HiredisKvStore::LTrim(const std::string& key, long long start, long long stop) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  redisReply* r = RunArgv(ctx_, error_, reconnect,
                          {"LTRIM", key, std::to_string(start), std::to_string(stop)});
  if (r) freeReplyObject(r);
}

bool HiredisKvStore::LPop(const std::string& key, std::string& out) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  redisReply* r = RunArgv(ctx_, error_, reconnect, {"LPOP", key});
  bool ok = false;
  if (r) {
    if (r->type == REDIS_REPLY_STRING) {
      out.assign(r->str, r->len);
      ok = true;
    }
    freeReplyObject(r);
  }
  return ok;
}

bool HiredisKvStore::Get(const std::string& key, std::string& out) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  redisReply* r = RunArgv(ctx_, error_, reconnect, {"GET", key});
  bool ok = false;
  if (r) {
    if (r->type == REDIS_REPLY_STRING) {
      out.assign(r->str, r->len);
      ok = true;
    }
    freeReplyObject(r);
  }
  return ok;
}

std::vector<std::string> HiredisKvStore::ScanMatch(const std::string& pattern, int count) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  std::vector<std::string> out;
  std::string cursor = "0";
  const std::string count_s = std::to_string(count > 0 ? count : 100);
  do {
    redisReply* r = RunArgv(ctx_, error_, reconnect,
                            {"SCAN", cursor, "MATCH", pattern, "COUNT", count_s});
    if (!r) break;
    // SCAN reply: [cursor, [keys...]]
    if (r->type == REDIS_REPLY_ARRAY && r->elements == 2) {
      redisReply* cur = r->element[0];
      redisReply* keys = r->element[1];
      cursor = (cur && cur->type == REDIS_REPLY_STRING) ? std::string(cur->str, cur->len) : "0";
      if (keys && keys->type == REDIS_REPLY_ARRAY) {
        for (size_t i = 0; i < keys->elements; ++i) {
          redisReply* k = keys->element[i];
          if (k && k->type == REDIS_REPLY_STRING) out.emplace_back(k->str, k->len);
        }
      }
    } else {
      cursor = "0";
    }
    freeReplyObject(r);
  } while (cursor != "0");
  return out;
}

bool HiredisKvStore::SetNx(const std::string& key, const std::string& value, long long ttl_ms) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  redisReply* r = RunArgv(ctx_, error_, reconnect,
                          {"SET", key, value, "NX", "PX", std::to_string(ttl_ms > 0 ? ttl_ms : 1)});
  bool ok = false;
  if (r) {
    // "OK" status on set, nil when the key already exists (NX fails).
    ok = (r->type == REDIS_REPLY_STATUS);
    freeReplyObject(r);
  }
  return ok;
}

std::int64_t HiredisKvStore::Incr(const std::string& key) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  redisReply* r = RunArgv(ctx_, error_, reconnect, {"INCR", key});
  std::int64_t v = 0;
  if (r) {
    if (r->type == REDIS_REPLY_INTEGER) v = r->integer;
    freeReplyObject(r);
  }
  return v;
}

bool HiredisKvStore::CompareAndPExpire(const std::string& key, const std::string& expected,
                                       long long ttl_ms) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  redisReply* r = RunArgv(ctx_, error_, reconnect,
                          {"EVAL", kCasPExpire, "1", key, expected,
                           std::to_string(ttl_ms > 0 ? ttl_ms : 1)});
  bool ok = false;
  if (r) {
    ok = (r->type == REDIS_REPLY_INTEGER && r->integer == 1);
    freeReplyObject(r);
  }
  return ok;
}

bool HiredisKvStore::CompareAndDel(const std::string& key, const std::string& expected) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  redisReply* r = RunArgv(ctx_, error_, reconnect, {"EVAL", kCasDel, "1", key, expected});
  bool ok = false;
  if (r) {
    ok = (r->type == REDIS_REPLY_INTEGER && r->integer == 1);
    freeReplyObject(r);
  }
  return ok;
}

long long HiredisKvStore::Pttl(const std::string& key) {
  std::lock_guard<std::mutex> lk(mu_);
  auto reconnect = [this]() { return EnsureConnected(); };
  redisReply* r = RunArgv(ctx_, error_, reconnect, {"PTTL", key});
  long long v = -1;
  if (r) {
    if (r->type == REDIS_REPLY_INTEGER) v = r->integer;
    freeReplyObject(r);
  }
  return v;
}

#endif  // SAMURAI_CONTROL_HAVE_HIREDIS

std::unique_ptr<KvStore> MakeKvStore(const std::string& redis_url, std::string& err) {
  const RedisUrl u = ParseRedisUrl(redis_url);
  if (!u.ok) {
    err = u.error.empty() ? "invalid redis url" : u.error;
    return nullptr;
  }
#ifdef SAMURAI_CONTROL_HAVE_HIREDIS
  auto store = std::make_unique<HiredisKvStore>(u.host, u.port, u.db);
  if (!store->connected()) {
    err = store->error();
    return nullptr;
  }
  return store;
#else
  (void)u;
  err = "hiredis not compiled in (SAMURAI_CONTROL_HAVE_HIREDIS undefined)";
  return nullptr;
#endif
}

}  // namespace samurai::control
