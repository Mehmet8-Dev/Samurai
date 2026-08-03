#include "multimaster.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <string>
#include <vector>

namespace samurai::control {

namespace {

using samurai::core::json::Value;

std::string Strip(const std::string& s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

std::string Lower(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return s;
}

std::string StripOr(const std::string& s, const std::string& fallback) {
  const std::string t = Strip(s);
  return t.empty() ? fallback : t;
}

std::int64_t WallMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// Glob match supporting '*' and '?' (the patterns the coordinator uses).
bool GlobMatch(const std::string& pat, const std::string& str) {
  std::size_t p = 0, s = 0, star = std::string::npos, mark = 0;
  while (s < str.size()) {
    if (p < pat.size() && (pat[p] == '?' || pat[p] == str[s])) {
      ++p;
      ++s;
    } else if (p < pat.size() && pat[p] == '*') {
      star = p++;
      mark = s;
    } else if (star != std::string::npos) {
      p = star + 1;
      s = ++mark;
    } else {
      return false;
    }
  }
  while (p < pat.size() && pat[p] == '*') ++p;
  return p == pat.size();
}

}  // namespace

// --- InMemoryKvStore -------------------------------------------------------

void InMemoryKvStore::SetEx(const std::string& key, const std::string& value, int) {
  strings_[key] = value;
}
void InMemoryKvStore::SetWithTtl(const std::string& key, const std::string& value, int) {
  strings_[key] = value;
}
void InMemoryKvStore::LPush(const std::string& key, const std::string& value) {
  lists_[key].push_front(value);
}
void InMemoryKvStore::RPush(const std::string& key, const std::string& value) {
  lists_[key].push_back(value);
}
void InMemoryKvStore::LTrim(const std::string& key, long long start, long long stop) {
  auto it = lists_.find(key);
  if (it == lists_.end()) return;
  std::deque<std::string>& lst = it->second;
  const long long n = static_cast<long long>(lst.size());
  if (n == 0) return;
  if (start < 0) start += n;
  if (stop < 0) stop += n;
  if (start < 0) start = 0;
  if (stop >= n) stop = n - 1;
  if (start > stop) {
    lst.clear();
    lists_.erase(it);
    return;
  }
  std::deque<std::string> trimmed(lst.begin() + start, lst.begin() + stop + 1);
  lst.swap(trimmed);
}
bool InMemoryKvStore::LPop(const std::string& key, std::string& out) {
  auto it = lists_.find(key);
  if (it == lists_.end() || it->second.empty()) return false;
  out = it->second.front();
  it->second.pop_front();
  if (it->second.empty()) lists_.erase(it);
  return true;
}
bool InMemoryKvStore::Get(const std::string& key, std::string& out) {
  auto it = strings_.find(key);
  if (it == strings_.end()) return false;
  out = it->second;
  return true;
}
std::vector<std::string> InMemoryKvStore::ScanMatch(const std::string& pattern, int) {
  std::vector<std::string> out;
  for (const auto& kv : strings_) {
    if (GlobMatch(pattern, kv.first)) out.push_back(kv.first);
  }
  for (const auto& kv : lists_) {
    if (GlobMatch(pattern, kv.first)) out.push_back(kv.first);
  }
  return out;
}

// --- RedisMultiMasterCoordinator ------------------------------------------

RedisMultiMasterCoordinator::RedisMultiMasterCoordinator(const MultiMasterConfig& cfg,
                                                         KvStore* store,
                                                         std::function<std::int64_t()> now_ms_fn)
    : enabled_(cfg.enabled),
      namespace_(StripOr(cfg.namespace_, "default")),
      region_id_(Lower(Strip(cfg.region_id))),
      node_id_(StripOr(cfg.node_id, "master")),
      heartbeat_ttl_s_(std::max(5, cfg.heartbeat_ttl_s)),
      store_(store),
      active_(cfg.enabled && store != nullptr),
      now_ms_fn_(now_ms_fn ? std::move(now_ms_fn) : std::function<std::int64_t()>(WallMs)) {
  if (enabled_ && store_ == nullptr) {
    error_ = "redis backend unavailable";
  }
}

std::string RedisMultiMasterCoordinator::KRegionHb(const std::string& region_id,
                                                   const std::string& node_id) const {
  return "samurai:mm:" + namespace_ + ":region:" + region_id + ":node:" + node_id + ":hb";
}
std::string RedisMultiMasterCoordinator::KRegionLatest(const std::string& region_id) const {
  return "samurai:mm:" + namespace_ + ":region:" + region_id + ":latest";
}
std::string RedisMultiMasterCoordinator::KEvents() const {
  return "samurai:mm:" + namespace_ + ":events";
}
std::string RedisMultiMasterCoordinator::KRegionJobs(const std::string& region_id) const {
  return "samurai:mm:" + namespace_ + ":jobs:" + region_id;
}

bool RedisMultiMasterCoordinator::Heartbeat(const Value& payload) {
  if (!active_ || region_id_.empty()) return false;
  Value item = Value::Object();
  item.set("ts_ms", Value::Int(now_ms_fn_()));
  item.set("region_id", Value::Str(region_id_));
  item.set("node_id", Value::Str(node_id_));
  if (payload.is_object()) {
    for (const auto& kv : payload.members()) item.set(kv.first, kv.second);
  }
  store_->SetEx(KRegionHb(region_id_, node_id_), item.dump(), heartbeat_ttl_s_);
  return true;
}

bool RedisMultiMasterCoordinator::PublishSnapshot(const Value& snapshot) {
  if (!active_ || region_id_.empty()) return false;
  Value item = Value::Object();
  item.set("ts_ms", Value::Int(now_ms_fn_()));
  item.set("region_id", Value::Str(region_id_));
  item.set("node_id", Value::Str(node_id_));
  item.set("snapshot", snapshot.is_object() ? snapshot : Value::Object());
  store_->SetWithTtl(KRegionLatest(region_id_), item.dump(),
                     std::max(10, heartbeat_ttl_s_ * 3));
  return true;
}

bool RedisMultiMasterCoordinator::PublishEvent(const Value& event) {
  if (!active_) return false;
  Value item = Value::Object();
  item.set("ts_ms", Value::Int(now_ms_fn_()));
  item.set("region_id", Value::Str(region_id_));
  item.set("node_id", Value::Str(node_id_));
  item.set("event", event.is_object() ? event : Value::Object());
  store_->LPush(KEvents(), item.dump());
  store_->LTrim(KEvents(), 0, 999);
  return true;
}

bool RedisMultiMasterCoordinator::EnqueueJob(const std::string& region_id, const Value& job) {
  if (!active_) return false;
  const std::string rid = Lower(Strip(region_id));
  if (rid.empty()) return false;
  Value item = Value::Object();
  item.set("ts_ms", Value::Int(now_ms_fn_()));
  item.set("from_region", Value::Str(region_id_));
  item.set("to_region", Value::Str(rid));
  item.set("job", job.is_object() ? job : Value::Object());
  store_->RPush(KRegionJobs(rid), item.dump());
  store_->LTrim(KRegionJobs(rid), -5000, -1);
  return true;
}

std::vector<Value> RedisMultiMasterCoordinator::DequeueJobs(int max_count) {
  std::vector<Value> out;
  if (!active_ || region_id_.empty()) return out;
  const int n = std::max(0, max_count);
  if (n <= 0) return out;
  const std::string key = KRegionJobs(region_id_);
  for (int i = 0; i < n; ++i) {
    std::string raw;
    if (!store_->LPop(key, raw)) break;
    const auto parsed = samurai::core::json::Parse(raw);
    if (!parsed.ok || !parsed.value.is_object()) continue;
    const Value* job = parsed.value.find("job");
    if (!job || !job->is_object() || job->members().empty()) continue;
    Value delegated = *job;
    const Value* from = parsed.value.find("from_region");
    delegated.set("_mmr_delegated_from", Value::Str(from ? from->as_string("") : ""));
    out.push_back(std::move(delegated));
  }
  return out;
}

std::vector<Value> RedisMultiMasterCoordinator::RegionsState() {
  std::vector<Value> out;
  if (!active_) return out;
  const std::string pattern = "samurai:mm:" + namespace_ + ":region:*:node:*:hb";
  for (const std::string& key : store_->ScanMatch(pattern, 200)) {
    std::string raw;
    if (!store_->Get(key, raw) || raw.empty()) continue;
    const auto parsed = samurai::core::json::Parse(raw);
    if (parsed.ok && parsed.value.is_object()) out.push_back(parsed.value);
  }
  std::sort(out.begin(), out.end(), [](const Value& a, const Value& b) {
    const std::string ar = a.find("region_id") ? a.find("region_id")->as_string("") : "";
    const std::string br = b.find("region_id") ? b.find("region_id")->as_string("") : "";
    if (ar != br) return ar < br;
    const std::string an = a.find("node_id") ? a.find("node_id")->as_string("") : "";
    const std::string bn = b.find("node_id") ? b.find("node_id")->as_string("") : "";
    return an < bn;
  });
  return out;
}

std::vector<Value> RedisMultiMasterCoordinator::LatestRegionSnapshots() {
  std::vector<Value> out;
  if (!active_) return out;
  const std::string pattern = "samurai:mm:" + namespace_ + ":region:*:latest";
  for (const std::string& key : store_->ScanMatch(pattern, 200)) {
    std::string raw;
    if (!store_->Get(key, raw) || raw.empty()) continue;
    const auto parsed = samurai::core::json::Parse(raw);
    if (parsed.ok && parsed.value.is_object()) out.push_back(parsed.value);
  }
  std::sort(out.begin(), out.end(), [](const Value& a, const Value& b) {
    const std::string ar = a.find("region_id") ? a.find("region_id")->as_string("") : "";
    const std::string br = b.find("region_id") ? b.find("region_id")->as_string("") : "";
    return ar < br;
  });
  return out;
}

Value RedisMultiMasterCoordinator::Snapshot() const {
  Value out = Value::Object();
  // Effective enabled: flips false when the backend is unavailable, matching
  // Python where _init_client() clears self.enabled on connect failure.
  out.set("enabled", Value::Bool(active_));
  out.set("namespace", Value::Str(namespace_));
  out.set("region_id", Value::Str(region_id_));
  out.set("node_id", Value::Str(node_id_));
  out.set("heartbeat_ttl_s", Value::Int(heartbeat_ttl_s_));
  out.set("error", Value::Str(error_));
  return out;
}

}  // namespace samurai::control
