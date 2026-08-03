#include "telemetry.hpp"

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace samurai::control {

namespace {

using samurai::core::json::Value;

std::string Lower(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return s;
}

std::string Strip(const std::string& s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

std::int64_t IntField(const Value& item, const char* key) {
  const Value* v = item.find(key);
  return v ? v->as_int(0) : 0;
}

double DoubleField(const Value& item, const char* key) {
  const Value* v = item.find(key);
  return v ? v->as_double(0.0) : 0.0;
}

std::string StrField(const Value& item, const char* key) {
  const Value* v = item.find(key);
  return v ? v->as_string("") : "";
}

// Resolve the region: region | worker_region | target_region | "unknown".
std::string ResolveRegion(const Value& item) {
  std::string r = Strip(StrField(item, "region"));
  if (r.empty()) r = Strip(StrField(item, "worker_region"));
  if (r.empty()) r = Strip(StrField(item, "target_region"));
  r = Lower(r);
  return r.empty() ? "unknown" : r;
}

struct ShardRec {
  std::string shard_id;
  std::string worker_id;
  std::int64_t leader_epoch_max = 0;
  std::int64_t sent = 0;
  std::int64_t errors = 0;
  std::int64_t progress = 0;
  double duration_s_max = 0.0;
  std::string last_status;
  std::int64_t last_exitcode = 0;
  std::int64_t updates = 0;
};

struct WorkerRec {
  std::string worker_id;
  std::int64_t sent = 0;
  std::int64_t errors = 0;
  std::int64_t progress = 0;
  std::set<std::string> shard_ids;
  std::int64_t updates = 0;
};

struct RegionRec {
  std::string region;
  std::int64_t sent = 0;
  std::int64_t errors = 0;
  std::int64_t progress = 0;
  std::set<std::string> workers;
  std::set<std::string> shards;
  std::int64_t updates = 0;
};

Value StrArray(const std::set<std::string>& s) {
  Value arr = Value::Array();
  for (const auto& x : s) arr.push_back(Value::Str(x));  // std::set -> sorted
  return arr;
}

}  // namespace

void DistributedAggregator::Add(const Value& item) {
  if (item.is_object()) {
    items_.push_back(item);
  } else {
    items_.push_back(Value::Object());  // dict(item or {}) -> {}
  }
}

Value DistributedAggregator::Snapshot() const {
  std::int64_t sent = 0, errors = 0, progress = 0;
  std::set<std::string> workers, shards;
  Value numeric_totals = Value::Object();  // insertion-ordered, like the dict
  std::map<std::string, ShardRec> per_shard;
  std::map<std::string, WorkerRec> worker_rollup;
  std::map<std::string, RegionRec> region_rollup;

  for (const auto& item : items_) {
    sent += IntField(item, "sent");
    errors += IntField(item, "errors");
    progress += IntField(item, "progress");

    // numeric_totals: sum every non-bool numeric field, first-seen order.
    for (const auto& kv : item.members()) {
      const Value& v = kv.second;
      if (v.is_bool()) continue;
      if (v.is_number()) {
        const Value* cur = numeric_totals.find(kv.first);
        const double base = cur ? cur->as_double(0.0) : 0.0;
        numeric_totals.set(kv.first, Value::Double(base + v.as_double(0.0)));
      }
    }

    const std::string wid = Strip(StrField(item, "worker_id"));
    const std::string sid = Strip(StrField(item, "shard_id"));
    const std::string region = ResolveRegion(item);

    if (!wid.empty()) workers.insert(wid);

    if (!sid.empty()) {
      shards.insert(sid);
      ShardRec& s = per_shard[sid];
      s.shard_id = sid;
      if (!wid.empty()) s.worker_id = wid;
      s.sent = std::max(s.sent, IntField(item, "sent"));
      s.errors = std::max(s.errors, IntField(item, "errors"));
      s.progress = std::max(s.progress, IntField(item, "progress"));
      s.leader_epoch_max = std::max(s.leader_epoch_max, IntField(item, "leader_epoch"));
      s.duration_s_max = std::max(s.duration_s_max, DoubleField(item, "duration_s"));
      if (item.contains("status")) {
        const std::string st = StrField(item, "status");
        if (!st.empty()) s.last_status = st;  // str(x or old)
      }
      if (item.contains("exitcode")) s.last_exitcode = IntField(item, "exitcode");
      s.updates += 1;
    }

    if (!wid.empty()) {
      WorkerRec& w = worker_rollup[wid];
      w.worker_id = wid;
      w.sent = std::max(w.sent, IntField(item, "sent"));
      w.errors = std::max(w.errors, IntField(item, "errors"));
      w.progress = std::max(w.progress, IntField(item, "progress"));
      if (!sid.empty()) w.shard_ids.insert(sid);
      w.updates += 1;
    }

    RegionRec& r = region_rollup[region];
    r.region = region;
    r.sent = std::max(r.sent, IntField(item, "sent"));
    r.errors = std::max(r.errors, IntField(item, "errors"));
    r.progress = std::max(r.progress, IntField(item, "progress"));
    if (!wid.empty()) r.workers.insert(wid);
    if (!sid.empty()) r.shards.insert(sid);
    r.updates += 1;
  }

  // per_shard sorted by (-errors, -last_exitcode, shard_id).
  std::vector<const ShardRec*> shard_ptrs;
  shard_ptrs.reserve(per_shard.size());
  for (const auto& kv : per_shard) shard_ptrs.push_back(&kv.second);
  std::sort(shard_ptrs.begin(), shard_ptrs.end(), [](const ShardRec* a, const ShardRec* b) {
    if (a->errors != b->errors) return a->errors > b->errors;
    if (a->last_exitcode != b->last_exitcode) return a->last_exitcode > b->last_exitcode;
    return a->shard_id < b->shard_id;
  });

  auto shard_to_json = [](const ShardRec* s) {
    Value o = Value::Object();
    o.set("shard_id", Value::Str(s->shard_id));
    o.set("worker_id", Value::Str(s->worker_id));
    o.set("leader_epoch_max", Value::Int(s->leader_epoch_max));
    o.set("sent", Value::Int(s->sent));
    o.set("errors", Value::Int(s->errors));
    o.set("progress", Value::Int(s->progress));
    o.set("duration_s_max", Value::Double(s->duration_s_max));
    o.set("last_status", Value::Str(s->last_status));
    o.set("last_exitcode", Value::Int(s->last_exitcode));
    o.set("updates", Value::Int(s->updates));
    return o;
  };

  Value per_shard_list = Value::Array();
  Value top_error_shards = Value::Array();
  for (std::size_t i = 0; i < shard_ptrs.size(); ++i) {
    Value o = shard_to_json(shard_ptrs[i]);
    if (i < 10) top_error_shards.push_back(o);
    per_shard_list.push_back(std::move(o));
  }

  // worker_rollup sorted by (-errors, -sent, worker_id).
  std::vector<const WorkerRec*> worker_ptrs;
  worker_ptrs.reserve(worker_rollup.size());
  for (const auto& kv : worker_rollup) worker_ptrs.push_back(&kv.second);
  std::sort(worker_ptrs.begin(), worker_ptrs.end(), [](const WorkerRec* a, const WorkerRec* b) {
    if (a->errors != b->errors) return a->errors > b->errors;
    if (a->sent != b->sent) return a->sent > b->sent;
    return a->worker_id < b->worker_id;
  });
  Value worker_rollup_list = Value::Array();
  for (const WorkerRec* w : worker_ptrs) {
    Value o = Value::Object();
    o.set("worker_id", Value::Str(w->worker_id));
    o.set("sent", Value::Int(w->sent));
    o.set("errors", Value::Int(w->errors));
    o.set("progress", Value::Int(w->progress));
    o.set("shard_count", Value::Int(static_cast<std::int64_t>(w->shard_ids.size())));
    o.set("shard_ids", StrArray(w->shard_ids));
    o.set("updates", Value::Int(w->updates));
    worker_rollup_list.push_back(std::move(o));
  }

  // region_rollup sorted by (-errors, -sent, region).
  std::vector<const RegionRec*> region_ptrs;
  region_ptrs.reserve(region_rollup.size());
  for (const auto& kv : region_rollup) region_ptrs.push_back(&kv.second);
  std::sort(region_ptrs.begin(), region_ptrs.end(), [](const RegionRec* a, const RegionRec* b) {
    if (a->errors != b->errors) return a->errors > b->errors;
    if (a->sent != b->sent) return a->sent > b->sent;
    return a->region < b->region;
  });
  Value region_rollup_list = Value::Array();
  for (const RegionRec* r : region_ptrs) {
    Value o = Value::Object();
    o.set("region", Value::Str(r->region));
    o.set("sent", Value::Int(r->sent));
    o.set("errors", Value::Int(r->errors));
    o.set("progress", Value::Int(r->progress));
    o.set("workers", Value::Int(static_cast<std::int64_t>(r->workers.size())));
    o.set("worker_ids", StrArray(r->workers));
    o.set("shards", Value::Int(static_cast<std::int64_t>(r->shards.size())));
    o.set("shard_ids", StrArray(r->shards));
    o.set("updates", Value::Int(r->updates));
    region_rollup_list.push_back(std::move(o));
  }

  Value items_arr = Value::Array();
  for (const auto& it : items_) items_arr.push_back(it);

  Value out = Value::Object();
  out.set("sent", Value::Int(sent));
  out.set("errors", Value::Int(errors));
  out.set("progress", Value::Int(progress));
  out.set("shards", Value::Int(static_cast<std::int64_t>(
                        !shards.empty() ? shards.size() : items_.size())));
  out.set("workers", Value::Int(static_cast<std::int64_t>(workers.size())));
  out.set("worker_ids", StrArray(workers));
  out.set("shard_ids", StrArray(shards));
  out.set("numeric_totals", std::move(numeric_totals));
  out.set("per_shard", std::move(per_shard_list));
  out.set("top_error_shards", std::move(top_error_shards));
  out.set("worker_rollup", std::move(worker_rollup_list));
  out.set("region_rollup", std::move(region_rollup_list));
  out.set("items", std::move(items_arr));
  return out;
}

}  // namespace samurai::control
