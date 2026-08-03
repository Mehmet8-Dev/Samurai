#include "master_coordinator.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "telemetry.hpp"

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

std::vector<std::int64_t> ChunkCounts(std::int64_t total, std::int64_t unit) {
  total = std::max<std::int64_t>(0, total);
  unit = std::max<std::int64_t>(1, unit);
  std::vector<std::int64_t> out;
  std::int64_t rem = total;
  while (rem > 0) {
    const std::int64_t c = std::min(unit, rem);
    out.push_back(c);
    rem -= c;
  }
  return out;
}

struct Shard {
  std::string shard_id;
  std::int64_t packet_count = 0;
  int attempt = 0;
  std::string target_region;
  std::string worker_id;  // set on dispatch
};

const std::string* CapPtr(const std::map<std::string, std::string>& caps, const std::string& k) {
  auto it = caps.find(k);
  return it == caps.end() ? nullptr : &it->second;
}
std::string CapStr(const std::map<std::string, std::string>& caps, const std::string& k) {
  const std::string* p = CapPtr(caps, k);
  return p ? *p : "";
}
bool CapFlag(const std::map<std::string, std::string>& caps, const std::string& k) {
  const std::string v = Lower(Strip(CapStr(caps, k)));
  return v == "1" || v == "true" || v == "yes";
}

double WorkerDispatchScore(const std::map<std::string, std::string>& caps, const Shard& sh,
                           const std::string& target_region, bool region_aware) {
  double score = 0.0;
  std::string tr = Lower(Strip(sh.target_region.empty() ? target_region : sh.target_region));
  const std::string wr = Lower(Strip(CapStr(caps, "region")));
  if (region_aware && !tr.empty()) {
    if (wr == tr) {
      score += 100.0;
    } else if (!wr.empty() && wr != tr) {
      score -= 20.0;
    }
  }
  const std::string* cap_score = CapPtr(caps, "capacity_score");
  if (cap_score) {
    try {
      score += static_cast<double>(std::stoll(*cap_score));
    } catch (...) {
    }
  }
  if (CapFlag(caps, "gpu_available")) score += 2.0;
  if (CapFlag(caps, "xdp_available")) score += 1.0;
  return score;
}

}  // namespace

MasterCoordinator::MasterCoordinator(MasterView* view, WorkerCommander* commander,
                                     std::function<std::int64_t()> now_ms,
                                     std::function<void(int)> sleep_ms)
    : view_(view), commander_(commander) {
  now_ms_ = now_ms ? std::move(now_ms) : std::function<std::int64_t()>([]() {
    using namespace std::chrono;
    return static_cast<std::int64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
  });
  sleep_ms_ = sleep_ms ? std::move(sleep_ms) : std::function<void(int)>([](int ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
  });
}

JobResult MasterCoordinator::RunSingleJob(const JobConfig& job, const std::string& job_id,
                                          std::function<bool()> leadership_guard) {
  JobResult result;
  if (job.count <= 0) {
    Value snap = Value::Object();
    snap.set("job_id", Value::Str(job_id));
    snap.set("error", Value::Str("count<=0"));
    result.rc = 1;
    result.snapshot = std::move(snap);
    return result;
  }

  const std::int64_t wait_s = job.job_timeout_s > 0 ? job.job_timeout_s : 120;
  const std::int64_t timeout_ms = job.job_timeout_s * 1000;
  const bool region_aware =
      job.region_aware_routing || Lower(Strip(job.shard_strategy)) == "region";
  const std::string target_region = Lower(Strip(job.target_region));
  const std::string master_region = Lower(Strip(job.worker_region));
  const int poll_ms = std::max(1, job.master_poll_interval_ms);

  auto load_workers = [&]() {
    std::map<std::string, WorkerInfo> m;
    for (auto& w : view_->Workers()) m[w.worker_id] = std::move(w);
    return m;
  };

  std::int64_t initial_workers = std::max<std::int64_t>(1, static_cast<std::int64_t>(load_workers().size()));
  std::int64_t shard_unit = job.shard_unit_count;
  if (shard_unit <= 0) {
    shard_unit = std::max<std::int64_t>(1, job.count / std::max<std::int64_t>(4, initial_workers * 4));
  }
  const auto counts = ChunkCounts(job.count, shard_unit);

  std::deque<Shard> pending;
  std::set<std::string> all_sids;
  int seq = 0;
  for (std::int64_t c : counts) {
    ++seq;
    Shard s;
    s.shard_id = job_id + "-shard-" + std::to_string(seq);
    s.packet_count = c;
    s.attempt = 0;
    s.target_region = target_region;
    all_sids.insert(s.shard_id);
    pending.push_back(std::move(s));
  }

  std::map<std::string, Shard> inflight_by_worker;
  std::map<std::string, Shard> inflight_by_sid;
  std::set<std::string> lost_workers;
  std::set<std::string> done_shards;
  std::vector<std::string> dispatch_failures;

  auto endpoint_of = [&](const std::map<std::string, WorkerInfo>& workers, const std::string& wid) {
    auto it = workers.find(wid);
    if (it == workers.end()) return std::string();
    return Strip(CapStr(it->second.capabilities, "control_endpoint"));
  };
  auto hb_timeout_for = [&](const std::map<std::string, std::string>& caps) -> std::int64_t {
    if (!region_aware) return job.heartbeat_timeout_ms;
    const std::string wr = Lower(Strip(CapStr(caps, "region")));
    const std::int64_t stretched = static_cast<std::int64_t>(
        std::max<double>(job.heartbeat_timeout_ms,
                         job.heartbeat_timeout_ms * job.cross_region_heartbeat_factor));
    if (!master_region.empty() && !wr.empty() && wr != master_region) return stretched;
    if (!target_region.empty() && !wr.empty() && wr != target_region) return stretched;
    return job.heartbeat_timeout_ms;
  };

  const std::int64_t deadline = now_ms_() + wait_s * 1000;

  while (now_ms_() < deadline) {
    if (leadership_guard && !leadership_guard()) {
      Value snap = Value::Object();
      snap.set("job_id", Value::Str(job_id));
      snap.set("error", Value::Str("leadership_lost_abort"));
      snap.set("leader_epoch", Value::Int(job.leader_epoch));
      result.rc = 1;
      result.snapshot = std::move(snap);
      return result;
    }

    const std::int64_t now = now_ms_();
    auto workers = load_workers();

    // Lost-worker detection via heartbeat timeout.
    for (const auto& kv : workers) {
      const std::int64_t last_hb = kv.second.last_heartbeat_ms;
      if (last_hb > 0 && (now - last_hb) > hb_timeout_for(kv.second.capabilities)) {
        lost_workers.insert(kv.first);
      }
    }
    // Rebalance shards held by lost workers.
    for (auto it = inflight_by_worker.begin(); it != inflight_by_worker.end();) {
      if (lost_workers.count(it->first)) {
        Shard sh = it->second;
        it = inflight_by_worker.erase(it);
        inflight_by_sid.erase(sh.shard_id);
        if (!done_shards.count(sh.shard_id)) {
          sh.attempt += 1;
          if (sh.attempt <= 2) pending.push_front(sh);
        }
      } else {
        ++it;
      }
    }
    if (!lost_workers.empty() && Lower(Strip(job.on_worker_loss)) == "abort") {
      Value snap = Value::Object();
      snap.set("job_id", Value::Str(job_id));
      snap.set("error", Value::Str("worker_loss_abort"));
      snap.set("leader_epoch", Value::Int(job.leader_epoch));
      result.rc = 1;
      result.snapshot = std::move(snap);
      return result;
    }

    // Completion via reported stats or status probe.
    std::vector<std::string> sids;
    sids.reserve(inflight_by_sid.size());
    for (const auto& kv : inflight_by_sid) sids.push_back(kv.first);
    for (const std::string& sid : sids) {
      auto sit = inflight_by_sid.find(sid);
      if (sit == inflight_by_sid.end()) continue;
      if (view_->ShardReported(sid)) {
        done_shards.insert(sid);
        const std::string wid = sit->second.worker_id;
        inflight_by_sid.erase(sit);
        inflight_by_worker.erase(wid);
        continue;
      }
      const std::string wid = sit->second.worker_id;
      if (wid.empty()) continue;
      if (!job.worker_status_probe) continue;
      const std::string ep = endpoint_of(workers, wid);
      if (ep.empty()) continue;
      const ProbeOutcome probe = commander_->Probe(ep, wid);
      const std::string st = Lower(Strip(probe.state));
      if ((st == "done" || st == "error") &&
          (probe.active_shard_id.empty() || probe.active_shard_id == sid)) {
        if (!probe.stats_json.empty() && probe.stats_json != "{}") {
          view_->SetShardStats(sid, probe.stats_json);
        }
        done_shards.insert(sid);
        inflight_by_sid.erase(sid);
        inflight_by_worker.erase(wid);
      }
    }

    if (pending.empty() && inflight_by_sid.empty()) break;

    // Dispatch pending shards to free workers.
    std::vector<std::string> free_workers;
    for (const auto& kv : workers) {
      if (lost_workers.count(kv.first)) continue;
      if (inflight_by_worker.count(kv.first)) continue;
      if (!endpoint_of(workers, kv.first).empty()) free_workers.push_back(kv.first);
    }

    while (!pending.empty() && !free_workers.empty()) {
      Shard sh = pending.front();
      pending.pop_front();
      // Select a worker (region-aware if enabled), else the first free one.
      std::size_t pick = 0;
      if (region_aware) {
        double best = -1e300;
        for (std::size_t i = 0; i < free_workers.size(); ++i) {
          const double sc =
              WorkerDispatchScore(workers[free_workers[i]].capabilities, sh, target_region, true);
          if (sc > best) {
            best = sc;
            pick = i;
          }
        }
      }
      const std::string wid = free_workers[pick];
      free_workers.erase(free_workers.begin() + pick);

      const std::string ep = endpoint_of(workers, wid);
      if (ep.empty()) {
        dispatch_failures.push_back("E_STARTSHARD_NO_ENDPOINT worker=" + wid + " shard=" + sh.shard_id);
        sh.attempt += 1;
        if (sh.attempt <= 2) pending.push_back(sh);
        continue;
      }
      // Build the per-shard args from the job's base args.
      Value args = job.base_args.is_object() ? job.base_args : Value::Object();
      args.set("count", Value::Int(sh.packet_count));
      args.set("role", Value::Str("standalone"));
      args.set("_worker_id", Value::Str(wid));
      args.set("_leader_epoch", Value::Int(job.leader_epoch));
      const DispatchOutcome d =
          commander_->Dispatch(ep, sh.shard_id, job_id, args.dump(), sh.packet_count, timeout_ms);
      if (d.started) {
        sh.worker_id = wid;
        inflight_by_worker[wid] = sh;
        inflight_by_sid[sh.shard_id] = sh;
      } else {
        dispatch_failures.push_back(d.message.empty()
                                        ? ("E_STARTSHARD_REJECTED worker=" + wid + " shard=" + sh.shard_id)
                                        : d.message);
        sh.attempt += 1;
        if (sh.attempt <= 2) pending.push_back(sh);
      }
    }

    sleep_ms_(poll_ms);
  }

  // Best-effort stop of any stragglers.
  std::set<std::string> unresolved;
  for (const auto& kv : inflight_by_sid) unresolved.insert(kv.first);
  const int stop_retries = std::max(1, job.stop_shard_retries);
  for (int r = 0; r < stop_retries && !unresolved.empty(); ++r) {
    auto workers = load_workers();
    for (auto it = unresolved.begin(); it != unresolved.end();) {
      const std::string sid = *it;
      const auto sh = inflight_by_sid.find(sid);
      const std::string ep = sh == inflight_by_sid.end() ? std::string()
                                                         : endpoint_of(workers, sh->second.worker_id);
      if (!ep.empty() && commander_->StopShard(ep, sid)) {
        it = unresolved.erase(it);
      } else {
        ++it;
      }
    }
    if (!unresolved.empty()) sleep_ms_(poll_ms);
  }

  // Aggregate reported stats for this job's shards.
  DistributedAggregator aggregator;
  for (const std::string& sid : all_sids) {
    if (!view_->ShardReported(sid)) continue;
    const auto parsed = samurai::core::json::Parse(view_->GetShardStats(sid));
    if (!parsed.ok || !parsed.value.is_object()) continue;
    Value item = parsed.value;
    if (!item.find("shard_id")) item.set("shard_id", Value::Str(sid));
    aggregator.Add(item);
  }
  const Value agg = aggregator.Snapshot();

  auto agg_field = [&](const char* k) -> const Value* { return agg.find(k); };

  Value snap = Value::Object();
  snap.set("job_id", Value::Str(job_id));
  snap.set("leader_epoch", Value::Int(job.leader_epoch));
  snap.set("workers", Value::Int(static_cast<std::int64_t>(load_workers().size())));
  const Value* shard_ids = agg_field("shard_ids");
  snap.set("shards_reported",
           Value::Int(shard_ids ? static_cast<std::int64_t>(shard_ids->elements().size()) : 0));
  Value lost_arr = Value::Array();
  for (const auto& w : lost_workers) lost_arr.push_back(Value::Str(w));
  snap.set("lost_workers", std::move(lost_arr));
  Value df_arr = Value::Array();
  for (const auto& m : dispatch_failures) df_arr.push_back(Value::Str(m));
  snap.set("dispatch_failures", std::move(df_arr));
  snap.set("sent", Value::Int(agg_field("sent") ? agg_field("sent")->as_int(0) : 0));
  snap.set("errors", Value::Int(agg_field("errors") ? agg_field("errors")->as_int(0) : 0));
  if (const Value* v = agg_field("worker_ids")) snap.set("worker_ids", *v);
  if (const Value* v = agg_field("shard_ids")) snap.set("shard_ids", *v);
  if (const Value* v = agg_field("numeric_totals")) snap.set("numeric_totals", *v);
  if (const Value* v = agg_field("top_error_shards")) snap.set("top_error_shards", *v);
  if (const Value* v = agg_field("worker_rollup")) snap.set("worker_rollup", *v);
  if (const Value* v = agg_field("region_rollup")) snap.set("region_rollup", *v);
  snap.set("pending_shards_left", Value::Int(static_cast<std::int64_t>(pending.size())));
  snap.set("inflight_shards_left", Value::Int(static_cast<std::int64_t>(inflight_by_sid.size())));

  result.rc = (pending.empty() && inflight_by_sid.empty()) ? 0 : 1;
  result.snapshot = std::move(snap);
  return result;
}

}  // namespace samurai::control
