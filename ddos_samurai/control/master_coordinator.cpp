#include "master_coordinator.hpp"
#include "shard.hpp"

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

struct CoordShard {
  std::string shard_id;
  std::int64_t packet_count = 0;
  int attempt = 0;
  std::string target_region;
  std::string worker_id;  // set on dispatch
  std::string preferred_worker;
  bool is_telco = false;
  TelcoShardSpec telco_spec;
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

// True if the worker can run the job's required worker flavor. `required` empty
// (job declared no kind) always matches. A worker that doesn't advertise
// `worker_kinds` (legacy) is treated as a wildcard so old workers keep working;
// otherwise the required kind must be in its comma-separated list (bundle nodes
// list the whole catalog).
bool WorkerRunsKind(const std::map<std::string, std::string>& caps, const std::string& required) {
  if (required.empty()) return true;
  const std::string* kinds = CapPtr(caps, "worker_kinds");
  if (kinds == nullptr) return true;
  std::size_t pos = 0;
  const std::string& list = *kinds;
  while (pos <= list.size()) {
    const std::size_t comma = list.find(',', pos);
    const std::size_t end = comma == std::string::npos ? list.size() : comma;
    if (Lower(Strip(list.substr(pos, end - pos))) == required) return true;
    if (comma == std::string::npos) break;
    pos = comma + 1;
  }
  return false;
}

double WorkerDispatchScore(const std::map<std::string, std::string>& caps, const CoordShard& sh,
                           const std::string& target_region, bool region_aware,
                           const RegionTopology& topology) {
  double score = 0.0;
  std::string tr = topology.CanonicalRegion(sh.target_region.empty() ? target_region : sh.target_region);
  const std::string wr = Lower(Strip(CapStr(caps, "region")));
  if (region_aware && !tr.empty()) {
    score += static_cast<double>(topology.AffinityDelta(wr, tr)) * 20.0;
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

int MasterCoordinator::ReconfigureActiveShards(const std::string& args_json,
                                               std::int64_t leader_epoch,
                                               const std::string& filter_shard_id,
                                               const std::string& filter_worker_id) {
  if (!commander_ || args_json.empty()) return 0;
  std::vector<std::pair<std::string, ActiveShardTarget>> targets;
  {
    std::lock_guard<std::mutex> lk(active_mu_);
    for (const auto& kv : active_shards_) {
      if (!filter_shard_id.empty() && kv.first != filter_shard_id) continue;
      if (!filter_worker_id.empty() && kv.second.worker_id != filter_worker_id) continue;
      targets.push_back(kv);
    }
  }
  int applied = 0;
  for (const auto& item : targets) {
    const std::string& sid = item.first;
    const ActiveShardTarget& tgt = item.second;
    const std::int64_t eff_epoch = (leader_epoch >= 0) ? leader_epoch : tgt.leader_epoch;
    bool ok = false;
    if (tgt.via_reverse) {
      ok = commander_->ReconfigureShardReverse(tgt.worker_id, sid, args_json, eff_epoch);
    } else {
      if (!tgt.endpoint.empty()) {
        ok = commander_->ReconfigureShard(tgt.endpoint, sid, args_json, eff_epoch);
      }
      if (!ok && tgt.is_auto) {
        ok = commander_->ReconfigureShardReverse(tgt.worker_id, sid, args_json, eff_epoch);
      }
    }
    if (ok) ++applied;
  }
  return applied;
}

std::map<std::string, std::string> MasterCoordinator::ActiveShardWorkers() const {
  std::lock_guard<std::mutex> lk(active_mu_);
  std::map<std::string, std::string> out;
  for (const auto& kv : active_shards_) {
    out[kv.first] = kv.second.worker_id;
  }
  return out;
}

JobResult MasterCoordinator::RunSingleJob(const JobConfig& job, const std::string& job_id,
                                          std::function<bool()> leadership_guard) {
  JobResult result;
  const bool is_telco =
      job.is_telco_job ||
      (job.base_args.is_object() &&
       (job.base_args.find("telco") != nullptr ||
        (job.base_args.find("worker") != nullptr &&
         Lower(Strip(job.base_args.find("worker")->as_string(""))) == "telco")));
  const std::int64_t total_workload = is_telco ? (job.telco_subscribers > 0 ? static_cast<std::int64_t>(job.telco_subscribers) : job.count) : job.count;

  if (total_workload <= 0) {
    Value snap = Value::Object();
    snap.set("job_id", Value::Str(job_id));
    snap.set("error", Value::Str(is_telco ? "telco_subscribers<=0" : "count<=0"));
    result.rc = 1;
    result.snapshot = std::move(snap);
    return result;
  }

  const std::int64_t wait_s = job.job_timeout_s > 0 ? job.job_timeout_s : 120;
  const std::int64_t timeout_ms = job.job_timeout_s * 1000;
  const std::string target_region =
      job.region_topology.ResolveRegion(job.target_asn, job.target_region);
  const std::string master_region = job.region_topology.CanonicalRegion(job.worker_region);
  const std::string strategy_norm = Lower(Strip(job.shard_strategy.empty() ? "equal" : job.shard_strategy));
  const bool region_aware =
      job.region_aware_routing || strategy_norm == "region" || !target_region.empty();
  const int poll_ms = std::max(1, job.master_poll_interval_ms);
  // Worker flavor this job needs (from base_args["worker"]); shards only go to
  // workers advertising it. Empty (or a legacy worker with no worker_kinds cap)
  // disables the filter for backward compatibility.
  const std::string required_kind = [&]() -> std::string {
    if (is_telco) return "telco";
    const Value* w = job.base_args.is_object() ? job.base_args.find("worker") : nullptr;
    return (w != nullptr && w->is_string()) ? Lower(Strip(w->as_string(""))) : std::string();
  }();

  auto load_workers = [&]() {
    std::map<std::string, WorkerInfo> m;
    for (auto& w : view_->Workers()) m[w.worker_id] = std::move(w);
    return m;
  };

  std::deque<CoordShard> pending;
  std::set<std::string> all_sids;

  if (is_telco) {
    auto w_map = load_workers();
    std::vector<std::string> telco_workers;
    std::map<std::string, WorkerCapabilities> telco_caps;
    for (const auto& kv : w_map) {
      if (WorkerRunsKind(kv.second.capabilities, "telco")) {
        telco_workers.push_back(kv.first);
        telco_caps[kv.first] = CapabilitiesFromStrings(kv.second.capabilities);
      }
    }
    if (telco_workers.empty()) {
      for (const auto& kv : w_map) {
        telco_workers.push_back(kv.first);
        telco_caps[kv.first] = CapabilitiesFromStrings(kv.second.capabilities);
      }
    }
    if (telco_workers.empty()) {
      telco_workers.push_back("worker-1");
    }

    const std::string telco_strategy =
        region_aware ? "region" : (strategy_norm.empty() ? "equal" : strategy_norm);
    const TelcoLabSizingProfile* pool_ptr =
        job.telco_pool_profile.buckets.empty() ? nullptr : &job.telco_pool_profile;
    auto telco_specs = SplitTelcoSubscribers(
        static_cast<std::uint32_t>(total_workload),
        telco_workers,
        telco_caps,
        target_region,
        telco_strategy,
        job.telco_protocol,
        job.telco_rate_cps,
        job.telco_base_vlan_s,
        job.telco_base_vlan_c,
        nullptr,
        job.telco_base_ip,
        job.telco_gateway_ip,
        pool_ptr,
        &job.region_topology);

    int seq = 0;
    for (auto& spec : telco_specs) {
      ++seq;
      CoordShard s;
      s.shard_id = job_id + "-telco-shard-" + std::to_string(seq);
      spec.shard_id = s.shard_id;
      s.packet_count = spec.range.count;
      s.attempt = 0;
      s.target_region = target_region;
      s.preferred_worker = spec.worker_id;
      s.is_telco = true;
      s.telco_spec = std::move(spec);
      all_sids.insert(s.shard_id);
      pending.push_back(std::move(s));
    }
  } else {
    std::int64_t initial_workers = std::max<std::int64_t>(1, static_cast<std::int64_t>(load_workers().size()));
    std::int64_t shard_unit = job.shard_unit_count;
    if (shard_unit <= 0) {
      shard_unit = std::max<std::int64_t>(1, job.count / std::max<std::int64_t>(4, initial_workers * 4));
    }
    const auto counts = ChunkCounts(job.count, shard_unit);
    int seq = 0;
    for (std::int64_t c : counts) {
      ++seq;
      CoordShard s;
      s.shard_id = job_id + "-shard-" + std::to_string(seq);
      s.packet_count = c;
      s.attempt = 0;
      s.target_region = target_region;
      all_sids.insert(s.shard_id);
      pending.push_back(std::move(s));
    }
  }

  std::map<std::string, CoordShard> inflight_by_worker;
  std::map<std::string, CoordShard> inflight_by_sid;
  std::map<std::string, std::int64_t> reverse_dispatch_ms;  // sid -> dispatch time (reverse)
  std::set<std::string> lost_workers;
  std::set<std::string> done_shards;
  std::vector<std::string> dispatch_failures;

  struct ActiveScopeGuard {
    std::mutex& mu;
    std::map<std::string, ActiveShardTarget>& m;
    std::set<std::string>& sids;
    ~ActiveScopeGuard() {
      std::lock_guard<std::mutex> lk(mu);
      for (const auto& s : sids) m.erase(s);
    }
  } active_scope_guard{active_mu_, active_shards_, all_sids};

  auto track_active = [&](const std::string& sid, const ActiveShardTarget& tgt) {
    std::lock_guard<std::mutex> lk(active_mu_);
    active_shards_[sid] = tgt;
  };
  auto untrack_active = [&](const std::string& sid) {
    std::lock_guard<std::mutex> lk(active_mu_);
    active_shards_.erase(sid);
  };

  auto endpoint_of = [&](const std::map<std::string, WorkerInfo>& workers, const std::string& wid) {
    auto it = workers.find(wid);
    if (it == workers.end()) return std::string();
    return Strip(CapStr(it->second.capabilities, "control_endpoint"));
  };
  auto dispatch_mode_of = [&](const std::map<std::string, WorkerInfo>& workers,
                              const std::string& wid) -> std::string {
    auto it = workers.find(wid);
    if (it == workers.end()) return "";
    return Lower(Strip(CapStr(it->second.capabilities, "dispatch_mode")));
  };
  // Pure reverse: no inbound endpoint, pull-only.
  auto is_reverse = [&](const std::map<std::string, WorkerInfo>& workers, const std::string& wid) {
    return dispatch_mode_of(workers, wid) == "reverse";
  };
  // Auto: advertises an endpoint (direct-preferred) but is also reverse-capable,
  // so the master can fall back to the heartbeat pull path if direct is
  // unreachable (NAT).
  auto is_auto = [&](const std::map<std::string, WorkerInfo>& workers, const std::string& wid) {
    return dispatch_mode_of(workers, wid) == "auto";
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
  std::int64_t next_window_tick_ms =
      (job.window_tick_cb && job.window_tick_interval_ms > 0)
          ? (now_ms_() + job.window_tick_interval_ms)
          : 0;
  int window_tick_index = 0;
  bool converged_stop = false;

  while (now_ms_() < deadline) {
    if (leadership_guard && !leadership_guard()) {
      // Leadership lost mid-job. Fencing already blocks *new* commands from this
      // now-stale master, but shards it already dispatched keep running on the
      // workers. Recall them best-effort so residual unauthorized execution is
      // bounded by stop latency (ms) rather than the shard's own burst length.
      // The stops carry this job's leader_epoch: a worker the new leader already
      // superseded fences them off (correct — the new leader owns those now),
      // otherwise they land and stop our own inflight work cleanly.
      const std::int64_t t_loss = now_ms_();
      const auto workers = load_workers();
      const int active_at_loss = static_cast<int>(inflight_by_sid.size());
      int recalled = 0;
      for (const auto& kv : inflight_by_sid) {
        const std::string& sid = kv.first;
        const std::string& wid = kv.second.worker_id;
        if (done_shards.count(sid)) continue;
        bool ok = false;
        if (reverse_dispatch_ms.count(sid)) {
          ok = wid.empty() ? false : commander_->StopShardReverse(wid, sid, job.leader_epoch);
        } else {
          const std::string ep = wid.empty() ? std::string() : endpoint_of(workers, wid);
          if (!ep.empty()) ok = commander_->StopShard(ep, sid, job.leader_epoch);
        }
        if (ok) ++recalled;
      }
      Value snap = Value::Object();
      snap.set("job_id", Value::Str(job_id));
      snap.set("error", Value::Str("leadership_lost_abort"));
      snap.set("leader_epoch", Value::Int(job.leader_epoch));
      snap.set("active_shards_at_loss", Value::Int(active_at_loss));
      snap.set("recalled_shards", Value::Int(recalled));
      snap.set("abort_latency_ms", Value::Int(now_ms_() - t_loss));
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
        CoordShard sh = it->second;
        it = inflight_by_worker.erase(it);
        inflight_by_sid.erase(sh.shard_id);
        reverse_dispatch_ms.erase(sh.shard_id);
        untrack_active(sh.shard_id);
        if (!done_shards.count(sh.shard_id)) {
          sh.attempt += 1;
          if (sh.attempt <= job.max_shard_retries) pending.push_front(sh);
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
    std::map<std::string, ProbeOutcome> probed_this_tick;
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
        untrack_active(sid);
        continue;
      }
      const std::string wid = sit->second.worker_id;
      if (wid.empty()) continue;
      // A shard delivered over the pull path (pure reverse, or an auto worker
      // that fell back) can't be probed; instead verify the worker echoed the
      // dispatched shard, and rebalance if the enqueue looks lost (worker alive
      // — lost workers were already handled above).
      if (reverse_dispatch_ms.count(sid)) {
        const std::int64_t grace = job.reverse_pickup_grace_ms > 0
                                       ? job.reverse_pickup_grace_ms
                                       : 2 * job.heartbeat_timeout_ms;
        auto wit = workers.find(wid);
        const std::int64_t disp = reverse_dispatch_ms.count(sid) ? reverse_dispatch_ms[sid] : now;
        const std::string echoed = wit == workers.end() ? std::string() : wit->second.active_shard_id;
        if ((now - disp) > grace && echoed != sid) {
          CoordShard sh = sit->second;
          inflight_by_sid.erase(sid);
          inflight_by_worker.erase(wid);
          reverse_dispatch_ms.erase(sid);
          untrack_active(sid);
          if (!done_shards.count(sid)) {
            sh.attempt += 1;
            if (sh.attempt <= job.max_shard_retries) {
              pending.push_front(sh);
            } else {
              dispatch_failures.push_back("E_REVERSE_PICKUP_LOST worker=" + wid + " shard=" + sid);
            }
          }
        }
        continue;
      }
      if (!job.worker_status_probe) continue;
      const std::string ep = endpoint_of(workers, wid);
      if (ep.empty()) continue;
      const ProbeOutcome probe = commander_->Probe(ep, wid);
      probed_this_tick[sid] = probe;
      const std::string st = Lower(Strip(probe.state));
      if ((st == "done" || st == "error") &&
          (probe.active_shard_id.empty() || probe.active_shard_id == sid)) {
        if (!probe.stats_json.empty() && probe.stats_json != "{}") {
          view_->SetShardStats(sid, probe.stats_json);
        }
        done_shards.insert(sid);
        inflight_by_sid.erase(sid);
        inflight_by_worker.erase(wid);
        untrack_active(sid);
      }
    }

    // Live closed-loop / window transition tick: collect probes across active
    // shards and push live ReconfigureShard RPCs without worker teardown.
    if (job.window_tick_cb && job.window_tick_interval_ms > 0 &&
        !inflight_by_sid.empty() && now >= next_window_tick_ms) {
      std::vector<ProbeOutcome> live_probes;
      live_probes.reserve(inflight_by_sid.size());
      for (const auto& kv : inflight_by_sid) {
        const std::string& sid = kv.first;
        const std::string& wid = kv.second.worker_id;
        auto pit = probed_this_tick.find(sid);
        if (pit != probed_this_tick.end()) {
          live_probes.push_back(pit->second);
        } else if (!reverse_dispatch_ms.count(sid)) {
          const std::string ep = wid.empty() ? std::string() : endpoint_of(workers, wid);
          if (!ep.empty()) {
            live_probes.push_back(commander_->Probe(ep, wid));
          }
        } else {
          ProbeOutcome syn;
          syn.active_shard_id = sid;
          syn.state = "running";
          live_probes.push_back(std::move(syn));
        }
      }
      bool should_stop = false;
      const std::string next_args =
          job.window_tick_cb(window_tick_index++, live_probes, should_stop);
      next_window_tick_ms = now + job.window_tick_interval_ms;
      if (should_stop) {
        converged_stop = true;
        pending.clear();
        break;
      }
      if (!next_args.empty()) {
        ReconfigureActiveShards(next_args, job.leader_epoch);
      }
    }

    // Live progress for the autoscale controller (no-op if unset): the current
    // backlog (pending, not yet dispatched) and in-flight (dispatched, running)
    // shard counts. Reported before the terminal break so a completed job emits
    // its final 0/0.
    if (job.progress_cb) {
      job.progress_cb(static_cast<int>(pending.size()),
                      static_cast<int>(inflight_by_sid.size()));
    }

    if (pending.empty() && inflight_by_sid.empty()) break;

    // Dispatch pending shards to free workers.
    std::vector<std::string> free_workers;
    for (const auto& kv : workers) {
      if (lost_workers.count(kv.first)) continue;
      if (inflight_by_worker.count(kv.first)) continue;
      // Skip workers that can't run this job's flavor (bundle nodes match all).
      if (!WorkerRunsKind(kv.second.capabilities, required_kind)) continue;
      // Direct workers advertise a control_endpoint; reverse workers advertise
      // none but are reachable via the heartbeat pull path.
      if (!endpoint_of(workers, kv.first).empty() || is_reverse(workers, kv.first))
        free_workers.push_back(kv.first);
    }

    while (!pending.empty() && !free_workers.empty()) {
      CoordShard sh = pending.front();
      pending.pop_front();
      // Select a worker (preserving initial Telco partition affinity or region score),
      // else the first free one.
      std::size_t pick = 0;
      const bool honor_preferred = (sh.attempt == 0 && !sh.preferred_worker.empty());
      if (region_aware || honor_preferred) {
        double best = -1e300;
        for (std::size_t i = 0; i < free_workers.size(); ++i) {
          double sc =
              WorkerDispatchScore(workers[free_workers[i]].capabilities, sh, target_region,
                                  region_aware, job.region_topology);
          if (honor_preferred && free_workers[i] == sh.preferred_worker) {
            sc += 100000.0;
          }
          if (sc > best) {
            best = sc;
            pick = i;
          }
        }
      }
      const std::string wid = free_workers[pick];
      free_workers.erase(free_workers.begin() + pick);

      const std::string ep = endpoint_of(workers, wid);
      const bool pure_reverse = is_reverse(workers, wid);
      const bool reverse_capable = pure_reverse || is_auto(workers, wid);
      if (ep.empty() && !reverse_capable) {
        dispatch_failures.push_back("E_STARTSHARD_NO_ENDPOINT worker=" + wid + " shard=" + sh.shard_id);
        sh.attempt += 1;
        if (sh.attempt <= job.max_shard_retries) pending.push_back(sh);
        continue;
      }
      // Build the per-shard args from the job's base args.
      Value args = job.base_args.is_object() ? job.base_args : Value::Object();
      args.set("count", Value::Int(sh.packet_count));
      args.set("role", Value::Str("standalone"));
      args.set("_worker_id", Value::Str(wid));
      args.set("_leader_epoch", Value::Int(job.leader_epoch));
      args.set("db_port", Value::Int(job.db_port));
      if (job.ipfix_enabled) {
        args.set("ipfix_enabled", Value::Bool(true));
        args.set("ipfix_collector", Value::Str(job.ipfix_collector));
        args.set("ipfix_port", Value::Int(job.ipfix_port));
        args.set("ipfix_sample_rate", Value::Int(job.ipfix_sample_rate));
        args.set("ipfix_netflow_v9", Value::Bool(job.ipfix_netflow_v9));
        args.set("ipfix_domain_id", Value::Int(job.ipfix_domain_id));
        args.set("ipfix_export_interval_ms", Value::Int(job.ipfix_export_interval_ms));
      }
      if (sh.is_telco) {
        args.set("worker", Value::Str("telco"));
        args.set("telco", sh.telco_spec.ToJson());
        args.set("start_idx", Value::Int(sh.telco_spec.range.start_idx));
        args.set("sub_count", Value::Int(sh.telco_spec.range.count));
        args.set("protocol", Value::Str(sh.telco_spec.protocol));
        args.set("target_cps", Value::Int(sh.telco_spec.target_cps));
        args.set("base_vlan_s", Value::Int(sh.telco_spec.range.base_vlan_s));
        args.set("base_vlan_c", Value::Int(sh.telco_spec.range.base_vlan_c));
        args.set("base_ip", Value::Int(sh.telco_spec.range.base_ip));
        args.set("gateway_ip", Value::Int(sh.telco_spec.range.gateway_ip));
        if (job.telco_duration_ms > 0) {
          args.set("duration_ms", Value::Int(job.telco_duration_ms));
        }
        if (job.sctp_rate > 0) args.set("sctp_rate", Value::Int(job.sctp_rate));
        if (job.diameter_rate > 0) args.set("diameter_rate", Value::Int(job.diameter_rate));
        if (job.sip_rate > 0) args.set("sip_rate", Value::Int(job.sip_rate));
        if (job.enable_srtp) args.set("enable_srtp", Value::Bool(true));
        if (job.teid_start > 0) args.set("teid_start", Value::Int(job.teid_start));
        if (job.teid_count > 0) args.set("teid_count", Value::Int(job.teid_count));
        args.set("qfi", Value::Int(job.qfi));
      }
      DispatchOutcome d;
      bool via_reverse = false;
      if (pure_reverse) {
        d = commander_->DispatchReverse(wid, sh.shard_id, job_id, args.dump(), sh.packet_count,
                                        timeout_ms);
        via_reverse = true;
      } else {
        // Direct-preferred (a direct worker, or an auto worker with an endpoint).
        d = commander_->Dispatch(ep, sh.shard_id, job_id, args.dump(), sh.packet_count, timeout_ms);
        if (!d.started && is_auto(workers, wid)) {
          // Auto-fallback: the direct RPC failed (endpoint unreachable, likely
          // NAT) -> deliver over the heartbeat pull path instead.
          const DispatchOutcome fb = commander_->DispatchReverse(
              wid, sh.shard_id, job_id, args.dump(), sh.packet_count, timeout_ms);
          if (fb.started) {
            d = fb;
            via_reverse = true;
            dispatch_failures.push_back("W_DIRECT_FALLBACK_REVERSE worker=" + wid + " shard=" +
                                        sh.shard_id);
          }
        }
      }
      if (d.started) {
        sh.worker_id = wid;
        inflight_by_worker[wid] = sh;
        inflight_by_sid[sh.shard_id] = sh;
        if (via_reverse) reverse_dispatch_ms[sh.shard_id] = now;
        track_active(sh.shard_id,
                     ActiveShardTarget{wid, ep, via_reverse, is_auto(workers, wid), job.leader_epoch});
      } else {
        dispatch_failures.push_back(d.message.empty()
                                        ? ("E_STARTSHARD_REJECTED worker=" + wid + " shard=" + sh.shard_id)
                                        : d.message);
        sh.attempt += 1;
        if (sh.attempt <= job.max_shard_retries) pending.push_back(sh);
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
      const std::string wid = sh == inflight_by_sid.end() ? std::string() : sh->second.worker_id;
      const std::string ep = wid.empty() ? std::string() : endpoint_of(workers, wid);
      bool stopped = false;
      if (reverse_dispatch_ms.count(sid)) {
        // Pull-delivered shard (reverse or auto-fallback): queue the stop; the
        // worker pulls it on the next heartbeat.
        stopped = wid.empty() ? false : commander_->StopShardReverse(wid, sid, job.leader_epoch);
      } else if (!ep.empty()) {
        stopped = commander_->StopShard(ep, sid, job.leader_epoch);
      }
      if (stopped) {
        if (converged_stop && !reverse_dispatch_ms.count(sid) && !ep.empty() &&
            !view_->ShardReported(sid)) {
          const ProbeOutcome probe = commander_->Probe(ep, wid);
          if (!probe.stats_json.empty() && probe.stats_json != "{}") {
            view_->SetShardStats(sid, probe.stats_json);
          }
          done_shards.insert(sid);
          inflight_by_sid.erase(sid);
          if (!wid.empty()) inflight_by_worker.erase(wid);
        }
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

  if (const Value* nt = agg_field("numeric_totals"); nt && nt->is_object()) {
    auto ntdbl = [&](const char* k) -> double {
      const Value* v = nt->find(k);
      return v ? v->as_double(0.0) : 0.0;
    };
    if (nt->find("ipfix_exported_packets") || nt->find("ipfix_exported_records")) {
      Value ipfix_obj = Value::Object();
      ipfix_obj.set("exported_packets", Value::Int(static_cast<std::int64_t>(ntdbl("ipfix_exported_packets"))));
      ipfix_obj.set("exported_records", Value::Int(static_cast<std::int64_t>(ntdbl("ipfix_exported_records"))));
      snap.set("ipfix_telemetry", std::move(ipfix_obj));
    }
    if (is_telco) {
      Value t_obj = Value::Object();
      t_obj.set("active_sessions", Value::Int(static_cast<std::int64_t>(ntdbl("telco_active_sessions"))));
      t_obj.set("established_sessions", Value::Int(static_cast<std::int64_t>(ntdbl("telco_established_sessions"))));
      t_obj.set("failed_sessions", Value::Int(static_cast<std::int64_t>(ntdbl("telco_failed_sessions"))));
      t_obj.set("retransmit_count", Value::Int(static_cast<std::int64_t>(ntdbl("telco_retransmit_count"))));
      snap.set("telco_telemetry", std::move(t_obj));
    }
  }

  if (is_telco) {
    snap.set("is_telco", Value::Bool(true));
    snap.set("telco_protocol", Value::Str(job.telco_protocol));
    snap.set("telco_subscribers", Value::Int(total_workload));
    snap.set("cluster_db_port", Value::Int(job.db_port));
    snap.set("telco_routing_prefixes", Value::Int(job.telco_pool_profile.RouteCount()));
    if (!job.telco_pool_profile.name.empty()) {
      snap.set("telco_pool_profile", Value::Str(job.telco_pool_profile.name));
    }
  }
  if (!target_region.empty()) {
    snap.set("resolved_target_region", Value::Str(target_region));
  }

  if (converged_stop) {
    snap.set("converged_stop", Value::Bool(true));
  }

  // Başarı ölçütü: TÜM shard'lar gerçekten tamamlandı mı (done_shards) veya
  // kapalı çevrim (converged_stop) ile temizce durduruldu mu.
  // Yeniden deneme limitini aşıp düşen shard'lar done_shards'a girmez, dolayısıyla
  // kuyruklar boşalsa bile job başarısız sayılır. dispatch_failures'a bakmıyoruz:
  // içinde W_DIRECT_FALLBACK_REVERSE gibi UYARILAR da var (job yine de başarılı);
  // gerçek başarısızlık zaten done_shards eksikliği olarak yansır.
  const bool all_done = (done_shards.size() == all_sids.size());
  const bool converged_ok = converged_stop && unresolved.empty();
  result.rc = ((all_done && pending.empty() && inflight_by_sid.empty()) || converged_ok) ? 0 : 1;
  result.snapshot = std::move(snap);
  return result;
}

}  // namespace samurai::control
