#include "worker_shard_service.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>

namespace samurai::control {

namespace {

using samurai::core::json::Value;

double NowSec() {
  using namespace std::chrono;
  return duration_cast<duration<double>>(steady_clock::now().time_since_epoch()).count();
}

std::int64_t NowNs() {
  using namespace std::chrono;
  return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

std::string StrField(const Value& v, const char* key) {
  const Value* f = v.find(key);
  return f ? f->as_string("") : "";
}

Value Str(const std::string& s) { return Value::Str(s); }

}  // namespace

WorkerShardService::WorkerShardService(const std::string& worker_id, ShardRunner* runner)
    : worker_id_(worker_id), runner_(runner) {}

WorkerShardService::~WorkerShardService() {
  for (auto& t : monitors_) {
    if (t.joinable()) t.join();
  }
}

void WorkerShardService::RefreshWorkerStateLocked() {
  std::string active_sid;
  for (const auto& kv : shard_runs_) {
    if (kv.second.running) {
      active_sid = kv.first;
      break;
    }
  }
  if (!active_sid.empty()) {
    worker_state_ = "running";
    worker_active_shard_ = active_sid;
    return;
  }
  const StatusRec* latest = nullptr;
  double latest_ts = -1.0;
  for (const auto& kv : shard_status_) {
    if (kv.second.updated_ts >= latest_ts) {
      latest_ts = kv.second.updated_ts;
      latest = &kv.second;
    }
  }
  if (latest == nullptr) {
    worker_state_ = "idle";
    worker_active_shard_ = "";
    return;
  }
  worker_state_ = latest->state.empty() ? "idle" : latest->state;
  worker_active_shard_ = latest->active_shard_id;
}

std::string WorkerShardService::FinalizeStats(const std::string& shard_id, const ShardRec& rec,
                                              double started_ts, int exitcode,
                                              const char* status_override) const {
  Value o = Value::Object();
  o.set("worker_id", Str(worker_id_));
  o.set("shard_id", Str(shard_id));
  o.set("status", Str(status_override ? status_override : (exitcode == 0 ? "ok" : "error")));
  o.set("exitcode", Value::Int(exitcode));
  o.set("duration_s", Value::Double(std::max(0.0, NowSec() - started_ts)));
  o.set("progress", Value::Int(rec.run ? rec.run->Progress() : 0));
  o.set("sent", Value::Int(rec.run ? rec.run->Sent() : 0));
  o.set("errors", Value::Int(rec.run ? rec.run->Errors() : 0));
  o.set("leader_epoch", Value::Int(rec.leader_epoch));
  return o.dump();
}

void WorkerShardService::MonitorRuntime(const std::string& shard_id, std::int64_t runtime_id) {
  std::shared_ptr<ShardRun> run;
  ShardRec rec_copy;
  double started_ts = NowSec();
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = shard_runs_.find(shard_id);
    if (it != shard_runs_.end()) {
      run = it->second.run;
      rec_copy = it->second;
      started_ts = it->second.started_ts;
    }
  }
  if (run) run->Join();

  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = shard_runs_.find(shard_id);
    // Bail if the shard was superseded/removed (e.g. StopShard handled it).
    if (it != shard_runs_.end() && it->second.runtime_id == runtime_id) {
      const int exitcode = run ? run->ExitCode() : 1;
      const std::string stats = FinalizeStats(shard_id, it->second, started_ts, exitcode, nullptr);
      shard_runs_.erase(it);
      StatusRec s;
      s.state = exitcode == 0 ? "done" : "error";
      s.active_shard_id = "";
      s.updated_ts = NowSec();
      s.stats_json = stats;
      shard_status_[shard_id] = std::move(s);
      RefreshWorkerStateLocked();
    }
  }
  active_monitors_.fetch_sub(1);
  idle_cv_.notify_all();
}

void WorkerShardService::WaitForShardIdle(const std::string& /*shard_id*/) {
  std::unique_lock<std::mutex> lk(mu_);
  idle_cv_.wait(lk, [this]() { return active_monitors_.load() == 0; });
}

Value WorkerShardService::StartShard(const Value& body, const RpcContext& /*ctx*/) {
  Value out = Value::Object();
  const std::string args_text = StrField(body, "args_json").empty() ? "{}" : StrField(body, "args_json");
  const auto parsed = samurai::core::json::Parse(args_text);
  if (!parsed.ok || !parsed.value.is_object()) {
    out.set("started", Value::Bool(false));
    out.set("error", Str("invalid args_json"));
    return out;
  }
  const Value& args = parsed.value;
  const Value* ep = args.find("_leader_epoch");
  const std::int64_t req_epoch = ep ? ep->as_int(0) : 0;
  const std::string sid = StrField(body, "shard_id");
  const std::string job_id = StrField(body, "job_id");

  std::int64_t runtime_id = 0;
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (req_epoch < leader_epoch_max_seen_) {
      out.set("started", Value::Bool(false));
      out.set("error", Str("stale leader epoch: got=" + std::to_string(req_epoch) +
                           " min=" + std::to_string(leader_epoch_max_seen_)));
      return out;
    }
    if (req_epoch > leader_epoch_max_seen_) leader_epoch_max_seen_ = req_epoch;

    auto existing = shard_runs_.find(sid);
    if (existing != shard_runs_.end() && existing->second.running) {
      out.set("started", Value::Bool(false));
      out.set("error", Str("shard already running"));
      return out;
    }

    std::shared_ptr<ShardRun> run = runner_ ? runner_->Start(sid, args) : nullptr;
    if (!run) {
      StatusRec s;
      s.state = "error";
      s.updated_ts = NowSec();
      shard_status_[sid] = std::move(s);
      RefreshWorkerStateLocked();
      out.set("started", Value::Bool(false));
      out.set("error", Str("start failed"));
      return out;
    }

    runtime_id = NowNs();
    ShardRec rec;
    rec.run = run;
    rec.runtime_id = runtime_id;
    rec.running = true;
    rec.job_id = job_id;
    rec.leader_epoch = req_epoch;
    rec.started_ts = NowSec();
    shard_runs_[sid] = std::move(rec);

    int active_count = 0;
    for (const auto& kv : shard_runs_) {
      if (kv.second.running) ++active_count;
    }
    StatusRec s;
    s.state = active_count > 1 ? "queued" : "running";
    s.active_shard_id = sid;
    s.updated_ts = NowSec();
    s.stats_json = "{}";
    shard_status_[sid] = std::move(s);
    RefreshWorkerStateLocked();
    active_monitors_.fetch_add(1);
  }

  monitors_.emplace_back(&WorkerShardService::MonitorRuntime, this, sid, runtime_id);

  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = shard_status_.find(sid);
    if (it != shard_status_.end() && it->second.state == "queued") {
      it->second.state = "running";
      it->second.updated_ts = NowSec();
      RefreshWorkerStateLocked();
    }
  }

  out.set("started", Value::Bool(true));
  out.set("error", Str(""));
  return out;
}

Value WorkerShardService::StopShard(const Value& body, const RpcContext& /*ctx*/) {
  Value out = Value::Object();
  const std::string sid = StrField(body, "shard_id");

  ShardRec rec;
  bool had = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = shard_runs_.find(sid);
    if (it != shard_runs_.end() && it->second.running) {
      rec = it->second;      // copy (shared_ptr run)
      shard_runs_.erase(it); // remove so the monitor bails on finalize
      had = true;
    }
  }
  if (!had || !rec.run) {
    out.set("stopped", Value::Bool(false));
    return out;
  }

  if (rec.run->IsAlive()) rec.run->Terminate();
  rec.run->Join();
  const std::string stats = FinalizeStats(sid, rec, rec.started_ts, rec.run->ExitCode(), "stopped");
  {
    std::lock_guard<std::mutex> lk(mu_);
    StatusRec s;
    s.state = "error";
    s.active_shard_id = "";
    s.updated_ts = NowSec();
    s.stats_json = stats;
    shard_status_[sid] = std::move(s);
    RefreshWorkerStateLocked();
  }
  out.set("stopped", Value::Bool(true));
  return out;
}

Value WorkerShardService::GetWorkerStatus(const Value& body, const RpcContext& /*ctx*/) {
  const std::string wid = StrField(body, "worker_id");
  Value out = Value::Object();
  if (!wid.empty() && wid != worker_id_) {
    out.set("worker_id", Str(wid));
    out.set("state", Str("disconnected"));
    out.set("active_shard_id", Str(""));
    out.set("stats_json", Str("{}"));
    out.set("last_heartbeat_ms", Value::Int(0));
    return out;
  }
  std::string state, active_sid, stats_json = "{}";
  {
    std::lock_guard<std::mutex> lk(mu_);
    state = worker_state_.empty() ? "idle" : worker_state_;
    active_sid = worker_active_shard_;
    if (!active_sid.empty()) {
      auto it = shard_status_.find(active_sid);
      if (it != shard_status_.end() && !it->second.stats_json.empty()) stats_json = it->second.stats_json;
    } else if (!shard_status_.empty()) {
      const StatusRec* latest = nullptr;
      double latest_ts = -1.0;
      for (const auto& kv : shard_status_) {
        if (kv.second.updated_ts >= latest_ts) {
          latest_ts = kv.second.updated_ts;
          latest = &kv.second;
        }
      }
      if (latest && !latest->stats_json.empty()) stats_json = latest->stats_json;
    }
  }
  using namespace std::chrono;
  const std::int64_t now_ms =
      duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
  out.set("worker_id", Str(worker_id_));
  out.set("state", Str(state));
  out.set("active_shard_id", Str(active_sid));
  out.set("stats_json", Str(stats_json));
  out.set("last_heartbeat_ms", Value::Int(now_ms));
  return out;
}

// --- inert (non-worker-role) RPCs -----------------------------------------

Value WorkerShardService::RegisterWorker(const Value&, const RpcContext&) {
  Value o = Value::Object();
  o.set("accepted", Value::Bool(false));
  o.set("cluster_id", Str(""));
  o.set("rejection_reason", Str("not a master"));
  return o;
}
Value WorkerShardService::Heartbeat(const Value&, const RpcContext&) {
  Value o = Value::Object();
  o.set("acknowledged", Value::Bool(false));
  o.set("command", Str("register"));
  return o;
}
Value WorkerShardService::ReportStats(const Value&, const RpcContext&) {
  Value o = Value::Object();
  o.set("received", Value::Bool(false));
  return o;
}
Value WorkerShardService::AbortJob(const Value&, const RpcContext&) {
  Value o = Value::Object();
  o.set("aborted", Value::Bool(false));
  o.set("workers_notified", Value::Int(0));
  return o;
}
Value WorkerShardService::ForceSync(const Value&, const RpcContext&) {
  Value o = Value::Object();
  o.set("stats_json", Str("{}"));
  o.set("logs_json", Str("[]"));
  return o;
}

}  // namespace samurai::control
