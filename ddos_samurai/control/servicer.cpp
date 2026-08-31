#include "servicer.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

#include "jwt.hpp"

namespace samurai::control {

namespace {

using samurai::core::json::Value;

std::int64_t NowMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

std::string Strip(const std::string& s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

std::string StrField(const Value& v, const char* key) {
  const Value* f = v.find(key);
  return f ? f->as_string("") : "";
}

Value Str(const std::string& s) { return Value::Str(s); }

}  // namespace

Servicer::Servicer(const ServicerConfig& cfg) : cfg_(cfg) {
  cfg_.tenant_namespace = Strip(cfg_.tenant_namespace);
  cfg_.jwt_secret = Strip(cfg_.jwt_secret);
  if (cfg_.jwt_tenant_claim.empty()) cfg_.jwt_tenant_claim = "tenant_namespace";
}

void Servicer::set_leader_epoch_min(std::int64_t epoch) {
  leader_epoch_min_ = std::max<std::int64_t>(0, epoch);
}

std::size_t Servicer::worker_count() const {
  std::lock_guard<std::mutex> lk(mu_);
  return workers_.size();
}

std::vector<Servicer::WorkerSnapshot> Servicer::SnapshotWorkers() const {
  std::lock_guard<std::mutex> lk(mu_);
  std::vector<WorkerSnapshot> out;
  out.reserve(workers_.size());
  for (const auto& kv : workers_) {
    WorkerSnapshot s;
    s.worker_id = kv.second.worker_id;
    s.capabilities = kv.second.capabilities;
    s.last_heartbeat_ms = kv.second.last_heartbeat_ms;
    s.active_shard_id = kv.second.active_shard_id;
    out.push_back(std::move(s));
  }
  return out;
}

bool Servicer::HasShardStats(const std::string& shard_id) const {
  std::lock_guard<std::mutex> lk(mu_);
  return shard_stats_.find(shard_id) != shard_stats_.end();
}

std::string Servicer::GetShardStatsRaw(const std::string& shard_id) const {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = shard_stats_.find(shard_id);
  return it == shard_stats_.end() ? std::string("{}") : it->second;
}

void Servicer::SetShardStatsRaw(const std::string& shard_id, const std::string& stats_json) {
  std::lock_guard<std::mutex> lk(mu_);
  shard_stats_[shard_id] = stats_json;
}

std::string Servicer::TenantFromContext(const RpcContext& ctx) const {
  if (ctx.meta == nullptr) return "";
  const std::string raw = Strip(StrField(*ctx.meta, "x-tenant-namespace"));
  if (!raw.empty()) return raw;
  if (cfg_.jwt_secret.empty()) return "";
  const std::string secret = StrField(*ctx.meta, "x-cluster-secret");
  const auto dec = DecodeJwtHs256(secret, cfg_.jwt_secret);
  if (!dec.ok) return "";
  const Value* claim = dec.payload.find(cfg_.jwt_tenant_claim);
  return claim ? Strip(claim->as_string("")) : "";
}

bool Servicer::TenantGuard(const RpcContext& ctx) const {
  if (cfg_.tenant_namespace.empty()) return true;
  return TenantFromContext(ctx) == cfg_.tenant_namespace;
}

Value Servicer::RegisterWorker(const Value& body, const RpcContext& ctx) {
  const std::string wid = StrField(body, "worker_id");
  Value out = Value::Object();
  if (!cfg_.tenant_namespace.empty()) {
    if (TenantFromContext(ctx) != cfg_.tenant_namespace) {
      out.set("accepted", Value::Bool(false));
      out.set("cluster_id", Str(""));
      out.set("rejection_reason",
              Str("tenant namespace mismatch (expected=" + cfg_.tenant_namespace + ")"));
      return out;
    }
  }

  WorkerRec rec;
  rec.worker_id = wid;
  rec.hostname = StrField(body, "hostname");
  const Value* caps = body.find("capabilities");
  if (caps && caps->is_object()) {
    for (const auto& kv : caps->members()) rec.capabilities[kv.first] = kv.second.as_string("");
  }
  rec.tenant_namespace = cfg_.tenant_namespace.empty() ? TenantFromContext(ctx) : cfg_.tenant_namespace;
  rec.state = "idle";
  rec.active_shard_id = "";
  rec.last_heartbeat_ms = NowMs();
  rec.stats_json = "{}";
  {
    std::lock_guard<std::mutex> lk(mu_);
    workers_[wid] = std::move(rec);
  }

  out.set("accepted", Value::Bool(true));
  out.set("cluster_id", Str(cfg_.cluster_id));
  out.set("rejection_reason", Str(""));
  return out;
}

Value Servicer::Heartbeat(const Value& body, const RpcContext& ctx) {
  Value out = Value::Object();
  const std::string wid = StrField(body, "worker_id");
  if (!TenantGuard(ctx)) {
    out.set("acknowledged", Value::Bool(false));
    out.set("command", Str("register"));
    return out;
  }
  bool acknowledged = false;
  std::string command = "continue";
  PendingCommand cmd;
  bool have_cmd = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = workers_.find(wid);
    if (it != workers_.end()) {
      it->second.last_heartbeat_ms = NowMs();
      acknowledged = true;
      // Apply the worker's echoed active shard (reverse pickup ground truth)
      // before any optimistic override from a freshly delivered command below.
      const Value* echo = body.find("active_shard_id");
      if (echo) it->second.active_shard_id = echo->as_string("");
      // Drain one queued command (reverse-mode dispatch) into this response.
      auto qit = pending_cmds_.find(wid);
      if (qit != pending_cmds_.end() && !qit->second.empty()) {
        cmd = qit->second.front();
        qit->second.pop_front();
        if (qit->second.empty()) pending_cmds_.erase(qit);
        have_cmd = true;
        if (cmd.type == "start") {
          it->second.state = "running";
          it->second.active_shard_id = cmd.shard_id;
        } else if (cmd.type == "stop") {
          it->second.state = "idle";
          it->second.active_shard_id = "";
        }
      }
    } else {
      command = "register";
    }
  }
  out.set("acknowledged", Value::Bool(acknowledged));
  out.set("command", Str(command));
  if (have_cmd) {
    if (cmd.type == "start") {
      Value shard = Value::Object();
      shard.set("shard_id", Str(cmd.shard_id));
      shard.set("job_id", Str(cmd.job_id));
      shard.set("args_json", Str(cmd.args_json.empty() ? "{}" : cmd.args_json));
      shard.set("packet_count", Value::Int(cmd.packet_count));
      shard.set("timeout_ms", Value::Int(cmd.timeout_ms));
      out.set("shard", std::move(shard));
    } else if (cmd.type == "stop") {
      out.set("stop_shard", Str(cmd.shard_id));
      out.set("stop_leader_epoch", Value::Int(cmd.leader_epoch));
    }
  }
  return out;
}

void Servicer::EnqueueCommand(const std::string& worker_id, const PendingCommand& cmd) {
  std::lock_guard<std::mutex> lk(mu_);
  pending_cmds_[worker_id].push_back(cmd);
}

Value Servicer::StartShard(const Value& body, const RpcContext& ctx) {
  Value out = Value::Object();
  if (!TenantGuard(ctx)) {
    out.set("started", Value::Bool(false));
    out.set("error", Str("tenant namespace mismatch"));
    return out;
  }
  std::string wid;
  const auto parsed = samurai::core::json::Parse(StrField(body, "args_json").empty()
                                                     ? std::string("{}")
                                                     : StrField(body, "args_json"));
  if (parsed.ok && parsed.value.is_object()) {
    const Value* w = parsed.value.find("_worker_id");
    if (w) wid = w->as_string("");
  }
  const std::string sid = StrField(body, "shard_id");
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = workers_.find(wid);
    if (!wid.empty() && it != workers_.end()) {
      it->second.state = "running";
      it->second.active_shard_id = sid;
    }
  }
  out.set("started", Value::Bool(true));
  out.set("error", Str(""));
  return out;
}

Value Servicer::StopShard(const Value& body, const RpcContext& ctx) {
  Value out = Value::Object();
  if (!TenantGuard(ctx)) {
    out.set("stopped", Value::Bool(false));
    return out;
  }
  const std::string sid = StrField(body, "shard_id");
  {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& kv : workers_) {
      if (kv.second.active_shard_id == sid) {
        kv.second.state = "idle";
        kv.second.active_shard_id = "";
      }
    }
  }
  out.set("stopped", Value::Bool(true));
  return out;
}

Value Servicer::ReportStats(const Value& body, const RpcContext& ctx) {
  Value out = Value::Object();
  if (!TenantGuard(ctx)) {
    out.set("received", Value::Bool(false));
    return out;
  }
  std::string payload = StrField(body, "stats_json");
  if (payload.empty()) payload = "{}";

  if (leader_epoch_min_ > 0) {
    std::int64_t req_epoch = 0;
    const auto parsed = samurai::core::json::Parse(payload);
    if (parsed.ok && parsed.value.is_object()) {
      const Value* e = parsed.value.find("leader_epoch");
      if (e) req_epoch = e->as_int(0);
    }
    if (req_epoch > 0 && req_epoch < leader_epoch_min_) {
      out.set("received", Value::Bool(false));
      return out;
    }
  }

  const std::string wid = StrField(body, "worker_id");
  const std::string sid = StrField(body, "shard_id");
  {
    std::lock_guard<std::mutex> lk(mu_);
    shard_stats_[sid] = payload;
    auto it = workers_.find(wid);
    if (it != workers_.end()) it->second.stats_json = payload;
  }
  out.set("received", Value::Bool(true));
  return out;
}

Value Servicer::AbortJob(const Value& /*body*/, const RpcContext& ctx) {
  Value out = Value::Object();
  if (!TenantGuard(ctx)) {
    out.set("aborted", Value::Bool(false));
    out.set("workers_notified", Value::Int(0));
    return out;
  }
  std::int64_t n = 0;
  {
    std::lock_guard<std::mutex> lk(mu_);
    n = static_cast<std::int64_t>(workers_.size());
    for (auto& kv : workers_) {
      kv.second.state = "idle";
      kv.second.active_shard_id = "";
    }
  }
  out.set("aborted", Value::Bool(true));
  out.set("workers_notified", Value::Int(n));
  return out;
}

Value Servicer::GetWorkerStatus(const Value& body, const RpcContext& ctx) {
  const std::string wid = StrField(body, "worker_id");
  Value out = Value::Object();
  if (!TenantGuard(ctx)) {
    out.set("worker_id", Str(wid));
    out.set("state", Str("forbidden"));
    out.set("active_shard_id", Str(""));
    out.set("stats_json", Str("{}"));
    out.set("last_heartbeat_ms", Value::Int(0));
    return out;
  }
  WorkerRec rec;
  bool found = false;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = workers_.find(wid);
    if (it != workers_.end()) {
      rec = it->second;
      found = true;
    }
  }
  if (!found) {
    out.set("worker_id", Str(wid));
    out.set("state", Str("disconnected"));
    out.set("active_shard_id", Str(""));
    out.set("stats_json", Str("{}"));
    out.set("last_heartbeat_ms", Value::Int(0));
    return out;
  }
  out.set("worker_id", Str(wid));
  out.set("state", Str(rec.state.empty() ? "idle" : rec.state));
  out.set("active_shard_id", Str(rec.active_shard_id));
  out.set("stats_json", Str(rec.stats_json.empty() ? "{}" : rec.stats_json));
  out.set("last_heartbeat_ms", Value::Int(rec.last_heartbeat_ms));
  return out;
}

Value Servicer::ForceSync(const Value& body, const RpcContext& ctx) {
  const std::string wid = StrField(body, "worker_id");
  Value out = Value::Object();
  if (!TenantGuard(ctx)) {
    out.set("stats_json", Str("{}"));
    out.set("logs_json", Str("[]"));
    return out;
  }
  std::string stats = "{}";
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = workers_.find(wid);
    if (it != workers_.end() && !it->second.stats_json.empty()) stats = it->second.stats_json;
  }
  out.set("stats_json", Str(stats));
  out.set("logs_json", Str("[]"));
  return out;
}

}  // namespace samurai::control
