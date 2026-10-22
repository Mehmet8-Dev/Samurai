#include "master_adapters.hpp"

#include <string>

#include "control_client.hpp"
#include "control_wire.hpp"

namespace samurai::control {

namespace {
using samurai::core::json::Value;

std::string BodyStr(const wire::Response& r, const char* key) {
  const Value* v = r.body.find(key);
  return v ? v->as_string("") : "";
}
bool BodyBool(const wire::Response& r, const char* key) {
  const Value* v = r.body.find(key);
  return v && v->as_bool();
}

// Per-worker direct-channel CURVE: a slave started with --gen-control-curve
// advertises its inbound control server's public key in capabilities. Look it up
// so the master encrypts the direct RPC toward that worker. Empty => plaintext.
std::string CurveByEndpoint(Servicer* s, const std::string& endpoint) {
  if (!s || endpoint.empty()) return "";
  for (const auto& w : s->SnapshotWorkers()) {
    const auto ep = w.capabilities.find("control_endpoint");
    if (ep != w.capabilities.end() && ep->second == endpoint) {
      const auto pub = w.capabilities.find("control_curve_public");
      if (pub != w.capabilities.end()) return pub->second;
    }
  }
  return "";
}
std::string CurveByWorker(Servicer* s, const std::string& worker_id) {
  if (!s || worker_id.empty()) return "";
  for (const auto& w : s->SnapshotWorkers()) {
    if (w.worker_id == worker_id) {
      const auto pub = w.capabilities.find("control_curve_public");
      if (pub != w.capabilities.end()) return pub->second;
    }
  }
  return "";
}
}  // namespace

// --- ServicerMasterView ----------------------------------------------------

std::vector<WorkerInfo> ServicerMasterView::Workers() {
  std::vector<WorkerInfo> out;
  for (auto& w : servicer_->SnapshotWorkers()) {
    WorkerInfo wi;
    wi.worker_id = w.worker_id;
    wi.capabilities = std::move(w.capabilities);
    wi.last_heartbeat_ms = w.last_heartbeat_ms;
    wi.active_shard_id = std::move(w.active_shard_id);
    out.push_back(std::move(wi));
  }
  return out;
}
bool ServicerMasterView::ShardReported(const std::string& shard_id) {
  return servicer_->HasShardStats(shard_id);
}
std::string ServicerMasterView::GetShardStats(const std::string& shard_id) {
  return servicer_->GetShardStatsRaw(shard_id);
}
void ServicerMasterView::SetShardStats(const std::string& shard_id, const std::string& stats_json) {
  servicer_->SetShardStatsRaw(shard_id, stats_json);
}

// --- ClientWorkerCommander -------------------------------------------------

DispatchOutcome ClientWorkerCommander::Dispatch(const std::string& endpoint,
                                                const std::string& shard_id,
                                                const std::string& job_id,
                                                const std::string& args_json,
                                                std::int64_t packet_count,
                                                std::int64_t timeout_ms) {
  WorkerControlClient wc(endpoint, cluster_secret_, tenant_namespace_, timeout_ms_);
  const std::string cpub = CurveByEndpoint(servicer_, endpoint);
  if (!cpub.empty()) (void)wc.set_curve_client(cpub);
  const wire::Response r = wc.StartShard(shard_id, job_id, args_json, packet_count, timeout_ms);
  DispatchOutcome out;
  if (!r.ok) {
    out.started = false;
    out.message = "E_STARTSHARD_RPC worker_endpoint=" + endpoint + " shard=" + shard_id +
                  " error=" + r.error;
    return out;
  }
  out.started = BodyBool(r, "started");
  if (out.started) {
    out.message = "Dispatched shard " + shard_id + " -> " + endpoint;
  } else {
    out.message = "E_STARTSHARD_REJECTED shard=" + shard_id + " error=" + BodyStr(r, "error");
  }
  return out;
}

ProbeOutcome ClientWorkerCommander::Probe(const std::string& endpoint,
                                          const std::string& worker_id) {
  const int p_timeout = timeout_ms_ > 0 ? std::min(timeout_ms_, 1000) : 1000;
  WorkerControlClient wc(endpoint, cluster_secret_, tenant_namespace_, p_timeout);
  const std::string cpub = CurveByWorker(servicer_, worker_id);
  if (!cpub.empty()) (void)wc.set_curve_client(cpub);
  const wire::Response r = wc.GetWorkerStatus(worker_id);
  ProbeOutcome out;
  if (!r.ok) return out;  // empty state -> treated as not-done
  out.state = BodyStr(r, "state");
  out.active_shard_id = BodyStr(r, "active_shard_id");
  const std::string sj = BodyStr(r, "stats_json");
  out.stats_json = sj.empty() ? "{}" : sj;
  return out;
}

bool ClientWorkerCommander::StopShard(const std::string& endpoint, const std::string& shard_id,
                                      std::int64_t leader_epoch) {
  WorkerControlClient wc(endpoint, cluster_secret_, tenant_namespace_, timeout_ms_);
  const std::string cpub = CurveByEndpoint(servicer_, endpoint);
  if (!cpub.empty()) (void)wc.set_curve_client(cpub);
  const wire::Response r = wc.StopShard(shard_id, true, leader_epoch);
  return r.ok && BodyBool(r, "stopped");
}

DispatchOutcome ClientWorkerCommander::DispatchReverse(const std::string& worker_id,
                                                       const std::string& shard_id,
                                                       const std::string& job_id,
                                                       const std::string& args_json,
                                                       std::int64_t packet_count,
                                                       std::int64_t timeout_ms) {
  DispatchOutcome out;
  if (!servicer_) {
    out.started = false;
    out.message = "E_STARTSHARD_NO_SERVICER worker=" + worker_id + " shard=" + shard_id;
    return out;
  }
  PendingCommand cmd;
  cmd.type = "start";
  cmd.shard_id = shard_id;
  cmd.job_id = job_id;
  cmd.args_json = args_json.empty() ? "{}" : args_json;
  cmd.packet_count = packet_count;
  cmd.timeout_ms = timeout_ms;
  servicer_->EnqueueCommand(worker_id, cmd);
  // Optimistic accept: the worker pulls + acks on its next heartbeat; completion
  // is confirmed later via ReportStats (ShardReported).
  out.started = true;
  out.message = "Enqueued reverse shard " + shard_id + " -> " + worker_id;
  return out;
}

bool ClientWorkerCommander::StopShardReverse(const std::string& worker_id,
                                             const std::string& shard_id,
                                             std::int64_t leader_epoch) {
  if (!servicer_) return false;
  PendingCommand cmd;
  cmd.type = "stop";
  cmd.shard_id = shard_id;
  cmd.leader_epoch = leader_epoch;
  servicer_->EnqueueCommand(worker_id, cmd);
  return true;  // best-effort enqueue; delivered on the worker's next heartbeat
}

}  // namespace samurai::control
