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
}  // namespace

// --- ServicerMasterView ----------------------------------------------------

std::vector<WorkerInfo> ServicerMasterView::Workers() {
  std::vector<WorkerInfo> out;
  for (auto& w : servicer_->SnapshotWorkers()) {
    WorkerInfo wi;
    wi.worker_id = w.worker_id;
    wi.capabilities = std::move(w.capabilities);
    wi.last_heartbeat_ms = w.last_heartbeat_ms;
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
  WorkerControlClient wc(endpoint, cluster_secret_, tenant_namespace_, timeout_ms_);
  const wire::Response r = wc.GetWorkerStatus(worker_id);
  ProbeOutcome out;
  if (!r.ok) return out;  // empty state -> treated as not-done
  out.state = BodyStr(r, "state");
  out.active_shard_id = BodyStr(r, "active_shard_id");
  const std::string sj = BodyStr(r, "stats_json");
  out.stats_json = sj.empty() ? "{}" : sj;
  return out;
}

bool ClientWorkerCommander::StopShard(const std::string& endpoint, const std::string& shard_id) {
  WorkerControlClient wc(endpoint, cluster_secret_, tenant_namespace_, timeout_ms_);
  const wire::Response r = wc.StopShard(shard_id, true);
  return r.ok && BodyBool(r, "stopped");
}

}  // namespace samurai::control
