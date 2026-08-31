#include "control_client.hpp"

#include <string>
#include <vector>

#include <zmq.h>

#include "auth.hpp"  // SplitEndpoints
#include "json.hpp"

namespace samurai::control {

namespace {

using samurai::core::json::Value;

Value BuildMeta(const std::string& cluster_secret, const std::string& tenant) {
  Value meta = Value::Object();
  if (!cluster_secret.empty()) meta.set("x-cluster-secret", Value::Str(cluster_secret));
  if (!tenant.empty()) meta.set("x-tenant-namespace", Value::Str(tenant));
  return meta;
}

wire::Response TransportError(const std::string& msg) {
  wire::Response r;
  r.ok = false;
  r.status = wire::kStatusError;
  r.error = msg;
  r.body = Value::Object();
  return r;
}

// One request/response round trip on a fresh ZMQ_REQ socket. Returns false on
// any transport failure (connect/send/timeout), leaving `out` untouched. When
// `curve` is non-null and complete, the socket is a CURVE client.
bool CallOnce(void* ctx, const std::string& endpoint, const std::string& request,
              int timeout_ms, wire::Response& out, const CurveClientCreds* curve) {
  void* sock = zmq_socket(ctx, ZMQ_REQ);
  if (!sock) return false;
  int linger = 0;
  zmq_setsockopt(sock, ZMQ_LINGER, &linger, sizeof(linger));
  zmq_setsockopt(sock, ZMQ_RCVTIMEO, &timeout_ms, sizeof(timeout_ms));
  zmq_setsockopt(sock, ZMQ_SNDTIMEO, &timeout_ms, sizeof(timeout_ms));
  if (curve && curve->ok()) {
    if (zmq_setsockopt(sock, ZMQ_CURVE_SERVERKEY, curve->server_public.data(),
                       curve->server_public.size()) != 0 ||
        zmq_setsockopt(sock, ZMQ_CURVE_PUBLICKEY, curve->client_public.data(),
                       curve->client_public.size()) != 0 ||
        zmq_setsockopt(sock, ZMQ_CURVE_SECRETKEY, curve->client_secret.data(),
                       curve->client_secret.size()) != 0) {
      zmq_close(sock);
      return false;
    }
  }

  bool ok = false;
  if (zmq_connect(sock, endpoint.c_str()) == 0) {
    if (zmq_send(sock, request.data(), request.size(), 0) >= 0) {
      zmq_msg_t msg;
      zmq_msg_init(&msg);
      if (zmq_msg_recv(&msg, sock, 0) >= 0) {
        const std::string payload(static_cast<char*>(zmq_msg_data(&msg)), zmq_msg_size(&msg));
        ok = wire::ParseResponse(payload, out);
      }
      zmq_msg_close(&msg);
    }
  }
  zmq_close(sock);
  return ok;
}

}  // namespace

// --- SlaveControlClient ----------------------------------------------------

SlaveControlClient::SlaveControlClient(const std::string& endpoints,
                                       const std::string& cluster_secret,
                                       const std::string& tenant_namespace, int timeout_ms)
    : endpoints_(SplitEndpoints(endpoints)),
      cluster_secret_(cluster_secret),
      tenant_namespace_(tenant_namespace),
      timeout_ms_(timeout_ms > 0 ? timeout_ms : 3000) {
  ctx_ = zmq_ctx_new();
}

SlaveControlClient::~SlaveControlClient() {
  if (ctx_) {
    zmq_ctx_term(ctx_);
    ctx_ = nullptr;
  }
}

bool SlaveControlClient::set_curve_client(const std::string& server_public_key) {
  if (server_public_key.empty()) return false;
  const CurveKeypair kp = GenerateCurveKeypair();
  if (!kp.ok) return false;
  curve_.server_public = server_public_key;
  curve_.client_public = kp.public_key;
  curve_.client_secret = kp.secret_key;
  return true;
}

wire::Response SlaveControlClient::CallWithFailover(const std::string& method, const Value& body) {
  if (!ok()) return TransportError("no endpoint available");
  const std::string request = wire::BuildRequest(method, BuildMeta(cluster_secret_, tenant_namespace_), body);
  const std::size_t n = endpoints_.size();
  const std::size_t start = last_idx_ % n;
  for (std::size_t i = 0; i < n; ++i) {
    const std::size_t idx = (start + i) % n;
    wire::Response resp;
    if (CallOnce(ctx_, endpoints_[idx], request, timeout_ms_, resp, &curve_)) {
      last_idx_ = idx;
      return resp;
    }
  }
  return TransportError("no endpoint available");
}

wire::Response SlaveControlClient::RegisterWorker(
    const std::string& worker_id, const std::string& hostname,
    const std::map<std::string, std::string>& capabilities) {
  Value body = Value::Object();
  body.set("worker_id", Value::Str(worker_id));
  body.set("hostname", Value::Str(hostname));
  Value caps = Value::Object();
  for (const auto& kv : capabilities) caps.set(kv.first, Value::Str(kv.second));
  body.set("capabilities", std::move(caps));
  return CallWithFailover(wire::kRegisterWorker, body);
}

wire::Response SlaveControlClient::Heartbeat(const std::string& worker_id, long long uptime_ms,
                                             double cpu_pct, double mem_pct, double gpu_util_pct,
                                             const std::string* active_shard_id) {
  Value body = Value::Object();
  body.set("worker_id", Value::Str(worker_id));
  body.set("uptime_ms", Value::Int(uptime_ms));
  body.set("cpu_pct", Value::Double(cpu_pct));
  body.set("mem_pct", Value::Double(mem_pct));
  body.set("gpu_util_pct", Value::Double(gpu_util_pct));
  if (active_shard_id) body.set("active_shard_id", Value::Str(*active_shard_id));
  return CallWithFailover(wire::kHeartbeat, body);
}

wire::Response SlaveControlClient::ReportStats(const std::string& worker_id,
                                               const std::string& shard_id,
                                               const std::string& stats_json,
                                               long long timestamp_ms) {
  Value body = Value::Object();
  body.set("worker_id", Value::Str(worker_id));
  body.set("shard_id", Value::Str(shard_id));
  body.set("stats_json", Value::Str(stats_json.empty() ? "{}" : stats_json));
  body.set("timestamp_ms", Value::Int(timestamp_ms));
  return CallWithFailover(wire::kReportStats, body);
}

// --- WorkerControlClient ---------------------------------------------------

WorkerControlClient::WorkerControlClient(const std::string& endpoint,
                                         const std::string& cluster_secret,
                                         const std::string& tenant_namespace, int timeout_ms)
    : endpoint_(endpoint),
      cluster_secret_(cluster_secret),
      tenant_namespace_(tenant_namespace),
      timeout_ms_(timeout_ms > 0 ? timeout_ms : 5000) {
  ctx_ = zmq_ctx_new();
}

WorkerControlClient::~WorkerControlClient() {
  if (ctx_) {
    zmq_ctx_term(ctx_);
    ctx_ = nullptr;
  }
}

bool WorkerControlClient::set_curve_client(const std::string& server_public_key) {
  if (server_public_key.empty()) return false;
  const CurveKeypair kp = GenerateCurveKeypair();
  if (!kp.ok) return false;
  curve_.server_public = server_public_key;
  curve_.client_public = kp.public_key;
  curve_.client_secret = kp.secret_key;
  return true;
}

wire::Response WorkerControlClient::Call(const std::string& method, const Value& body) {
  if (!ok()) return TransportError("worker endpoint is empty");
  const std::string request = wire::BuildRequest(method, BuildMeta(cluster_secret_, tenant_namespace_), body);
  wire::Response resp;
  if (CallOnce(ctx_, endpoint_, request, timeout_ms_, resp, &curve_)) return resp;
  return TransportError("E_RPC endpoint=" + endpoint_);
}

wire::Response WorkerControlClient::StartShard(const std::string& shard_id,
                                               const std::string& job_id,
                                               const std::string& args_json,
                                               long long packet_count, long long timeout_ms) {
  Value body = Value::Object();
  body.set("shard_id", Value::Str(shard_id));
  body.set("job_id", Value::Str(job_id));
  body.set("args_json", Value::Str(args_json.empty() ? "{}" : args_json));
  body.set("packet_count", Value::Int(packet_count));
  body.set("timeout_ms", Value::Int(timeout_ms));
  return Call(wire::kStartShard, body);
}

wire::Response WorkerControlClient::StopShard(const std::string& shard_id, bool graceful,
                                             std::int64_t leader_epoch) {
  Value body = Value::Object();
  body.set("shard_id", Value::Str(shard_id));
  body.set("graceful", Value::Bool(graceful));
  body.set("_leader_epoch", Value::Int(leader_epoch));
  return Call(wire::kStopShard, body);
}

wire::Response WorkerControlClient::GetWorkerStatus(const std::string& worker_id) {
  Value body = Value::Object();
  body.set("worker_id", Value::Str(worker_id));
  return Call(wire::kGetWorkerStatus, body);
}

wire::Response WorkerControlClient::AbortJob(const std::string& job_id, const std::string& reason) {
  Value body = Value::Object();
  body.set("job_id", Value::Str(job_id));
  body.set("reason", Value::Str(reason));
  return Call(wire::kAbortJob, body);
}

wire::Response WorkerControlClient::ForceSync(const std::string& worker_id) {
  Value body = Value::Object();
  body.set("worker_id", Value::Str(worker_id));
  return Call(wire::kForceSync, body);
}

}  // namespace samurai::control
