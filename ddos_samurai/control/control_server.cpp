#include "control_server.hpp"

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include <zmq.h>

#include "control_wire.hpp"
#include "json.hpp"

namespace samurai::control {

namespace {

using samurai::core::json::Value;

// Send a multipart [identity][empty][payload] ROUTER reply.
void SendReply(void* sock, const std::string& identity, const std::string& payload) {
  zmq_send(sock, identity.data(), identity.size(), ZMQ_SNDMORE);
  zmq_send(sock, "", 0, ZMQ_SNDMORE);
  zmq_send(sock, payload.data(), payload.size(), 0);
}

}  // namespace

ControlServer::ControlServer(const std::string& bind_endpoint, ControlService* service,
                             const AuthConfig& auth)
    : bind_endpoint_(bind_endpoint), service_(service), interceptor_(auth) {}

ControlServer::~ControlServer() { Stop(); }

bool ControlServer::Start() {
  if (running_.load()) return true;
  ctx_ = zmq_ctx_new();
  if (!ctx_) return false;
  sock_ = zmq_socket(ctx_, ZMQ_ROUTER);
  if (!sock_) {
    zmq_ctx_term(ctx_);
    ctx_ = nullptr;
    return false;
  }
  int linger = 0;
  zmq_setsockopt(sock_, ZMQ_LINGER, &linger, sizeof(linger));
  int rcvtimeo = 200;  // ms, so Loop can observe the stop flag
  zmq_setsockopt(sock_, ZMQ_RCVTIMEO, &rcvtimeo, sizeof(rcvtimeo));
  if (!curve_secret_.empty()) {
    // CURVE server: encrypt + authenticate. Clients must present the matching
    // public key. Fail closed if the key is rejected.
    int as_server = 1;
    if (zmq_setsockopt(sock_, ZMQ_CURVE_SERVER, &as_server, sizeof(as_server)) != 0 ||
        zmq_setsockopt(sock_, ZMQ_CURVE_SECRETKEY, curve_secret_.data(), curve_secret_.size()) != 0) {
      zmq_close(sock_);
      zmq_ctx_term(ctx_);
      sock_ = nullptr;
      ctx_ = nullptr;
      return false;
    }
  }
  if (zmq_bind(sock_, bind_endpoint_.c_str()) != 0) {
    zmq_close(sock_);
    zmq_ctx_term(ctx_);
    sock_ = nullptr;
    ctx_ = nullptr;
    return false;
  }
  char buf[256];
  size_t len = sizeof(buf);
  if (zmq_getsockopt(sock_, ZMQ_LAST_ENDPOINT, buf, &len) == 0 && len > 0) {
    endpoint_.assign(buf, len - 1);  // len includes the NUL terminator
  } else {
    endpoint_ = bind_endpoint_;
  }
  running_.store(true);
  thread_ = std::thread(&ControlServer::Loop, this);
  return true;
}

void ControlServer::Stop() {
  if (!running_.exchange(false)) {
    // not running; still clean up any partially-created context
  }
  if (thread_.joinable()) thread_.join();
  if (sock_) {
    zmq_close(sock_);
    sock_ = nullptr;
  }
  if (ctx_) {
    zmq_ctx_term(ctx_);
    ctx_ = nullptr;
  }
}

void ControlServer::Loop() {
  while (running_.load()) {
    zmq_msg_t id;
    zmq_msg_init(&id);
    const int rc = zmq_msg_recv(&id, sock_, 0);
    if (rc < 0) {
      zmq_msg_close(&id);
      if (errno == EAGAIN) continue;  // timeout: re-check running_
      break;                          // context terminated or fatal
    }
    const std::string identity(static_cast<char*>(zmq_msg_data(&id)), zmq_msg_size(&id));
    int more = zmq_msg_more(&id);
    zmq_msg_close(&id);

    std::vector<std::string> parts;
    while (more) {
      zmq_msg_t part;
      zmq_msg_init(&part);
      if (zmq_msg_recv(&part, sock_, 0) < 0) {
        zmq_msg_close(&part);
        more = 0;
        break;
      }
      parts.emplace_back(static_cast<char*>(zmq_msg_data(&part)), zmq_msg_size(&part));
      more = zmq_msg_more(&part);
      zmq_msg_close(&part);
    }

    // REQ envelope: [empty delimiter][payload]; payload is the last frame.
    const std::string payload = parts.empty() ? std::string() : parts.back();
    const std::string reply = Handle(payload);
    SendReply(sock_, identity, reply);
  }
}

std::string ControlServer::Handle(const std::string& request_payload) {
  wire::Request req;
  if (!wire::ParseRequest(request_payload, req)) {
    return wire::BuildResponse(false, wire::kStatusError, "bad request", Value::Object());
  }

  RpcContext ctx;
  ctx.meta = &req.meta;
  if (interceptor_.active()) {
    const AuthResult ar = interceptor_.Authorize(req.meta, req.method);
    if (!ar.ok) {
      return wire::BuildResponse(false, ar.status, ar.error, Value::Object());
    }
    ctx.role = ar.role;
  }

  const std::string& m = req.method;
  Value body;
  if (m == wire::kRegisterWorker) {
    body = service_->RegisterWorker(req.body, ctx);
  } else if (m == wire::kHeartbeat) {
    body = service_->Heartbeat(req.body, ctx);
  } else if (m == wire::kStartShard) {
    body = service_->StartShard(req.body, ctx);
  } else if (m == wire::kStopShard) {
    body = service_->StopShard(req.body, ctx);
  } else if (m == wire::kReportStats) {
    body = service_->ReportStats(req.body, ctx);
  } else if (m == wire::kAbortJob) {
    body = service_->AbortJob(req.body, ctx);
  } else if (m == wire::kGetWorkerStatus) {
    body = service_->GetWorkerStatus(req.body, ctx);
  } else if (m == wire::kForceSync) {
    body = service_->ForceSync(req.body, ctx);
  } else {
    return wire::BuildResponse(false, wire::kStatusError, "unknown method: " + m, Value::Object());
  }

  return wire::BuildResponse(true, wire::kStatusOk, "", body);
}

}  // namespace samurai::control
