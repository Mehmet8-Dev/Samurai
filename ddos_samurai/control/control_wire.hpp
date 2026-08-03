#pragma once

// Control-plane wire schema over ZMQ. Replaces the gRPC/protobuf message
// contract (samurai_control.proto) with a JSON envelope carried on ZMQ frames:
//
//   request  : {"method":"<Name>","meta":{"x-cluster-secret":..,
//               "x-tenant-namespace":..},"body":{ ...method fields... }}
//   response : {"ok":bool,"status":"<code>","error":"..","body":{ .. }}
//
// The eight methods and message fields mirror the proto one-for-one; bytes
// fields (args_json/stats_json/logs_json) are carried as JSON-text strings.

#include <string>

#include "json.hpp"

namespace samurai::control::wire {

// RPC method names (match the proto service methods).
inline constexpr const char* kRegisterWorker = "RegisterWorker";
inline constexpr const char* kHeartbeat = "Heartbeat";
inline constexpr const char* kStartShard = "StartShard";
inline constexpr const char* kStopShard = "StopShard";
inline constexpr const char* kReportStats = "ReportStats";
inline constexpr const char* kAbortJob = "AbortJob";
inline constexpr const char* kGetWorkerStatus = "GetWorkerStatus";
inline constexpr const char* kForceSync = "ForceSync";

// Response status codes (mirror the gRPC StatusCode names the interceptor used).
inline constexpr const char* kStatusOk = "";
inline constexpr const char* kStatusUnauthenticated = "UNAUTHENTICATED";
inline constexpr const char* kStatusPermissionDenied = "PERMISSION_DENIED";
inline constexpr const char* kStatusError = "RPC_ERROR";

struct Request {
  std::string method;
  samurai::core::json::Value meta;   // object
  samurai::core::json::Value body;   // object
};

struct Response {
  bool ok = false;
  std::string status;
  std::string error;
  samurai::core::json::Value body;   // object
};

inline std::string BuildRequest(const std::string& method,
                                const samurai::core::json::Value& meta,
                                const samurai::core::json::Value& body) {
  using samurai::core::json::Value;
  Value env = Value::Object();
  env.set("method", Value::Str(method));
  env.set("meta", meta.is_object() ? meta : Value::Object());
  env.set("body", body.is_object() ? body : Value::Object());
  return env.dump();
}

inline std::string BuildResponse(bool ok, const std::string& status,
                                 const std::string& error,
                                 const samurai::core::json::Value& body) {
  using samurai::core::json::Value;
  Value env = Value::Object();
  env.set("ok", Value::Bool(ok));
  env.set("status", Value::Str(status));
  env.set("error", Value::Str(error));
  env.set("body", body.is_object() ? body : Value::Object());
  return env.dump();
}

inline bool ParseRequest(const std::string& text, Request& out) {
  const auto r = samurai::core::json::Parse(text);
  if (!r.ok || !r.value.is_object()) return false;
  const auto* m = r.value.find("method");
  if (!m || !m->is_string()) return false;
  out.method = m->as_string();
  const auto* meta = r.value.find("meta");
  out.meta = (meta && meta->is_object()) ? *meta : samurai::core::json::Value::Object();
  const auto* body = r.value.find("body");
  out.body = (body && body->is_object()) ? *body : samurai::core::json::Value::Object();
  return true;
}

inline bool ParseResponse(const std::string& text, Response& out) {
  const auto r = samurai::core::json::Parse(text);
  if (!r.ok || !r.value.is_object()) return false;
  const auto* ok = r.value.find("ok");
  out.ok = ok && ok->as_bool();
  const auto* st = r.value.find("status");
  out.status = st ? st->as_string("") : "";
  const auto* er = r.value.find("error");
  out.error = er ? er->as_string("") : "";
  const auto* body = r.value.find("body");
  out.body = (body && body->is_object()) ? *body : samurai::core::json::Value::Object();
  return true;
}

}  // namespace samurai::control::wire
