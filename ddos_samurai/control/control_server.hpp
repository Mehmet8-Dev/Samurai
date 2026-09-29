#pragma once

// ZMQ control server — the native transport that replaces the gRPC
// MasterControlServer. A ZMQ_ROUTER socket accepts request envelopes
// (control_wire), authorizes them (Interceptor), and dispatches to a
// ControlService (the Servicer). Runs its receive loop on a background thread.
//
// TLS and the RBAC audit-chain from the Python server are deferred to a later
// increment; this lands the transport + auth + dispatch core.

#include <atomic>
#include <string>
#include <thread>

#include "control_auth.hpp"
#include "servicer.hpp"

namespace samurai::control {

class ControlServer {
 public:
  // `service` is non-owning and must outlive the server. bind_endpoint is a ZMQ
  // endpoint, e.g. "tcp://127.0.0.1:5099" or "tcp://127.0.0.1:*" (ephemeral).
  ControlServer(const std::string& bind_endpoint, ControlService* service,
                const AuthConfig& auth);
  ~ControlServer();

  ControlServer(const ControlServer&) = delete;
  ControlServer& operator=(const ControlServer&) = delete;

  // Enable CURVE encryption on this server (call before Start()). `secret_key`
  // is the server's Z85 secret key; clients must present the matching public
  // key. Empty key = plaintext (default).
  void set_curve_server(const std::string& secret_key) { curve_secret_ = secret_key; }

  bool Start();  // bind + spawn the receive thread; false on failure
  void Stop();   // signal + join + close

  // The actually-bound endpoint (resolved after Start(), useful with ":*").
  const std::string& endpoint() const { return endpoint_; }
  bool running() const { return running_.load(); }

 private:
  void Loop();
  std::string Handle(const std::string& request_payload);

  std::string bind_endpoint_;
  std::string endpoint_;
  ControlService* service_;
  Interceptor interceptor_;
  std::string curve_secret_;  // Z85 server secret; empty = plaintext

  void* ctx_ = nullptr;   // zmq context (opaque)
  void* sock_ = nullptr;  // zmq ROUTER socket (opaque)
  std::atomic<bool> running_{false};
  std::thread thread_;
};

}  // namespace samurai::control
