#pragma once

// HTTP management API — a minimal HTTP/1.1 server (POSIX sockets, no framework)
// exposes the cluster's read endpoints plus
// a job-abort action, with the same auth model: trusted-identity proxy headers,
// bearer role tokens, and JWT role/tenant claims, all tenant-filtered.
//
// Ported: /healthz, /v1/cluster/{summary,workers,shards,events}, /v1/jobs/abort,
// /metrics. The SSE and WebSocket live streams are deferred (long-lived
// streaming); the same state_provider feeds them when added.

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>

#include "json.hpp"

namespace samurai::control {

struct HttpRequest {
  std::string method;
  std::string path;                            // without query
  std::map<std::string, std::string> query;    // decoded query params
  std::map<std::string, std::string> headers;  // lower-cased keys
};

struct HttpResponse {
  int status = 200;
  std::string reason = "OK";
  std::string content_type = "application/json";
  std::string body;
};

struct ManagementConfig {
  std::string auth_token;                          // legacy single token (grants all roles)
  std::map<std::string, std::string> role_tokens;  // "admin"/"operator"/"viewer" -> token
  std::string tenant_namespace;
  std::string jwt_secret;
  std::string jwt_role_claim = "role";
  std::string jwt_tenant_claim = "tenant_namespace";
  std::string trusted_identity_secret;
  std::string trusted_secret_header = "x-samurai-auth-proxy-secret";
  std::string trusted_role_header = "x-auth-request-role";
  std::string trusted_tenant_header = "x-auth-request-tenant";
  int db_port = 5099;                              // Default DB persistence port (user memory standard)
  int rate_limit_per_sec = 100;                    // Max HTTP requests per second per client

  // Self-bootstrapping agent join (zero-install slave). When agent_join_token is
  // non-empty the /v1/agent/{install,manifest,blob} endpoints are enabled: a node
  // runs `curl -fsSL http://master:PORT/v1/agent/install?token=T | sh`, which
  // fetches an HMAC-signed manifest (key = the join token), downloads the slave +
  // worker binaries from agent_artifact_dir, verifies each SHA-256, and execs the
  // slave in reverse mode pointed at agent_advertise_endpoint.
  std::string agent_join_token;          // gates the endpoints + HMAC key; empty = disabled
  std::string agent_artifact_dir;        // dir holding samurai_slave + worker binaries
  std::string agent_advertise_endpoint;  // control endpoint the agent connects to (public)
  std::string agent_curve_public;        // master control-server CURVE public key (Z85), optional
  std::string agent_cluster_secret;      // cluster secret the agent presents to register (app-layer auth)
  std::string agent_dispatch_mode = "reverse";  // reverse|auto (NAT-friendly)
  std::string agent_worker = "cpu";      // dataplane worker kind the agent runs
};

struct ManagementProviders {
  std::function<samurai::core::json::Value()> state_provider;
  std::function<samurai::core::json::Value()> abort_callback;
  std::function<std::string()> metrics_provider;  // may be empty
};

class RateLimiter {
 public:
  explicit RateLimiter(int max_per_sec = 100);
  bool Allow(const std::string& client_key);

 private:
  int max_per_sec_;
  // Internal rate state implementation
  struct Impl;
  std::shared_ptr<Impl> impl_;
};

// Pure request router + auth. Testable without a socket.
class ManagementApi {
 public:
  ManagementApi(const ManagementConfig& cfg, ManagementProviders providers);
  HttpResponse Handle(const HttpRequest& req) const;

  // Exposed for testing/reuse.
  std::string ResolveRole(const std::string& authorization,
                          const std::map<std::string, std::string>& headers) const;

 private:
  ManagementConfig cfg_;
  ManagementProviders providers_;
};

// Parse a raw HTTP request head (request line + headers). Returns false if the
// request line is malformed. Body is not consumed (endpoints need none).
bool ParseHttpRequest(const std::string& raw, HttpRequest& out);

// Minimal blocking HTTP server hosting a ManagementApi on a background thread.
class ManagementApiServer {
 public:
  ManagementApiServer(const std::string& listen_addr, const ManagementConfig& cfg,
                      ManagementProviders providers);
  ~ManagementApiServer();

  bool Start();
  void Stop();
  const std::string& endpoint() const { return endpoint_; }  // resolved host:port
  bool running() const { return running_.load(); }

 private:
  void Loop();

  std::string listen_addr_;
  std::string endpoint_;
  ManagementApi api_;
  int listen_fd_ = -1;
  std::atomic<bool> running_{false};
  std::thread thread_;
};

}  // namespace samurai::control
