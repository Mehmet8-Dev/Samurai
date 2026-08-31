#pragma once

// Minimal Kubernetes client for the autoscale controller: read and patch the
// `scale` subresource of a Deployment/StatefulSet. Self-contained HTTP(S) over
// POSIX sockets + OpenSSL (samurai_control already links OpenSSL), so it adds no
// external dependency.
//
// Two auth modes:
//   * in-cluster  — the master runs as a pod; the service-account bearer token
//                   and cluster CA are mounted under /var/run/secrets/... and the
//                   API server is reachable via KUBERNETES_SERVICE_HOST/PORT.
//   * api-override — a plain base URL (e.g. http://127.0.0.1:8001 from
//                   `kubectl proxy`) for local development, skipping TLS/auth.
// When neither resolves, the config is inactive and the caller falls back to the
// controller's in-memory mode.

#include <string>

namespace samurai::control {

struct K8sConfig {
  bool active = false;    // false => caller falls back to in-memory autoscale
  std::string api_base;   // e.g. https://10.0.0.1:443  or  http://127.0.0.1:8001
  std::string token;      // service-account bearer (empty for kubectl-proxy)
  std::string ca_file;    // PEM CA bundle to trust (empty => system defaults)
  bool insecure = false;  // skip TLS peer verification (dev only)
  int timeout_s = 5;
  std::string source;     // "in-cluster" | "api-override" | "" (debug/log)
};

// Resolve the effective config. A non-empty `api_override` (plain dev proxy)
// wins; otherwise the in-cluster service-account files are used when present;
// otherwise the result is inactive.
K8sConfig ResolveK8sConfig(const std::string& api_override, bool insecure);

struct ScaleResult {
  bool ok = false;
  int replicas = 0;    // spec.replicas (read) / applied replicas (patch)
  int status = 0;      // HTTP status code
  std::string error;   // populated when ok == false
};

// `kind` is "deployment" or "statefulset" (case-insensitive). Reads
// .spec.replicas from the scale subresource.
ScaleResult GetScale(const K8sConfig& cfg, const std::string& kind, const std::string& ns,
                     const std::string& name);

// PATCH .spec.replicas = `replicas` on the scale subresource
// (application/merge-patch+json). Returns the replicas echoed by the API server.
ScaleResult PatchScale(const K8sConfig& cfg, const std::string& kind, const std::string& ns,
                       const std::string& name, int replicas);

// Exposed for testing: the scale subresource path for a kind/ns/name.
std::string ScalePath(const std::string& kind, const std::string& ns, const std::string& name);

// Exposed for testing: whether a raw HTTP response is fully received (so the
// reader can stop without waiting for a keep-alive close).
bool ResponseCompleteForTest(const std::string& raw);

}  // namespace samurai::control
