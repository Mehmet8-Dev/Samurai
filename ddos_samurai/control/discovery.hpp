#pragma once

// Endpoint discovery — native C++ port of ddos_samurai/control/discovery.py.
// Manual endpoints are first-class and always win when present (the v1 policy).
// Kubernetes-based discovery is deferred to a native k8s client; until then
// ResolveWithFallback() returns the manual set (or empty).

#include <string>
#include <vector>

namespace samurai::control {

class EndpointDiscovery {
 public:
  explicit EndpointDiscovery(const std::string& manual_endpoints,
                             bool prefer_k8s = false,
                             const std::string& k8s_namespace = "default",
                             const std::string& k8s_selector = "",
                             int k8s_port = 5099);

  // Manual endpoints (comma-separated, trimmed, blanks dropped).
  std::vector<std::string> Resolve() const;

  // Manual endpoints when present; otherwise the k8s set when prefer_k8s (not
  // yet wired natively -> empty), else empty.
  std::vector<std::string> ResolveWithFallback() const;

  bool prefer_k8s() const { return prefer_k8s_; }

 private:
  std::vector<std::string> manual_;
  bool prefer_k8s_;
  std::string k8s_namespace_;
  std::string k8s_selector_;
  int k8s_port_;
};

}  // namespace samurai::control
