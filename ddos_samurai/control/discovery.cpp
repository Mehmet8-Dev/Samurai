#include "discovery.hpp"

#include <string>
#include <vector>

#include "auth.hpp"  // SplitEndpoints

namespace samurai::control {

namespace {

std::string StripNonEmpty(const std::string& s, const std::string& fallback) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return fallback;
  const auto last = s.find_last_not_of(" \t\r\n");
  const std::string t = s.substr(first, last - first + 1);
  return t.empty() ? fallback : t;
}

}  // namespace

EndpointDiscovery::EndpointDiscovery(const std::string& manual_endpoints,
                                     bool prefer_k8s,
                                     const std::string& k8s_namespace,
                                     const std::string& k8s_selector,
                                     int k8s_port)
    : manual_(SplitEndpoints(manual_endpoints)),
      prefer_k8s_(prefer_k8s),
      k8s_namespace_(StripNonEmpty(k8s_namespace, "default")),
      k8s_selector_(StripNonEmpty(k8s_selector, "")),
      k8s_port_(k8s_port ? k8s_port : 5099) {}

std::vector<std::string> EndpointDiscovery::Resolve() const { return manual_; }

std::vector<std::string> EndpointDiscovery::ResolveWithFallback() const {
  if (!manual_.empty()) return manual_;
  // K8s discovery is deferred to the native k8s client; nothing to fall back to.
  return {};
}

}  // namespace samurai::control
