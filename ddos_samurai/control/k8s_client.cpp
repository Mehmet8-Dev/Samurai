#include "k8s_client.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include "http_client.hpp"
#include "json.hpp"

namespace samurai::control {

namespace {

std::string LowerCopy(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return s;
}

std::string Trim(const std::string& s) {
  const auto a = s.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return "";
  const auto b = s.find_last_not_of(" \t\r\n");
  return s.substr(a, b - a + 1);
}

bool ReadFile(const std::string& path, std::string& out) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return true;
}

bool PathExists(const std::string& p) {
  struct stat st{};
  return ::stat(p.c_str(), &st) == 0;
}

namespace http = samurai::core::http;

// Thin wrapper preserving the old (method, cfg, path, body, content_type)
// signature; the HTTP transport now lives in samurai_core.
http::HttpResponse HttpRequest(const std::string& method, const K8sConfig& cfg,
                               const std::string& path, const std::string& body,
                               const std::string& content_type) {
  http::HttpOptions o;
  o.method = method;
  o.body = body;
  o.content_type = content_type;
  o.bearer = cfg.token;
  o.ca_file = cfg.ca_file;
  o.insecure = cfg.insecure;
  o.timeout_s = cfg.timeout_s;
  return http::Request(http::JoinUrl(cfg.api_base, path), o);
}


// spec.replicas out of a scale-subresource JSON body.
bool ParseReplicas(const std::string& body, int& out) {
  auto pr = samurai::core::json::Parse(body);
  if (!pr.ok || !pr.value.is_object()) return false;
  const auto* spec = pr.value.find("spec");
  if (!spec || !spec->is_object()) return false;
  const auto* rep = spec->find("replicas");
  if (!rep) return false;
  out = static_cast<int>(rep->as_int(0));
  return true;
}

}  // namespace

bool ResponseCompleteForTest(const std::string& raw) {
  return samurai::core::http::ResponseCompleteForTest(raw);
}

std::string ScalePath(const std::string& kind, const std::string& ns, const std::string& name) {
  const std::string plural = LowerCopy(kind) == "statefulset" ? "statefulsets" : "deployments";
  return "/apis/apps/v1/namespaces/" + ns + "/" + plural + "/" + name + "/scale";
}

K8sConfig ResolveK8sConfig(const std::string& api_override, bool insecure) {
  K8sConfig cfg;
  cfg.insecure = insecure;
  const std::string ov = Trim(api_override);
  if (!ov.empty()) {
    cfg.active = true;
    cfg.api_base = ov;
    cfg.source = "api-override";
    return cfg;
  }
  // In-cluster: service-account token + CA + API host/port from the environment.
  const char* host = std::getenv("KUBERNETES_SERVICE_HOST");
  const char* port = std::getenv("KUBERNETES_SERVICE_PORT");
  const std::string sa = "/var/run/secrets/kubernetes.io/serviceaccount";
  const std::string token_path = sa + "/token";
  const std::string ca_path = sa + "/ca.crt";
  std::string token;
  if (host && *host && PathExists(token_path) && ReadFile(token_path, token)) {
    cfg.active = true;
    cfg.api_base = std::string("https://") + host + ":" + (port && *port ? port : "443");
    cfg.token = Trim(token);
    if (PathExists(ca_path)) cfg.ca_file = ca_path;
    cfg.source = "in-cluster";
    return cfg;
  }
  cfg.source = "";
  return cfg;  // inactive
}

ScaleResult GetScale(const K8sConfig& cfg, const std::string& kind, const std::string& ns,
                     const std::string& name) {
  ScaleResult r;
  if (!cfg.active) {
    r.error = "k8s config inactive";
    return r;
  }
  const auto h = HttpRequest("GET", cfg, ScalePath(kind, ns, name), "", "application/json");
  r.status = h.status;
  if (!h.ok) {
    r.error = h.error;
    return r;
  }
  if (h.status / 100 != 2) {
    r.error = "k8s GET scale status " + std::to_string(h.status);
    return r;
  }
  if (!ParseReplicas(h.body, r.replicas)) {
    r.error = "scale response missing spec.replicas";
    return r;
  }
  r.ok = true;
  return r;
}

ScaleResult PatchScale(const K8sConfig& cfg, const std::string& kind, const std::string& ns,
                       const std::string& name, int replicas) {
  ScaleResult r;
  if (!cfg.active) {
    r.error = "k8s config inactive";
    return r;
  }
  const std::string body = "{\"spec\":{\"replicas\":" + std::to_string(replicas) + "}}";
  const auto h =
      HttpRequest("PATCH", cfg, ScalePath(kind, ns, name), body, "application/merge-patch+json");
  r.status = h.status;
  if (!h.ok) {
    r.error = h.error;
    return r;
  }
  if (h.status / 100 != 2) {
    r.error = "k8s PATCH scale status " + std::to_string(h.status);
    return r;
  }
  // The API server echoes the object; prefer its replicas, else assume applied.
  if (!ParseReplicas(h.body, r.replicas)) r.replicas = replicas;
  r.ok = true;
  return r;
}

}  // namespace samurai::control
