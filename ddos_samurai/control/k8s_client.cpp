#include "k8s_client.hpp"

#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include <openssl/ssl.h>
#include <openssl/x509.h>

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

struct Url {
  bool https = false;
  std::string host;
  std::string port;
  std::string path;
};

// Split "http(s)://host[:port]/path" into parts.
bool ParseUrl(const std::string& url, const std::string& path_suffix, Url& out) {
  const auto scheme_end = url.find("://");
  if (scheme_end == std::string::npos) return false;
  const std::string scheme = url.substr(0, scheme_end);
  if (scheme != "http" && scheme != "https") return false;
  out.https = (scheme == "https");
  std::string rest = url.substr(scheme_end + 3);
  // The base URL may carry a trailing path; we only use its authority.
  std::string authority = rest;
  const auto slash = rest.find('/');
  if (slash != std::string::npos) authority = rest.substr(0, slash);
  std::string host = authority;
  std::string port = out.https ? "443" : "80";
  if (!authority.empty() && authority.front() == '[') {  // [ipv6]:port
    const auto rb = authority.find(']');
    if (rb == std::string::npos) return false;
    host = authority.substr(1, rb - 1);
    if (rb + 1 < authority.size() && authority[rb + 1] == ':') port = authority.substr(rb + 2);
  } else {
    const auto colon = authority.rfind(':');
    if (colon != std::string::npos) {
      host = authority.substr(0, colon);
      port = authority.substr(colon + 1);
    }
  }
  out.host = host;
  out.port = port;
  out.path = path_suffix;
  return true;
}

int ConnectTcp(const std::string& host, const std::string& port, int timeout_s) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) return -1;
  int fd = -1;
  for (addrinfo* p = res; p; p = p->ai_next) {
    fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) continue;
    timeval tv{timeout_s, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  ::freeaddrinfo(res);
  return fd;
}

std::string BuildRequest(const std::string& method, const Url& u, const std::string& body,
                         const std::string& content_type, const std::string& bearer) {
  std::ostringstream os;
  os << method << " " << u.path << " HTTP/1.1\r\n"
     << "Host: " << u.host << "\r\n"
     << "Accept: application/json\r\n";
  if (!bearer.empty()) os << "Authorization: Bearer " << bearer << "\r\n";
  if (!body.empty() || method == "PATCH" || method == "POST" || method == "PUT") {
    os << "Content-Type: " << content_type << "\r\n"
       << "Content-Length: " << body.size() << "\r\n";
  }
  os << "Connection: close\r\n\r\n";
  if (!body.empty()) os << body;
  return os.str();
}

struct HttpResult {
  bool ok = false;
  int status = 0;
  std::string body;
  std::string error;
};

// Case-insensitive search for a header value; returns "" if absent.
std::string HeaderValue(const std::string& headers, const std::string& name) {
  std::string lh = headers, ln = name;
  for (char& c : lh) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  for (char& c : ln) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  auto pos = lh.find("\r\n" + ln + ":");
  if (pos == std::string::npos) return "";
  pos += 2 + ln.size() + 1;  // skip "\r\n" + name + ":"
  auto end = lh.find("\r\n", pos);
  std::string v = headers.substr(pos, (end == std::string::npos ? headers.size() : end) - pos);
  const auto a = v.find_first_not_of(" \t");
  const auto b = v.find_last_not_of(" \t");
  return a == std::string::npos ? "" : v.substr(a, b - a + 1);
}

// True once `raw` holds a complete HTTP response, so the reader can stop without
// waiting for the server to close a keep-alive connection (which would otherwise
// block until the socket timeout — the cause of stalls against the API server).
bool ResponseComplete(const std::string& raw) {
  const auto hdr_end = raw.find("\r\n\r\n");
  if (hdr_end == std::string::npos) return false;  // headers not fully received
  const std::string headers = raw.substr(0, hdr_end);
  const std::size_t body_len = raw.size() - (hdr_end + 4);
  const std::string te = HeaderValue(headers, "Transfer-Encoding");
  if (!te.empty() && te.find("chunked") != std::string::npos) {
    return raw.size() >= hdr_end + 4 + 5 && raw.compare(raw.size() - 5, 5, "0\r\n\r\n") == 0;
  }
  const std::string cl = HeaderValue(headers, "Content-Length");
  if (!cl.empty()) {
    try {
      return body_len >= static_cast<std::size_t>(std::stoul(cl));
    } catch (...) {
      return false;
    }
  }
  // No length signalled (e.g. 204 No Content or a bodyless status): headers alone
  // complete the response.
  return true;
}

HttpResult ParseResponse(const std::string& raw) {
  HttpResult r;
  if (raw.empty()) {
    r.error = "empty response";
    return r;
  }
  const auto line_end = raw.find("\r\n");
  const std::string status_line = raw.substr(0, line_end);
  const auto sp1 = status_line.find(' ');
  if (sp1 != std::string::npos) {
    try {
      r.status = std::stoi(status_line.substr(sp1 + 1, 4));
    } catch (...) {
      r.status = 0;
    }
  }
  const auto hdr_end = raw.find("\r\n\r\n");
  r.body = hdr_end == std::string::npos ? "" : raw.substr(hdr_end + 4);
  r.ok = r.status > 0;
  if (!r.ok) r.error = "malformed response";
  return r;
}

// One blocking request. HTTPS uses OpenSSL; verification is enabled unless
// cfg.insecure, trusting cfg.ca_file when provided (the cluster CA in-cluster).
HttpResult HttpRequest(const std::string& method, const K8sConfig& cfg,
                       const std::string& path, const std::string& body,
                       const std::string& content_type) {
  HttpResult r;
  Url u;
  if (!ParseUrl(cfg.api_base, path, u)) {
    r.error = "invalid api base: " + cfg.api_base;
    return r;
  }
  const int fd = ConnectTcp(u.host, u.port, cfg.timeout_s);
  if (fd < 0) {
    r.error = "connect failed: " + u.host + ":" + u.port;
    return r;
  }
  const std::string request = BuildRequest(method, u, body, content_type, cfg.token);
  std::string raw;
  if (u.https) {
    static bool ssl_inited = [] {
      SSL_library_init();
      SSL_load_error_strings();
      return true;
    }();
    (void)ssl_inited;
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
      ::close(fd);
      r.error = "ssl ctx failed";
      return r;
    }
    if (!cfg.insecure) {
      if (!cfg.ca_file.empty()) {
        SSL_CTX_load_verify_locations(ctx, cfg.ca_file.c_str(), nullptr);
      } else {
        SSL_CTX_set_default_verify_paths(ctx);
      }
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    }
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
      SSL_CTX_free(ctx);
      ::close(fd);
      r.error = "ssl new failed";
      return r;
    }
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, u.host.c_str());  // SNI
    if (SSL_connect(ssl) != 1) {
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      ::close(fd);
      r.error = "tls handshake failed";
      return r;
    }
    if (!cfg.insecure && SSL_get_verify_result(ssl) != X509_V_OK) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      ::close(fd);
      r.error = "tls certificate verification failed";
      return r;
    }
    SSL_write(ssl, request.data(), static_cast<int>(request.size()));
    char buf[4096];
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
      raw.append(buf, static_cast<std::size_t>(n));
      if (ResponseComplete(raw)) break;  // don't wait for a keep-alive close
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
  } else {
    ::send(fd, request.data(), request.size(), 0);
    char buf[4096];
    ssize_t n;
    while ((n = ::recv(fd, buf, sizeof(buf), 0)) > 0) {
      raw.append(buf, static_cast<std::size_t>(n));
      if (ResponseComplete(raw)) break;
    }
  }
  ::close(fd);
  if (raw.empty()) {
    r.error = "no response / timeout";
    return r;
  }
  return ParseResponse(raw);
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

bool ResponseCompleteForTest(const std::string& raw) { return ResponseComplete(raw); }

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
  const HttpResult h = HttpRequest("GET", cfg, ScalePath(kind, ns, name), "", "application/json");
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
  const HttpResult h =
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
