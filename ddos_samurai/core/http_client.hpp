#pragma once

// Minimal blocking HTTP(S) client over POSIX sockets + OpenSSL. Extracted from
// the k8s scale client so the same proven transport backs every native
// outbound HTTP need (k8s scale subresource, SUT-correlation Prometheus
// scrapes, ...). No external dependency beyond OpenSSL, which the control layer
// already links.
//
// One request per call, Connection: close, with a receive/send timeout. HTTPS
// verifies the peer unless `insecure`, trusting `ca_file` when provided (else
// the system default trust store).

#include <string>

namespace samurai::core::http {

struct HttpOptions {
  std::string method = "GET";
  std::string body;
  std::string content_type = "application/json";
  std::string accept = "application/json";
  std::string bearer;         // optional Authorization: Bearer <token>
  std::string ca_file;        // TLS trust bundle (empty => system defaults)
  bool insecure = false;      // skip TLS peer verification (dev only)
  int timeout_s = 5;
};

struct HttpResponse {
  bool ok = false;       // transport succeeded and a status line parsed
  int status = 0;        // HTTP status code (0 on transport failure)
  std::string body;      // response body
  std::string error;     // populated when ok == false
};

// Perform one request against a full URL ("http(s)://host[:port]/path?query").
HttpResponse Request(const std::string& url, const HttpOptions& opts = {});

// Convenience GET.
inline HttpResponse Get(const std::string& url, int timeout_s = 5) {
  HttpOptions o;
  o.timeout_s = timeout_s;
  return Request(url, o);
}

// Take the scheme://authority prefix of `base` (dropping any trailing path) and
// append `path` (which should start with '/'). Lets callers keep a base URL +
// a computed path, like the k8s api_base + scale subresource path.
std::string JoinUrl(const std::string& base, const std::string& path);

// Exposed for tests: whether a raw HTTP response is fully received.
bool ResponseCompleteForTest(const std::string& raw);

}  // namespace samurai::core::http
