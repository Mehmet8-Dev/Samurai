#pragma once

// Minimal native HTTP(S) client — the transport the Python licensing client got
// from urllib. POST a JSON body to an http:// or https:// URL and read the
// response. Plain HTTP uses POSIX sockets; HTTPS uses OpenSSL (libssl). Blocking,
// with a timeout. This unblocks the previously-deferred native license client.

#include <string>

namespace samurai::licensing {

struct HttpResponse {
  bool ok = false;     // transport-level success (a response was received)
  int status = 0;      // HTTP status code
  std::string body;
  std::string error;   // populated when ok == false
};

// POST `json_body` (Content-Type: application/json) to `url`. Follows no
// redirects. `extra_headers` is appended verbatim (each must end without CRLF).
HttpResponse HttpPostJson(const std::string& url, const std::string& json_body,
                          int timeout_s = 10, const std::string& bearer_token = "");

}  // namespace samurai::licensing
