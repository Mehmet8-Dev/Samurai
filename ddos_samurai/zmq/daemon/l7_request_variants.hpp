#pragma once

// Request-variant table for the `request_mix` Mahoraga lever.
//
// request_mix selects WHICH request the L7 worker emits from a small, fixed set
// of benign but distinct HTTP shapes. A defended target (WAF + rate limiter)
// reacts differently to each — a query-bearing search path, an API path, a
// state-changing POST, and a cacheable static asset land in different WAF rule
// groups and rate-limit buckets — so the captured corpus gains a shaping
// dimension the reward actually responds to. These are ordinary load-test
// request shapes, not evasion payloads: the lever varies the *distribution* of
// legitimate requests, it does not obfuscate or spoof them.
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
inline constexpr RequestVariant kRequestVariants[] = {
    {"GET", "/"},                    // 0 baseline root
    {"GET", "/search?q=samurai"},    // 1 query param — trips WAF query inspection
    {"GET", "/api/v1/status"},       // 2 API path — separate limit bucket
    {"POST", "/login"},              // 3 state-changing auth endpoint — rate-limited
    {"GET", "/static/app.js"},       // 4 static asset — cacheable, distinct bucket
};

inline constexpr std::size_t kRequestVariantCount =
    sizeof(kRequestVariants) / sizeof(kRequestVariants[0]);

// The variant for `request_mix`, wrapping out of range so any policy/exploration
// draw maps to a defined request instead of falling off the table.
inline const RequestVariant& VariantFor(std::uint32_t request_mix) {
  return kRequestVariants[request_mix % kRequestVariantCount];
}

// Build a complete HTTP/1.1 request line + headers for the selected variant. A
// POST variant carries an empty body with an explicit Content-Length: 0 so the
// target treats it as a well-formed request rather than a truncated one.
inline std::string BuildHttp1Request(std::uint32_t request_mix, const std::string& host) {
  const RequestVariant& v = VariantFor(request_mix);
  const std::string h = host.empty() ? std::string("localhost") : host;
  std::string req = std::string(v.method) + " " + v.path + " HTTP/1.1\r\n" +
                    "Host: " + h + "\r\n" +
                    "User-Agent: samurai-l7-worker\r\n";
  if (std::string(v.method) == "POST") {
    req += "Content-Length: 0\r\n";
  }
  req += "Connection: close\r\n\r\n";
  return req;
}

}  // namespace samurai::l7
