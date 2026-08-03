#pragma once

// Minimal JWT HS256 helpers — native C++ port of
// ddos_samurai/control/jwt_claims.py. Verifies/creates HS256 (HMAC-SHA256)
// tokens for control-plane auth, using OpenSSL for the MAC and samurai_core's
// JSON for the header/payload. Signature comparison is constant-time.

#include <string>

#include "json.hpp"  // samurai::core::json::Value

namespace samurai::control {

struct JwtDecodeResult {
  bool ok = false;
  std::string error;               // populated when ok == false
  samurai::core::json::Value payload;  // the claims object when ok == true
};

// Decode + verify an HS256 JWT. On any failure (format, alg, signature, and —
// when verify_exp — exp/nbf) returns ok == false with a reason matching the
// Python ValueError messages ("invalid jwt format", "unsupported jwt alg",
// "jwt signature mismatch", "jwt expired", "jwt not yet valid", ...).
JwtDecodeResult DecodeJwtHs256(const std::string& token, const std::string& secret,
                               bool verify_exp = true);

// Build an HS256 JWT for the given claims (header {"alg":"HS256","typ":"JWT"}).
// Mirrors utils/tests' encode_jwt_hs256; compact JSON, base64url, no padding.
std::string EncodeJwtHs256(const samurai::core::json::Value& payload, const std::string& secret);

}  // namespace samurai::control
