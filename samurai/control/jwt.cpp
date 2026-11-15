#include "jwt.hpp"

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "json.hpp"

namespace samurai::control {

namespace {

using samurai::core::json::Value;

const char kB64UrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// base64url encode without padding (matches _b64url_encode).
std::string B64UrlEncode(const unsigned char* data, std::size_t len) {
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  std::size_t i = 0;
  for (; i + 3 <= len; i += 3) {
    const std::uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
    out.push_back(kB64UrlAlphabet[(n >> 18) & 0x3F]);
    out.push_back(kB64UrlAlphabet[(n >> 12) & 0x3F]);
    out.push_back(kB64UrlAlphabet[(n >> 6) & 0x3F]);
    out.push_back(kB64UrlAlphabet[n & 0x3F]);
  }
  const std::size_t rem = len - i;
  if (rem == 1) {
    const std::uint32_t n = data[i] << 16;
    out.push_back(kB64UrlAlphabet[(n >> 18) & 0x3F]);
    out.push_back(kB64UrlAlphabet[(n >> 12) & 0x3F]);
  } else if (rem == 2) {
    const std::uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
    out.push_back(kB64UrlAlphabet[(n >> 18) & 0x3F]);
    out.push_back(kB64UrlAlphabet[(n >> 12) & 0x3F]);
    out.push_back(kB64UrlAlphabet[(n >> 6) & 0x3F]);
  }
  return out;
}

std::string B64UrlEncode(const std::string& s) {
  return B64UrlEncode(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

int B64Val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-' || c == '+') return 62;
  if (c == '_' || c == '/') return 63;
  return -1;
}

// base64url decode, padding-tolerant (matches _b64url_decode). Returns false on
// malformed input.
bool B64UrlDecode(const std::string& in, std::string& out) {
  out.clear();
  std::uint32_t buf = 0;
  int bits = 0;
  for (char c : in) {
    if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
    const int v = B64Val(c);
    if (v < 0) return false;
    buf = (buf << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buf >> bits) & 0xFF));
    }
  }
  return true;
}

std::string Strip(const std::string& s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

std::string Upper(const std::string& s) {
  std::string out = s;
  for (char& c : out) {
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
  }
  return out;
}

// HMAC-SHA256(key, msg) -> 32 raw bytes.
std::string HmacSha256(const std::string& key, const std::string& msg) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int md_len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), md, &md_len);
  return std::string(reinterpret_cast<char*>(md), md_len);
}

JwtDecodeResult Err(const std::string& reason) {
  JwtDecodeResult r;
  r.ok = false;
  r.error = reason;
  return r;
}

}  // namespace

JwtDecodeResult DecodeJwtHs256(const std::string& token, const std::string& secret,
                               bool verify_exp) {
  const std::string raw = Strip(token);
  if (raw.empty()) return Err("empty token");

  // Split into exactly three dot-separated parts.
  const auto d1 = raw.find('.');
  if (d1 == std::string::npos) return Err("invalid jwt format");
  const auto d2 = raw.find('.', d1 + 1);
  if (d2 == std::string::npos) return Err("invalid jwt format");
  if (raw.find('.', d2 + 1) != std::string::npos) return Err("invalid jwt format");

  const std::string h_b64 = raw.substr(0, d1);
  const std::string p_b64 = raw.substr(d1 + 1, d2 - d1 - 1);
  const std::string s_b64 = raw.substr(d2 + 1);

  std::string header_json, payload_json, provided_sig;
  if (!B64UrlDecode(h_b64, header_json)) return Err("invalid jwt format");
  if (!B64UrlDecode(p_b64, payload_json)) return Err("invalid jwt format");
  if (!B64UrlDecode(s_b64, provided_sig)) return Err("invalid jwt format");

  const auto header = samurai::core::json::Parse(header_json);
  if (!header.ok || !header.value.is_object()) return Err("invalid jwt format");
  const Value* alg = header.value.find("alg");
  if (!alg || Upper(Strip(alg->as_string())) != "HS256") return Err("unsupported jwt alg");

  const std::string signing_input = h_b64 + "." + p_b64;
  const std::string expected_sig = HmacSha256(secret, signing_input);
  // Constant-time comparison; unequal lengths fail without leaking timing.
  if (provided_sig.size() != expected_sig.size() ||
      CRYPTO_memcmp(provided_sig.data(), expected_sig.data(), expected_sig.size()) != 0) {
    return Err("jwt signature mismatch");
  }

  const auto payload = samurai::core::json::Parse(payload_json);
  if (!payload.ok || !payload.value.is_object()) return Err("invalid jwt format");

  if (verify_exp) {
    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    if (const Value* exp = payload.value.find("exp")) {
      if (!exp->is_null() && exp->as_int() < now) return Err("jwt expired");
    }
    if (const Value* nbf = payload.value.find("nbf")) {
      if (!nbf->is_null() && nbf->as_int() > now) return Err("jwt not yet valid");
    }
  }

  JwtDecodeResult r;
  r.ok = true;
  r.payload = payload.value;
  return r;
}

std::string EncodeJwtHs256(const Value& payload, const std::string& secret) {
  Value header = Value::Object();
  header.set("alg", Value::Str("HS256"));
  header.set("typ", Value::Str("JWT"));

  const std::string h_b64 = B64UrlEncode(header.dump());
  const std::string p_b64 = B64UrlEncode(payload.is_object() ? payload.dump() : std::string("{}"));
  const std::string signing_input = h_b64 + "." + p_b64;
  const std::string sig = HmacSha256(secret, signing_input);
  const std::string s_b64 = B64UrlEncode(reinterpret_cast<const unsigned char*>(sig.data()), sig.size());
  return h_b64 + "." + p_b64 + "." + s_b64;
}

}  // namespace samurai::control
