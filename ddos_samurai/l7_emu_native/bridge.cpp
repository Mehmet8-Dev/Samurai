#include "bridge.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "custom_quic_stack/h3_minimal_client.hpp"
#include "../l4/tcp_dataplane_ffi.h"

namespace ddos_samurai::l7_emu_native {

namespace json = samurai::core::json;

namespace {

std::string GetStr(const json::Value& v, const std::string& key, const std::string& def = "") {
  const json::Value* p = v.find(key);
  return p != nullptr ? p->as_string(def) : def;
}

int GetInt(const json::Value& v, const std::string& key, int def = 0) {
  const json::Value* p = v.find(key);
  return p != nullptr ? static_cast<int>(p->as_int(def)) : def;
}

double GetDouble(const json::Value& v, const std::string& key, double def = 0.0) {
  const json::Value* p = v.find(key);
  return p != nullptr ? p->as_double(def) : def;
}

std::map<std::string, std::string> GetStrMap(const json::Value& v, const std::string& key) {
  std::map<std::string, std::string> out{};
  const json::Value* p = v.find(key);
  if (p != nullptr && p->is_object()) {
    for (const auto& kv : p->members()) out[kv.first] = kv.second.as_string();
  }
  return out;
}

const char kHexDigits[] = "0123456789abcdef";

std::string bytes_to_hex(const std::uint8_t* data, std::size_t len) {
  std::string out;
  out.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    out.push_back(kHexDigits[(data[i] >> 4) & 0x0F]);
    out.push_back(kHexDigits[data[i] & 0x0F]);
  }
  return out;
}

std::vector<std::uint8_t> hex_to_bytes(const std::string& hex) {
  std::vector<std::uint8_t> out;
  if (hex.size() % 2 != 0) throw std::runtime_error("hex string must have even length");
  out.reserve(hex.size() / 2);
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int hi = nibble(hex[i]);
    const int lo = nibble(hex[i + 1]);
    if (hi < 0 || lo < 0) throw std::runtime_error("invalid hex digit");
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

std::string ToLower(std::string v) {
  for (char& c : v) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return v;
}

std::string normalize_runtime_backend(const std::string& raw) {
  const std::string out = ToLower(raw);
  if (out != "afxdp" && out != "dpdk") {
    return "afxdp";
  }
  return out;
}

struct RuntimeFailureReason {
  std::string reason;
  std::string detail;
};

RuntimeFailureReason runtime_failure_reason_from_code(double raw_code) {
  const long long code = static_cast<long long>(raw_code);
  switch (code) {
    case 1:
      return RuntimeFailureReason{
          "custom_tcp_transport_not_yet_wired",
          "custom TCP bridge is not ready in native runtime",
      };
    case 2:
      return RuntimeFailureReason{
          "custom_tcp_connect_enqueue_failed",
          "custom TCP connect enqueue failed in native runtime",
      };
    case 3:
      return RuntimeFailureReason{
          "invalid_target_ip",
          "target IP is invalid for native runtime",
      };
    case 4:
      return RuntimeFailureReason{
          "capability_unavailable",
          "required native capability is unavailable",
      };
    case 5:
      return RuntimeFailureReason{
          "nghttp2_not_built",
          "nghttp2 support is not built in native runtime",
      };
    default:
      return RuntimeFailureReason{
          "custom_tcp_transport_unavailable",
          "custom TCP transport is unavailable in native runtime",
      };
  }
}

std::uint32_t rotl32(std::uint32_t v, int bits) {
  return static_cast<std::uint32_t>((v << bits) | (v >> (32 - bits)));
}

std::array<std::uint8_t, 20> sha1_digest(const std::string& input) {
  std::uint32_t h0 = 0x67452301U;
  std::uint32_t h1 = 0xEFCDAB89U;
  std::uint32_t h2 = 0x98BADCFEU;
  std::uint32_t h3 = 0x10325476U;
  std::uint32_t h4 = 0xC3D2E1F0U;

  std::vector<std::uint8_t> data(input.begin(), input.end());
  const std::uint64_t bit_len = static_cast<std::uint64_t>(data.size()) * 8ULL;
  data.push_back(0x80U);
  while ((data.size() % 64U) != 56U) {
    data.push_back(0U);
  }
  for (int shift = 56; shift >= 0; shift -= 8) {
    data.push_back(static_cast<std::uint8_t>((bit_len >> shift) & 0xFFU));
  }

  for (std::size_t offset = 0; offset < data.size(); offset += 64U) {
    std::uint32_t w[80]{};
    for (int i = 0; i < 16; ++i) {
      const std::size_t pos = offset + static_cast<std::size_t>(i * 4);
      w[i] = (static_cast<std::uint32_t>(data[pos]) << 24) |
             (static_cast<std::uint32_t>(data[pos + 1]) << 16) |
             (static_cast<std::uint32_t>(data[pos + 2]) << 8) |
             static_cast<std::uint32_t>(data[pos + 3]);
    }
    for (int i = 16; i < 80; ++i) {
      w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    std::uint32_t a = h0;
    std::uint32_t b = h1;
    std::uint32_t c = h2;
    std::uint32_t d = h3;
    std::uint32_t e = h4;
    for (int i = 0; i < 80; ++i) {
      std::uint32_t f = 0;
      std::uint32_t k = 0;
      if (i < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999U;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1U;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDCU;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6U;
      }
      const std::uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = rotl32(b, 30);
      b = a;
      a = temp;
    }
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  std::array<std::uint8_t, 20> out{};
  const std::uint32_t words[5] = {h0, h1, h2, h3, h4};
  for (int i = 0; i < 5; ++i) {
    out[static_cast<std::size_t>(i * 4)] = static_cast<std::uint8_t>((words[i] >> 24) & 0xFFU);
    out[static_cast<std::size_t>(i * 4 + 1)] = static_cast<std::uint8_t>((words[i] >> 16) & 0xFFU);
    out[static_cast<std::size_t>(i * 4 + 2)] = static_cast<std::uint8_t>((words[i] >> 8) & 0xFFU);
    out[static_cast<std::size_t>(i * 4 + 3)] = static_cast<std::uint8_t>(words[i] & 0xFFU);
  }
  return out;
}

std::string sha1_hexdigest(const std::string& input) {
  const auto digest = sha1_digest(input);
  return bytes_to_hex(digest.data(), digest.size());
}

bool parse_ipv4_literal(const std::string& text, std::uint32_t& out) {
  std::uint32_t parts[4]{};
  std::size_t start = 0;
  for (int i = 0; i < 4; ++i) {
    if (start >= text.size()) return false;
    std::size_t end = text.find('.', start);
    if (i == 3) {
      end = text.size();
    } else if (end == std::string::npos) {
      return false;
    }
    if (end == start) return false;
    unsigned long value = 0;
    for (std::size_t pos = start; pos < end; ++pos) {
      if (!std::isdigit(static_cast<unsigned char>(text[pos]))) return false;
      value = value * 10UL + static_cast<unsigned long>(text[pos] - '0');
      if (value > 255UL) return false;
    }
    parts[i] = static_cast<std::uint32_t>(value);
    start = end + 1;
  }
  out = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  return true;
}

std::string ipv4_to_string(std::uint32_t ip) {
  return std::to_string((ip >> 24) & 0xFFU) + "." +
         std::to_string((ip >> 16) & 0xFFU) + "." +
         std::to_string((ip >> 8) & 0xFFU) + "." +
         std::to_string(ip & 0xFFU);
}

bool parse_ipv4_cidr(const std::string& text, std::uint64_t& start, std::uint64_t& end) {
  const std::size_t slash = text.find('/');
  const std::string ip_text = slash == std::string::npos ? text : text.substr(0, slash);
  int prefix = 32;
  if (slash != std::string::npos) {
    const std::string prefix_text = text.substr(slash + 1);
    if (prefix_text.empty()) return false;
    prefix = std::stoi(prefix_text);
    if (prefix < 0 || prefix > 32) return false;
  }
  std::uint32_t ip = 0;
  if (!parse_ipv4_literal(ip_text, ip)) return false;
  const std::uint32_t mask = prefix == 0 ? 0U : static_cast<std::uint32_t>(0xFFFFFFFFU << (32 - prefix));
  const std::uint32_t network = ip & mask;
  const std::uint32_t broadcast = network | ~mask;
  start = static_cast<std::uint64_t>(network);
  end = static_cast<std::uint64_t>(broadcast);
  return true;
}

bool parse_hextet(const std::string& token, std::uint16_t& out) {
  if (token.empty() || token.size() > 4) return false;
  unsigned value = 0;
  for (char ch : token) {
    value <<= 4U;
    if (ch >= '0' && ch <= '9') {
      value += static_cast<unsigned>(ch - '0');
    } else if (ch >= 'a' && ch <= 'f') {
      value += static_cast<unsigned>(ch - 'a' + 10);
    } else if (ch >= 'A' && ch <= 'F') {
      value += static_cast<unsigned>(ch - 'A' + 10);
    } else {
      return false;
    }
  }
  out = static_cast<std::uint16_t>(value);
  return true;
}

bool parse_ipv6_literal(const std::string& text, unsigned __int128& out) {
  if (text.empty()) return false;
  std::vector<std::uint16_t> left;
  std::vector<std::uint16_t> right;
  const std::size_t compress = text.find("::");
  if (compress != std::string::npos && text.find("::", compress + 2) != std::string::npos) return false;

  auto parse_side = [](const std::string& side, std::vector<std::uint16_t>& words) -> bool {
    if (side.empty()) return true;
    std::size_t start = 0;
    while (start <= side.size()) {
      std::size_t end = side.find(':', start);
      if (end == std::string::npos) end = side.size();
      std::uint16_t word = 0;
      if (!parse_hextet(side.substr(start, end - start), word)) return false;
      words.push_back(word);
      if (end == side.size()) break;
      start = end + 1;
    }
    return true;
  };

  if (compress == std::string::npos) {
    if (!parse_side(text, left) || left.size() != 8) return false;
  } else {
    if (!parse_side(text.substr(0, compress), left)) return false;
    if (!parse_side(text.substr(compress + 2), right)) return false;
    if (left.size() + right.size() >= 8) return false;
  }

  std::array<std::uint16_t, 8> words{};
  std::size_t pos = 0;
  for (std::uint16_t w : left) words[pos++] = w;
  if (compress != std::string::npos) {
    const std::size_t zeros = 8 - left.size() - right.size();
    pos += zeros;
    for (std::size_t i = 0; i < right.size(); ++i) words[pos + i] = right[i];
  }

  out = 0;
  for (std::uint16_t w : words) {
    out = (out << 16) | static_cast<unsigned __int128>(w);
  }
  return true;
}

std::string ipv6_to_string(unsigned __int128 ip) {
  std::array<std::uint16_t, 8> words{};
  for (int i = 7; i >= 0; --i) {
    words[static_cast<std::size_t>(i)] = static_cast<std::uint16_t>(ip & 0xFFFFU);
    ip >>= 16;
  }

  int best_start = -1;
  int best_len = 0;
  for (int i = 0; i < 8;) {
    if (words[static_cast<std::size_t>(i)] != 0) {
      ++i;
      continue;
    }
    int j = i;
    while (j < 8 && words[static_cast<std::size_t>(j)] == 0) ++j;
    if (j - i > best_len && j - i >= 2) {
      best_start = i;
      best_len = j - i;
    }
    i = j;
  }

  std::ostringstream oss;
  oss << std::hex << std::nouppercase;
  bool just_compressed = false;
  for (int i = 0; i < 8; ++i) {
    if (i == best_start) {
      oss << "::";
      just_compressed = true;
      i += best_len - 1;
      if (i == 7) break;
      continue;
    }
    if (i > 0 && !just_compressed) oss << ':';
    oss << words[static_cast<std::size_t>(i)];
    just_compressed = false;
  }
  return oss.str();
}

std::uint64_t clamp_u128_to_u64(unsigned __int128 value) {
  const unsigned __int128 max_u64 = static_cast<unsigned __int128>(std::numeric_limits<std::uint64_t>::max());
  return value > max_u64 ? std::numeric_limits<std::uint64_t>::max() : static_cast<std::uint64_t>(value);
}

bool parse_ipv6_cidr(const std::string& text, unsigned __int128& start, unsigned __int128& end) {
  const std::size_t slash = text.find('/');
  const std::string ip_text = slash == std::string::npos ? text : text.substr(0, slash);
  int prefix = 128;
  if (slash != std::string::npos) {
    const std::string prefix_text = text.substr(slash + 1);
    if (prefix_text.empty()) return false;
    prefix = std::stoi(prefix_text);
    if (prefix < 0 || prefix > 128) return false;
  }
  unsigned __int128 ip = 0;
  if (!parse_ipv6_literal(ip_text, ip)) return false;
  const unsigned __int128 all = ~static_cast<unsigned __int128>(0);
  const unsigned __int128 mask = prefix == 0 ? 0 : (all << (128 - prefix));
  start = ip & mask;
  end = start | (~mask);
  return true;
}

struct IpSpan {
  unsigned __int128 start = 0;
  unsigned __int128 end = 0;
  std::uint64_t width = 0;
  int family = 4;
};

bool parse_ip_span_string(const std::string& text, int family, IpSpan& span) {
  if (family == 4) {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    if (!parse_ipv4_cidr(text, start, end)) return false;
    span.start = static_cast<unsigned __int128>(start);
    span.end = static_cast<unsigned __int128>(end);
    span.width = static_cast<std::uint64_t>(end - start + 1ULL);
    span.family = 4;
    return true;
  }
  unsigned __int128 start = 0;
  unsigned __int128 end = 0;
  if (!parse_ipv6_cidr(text, start, end)) return false;
  span.start = start;
  span.end = end;
  span.width = clamp_u128_to_u64(end - start + 1);
  span.family = 6;
  return true;
}

bool parse_ip_literal_for_family(const std::string& text, int family, unsigned __int128& out) {
  if (family == 4) {
    std::uint32_t ip = 0;
    if (!parse_ipv4_literal(text, ip)) return false;
    out = static_cast<unsigned __int128>(ip);
    return true;
  }
  return parse_ipv6_literal(text, out);
}

std::string ip_to_string(unsigned __int128 ip, int family) {
  if (family == 4) {
    return ipv4_to_string(static_cast<std::uint32_t>(ip));
  }
  return ipv6_to_string(ip);
}

FlowOp parse_op(const json::Value& obj) {
  FlowOp op;
  op.opcode = GetStr(obj, "opcode");
  op.method = GetStr(obj, "method");
  op.path = GetStr(obj, "path");
  op.headers = GetStrMap(obj, "headers");
  const json::Value* body = obj.find("body");
  if (body != nullptr && body->is_string()) {
    const std::string raw = body->as_string();
    op.body.assign(raw.begin(), raw.end());
  }
  const json::Value* expect = obj.find("expect");
  if (expect != nullptr && !expect->is_null()) {
    op.has_expect = true;
    op.expect.kind = GetStr(*expect, "kind");
    op.expect.name = GetStr(*expect, "name");
    op.expect.value = GetStr(*expect, "value");
    op.expect.status_min = GetInt(*expect, "status_min", op.expect.status_min);
    op.expect.status_max = GetInt(*expect, "status_max", op.expect.status_max);
  }
  op.capture_name = GetStr(obj, "capture_name");
  op.capture_source = GetStr(obj, "capture_source");
  op.think_time_ms = GetInt(obj, "think_time_ms", op.think_time_ms);
  op.loop_count = GetInt(obj, "loop_count", op.loop_count);

  // Parse L7 scenario fields
  op.tls_sni = GetStr(obj, "tls_sni");
  op.tls_alpn = GetStr(obj, "tls_alpn");
  op.tls_cipher_list = GetStr(obj, "tls_cipher_list");
  op.tls_verify = GetInt(obj, "tls_verify", op.tls_verify);

  op.dns_hostname = GetStr(obj, "dns_hostname");
  op.dns_protocol = GetStr(obj, "dns_protocol", op.dns_protocol);
  op.dns_qtype = GetStr(obj, "dns_qtype", op.dns_qtype);
  op.dns_edns0 = GetInt(obj, "dns_edns0", op.dns_edns0);
  op.dns_ecs_subnet = GetStr(obj, "dns_ecs_subnet");

  op.dhcp_client_mac = GetStr(obj, "dhcp_client_mac");
  op.dhcp_version = GetInt(obj, "dhcp_version", op.dhcp_version);

  op.igmp_group_ip = GetStr(obj, "igmp_group_ip");
  op.igmp_version = GetInt(obj, "igmp_version", op.igmp_version);

  op.nd_target_ip = GetStr(obj, "nd_target_ip");

  return op;
}

std::uint64_t ip_range_size(const json::Value& entry, int family) {
  if (entry.is_string()) {
    IpSpan span;
    if (!parse_ip_span_string(entry.as_string(), family, span)) {
      throw std::runtime_error("topology ip family mismatch");
    }
    return span.width;
  }
  if (entry.is_object()) {
    const json::Value* s = entry.find("start");
    const json::Value* e = entry.find("end");
    if (s == nullptr || e == nullptr) {
      throw std::runtime_error("ip range object requires start/end");
    }
    unsigned __int128 start_i = 0;
    unsigned __int128 end_i = 0;
    if (!parse_ip_literal_for_family(s->as_string(), family, start_i) ||
        !parse_ip_literal_for_family(e->as_string(), family, end_i)) {
      throw std::runtime_error("topology ip range wrong family");
    }
    if (end_i < start_i) {
      throw std::runtime_error("topology ip range start>end");
    }
    return clamp_u128_to_u64(end_i - start_i + 1);
  }
  throw std::runtime_error("ip range must be cidr string or {start,end}");
}

std::uint64_t ip_ranges_size(const json::Value& ranges) {
  std::uint64_t total = 0;
  const json::Value* v4 = ranges.find("v4");
  if (v4 != nullptr && v4->is_array()) {
    for (const auto& it : v4->elements()) total += ip_range_size(it, 4);
  }
  const json::Value* v6 = ranges.find("v6");
  if (v6 != nullptr && v6->is_array()) {
    for (const auto& it : v6->elements()) total += ip_range_size(it, 6);
  }
  return total;
}

void require_list_field(const json::Value& root, const char* key, bool strict) {
  const json::Value* p = root.find(key);
  if (p == nullptr) {
    if (strict) throw std::runtime_error(std::string("missing required field: ") + key);
    return;
  }
  if (!p->is_array()) {
    throw std::runtime_error(std::string("field must be list: ") + key);
  }
}

}  // namespace

Profile parse_profile(const json::Value& profile_dict) {
  Profile profile;
  profile.protocol = GetStr(profile_dict, "protocol");
  profile.sender_path = GetStr(profile_dict, "sender_path");
  profile.flow_attempted = GetInt(profile_dict, "flow_attempted", profile.flow_attempted);
  const json::Value* conn = profile_dict.find("connection_template");
  if (conn != nullptr && conn->is_object()) {
    profile.transport_backend = GetStr(*conn, "transport_backend", profile.transport_backend);
    profile.stateful_runtime_backend = GetStr(*conn, "stateful_runtime_backend", profile.stateful_runtime_backend);
    profile.stateful_runtime_strict = GetInt(*conn, "stateful_runtime_strict", profile.stateful_runtime_strict);
    profile.legacy_mode = GetInt(*conn, "legacy_mode", profile.legacy_mode);
    std::string raw_reactor = GetStr(*conn, "reactor_backend");
    if (raw_reactor.empty()) {
      raw_reactor = GetStr(profile_dict, "reactor_backend");
    }
    if (!raw_reactor.empty()) {
      profile.reactor_backend = raw_reactor;
    }
    profile.source_ip = GetStr(*conn, "source_ip");
    if (profile.source_ip.empty()) profile.source_ip = GetStr(*conn, "client_ip");
    profile.target_ip = GetStr(*conn, "target_ip");
    profile.target_port = GetInt(*conn, "target_port", profile.target_port);
    profile.scheme = GetStr(*conn, "scheme");
    profile.host_header = GetStr(*conn, "host_header");
    profile.tls_cipher_list = GetStr(*conn, "tls_cipher_list");
    profile.tls_ktls = GetInt(*conn, "tls_ktls", profile.tls_ktls);
    profile.verify = GetInt(*conn, "verify", profile.verify);
    profile.keepalive = GetInt(*conn, "keepalive", profile.keepalive);
    profile.timeout_ms = GetInt(*conn, "timeout_ms", profile.timeout_ms);
    profile.max_connections = GetInt(*conn, "max_connections", profile.max_connections);
    profile.max_streams_per_connection = GetInt(*conn, "max_streams_per_connection", profile.max_streams_per_connection);
    profile.session_repeats = GetInt(*conn, "session_repeats", profile.session_repeats);
  }
  const json::Value* flow_program = profile_dict.find("flow_program");
  if (flow_program != nullptr && flow_program->is_object()) {
    const json::Value* ops = flow_program->find("ops");
    if (ops != nullptr && ops->is_array()) {
      for (const auto& item : ops->elements()) {
        if (item.is_object()) profile.ops.push_back(parse_op(item));
      }
    }
  }
  return profile;
}

RuntimeConfig parse_runtime_cfg(const json::Value& cfg_dict) {
  RuntimeConfig cfg;
  cfg.concurrency = GetInt(cfg_dict, "concurrency", cfg.concurrency);
  cfg.profile_l7 = GetInt(cfg_dict, "profile_l7", cfg.profile_l7);
  cfg.profile_sample_limit = GetInt(cfg_dict, "profile_sample_limit", cfg.profile_sample_limit);
  return cfg;
}

json::Value runtime_capabilities_json() {
  const RuntimeCapabilities caps = detect_capabilities();
  bool quic_native_built = false;
#if defined(SAMURAI_WITH_NGTCP2) && defined(SAMURAI_WITH_NGHTTP3) && defined(SAMURAI_WITH_GNUTLS) && defined(SAMURAI_WITH_NGTCP2_GNUTLS)
  quic_native_built = true;
#endif
  json::Value out = json::Value::Object();
  out.set("openssl", json::Value::Bool(caps.openssl));
  out.set("nghttp2", json::Value::Bool(caps.nghttp2));
  out.set("ngtcp2", json::Value::Bool(caps.ngtcp2));
  out.set("nghttp3", json::Value::Bool(caps.nghttp3));
  out.set("io_uring", json::Value::Bool(caps.io_uring));
  out.set("quic_native", json::Value::Bool(quic_native_built));
  return out;
}

json::Value run_profile_json(const json::Value& profile_dict, const json::Value& cfg_dict) {
  const Profile profile = parse_profile(profile_dict);
  const RuntimeConfig cfg = parse_runtime_cfg(cfg_dict);
  const RuntimeCapabilities caps = detect_capabilities();
  const bool strict_runtime = profile.stateful_runtime_strict != 0;
  const bool is_quic_profile = ToLower(profile.protocol) == "quic";
  const bool runtime_requires_custom_tcp = strict_runtime && !is_quic_profile;
  const std::string requested_transport = ToLower(profile.transport_backend);
  const std::string requested_stateful_backend = ToLower(profile.stateful_runtime_backend);
  const bool is_dpdk_direct = requested_transport == "dpdk" || requested_transport == "dpdk_direct" || requested_stateful_backend == "dpdk";
  const bool requested_custom_tcp = requested_transport == "custom_tcp" || is_dpdk_direct;
  const TransportBackend transport_backend =
      is_quic_profile
          ? TransportBackend::CustomQuic
          : (requested_transport == "kernel_socket"
                 ? TransportBackend::KernelSocket
                 : (is_dpdk_direct
                        ? TransportBackend::DpdkDirect
                        : TransportBackend::CustomTcp));

  auto build_failed = [&](const std::string& reason, const std::string& detail) {
    json::Value failed = json::Value::Object();
    failed.set("sender_path", json::Value::Str(profile.sender_path));
    failed.set("sender_fallback_reason", json::Value::Str(reason));
    failed.set("l7_engine_path_used", json::Value::Str("L7_EMU_NATIVE"));
    failed.set("l7_fallback_reason", json::Value::Str(reason));
    failed.set("stateful_runtime_reason", json::Value::Str(reason));
    failed.set("stateful_runtime_detail", json::Value::Str(detail));
    failed.set("attempted", json::Value::Int(profile.flow_attempted));
    failed.set("sent", json::Value::Int(0));
    failed.set("errors", json::Value::Int(profile.flow_attempted));
    failed.set("l7_flow_attempted", json::Value::Int(profile.flow_attempted));
    failed.set("l7_flow_completed", json::Value::Int(0));
    failed.set("l7_expectation_failures", json::Value::Int(profile.flow_attempted));
    const ReactorBackend failed_reactor = resolve_reactor_backend(profile.reactor_backend, caps.io_uring);
    failed.set("runtime_reactor_backend", json::Value::Str(reactor_backend_name(failed_reactor)));
    failed.set("runtime_transport_backend", json::Value::Str(transport_backend_name(transport_backend)));
    failed.set("runtime_tls_backend", json::Value::Str(caps.openssl ? "openssl" : "unavailable"));
    failed.set("runtime_http2_backend", json::Value::Str(caps.nghttp2 ? "nghttp2_native" : "unavailable"));
    failed.set("runtime_native_hot_path_level", json::Value::Str("userspace_reactor_templates"));
    failed.set("runtime_transport_custom_tcp_requested", json::Value::Int(0));
    failed.set("runtime_transport_custom_tcp_bridge_ready", json::Value::Int(0));
    failed.set("runtime_transport_custom_tcp_rx_bridge_active", json::Value::Int(0));
    failed.set("runtime_transport_seam_ready", json::Value::Int(0));
    return failed;
  };

  if (runtime_requires_custom_tcp && !requested_custom_tcp) {
    return build_failed(
        "stateful_runtime_transport_unavailable",
        "kernel_socket fallback is disabled; strict stateful runtime requires custom_tcp transport.");
  }

  std::map<std::string, double> out = run_profile(profile, cfg);
  const auto active_uring_it = out.find("runtime_reactor_io_uring_active");
  const bool was_uring_active = active_uring_it != out.end() && active_uring_it->second > 0.0;
  const ReactorBackend reactor_backend = was_uring_active ? ReactorBackend::SocketIoUring : ReactorBackend::SocketEpoll;
  const TlsBackend tls_backend = caps.openssl ? TlsBackend::OpenSSL : TlsBackend::Unavailable;
  const Http2Backend http2_backend = caps.nghttp2 ? Http2Backend::Nghttp2Native : Http2Backend::Unavailable;
  const NativeHotPathLevel hot_path_level = NativeHotPathLevel::UserspaceReactorTemplates;

  json::Value result = json::Value::Object();
  result.set("sender_path", json::Value::Str(profile.protocol == "quic" ? "L7_QUIC_CUSTOM" : profile.sender_path));
  result.set("sender_fallback_reason", json::Value::Str("none"));
  result.set("l7_engine_path_used", json::Value::Str(profile.protocol == "quic" ? "L7_QUIC_CUSTOM" : "L7_EMU_NATIVE"));
  result.set("l7_fallback_reason", json::Value::Str("none"));
  result.set("runtime_reactor_backend", json::Value::Str(reactor_backend_name(reactor_backend)));
  result.set("runtime_transport_backend", json::Value::Str(transport_backend_name(transport_backend)));
  result.set("runtime_tls_backend", json::Value::Str(tls_backend_name(tls_backend)));
  result.set("runtime_http2_backend", json::Value::Str(http2_backend_name(http2_backend)));
  result.set("runtime_native_hot_path_level", json::Value::Str(native_hot_path_level_name(hot_path_level)));

  const auto custom_tcp_bridge_ready = out.find("runtime_transport_custom_tcp_bridge_ready");
  if (transport_backend == TransportBackend::CustomTcp &&
      custom_tcp_bridge_ready != out.end() &&
      custom_tcp_bridge_ready->second == 0.0) {
    const auto reason_code_it = out.find("runtime_failure_reason_code");
    const double reason_code = reason_code_it != out.end() ? reason_code_it->second : 0.0;
    const RuntimeFailureReason resolved = runtime_failure_reason_from_code(reason_code);
    result.set("sender_fallback_reason", json::Value::Str(resolved.reason));
    result.set("l7_fallback_reason", json::Value::Str(resolved.reason));
    result.set("stateful_runtime_reason", json::Value::Str(resolved.reason));
    result.set("stateful_runtime_detail", json::Value::Str(resolved.detail));
  }
  if (profile.protocol == "http2") {
    result.set("h2_transport", json::Value::Str(
        transport_backend == TransportBackend::CustomTcp ? "custom_tcp_native" : "nghttp2_native"));
    if (transport_backend != TransportBackend::CustomTcp && !(caps.openssl && caps.nghttp2)) {
      result.set("sender_fallback_reason", json::Value::Str("capability_unavailable:nghttp2_native"));
      result.set("l7_fallback_reason", json::Value::Str("capability_unavailable:nghttp2_native"));
    }
  }
  if (profile.protocol == "quic") {
    const auto quic_capability_available_it = out.find("quic_capability_available");
    const bool quic_capability_available =
        quic_capability_available_it != out.end() && quic_capability_available_it->second > 0.0;
    const auto quic_hot_path_ready_it = out.find("quic_runtime_native_hot_path_ready");
    const bool quic_hot_path_ready =
        quic_hot_path_ready_it != out.end() && quic_hot_path_ready_it->second > 0.0;
    result.set("runtime_http3_backend", json::Value::Str(quic_capability_available ? "nghttp3_native" : "unavailable"));
    result.set("runtime_quic_transport_backend", json::Value::Str(
        quic_capability_available
            ? (quic_hot_path_ready ? "custom_quic_stack_hotpath" : "kernel_udp_socket")
            : "unavailable"));
    result.set("runtime_quic_hot_path_ready", json::Value::Int(quic_hot_path_ready ? 1 : 0));
    result.set("quic_stack_mode", json::Value::Str(quic_capability_available ? "custom_native" : "unavailable"));
    if (!quic_capability_available) {
      result.set("sender_fallback_reason", json::Value::Str("quic_capability_unavailable"));
      result.set("l7_fallback_reason", json::Value::Str("quic_capability_unavailable"));
    }
  }
  if (result.find("stateful_runtime_reason") == nullptr) {
    result.set("stateful_runtime_reason", json::Value::Str("none"));
    result.set("stateful_runtime_detail", json::Value::Str(""));
  }
  for (const auto& [key, value] : out) {
    if (key == "l7_engine_path_used" ||
        key == "sender_path" ||
        key == "sender_fallback_reason" ||
        key == "l7_fallback_reason") {
      continue;
    }
    const double integral = static_cast<double>(static_cast<long long>(value));
    if (value == integral) {
      result.set(key, json::Value::Int(static_cast<long long>(integral)));
    } else {
      result.set(key, json::Value::Double(value));
    }
  }
  json::Value step_results = json::Value::Array();
  for (const auto& row : consume_last_scenario_step_results()) {
    json::Value it = json::Value::Object();
    it.set("flow", json::Value::Str(row.flow));
    it.set("vu_id", json::Value::Str(row.vu_id));
    it.set("on_failure", json::Value::Str(row.on_failure));
    it.set("success", json::Value::Bool(row.success));
    it.set("timeout", json::Value::Bool(row.timeout));
    it.set("status_code", json::Value::Int(row.status_code));
    it.set("latency_ms", json::Value::Double(row.latency_ms));
    it.set("protocol", json::Value::Str(row.protocol));
    step_results.push_back(std::move(it));
  }
  result.set("scenario_step_results", std::move(step_results));
  return result;
}

json::Value compile_topology_json(const std::string& json_text, int seed, bool strict) {
  const json::ParseResult loaded = json::Parse(json_text);
  if (!loaded.ok) {
    throw std::runtime_error("topology json parse failed: " + loaded.error);
  }
  if (!loaded.value.is_object()) {
    throw std::runtime_error("topology root must be object");
  }
  const json::Value& root = loaded.value;
  require_list_field(root, "clients", strict);
  require_list_field(root, "servers", strict);
  require_list_field(root, "templates", strict);
  require_list_field(root, "links", strict);

  const json::Value* clients = root.find("clients");
  const json::Value* servers = root.find("servers");
  const json::Value* templates = root.find("templates");
  const json::Value* links = root.find("links");

  if (strict &&
      (clients == nullptr || clients->elements().empty() ||
       servers == nullptr || servers->elements().empty() ||
       templates == nullptr || templates->elements().empty() ||
       links == nullptr || links->elements().empty())) {
    throw std::runtime_error("topology requires non-empty clients/servers/templates/links");
  }

  std::uint64_t client_pool = 0;
  if (clients != nullptr) {
    for (const auto& c_obj : clients->elements()) {
      if (!c_obj.is_object()) throw std::runtime_error("client entry must be object");
      if (!c_obj.contains("name") || !c_obj.contains("ip_ranges") || !c_obj.contains("port_ranges")) {
        throw std::runtime_error("client requires name/ip_ranges/port_ranges");
      }
      const json::Value* ip_ranges = c_obj.find("ip_ranges");
      if (ip_ranges == nullptr || !ip_ranges->is_object()) {
        throw std::runtime_error("client ip_ranges must be object");
      }
      client_pool += ip_ranges_size(*ip_ranges);
    }
  }

  std::uint64_t server_pool = 0;
  if (servers != nullptr) {
    for (const auto& s_obj : servers->elements()) {
      if (!s_obj.is_object()) throw std::runtime_error("server entry must be object");
      if (!s_obj.contains("name") || !s_obj.contains("ip_ranges") || !s_obj.contains("ports")) {
        throw std::runtime_error("server requires name/ip_ranges/ports");
      }
      const json::Value* ip_ranges = s_obj.find("ip_ranges");
      if (ip_ranges == nullptr || !ip_ranges->is_object()) {
        throw std::runtime_error("server ip_ranges must be object");
      }
      server_pool += ip_ranges_size(*ip_ranges);
    }
  }

  json::Value digest_payload = json::Value::Object();
  digest_payload.set("seed", json::Value::Int(seed));
  digest_payload.set("spec", loaded.value);
  const std::string hexdigest = sha1_hexdigest(digest_payload.dump(true));
  const std::string plan_id = hexdigest.substr(0, 16);

  json::Value out = json::Value::Object();
  out.set("plan_id", json::Value::Str(plan_id));
  out.set("seed", json::Value::Int(seed));
  out.set("client_pool_size", json::Value::Int(static_cast<std::int64_t>(client_pool)));
  out.set("server_pool_size", json::Value::Int(static_cast<std::int64_t>(server_pool)));
  out.set("spec", loaded.value);
  return out;
}

namespace {

double stable_u01(int seed, int idx, const std::string& salt) {
  const std::string token = std::to_string(seed) + ":" + std::to_string(idx) + ":" + salt;
  const auto raw = sha1_digest(token);
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v = (v << 8) | static_cast<std::uint64_t>(raw[static_cast<std::size_t>(i)]);
  }
  const std::uint64_t frac = v & ((1ULL << 53) - 1ULL);
  return static_cast<double>(frac) / static_cast<double>(1ULL << 53);
}

const json::Value* find_group(const json::Value& pool, const std::string& name) {
  for (const auto& item : pool.elements()) {
    if (!item.is_object()) continue;
    const json::Value* n = item.find("name");
    if (n != nullptr && n->is_string() && n->as_string() == name) return &item;
  }
  return nullptr;
}

std::string pick_ip(const json::Value& ip_ranges, int idx, const std::string& dist, const std::string& salt, int seed) {
  const json::Value* entries = nullptr;
  int family = 4;
  const json::Value* v4 = ip_ranges.find("v4");
  if (v4 != nullptr && v4->is_array() && !v4->elements().empty()) {
    entries = v4;
    family = 4;
  } else {
    const json::Value* v6 = ip_ranges.find("v6");
    if (v6 != nullptr && v6->is_array() && !v6->elements().empty()) {
      entries = v6;
      family = 6;
    } else {
      return std::string();
    }
  }
  std::vector<IpSpan> spans;
  std::uint64_t total = 0;
  for (const auto& it : entries->elements()) {
    IpSpan span;
    if (it.is_string()) {
      if (!parse_ip_span_string(it.as_string(), family, span)) continue;
    } else if (it.is_object()) {
      const json::Value* s = it.find("start");
      const json::Value* e = it.find("end");
      if (s == nullptr || e == nullptr) continue;
      if (!parse_ip_literal_for_family(s->as_string(), family, span.start) ||
          !parse_ip_literal_for_family(e->as_string(), family, span.end)) {
        continue;
      }
      if (span.end < span.start) continue;
      span.width = clamp_u128_to_u64(span.end - span.start + 1);
      span.family = family;
    } else {
      continue;
    }
    if (span.width == 0) continue;
    spans.push_back(span);
    const std::uint64_t remaining = std::numeric_limits<std::uint64_t>::max() - total;
    total = span.width > remaining ? std::numeric_limits<std::uint64_t>::max() : total + span.width;
  }
  if (spans.empty() || total == 0) return std::string();
  std::uint64_t off = 0;
  if (dist == "seq") {
    off = static_cast<std::uint64_t>(idx) % total;
  } else if (dist == "zipf") {
    const double u = stable_u01(seed, idx, salt + ":zipf");
    off = static_cast<std::uint64_t>((u * u * u) * static_cast<double>(total - 1));
  } else {
    const double u = stable_u01(seed, idx, salt + ":uniform");
    off = static_cast<std::uint64_t>(u * static_cast<double>(total - 1));
  }
  for (const auto& span : spans) {
    if (off < span.width) {
      return ip_to_string(span.start + static_cast<unsigned __int128>(off), family);
    }
    off -= span.width;
  }
  return ip_to_string(spans.back().start, family);
}

std::pair<int, int> parse_port_range(const json::Value& item) {
  if (item.is_int()) {
    const int p = static_cast<int>(item.as_int(1024));
    return std::make_pair(p, p);
  }
  if (item.is_string()) {
    const std::string token = item.as_string();
    const std::size_t dash = token.find('-');
    if (dash == std::string::npos) {
      const int p = std::stoi(token);
      return std::make_pair(p, p);
    }
    const int a = std::stoi(token.substr(0, dash));
    const int b = std::stoi(token.substr(dash + 1));
    return std::make_pair(a, b);
  }
  if (item.is_object()) {
    const int a = GetInt(item, "start", 0);
    const int b = GetInt(item, "end", 0);
    return std::make_pair(a, b);
  }
  return std::make_pair(1024, 1024);
}

int pick_client_port(const json::Value& ranges, int idx, const std::string& salt, const std::string& allocator, int seed) {
  std::vector<std::pair<int, int>> parsed;
  long long total = 0;
  for (const auto& it : ranges.elements()) {
    auto pr = parse_port_range(it);
    if (pr.first < 1) pr.first = 1;
    if (pr.second > 65535) pr.second = 65535;
    if (pr.second < pr.first) continue;
    parsed.push_back(pr);
    total += static_cast<long long>(pr.second - pr.first + 1);
  }
  if (parsed.empty() || total <= 0) return 1024;
  long long off = 0;
  if (allocator == "sequential") {
    off = static_cast<long long>(idx) % total;
  } else if (allocator == "random") {
    off = static_cast<long long>(stable_u01(seed, idx, salt + ":cport_random") * static_cast<double>(total - 1));
  } else {
    off = static_cast<long long>(stable_u01(seed, idx, salt + ":cport_hash") * static_cast<double>(total - 1));
  }
  for (const auto& pr : parsed) {
    const long long width = static_cast<long long>(pr.second - pr.first + 1);
    if (off < width) return static_cast<int>(pr.first + off);
    off -= width;
  }
  return parsed.front().first;
}

int pick_server_port(const json::Value& ports, int idx, const std::string& salt, const std::string& allocator, int seed) {
  const std::size_t port_count = ports.elements().size();
  if (port_count == 0) return 80;
  std::size_t pos = 0;
  if (allocator == "sequential") {
    pos = static_cast<std::size_t>(idx) % port_count;
  } else if (allocator == "random") {
    pos = static_cast<std::size_t>(
        stable_u01(seed, idx, salt + ":sport_random") * static_cast<double>(port_count));
  } else {
    pos = static_cast<std::size_t>(
        stable_u01(seed, idx, salt + ":sport_hash") * static_cast<double>(port_count));
  }
  if (pos >= port_count) pos = port_count - 1;
  return static_cast<int>(ports.elements()[pos].as_int(80));
}

}  // namespace

json::Value topology_tuple_preview_json(const json::Value& compiled_plan, int sample_size) {
  const json::Value* spec = compiled_plan.find("spec");
  if (spec == nullptr || !spec->is_object()) {
    throw std::runtime_error("compiled topology plan missing spec");
  }
  const json::Value* clients = spec->find("clients");
  const json::Value* servers = spec->find("servers");
  const json::Value* templates = spec->find("templates");
  const json::Value* links = spec->find("links");
  if (clients == nullptr || servers == nullptr || links == nullptr ||
      clients->elements().empty() || servers->elements().empty() || links->elements().empty()) {
    return json::Value::Array();
  }

  const int seed = GetInt(compiled_plan, "seed", 0);
  std::string allocator = "hash";
  const json::Value* tuple_gen = spec->find("tuple_gen");
  if (tuple_gen != nullptr && tuple_gen->is_object()) {
    allocator = GetStr(*tuple_gen, "port_allocator", allocator);
  }

  json::Value out = json::Value::Array();
  int n = sample_size < 0 ? 0 : sample_size;
  for (int i = 0; i < n; ++i) {
    const json::Value& l = links->elements()[static_cast<std::size_t>(i % links->elements().size())];
    const std::string client_name = GetStr(l, "client_group");
    const std::string server_name = GetStr(l, "server_group");
    const std::string template_name = GetStr(l, "template");
    const json::Value* c = find_group(*clients, client_name);
    const json::Value* s = find_group(*servers, server_name);
    const json::Value* t = templates != nullptr ? find_group(*templates, template_name) : nullptr;
    if (c == nullptr || s == nullptr) continue;
    const json::Value* c_ranges = c->find("ip_ranges");
    const json::Value* s_ranges = s->find("ip_ranges");
    const json::Value* c_port_ranges = c->find("port_ranges");
    const json::Value* s_ports = s->find("ports");
    const json::Value kEmptyObj = json::Value::Object();
    const json::Value kEmptyArr = json::Value::Array();
    if (c_ranges == nullptr || !c_ranges->is_object()) c_ranges = &kEmptyObj;
    if (s_ranges == nullptr || !s_ranges->is_object()) s_ranges = &kEmptyObj;
    if (c_port_ranges == nullptr || !c_port_ranges->is_array()) c_port_ranges = &kEmptyArr;
    if (s_ports == nullptr || !s_ports->is_array()) s_ports = &kEmptyArr;
    const std::string c_dist = GetStr(*c, "dist", "uniform");
    const std::string client_ip = pick_ip(*c_ranges, i, c_dist, client_name + ":client_ip", seed);
    const std::string server_ip = pick_ip(*s_ranges, i + 17, "uniform", server_name + ":server_ip", seed);
    const int client_port = pick_client_port(
        *c_port_ranges, i, client_ip + ":" + server_ip + ":" + template_name, allocator, seed);
    const int server_port = pick_server_port(
        *s_ports, i, server_ip + ":" + client_ip + ":" + template_name, allocator, seed);

    json::Value row = json::Value::Object();
    row.set("client_group", json::Value::Str(client_name));
    row.set("server_group", json::Value::Str(server_name));
    row.set("template", json::Value::Str(template_name));
    row.set("client_ip", json::Value::Str(client_ip));
    row.set("server_ip", json::Value::Str(server_ip));
    row.set("client_port", json::Value::Int(client_port));
    row.set("server_port", json::Value::Int(server_port));
    if (t != nullptr) {
      if (t->contains("protocol")) row.set("template_protocol", *t->find("protocol"));
      if (t->contains("method")) row.set("template_method", *t->find("method"));
      if (t->contains("path")) row.set("template_path", *t->find("path"));
      if (t->contains("flags")) row.set("template_flags", *t->find("flags"));
    }
    out.push_back(std::move(row));
  }
  return out;
}

FiveTuple generate_5tuple(const json::Value& compiled_plan, uint64_t index) {
  FiveTuple tup{};
  const json::Value* spec = compiled_plan.find("spec");
  if (spec == nullptr || !spec->is_object()) {
    return tup;
  }
  const json::Value* clients = spec->find("clients");
  const json::Value* servers = spec->find("servers");
  const json::Value* templates = spec->find("templates");
  const json::Value* links = spec->find("links");
  if (clients == nullptr || servers == nullptr || links == nullptr ||
      clients->elements().empty() || servers->elements().empty() || links->elements().empty()) {
    return tup;
  }

  const int seed = GetInt(compiled_plan, "seed", 0);
  std::string allocator = "hash";
  const json::Value* tuple_gen = spec->find("tuple_gen");
  if (tuple_gen != nullptr && tuple_gen->is_object()) {
    allocator = GetStr(*tuple_gen, "port_allocator", allocator);
  }

  const int idx = static_cast<int>(index);
  const json::Value& l = links->elements()[static_cast<std::size_t>(index % links->elements().size())];
  tup.client_group = GetStr(l, "client_group");
  tup.server_group = GetStr(l, "server_group");
  tup.template_name = GetStr(l, "template");

  const json::Value* c = find_group(*clients, tup.client_group);
  const json::Value* s = find_group(*servers, tup.server_group);
  const json::Value* t = templates != nullptr ? find_group(*templates, tup.template_name) : nullptr;
  if (c == nullptr || s == nullptr) return tup;

  const json::Value* c_ranges = c->find("ip_ranges");
  const json::Value* s_ranges = s->find("ip_ranges");
  const json::Value* c_port_ranges = c->find("port_ranges");
  const json::Value* s_ports = s->find("ports");

  const json::Value kEmptyObj = json::Value::Object();
  const json::Value kEmptyArr = json::Value::Array();
  if (c_ranges == nullptr || !c_ranges->is_object()) c_ranges = &kEmptyObj;
  if (s_ranges == nullptr || !s_ranges->is_object()) s_ranges = &kEmptyObj;
  if (c_port_ranges == nullptr || !c_port_ranges->is_array()) c_port_ranges = &kEmptyArr;
  if (s_ports == nullptr || !s_ports->is_array()) s_ports = &kEmptyArr;

  const std::string c_dist = GetStr(*c, "dist", "uniform");
  tup.client_ip = pick_ip(*c_ranges, idx, c_dist, tup.client_group + ":client_ip", seed);
  tup.server_ip = pick_ip(*s_ranges, idx + 17, "uniform", tup.server_group + ":server_ip", seed);
  tup.client_port = static_cast<uint16_t>(pick_client_port(
      *c_port_ranges, idx, tup.client_ip + ":" + tup.server_ip + ":" + tup.template_name, allocator, seed));
  tup.server_port = static_cast<uint16_t>(pick_server_port(
      *s_ports, idx, tup.server_ip + ":" + tup.client_ip + ":" + tup.template_name, allocator, seed));

  if (t != nullptr && t->contains("protocol")) {
    tup.protocol = GetStr(*t, "protocol", "tcp");
  }
  return tup;
}


json::Value peek_custom_tcp_tx_buffer_strided_json() {
  const std::uint8_t* base = nullptr;
  std::uint32_t count = 0;
  std::size_t packet_size = 0;
  std::size_t stride = 0;
  if (tcpdp_peek_tx_packets_strided(0, &base, &count, &packet_size, &stride) != 0) {
    throw std::runtime_error("failed to peek custom TCP TX strided buffer");
  }
  json::Value out = json::Value::Object();
  if (base != nullptr && count > 0 && stride > 0) {
    out.set("payload_hex", json::Value::Str(bytes_to_hex(base, stride * static_cast<std::size_t>(count))));
  } else {
    out.set("payload_hex", json::Value::Str(""));
  }
  out.set("count", json::Value::Int(static_cast<std::int64_t>(count)));
  out.set("packet_size", json::Value::Int(static_cast<std::int64_t>(packet_size)));
  out.set("stride", json::Value::Int(static_cast<std::int64_t>(stride)));
  out.set("uniform", json::Value::Int(1));
  return out;
}

int consume_custom_tcp_tx_packets(std::uint32_t max_packets) {
  std::uint32_t consumed = 0;
  if (tcpdp_consume_tx_packets(max_packets, &consumed) != 0) {
    throw std::runtime_error("failed to consume custom TCP TX packets");
  }
  return static_cast<int>(consumed);
}

int peek_custom_tcp_tx_packets_raw(
    std::uint32_t max_packets,
    const std::uint8_t** out_base,
    std::uint32_t* out_count,
    std::size_t* out_packet_size,
    std::size_t* out_stride) {
  return tcpdp_peek_tx_packets_strided(max_packets, out_base, out_count, out_packet_size, out_stride);
}

int consume_custom_tcp_tx_packets_raw(std::uint32_t max_packets, std::uint32_t* out_consumed) {
  return tcpdp_consume_tx_packets(max_packets, out_consumed);
}

int ingest_custom_tcp_rx_frame_raw(const std::uint8_t* raw_bytes, std::size_t len, std::uint32_t* out_updated) {
  return tcpdp_ingest_rx_frame(raw_bytes, len, out_updated);
}

int ingest_custom_tcp_rx_frame_hex(const std::string& hex_frame) {
  const std::vector<std::uint8_t> raw = hex_to_bytes(hex_frame);
  std::uint32_t updated = 0;
  if (tcpdp_ingest_rx_frame(raw.data(), raw.size(), &updated) != 0) {
    throw std::runtime_error("failed to ingest custom TCP RX frame");
  }
  return static_cast<int>(updated);
}

json::Value snapshot_custom_tcp_stats_json() {
  tcpdp_stats_snapshot_t stats{};
  if (tcpdp_snapshot_stats(&stats) != 0) {
    throw std::runtime_error("failed to snapshot custom TCP stats");
  }
  json::Value out = json::Value::Object();
  auto set_u64 = [&out](const char* key, std::uint64_t v) {
    out.set(key, json::Value::Int(static_cast<std::int64_t>(v)));
  };
  set_u64("tcp_flows_active", stats.flows_active);
  set_u64("tcp_connect_attempts", stats.connect_attempts);
  set_u64("tcp_connect_established", stats.connect_established);
  set_u64("tcp_retransmit_count", stats.retransmit_count);
  set_u64("tcp_timeout_close_count", stats.timeout_close_count);
  set_u64("tcp_connect_timeout_count", stats.connect_timeout_count);
  set_u64("tcp_idle_timeout_count", stats.idle_timeout_count);
  set_u64("tcp_retransmit_exhausted_count", stats.retransmit_exhausted_count);
  set_u64("tcp_rx_ack_count", stats.rx_ack_count);
  set_u64("tcp_dup_ack_count", stats.dup_ack_count);
  set_u64("tcp_partial_ack_count", stats.partial_ack_count);
  set_u64("tcp_fast_retransmit_count", stats.fast_retransmit_count);
  set_u64("tcp_unexpected_ack_count", stats.unexpected_ack_count);
  set_u64("tcp_tx_data_bytes", stats.tx_data_bytes);
  set_u64("tcp_rx_data_bytes", stats.rx_data_bytes);
  set_u64("tcp_out_of_order_rx_count", stats.out_of_order_rx_count);
  set_u64("tcp_peer_rst_count", stats.peer_rst_count);
  set_u64("tcp_peer_fin_count", stats.peer_fin_count);
  return out;
}

std::string build_minimal_h3_request_hex(
    const std::string& method,
    const std::string& path,
    const std::string& body_hex) {
  std::vector<std::uint8_t> body;
  if (!body_hex.empty()) body = hex_to_bytes(body_hex);
  const std::vector<std::uint8_t> packet =
      custom_quic_stack::build_minimal_h3_request(method, path, body);
  return bytes_to_hex(packet.data(), packet.size());
}

json::Value parse_minimal_h3_response_hex(const std::string& response_hex) {
  const std::vector<std::uint8_t> raw = hex_to_bytes(response_hex);
  const auto parsed = custom_quic_stack::parse_minimal_h3_response(raw.data(), raw.size());
  json::Value out = json::Value::Object();
  out.set("valid", json::Value::Int(parsed.valid ? 1 : 0));
  out.set("headers_ok", json::Value::Int(parsed.headers_ok ? 1 : 0));
  out.set("body_ok", json::Value::Int(parsed.body_ok ? 1 : 0));
  out.set("expected_header_ok", json::Value::Int(parsed.expected_header_ok ? 1 : 0));
  out.set("expected_body_match_ok", json::Value::Int(parsed.expected_body_match_ok ? 1 : 0));
  return out;
}

}  // namespace ddos_samurai::l7_emu_native
