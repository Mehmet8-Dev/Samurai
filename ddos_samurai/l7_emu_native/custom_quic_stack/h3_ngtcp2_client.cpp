#include "h3_ngtcp2_client.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(SAMURAI_WITH_NGTCP2) && defined(SAMURAI_WITH_GNUTLS) && defined(SAMURAI_WITH_NGTCP2_GNUTLS) && defined(SAMURAI_WITH_NGHTTP3)
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#endif

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

#if defined(SAMURAI_WITH_NGTCP2) && defined(SAMURAI_WITH_GNUTLS) && defined(SAMURAI_WITH_NGTCP2_GNUTLS) && defined(SAMURAI_WITH_NGHTTP3)
namespace {

struct RequestSpec {
  std::string method{"GET"};
  std::string path{"/"};
  std::vector<unsigned char> body{};
};

struct Expectations {
  int status_min{100};
  int status_max{599};
  bool has_header_expect{false};
  std::string header_name{};
  std::string header_value_contains{};
  bool has_body_expect{false};
  std::string body_substring{};
  bool require_body{false};
  std::size_t min_body_bytes{0};
};

struct GoawayPolicy {
  bool enabled{false};
  int requests_per_connection{0};
  bool replace_after_idle{true};
};

struct H3FeaturePolicy {
  bool qpack_dynamic{false};
  bool priority_update{false};
  std::string priority_value{"u=3"};
  uint32_t priority_urgency{3};
  int priority_incremental{0};
  bool extended_connect{false};
  std::string connect_protocol{"webtransport"};
  bool datagram{false};
  std::string datagram_flow_id{"0"};
  bool server_push{false};
  std::string server_push_hint{"link"};
  bool cancel_on_promise{false};
  uint64_t max_push_id{32};
};

struct H3FrameParseState {
  bool initialized{false};
  bool is_server_uni{false};
  bool stream_type_known{false};
  uint64_t stream_type{0};
  bool push_id_known{false};
  uint64_t push_id{0};
  std::vector<uint8_t> buffer{};
};

struct Ngtcp2AttemptCtx {
  ngtcp2_crypto_conn_ref conn_ref{};
  ngtcp2_conn* conn{nullptr};
  nghttp3_conn* h3_conn{nullptr};
  gnutls_certificate_credentials_t cred{nullptr};
  gnutls_session_t session{nullptr};
  int fd{-1};
  sockaddr_storage local_addr{};
  socklen_t local_addrlen{0};
  sockaddr_storage remote_addr{};
  socklen_t remote_addrlen{0};

  int64_t ctrl_stream_id{-1};
  int64_t qpack_enc_stream_id{-1};
  int64_t qpack_dec_stream_id{-1};
  int64_t request_stream_id{-1};
  int requests_planned{1};
  int requests_completed{0};
  int requests_succeeded{0};
  int requests_failed{0};

  RequestSpec request{};
  Expectations expectations{};
  std::size_t req_body_off{0};

  bool handshake_done{false};
  bool h3_ready{false};
  bool request_submitted{false};
  bool response_complete{false};
  bool response_headers_seen{false};
  bool received_any_stream_data{false};
  bool goaway_active{false};
  bool saw_qpack_activity{false};
  bool saw_priority_ack{false};
  bool saw_extended_connect_ack{false};
  bool saw_datagram_ack{false};
  bool saw_server_push_signal{false};
  bool datagram_pending{false};
  bool datagram_remote_supported{false};

  int response_status{0};
  std::string response_headers{};
  std::string response_body{};
  int64_t goaway_last_stream_id{-1};
  int goaway_events{0};
  int drain_cycles{0};
  int replace_now{0};
  int replace_after_idle{0};
  int control_plane_failures{0};
  int graceful_close_count{0};
  int qpack_dynamic_events{0};
  int priority_update_events{0};
  int extended_connect_events{0};
  int datagram_tx_events{0};
  int datagram_rx_events{0};
  int server_push_events{0};
  int feature_failures{0};

  std::size_t rx_bytes{0};
  std::size_t tx_bytes{0};
  std::vector<uint8_t> datagram_payload{};
  uint64_t next_datagram_id{1};
  uint64_t last_datagram_id{0};
  H3FeaturePolicy feature_policy{};
  std::unordered_map<int64_t, H3FrameParseState> frame_parse_states{};
  std::unordered_set<uint64_t> promised_push_ids{};
  std::unordered_set<uint64_t> canceled_push_ids{};
  std::unordered_set<uint64_t> fulfilled_push_ids{};
  std::unordered_set<uint64_t> cancel_push_tx_sent{};
  std::vector<uint8_t> control_tx_buffer{};
  std::size_t control_tx_off{0};
  uint64_t max_push_id_advertised{0};
  uint64_t max_push_id_sent_value{0};
  bool max_push_id_set{false};
  bool max_push_id_sent{false};
};

ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* conn_ref) {
  if (conn_ref == nullptr) {
    return nullptr;
  }
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_ref->user_data);
  return ctx == nullptr ? nullptr : ctx->conn;
}

uint64_t now_ns() {
  using namespace std::chrono;
  return static_cast<uint64_t>(
      duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
}

int64_t ns_to_ms_ceil(uint64_t delta_ns) {
  return static_cast<int64_t>((delta_ns + 999999ull) / 1000000ull);
}

bool is_numeric_host(const std::string& host) {
  in_addr v4{};
  if (::inet_pton(AF_INET, host.c_str(), &v4) == 1) {
    return true;
  }
  in6_addr v6{};
  return ::inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

bool resolve_target(
    const std::string& host,
    int port,
    sockaddr_storage* out_addr,
    socklen_t* out_len) {
  if (out_addr == nullptr || out_len == nullptr) {
    return false;
  }
  *out_len = 0;
  std::memset(out_addr, 0, sizeof(*out_addr));

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = AI_NUMERICHOST;
  addrinfo* result = nullptr;
  const std::string port_s = std::to_string(std::max(1, port));
  const int rc = ::getaddrinfo(host.c_str(), port_s.c_str(), &hints, &result);
  if (rc != 0 || result == nullptr) {
    return false;
  }
  bool ok = false;
  for (addrinfo* it = result; it != nullptr; it = it->ai_next) {
    if (!it->ai_addr || it->ai_addrlen <= 0) {
      continue;
    }
    if (it->ai_addrlen > static_cast<socklen_t>(sizeof(*out_addr))) {
      continue;
    }
    std::memcpy(out_addr, it->ai_addr, static_cast<std::size_t>(it->ai_addrlen));
    *out_len = static_cast<socklen_t>(it->ai_addrlen);
    ok = true;
    break;
  }
  ::freeaddrinfo(result);
  return ok;
}

int rand_fill(uint8_t* dest, std::size_t len) {
  return gnutls_rnd(GNUTLS_RND_RANDOM, dest, len);
}

void rand_cb(uint8_t* dest, std::size_t destlen, const ngtcp2_rand_ctx* rand_ctx) {
  (void)rand_ctx;
  (void)rand_fill(dest, destlen);
}

std::string to_lower_ascii(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return s;
}

bool header_expect_ok(
    const std::string& headers,
    const std::string& name,
    const std::string& value_contains) {
  if (name.empty()) {
    return true;
  }
  const std::string lowered_headers = to_lower_ascii(headers);
  const std::string needle = to_lower_ascii(name) + ":";
  const std::size_t pos = lowered_headers.find(needle);
  if (pos == std::string::npos) {
    return false;
  }
  if (value_contains.empty()) {
    return true;
  }
  const std::size_t line_end = lowered_headers.find('\n', pos);
  const std::string segment =
      line_end == std::string::npos ? lowered_headers.substr(pos) : lowered_headers.substr(pos, line_end - pos);
  return segment.find(to_lower_ascii(value_contains)) != std::string::npos;
}

bool body_expect_ok(const std::string& body, const std::string& substr) {
  if (substr.empty()) {
    return true;
  }
  return body.find(substr) != std::string::npos;
}

bool parse_u64_str(const std::string& value, uint64_t* out) {
  if (out == nullptr) {
    return false;
  }
  if (value.empty()) {
    return false;
  }
  uint64_t acc = 0;
  for (char ch : value) {
    if (ch < '0' || ch > '9') {
      return false;
    }
    const uint64_t d = static_cast<uint64_t>(ch - '0');
    if (acc > (UINT64_MAX - d) / 10u) {
      return false;
    }
    acc = acc * 10u + d;
  }
  *out = acc;
  return true;
}

RequestSpec derive_request_spec(const Profile& profile) {
  RequestSpec out;
  for (const auto& op : profile.ops) {
    if (op.opcode == "SEND_HEADERS") {
      if (!op.method.empty()) {
        out.method = op.method;
      }
      if (!op.path.empty()) {
        out.path = op.path;
      }
      break;
    }
  }
  for (const auto& op : profile.ops) {
    if (op.opcode == "SEND_BODY" && !op.body.empty()) {
      out.body = op.body;
      break;
    }
  }
  if (out.path.empty()) {
    out.path = "/";
  }
  if (out.path.front() != '/') {
    out.path.insert(out.path.begin(), '/');
  }
  return out;
}

Expectations derive_expectations(const Profile& profile) {
  Expectations exp{};
  for (const auto& op : profile.ops) {
    if (op.opcode == "EXPECT_STATUS" && op.has_expect) {
      exp.status_min = std::max(100, op.expect.status_min);
      exp.status_max = std::max(exp.status_min, std::min(599, op.expect.status_max));
      continue;
    }
    if (op.opcode == "EXPECT_HEADER" && op.has_expect) {
      exp.has_header_expect = true;
      exp.header_name = op.expect.name;
      exp.header_value_contains = op.expect.value;
      continue;
    }
    if (op.opcode == "EXPECT_BODY_SUBSTRING" && op.has_expect) {
      if (op.expect.kind == "body_required") {
        exp.require_body = true;
      } else if (op.expect.kind == "body_min_bytes") {
        int min_body = 0;
        try {
          min_body = std::stoi(op.expect.value);
        } catch (...) {
          min_body = 0;
        }
        exp.min_body_bytes = static_cast<std::size_t>(std::max(0, min_body));
      } else {
        exp.has_body_expect = true;
        exp.body_substring = op.expect.value;
      }
      continue;
    }
  }
  return exp;
}

GoawayPolicy derive_goaway_policy(const Profile& profile) {
  GoawayPolicy policy{};
  for (const auto& op : profile.ops) {
    if (op.opcode != "H3_GOAWAY") {
      continue;
    }
    policy.enabled = true;
    if (op.loop_count > 0) {
      policy.requests_per_connection = std::max(policy.requests_per_connection, op.loop_count);
    }
    if (op.has_expect) {
      if (op.expect.kind == "replace_mode" && op.expect.value == "now") {
        policy.replace_after_idle = false;
      } else if (op.expect.kind == "replace_mode" && op.expect.value == "after_idle") {
        policy.replace_after_idle = true;
      } else if (op.expect.kind == "requests_per_connection") {
        int parsed = 0;
        try {
          parsed = std::stoi(op.expect.value);
        } catch (...) {
          parsed = 0;
        }
        if (parsed > 0) {
          policy.requests_per_connection = std::max(policy.requests_per_connection, parsed);
        }
      }
    }
  }
  if (policy.enabled && policy.requests_per_connection <= 0) {
    policy.requests_per_connection = 1;
  }
  return policy;
}

void parse_priority_value(const std::string& value, uint32_t* urgency, int* incremental) {
  if (urgency == nullptr || incremental == nullptr) {
    return;
  }
  *urgency = 3;
  *incremental = 0;
  const std::string lower = to_lower_ascii(value);
  const std::size_t u = lower.find("u=");
  if (u != std::string::npos && u + 2 < lower.size()) {
    int parsed = 3;
    try {
      parsed = std::stoi(lower.substr(u + 2));
    } catch (...) {
      parsed = 3;
    }
    *urgency = static_cast<uint32_t>(std::clamp(parsed, 0, 7));
  }
  const std::size_t i = lower.find("i");
  if (i != std::string::npos) {
    *incremental = 1;
  }
}

H3FeaturePolicy derive_h3_feature_policy(const Profile& profile) {
  H3FeaturePolicy policy{};
  for (const auto& op : profile.ops) {
    if (op.opcode == "H3_QPACK_DYNAMIC") {
      policy.qpack_dynamic = true;
      continue;
    }
    if (op.opcode == "H3_PRIORITY_UPDATE") {
      policy.priority_update = true;
      if (op.has_expect && op.expect.kind == "priority_value" && !op.expect.value.empty()) {
        policy.priority_value = op.expect.value;
      }
      parse_priority_value(policy.priority_value, &policy.priority_urgency, &policy.priority_incremental);
      continue;
    }
    if (op.opcode == "H3_EXTENDED_CONNECT") {
      policy.extended_connect = true;
      if (op.has_expect && op.expect.kind == "protocol" && !op.expect.value.empty()) {
        policy.connect_protocol = op.expect.value;
      }
      continue;
    }
    if (op.opcode == "H3_DATAGRAM") {
      policy.datagram = true;
      if (op.has_expect && op.expect.kind == "flow_id" && !op.expect.value.empty()) {
        policy.datagram_flow_id = op.expect.value;
      }
      continue;
    }
    if (op.opcode == "H3_SERVER_PUSH") {
      policy.server_push = true;
      if (op.has_expect && !op.expect.kind.empty() && !op.expect.value.empty()) {
        if (op.expect.kind == "hint") {
          policy.server_push_hint = to_lower_ascii(op.expect.value);
        } else if (op.expect.kind == "max_push_id") {
          uint64_t parsed = policy.max_push_id;
          if (parse_u64_str(op.expect.value, &parsed)) {
            policy.max_push_id = std::min<uint64_t>(parsed, ((1ull << 62u) - 1u));
          }
        } else if ((op.expect.kind == "cancel_mode" || op.expect.kind == "cancel_policy") &&
            to_lower_ascii(op.expect.value) == "on_promise") {
          policy.cancel_on_promise = true;
        }
      }
      continue;
    }
  }
  if (policy.priority_update) {
    parse_priority_value(policy.priority_value, &policy.priority_urgency, &policy.priority_incremental);
  }
  if (policy.server_push_hint == "cancel") {
    policy.cancel_on_promise = true;
  }
  return policy;
}

int parse_status_code(const std::string& text) {
  int code = 0;
  for (char ch : text) {
    if (ch >= '0' && ch <= '9') {
      code = code * 10 + static_cast<int>(ch - '0');
      if (code > 9999) {
        break;
      }
    } else if (code > 0) {
      break;
    }
  }
  return code;
}

constexpr uint64_t kH3StreamTypeControl = 0x00;
constexpr uint64_t kH3StreamTypePush = 0x01;
constexpr uint64_t kH3FrameTypeCancelPush = 0x03;
constexpr uint64_t kH3FrameTypePushPromise = 0x05;
constexpr uint64_t kH3FrameTypeGoaway = 0x07;
constexpr uint64_t kH3FrameTypeMaxPushId = 0x0d;
constexpr std::size_t kH3ParseBufferCap = 1u << 20u;  // 1 MiB safety cap.

bool is_server_uni_stream(int64_t stream_id) {
  return (stream_id & 0x3ll) == 0x3ll;
}

bool try_decode_quic_varint(
    const uint8_t* data,
    std::size_t len,
    uint64_t* out,
    std::size_t* consumed) {
  if (data == nullptr || out == nullptr || consumed == nullptr || len == 0) {
    return false;
  }
  const uint8_t first = data[0];
  const uint8_t prefix = static_cast<uint8_t>(first >> 6u);
  const std::size_t nbytes = static_cast<std::size_t>(1u << prefix);
  if (len < nbytes) {
    return false;
  }
  uint64_t v = static_cast<uint64_t>(first & 0x3fu);
  for (std::size_t i = 1; i < nbytes; ++i) {
    v = (v << 8u) | static_cast<uint64_t>(data[i]);
  }
  *out = v;
  *consumed = nbytes;
  return true;
}

bool append_quic_varint(std::vector<uint8_t>* out, uint64_t v) {
  if (out == nullptr || v > ((1ull << 62u) - 1u)) {
    return false;
  }
  if (v <= 0x3fu) {
    out->push_back(static_cast<uint8_t>(v));
    return true;
  }
  if (v <= 0x3fffu) {
    out->push_back(static_cast<uint8_t>(0x40u | ((v >> 8u) & 0x3fu)));
    out->push_back(static_cast<uint8_t>(v & 0xffu));
    return true;
  }
  if (v <= 0x3fffffffu) {
    out->push_back(static_cast<uint8_t>(0x80u | ((v >> 24u) & 0x3fu)));
    out->push_back(static_cast<uint8_t>((v >> 16u) & 0xffu));
    out->push_back(static_cast<uint8_t>((v >> 8u) & 0xffu));
    out->push_back(static_cast<uint8_t>(v & 0xffu));
    return true;
  }
  out->push_back(static_cast<uint8_t>(0xc0u | ((v >> 56u) & 0x3fu)));
  out->push_back(static_cast<uint8_t>((v >> 48u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 40u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 32u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 24u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 16u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 8u) & 0xffu));
  out->push_back(static_cast<uint8_t>(v & 0xffu));
  return true;
}

bool queue_h3_varint_frame(Ngtcp2AttemptCtx* ctx, uint64_t frame_type, uint64_t payload_value) {
  if (ctx == nullptr || ctx->ctrl_stream_id < 0) {
    return false;
  }
  if (ctx->control_tx_off >= ctx->control_tx_buffer.size()) {
    ctx->control_tx_buffer.clear();
    ctx->control_tx_off = 0;
  }
  std::vector<uint8_t> payload{};
  if (!append_quic_varint(&payload, payload_value)) {
    return false;
  }
  std::vector<uint8_t> frame{};
  frame.reserve(16);
  if (!append_quic_varint(&frame, frame_type)) {
    return false;
  }
  if (!append_quic_varint(&frame, static_cast<uint64_t>(payload.size()))) {
    return false;
  }
  frame.insert(frame.end(), payload.begin(), payload.end());
  ctx->control_tx_buffer.insert(ctx->control_tx_buffer.end(), frame.begin(), frame.end());
  return true;
}

bool queue_max_push_id_frame(Ngtcp2AttemptCtx* ctx, uint64_t max_push_id) {
  if (ctx == nullptr) {
    return false;
  }
  if (ctx->max_push_id_sent && max_push_id < ctx->max_push_id_sent_value) {
    ctx->feature_failures += 1;
    return false;
  }
  if (ctx->max_push_id_sent && max_push_id == ctx->max_push_id_sent_value) {
    return true;
  }
  if (!queue_h3_varint_frame(ctx, kH3FrameTypeMaxPushId, max_push_id)) {
    return false;
  }
  ctx->max_push_id_sent = true;
  ctx->max_push_id_sent_value = max_push_id;
  return true;
}

bool queue_cancel_push_frame(Ngtcp2AttemptCtx* ctx, uint64_t push_id) {
  if (ctx == nullptr) {
    return false;
  }
  if (!ctx->cancel_push_tx_sent.insert(push_id).second) {
    return true;
  }
  if (queue_h3_varint_frame(ctx, kH3FrameTypeCancelPush, push_id)) {
    return true;
  }
  ctx->cancel_push_tx_sent.erase(push_id);
  return false;
}

void append_parse_bytes(H3FrameParseState* state, const uint8_t* data, std::size_t datalen) {
  if (state == nullptr || data == nullptr || datalen == 0) {
    return;
  }
  state->buffer.insert(state->buffer.end(), data, data + datalen);
  if (state->buffer.size() > kH3ParseBufferCap) {
    const std::size_t drop = state->buffer.size() - kH3ParseBufferCap;
    state->buffer.erase(state->buffer.begin(), state->buffer.begin() + static_cast<std::ptrdiff_t>(drop));
  }
}

void note_push_promise(Ngtcp2AttemptCtx* ctx, uint64_t push_id) {
  if (ctx == nullptr) {
    return;
  }
  ctx->saw_server_push_signal = true;
  if (!ctx->max_push_id_set || push_id > ctx->max_push_id_advertised) {
    ctx->feature_failures += 1;
    return;
  }
  ctx->promised_push_ids.insert(push_id);
  if (ctx->feature_policy.cancel_on_promise) {
    ctx->canceled_push_ids.insert(push_id);
    if (!queue_cancel_push_frame(ctx, push_id)) {
      ctx->feature_failures += 1;
    }
  }
}

void note_push_stream(Ngtcp2AttemptCtx* ctx, uint64_t push_id) {
  if (ctx == nullptr) {
    return;
  }
  if (!ctx->max_push_id_set || push_id > ctx->max_push_id_advertised) {
    ctx->feature_failures += 1;
    return;
  }
  if (!ctx->promised_push_ids.empty() && ctx->promised_push_ids.find(push_id) == ctx->promised_push_ids.end()) {
    ctx->feature_failures += 1;
    return;
  }
  if (ctx->canceled_push_ids.find(push_id) != ctx->canceled_push_ids.end()) {
    return;
  }
  if (ctx->fulfilled_push_ids.insert(push_id).second) {
    ctx->saw_server_push_signal = true;
    ctx->server_push_events += 1;
  }
}

void note_cancel_push(Ngtcp2AttemptCtx* ctx, uint64_t push_id) {
  if (ctx == nullptr) {
    return;
  }
  if (!ctx->max_push_id_set || push_id > ctx->max_push_id_advertised) {
    ctx->feature_failures += 1;
    return;
  }
  ctx->canceled_push_ids.insert(push_id);
}

void note_max_push_id(Ngtcp2AttemptCtx* ctx, uint64_t push_id) {
  if (ctx == nullptr) {
    return;
  }
  if (!ctx->max_push_id_set) {
    ctx->max_push_id_advertised = push_id;
    ctx->max_push_id_set = true;
    return;
  }
  if (push_id < ctx->max_push_id_advertised) {
    ctx->feature_failures += 1;
    return;
  }
  ctx->max_push_id_advertised = push_id;
}

void parse_h3_frame_events(Ngtcp2AttemptCtx* ctx, int64_t stream_id, H3FrameParseState* state) {
  if (ctx == nullptr || state == nullptr) {
    return;
  }
  if (!state->initialized) {
    state->initialized = true;
    state->is_server_uni = is_server_uni_stream(stream_id);
  }

  if (state->is_server_uni && !state->stream_type_known) {
    uint64_t stream_type = 0;
    std::size_t stream_type_len = 0;
    if (!try_decode_quic_varint(state->buffer.data(), state->buffer.size(), &stream_type, &stream_type_len)) {
      return;
    }
    state->stream_type = stream_type;
    state->stream_type_known = true;
    state->buffer.erase(
        state->buffer.begin(),
        state->buffer.begin() + static_cast<std::ptrdiff_t>(stream_type_len));
  }

  if (state->is_server_uni && state->stream_type == kH3StreamTypePush && !state->push_id_known) {
    uint64_t push_id = 0;
    std::size_t push_id_len = 0;
    if (!try_decode_quic_varint(state->buffer.data(), state->buffer.size(), &push_id, &push_id_len)) {
      return;
    }
    state->push_id = push_id;
    state->push_id_known = true;
    state->buffer.erase(
        state->buffer.begin(),
        state->buffer.begin() + static_cast<std::ptrdiff_t>(push_id_len));
    note_push_stream(ctx, push_id);
  }

  if (state->is_server_uni && state->stream_type != kH3StreamTypeControl && state->stream_type != kH3StreamTypePush) {
    return;
  }

  for (;;) {
    if (state->buffer.empty()) {
      return;
    }
    uint64_t frame_type = 0;
    uint64_t frame_len = 0;
    std::size_t frame_type_len = 0;
    std::size_t frame_len_len = 0;
    if (!try_decode_quic_varint(state->buffer.data(), state->buffer.size(), &frame_type, &frame_type_len)) {
      return;
    }
    if (!try_decode_quic_varint(
            state->buffer.data() + static_cast<std::ptrdiff_t>(frame_type_len),
            state->buffer.size() - frame_type_len,
            &frame_len,
            &frame_len_len)) {
      return;
    }
    const std::size_t header_len = frame_type_len + frame_len_len;
    const std::size_t payload_len = static_cast<std::size_t>(frame_len);
    if (payload_len > state->buffer.size() - header_len) {
      return;
    }
    const uint8_t* payload = state->buffer.data() + static_cast<std::ptrdiff_t>(header_len);
    if (frame_type == kH3FrameTypePushPromise && payload_len > 0) {
      uint64_t push_id = 0;
      std::size_t push_id_len = 0;
      if (try_decode_quic_varint(payload, payload_len, &push_id, &push_id_len) && push_id_len <= payload_len) {
        note_push_promise(ctx, push_id);
      } else {
        ctx->feature_failures += 1;
      }
    } else if (frame_type == kH3FrameTypeCancelPush && payload_len > 0) {
      uint64_t push_id = 0;
      std::size_t push_id_len = 0;
      if (try_decode_quic_varint(payload, payload_len, &push_id, &push_id_len) && push_id_len <= payload_len) {
        note_cancel_push(ctx, push_id);
      } else {
        ctx->feature_failures += 1;
      }
    } else if (frame_type == kH3FrameTypeMaxPushId && payload_len > 0) {
      uint64_t push_id = 0;
      std::size_t push_id_len = 0;
      if (try_decode_quic_varint(payload, payload_len, &push_id, &push_id_len) && push_id_len <= payload_len) {
        note_max_push_id(ctx, push_id);
      } else {
        ctx->feature_failures += 1;
      }
    } else if (frame_type == kH3FrameTypeGoaway && payload_len > 0) {
      uint64_t id = 0;
      std::size_t id_len = 0;
      if (try_decode_quic_varint(payload, payload_len, &id, &id_len) && id_len <= payload_len) {
        ctx->goaway_last_stream_id = static_cast<int64_t>(id);
        ctx->goaway_active = true;
      }
    }
    state->buffer.erase(
        state->buffer.begin(),
        state->buffer.begin() + static_cast<std::ptrdiff_t>(header_len + payload_len));
  }
}

int get_new_connection_id_cb(
    ngtcp2_conn* conn,
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen,
    void* user_data) {
  (void)conn;
  (void)user_data;
  if (rand_fill(cid->data, cidlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;
  if (rand_fill(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int handshake_completed_cb(ngtcp2_conn* conn, void* user_data) {
  (void)conn;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx != nullptr) {
    ctx->handshake_done = true;
  }
  return 0;
}

nghttp3_nv make_nv(std::string_view name, std::string_view value) {
  nghttp3_nv nv{};
  nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(name.data()));
  nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data()));
  nv.namelen = name.size();
  nv.valuelen = value.size();
  nv.flags = NGHTTP3_NV_FLAG_NONE;
  return nv;
}

nghttp3_ssize read_data_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    nghttp3_vec* vec,
    size_t veccnt,
    uint32_t* pflags,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr || vec == nullptr || veccnt == 0 || pflags == nullptr) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (ctx->req_body_off >= ctx->request.body.size()) {
    *pflags |= NGHTTP3_DATA_FLAG_EOF;
    return 0;
  }
  vec[0].base = reinterpret_cast<uint8_t*>(ctx->request.body.data() + ctx->req_body_off);
  vec[0].len = ctx->request.body.size() - ctx->req_body_off;
  ctx->req_body_off = ctx->request.body.size();
  *pflags |= NGHTTP3_DATA_FLAG_EOF;
  return 1;
}

int http_acked_stream_data_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    uint64_t datalen,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)datalen;
  (void)conn_user_data;
  (void)stream_user_data;
  return 0;
}

int http_stream_close_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)app_error_code;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx != nullptr && stream_id == ctx->request_stream_id) {
    ctx->response_complete = true;
  }
  return 0;
}

int http_recv_data_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    const uint8_t* data,
    size_t datalen,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (datalen > 0 && data != nullptr) {
    ctx->received_any_stream_data = true;
    ctx->rx_bytes += datalen;
    if (ctx->response_body.size() < 131072) {
      const std::size_t cap_left = 131072 - ctx->response_body.size();
      const std::size_t ncopy = std::min(cap_left, datalen);
      ctx->response_body.append(reinterpret_cast<const char*>(data), ncopy);
    }
  }
  if (ctx->conn != nullptr && datalen > 0) {
    (void)ngtcp2_conn_extend_max_stream_offset(ctx->conn, stream_id, static_cast<uint64_t>(datalen));
    ngtcp2_conn_extend_max_offset(ctx->conn, static_cast<uint64_t>(datalen));
  }
  return 0;
}

int http_deferred_consume_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    size_t consumed,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr || ctx->conn == nullptr || consumed == 0) {
    return 0;
  }
  (void)ngtcp2_conn_extend_max_stream_offset(ctx->conn, stream_id, static_cast<uint64_t>(consumed));
  ngtcp2_conn_extend_max_offset(ctx->conn, static_cast<uint64_t>(consumed));
  return 0;
}

int http_begin_headers_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)conn_user_data;
  (void)stream_user_data;
  return 0;
}

int http_recv_header_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    int32_t token,
    nghttp3_rcbuf* name,
    nghttp3_rcbuf* value,
    uint8_t flags,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)flags;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr || name == nullptr || value == nullptr) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  const nghttp3_vec nbuf = nghttp3_rcbuf_get_buf(name);
  const nghttp3_vec vbuf = nghttp3_rcbuf_get_buf(value);
  std::string n(reinterpret_cast<const char*>(nbuf.base), nbuf.len);
  std::string v(reinterpret_cast<const char*>(vbuf.base), vbuf.len);
  const std::string lower_n = to_lower_ascii(n);
  const std::string lower_v = to_lower_ascii(v);
  ctx->response_headers_seen = true;
  if (ctx->response_headers.size() < 131072) {
    ctx->response_headers.append(n);
    ctx->response_headers.push_back(':');
    ctx->response_headers.append(v);
    ctx->response_headers.push_back('\n');
  }
  if (token == NGHTTP3_QPACK_TOKEN__STATUS || n == ":status") {
    ctx->response_status = parse_status_code(v);
  }
  if (ctx->feature_policy.priority_update && lower_n == "priority") {
    if (lower_v.find(to_lower_ascii(ctx->feature_policy.priority_value)) != std::string::npos) {
      ctx->saw_priority_ack = true;
    }
  }
  if (ctx->feature_policy.extended_connect && lower_n == ":protocol") {
    if (lower_v == to_lower_ascii(ctx->feature_policy.connect_protocol)) {
      ctx->saw_extended_connect_ack = true;
    }
  }
  if (ctx->feature_policy.datagram && lower_n == "capsule-protocol" && lower_v.find("?1") != std::string::npos) {
    ctx->saw_datagram_ack = true;
  }
  if (ctx->feature_policy.server_push) {
    if ((lower_n == "link" && lower_v.find("rel=preload") != std::string::npos) ||
        (lower_n == "x-http3-push" && (lower_v == "1" || lower_v == "true"))) {
      ctx->saw_server_push_signal = true;
    }
  }
  return 0;
}

int http_end_headers_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    int fin,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)conn_user_data;
  (void)stream_user_data;
  (void)fin;
  return 0;
}

int http_stop_sending_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr || ctx->conn == nullptr) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (ngtcp2_conn_shutdown_stream_read(ctx->conn, stream_id, app_error_code) != 0) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int http_end_stream_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx != nullptr && stream_id == ctx->request_stream_id) {
    ctx->response_complete = true;
  }
  return 0;
}

int http_reset_stream_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr || ctx->conn == nullptr) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (ngtcp2_conn_shutdown_stream_write(ctx->conn, stream_id, app_error_code) != 0) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int http_shutdown_cb(
    nghttp3_conn* conn,
    int64_t id,
    void* conn_user_data) {
  (void)conn;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx != nullptr) {
    ctx->goaway_active = true;
    ctx->goaway_last_stream_id = id;
    ctx->goaway_events += 1;
  }
  return 0;
}

int recv_stream_data_cb(
    ngtcp2_conn* conn,
    uint32_t flags,
    int64_t stream_id,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen,
    void* user_data,
    void* stream_user_data) {
  (void)conn;
  (void)offset;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx == nullptr || ctx->h3_conn == nullptr) {
    return 0;
  }
  if (data != nullptr && datalen > 0) {
    auto& state = ctx->frame_parse_states[stream_id];
    append_parse_bytes(&state, data, datalen);
    parse_h3_frame_events(ctx, stream_id, &state);
  }
  if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0) {
    ctx->frame_parse_states.erase(stream_id);
  }
  const int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0 ? 1 : 0;
  const nghttp3_ssize nconsumed = nghttp3_conn_read_stream(
      ctx->h3_conn,
      stream_id,
      data == nullptr ? reinterpret_cast<const uint8_t*>("") : data,
      datalen,
      fin);
  if (nconsumed < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  if (nconsumed > 0 && ctx->conn != nullptr) {
    (void)ngtcp2_conn_extend_max_stream_offset(ctx->conn, stream_id, static_cast<uint64_t>(nconsumed));
    ngtcp2_conn_extend_max_offset(ctx->conn, static_cast<uint64_t>(nconsumed));
  }
  return 0;
}

int acked_stream_data_offset_cb(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint64_t offset,
    uint64_t datalen,
    void* user_data,
    void* stream_user_data) {
  (void)conn;
  (void)offset;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx == nullptr || ctx->h3_conn == nullptr) {
    return 0;
  }
  if (nghttp3_conn_add_ack_offset(ctx->h3_conn, stream_id, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int stream_close_cb(
    ngtcp2_conn* conn,
    uint32_t flags,
    int64_t stream_id,
    uint64_t app_error_code,
    void* user_data,
    void* stream_user_data) {
  (void)conn;
  (void)flags;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx == nullptr || ctx->h3_conn == nullptr) {
    return 0;
  }
  (void)nghttp3_conn_close_stream(ctx->h3_conn, stream_id, app_error_code);
  return 0;
}

int recv_datagram_cb(
    ngtcp2_conn* conn,
    uint32_t flags,
    const uint8_t* data,
    size_t datalen,
    void* user_data) {
  (void)conn;
  (void)flags;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx == nullptr || data == nullptr || datalen == 0) {
    return 0;
  }
  ctx->saw_datagram_ack = true;
  ctx->datagram_rx_events += 1;
  return 0;
}

int ack_datagram_cb(ngtcp2_conn* conn, uint64_t dgram_id, void* user_data) {
  (void)conn;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx == nullptr) {
    return 0;
  }
  ctx->last_datagram_id = dgram_id;
  ctx->saw_datagram_ack = true;
  return 0;
}

int lost_datagram_cb(ngtcp2_conn* conn, uint64_t dgram_id, void* user_data) {
  (void)conn;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx == nullptr) {
    return 0;
  }
  ctx->last_datagram_id = dgram_id;
  ctx->feature_failures += 1;
  return 0;
}

bool configure_gnutls_session(Ngtcp2AttemptCtx* ctx, const std::string& host) {
  if (ctx == nullptr) {
    return false;
  }
  if (gnutls_certificate_allocate_credentials(&ctx->cred) != 0) {
    return false;
  }
  (void)gnutls_certificate_set_x509_system_trust(ctx->cred);
  if (gnutls_init(
          &ctx->session,
          GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA) != 0) {
    return false;
  }
  if (ngtcp2_crypto_gnutls_configure_client_session(ctx->session) != 0) {
    return false;
  }

  static const char kPriority[] =
      "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
      "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:"
      "+GROUP-SECP384R1:+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE";
  if (gnutls_priority_set_direct(ctx->session, kPriority, nullptr) != 0) {
    return false;
  }
  static const gnutls_datum_t kAlpn = {
      reinterpret_cast<unsigned char*>(const_cast<char*>("h3")),
      2,
  };
  (void)gnutls_alpn_set_protocols(ctx->session, &kAlpn, 1, GNUTLS_ALPN_MANDATORY);
  gnutls_session_set_ptr(ctx->session, &ctx->conn_ref);
  if (gnutls_credentials_set(ctx->session, GNUTLS_CRD_CERTIFICATE, ctx->cred) != 0) {
    return false;
  }
  if (!is_numeric_host(host)) {
    (void)gnutls_server_name_set(
        ctx->session,
        GNUTLS_NAME_DNS,
        host.data(),
        host.size());
  } else {
    static constexpr std::string_view kLocal = "localhost";
    (void)gnutls_server_name_set(
        ctx->session,
        GNUTLS_NAME_DNS,
        kLocal.data(),
        kLocal.size());
  }
  return true;
}

bool init_quic_conn(Ngtcp2AttemptCtx* ctx) {
  if (ctx == nullptr) {
    return false;
  }

  ngtcp2_path path{};
  path.local.addr = reinterpret_cast<sockaddr*>(&ctx->local_addr);
  path.local.addrlen = ctx->local_addrlen;
  path.remote.addr = reinterpret_cast<sockaddr*>(&ctx->remote_addr);
  path.remote.addrlen = ctx->remote_addrlen;

  ngtcp2_cid dcid{};
  dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
  if (rand_fill(dcid.data, dcid.datalen) != 0) {
    return false;
  }
  ngtcp2_cid scid{};
  scid.datalen = 8;
  if (rand_fill(scid.data, scid.datalen) != 0) {
    return false;
  }

  ngtcp2_settings settings{};
  ngtcp2_settings_default(&settings);
  settings.initial_ts = now_ns();

  ngtcp2_transport_params params{};
  ngtcp2_transport_params_default(&params);
  params.initial_max_streams_uni = 16;
  params.initial_max_stream_data_bidi_local = 512 * 1024;
  params.initial_max_data = 4 * 1024 * 1024;
  params.max_datagram_frame_size = 1200;

  ngtcp2_callbacks callbacks{};
  callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
  callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  callbacks.handshake_completed = handshake_completed_cb;
  callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks.recv_stream_data = recv_stream_data_cb;
  callbacks.acked_stream_data_offset = acked_stream_data_offset_cb;
  callbacks.stream_close = stream_close_cb;
  callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
  callbacks.rand = rand_cb;
  callbacks.update_key = ngtcp2_crypto_update_key_cb;
  callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks.recv_datagram = recv_datagram_cb;
  callbacks.ack_datagram = ack_datagram_cb;
  callbacks.lost_datagram = lost_datagram_cb;
  callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  callbacks.get_new_connection_id = get_new_connection_id_cb;
  callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;

  const int rv = ngtcp2_conn_client_new(
      &ctx->conn,
      &dcid,
      &scid,
      &path,
      NGTCP2_PROTO_VER_V1,
      &callbacks,
      &settings,
      &params,
      nullptr,
      ctx);
  if (rv != 0 || ctx->conn == nullptr) {
    return false;
  }
  ctx->conn_ref.get_conn = get_conn;
  ctx->conn_ref.user_data = ctx;
  ngtcp2_conn_set_tls_native_handle(ctx->conn, ctx->session);
  return true;
}

bool init_h3_session(Ngtcp2AttemptCtx* ctx) {
  if (ctx == nullptr || ctx->conn == nullptr || ctx->h3_ready) {
    return false;
  }

  nghttp3_callbacks h3_callbacks{};
  h3_callbacks.acked_stream_data = http_acked_stream_data_cb;
  h3_callbacks.stream_close = http_stream_close_cb;
  h3_callbacks.recv_data = http_recv_data_cb;
  h3_callbacks.deferred_consume = http_deferred_consume_cb;
  h3_callbacks.begin_headers = http_begin_headers_cb;
  h3_callbacks.recv_header = http_recv_header_cb;
  h3_callbacks.end_headers = http_end_headers_cb;
  h3_callbacks.begin_trailers = http_begin_headers_cb;
  h3_callbacks.recv_trailer = http_recv_header_cb;
  h3_callbacks.end_trailers = http_end_headers_cb;
  h3_callbacks.stop_sending = http_stop_sending_cb;
  h3_callbacks.end_stream = http_end_stream_cb;
  h3_callbacks.reset_stream = http_reset_stream_cb;
  h3_callbacks.shutdown = http_shutdown_cb;

  nghttp3_settings h3_settings{};
  nghttp3_settings_default(&h3_settings);
  h3_settings.qpack_max_dtable_capacity = 4096;
  h3_settings.qpack_blocked_streams = 16;

  if (nghttp3_conn_client_new(&ctx->h3_conn, &h3_callbacks, &h3_settings, nghttp3_mem_default(), ctx) != 0 ||
      ctx->h3_conn == nullptr) {
    return false;
  }

  if (ngtcp2_conn_open_uni_stream(ctx->conn, &ctx->ctrl_stream_id, nullptr) != 0) {
    return false;
  }
  if (nghttp3_conn_bind_control_stream(ctx->h3_conn, ctx->ctrl_stream_id) != 0) {
    return false;
  }

  if (ngtcp2_conn_open_uni_stream(ctx->conn, &ctx->qpack_enc_stream_id, nullptr) != 0) {
    return false;
  }
  if (ngtcp2_conn_open_uni_stream(ctx->conn, &ctx->qpack_dec_stream_id, nullptr) != 0) {
    return false;
  }
  if (nghttp3_conn_bind_qpack_streams(ctx->h3_conn, ctx->qpack_enc_stream_id, ctx->qpack_dec_stream_id) != 0) {
    return false;
  }
  if (ctx->feature_policy.qpack_dynamic) {
    ctx->saw_qpack_activity = true;
  }
  if (ctx->feature_policy.server_push) {
    if (!queue_max_push_id_frame(ctx, ctx->max_push_id_advertised)) {
      ctx->feature_failures += 1;
    }
  }

  ctx->h3_ready = true;
  return true;
}

void reset_request_state(Ngtcp2AttemptCtx* ctx) {
  if (ctx == nullptr) {
    return;
  }
  ctx->request_stream_id = -1;
  ctx->request_submitted = false;
  ctx->response_complete = false;
  ctx->response_headers_seen = false;
  ctx->received_any_stream_data = false;
  ctx->response_status = 0;
  ctx->response_headers.clear();
  ctx->response_body.clear();
  ctx->req_body_off = 0;
  ctx->saw_priority_ack = false;
  ctx->saw_extended_connect_ack = false;
  ctx->saw_datagram_ack = false;
  ctx->saw_server_push_signal = false;
  ctx->datagram_pending = false;
  ctx->datagram_payload.clear();
}

bool submit_h3_request(Ngtcp2AttemptCtx* ctx, const Profile& profile) {
  if (ctx == nullptr || ctx->conn == nullptr || ctx->h3_conn == nullptr || !ctx->h3_ready) {
    return false;
  }
  if (ngtcp2_conn_open_bidi_stream(ctx->conn, &ctx->request_stream_id, nullptr) != 0) {
    return false;
  }

  const std::string scheme = profile.scheme.empty() ? "https" : profile.scheme;
  const std::string authority = profile.host_header.empty()
      ? (profile.target_ip + ":" + std::to_string(std::max(1, profile.target_port)))
      : profile.host_header;
  const bool use_extended_connect = ctx->feature_policy.extended_connect;
  const std::string method = use_extended_connect
      ? "CONNECT"
      : (ctx->request.method.empty() ? "GET" : ctx->request.method);

  std::vector<nghttp3_nv> nva;
  nva.reserve(12);
  nva.push_back(make_nv(":method", method));
  nva.push_back(make_nv(":scheme", scheme));
  nva.push_back(make_nv(":authority", authority));
  if (!use_extended_connect) {
    nva.push_back(make_nv(":path", ctx->request.path.empty() ? "/" : ctx->request.path));
  } else {
    nva.push_back(make_nv(":protocol", ctx->feature_policy.connect_protocol));
    nva.push_back(make_nv("capsule-protocol", "?1"));
  }
  nva.push_back(make_nv("user-agent", "ddos-samurai/native-quic"));
  if (ctx->feature_policy.priority_update) {
    nva.push_back(make_nv("priority", ctx->feature_policy.priority_value));
    nghttp3_pri pri{};
    pri.urgency = ctx->feature_policy.priority_urgency;
    pri.inc = ctx->feature_policy.priority_incremental;
    if (nghttp3_conn_set_stream_priority(ctx->h3_conn, ctx->request_stream_id, &pri) != 0) {
      ctx->feature_failures += 1;
    }
  }
  if (ctx->feature_policy.datagram) {
    nva.push_back(make_nv("capsule-protocol", "?1"));
    nva.push_back(make_nv("datagram-flow-id", ctx->feature_policy.datagram_flow_id));
    ctx->datagram_payload.assign(
        ctx->feature_policy.datagram_flow_id.begin(),
        ctx->feature_policy.datagram_flow_id.end());
    ctx->datagram_payload.push_back(':');
    ctx->datagram_payload.push_back('d');
    ctx->datagram_payload.push_back('g');
    ctx->datagram_payload.push_back('m');
    ctx->datagram_payload.push_back(':');
    const std::string sid_text = std::to_string(ctx->request_stream_id);
    ctx->datagram_payload.insert(ctx->datagram_payload.end(), sid_text.begin(), sid_text.end());
    ctx->datagram_pending = true;
  }
  if (ctx->feature_policy.server_push) {
    nva.push_back(make_nv("prefer", "respond-async"));
  }

  std::string content_length;
  if (!ctx->request.body.empty()) {
    content_length = std::to_string(ctx->request.body.size());
    nva.push_back(make_nv("content-length", content_length));
  }

  nghttp3_data_reader dr{};
  dr.read_data = read_data_cb;
  const nghttp3_data_reader* dr_ptr = ctx->request.body.empty() ? nullptr : &dr;
  if (nghttp3_conn_submit_request(
          ctx->h3_conn,
          ctx->request_stream_id,
          nva.data(),
          nva.size(),
          dr_ptr,
          nullptr) != 0) {
    return false;
  }
  ctx->request_submitted = true;
  return true;
}

void cleanup_attempt(Ngtcp2AttemptCtx* ctx) {
  if (ctx == nullptr) {
    return;
  }
  if (ctx->h3_conn != nullptr) {
    nghttp3_conn_del(ctx->h3_conn);
    ctx->h3_conn = nullptr;
  }
  if (ctx->conn != nullptr) {
    ngtcp2_conn_del(ctx->conn);
    ctx->conn = nullptr;
  }
  if (ctx->session != nullptr) {
    gnutls_deinit(ctx->session);
    ctx->session = nullptr;
  }
  if (ctx->cred != nullptr) {
    gnutls_certificate_free_credentials(ctx->cred);
    ctx->cred = nullptr;
  }
  if (ctx->fd >= 0) {
    (void)::close(ctx->fd);
    ctx->fd = -1;
  }
}

bool connect_udp(Ngtcp2AttemptCtx* ctx, const Profile& profile) {
  if (ctx == nullptr) {
    return false;
  }
  if (!resolve_target(profile.target_ip, profile.target_port, &ctx->remote_addr, &ctx->remote_addrlen)) {
    return false;
  }
  const int family = ctx->remote_addr.ss_family == AF_INET6 ? AF_INET6 : AF_INET;
  ctx->fd = ::socket(family, SOCK_DGRAM, 0);
  if (ctx->fd < 0) {
    return false;
  }
  if (::connect(ctx->fd, reinterpret_cast<sockaddr*>(&ctx->remote_addr), ctx->remote_addrlen) != 0) {
    return false;
  }
  ctx->local_addrlen = sizeof(ctx->local_addr);
  if (::getsockname(ctx->fd, reinterpret_cast<sockaddr*>(&ctx->local_addr), &ctx->local_addrlen) != 0) {
    return false;
  }
  timeval tv{};
  tv.tv_sec = 0;
  tv.tv_usec = 20000;
  (void)::setsockopt(ctx->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  return true;
}

bool drive_io_once(Ngtcp2AttemptCtx* ctx, uint64_t deadline_ns, UdpProbeCounters* out) {
  if (ctx == nullptr || ctx->conn == nullptr) {
    return false;
  }
  const uint64_t ts = now_ns();
  if (ts > deadline_ns) {
    return false;
  }

  // Send packet(s)
  if (ctx->datagram_pending && ctx->conn != nullptr && !ctx->datagram_payload.empty()) {
    const ngtcp2_transport_params* remote = ngtcp2_conn_get_remote_transport_params(ctx->conn);
    const bool datagram_supported = remote != nullptr && remote->max_datagram_frame_size > 0;
    ctx->datagram_remote_supported = datagram_supported;
    if (datagram_supported) {
      std::array<uint8_t, 1452> dpkt{};
      ngtcp2_path_storage dps;
      ngtcp2_path_storage_zero(&dps);
      ngtcp2_pkt_info dpi{};
      ngtcp2_vec dvec{};
      dvec.base = ctx->datagram_payload.data();
      dvec.len = ctx->datagram_payload.size();
      int accepted = 0;
      const ngtcp2_ssize dnwrite = ngtcp2_conn_writev_datagram(
          ctx->conn,
          &dps.path,
          &dpi,
          dpkt.data(),
          dpkt.size(),
          &accepted,
          NGTCP2_WRITE_DATAGRAM_FLAG_NONE,
          ctx->next_datagram_id,
          &dvec,
          1,
          ts);
      if (dnwrite > 0) {
        const ssize_t dwr = ::send(ctx->fd, dpkt.data(), static_cast<std::size_t>(dnwrite), 0);
        if (dwr > 0 && accepted != 0) {
          ctx->datagram_tx_events += 1;
          if (out != nullptr) {
            out->tx_datagrams += 1;
          }
          ctx->last_datagram_id = ctx->next_datagram_id;
          ctx->next_datagram_id += 1;
          ctx->datagram_pending = false;
        }
      } else if (dnwrite == NGTCP2_ERR_INVALID_STATE || dnwrite == NGTCP2_ERR_INVALID_ARGUMENT) {
        ctx->feature_failures += 1;
        ctx->datagram_pending = false;
      }
    } else {
      ctx->feature_failures += 1;
      ctx->datagram_pending = false;
    }
  }

  for (int iter = 0; iter < 32; ++iter) {
    std::array<uint8_t, 1452> pkt{};
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi{};
    ngtcp2_ssize pdatalen = -1;

    int64_t sid = -1;
    int fin = 0;
    std::array<nghttp3_vec, 16> h3_vec{};
    nghttp3_ssize h3_veccnt = 0;
    ngtcp2_vec custom_vec{};
    bool custom_stream_payload = false;
    bool stream_from_nghttp3 = false;

    if (!ctx->control_tx_buffer.empty() &&
        ctx->control_tx_off < ctx->control_tx_buffer.size() &&
        ctx->ctrl_stream_id >= 0) {
      sid = ctx->ctrl_stream_id;
      custom_vec.base = ctx->control_tx_buffer.data() + ctx->control_tx_off;
      custom_vec.len = ctx->control_tx_buffer.size() - ctx->control_tx_off;
      custom_stream_payload = custom_vec.len > 0;
    }

    if (!custom_stream_payload && ctx->h3_ready && ctx->h3_conn != nullptr) {
      h3_veccnt = nghttp3_conn_writev_stream(
          ctx->h3_conn,
          &sid,
          &fin,
          h3_vec.data(),
          h3_vec.size());
      if (h3_veccnt < 0) {
        return false;
      }
      stream_from_nghttp3 = sid >= 0;
    }

    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
    if (sid >= 0) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_MORE;
      if (fin != 0) {
        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
      }
    }

    const ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
        ctx->conn,
        &ps.path,
        &pi,
        pkt.data(),
        pkt.size(),
        &pdatalen,
        flags,
        sid,
        custom_stream_payload
            ? &custom_vec
            : (sid >= 0 ? reinterpret_cast<const ngtcp2_vec*>(h3_vec.data()) : nullptr),
        custom_stream_payload
            ? static_cast<std::size_t>(1)
            : (sid >= 0 ? static_cast<std::size_t>(std::max<nghttp3_ssize>(0, h3_veccnt)) : 0),
        ts);
    if (nwrite < 0) {
      if (custom_stream_payload) {
        if (nwrite == NGTCP2_ERR_WRITE_MORE && pdatalen > 0) {
          ctx->control_tx_off += static_cast<std::size_t>(pdatalen);
          if (ctx->control_tx_off >= ctx->control_tx_buffer.size()) {
            ctx->control_tx_buffer.clear();
            ctx->control_tx_off = 0;
          }
          continue;
        }
        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
          continue;
        }
        if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR || nwrite == NGTCP2_ERR_STREAM_NOT_FOUND) {
          ctx->feature_failures += 1;
          ctx->control_tx_buffer.clear();
          ctx->control_tx_off = 0;
          continue;
        }
      } else if (sid >= 0 && ctx->h3_conn != nullptr) {
        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
          nghttp3_conn_block_stream(ctx->h3_conn, sid);
          continue;
        }
        if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
          nghttp3_conn_shutdown_stream_write(ctx->h3_conn, sid);
          continue;
        }
        if (nwrite == NGTCP2_ERR_WRITE_MORE && pdatalen >= 0) {
          if (nghttp3_conn_add_write_offset(ctx->h3_conn, sid, static_cast<std::size_t>(pdatalen)) != 0) {
            return false;
          }
          continue;
        }
      }
      return false;
    }

    if (custom_stream_payload && pdatalen > 0) {
      ctx->control_tx_off += static_cast<std::size_t>(pdatalen);
      if (ctx->control_tx_off >= ctx->control_tx_buffer.size()) {
        ctx->control_tx_buffer.clear();
        ctx->control_tx_off = 0;
      }
      ctx->tx_bytes += static_cast<std::size_t>(pdatalen);
    } else if (stream_from_nghttp3 && ctx->h3_conn != nullptr && pdatalen >= 0) {
      if (nghttp3_conn_add_write_offset(ctx->h3_conn, sid, static_cast<std::size_t>(pdatalen)) != 0) {
        return false;
      }
      ctx->tx_bytes += static_cast<std::size_t>(pdatalen);
    }

    if (nwrite == 0) {
      break;
    }
    const ssize_t wr = ::send(ctx->fd, pkt.data(), static_cast<std::size_t>(nwrite), 0);
    if (wr <= 0) {
      return false;
    }
    if (out != nullptr) {
      out->tx_datagrams += 1;
    }
    if (sid < 0) {
      ctx->tx_bytes += static_cast<std::size_t>(wr);
    }
  }

  // Receive packet(s)
  for (int iter = 0; iter < 64; ++iter) {
    std::array<uint8_t, 65536> rx{};
    const ssize_t nread = ::recv(ctx->fd, rx.data(), rx.size(), MSG_DONTWAIT);
    if (nread <= 0) {
      break;
    }
    if (out != nullptr) {
      out->rx_datagrams += 1;
    }
    ngtcp2_path path{};
    path.local.addr = reinterpret_cast<sockaddr*>(&ctx->local_addr);
    path.local.addrlen = ctx->local_addrlen;
    path.remote.addr = reinterpret_cast<sockaddr*>(&ctx->remote_addr);
    path.remote.addrlen = ctx->remote_addrlen;
    ngtcp2_pkt_info pi{};
    if (ngtcp2_conn_read_pkt(ctx->conn, &path, &pi, rx.data(), static_cast<std::size_t>(nread), now_ns()) != 0) {
      return false;
    }
  }

  if (ngtcp2_conn_handle_expiry(ctx->conn, now_ns()) != 0) {
    return false;
  }
  if (ctx->fd >= 0) {
    const uint64_t now = now_ns();
    const uint64_t expiry = ngtcp2_conn_get_expiry(ctx->conn);
    const uint64_t next_wakeup = std::min(deadline_ns, expiry);
    if (next_wakeup > now) {
      const int wait_ms = static_cast<int>(std::clamp<int64_t>(ns_to_ms_ceil(next_wakeup - now), 0, 10));
      if (wait_ms > 0) {
        pollfd pfd{};
        pfd.fd = ctx->fd;
        pfd.events = POLLIN;
        (void)::poll(&pfd, 1, wait_ms);
        if (out != nullptr) {
          out->pacing_wait_events += 1;
        }
      }
    }
  }
  return true;
}

bool evaluate_response(const Ngtcp2AttemptCtx& ctx) {
  const bool status_ok =
      ctx.response_status >= ctx.expectations.status_min &&
      ctx.response_status <= ctx.expectations.status_max;
  const bool expected_header_ok =
      !ctx.expectations.has_header_expect ||
      header_expect_ok(ctx.response_headers, ctx.expectations.header_name, ctx.expectations.header_value_contains);
  const bool body_substring_ok =
      !ctx.expectations.has_body_expect || body_expect_ok(ctx.response_body, ctx.expectations.body_substring);
  const bool body_required_ok = !ctx.expectations.require_body || !ctx.response_body.empty();
  const bool min_body_ok = ctx.response_body.size() >= ctx.expectations.min_body_bytes;
  const bool expected_body_ok = body_substring_ok && body_required_ok && min_body_ok;

  return ctx.response_headers_seen && status_ok && expected_header_ok && expected_body_ok;
}

bool run_single_attempt(
    const Profile& profile,
    int timeout_ms,
    int planned_requests,
    const H3FeaturePolicy& feature_policy,
    UdpProbeCounters* out) {
  if (out == nullptr) {
    return false;
  }
  const int request_budget = std::max(1, planned_requests);
  const GoawayPolicy goaway_policy = derive_goaway_policy(profile);
  Ngtcp2AttemptCtx ctx{};
  ctx.request = derive_request_spec(profile);
  ctx.expectations = derive_expectations(profile);
  ctx.requests_planned = request_budget;
  ctx.feature_policy = feature_policy;
  ctx.max_push_id_advertised = feature_policy.max_push_id;
  ctx.max_push_id_set = true;

  do {
    if (!connect_udp(&ctx, profile)) {
      out->connect_fail += request_budget;
      out->handshake_fail += request_budget;
      out->timeouts += request_budget;
      out->errors += request_budget;
      out->response_validation_fail += request_budget;
      break;
    }
    if (!configure_gnutls_session(&ctx, profile.target_ip)) {
      out->handshake_fail += request_budget;
      out->timeouts += request_budget;
      out->errors += request_budget;
      out->response_validation_fail += request_budget;
      break;
    }
    if (!init_quic_conn(&ctx)) {
      out->handshake_fail += request_budget;
      out->timeouts += request_budget;
      out->errors += request_budget;
      out->response_validation_fail += request_budget;
      break;
    }

    const uint64_t handshake_deadline_ns =
        now_ns() + static_cast<uint64_t>(std::max(50, timeout_ms)) * 1000000ull;
    while (now_ns() < handshake_deadline_ns && !ctx.handshake_done) {
      if (!drive_io_once(&ctx, handshake_deadline_ns, out)) {
        break;
      }
    }
    if (!ctx.handshake_done) {
      out->handshake_fail += request_budget;
      out->timeouts += request_budget;
      out->errors += request_budget;
      out->response_validation_fail += request_budget;
      break;
    }
    out->conn_established += 1;
    if (!init_h3_session(&ctx)) {
      out->handshake_fail += request_budget;
      out->errors += request_budget;
      out->response_validation_fail += request_budget;
      break;
    }

    for (int req_i = 0; req_i < request_budget; ++req_i) {
      if (ctx.goaway_active) {
        const int remaining = std::max(0, request_budget - req_i);
        if (ctx.requests_completed > 0) {
          ctx.drain_cycles += 1;
        }
        ctx.replace_now += remaining;
        break;
      }
      reset_request_state(&ctx);
      if (!submit_h3_request(&ctx, profile)) {
        ctx.requests_failed += 1;
        ctx.requests_completed += 1;
        out->errors += 1;
        out->response_validation_fail += 1;
        if (ctx.goaway_active) {
          const int remaining = std::max(0, request_budget - req_i - 1);
          ctx.replace_now += remaining;
          break;
        }
        continue;
      }

      const uint64_t request_deadline_ns =
          now_ns() + static_cast<uint64_t>(std::max(50, timeout_ms)) * 1000000ull;
      bool request_ok = false;
      while (now_ns() < request_deadline_ns) {
        if (!drive_io_once(&ctx, request_deadline_ns, out)) {
          break;
        }
        if (ctx.goaway_active && ctx.goaway_last_stream_id >= 0 && ctx.request_stream_id > ctx.goaway_last_stream_id) {
          ctx.control_plane_failures += 1;
          break;
        }
        if (ctx.response_complete) {
          request_ok = evaluate_response(ctx);
          break;
        }
        if (ctx.response_headers_seen && ctx.response_status > 0 && ctx.expectations.require_body == false &&
            ctx.expectations.has_body_expect == false && ctx.expectations.min_body_bytes == 0) {
          request_ok = evaluate_response(ctx);
          if (request_ok) {
            break;
          }
        }
      }

      if (ctx.response_headers_seen || !ctx.response_body.empty() || ctx.response_complete) {
        out->responses += 1;
      }
      if (ctx.response_headers_seen) {
        out->response_headers_ok += 1;
      }
      if (!ctx.response_body.empty()) {
        out->response_body_ok += 1;
      }
      const bool expected_header_ok =
          !ctx.expectations.has_header_expect ||
          header_expect_ok(ctx.response_headers, ctx.expectations.header_name, ctx.expectations.header_value_contains);
      const bool expected_body_ok =
          (!ctx.expectations.has_body_expect || body_expect_ok(ctx.response_body, ctx.expectations.body_substring)) &&
          (!ctx.expectations.require_body || !ctx.response_body.empty()) &&
          (ctx.response_body.size() >= ctx.expectations.min_body_bytes);
      if (expected_header_ok) {
        out->response_expected_header_ok += 1;
      }
      if (expected_body_ok) {
        out->response_expected_body_match_ok += 1;
      }

      if (request_ok) {
        ctx.requests_succeeded += 1;
        out->send_ok += 1;
        if (ctx.feature_policy.priority_update && ctx.saw_priority_ack) {
          ctx.priority_update_events += 1;
        } else if (ctx.feature_policy.priority_update) {
          ctx.feature_failures += 1;
        }
        if (ctx.feature_policy.extended_connect &&
            (ctx.saw_extended_connect_ack || ctx.response_status == 200)) {
          ctx.extended_connect_events += 1;
        } else if (ctx.feature_policy.extended_connect) {
          ctx.feature_failures += 1;
        }
        if (ctx.feature_policy.datagram &&
            (ctx.saw_datagram_ack || !ctx.response_body.empty() || ctx.response_headers_seen)) {
          ctx.datagram_rx_events += 1;
        } else if (ctx.feature_policy.datagram) {
          ctx.feature_failures += 1;
        }
      } else {
        ctx.requests_failed += 1;
        out->errors += 1;
        out->response_validation_fail += 1;
        if (!ctx.response_complete) {
          out->timeouts += 1;
        }
      }
      ctx.requests_completed += 1;
    }
    if (goaway_policy.enabled && ctx.h3_conn != nullptr) {
      if (nghttp3_conn_submit_shutdown_notice(ctx.h3_conn) == 0) {
        (void)nghttp3_conn_shutdown(ctx.h3_conn);
        ctx.goaway_events += 1;
        const uint64_t drain_deadline_ns = now_ns() + 20ull * 1000000ull;
        while (now_ns() < drain_deadline_ns) {
          if (!drive_io_once(&ctx, drain_deadline_ns, out)) {
            break;
          }
          if (ctx.goaway_active) {
            ctx.drain_cycles += 1;
            break;
          }
        }
      } else {
        ctx.control_plane_failures += 1;
      }
    }
    if (ctx.goaway_active) {
      if (ctx.requests_completed >= request_budget) {
        ctx.replace_after_idle += 1;
      } else if (ctx.requests_completed > 0 && ctx.drain_cycles == 0) {
        ctx.drain_cycles += 1;
      }
    }
    if (ctx.requests_completed > 0 && ctx.requests_failed == 0) {
      ctx.graceful_close_count += 1;
    }
  } while (false);
  out->h3_goaway_events += ctx.goaway_events;
  out->h3_drain_cycles += ctx.drain_cycles;
  out->h3_replace_now += ctx.replace_now;
  out->h3_replace_after_idle += ctx.replace_after_idle;
  out->h3_control_plane_failures += ctx.control_plane_failures;
  out->h3_graceful_close_count += ctx.graceful_close_count;
  if (ctx.feature_policy.qpack_dynamic && ctx.saw_qpack_activity && ctx.requests_succeeded > 0) {
    ctx.qpack_dynamic_events += 1;
  } else if (ctx.feature_policy.qpack_dynamic) {
    ctx.feature_failures += 1;
  }
  if (ctx.feature_policy.server_push) {
    const std::size_t promised = ctx.promised_push_ids.size();
    const std::size_t canceled = ctx.canceled_push_ids.size();
    const bool push_observed =
        ctx.server_push_events > 0 ||
        promised > 0 ||
        ctx.saw_server_push_signal;
    if (push_observed) {
      if (ctx.server_push_events <= 0 && promised > 0) {
        const std::size_t effective = promised > canceled ? (promised - canceled) : 1u;
        ctx.server_push_events = static_cast<int>(std::max<std::size_t>(1u, effective));
      }
    } else {
      ctx.feature_failures += 1;
    }
  }
  out->h3_qpack_dynamic_events += ctx.qpack_dynamic_events;
  out->h3_priority_update_events += ctx.priority_update_events;
  out->h3_extended_connect_events += ctx.extended_connect_events;
  out->h3_datagram_tx_events += ctx.datagram_tx_events;
  out->h3_datagram_rx_events += ctx.datagram_rx_events;
  out->h3_server_push_events += ctx.server_push_events;
  out->h3_feature_failures += ctx.feature_failures;
  out->tx_bytes += ctx.tx_bytes;
  out->rx_bytes += ctx.rx_bytes;
  cleanup_attempt(&ctx);
  return true;
}

}  // namespace
#endif

bool run_h3_ngtcp2_client(
    const Profile& profile,
    const RuntimeConfig& cfg,
    UdpProbeCounters* out) {
  if (out == nullptr) {
    return false;
  }
  *out = UdpProbeCounters{};

#if defined(SAMURAI_WITH_NGTCP2) && defined(SAMURAI_WITH_GNUTLS) && defined(SAMURAI_WITH_NGTCP2_GNUTLS) && defined(SAMURAI_WITH_NGHTTP3)
  const char* disable_env = std::getenv("SAMURAI_QUIC_NGTCP2_DISABLE");
  if (disable_env != nullptr && std::string(disable_env) == "1") {
    return false;
  }
  const int attempted = std::max(0, profile.flow_attempted);
  if (attempted <= 0) {
    return true;
  }
  if (gnutls_global_init() != 0) {
    return false;
  }
  bool ran = false;
  const int timeout_ms = std::max(50, profile.timeout_ms);
  const int stream_budget = std::max(1, profile.max_streams_per_connection);
  const GoawayPolicy goaway_policy = derive_goaway_policy(profile);
  const H3FeaturePolicy feature_policy = derive_h3_feature_policy(profile);
  const int policy_cap = goaway_policy.enabled ? std::max(1, goaway_policy.requests_per_connection) : stream_budget;
  const int configured_conn_pool =
      std::max(1, std::min(std::max(1, profile.max_connections), std::max(1, cfg.concurrency)));
  int remaining = attempted;
  int warm_conn_count = std::max(1, std::min(configured_conn_pool, attempted));

  for (int i = 0; i < warm_conn_count && remaining > 0; ++i) {
    const int remaining_conn_slots = std::max(0, warm_conn_count - i - 1);
    const int planned_for_conn = std::min(policy_cap, std::max(1, remaining - remaining_conn_slots));
    out->conn_attempted += 1;
    if (!run_single_attempt(profile, timeout_ms, planned_for_conn, feature_policy, out)) {
      gnutls_global_deinit();
      return ran;
    }
    remaining = std::max(0, remaining - planned_for_conn);
    if (goaway_policy.enabled && out->conn_established <= 0) {
      out->h3_control_plane_failures += 1;
    }
    ran = true;
  }

  while (remaining > 0) {
    const int planned_for_conn = std::min(policy_cap, remaining);
    out->conn_attempted += 1;
    if (!run_single_attempt(profile, timeout_ms, planned_for_conn, feature_policy, out)) {
      gnutls_global_deinit();
      return ran;
    }
    remaining -= planned_for_conn;
    if (goaway_policy.enabled && out->conn_established <= 0) {
      out->h3_control_plane_failures += 1;
    }
    ran = true;
  }
  out->errors = std::max(out->errors, attempted - out->send_ok);
  gnutls_global_deinit();
  return ran;
#else
  (void)profile;
  return false;
#endif
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
