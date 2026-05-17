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

  int response_status{0};
  std::string response_headers{};
  std::string response_body{};

  std::size_t rx_bytes{0};
  std::size_t tx_bytes{0};
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
  (void)id;
  (void)conn_user_data;
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

  std::vector<nghttp3_nv> nva;
  nva.reserve(8);
  nva.push_back(make_nv(":method", ctx->request.method.empty() ? "GET" : ctx->request.method));
  nva.push_back(make_nv(":scheme", scheme));
  nva.push_back(make_nv(":authority", authority));
  nva.push_back(make_nv(":path", ctx->request.path.empty() ? "/" : ctx->request.path));
  nva.push_back(make_nv("user-agent", "ddos-samurai/native-quic"));

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

    if (ctx->h3_ready && ctx->h3_conn != nullptr) {
      h3_veccnt = nghttp3_conn_writev_stream(
          ctx->h3_conn,
          &sid,
          &fin,
          h3_vec.data(),
          h3_vec.size());
      if (h3_veccnt < 0) {
        return false;
      }
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
        sid >= 0 ? reinterpret_cast<const ngtcp2_vec*>(h3_vec.data()) : nullptr,
        sid >= 0 ? static_cast<std::size_t>(std::max<nghttp3_ssize>(0, h3_veccnt)) : 0,
        ts);
    if (nwrite < 0) {
      if (sid >= 0 && ctx->h3_conn != nullptr) {
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

    if (sid >= 0 && ctx->h3_conn != nullptr && pdatalen >= 0) {
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
    UdpProbeCounters* out) {
  if (out == nullptr) {
    return false;
  }
  const int request_budget = std::max(1, planned_requests);
  Ngtcp2AttemptCtx ctx{};
  ctx.request = derive_request_spec(profile);
  ctx.expectations = derive_expectations(profile);
  ctx.requests_planned = request_budget;

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
      reset_request_state(&ctx);
      if (!submit_h3_request(&ctx, profile)) {
        ctx.requests_failed += 1;
        out->errors += 1;
        out->response_validation_fail += 1;
        continue;
      }

      const uint64_t request_deadline_ns =
          now_ns() + static_cast<uint64_t>(std::max(50, timeout_ms)) * 1000000ull;
      bool request_ok = false;
      while (now_ns() < request_deadline_ns) {
        if (!drive_io_once(&ctx, request_deadline_ns, out)) {
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
  } while (false);
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
  const char* enable_env = std::getenv("SAMURAI_QUIC_NGTCP2_ENABLE");
  if (enable_env == nullptr || std::string(enable_env) != "1") {
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
  const int configured_conn_pool =
      std::max(1, std::min(std::max(1, profile.max_connections), std::max(1, cfg.concurrency)));
  int remaining = attempted;
  int warm_conn_count = std::max(1, std::min(configured_conn_pool, attempted));

  for (int i = 0; i < warm_conn_count && remaining > 0; ++i) {
    const int remaining_conn_slots = std::max(0, warm_conn_count - i - 1);
    const int planned_for_conn = std::min(stream_budget, std::max(1, remaining - remaining_conn_slots));
    out->conn_attempted += 1;
    if (!run_single_attempt(profile, timeout_ms, planned_for_conn, out)) {
      gnutls_global_deinit();
      return ran;
    }
    remaining = std::max(0, remaining - planned_for_conn);
    ran = true;
  }

  while (remaining > 0) {
    const int planned_for_conn = std::min(stream_budget, remaining);
    out->conn_attempted += 1;
    if (!run_single_attempt(profile, timeout_ms, planned_for_conn, out)) {
      gnutls_global_deinit();
      return ran;
    }
    remaining -= planned_for_conn;
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
