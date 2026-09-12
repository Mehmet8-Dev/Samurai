#include "engine_internal.hpp"
#include "tls_session_engine.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace ddos_samurai::l7_emu_native {

// Probe once whether this host exposes the TCP "tls" ULP so kTLS can engage.
// Cached. The authoritative signal is the kernel's registered-ULP list in
// /proc/sys/net/ipv4/tcp_available_ulp (a space-separated set, e.g.
// "espintcp mptcp tls"). We fall back to setsockopt(TCP_ULP,"tls") on a throwaway
// socket: on an unconnected socket the kernel reports the ULP is present but not
// applicable via ENOTCONN/EINVAL/EISCONN (as opposed to ENOENT/EOPNOTSUPP when
// the module is absent). Any TLS session that requested kTLS falls back to the
// memory-BIO path when this is false, so a missing ULP is never fatal.
bool ktls_ulp_available() {
#if defined(__linux__) && defined(TCP_ULP)
  static const bool available = []() -> bool {
    if (FILE* f = std::fopen("/proc/sys/net/ipv4/tcp_available_ulp", "re")) {
      char buf[256];
      const std::size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
      std::fclose(f);
      buf[n] = '\0';
      // Match the whole "tls" token, not a substring of another ULP name.
      for (char* tok = std::strtok(buf, " \t\n"); tok != nullptr;
           tok = std::strtok(nullptr, " \t\n")) {
        if (std::strcmp(tok, "tls") == 0) {
          return true;
        }
      }
      return false;  // proc file present and readable but no tls ULP listed
    }
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      return false;
    }
    const int rc = ::setsockopt(fd, SOL_TCP, TCP_ULP, "tls", 4);
    const int saved = errno;
    ::close(fd);
    if (rc == 0) {
      return true;
    }
    // The ULP exists but refuses an unconnected socket -> still available.
    return saved == ENOTCONN || saved == EINVAL || saved == EISCONN;
  }();
  return available;
#else
  return false;
#endif
}

const std::string& build_h2_preface_and_settings() {
  static const std::string preface = []() {
    std::string out("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    // Empty SETTINGS frame: len=0, type=0x4, flags=0x0, stream=0.
    const unsigned char settings_frame[9] = {
        0x00, 0x00, 0x00,
        0x04,
        0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    out.append(reinterpret_cast<const char*>(settings_frame), sizeof(settings_frame));
    return out;
  }();
  return preface;
}

#ifdef SAMURAI_WITH_NGHTTP2

void reset_h2_stream_state(H2StreamState& stream) {
  trim_reusable_string(stream.request_method, 64);
  ensure_reusable_string_capacity(stream.request_method, 16);
  trim_reusable_string(stream.request_path, 4096);
  ensure_reusable_string_capacity(stream.request_path, kH2SlabRequestPathBytes);
  if (stream.request_headers.empty()) {
    stream.request_headers.resize(kReusableHeaderSlotReserve);
    for (auto& slot : stream.request_headers) {
      ensure_reusable_string_capacity(slot.key, 32);
      ensure_reusable_string_capacity(slot.value, kArenaBucketSmallBytes);
    }
  } else {
    for (auto& slot : stream.request_headers) {
      slot.key.clear();
      slot.value.clear();
    }
  }
  stream.request_header_count = 0;
  trim_reusable_string(stream.outbound_body);
  ensure_reusable_string_capacity(stream.outbound_body, kH2SlabOutboundBodyBytes);
  stream.outbound_offset = 0;
  stream.status_code = 0;
  stream.response_headers.clear();
  stream.response_header_fields.clear();
  stream.response_header_fields.reserve(kReusableResponseHeaderReserve);
  trim_reusable_string(stream.response_body);
  ensure_reusable_string_capacity(stream.response_body, kH2SlabResponseBodyBytes);
  stream.follow_ops.clear();
  stream.submit_header_names.clear();
  stream.submit_header_values.clear();
  stream.completed = false;
}

std::unique_ptr<H2StreamState> acquire_h2_stream_state(H2ClientSession& client) {
  if (!client.free_streams.empty()) {
    client.stream_pool_reuse_hits += 1;
    auto stream = std::move(client.free_streams.back());
    client.free_streams.pop_back();
    if (stream) {
      reset_h2_stream_state(*stream);
      return stream;
    }
  }
  perf_alloc(sizeof(H2StreamState));
  return std::make_unique<H2StreamState>();
}

void recycle_h2_stream_state(H2ClientSession& client, std::unique_ptr<H2StreamState> stream) {
  if (!stream) {
    return;
  }
  reset_h2_stream_state(*stream);
  client.free_streams.push_back(std::move(stream));
}

void register_custom_tcp_h2_flow_binding(
    NativeRuntime& runtime,
    std::size_t shard_idx,
    H2ClientSession& client) {
  if (!is_custom_tcp_backend(client.ctx.transport_backend)) {
    return;
  }
  if (client.ctx.custom_flow_id == 0) {
    return;
  }
  NativeRuntime::CustomTcpFlowBinding binding{};
  binding.kind = ReactorLaneKind::H2;
  binding.shard_idx = shard_idx;
  binding.lane_idx = client.session_idx;
  binding.h1_lane = nullptr;
  binding.h2_session = &client;
  std::lock_guard<std::mutex> lk(custom_tcp_registry_mu());
  runtime.custom_tcp_flow_registry[client.ctx.custom_flow_id] = binding;
}

void unregister_custom_tcp_h2_flow_binding(NativeRuntime& runtime, H2ClientSession& client) {
  if (!is_custom_tcp_backend(client.ctx.transport_backend)) {
    return;
  }
  unregister_custom_tcp_flow_binding(runtime, client.ctx.custom_flow_id);
}

void register_h2_lane_fd(
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession* session) {
  if (session == nullptr || session->ctx.fd < 0 || shard.epoll_fd < 0) {
    return;
  }
  epoll_event ev {};
  ev.events = reactor_interest_mask();
  ev.data.fd = session->ctx.fd;
  if (::epoll_ctl(shard.epoll_fd, EPOLL_CTL_MOD, session->ctx.fd, &ev) != 0) {
    (void)::epoll_ctl(shard.epoll_fd, EPOLL_CTL_ADD, session->ctx.fd, &ev);
  }
  local_shard.active_fd_registry[session->ctx.fd] = NativeRuntime::LocalShard::RegisteredLaneFd{
      ReactorLaneKind::H2,
      nullptr,
      0,
      session,
  };
}

void service_custom_tcp_h2_shard_sessions(
    NativeRuntime& runtime, const Profile& profile, std::size_t shard_idx) {
  if (shard_idx >= runtime.local_shards.size()) {
    return;
  }
  auto& local_shard = runtime.local_shards[shard_idx];
  auto& shard = runtime.shards[shard_idx];
  for (auto& session_ptr : local_shard.h2_sessions) {
    if (!session_ptr) {
      continue;
    }
    H2ClientSession& client = *session_ptr;
    if (!client.ready || !is_custom_tcp_backend(client.ctx.transport_backend)) {
      continue;
    }
    service_h2_session_io(runtime, profile, shard, local_shard, client, 0, true);
    flush_ready_h2_completions(runtime, shard_idx, client);
  }
}

#ifdef SAMURAI_WITH_OPENSSL
// Buffer wire-ready bytes (ciphertext under TLS, plaintext otherwise) that
// nghttp2/OpenSSL emitted. Everything is appended to the owning session's
// uring_out_buffer; the reactor drains it to the wire afterwards (ring Send SQE
// under io_uring, send() under epoll, tcpdp under custom-tcp). Buffering here --
// rather than pushing straight to the transport -- is required because
// nghttp2_session_mem_send treats returned bytes as already sent, so a
// transport that is momentarily not writable must not drop them.
bool h2_queue_wire_bytes(H2ConnectionContext& ctx, const uint8_t* data, std::size_t len) {
  if (len == 0) {
    return true;
  }
  if (ctx.owner_session == nullptr) {
    errno = EIO;
    return false;
  }
  ctx.owner_session->uring_out_buffer.append(
      reinterpret_cast<const char*>(data), len);
  ctx.bytes_sent += len;
  return true;
}

// Drain the pending wire buffer into the tcpdp userspace stack (custom-tcp
// backend). Leaves unqueued bytes in place for the next pass. Returns false only
// on a fatal enqueue error.
bool h2_flush_out_buffer_tcpdp(H2ClientSession& client) {
  H2ConnectionContext& ctx = client.ctx;
  if (ctx.custom_flow_id == 0 || !ctx.custom_connect_ready) {
    return true;  // flow not up yet; retry later
  }
  while (client.uring_out_offset < client.uring_out_buffer.size()) {
    uint32_t queued = 0;
    const std::size_t remaining = client.uring_out_buffer.size() - client.uring_out_offset;
    const int rc = tcpdp_enqueue_send(
        ctx.custom_flow_id,
        reinterpret_cast<const uint8_t*>(client.uring_out_buffer.data()) + client.uring_out_offset,
        remaining, &queued);
    if (rc != 0) {
      ctx.transport_error = 1;
      return false;
    }
    if (queued == 0) {
      break;  // tcpdp queue full; retry next pass
    }
    client.uring_out_offset += queued;
  }
  if (client.uring_out_offset >= client.uring_out_buffer.size()) {
    client.uring_out_buffer.clear();
    client.uring_out_offset = 0;
  }
  return true;
}

// Retained name used by TLS flush; delegates to the generalized wire queue.
bool h2_custom_queue_ciphertext(H2ConnectionContext& ctx, const uint8_t* data, std::size_t len) {
  return h2_queue_wire_bytes(ctx, data, len);
}

bool h2_custom_flush_tls_wbio(H2ConnectionContext& ctx) {
  if (ctx.ssl == nullptr) {
    errno = EIO;
    return false;
  }
  BIO* wbio = SSL_get_wbio(ctx.ssl);
  if (wbio == nullptr) {
    errno = EIO;
    return false;
  }
  uint8_t out[8192];
  while (true) {
    const int n = BIO_read(wbio, out, static_cast<int>(sizeof(out)));
    if (n > 0) {
      if (!h2_custom_queue_ciphertext(ctx, out, static_cast<std::size_t>(n))) {
        return false;
      }
      continue;
    }
    if (n == 0) {
      break;
    }
    if (!BIO_should_retry(wbio)) {
      errno = EIO;
      return false;
    }
    break;
  }
  return true;
}

void h2_custom_feed_tls_rbio(H2ConnectionContext& ctx) {
  if (ctx.ssl == nullptr || ctx.read_buffer.empty()) {
    return;
  }
  BIO* rbio = SSL_get_rbio(ctx.ssl);
  if (rbio == nullptr) {
    return;
  }
  const int to_write = static_cast<int>(std::min<std::size_t>(
      ctx.read_buffer.size(),
      static_cast<std::size_t>(std::numeric_limits<int>::max())));
  if (to_write <= 0) {
    return;
  }
  const int written = BIO_write(rbio, ctx.read_buffer.data(), to_write);
  if (written > 0) {
    ctx.read_buffer.erase(0, static_cast<std::size_t>(written));
  }
}

bool h2_custom_advance_tls(H2ConnectionContext& ctx) {
  if (!ctx.use_tls) {
    return true;
  }
  if (ctx.ssl == nullptr) {
    errno = EIO;
    return false;
  }
  // Custom-tcp must wait for the userspace handshake to establish the flow; the
  // kernel-socket path is already connected by the time we drive TLS.
  if (is_custom_tcp_backend(ctx.transport_backend) && !ctx.custom_connect_ready) {
    errno = EAGAIN;
    return false;
  }
  h2_custom_feed_tls_rbio(ctx);
  if (!ctx.tls_handshake_complete) {
    const int hs = SSL_do_handshake(ctx.ssl);
    if (hs == 1) {
      const unsigned char* alpn = nullptr;
      unsigned int alpn_len = 0;
      SSL_get0_alpn_selected(ctx.ssl, &alpn, &alpn_len);
      if (alpn == nullptr || alpn_len != 2 || std::memcmp(alpn, "h2", 2) != 0) {
        errno = EPROTO;
        ctx.transport_error = 1;
        return false;
      }
      ctx.tls_handshake_complete = true;
    } else {
      const int err = SSL_get_error(ctx.ssl, hs);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        errno = EIO;
        ctx.transport_error = 1;
        return false;
      }
    }
  }
  if (!h2_custom_flush_tls_wbio(ctx)) {
    return false;
  }
  return ctx.tls_handshake_complete;
}

// Advance the socket-BIO handshake for a kTLS session. OpenSSL owns the fd, so
// SSL_do_handshake reads/writes it directly (non-blocking); the reactor only
// wakes us on readiness. On completion we enforce ALPN=h2 and latch which
// directions the kernel actually offloaded (BIO_get_ktls_{send,recv}); if the
// ULP silently declined, ktls_*_active stay false and SSL_read/SSL_write still
// work correctly (just in-process crypto) so the session remains valid.
bool h2_ktls_advance_handshake(H2ConnectionContext& ctx) {
  if (ctx.tls_handshake_complete) {
    return true;
  }
  const int hs = SSL_do_handshake(ctx.ssl);
  if (hs == 1) {
    const unsigned char* alpn = nullptr;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ctx.ssl, &alpn, &alpn_len);
    if (alpn == nullptr || alpn_len != 2 || std::memcmp(alpn, "h2", 2) != 0) {
      errno = EPROTO;
      ctx.transport_error = 1;
      return false;
    }
    ctx.tls_handshake_complete = true;
#ifdef BIO_get_ktls_send
    ctx.ktls_send_active = BIO_get_ktls_send(SSL_get_wbio(ctx.ssl)) > 0;
#endif
#ifdef BIO_get_ktls_recv
    ctx.ktls_recv_active = BIO_get_ktls_recv(SSL_get_rbio(ctx.ssl)) > 0;
#endif
    if (std::getenv("SAMURAI_H2_KTLS_DEBUG") != nullptr) {
      std::fprintf(stderr,
                   "[ktls] handshake done ver=%s cipher=%s send_active=%d recv_active=%d\n",
                   SSL_get_version(ctx.ssl), SSL_get_cipher(ctx.ssl),
                   ctx.ktls_send_active ? 1 : 0, ctx.ktls_recv_active ? 1 : 0);
    }
    return true;
  }
  const int err = SSL_get_error(ctx.ssl, hs);
  if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
    errno = EIO;
    ctx.transport_error = 1;
    return false;
  }
  errno = EAGAIN;
  return false;
}

// Drain nghttp2 output onto a kTLS socket via SSL_write (kernel encrypts). A
// WANT_WRITE (socket buffer full) copies the unconsumed tail into ktls_tx_pending
// and returns; the next writable wakeup retries it before pulling more from
// nghttp2. Returns false only on a fatal error. Sets errno=EAGAIN when it left
// pending bytes so the caller can arm POLLOUT.
bool h2_ktls_pump_outbound(H2ClientSession& client) {
  H2ConnectionContext& ctx = client.ctx;
  if (!h2_ktls_advance_handshake(ctx)) {
    return ctx.transport_error == 0;  // handshake still in flight is not fatal
  }
  auto write_all = [&](const uint8_t* data, std::size_t len,
                       std::size_t start) -> bool {
    std::size_t off = start;
    while (off < len) {
      const int w = SSL_write(
          ctx.ssl, data + off,
          static_cast<int>(std::min<std::size_t>(
              len - off, static_cast<std::size_t>(std::numeric_limits<int>::max()))));
      if (w > 0) {
        off += static_cast<std::size_t>(w);
        ctx.bytes_sent += static_cast<std::size_t>(w);
        continue;
      }
      const int err = SSL_get_error(ctx.ssl, w);
      if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
        if (&data[0] != reinterpret_cast<const uint8_t*>(client.ktls_tx_pending.data())) {
          client.ktls_tx_pending.assign(
              reinterpret_cast<const char*>(data + off), len - off);
        } else {
          client.ktls_tx_pending.erase(0, off);
        }
        client.ktls_tx_offset = 0;
        errno = EAGAIN;
        return false;
      }
      ctx.transport_error = 1;
      return false;
    }
    return true;
  };

  if (!client.ktls_tx_pending.empty()) {
    if (!write_all(reinterpret_cast<const uint8_t*>(client.ktls_tx_pending.data()),
                   client.ktls_tx_pending.size(), client.ktls_tx_offset)) {
      return ctx.transport_error == 0;
    }
    client.ktls_tx_pending.clear();
    client.ktls_tx_offset = 0;
  }

  for (;;) {
    const uint8_t* buf = nullptr;
    const ssize_t n = nghttp2_session_mem_send(client.session, &buf);
    if (n < 0) {
      ctx.protocol_error = 1;
      return false;
    }
    if (n == 0) {
      break;
    }
    if (!write_all(buf, static_cast<std::size_t>(n), 0)) {
      return ctx.transport_error == 0;
    }
  }
  return true;
}

// Read decrypted plaintext off a kTLS socket via SSL_read (kernel decrypts;
// OpenSSL transparently handles post-handshake control records / key updates)
// and feed it into nghttp2. Returns false on a fatal error.
bool h2_ktls_ingest_inbound(H2ClientSession& client) {
  H2ConnectionContext& ctx = client.ctx;
  if (!h2_ktls_advance_handshake(ctx)) {
    return ctx.transport_error == 0;
  }
  unsigned char plain[16384];
  for (;;) {
    const int rd = SSL_read(ctx.ssl, plain, static_cast<int>(sizeof(plain)));
    if (rd > 0) {
      ctx.bytes_received += static_cast<std::size_t>(rd);
      if (nghttp2_session_mem_recv(
              client.session, plain, static_cast<std::size_t>(rd)) < 0) {
        ctx.protocol_error = 1;
        return false;
      }
      continue;
    }
    const int err = SSL_get_error(ctx.ssl, rd);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      break;
    }
    if (err == SSL_ERROR_ZERO_RETURN) {
      if (!ctx.active_streams.empty()) {
        ctx.transport_error = 1;
      }
      break;
    }
    ctx.transport_error = 1;
    return false;
  }
  return ctx.transport_error == 0;
}
#endif

ssize_t h2_send_callback(
    nghttp2_session* session,
    const uint8_t* data,
    size_t length,
    int flags,
    void* user_data) {
  (void)session;
  (void)flags;
  auto* ctx = static_cast<H2ConnectionContext*>(user_data);
  if (ctx == nullptr) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  size_t off = 0;
  while (off < length) {
    ssize_t wr = -1;
    if (g_perf_stats != nullptr) {
      g_perf_stats->tx_syscalls += 1;
    }
    if (is_custom_tcp_backend(ctx->transport_backend)) {
      if (!ctx->custom_connect_ready) {
        errno = EAGAIN;
        return NGHTTP2_ERR_WOULDBLOCK;
      }
      if (ctx->use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
        if (!h2_custom_advance_tls(*ctx)) {
          if (ctx->transport_error != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
          }
          errno = EAGAIN;
          return NGHTTP2_ERR_WOULDBLOCK;
        }
        const int tls_wr = SSL_write(
            ctx->ssl,
            data + off,
            static_cast<int>(std::min<std::size_t>(length - off, static_cast<std::size_t>(std::numeric_limits<int>::max()))));
        if (tls_wr > 0) {
          if (!h2_custom_flush_tls_wbio(*ctx)) {
            if (ctx->transport_error != 0) {
              return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            errno = EAGAIN;
            return NGHTTP2_ERR_WOULDBLOCK;
          }
          wr = static_cast<ssize_t>(tls_wr);
        } else {
          const int err = SSL_get_error(ctx->ssl, tls_wr);
          if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (!h2_custom_flush_tls_wbio(*ctx)) {
              if (ctx->transport_error != 0) {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
              }
            }
            errno = EAGAIN;
            return NGHTTP2_ERR_WOULDBLOCK;
          }
          ctx->transport_error = 1;
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
#else
        ctx->transport_error = 1;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
#endif
      } else {
        uint32_t queued = 0;
        const int rc = tcpdp_enqueue_send(
            ctx->custom_flow_id,
            data + off,
            length - off,
            &queued);
        if (rc != 0 || queued == 0) {
          errno = EAGAIN;
          return NGHTTP2_ERR_WOULDBLOCK;
        }
        wr = static_cast<ssize_t>(queued);
      }
    } else if (ctx->use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
      if (ctx->ssl == nullptr) {
        ctx->transport_error = 1;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      const int tls_wr = SSL_write(ctx->ssl, data + off, static_cast<int>(length - off));
      if (tls_wr > 0) {
        wr = static_cast<ssize_t>(tls_wr);
      } else {
        const int err = SSL_get_error(ctx->ssl, tls_wr);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
          if (!wait_for_fd(ctx->epoll_fd, ctx->fd, err == SSL_ERROR_WANT_WRITE ? EPOLLOUT : EPOLLIN, ctx->timeout_ms)) {
            ctx->transport_error = 1;
            return NGHTTP2_ERR_CALLBACK_FAILURE;
          }
          continue;
        }
        ctx->transport_error = 1;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
#else
      ctx->transport_error = 1;
      return NGHTTP2_ERR_CALLBACK_FAILURE;
#endif
    } else {
      wr = ::send(ctx->fd, data + off, length - off, MSG_NOSIGNAL);
    }
    if (wr > 0) {
      off += static_cast<size_t>(wr);
      ctx->bytes_sent += static_cast<size_t>(wr);
      continue;
    }
    if (wr < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (!wait_for_fd(ctx->epoll_fd, ctx->fd, EPOLLOUT, ctx->timeout_ms)) {
        ctx->transport_error = 1;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      continue;
    }
    ctx->transport_error = 1;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  return static_cast<ssize_t>(length);
}

int h2_on_frame_recv_callback(
    nghttp2_session* session,
    const nghttp2_frame* frame,
    void* user_data) {
  (void)session;
  auto* ctx = static_cast<H2ConnectionContext*>(user_data);
  if (ctx != nullptr && frame != nullptr && frame->hd.type == NGHTTP2_GOAWAY) {
    ctx->goaway += 1;
  }
  return 0;
}

int h2_on_header_callback(
    nghttp2_session* session,
    const nghttp2_frame* frame,
    const uint8_t* name,
    size_t namelen,
    const uint8_t* value,
    size_t valuelen,
    uint8_t flags,
    void* user_data) {
  (void)session;
  (void)flags;
  auto* ctx = static_cast<H2ConnectionContext*>(user_data);
  if (ctx == nullptr || frame == nullptr || frame->hd.stream_id <= 0) {
    return 0;
  }
  if (frame->hd.type != NGHTTP2_HEADERS ||
      (frame->headers.cat != NGHTTP2_HCAT_RESPONSE && frame->headers.cat != NGHTTP2_HCAT_HEADERS)) {
    return 0;
  }
  const auto it = ctx->active_streams.find(frame->hd.stream_id);
  if (it == ctx->active_streams.end() || it->second == nullptr) {
    return 0;
  }
  H2StreamState& stream = *it->second;
  const std::string key = lower_copy(std::string(reinterpret_cast<const char*>(name), namelen));
  const std::string val(reinterpret_cast<const char*>(value), valuelen);
  if (key == ":status") {
    stream.status_code = std::atoi(val.c_str());
  } else {
    bool merged = false;
    for (auto& [field_key, field_value] : stream.response_header_fields) {
      if (field_key != key) {
        continue;
      }
      field_value.append("\n");
      field_value.append(val);
      merged = true;
      break;
    }
    if (!merged) {
      stream.response_header_fields.emplace_back(key, val);
    }
  }
  return 0;
}

int h2_on_data_chunk_recv_callback(
    nghttp2_session* session,
    uint8_t flags,
    int32_t stream_id,
    const uint8_t* data,
    size_t len,
    void* user_data) {
  (void)session;
  (void)flags;
  auto* ctx = static_cast<H2ConnectionContext*>(user_data);
  if (ctx == nullptr) {
    return 0;
  }
  const auto it = ctx->active_streams.find(stream_id);
  if (it == ctx->active_streams.end() || it->second == nullptr) {
    return 0;
  }
  it->second->response_body.append(reinterpret_cast<const char*>(data), len);
  ctx->bytes_received += len;
  return 0;
}

ssize_t h2_data_read_callback(
    nghttp2_session* session,
    int32_t stream_id,
    uint8_t* buf,
    size_t length,
    uint32_t* data_flags,
    nghttp2_data_source* source,
    void* user_data) {
  (void)session;
  (void)stream_id;
  (void)user_data;
  auto* stream = static_cast<H2StreamState*>(source != nullptr ? source->ptr : nullptr);
  if (stream == nullptr) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }
  const std::size_t remaining = stream->outbound_body.size() - stream->outbound_offset;
  const std::size_t to_copy = std::min(length, remaining);
  if (to_copy > 0) {
    std::memcpy(buf, stream->outbound_body.data() + stream->outbound_offset, to_copy);
    stream->outbound_offset += to_copy;
  }
  if (stream->outbound_offset >= stream->outbound_body.size()) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  return static_cast<ssize_t>(to_copy);
}

int h2_on_stream_close_callback(
    nghttp2_session* session,
    int32_t stream_id,
    uint32_t error_code,
    void* user_data) {
  (void)session;
  auto* ctx = static_cast<H2ConnectionContext*>(user_data);
  if (ctx == nullptr || stream_id <= 0) {
    return 0;
  }
  auto it = ctx->active_streams.find(stream_id);
  if (it == ctx->active_streams.end() || it->second == nullptr) {
    return 0;
  }
  H2StreamState& stream = *it->second;
  H2CompletedStream completed;
  completed.status_code = stream.status_code;
  completed.response_headers = std::move(stream.response_headers);
  completed.response_header_fields = std::move(stream.response_header_fields);
  completed.response_body = std::move(stream.response_body);
  completed.request_start_ms = stream.request_start_ms;
  completed.scenario_flow = std::move(stream.scenario_flow);
  completed.scenario_vu_id = std::move(stream.scenario_vu_id);
  completed.scenario_on_failure = std::move(stream.scenario_on_failure);
  if (error_code != NGHTTP2_NO_ERROR) {
    ctx->protocol_error = 1;
    ctx->rst_stream += 1;
    ctx->failed_streams += 1;
    completed.expectation_failures = 1;
    completed.rst_stream = true;
  } else {
    int think_time_total_ms = 0;
    evaluate_response_ops(
        stream.follow_ops,
        stream.status_code,
        completed.response_header_fields,
        completed.response_headers,
        completed.response_body,
        *ctx->captures,
        completed.expectation_failures,
        think_time_total_ms);
    completed.think_time_total_ms = think_time_total_ms;
    if (stream.status_code > 0) {
      if (stream.status_code >= 200 && stream.status_code <= 299) {
        completed.success = true;
      } else if (stream.status_code >= 300 && stream.status_code <= 399) {
        completed.success = true;
      } else if (stream.status_code >= 400 && stream.status_code <= 499) {
        completed.success = true;
      } else if (stream.status_code >= 500 && stream.status_code <= 599) {
        completed.success = true;
      }
    } else {
      completed.expectation_failures += 1;
    }
  }
  if (ctx->owner_session != nullptr) {
    ctx->owner_session->completed_streams.push_back(std::move(completed));
    recycle_h2_stream_state(*ctx->owner_session, std::move(it->second));
  }
  ctx->active_streams.erase(it);
  return 0;
}

ssize_t h2_socket_read(H2ConnectionContext& ctx, unsigned char* buf, size_t cap) {
  if (g_perf_stats != nullptr) {
    g_perf_stats->rx_syscalls += 1;
  }
  if (is_custom_tcp_backend(ctx.transport_backend)) {
    if (ctx.use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
      if (!h2_custom_advance_tls(ctx)) {
        if (ctx.transport_error != 0) {
          errno = EIO;
        } else {
          errno = EAGAIN;
        }
        return -1;
      }
      h2_custom_feed_tls_rbio(ctx);
      const int rd = SSL_read(
          ctx.ssl,
          buf,
          static_cast<int>(std::min<std::size_t>(cap, static_cast<std::size_t>(std::numeric_limits<int>::max()))));
      if (rd > 0) {
        return static_cast<ssize_t>(rd);
      }
      if (rd == 0) {
        return 0;
      }
      const int err = SSL_get_error(ctx.ssl, rd);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        (void)h2_custom_flush_tls_wbio(ctx);
        errno = EAGAIN;
        return -1;
      }
      if (err == SSL_ERROR_ZERO_RETURN) {
        return 0;
      }
      errno = EIO;
      return -1;
#else
      errno = EIO;
      return -1;
#endif
    }
    if (!ctx.read_buffer.empty()) {
      const std::size_t n = std::min<std::size_t>(cap, ctx.read_buffer.size());
      std::memcpy(buf, ctx.read_buffer.data(), n);
      ctx.read_buffer.erase(0, n);
      return static_cast<ssize_t>(n);
    }
    if (ctx.custom_terminal) {
      return 0;
    }
    errno = EAGAIN;
    return -1;
  }
  if (ctx.use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
    if (ctx.ssl == nullptr) {
      errno = EIO;
      return -1;
    }
    const int rd = SSL_read(ctx.ssl, buf, static_cast<int>(cap));
    if (rd > 0) {
      return static_cast<ssize_t>(rd);
    }
    if (rd == 0) {
      return 0;
    }
    const int err = SSL_get_error(ctx.ssl, rd);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      if (!wait_for_fd(ctx.epoll_fd, ctx.fd, err == SSL_ERROR_WANT_WRITE ? EPOLLOUT : EPOLLIN, ctx.timeout_ms)) {
        errno = EIO;
        return -1;
      }
      errno = EAGAIN;
    } else if (err == SSL_ERROR_ZERO_RETURN) {
      return 0;
    } else {
      errno = EIO;
    }
    return -1;
#else
    errno = EIO;
    return -1;
#endif
  }
  return ::recv(ctx.fd, buf, cap, 0);
}

bool setup_tls(H2ConnectionContext& ctx, const Profile& profile) {
#ifdef SAMURAI_WITH_OPENSSL
  if (!ctx.use_tls) {
    return true;
  }
  ctx.tls_ctx = SSL_CTX_new(TLS_client_method());
  if (ctx.tls_ctx == nullptr) {
    return false;
  }
  SSL_CTX_set_min_proto_version(ctx.tls_ctx, TLS1_2_VERSION);

#ifdef SSL_OP_ENABLE_KTLS
  // Offload symmetric record crypto to the kernel (and, where available, the
  // NIC) on the socket-BIO path so it does not burn userspace CPU. Memory-BIO
  // custom-TCP connections fall back to in-process crypto automatically.
  SSL_CTX_set_options(ctx.tls_ctx, SSL_OP_ENABLE_KTLS);
#endif

  // Pin the AES-NI-friendly cipher ordering (see tls_session_engine.hpp): under
  // high-throughput HTTP/2 the symmetric-encryption cost saturates the CPU
  // before the NIC, so preferring AES-128-GCM keeps that cost minimal. Honour an
  // explicit operator override when one is supplied.
  SSL_CTX_set_cipher_list(
      ctx.tls_ctx,
      profile.tls_cipher_list.empty() ? kDefaultTls12CipherList
                                      : profile.tls_cipher_list.c_str());
#if TLS1_3_VERSION
  SSL_CTX_set_ciphersuites(ctx.tls_ctx, kDefaultTls13Ciphersuites);
#endif

  SSL_CTX_set_alpn_protos(
      ctx.tls_ctx,
      reinterpret_cast<const unsigned char*>("\x02h2"),
      3);
  SSL_CTX_set_verify(ctx.tls_ctx, profile.verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
  ctx.ssl = SSL_new(ctx.tls_ctx);
  if (ctx.ssl == nullptr) {
    return false;
  }
  if (!profile.host_header.empty()) {
    SSL_set_tlsext_host_name(ctx.ssl, profile.host_header.c_str());
  }
  if (is_custom_tcp_backend(ctx.transport_backend)) {
    BIO* rbio = BIO_new(BIO_s_mem());
    BIO* wbio = BIO_new(BIO_s_mem());
    if (rbio == nullptr || wbio == nullptr) {
      if (rbio != nullptr) {
        BIO_free(rbio);
      }
      if (wbio != nullptr) {
        BIO_free(wbio);
      }
      return false;
    }
    BIO_set_mem_eof_return(rbio, -1);
    BIO_set_mem_eof_return(wbio, -1);
    SSL_set_bio(ctx.ssl, rbio, wbio);
    SSL_set_connect_state(ctx.ssl);
    ctx.tls_handshake_complete = false;
    return true;
  }
  const long long start_ms = monotonic_ms_now();
  if (SSL_set_fd(ctx.ssl, ctx.fd) != 1) {
    return false;
  }
  SSL_set_connect_state(ctx.ssl);
  while (true) {
    const int rc = SSL_connect(ctx.ssl);
    if (rc == 1) {
      break;
    }
    const int err = SSL_get_error(ctx.ssl, rc);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      return false;
    }
    if (!wait_for_fd(ctx.epoll_fd, ctx.fd, err == SSL_ERROR_WANT_WRITE ? EPOLLOUT : EPOLLIN, ctx.timeout_ms)) {
      return false;
    }
  }
  const unsigned char* alpn = nullptr;
  unsigned int alpn_len = 0;
  SSL_get0_alpn_selected(ctx.ssl, &alpn, &alpn_len);
  const bool ok = alpn != nullptr && alpn_len == 2 && std::memcmp(alpn, "h2", 2) == 0;
  if (ok) {
    perf_tls_latency(
        static_cast<double>(std::max<long long>(0, monotonic_ms_now() - start_ms)),
        0);
  }
  ctx.tls_handshake_complete = ok;
  return ok;
#else
  (void)ctx;
  (void)profile;
  return false;
#endif
}

void cleanup_tls(H2ConnectionContext& ctx) {
#ifdef SAMURAI_WITH_OPENSSL
  if (ctx.ssl != nullptr) {
    SSL_shutdown(ctx.ssl);
    SSL_free(ctx.ssl);
    ctx.ssl = nullptr;
  }
  if (ctx.tls_ctx != nullptr) {
    SSL_CTX_free(ctx.tls_ctx);
    ctx.tls_ctx = nullptr;
  }
  ctx.tls_handshake_complete = false;
#else
  (void)ctx;
#endif
}

bool submit_h2_request(
    H2ClientSession& client,
    const Profile& profile,
    const H2RequestSpec& raw_request,
    const std::map<std::string, std::string>& captures) {
  H2ConnectionContext& ctx = client.ctx;
  LaneStringArena& arena = ensure_lane_string_arena(client.string_arena);
  auto stream = acquire_h2_stream_state(client);
  {
    auto method_lease = arena_acquire_string(arena, std::max<std::size_t>(raw_request.method_template.static_bytes, 16));
    std::string& method = arena_string_or_throw(method_lease, "http2 method");
    render_capture_template_into(raw_request.method_template, captures, method);
    stream->request_method = method;
  }
  {
    auto path_lease = arena_acquire_string(arena, std::max<std::size_t>(raw_request.path_template.static_bytes, 64));
    std::string& path = arena_string_or_throw(path_lease, "http2 path");
    render_capture_template_into(raw_request.path_template, captures, path);
    stream->request_path = path;
  }
  if (stream->request_headers.size() < raw_request.compiled_headers.size()) {
    const std::size_t old_size = stream->request_headers.size();
    stream->request_headers.resize(raw_request.compiled_headers.size());
    for (std::size_t idx = old_size; idx < stream->request_headers.size(); ++idx) {
      ensure_reusable_string_capacity(stream->request_headers[idx].key, 32);
      ensure_reusable_string_capacity(stream->request_headers[idx].value, kArenaBucketSmallBytes);
    }
  }
  stream->request_header_count = raw_request.compiled_headers.size();
  for (std::size_t idx = 0; idx < raw_request.compiled_headers.size(); ++idx) {
    const auto& [key, compiled_value] = raw_request.compiled_headers[idx];
    auto value_lease = arena_acquire_string(
        arena,
        std::max<std::size_t>(compiled_value.static_bytes, kArenaBucketSmallBytes));
    std::string& value = arena_string_or_throw(value_lease, "http2 header value");
    render_capture_template_into(compiled_value, captures, value);
    stream->request_headers[idx].key = key;
    stream->request_headers[idx].value = value;
  }
  if (raw_request.body_template.has_value()) {
    auto body_lease = arena_acquire_string(
        arena,
        std::max<std::size_t>(raw_request.body_template->static_bytes, kArenaBucketBodyBytes));
    std::string& body = arena_string_or_throw(body_lease, "http2 body");
    render_capture_template_into(*raw_request.body_template, captures, body);
    stream->outbound_body = body;
  } else {
    stream->outbound_body = raw_request.body;
  }
  if (!stream->outbound_body.empty()) {
    ensure_reusable_string_capacity(
        stream->outbound_body,
        std::max<std::size_t>(stream->outbound_body.size(), kH2SlabOutboundBodyBytes));
  }
  const std::size_t response_reserve = std::max<std::size_t>(4096, stream->outbound_body.size());
  ensure_reusable_string_capacity(
      stream->response_body,
      std::max<std::size_t>(response_reserve, kH2SlabResponseBodyBytes));
  stream->follow_ops = raw_request.follow_ops;
  stream->scenario_flow = raw_request.scenario_flow;
  stream->scenario_vu_id = raw_request.scenario_vu_id;
  stream->scenario_on_failure = raw_request.scenario_on_failure;
  stream->request_start_ms = monotonic_ms_now();

  std::vector<nghttp2_nv> hdrs;
  const std::size_t header_capacity = 4 + stream->request_header_count;
  hdrs.reserve(header_capacity);
  std::vector<std::string>& header_names = stream->submit_header_names;
  std::vector<std::string>& header_values = stream->submit_header_values;
  header_names.clear();
  header_values.clear();
  header_names.reserve(header_capacity);
  header_values.reserve(header_capacity);
  auto add_header = [&hdrs, &header_names, &header_values](const std::string& key, const std::string& value) {
    header_names.push_back(key);
    header_values.push_back(value);
    nghttp2_nv nv {};
    nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(header_names.back().data()));
    nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(header_values.back().data()));
    nv.namelen = header_names.back().size();
    nv.valuelen = header_values.back().size();
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    hdrs.push_back(nv);
  };

  add_header(":method", stream->request_method.empty() ? "GET" : stream->request_method);
  add_header(":scheme", profile.scheme.empty() ? (ctx.use_tls ? "https" : "http") : profile.scheme);
  add_header(":authority", ctx.authority);
  add_header(":path", stream->request_path.empty() ? "/" : stream->request_path);
  for (std::size_t idx = 0; idx < stream->request_header_count; ++idx) {
    const std::string& key = stream->request_headers[idx].key;
    const std::string& value = stream->request_headers[idx].value;
    if (key.empty()) {
      continue;
    }
    add_header(lower_copy(key), value);
  }

  nghttp2_data_provider provider {};
  nghttp2_data_provider* provider_ptr = nullptr;
  if (!stream->outbound_body.empty()) {
    provider.source.ptr = stream.get();
    provider.read_callback = h2_data_read_callback;
    provider_ptr = &provider;
  }

  const int32_t stream_id =
      nghttp2_submit_request(client.session, nullptr, hdrs.data(), hdrs.size(), provider_ptr, stream.get());
  if (stream_id < 0) {
    recycle_h2_stream_state(client, std::move(stream));
    return false;
  }
  ctx.active_streams.emplace(stream_id, std::move(stream));
  return true;
}

void close_h2_client_session(H2ClientSession& client) {
  if (client.session != nullptr) {
    nghttp2_session_del(client.session);
    client.session = nullptr;
  }
  if (client.callbacks != nullptr) {
    nghttp2_session_callbacks_del(client.callbacks);
    client.callbacks = nullptr;
  }
  cleanup_tls(client.ctx);
  if (client.ctx.fd >= 0 && !is_custom_tcp_backend(client.ctx.transport_backend)) {
    ::close(client.ctx.fd);
  }
  client.ctx.fd = -1;
  client.ctx.active_streams.clear();
  client.ctx.custom_flow_id = 0;
  client.ctx.custom_connect_ready = false;
  client.ctx.custom_terminal = false;
  client.ctx.read_buffer.clear();
  client.pending_requests.clear();
  client.completed_streams.clear();
  // Reset the ring byte-path state and bump the generation so any Send/Recv CQE
  // still outstanding on the just-closed fd is rejected by the reactor.
  client.uring_out_buffer.clear();
  client.uring_out_offset = 0;
  client.uring_send_in_flight = false;
  client.uring_recv_in_flight = false;
  client.uring_recv_multishot = false;
  client.uring_poll_in_flight = false;
  client.uring_gen = static_cast<uint16_t>(client.uring_gen + 1);
  client.ktls_tx_pending.clear();
  client.ktls_tx_offset = 0;
  client.ctx.ktls_mode = false;
  client.ctx.ktls_send_active = false;
  client.ctx.ktls_recv_active = false;
  client.ready = false;
  client.replacement_mode = H2LaneReplacementMode::Ready;
  client.idle_deadline_ms = 0;
  client.dispatch_ready_ms = monotonic_ms_now();
  client.active_since_ms = 0;
  client.harvested_completed_success = 0;
  client.harvested_failed_streams = 0;
  client.harvested_status_2xx = 0;
  client.harvested_status_3xx = 0;
  client.harvested_status_4xx = 0;
  client.harvested_status_5xx = 0;
  client.harvested_expectation_failures = 0;
  client.harvested_goaway = 0;
  client.harvested_rst_stream = 0;
  client.harvested_drain_evictions = 0;
  client.harvested_max_think_time_ms = 0;
  client.harvested_rx_bytes = 0;
  client.harvested_tx_bytes = 0;
  client.harvested_stream_pool_reuse_hits = 0;
  client.drain_evictions = 0;
}

bool open_h2_client_session(
    NativeRuntime& runtime,
    std::size_t shard_idx,
    const Profile& profile,
    int epoll_fd,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client,
    H2RunStats& stats,
    std::size_t request_count) {
  unregister_custom_tcp_h2_flow_binding(runtime, client);
  close_h2_client_session(client);
  client.ctx = H2ConnectionContext{};
  client.ctx.epoll_fd = epoll_fd;
  client.ctx.use_tls = profile.scheme == "https";
  client.ctx.verify_peer = profile.verify != 0;
  client.ctx.timeout_ms = profile.timeout_ms;
  client.ctx.transport_backend = parse_transport_backend(profile);
  client.ctx.owner_session = &client;
  client.ctx.authority = profile.host_header.empty() ? profile.target_ip : profile.host_header;
  client.ctx.active_streams.reserve(
      static_cast<std::size_t>(std::max(1, profile.max_streams_per_connection)));
  if (client.ctx.authority.find(':') == std::string::npos && profile.target_port > 0) {
    client.ctx.authority += ":" + std::to_string(profile.target_port);
  }

  stats.conn_attempted += 1;
  if (is_custom_tcp_backend(client.ctx.transport_backend)) {
    uint32_t dst_ip = 0;
    if (!parse_ipv4_u32(profile.target_ip, &dst_ip)) {
      errno = EINVAL;
      stats.errors += static_cast<int>(request_count);
      stats.expectation_failures += static_cast<int>(request_count);
      return false;
    }
    uint64_t flow_id = 0;
    const int rc = tcpdp_enqueue_connect(
        custom_tcp_src_ip(profile),
        dst_ip,
        0,
        static_cast<uint16_t>(profile.target_port),
        &flow_id);
    if (rc != 0 || flow_id == 0) {
      errno = ENOTSUP;
      stats.errors += static_cast<int>(request_count);
      stats.expectation_failures += static_cast<int>(request_count);
      return false;
    }
    client.ctx.custom_flow_id = flow_id;
    client.ctx.custom_connect_ready = false;
    client.ctx.custom_terminal = false;
    client.ctx.tls_handshake_complete = !client.ctx.use_tls;
    client.ctx.fd = kVirtualCustomTcpFd;
  } else {
    client.ctx.fd = connect_h2_tcp_socket(profile, epoll_fd);
    if (client.ctx.fd < 0) {
      stats.errors += static_cast<int>(request_count);
      stats.expectation_failures += static_cast<int>(request_count);
      return false;
    }
    client.ctx.tls_handshake_complete = !client.ctx.use_tls;
  }
#ifdef SAMURAI_WITH_OPENSSL
  if (client.ctx.use_tls && runtime.tls_engine) {
    if (client.ctx.tls_tctx == nullptr) {
      client.ctx.tls_tctx = runtime.tls_engine->get_thread_context();
    }
    // Opt-in kTLS: on a kernel socket, when the host exposes the TCP "tls" ULP,
    // bind the SSL to the real fd so the kernel performs record crypto. Custom-tcp
    // has no kernel fd, so it always stays on memory-BIO. When the ULP is absent
    // we fall back transparently to memory-BIO (in-process crypto).
    // SAMURAI_H2_KTLS_FORCE_SOCKET_BIO exercises the entire socket-BIO kTLS data
    // path (incremental SSL_do_handshake on the fd, SSL_read/SSL_write, ring
    // poll-readiness / PollReadiness CQE handling) on hosts where the "tls" ULP
    // is unavailable. Without a real ULP the kernel simply does not offload, so
    // BIO_get_ktls_{send,recv} stay 0 and OpenSSL performs in-process crypto over
    // the socket BIO -- the byte path is otherwise identical, which is what lets
    // this validate the integration. Never enabled in production paths.
    static const bool ktls_force_socket_bio =
        std::getenv("SAMURAI_H2_KTLS_FORCE_SOCKET_BIO") != nullptr;
    const bool want_ktls = profile.tls_ktls != 0 &&
                           !is_custom_tcp_backend(client.ctx.transport_backend) &&
                           (ktls_ulp_available() || ktls_force_socket_bio);
    client.ctx.ktls_mode = want_ktls;
    // Unified memory-BIO TLS otherwise: handshake bytes ride the same wire
    // buffers as application data, so the reactor advances SSL_do_handshake
    // incrementally (h2_pump_outbound / h2_ingest_inbound). No blocking
    // SSL_connect / wait_for_fd runs on the shard thread, and ALPN=h2 is enforced
    // when the handshake completes. The kTLS path uses a socket-BIO SSL instead
    // (SSL owns the fd; the reactor supplies readiness only).
    client.ctx.ssl = static_cast<SSL*>(runtime.tls_engine->create_ssl(
        client.ctx.tls_tctx,
        profile.host_header,
        profile.target_port,
        /*use_mem_bio=*/!want_ktls,
        /*ktls_socket_fd=*/want_ktls ? client.ctx.fd : -1));
    if (client.ctx.ssl == nullptr) {
      unregister_custom_tcp_h2_flow_binding(runtime, client);
      close_h2_client_session(client);
      stats.errors += static_cast<int>(request_count);
      stats.expectation_failures += static_cast<int>(request_count);
      return false;
    }
    runtime.tls_engine->try_resume_session(
        client.ctx.tls_tctx, client.ctx.ssl, profile.host_header, profile.target_port);
    client.ctx.tls_handshake_complete = false;
  } else if (client.ctx.use_tls) {
    unregister_custom_tcp_h2_flow_binding(runtime, client);
    close_h2_client_session(client);
    stats.errors += static_cast<int>(request_count);
    stats.expectation_failures += static_cast<int>(request_count);
    return false;
  }
#else
  if (client.ctx.use_tls) {
    unregister_custom_tcp_h2_flow_binding(runtime, client);
    close_h2_client_session(client);
    stats.errors += static_cast<int>(request_count);
    stats.expectation_failures += static_cast<int>(request_count);
    return false;
  }
#endif

  stats.conn_established += 1;
  shard.connection_pool.active_connections += 1;
  shard.connection_pool.active_connections_peak = std::max(
      shard.connection_pool.active_connections_peak,
      shard.connection_pool.active_connections);
  if (nghttp2_session_callbacks_new(&client.callbacks) != 0 || client.callbacks == nullptr) {
    shard.connection_pool.active_connections =
        std::max(0, shard.connection_pool.active_connections - 1);
    unregister_custom_tcp_h2_flow_binding(runtime, client);
    close_h2_client_session(client);
    stats.errors += static_cast<int>(request_count);
    stats.expectation_failures += static_cast<int>(request_count);
    return false;
  }
  nghttp2_session_callbacks_set_send_callback(client.callbacks, h2_send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(client.callbacks, h2_on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_header_callback(client.callbacks, h2_on_header_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(client.callbacks, h2_on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(client.callbacks, h2_on_stream_close_callback);
  if (nghttp2_session_client_new(&client.session, client.callbacks, &client.ctx) != 0 || client.session == nullptr) {
    shard.connection_pool.active_connections =
        std::max(0, shard.connection_pool.active_connections - 1);
    unregister_custom_tcp_h2_flow_binding(runtime, client);
    close_h2_client_session(client);
    stats.errors += static_cast<int>(request_count);
    stats.expectation_failures += static_cast<int>(request_count);
    return false;
  }
  nghttp2_submit_settings(client.session, NGHTTP2_FLAG_NONE, nullptr, 0);
  if (!is_custom_tcp_backend(client.ctx.transport_backend)) {
    register_h2_lane_fd(shard, local_shard, &client);
  }
  client.ready = true;
  client.replacement_mode = H2LaneReplacementMode::Ready;
  client.idle_deadline_ms = monotonic_ms_now() + std::max(1, profile.timeout_ms);
  client.dispatch_ready_ms = monotonic_ms_now();
  client.active_since_ms = 0;
  client.consecutive_failures = 0;
  register_custom_tcp_h2_flow_binding(runtime, shard_idx, client);
  return true;
}

void collect_h2_session_stats(
    H2ClientSession& client,
    H2RunStats& stats,
    int sample_limit) {
  H2ConnectionContext& ctx = client.ctx;
  stats.goaway_count += std::max(0, ctx.goaway - client.harvested_goaway);
  stats.rst_stream_count += std::max(0, ctx.rst_stream - client.harvested_rst_stream);
  stats.drain_evictions += std::max(0, client.drain_evictions - client.harvested_drain_evictions);
  stats.stream_pool_reuse_hits += static_cast<int>(
      client.stream_pool_reuse_hits - client.harvested_stream_pool_reuse_hits);
  stats.active_streams_peak = std::max(
      stats.active_streams_peak,
      static_cast<int>(ctx.active_streams.size()));
  stats.rx_bytes += ctx.bytes_received - client.harvested_rx_bytes;
  stats.tx_bytes += ctx.bytes_sent - client.harvested_tx_bytes;

  client.harvested_completed_success = ctx.completed_success;
  client.harvested_failed_streams = ctx.failed_streams;
  client.harvested_status_2xx = ctx.status_2xx;
  client.harvested_status_3xx = ctx.status_3xx;
  client.harvested_status_4xx = ctx.status_4xx;
  client.harvested_status_5xx = ctx.status_5xx;
  client.harvested_expectation_failures = ctx.expectation_failures;
  client.harvested_goaway = ctx.goaway;
  client.harvested_rst_stream = ctx.rst_stream;
  client.harvested_drain_evictions = client.drain_evictions;
  client.harvested_max_think_time_ms = ctx.max_think_time_ms;
  client.harvested_rx_bytes = ctx.bytes_received;
  client.harvested_tx_bytes = ctx.bytes_sent;
  client.harvested_stream_pool_reuse_hits = client.stream_pool_reuse_hits;
  (void)sample_limit;
}

void flush_ready_h2_completions(
    NativeRuntime& runtime,
    std::size_t shard_idx,
    H2ClientSession& client) {
  while (!client.completed_streams.empty()) {
    client.completed_streams.front().session_idx = client.session_idx;
    enqueue_ready_h2_stream(runtime, shard_idx, std::move(client.completed_streams.front()));
    client.completed_streams.pop_front();
  }
}

void requeue_h2_pending_front(
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client) {
  while (!client.pending_requests.empty()) {
    local_shard.pending_h2_requests.push_front(client.pending_requests.back());
    client.pending_requests.pop_back();
  }
}

// ---------------------------------------------------------------------------
// Unified mem-BIO byte-path helpers. These carry all nghttp2 I/O for both
// reactors: the epoll path drives them with plain send()/recv(), the io_uring
// reactor with ring Send/Recv SQEs (see service_ready_lanes_io_uring), and
// custom-tcp with tcpdp. None of them block.
// ---------------------------------------------------------------------------

// Move eligible shard-level pending requests onto the session and submit them to
// nghttp2 (serializing into the session's send queue). Byte transfer happens
// later via h2_pump_outbound.
void h2_pull_pending_requests(
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client,
    const Profile& profile) {
  H2ConnectionContext& ctx = client.ctx;
  const std::size_t stream_budget =
      static_cast<std::size_t>(std::max(1, profile.max_streams_per_connection));
  while (ctx.goaway == 0 &&
         !local_shard.pending_h2_requests.empty() &&
         client.pending_requests.size() + ctx.active_streams.size() < stream_budget) {
    client.pending_requests.push_back(local_shard.pending_h2_requests.front());
    local_shard.pending_h2_requests.pop_front();
  }
  if (client.active_since_ms == 0 &&
      (!client.pending_requests.empty() || !ctx.active_streams.empty())) {
    client.active_since_ms = monotonic_ms_now();
  }
  while (ctx.goaway == 0 &&
         !client.pending_requests.empty() &&
         ctx.active_streams.size() < stream_budget) {
    static const std::map<std::string, std::string> empty_captures;
    const std::map<std::string, std::string>& request_captures =
        ctx.captures != nullptr ? *ctx.captures : empty_captures;
    if (!submit_h2_request(
            client, profile, client.pending_requests.front(), request_captures)) {
      ctx.protocol_error = 1;
      break;
    }
    client.pending_requests.pop_front();
  }
}

// Encrypt+queue one plaintext chunk emitted by nghttp2 onto the wire. With a
// memory-BIO SSL this never blocks on write space; a WANT_* here would only
// arise on a (client-GET) renegotiation we never initiate, so a short write is
// treated as fatal to avoid silently dropping the unconsumed tail.
bool h2_write_plain_to_wire(H2ConnectionContext& ctx, const uint8_t* data, std::size_t len) {
  if (!ctx.use_tls) {
    return h2_queue_wire_bytes(ctx, data, len);
  }
#ifdef SAMURAI_WITH_OPENSSL
  if (ctx.ssl == nullptr) {
    ctx.transport_error = 1;
    return false;
  }
  std::size_t off = 0;
  while (off < len) {
    const int w = SSL_write(
        ctx.ssl, data + off,
        static_cast<int>(std::min<std::size_t>(
            len - off, static_cast<std::size_t>(std::numeric_limits<int>::max()))));
    if (w > 0) {
      off += static_cast<std::size_t>(w);
      continue;
    }
    const int err = SSL_get_error(ctx.ssl, w);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      (void)h2_custom_flush_tls_wbio(ctx);
      ctx.transport_error = 1;
      errno = EAGAIN;
      return false;
    }
    ctx.transport_error = 1;
    return false;
  }
  return h2_custom_flush_tls_wbio(ctx);
#else
  (void)data;
  (void)len;
  ctx.transport_error = 1;
  return false;
#endif
}

// Progress the TLS handshake (if any) and drain every byte nghttp2 wants to send
// into the wire buffer / tcpdp. Returns false only on a fatal protocol/transport
// error; a still-pending handshake returns true (nothing to send yet).
bool h2_pump_outbound(H2ClientSession& client) {
  if (client.session == nullptr) {
    return false;
  }
  H2ConnectionContext& ctx = client.ctx;
#ifdef SAMURAI_WITH_OPENSSL
  if (ctx.ktls_mode) {
    return h2_ktls_pump_outbound(client);
  }
  if (ctx.use_tls) {
    const bool handshake_ready = h2_custom_advance_tls(ctx);
    if (ctx.transport_error != 0) {
      return false;
    }
    if (!handshake_ready) {
      return true;  // waiting on more inbound handshake bytes
    }
  }
#endif
  for (;;) {
    const uint8_t* buf = nullptr;
    const ssize_t n = nghttp2_session_mem_send(client.session, &buf);
    if (n < 0) {
      ctx.protocol_error = 1;
      return false;
    }
    if (n == 0) {
      break;
    }
    if (!h2_write_plain_to_wire(ctx, buf, static_cast<std::size_t>(n))) {
      return false;
    }
  }
  return true;
}

// Feed inbound wire bytes (already appended to ctx.read_buffer -- ciphertext
// under TLS, plaintext otherwise) into nghttp2. Under TLS this decrypts through
// the memory-BIO first. Returns false on a fatal error.
bool h2_ingest_inbound(H2ClientSession& client) {
  if (client.session == nullptr) {
    return false;
  }
  H2ConnectionContext& ctx = client.ctx;
#ifdef SAMURAI_WITH_OPENSSL
  if (ctx.ktls_mode) {
    return h2_ktls_ingest_inbound(client);
  }
#endif
  if (ctx.use_tls) {
#ifdef SAMURAI_WITH_OPENSSL
    const bool handshake_ready = h2_custom_advance_tls(ctx);
    if (ctx.transport_error != 0) {
      return false;
    }
    if (!handshake_ready) {
      return true;  // handshake still in flight
    }
    unsigned char plain[16384];
    for (;;) {
      const int rd = SSL_read(ctx.ssl, plain, static_cast<int>(sizeof(plain)));
      if (rd > 0) {
        if (nghttp2_session_mem_recv(
                client.session, plain, static_cast<std::size_t>(rd)) < 0) {
          ctx.protocol_error = 1;
          return false;
        }
        continue;
      }
      const int err = SSL_get_error(ctx.ssl, rd);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        break;
      }
      if (err == SSL_ERROR_ZERO_RETURN) {
        if (!ctx.active_streams.empty()) {
          ctx.transport_error = 1;
        }
        break;
      }
      ctx.transport_error = 1;
      return false;
    }
    return ctx.transport_error == 0;
#else
    ctx.transport_error = 1;
    return false;
#endif
  }
  if (!ctx.read_buffer.empty()) {
    if (nghttp2_session_mem_recv(
            client.session,
            reinterpret_cast<const uint8_t*>(ctx.read_buffer.data()),
            ctx.read_buffer.size()) < 0) {
      ctx.protocol_error = 1;
      return false;
    }
    ctx.read_buffer.clear();
  }
  return true;
}

// Drain the pending wire buffer to a kernel socket with non-blocking send()
// (epoll reactor). The io_uring reactor drains the same buffer with ring Send
// SQEs instead and never calls this. Returns false on a fatal transport error.
bool h2_flush_out_buffer_syscall(H2ClientSession& client) {
  H2ConnectionContext& ctx = client.ctx;
  while (client.uring_out_offset < client.uring_out_buffer.size()) {
    const ssize_t wr = ::send(
        ctx.fd,
        client.uring_out_buffer.data() + client.uring_out_offset,
        client.uring_out_buffer.size() - client.uring_out_offset,
        MSG_NOSIGNAL);
    if (wr > 0) {
      client.uring_out_offset += static_cast<std::size_t>(wr);
      continue;
    }
    if (wr < 0 && (errno == EINTR)) {
      continue;
    }
    if (wr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      break;  // socket buffer full; retry on next wakeup
    }
    ctx.transport_error = 1;
    return false;
  }
  if (client.uring_out_offset >= client.uring_out_buffer.size()) {
    client.uring_out_buffer.clear();
    client.uring_out_offset = 0;
  }
  return true;
}

// Shared post-I/O finalize: error teardown, GOAWAY drain, idle bookkeeping.
// Returns true when the session was torn down (caller must stop touching it).
bool h2_finalize_session_io(
    NativeRuntime& runtime,
    const Profile& profile,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client) {
  H2ConnectionContext& ctx = client.ctx;
  const long long now_ms = monotonic_ms_now();
  if (ctx.transport_error || ctx.protocol_error) {
    const int outstanding =
        static_cast<int>(client.pending_requests.size() + ctx.active_streams.size());
    ctx.failed_streams += outstanding;
    ctx.expectation_failures += outstanding;
    client.pending_requests.clear();
    client.consecutive_failures += 1;
    client.unhealthy_until_ms = now_ms + std::max(1, profile.timeout_ms / 4);
    shard.connection_pool.active_connections =
        std::max(0, shard.connection_pool.active_connections - 1);
    if (!is_custom_tcp_backend(ctx.transport_backend) && client.ctx.fd >= 0) {
      unregister_lane_fd(shard, local_shard, client.ctx.fd);
    }
    unregister_custom_tcp_h2_flow_binding(runtime, client);
    close_h2_client_session(client);
    local_shard.dispatch_ready_ms = client.unhealthy_until_ms;
    return true;
  }
  if (ctx.goaway > 0 && ctx.active_streams.empty()) {
    client.drain_evictions += 1;
    client.replacement_mode = H2LaneReplacementMode::ReplaceNow;
    requeue_h2_pending_front(local_shard, client);
    shard.connection_pool.active_connections =
        std::max(0, shard.connection_pool.active_connections - 1);
    if (!is_custom_tcp_backend(ctx.transport_backend) && client.ctx.fd >= 0) {
      unregister_lane_fd(shard, local_shard, client.ctx.fd);
    }
    unregister_custom_tcp_h2_flow_binding(runtime, client);
    close_h2_client_session(client);
    local_shard.dispatch_ready_ms = now_ms;
    return true;
  }
  client.idle_deadline_ms = now_ms + std::max(1, profile.timeout_ms);
  if (!client.pending_requests.empty() || !ctx.active_streams.empty()) {
    client.dispatch_ready_ms = now_ms;
  } else {
    client.dispatch_ready_ms = now_ms;
    client.active_since_ms = 0;
  }
  return false;
}

void service_h2_session_io(
    NativeRuntime& runtime,
    const Profile& profile,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    H2ClientSession& client,
    uint32_t events,
    bool allow_read_without_event) {
  if (!client.ready || client.ctx.fd < 0 || client.session == nullptr) {
    return;
  }

  H2ConnectionContext& ctx = client.ctx;
  ctx.epoll_fd = shard.epoll_fd;

  // Submit new requests and serialize all pending output onto the wire buffer
  // (TLS handshake is advanced inside the pump). Then drain that buffer to the
  // kernel socket; custom-tcp routes through tcpdp inside the pump itself.
  h2_pull_pending_requests(local_shard, client, profile);
  if (ctx.protocol_error == 0 && ctx.transport_error == 0) {
    h2_pump_outbound(client);
  }
  if (ctx.transport_error == 0 && !ctx.ktls_mode) {
    if (is_custom_tcp_backend(ctx.transport_backend)) {
      h2_flush_out_buffer_tcpdp(client);
    } else {
      h2_flush_out_buffer_syscall(client);
    }
  }

  // Read inbound bytes and feed nghttp2. For custom-tcp, ctx.read_buffer is
  // already populated by the tcpdp rx handler; for kernel sockets we pull it
  // here with non-blocking recv(). A handshake still in flight also needs to
  // read even before any stream is open.
  const bool want_read =
      ((events & (EPOLLIN | EPOLLERR | EPOLLHUP)) != 0) ||
      (allow_read_without_event &&
       (!ctx.active_streams.empty() || (ctx.use_tls && !ctx.tls_handshake_complete) ||
        is_custom_tcp_backend(ctx.transport_backend)));
  if (ctx.protocol_error == 0 && ctx.transport_error == 0 && want_read) {
    // kTLS sessions let SSL_read pull straight from the fd (kernel decrypts and
    // handles control records), so no raw recv() here -- that would steal bytes.
    if (!is_custom_tcp_backend(ctx.transport_backend) && !ctx.ktls_mode) {
      unsigned char rb[16384];
      while (true) {
        const ssize_t rd = ::recv(ctx.fd, rb, sizeof(rb), 0);
        if (rd > 0) {
          ctx.read_buffer.append(reinterpret_cast<const char*>(rb), static_cast<std::size_t>(rd));
          continue;
        }
        if (rd == 0) {
          if (!ctx.active_streams.empty()) {
            ctx.transport_error = 1;
          }
          break;
        }
        if (errno == EINTR) {
          continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        }
        ctx.transport_error = 1;
        break;
      }
    }
    if (ctx.transport_error == 0) {
      h2_ingest_inbound(client);
    }
    // Inbound frames (settings, window updates, responses) may have queued more
    // output; flush it before finalizing.
    if (ctx.protocol_error == 0 && ctx.transport_error == 0) {
      h2_pump_outbound(client);
      if (ctx.transport_error == 0 && !ctx.ktls_mode) {
        if (is_custom_tcp_backend(ctx.transport_backend)) {
          h2_flush_out_buffer_tcpdp(client);
        } else {
          h2_flush_out_buffer_syscall(client);
        }
      }
    }
  }

  h2_finalize_session_io(runtime, profile, shard, local_shard, client);
}

#endif  // SAMURAI_WITH_NGHTTP2

}  // namespace ddos_samurai::l7_emu_native
