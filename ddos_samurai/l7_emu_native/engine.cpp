#include "engine.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef SAMURAI_WITH_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

#ifdef SAMURAI_WITH_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

namespace ddos_samurai::l7_emu_native {

namespace {

struct ResponseInfo {
  int status_code{0};
  std::size_t bytes_received{0};
  std::string raw;
  std::map<std::string, std::string> headers;
  std::string body;
  bool keep_alive{false};
  std::size_t consumed_bytes{0};
};

#ifdef SAMURAI_WITH_NGHTTP2
struct H2ClientSession;
#endif

struct Http1Connection {
  int fd{-1};
  int shard_id{0};
  std::string read_buffer;
  long long idle_deadline_ms{0};
  std::size_t timer_slot{0};
  std::uint64_t timer_generation{0};
  bool timer_armed{false};
};

struct NativeRuntime {
  RuntimeCapabilities caps{};
  std::vector<ShardState> shards{};
  std::deque<std::size_t> ready_shards{};
  struct LocalShard {
    struct TimerEntry {
      Http1Connection* conn{nullptr};
      std::uint64_t generation{0};
    };
    std::vector<std::unique_ptr<Http1Connection>> http1_idle{};
    std::vector<Http1Connection*> http1_active{};
    std::vector<std::vector<TimerEntry>> timer_slots{};
    long long last_timer_tick_ms{0};
    long long dispatch_ready_ms{0};
    bool in_ready_queue{false};
#ifdef SAMURAI_WITH_NGHTTP2
    std::vector<std::unique_ptr<H2ClientSession>> h2_sessions{};
#endif
  };
  std::vector<LocalShard> local_shards{};
};

struct H1RequestSpec {
  FlowOp send_headers{};
  std::optional<FlowOp> body_op{};
  std::vector<FlowOp> follow_ops{};
};

struct H2RequestSpec {
  std::string method{"GET"};
  std::string path{"/"};
  std::map<std::string, std::string> headers{};
  std::string body{};
  std::vector<FlowOp> follow_ops{};
};

struct H2RunStats {
  int attempted{0};
  int sent{0};
  int errors{0};
  int conn_attempted{0};
  int conn_established{0};
  int conn_reused{0};
  int expectation_failures{0};
  int status_2xx{0};
  int status_3xx{0};
  int status_4xx{0};
  int status_5xx{0};
  int scheduler_backpressure{0};
  int goaway_count{0};
  int rst_stream_count{0};
  std::size_t rx_bytes{0};
  std::size_t tx_bytes{0};
};

std::string lower_copy(const std::string& in);

#ifdef SAMURAI_WITH_NGHTTP2
struct H2StreamState {
  std::string request_method;
  std::string request_path;
  std::map<std::string, std::string> request_headers;
  std::string outbound_body;
  std::size_t outbound_offset{0};
  int status_code{0};
  std::map<std::string, std::string> response_headers;
  std::string response_body;
  std::vector<FlowOp> follow_ops;
  bool completed{false};
};

struct H2ConnectionContext {
  int fd{-1};
  int epoll_fd{-1};
  bool use_tls{false};
  bool verify_peer{true};
  std::string authority;
  int timeout_ms{5000};
  int transport_error{0};
  int protocol_error{0};
  int goaway{0};
  int rst_stream{0};
  int expectation_failures{0};
  int status_2xx{0};
  int status_3xx{0};
  int status_4xx{0};
  int status_5xx{0};
  int completed_success{0};
  int failed_streams{0};
  int max_think_time_ms{0};
  std::size_t bytes_sent{0};
  std::size_t bytes_received{0};
  std::map<std::string, std::string>* captures{nullptr};
  std::map<int32_t, std::unique_ptr<H2StreamState>> active_streams;
#ifdef SAMURAI_WITH_OPENSSL
  SSL_CTX* tls_ctx{nullptr};
  SSL* ssl{nullptr};
#endif
};

struct H2ClientSession {
  H2ConnectionContext ctx{};
  nghttp2_session_callbacks* callbacks{nullptr};
  nghttp2_session* session{nullptr};
  bool ready{false};
  long long idle_deadline_ms{0};
  long long unhealthy_until_ms{0};
  long long dispatch_ready_ms{0};
  int consecutive_failures{0};
};

void cleanup_tls(H2ConnectionContext& ctx);
void close_h2_client_session(H2ClientSession& client);
#endif

int connect_socket(const Profile& profile) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }

  struct timeval tv {};
  tv.tv_sec = static_cast<long>(profile.timeout_ms / 1000);
  tv.tv_usec = static_cast<long>((profile.timeout_ms % 1000) * 1000);
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  const int one = 1;
  ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(profile.target_port));
  if (::inet_pton(AF_INET, profile.target_ip.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    return -1;
  }
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return -1;
  }
  const int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags >= 0) {
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  }
  return fd;
}

long long monotonic_ms_now() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

bool wait_for_fd(int epoll_fd, int fd, uint32_t events, int timeout_ms) {
  if (epoll_fd < 0 || fd < 0) {
    return false;
  }
  epoll_event ev {};
  ev.events = events;
  ev.data.fd = fd;
  if (::epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) != 0) {
    if (::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
      return false;
    }
  }
  epoll_event out {};
  const int rc = ::epoll_wait(epoll_fd, &out, 1, timeout_ms);
  if (rc <= 0) {
    return false;
  }
  return (out.events & events) != 0 || (out.events & (EPOLLERR | EPOLLHUP)) != 0;
}

bool send_all(int epoll_fd, int fd, const std::string& data, int timeout_ms) {
  const char* ptr = data.data();
  std::size_t remaining = data.size();
  while (remaining > 0) {
    const ssize_t sent = ::send(fd, ptr, remaining, MSG_NOSIGNAL);
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (!wait_for_fd(epoll_fd, fd, EPOLLOUT, timeout_ms)) {
        return false;
      }
      continue;
    }
    if (sent <= 0) {
      return false;
    }
    ptr += sent;
    remaining -= static_cast<std::size_t>(sent);
  }
  return true;
}

bool recv_into_buffer(int epoll_fd, int fd, std::string& buffer, std::size_t& rx_bytes, int timeout_ms) {
  char tmp[8192];
  while (true) {
    const ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
    if (n > 0) {
      buffer.append(tmp, static_cast<std::size_t>(n));
      rx_bytes += static_cast<std::size_t>(n);
      return true;
    }
    if (n == 0) {
      return false;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      if (!wait_for_fd(epoll_fd, fd, EPOLLIN, timeout_ms)) {
        return false;
      }
      continue;
    }
    return false;
  }
}

std::optional<std::size_t> parse_chunked_body_length(const std::string& payload, std::size_t body_offset) {
  std::size_t cursor = body_offset;
  while (true) {
    const std::size_t line_end = payload.find("\r\n", cursor);
    if (line_end == std::string::npos) {
      return std::nullopt;
    }
    const std::string size_line = payload.substr(cursor, line_end - cursor);
    char* end_ptr = nullptr;
    const unsigned long chunk_size = std::strtoul(size_line.c_str(), &end_ptr, 16);
    if (end_ptr == size_line.c_str()) {
      return std::nullopt;
    }
    cursor = line_end + 2;
    if (payload.size() < cursor + chunk_size + 2) {
      return std::nullopt;
    }
    cursor += chunk_size;
    if (payload.compare(cursor, 2, "\r\n") != 0) {
      return std::nullopt;
    }
    cursor += 2;
    if (chunk_size == 0) {
      if (payload.size() < cursor + 2) {
        return std::nullopt;
      }
      return cursor + 2 - body_offset;
    }
  }
}

ResponseInfo read_response(
    int epoll_fd,
    Http1Connection& conn,
    int timeout_ms) {
  ResponseInfo info;

  while (conn.read_buffer.find("\r\n\r\n") == std::string::npos) {
    if (!recv_into_buffer(epoll_fd, conn.fd, conn.read_buffer, info.bytes_received, timeout_ms)) {
      return info;
    }
  }

  const std::size_t header_end = conn.read_buffer.find("\r\n\r\n");
  info.raw = conn.read_buffer.substr(0, header_end + 4);
  const std::size_t line_end = info.raw.find("\r\n");
  if (line_end != std::string::npos) {
    const std::string status_line = info.raw.substr(0, line_end);
    std::istringstream iss(status_line);
    std::string version;
    iss >> version;
    iss >> info.status_code;
  }
  if (header_end != std::string::npos) {
    std::size_t pos = line_end == std::string::npos ? 0 : line_end + 2;
    while (pos < header_end) {
      const std::size_t next = conn.read_buffer.find("\r\n", pos);
      if (next == std::string::npos || next > header_end) {
        break;
      }
      const std::string line = conn.read_buffer.substr(pos, next - pos);
      const std::size_t colon = line.find(':');
      if (colon != std::string::npos) {
        std::string key = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
          value.erase(value.begin());
        }
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
          return static_cast<char>(std::tolower(c));
        });
        info.headers[key] = value;
      }
      pos = next + 2;
    }
  }

  const std::size_t body_offset = header_end + 4;
  std::size_t body_length = 0;
  bool needs_socket_close = false;
  const auto content_length_it = info.headers.find("content-length");
  const auto transfer_encoding_it = info.headers.find("transfer-encoding");
  if (transfer_encoding_it != info.headers.end() &&
      lower_copy(transfer_encoding_it->second).find("chunked") != std::string::npos) {
    while (true) {
      const auto parsed = parse_chunked_body_length(conn.read_buffer, body_offset);
      if (parsed.has_value()) {
        body_length = *parsed;
        break;
      }
      if (!recv_into_buffer(epoll_fd, conn.fd, conn.read_buffer, info.bytes_received, timeout_ms)) {
        return info;
      }
    }
  } else if (content_length_it != info.headers.end()) {
    body_length = static_cast<std::size_t>(std::max(0, std::atoi(content_length_it->second.c_str())));
    while (conn.read_buffer.size() < body_offset + body_length) {
      if (!recv_into_buffer(epoll_fd, conn.fd, conn.read_buffer, info.bytes_received, timeout_ms)) {
        return info;
      }
    }
  } else if ((info.status_code >= 100 && info.status_code < 200) || info.status_code == 204 ||
             info.status_code == 304) {
    body_length = 0;
  } else {
    needs_socket_close = true;
    while (recv_into_buffer(epoll_fd, conn.fd, conn.read_buffer, info.bytes_received, timeout_ms)) {
    }
    body_length = conn.read_buffer.size() - body_offset;
  }

  info.body = conn.read_buffer.substr(body_offset, body_length);
  info.consumed_bytes = body_offset + body_length;
  const std::string connection_header =
      lower_copy(info.headers.count("connection") ? info.headers.at("connection") : "");
  info.keep_alive = !needs_socket_close && connection_header != "close";
  if (info.consumed_bytes <= conn.read_buffer.size()) {
    conn.read_buffer.erase(0, info.consumed_bytes);
  } else {
    conn.read_buffer.clear();
  }
  return info;
}

std::string lower_copy(const std::string& in) {
  std::string out = in;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

std::string replace_all(
    std::string input,
    const std::string& needle,
    const std::string& replacement) {
  if (needle.empty()) {
    return input;
  }
  std::size_t pos = 0;
  while ((pos = input.find(needle, pos)) != std::string::npos) {
    input.replace(pos, needle.size(), replacement);
    pos += replacement.size();
  }
  return input;
}

std::string apply_captures(
    const std::string& input,
    const std::map<std::string, std::string>& captures) {
  std::string out = input;
  for (const auto& [key, value] : captures) {
    out = replace_all(out, "{{capture:" + key + "}}", value);
    out = replace_all(out, "{{header:" + key + "}}", value);
    out = replace_all(out, "{{cookie:" + key + "}}", value);
  }
  return out;
}

std::string build_http1_request(
    const Profile& profile,
    const FlowOp& send_headers,
    const FlowOp* send_body,
    const std::map<std::string, std::string>& captures) {
  std::ostringstream out;
  out << apply_captures(send_headers.method.empty() ? "GET" : send_headers.method, captures) << " "
      << apply_captures(send_headers.path.empty() ? "/" : send_headers.path, captures) << " HTTP/1.1\r\n";
  out << "Host: " << (profile.host_header.empty() ? profile.target_ip : profile.host_header) << "\r\n";
  out << "Connection: " << (profile.keepalive ? "keep-alive" : "close") << "\r\n";
  bool has_content_length = false;
  for (const auto& [key, value] : send_headers.headers) {
    if (key == "Content-Length" || key == "content-length") {
      has_content_length = true;
    }
    out << key << ": " << apply_captures(value, captures) << "\r\n";
  }
  if (send_body != nullptr && !send_body->body.empty() && !has_content_length) {
    out << "Content-Length: " << send_body->body.size() << "\r\n";
  }
  out << "\r\n";
  if (send_body != nullptr && !send_body->body.empty()) {
    const std::string body = apply_captures(
        std::string(reinterpret_cast<const char*>(send_body->body.data()), send_body->body.size()),
        captures);
    out.write(body.data(), static_cast<std::streamsize>(body.size()));
  }
  return out.str();
}

void init_stats(const Profile& profile, std::map<std::string, double>& out) {
  out["attempted"] = static_cast<double>(profile.flow_attempted);
  out["sent"] = 0.0;
  out["errors"] = static_cast<double>(profile.flow_attempted);
  out["responses_total"] = 0.0;
  out["status_2xx"] = 0.0;
  out["status_3xx"] = 0.0;
  out["status_4xx"] = 0.0;
  out["status_5xx"] = 0.0;
  out["l7_flow_attempted"] = static_cast<double>(profile.flow_attempted);
  out["l7_flow_completed"] = 0.0;
  out["l7_conn_attempted"] = 0.0;
  out["l7_conn_established"] = 0.0;
  out["l7_conn_reused"] = 0.0;
  out["l7_rx_bytes"] = 0.0;
  out["l7_tx_bytes"] = 0.0;
  out["l7_expectation_failures"] = 0.0;
  out["l7_scheduler_backpressure_count"] = 0.0;
  out["h2_goaway_count"] = 0.0;
  out["h2_stream_reset_ratio"] = 0.0;
  out["h2_native_capability_available"] = 0.0;
  out["runtime_shards"] = 0.0;
}

std::map<std::string, double> fail_visible_stats(
    const Profile& profile,
    const RuntimeCapabilities& caps,
    const std::string& reason) {
  (void)reason;
  std::map<std::string, double> out;
  init_stats(profile, out);
  out["attempted"] = static_cast<double>(profile.flow_attempted);
  out["sent"] = 0.0;
  out["errors"] = static_cast<double>(profile.flow_attempted);
  out["l7_flow_attempted"] = static_cast<double>(profile.flow_attempted);
  out["l7_flow_completed"] = 0.0;
  out["l7_expectation_failures"] = static_cast<double>(profile.flow_attempted);
  out["h2_native_capability_available"] = (caps.openssl && caps.nghttp2) ? 1.0 : 0.0;
  return out;
}

NativeRuntime build_runtime(const Profile& profile, const RuntimeConfig& cfg) {
  NativeRuntime runtime;
  runtime.caps = detect_capabilities();
  const int shard_count = std::max(1, std::min(cfg.concurrency, profile.max_connections));
  runtime.shards.reserve(static_cast<std::size_t>(shard_count));
  runtime.local_shards.reserve(static_cast<std::size_t>(shard_count));
  for (int i = 0; i < shard_count; ++i) {
    ShardState shard;
    shard.shard_id = i;
    shard.epoll_fd = ::epoll_create1(EPOLL_CLOEXEC);
    shard.timer_wheel.slot_count = 1024;
    shard.timer_wheel.active_timers = 0;
    shard.connection_pool.max_connections = std::max(1, profile.max_connections / shard_count);
    shard.connection_pool.active_connections = 0;
    shard.connection_pool.reused_connections = 0;
    runtime.shards.push_back(shard);
    NativeRuntime::LocalShard local;
    local.timer_slots.resize(shard.timer_wheel.slot_count);
    local.last_timer_tick_ms = monotonic_ms_now();
    local.dispatch_ready_ms = local.last_timer_tick_ms;
    runtime.local_shards.push_back(std::move(local));
  }
  return runtime;
}

void destroy_runtime(NativeRuntime& runtime) {
#ifdef SAMURAI_WITH_NGHTTP2
  for (auto& local_shard : runtime.local_shards) {
    for (auto& session : local_shard.h2_sessions) {
      if (!session) {
        continue;
      }
      if (session->session != nullptr) {
        nghttp2_session_del(session->session);
        session->session = nullptr;
      }
      if (session->callbacks != nullptr) {
        nghttp2_session_callbacks_del(session->callbacks);
        session->callbacks = nullptr;
      }
      cleanup_tls(session->ctx);
      if (session->ctx.fd >= 0) {
        ::close(session->ctx.fd);
        session->ctx.fd = -1;
      }
      session->ready = false;
    }
  }
#endif
  for (auto& shard : runtime.shards) {
    if (shard.epoll_fd >= 0) {
      ::close(shard.epoll_fd);
      shard.epoll_fd = -1;
    }
  }
}

void enqueue_ready_shard(NativeRuntime& runtime, std::size_t shard_idx) {
  if (shard_idx >= runtime.local_shards.size()) {
    return;
  }
  auto& local_shard = runtime.local_shards[shard_idx];
  if (local_shard.in_ready_queue || local_shard.dispatch_ready_ms > monotonic_ms_now()) {
    return;
  }
  runtime.ready_shards.push_back(shard_idx);
  local_shard.in_ready_queue = true;
}

void refresh_ready_queue(NativeRuntime& runtime) {
  const long long now_ms = monotonic_ms_now();
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    if (runtime.local_shards[shard_idx].dispatch_ready_ms <= now_ms) {
      enqueue_ready_shard(runtime, shard_idx);
    }
  }
}

std::optional<std::size_t> pop_ready_shard(NativeRuntime& runtime) {
  refresh_ready_queue(runtime);
  if (runtime.ready_shards.empty()) {
    return std::nullopt;
  }
  const std::size_t shard_idx = runtime.ready_shards.front();
  runtime.ready_shards.pop_front();
  runtime.local_shards[shard_idx].in_ready_queue = false;
  return shard_idx;
}

void erase_active_http1(NativeRuntime::LocalShard& local_shard, Http1Connection* conn) {
  local_shard.http1_active.erase(
      std::remove(local_shard.http1_active.begin(), local_shard.http1_active.end(), conn),
      local_shard.http1_active.end());
}

void close_http1_connection(
    std::unique_ptr<Http1Connection>& conn,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard) {
  if (!conn) {
    return;
  }
  erase_active_http1(local_shard, conn.get());
  if (conn->fd >= 0) {
    ::close(conn->fd);
    conn->fd = -1;
  }
  conn->read_buffer.clear();
  if (conn->timer_armed && shard.timer_wheel.active_timers > 0) {
    shard.timer_wheel.active_timers -= 1;
  }
  conn->timer_armed = false;
  shard.connection_pool.active_connections =
      std::max(0, shard.connection_pool.active_connections - 1);
}

void schedule_http1_idle(
    Http1Connection& conn,
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard,
    int timeout_ms) {
  const long long now_ms = monotonic_ms_now();
  conn.idle_deadline_ms = now_ms + std::max(1, timeout_ms);
  conn.timer_slot = static_cast<std::size_t>(conn.idle_deadline_ms % static_cast<long long>(shard.timer_wheel.slot_count));
  conn.timer_generation += 1;
  conn.timer_armed = true;
  local_shard.timer_slots[conn.timer_slot].push_back({&conn, conn.timer_generation});
  shard.timer_wheel.active_timers += 1;
}

void expire_http1_idle(
    ShardState& shard,
    NativeRuntime::LocalShard& local_shard) {
  if (local_shard.timer_slots.empty()) {
    return;
  }
  const long long now_ms = monotonic_ms_now();
  const long long start_tick = local_shard.last_timer_tick_ms;
  const long long slot_count = static_cast<long long>(shard.timer_wheel.slot_count);
  if (now_ms < start_tick) {
    return;
  }
  const long long tick_span = std::min(now_ms - start_tick + 1, slot_count);
  for (long long delta = 0; delta < tick_span; ++delta) {
    const std::size_t slot = static_cast<std::size_t>((start_tick + delta) % slot_count);
    auto& bucket = local_shard.timer_slots[slot];
    for (const auto& entry : bucket) {
      Http1Connection* conn_ptr = entry.conn;
      if (conn_ptr == nullptr || !conn_ptr->timer_armed ||
          conn_ptr->timer_generation != entry.generation ||
          conn_ptr->idle_deadline_ms > now_ms) {
        continue;
      }
      for (auto it = local_shard.http1_idle.begin(); it != local_shard.http1_idle.end(); ++it) {
        if (it->get() == conn_ptr) {
          close_http1_connection(*it, shard, local_shard);
          local_shard.http1_idle.erase(it);
          break;
        }
      }
      if (shard.timer_wheel.active_timers > 0) {
        shard.timer_wheel.active_timers -= 1;
      }
    }
    bucket.clear();
  }
  local_shard.last_timer_tick_ms = now_ms;
}

void expire_all_http1_idle(NativeRuntime& runtime) {
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    expire_http1_idle(runtime.shards[shard_idx], runtime.local_shards[shard_idx]);
  }
}

#ifdef SAMURAI_WITH_NGHTTP2
void expire_h2_idle(
    const Profile& profile,
    NativeRuntime::LocalShard& local_shard) {
  const long long now_ms = monotonic_ms_now();
  for (auto& session : local_shard.h2_sessions) {
    if (!session) {
      continue;
    }
    if (session->ready && session->idle_deadline_ms > 0 && session->idle_deadline_ms <= now_ms) {
      close_h2_client_session(*session);
    }
    if (session->unhealthy_until_ms > now_ms && local_shard.dispatch_ready_ms < session->unhealthy_until_ms) {
      local_shard.dispatch_ready_ms = session->unhealthy_until_ms;
    }
  }
  (void)profile;
}
#endif

void expire_all_lane_idle(NativeRuntime& runtime, const Profile& profile) {
  expire_all_http1_idle(runtime);
#ifdef SAMURAI_WITH_NGHTTP2
  for (auto& local_shard : runtime.local_shards) {
    expire_h2_idle(profile, local_shard);
  }
#else
  (void)profile;
#endif
}

void advance_runtime_until(NativeRuntime& runtime, const Profile& profile, long long deadline_ms) {
  const int slice_ms = 32;
  while (true) {
    expire_all_lane_idle(runtime, profile);
    refresh_ready_queue(runtime);
    const long long now_ms = monotonic_ms_now();
    if (now_ms >= deadline_ms) {
      break;
    }
    const long long remaining_ms = deadline_ms - now_ms;
    const int step_ms = static_cast<int>(std::min<long long>(remaining_ms, slice_ms));
    std::this_thread::sleep_for(std::chrono::milliseconds(std::max(1, step_ms)));
  }
}

std::vector<H1RequestSpec> build_h1_requests(const Profile& profile) {
  std::vector<H1RequestSpec> requests;
  for (std::size_t idx = 0; idx < profile.ops.size(); ++idx) {
    const FlowOp& op = profile.ops[idx];
    if (op.opcode != "SEND_HEADERS") {
      continue;
    }
    H1RequestSpec spec;
    spec.send_headers = op;
    std::size_t j = idx + 1;
    if (j < profile.ops.size() && profile.ops[j].opcode == "SEND_BODY") {
      spec.body_op = profile.ops[j];
      ++j;
    }
    while (j < profile.ops.size()) {
      const FlowOp& follow = profile.ops[j];
      if (follow.opcode == "SEND_HEADERS" || follow.opcode == "CONNECT" || follow.opcode == "CLOSE") {
        break;
      }
      spec.follow_ops.push_back(follow);
      ++j;
    }
    requests.push_back(std::move(spec));
  }
  return requests;
}

std::vector<std::vector<H1RequestSpec>> bucket_h1_requests_by_shard(
    const std::vector<H1RequestSpec>& requests,
    std::size_t shard_count) {
  const std::size_t count = std::max<std::size_t>(1, shard_count);
  std::vector<std::vector<H1RequestSpec>> buckets(count);
  for (std::size_t i = 0; i < requests.size(); ++i) {
    buckets[i % count].push_back(requests[i]);
  }
  return buckets;
}

std::vector<H2RequestSpec> build_h2_requests(const Profile& profile) {
  std::vector<H2RequestSpec> requests;
  for (const H1RequestSpec& h1_spec : build_h1_requests(profile)) {
    H2RequestSpec spec;
    spec.method = h1_spec.send_headers.method.empty() ? "GET" : h1_spec.send_headers.method;
    spec.path = h1_spec.send_headers.path.empty() ? "/" : h1_spec.send_headers.path;
    spec.headers = h1_spec.send_headers.headers;
    if (h1_spec.body_op.has_value()) {
      spec.body.assign(
          reinterpret_cast<const char*>(h1_spec.body_op->body.data()),
          h1_spec.body_op->body.size());
    }
    spec.follow_ops = h1_spec.follow_ops;
    requests.push_back(std::move(spec));
  }
  return requests;
}

void capture_cookie(
    const std::string& cookie_line,
    const std::string& capture_name,
    std::map<std::string, std::string>& captures) {
  const std::size_t sep = cookie_line.find(';');
  const std::string cookie = cookie_line.substr(0, sep);
  const std::size_t eq = cookie.find('=');
  if (eq != std::string::npos) {
    captures[cookie.substr(0, eq)] = cookie.substr(eq + 1);
  } else if (!capture_name.empty()) {
    captures[capture_name] = cookie;
  } else {
    captures["set-cookie"] = cookie;
  }
}

void evaluate_response_ops(
    const std::vector<FlowOp>& follow_ops,
    int status_code,
    const std::map<std::string, std::string>& headers,
    const std::string& body,
    std::map<std::string, std::string>& captures,
    int& expectation_failures,
    int& think_time_total_ms) {
  for (const FlowOp& follow : follow_ops) {
    if (follow.opcode == "EXPECT_STATUS" && follow.has_expect) {
      if (status_code < follow.expect.status_min || status_code > follow.expect.status_max) {
        expectation_failures += 1;
      }
      continue;
    }
    if (follow.opcode == "EXPECT_HEADER" && follow.has_expect) {
      const std::string key = lower_copy(follow.expect.name);
      const auto it = headers.find(key);
      if (it == headers.end() || it->second.find(follow.expect.value) == std::string::npos) {
        expectation_failures += 1;
      }
      continue;
    }
    if (follow.opcode == "EXPECT_BODY_SUBSTRING" && follow.has_expect) {
      if (body.find(follow.expect.value) == std::string::npos) {
        expectation_failures += 1;
      }
      continue;
    }
    if (follow.opcode == "CAPTURE_HEADER") {
      const std::string source = lower_copy(
          follow.capture_source.empty() ? follow.capture_name : follow.capture_source);
      const auto it = headers.find(source);
      if (it != headers.end()) {
        captures[follow.capture_name.empty() ? source : follow.capture_name] = it->second;
      }
      continue;
    }
    if (follow.opcode == "CAPTURE_COOKIE") {
      const auto it = headers.find("set-cookie");
      if (it != headers.end()) {
        capture_cookie(it->second, follow.capture_name, captures);
      }
      continue;
    }
    if (follow.opcode == "THINK_TIME") {
      think_time_total_ms += std::max(0, follow.think_time_ms);
    }
  }
}

#ifdef SAMURAI_WITH_NGHTTP2
std::vector<std::vector<H2RequestSpec>> bucket_h2_requests_by_shard(
    const std::vector<H2RequestSpec>& requests,
    std::size_t shard_count) {
  const std::size_t count = std::max<std::size_t>(1, shard_count);
  std::vector<std::vector<H2RequestSpec>> buckets(count);
  for (std::size_t i = 0; i < requests.size(); ++i) {
    buckets[i % count].push_back(requests[i]);
  }
  return buckets;
}

std::vector<std::vector<H2RequestSpec>> bucket_h2_requests_by_connection(
    const std::vector<H2RequestSpec>& requests,
    std::size_t connection_count) {
  const std::size_t count = std::max<std::size_t>(1, connection_count);
  std::vector<std::vector<H2RequestSpec>> buckets(count);
  for (std::size_t i = 0; i < requests.size(); ++i) {
    buckets[i % count].push_back(requests[i]);
  }
  return buckets;
}

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
    if (ctx->use_tls) {
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
    auto existing = stream.response_headers.find(key);
    if (existing == stream.response_headers.end()) {
      stream.response_headers.emplace(key, val);
    } else {
      existing->second.append("\n");
      existing->second.append(val);
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
  if (error_code != NGHTTP2_NO_ERROR) {
    ctx->protocol_error = 1;
    ctx->rst_stream += 1;
    ctx->expectation_failures += 1;
    ctx->failed_streams += 1;
  } else {
    int think_time_total_ms = 0;
    evaluate_response_ops(
        stream.follow_ops,
        stream.status_code,
        stream.response_headers,
        stream.response_body,
        *ctx->captures,
        ctx->expectation_failures,
        think_time_total_ms);
    ctx->max_think_time_ms = std::max(ctx->max_think_time_ms, think_time_total_ms);
    if (stream.status_code > 0) {
      if (stream.status_code >= 200 && stream.status_code <= 299) {
        ctx->status_2xx += 1;
      } else if (stream.status_code >= 300 && stream.status_code <= 399) {
        ctx->status_3xx += 1;
      } else if (stream.status_code >= 400 && stream.status_code <= 499) {
        ctx->status_4xx += 1;
      } else if (stream.status_code >= 500 && stream.status_code <= 599) {
        ctx->status_5xx += 1;
      }
      ctx->completed_success += 1;
    } else {
      ctx->failed_streams += 1;
      ctx->expectation_failures += 1;
    }
  }
  ctx->active_streams.erase(it);
  return 0;
}

ssize_t h2_socket_read(H2ConnectionContext& ctx, unsigned char* buf, size_t cap) {
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
  SSL_CTX_set_alpn_protos(
      ctx.tls_ctx,
      reinterpret_cast<const unsigned char*>("\x02h2"),
      3);
  SSL_CTX_set_verify(ctx.tls_ctx, profile.verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
  ctx.ssl = SSL_new(ctx.tls_ctx);
  if (ctx.ssl == nullptr) {
    return false;
  }
  if (SSL_set_fd(ctx.ssl, ctx.fd) != 1) {
    return false;
  }
  if (!profile.host_header.empty()) {
    SSL_set_tlsext_host_name(ctx.ssl, profile.host_header.c_str());
  }
  if (SSL_connect(ctx.ssl) != 1) {
    return false;
  }
  const unsigned char* alpn = nullptr;
  unsigned int alpn_len = 0;
  SSL_get0_alpn_selected(ctx.ssl, &alpn, &alpn_len);
  return alpn != nullptr && alpn_len == 2 && std::memcmp(alpn, "h2", 2) == 0;
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
#else
  (void)ctx;
#endif
}

bool submit_h2_request(
    nghttp2_session* session,
    H2ConnectionContext& ctx,
    const Profile& profile,
    const H2RequestSpec& raw_request,
    const std::map<std::string, std::string>& captures) {
  auto stream = std::make_unique<H2StreamState>();
  stream->request_method = apply_captures(raw_request.method, captures);
  stream->request_path = apply_captures(raw_request.path, captures);
  stream->request_headers = raw_request.headers;
  for (auto& [key, value] : stream->request_headers) {
    value = apply_captures(value, captures);
  }
  stream->outbound_body = apply_captures(raw_request.body, captures);
  stream->follow_ops = raw_request.follow_ops;

  std::vector<nghttp2_nv> hdrs;
  hdrs.reserve(4 + stream->request_headers.size());
  auto add_header = [&hdrs](const std::string& key, const std::string& value) {
    nghttp2_nv nv {};
    nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(key.data()));
    nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data()));
    nv.namelen = key.size();
    nv.valuelen = value.size();
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    hdrs.push_back(nv);
  };

  add_header(":method", stream->request_method.empty() ? "GET" : stream->request_method);
  add_header(":scheme", profile.scheme.empty() ? (ctx.use_tls ? "https" : "http") : profile.scheme);
  add_header(":authority", ctx.authority);
  add_header(":path", stream->request_path.empty() ? "/" : stream->request_path);
  for (const auto& [key, value] : stream->request_headers) {
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
      nghttp2_submit_request(session, nullptr, hdrs.data(), hdrs.size(), provider_ptr, stream.get());
  if (stream_id < 0) {
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
  if (client.ctx.fd >= 0) {
    ::close(client.ctx.fd);
    client.ctx.fd = -1;
  }
  client.ctx.active_streams.clear();
  client.ready = false;
  client.idle_deadline_ms = 0;
  client.dispatch_ready_ms = monotonic_ms_now();
}

bool open_h2_client_session(
    const Profile& profile,
    int epoll_fd,
    H2ClientSession& client,
    H2RunStats& stats,
    std::size_t request_count) {
  close_h2_client_session(client);
  client.ctx = H2ConnectionContext{};
  client.ctx.epoll_fd = epoll_fd;
  client.ctx.use_tls = profile.scheme == "https";
  client.ctx.verify_peer = profile.verify != 0;
  client.ctx.timeout_ms = profile.timeout_ms;
  client.ctx.authority = profile.host_header.empty() ? profile.target_ip : profile.host_header;
  if (client.ctx.authority.find(':') == std::string::npos && profile.target_port > 0) {
    client.ctx.authority += ":" + std::to_string(profile.target_port);
  }

  stats.conn_attempted += 1;
  client.ctx.fd = connect_socket(profile);
  if (client.ctx.fd < 0) {
    stats.errors += static_cast<int>(request_count);
    stats.expectation_failures += static_cast<int>(request_count);
    return false;
  }
  if (!setup_tls(client.ctx, profile)) {
    cleanup_tls(client.ctx);
    ::close(client.ctx.fd);
    client.ctx.fd = -1;
    stats.errors += static_cast<int>(request_count);
    stats.expectation_failures += static_cast<int>(request_count);
    return false;
  }
  stats.conn_established += 1;
  if (nghttp2_session_callbacks_new(&client.callbacks) != 0 || client.callbacks == nullptr) {
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
    close_h2_client_session(client);
    stats.errors += static_cast<int>(request_count);
    stats.expectation_failures += static_cast<int>(request_count);
    return false;
  }
  nghttp2_submit_settings(client.session, NGHTTP2_FLAG_NONE, nullptr, 0);
  client.ready = true;
  client.idle_deadline_ms = monotonic_ms_now() + std::max(1, profile.timeout_ms);
  client.dispatch_ready_ms = monotonic_ms_now();
  client.consecutive_failures = 0;
  return true;
}

bool run_h2_connection(
    const Profile& profile,
    H2ClientSession& client,
    int epoll_fd,
    const std::vector<H2RequestSpec>& requests,
    std::map<std::string, std::string>& captures,
    H2RunStats& stats) {
  if (requests.empty()) {
    return true;
  }

  if (client.ready && client.ctx.fd >= 0) {
    stats.conn_reused += 1;
  } else if (!open_h2_client_session(profile, epoll_fd, client, stats, requests.size())) {
    return false;
  }

  H2ConnectionContext& ctx = client.ctx;
  ctx.epoll_fd = epoll_fd;
  ctx.captures = &captures;

  const std::size_t stream_budget = static_cast<std::size_t>(std::max(1, profile.max_streams_per_connection));
  std::size_t next = 0;
  unsigned char read_buf[16384];
  const int completed_before = ctx.completed_success;
  const int failed_before = ctx.failed_streams;
  const int status_2xx_before = ctx.status_2xx;
  const int status_3xx_before = ctx.status_3xx;
  const int status_4xx_before = ctx.status_4xx;
  const int status_5xx_before = ctx.status_5xx;
  const int expectation_before = ctx.expectation_failures;
  const int goaway_before = ctx.goaway;
  const int rst_before = ctx.rst_stream;
  const int think_before = ctx.max_think_time_ms;
  const std::size_t rx_before = ctx.bytes_received;
  const std::size_t tx_before = ctx.bytes_sent;

  while (next < requests.size() || !ctx.active_streams.empty()) {
    while (next < requests.size() && ctx.active_streams.size() < stream_budget) {
      if (!submit_h2_request(client.session, ctx, profile, requests[next], captures)) {
        ctx.protocol_error = 1;
        stats.errors += static_cast<int>(requests.size() - next);
        stats.expectation_failures += static_cast<int>(requests.size() - next);
        next = requests.size();
        break;
      }
      next += 1;
    }
    if (next < requests.size() && ctx.active_streams.size() >= stream_budget) {
      stats.scheduler_backpressure += 1;
    }

    if (nghttp2_session_send(client.session) < 0) {
      ctx.protocol_error = 1;
      break;
    }
    if (ctx.active_streams.empty() && next >= requests.size()) {
      break;
    }

    const ssize_t rd = h2_socket_read(ctx, read_buf, sizeof(read_buf));
    if (rd > 0) {
      const ssize_t recv_rc = nghttp2_session_mem_recv(client.session, read_buf, static_cast<size_t>(rd));
      if (recv_rc < 0) {
        ctx.protocol_error = 1;
        break;
      }
      continue;
    }
    if (rd == 0) {
      break;
    }
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
      continue;
    }
    ctx.transport_error = 1;
    break;
  }

  const int dangling_streams = static_cast<int>(ctx.active_streams.size());
  for (auto it = ctx.active_streams.begin(); it != ctx.active_streams.end(); ++it) {
    stats.errors += 1;
    stats.expectation_failures += 1;
  }
  ctx.active_streams.clear();

  stats.sent += ctx.completed_success - completed_before;
  stats.errors += ctx.failed_streams - failed_before;
  stats.status_2xx += ctx.status_2xx - status_2xx_before;
  stats.status_3xx += ctx.status_3xx - status_3xx_before;
  stats.status_4xx += ctx.status_4xx - status_4xx_before;
  stats.status_5xx += ctx.status_5xx - status_5xx_before;
  stats.rx_bytes += ctx.bytes_received - rx_before;
  stats.tx_bytes += ctx.bytes_sent - tx_before;
  stats.expectation_failures += ctx.expectation_failures - expectation_before;
  stats.goaway_count += ctx.goaway - goaway_before;
  stats.rst_stream_count += ctx.rst_stream - rst_before;

  const bool ok = !(ctx.transport_error || ctx.protocol_error);
  const int think_delta_ms = std::max(0, ctx.max_think_time_ms - think_before);
  if (!ok || ctx.goaway > goaway_before || dangling_streams > 0) {
    client.consecutive_failures += 1;
    client.unhealthy_until_ms = monotonic_ms_now() + std::max(1, profile.timeout_ms / 4);
    close_h2_client_session(client);
  } else {
    client.ready = true;
    client.consecutive_failures = 0;
    client.idle_deadline_ms = monotonic_ms_now() + std::max(1, profile.timeout_ms);
    client.dispatch_ready_ms = monotonic_ms_now() + think_delta_ms;
  }
  return ok;
}
#endif

std::map<std::string, double> run_http2_profile(
    const Profile& profile,
    const RuntimeConfig& cfg,
    const RuntimeCapabilities& caps) {
  NativeRuntime runtime = build_runtime(profile, cfg);
  std::map<std::string, double> out;
  init_stats(profile, out);
  out["runtime_shards"] = static_cast<double>(runtime.shards.size());
  out["h2_native_capability_available"] = (caps.openssl && caps.nghttp2) ? 1.0 : 0.0;
  if (!(caps.openssl && caps.nghttp2)) {
    destroy_runtime(runtime);
    return fail_visible_stats(profile, caps, "capability_unavailable");
  }

#ifdef SAMURAI_WITH_NGHTTP2
  std::vector<H2RequestSpec> requests = build_h2_requests(profile);
  H2RunStats stats;
  stats.attempted = static_cast<int>(requests.size());
  if (stats.attempted == 0) {
    destroy_runtime(runtime);
    out["attempted"] = 0.0;
    out["sent"] = 0.0;
    out["errors"] = 0.0;
    out["l7_flow_attempted"] = 0.0;
    return out;
  }

  const auto shard_buckets = bucket_h2_requests_by_shard(requests, runtime.shards.size());
  std::vector<std::vector<std::vector<H2RequestSpec>>> shard_lanes(shard_buckets.size());
  std::vector<std::size_t> lane_offsets(shard_buckets.size(), 0);
  std::map<std::string, std::string> captures;
  for (std::size_t shard_idx = 0; shard_idx < shard_buckets.size(); ++shard_idx) {
    const auto& bucket = shard_buckets[shard_idx];
    auto& local_shard = runtime.local_shards[shard_idx];
    const std::size_t shard_conn_budget = static_cast<std::size_t>(
        std::max(1, runtime.shards.empty() ? profile.max_connections : runtime.shards[shard_idx].connection_pool.max_connections));
    while (local_shard.h2_sessions.size() < shard_conn_budget) {
      local_shard.h2_sessions.push_back(std::make_unique<H2ClientSession>());
    }
    shard_lanes[shard_idx] = bucket_h2_requests_by_connection(bucket, shard_conn_budget);
    if (!bucket.empty()) {
      enqueue_ready_shard(runtime, shard_idx);
    }
  }

  while (true) {
    expire_all_lane_idle(runtime, profile);
    auto ready_shard = pop_ready_shard(runtime);
    if (!ready_shard.has_value()) {
      bool pending = false;
      for (std::size_t shard_idx = 0; shard_idx < shard_lanes.size(); ++shard_idx) {
        if (lane_offsets[shard_idx] < shard_lanes[shard_idx].size()) {
          pending = true;
          break;
        }
      }
      if (!pending) {
        break;
      }
      std::optional<long long> next_deadline;
      for (std::size_t idx = 0; idx < shard_lanes.size(); ++idx) {
        if (lane_offsets[idx] >= shard_lanes[idx].size()) {
          continue;
        }
        const long long candidate = runtime.local_shards[idx].dispatch_ready_ms;
        if (!next_deadline.has_value() || candidate < *next_deadline) {
          next_deadline = candidate;
        }
      }
      if (!next_deadline.has_value()) {
        break;
      }
      advance_runtime_until(runtime, profile, *next_deadline);
      continue;
    }

    const std::size_t shard_idx = *ready_shard;
    auto& local_shard = runtime.local_shards[shard_idx];
    if (lane_offsets[shard_idx] >= shard_lanes[shard_idx].size()) {
      continue;
    }
    const std::size_t lane_idx = lane_offsets[shard_idx];
    const auto& conn_requests = shard_lanes[shard_idx][lane_idx];
    if (conn_requests.empty()) {
      lane_offsets[shard_idx] += 1;
      if (lane_offsets[shard_idx] < shard_lanes[shard_idx].size()) {
        enqueue_ready_shard(runtime, shard_idx);
      }
      continue;
    }

    auto& client = *local_shard.h2_sessions[lane_idx];
    const long long now_ms = monotonic_ms_now();
    if (!client.ready && client.unhealthy_until_ms > now_ms) {
      local_shard.dispatch_ready_ms = client.unhealthy_until_ms;
      stats.scheduler_backpressure += 1;
      enqueue_ready_shard(runtime, shard_idx);
      continue;
    }

    const int shard_epoll_fd = runtime.shards.empty() ? -1 : runtime.shards[shard_idx].epoll_fd;
    run_h2_connection(profile, client, shard_epoll_fd, conn_requests, captures, stats);
    lane_offsets[shard_idx] += 1;
    local_shard.dispatch_ready_ms = std::max(monotonic_ms_now(), client.dispatch_ready_ms);
    if (lane_offsets[shard_idx] < shard_lanes[shard_idx].size()) {
      enqueue_ready_shard(runtime, shard_idx);
    }
  }

  stats.errors += std::max(0, stats.attempted - stats.sent - stats.errors);
  out["attempted"] = static_cast<double>(stats.attempted);
  out["sent"] = static_cast<double>(stats.sent);
  out["errors"] = static_cast<double>(stats.errors);
  out["responses_total"] = static_cast<double>(stats.sent);
  out["status_2xx"] = static_cast<double>(stats.status_2xx);
  out["status_3xx"] = static_cast<double>(stats.status_3xx);
  out["status_4xx"] = static_cast<double>(stats.status_4xx);
  out["status_5xx"] = static_cast<double>(stats.status_5xx);
  out["l7_flow_attempted"] = static_cast<double>(stats.attempted);
  out["l7_flow_completed"] = static_cast<double>(stats.sent);
  out["l7_conn_attempted"] = static_cast<double>(stats.conn_attempted);
  out["l7_conn_established"] = static_cast<double>(stats.conn_established);
  out["l7_conn_reused"] = static_cast<double>(stats.conn_reused);
  out["l7_rx_bytes"] = static_cast<double>(stats.rx_bytes);
  out["l7_tx_bytes"] = static_cast<double>(stats.tx_bytes);
  out["l7_expectation_failures"] = static_cast<double>(stats.expectation_failures);
  out["l7_scheduler_backpressure_count"] = static_cast<double>(stats.scheduler_backpressure);
  out["h2_goaway_count"] = static_cast<double>(stats.goaway_count);
  out["h2_stream_reset_ratio"] = stats.attempted > 0
      ? static_cast<double>(stats.rst_stream_count) / static_cast<double>(stats.attempted)
      : 0.0;
  destroy_runtime(runtime);
  return out;
#else
  destroy_runtime(runtime);
  return fail_visible_stats(profile, caps, "nghttp2_not_built");
#endif
}

}  // namespace

RuntimeCapabilities detect_capabilities() {
  RuntimeCapabilities caps;
#ifdef SAMURAI_WITH_OPENSSL
  caps.openssl = true;
#endif
#ifdef SAMURAI_WITH_NGHTTP2
  caps.nghttp2 = true;
#endif
  return caps;
}

std::map<std::string, double> run_profile(const Profile& profile, const RuntimeConfig& cfg) {
  const RuntimeCapabilities caps = detect_capabilities();
  if (profile.protocol == "http2") {
    return run_http2_profile(profile, cfg, caps);
  }
  std::map<std::string, double> out;
  init_stats(profile, out);

  int status_2xx = 0;
  int status_3xx = 0;
  int status_4xx = 0;
  int status_5xx = 0;
  int sent = 0;
  int conn_attempted = 0;
  int conn_established = 0;
  int conn_reused = 0;
  int expectation_failures = 0;
  std::size_t rx_bytes = 0;
  std::size_t tx_bytes = 0;
  std::map<std::string, std::string> captures;

  const auto request_specs = build_h1_requests(profile);
  const int request_attempts = static_cast<int>(request_specs.size());
  NativeRuntime runtime = build_runtime(profile, cfg);
  out["runtime_shards"] = static_cast<double>(runtime.shards.size());
  auto acquire_connection = [&](int shard_id) -> std::unique_ptr<Http1Connection> {
    ShardState& shard = runtime.shards[static_cast<std::size_t>(shard_id)];
    auto& local_shard = runtime.local_shards[static_cast<std::size_t>(shard_id)];
    expire_http1_idle(shard, local_shard);
    while (!local_shard.http1_idle.empty()) {
      std::unique_ptr<Http1Connection> reused = std::move(local_shard.http1_idle.back());
      local_shard.http1_idle.pop_back();
      if (!reused || reused->fd < 0) {
        continue;
      }
      if (reused->timer_armed && shard.timer_wheel.active_timers > 0) {
        shard.timer_wheel.active_timers -= 1;
      }
      reused->timer_armed = false;
      local_shard.http1_active.push_back(reused.get());
      shard.connection_pool.active_connections += 1;
      shard.connection_pool.reused_connections += 1;
      conn_reused += 1;
      return reused;
    }
    auto created = std::make_unique<Http1Connection>();
    created->fd = connect_socket(profile);
    created->shard_id = shard_id;
    conn_attempted += 1;
    if (created->fd < 0) {
      return {};
    }
    conn_established += 1;
    local_shard.http1_active.push_back(created.get());
    shard.connection_pool.active_connections += 1;
    return created;
  };
  const auto shard_buckets = bucket_h1_requests_by_shard(request_specs, runtime.shards.size());
  std::vector<std::size_t> shard_offsets(shard_buckets.size(), 0);
  for (std::size_t shard_idx = 0; shard_idx < shard_buckets.size(); ++shard_idx) {
    if (!shard_buckets[shard_idx].empty()) {
      enqueue_ready_shard(runtime, shard_idx);
    }
  }

  while (true) {
    expire_all_lane_idle(runtime, profile);
    auto ready_shard = pop_ready_shard(runtime);
    if (!ready_shard.has_value()) {
      bool pending = false;
      for (std::size_t shard_idx = 0; shard_idx < shard_buckets.size(); ++shard_idx) {
        if (shard_offsets[shard_idx] < shard_buckets[shard_idx].size()) {
          pending = true;
          break;
        }
      }
      if (!pending) {
        break;
      }
      std::optional<long long> next_deadline;
      for (std::size_t idx = 0; idx < shard_buckets.size(); ++idx) {
        if (shard_offsets[idx] >= shard_buckets[idx].size()) {
          continue;
        }
        const long long candidate = runtime.local_shards[idx].dispatch_ready_ms;
        if (!next_deadline.has_value() || candidate < *next_deadline) {
          next_deadline = candidate;
        }
      }
      if (!next_deadline.has_value()) {
        break;
      }
      advance_runtime_until(runtime, profile, *next_deadline);
      continue;
    }

    const std::size_t ready_shard_idx = *ready_shard;
    ShardState& shard = runtime.shards[ready_shard_idx];
    auto& local_shard = runtime.local_shards[ready_shard_idx];
    if (shard_offsets[ready_shard_idx] >= shard_buckets[ready_shard_idx].size()) {
      continue;
    }
    const H1RequestSpec& request_spec = shard_buckets[ready_shard_idx][shard_offsets[ready_shard_idx]];
    local_shard.dispatch_ready_ms = monotonic_ms_now();

    std::unique_ptr<Http1Connection> conn = acquire_connection(static_cast<int>(ready_shard_idx));
    if (!conn || conn->fd < 0) {
      expectation_failures += 1;
      shard_offsets[ready_shard_idx] += 1;
      if (shard_offsets[ready_shard_idx] < shard_buckets[ready_shard_idx].size()) {
        enqueue_ready_shard(runtime, ready_shard_idx);
      }
      continue;
    }
    const int shard_epoll_fd = shard.epoll_fd;
    const FlowOp* body_op = request_spec.body_op.has_value() ? &*request_spec.body_op : nullptr;
    const std::string request = build_http1_request(profile, request_spec.send_headers, body_op, captures);
    tx_bytes += request.size();
    if (!send_all(shard_epoll_fd, conn->fd, request, profile.timeout_ms)) {
      expectation_failures += 1;
      close_http1_connection(conn, shard, local_shard);
      shard_offsets[ready_shard_idx] += 1;
      if (shard_offsets[ready_shard_idx] < shard_buckets[ready_shard_idx].size()) {
        enqueue_ready_shard(runtime, ready_shard_idx);
      }
      continue;
    }

    const ResponseInfo response = read_response(shard_epoll_fd, *conn, profile.timeout_ms);
    rx_bytes += response.bytes_received;
    int think_time_total_ms = 0;
    if (response.status_code <= 0) {
      expectation_failures += 1;
      close_http1_connection(conn, shard, local_shard);
      shard_offsets[ready_shard_idx] += 1;
      if (shard_offsets[ready_shard_idx] < shard_buckets[ready_shard_idx].size()) {
        enqueue_ready_shard(runtime, ready_shard_idx);
      }
      continue;
    }

    for (const FlowOp& follow : request_spec.follow_ops) {
      if (follow.opcode == "EXPECT_STATUS" && follow.has_expect) {
        if (response.status_code < follow.expect.status_min || response.status_code > follow.expect.status_max) {
          expectation_failures += 1;
        }
      } else if (follow.opcode == "EXPECT_HEADER" && follow.has_expect) {
        const std::string name = lower_copy(follow.expect.name);
        const auto it = response.headers.find(name);
        if (it == response.headers.end() || it->second.find(follow.expect.value) == std::string::npos) {
          expectation_failures += 1;
        }
      } else if (follow.opcode == "EXPECT_BODY_SUBSTRING" && follow.has_expect) {
        if (response.body.find(follow.expect.value) == std::string::npos) {
          expectation_failures += 1;
        }
      } else if (follow.opcode == "CAPTURE_HEADER") {
        const std::string key = lower_copy(follow.capture_source.empty() ? follow.capture_name : follow.capture_source);
        const auto it = response.headers.find(key);
        if (it != response.headers.end()) {
          captures[follow.capture_name.empty() ? key : follow.capture_name] = it->second;
        }
      } else if (follow.opcode == "CAPTURE_COOKIE") {
        const auto it = response.headers.find("set-cookie");
        if (it != response.headers.end()) {
          capture_cookie(it->second, follow.capture_name, captures);
        }
      } else if (follow.opcode == "THINK_TIME") {
        think_time_total_ms += std::max(0, follow.think_time_ms);
      }
    }

    if (!response.keep_alive || !profile.keepalive) {
      close_http1_connection(conn, shard, local_shard);
    } else {
      erase_active_http1(local_shard, conn.get());
      shard.connection_pool.active_connections =
          std::max(0, shard.connection_pool.active_connections - 1);
      schedule_http1_idle(*conn, shard, local_shard, profile.timeout_ms);
      local_shard.http1_idle.push_back(std::move(conn));
    }

    shard_offsets[ready_shard_idx] += 1;
    sent += 1;
    local_shard.dispatch_ready_ms = monotonic_ms_now() + think_time_total_ms;
    if (shard_offsets[ready_shard_idx] < shard_buckets[ready_shard_idx].size()) {
      enqueue_ready_shard(runtime, ready_shard_idx);
    }
    if (response.status_code >= 200 && response.status_code <= 299) {
      status_2xx += 1;
    } else if (response.status_code >= 300 && response.status_code <= 399) {
      status_3xx += 1;
    } else if (response.status_code >= 400 && response.status_code <= 499) {
      status_4xx += 1;
    } else if (response.status_code >= 500 && response.status_code <= 599) {
      status_5xx += 1;
    }
  }
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    auto& local_shard = runtime.local_shards[shard_idx];
    auto& shard = runtime.shards[shard_idx];
    for (auto& conn : local_shard.http1_idle) {
      close_http1_connection(conn, shard, local_shard);
    }
    local_shard.http1_idle.clear();
  }
  destroy_runtime(runtime);

  out["attempted"] = static_cast<double>(request_attempts);
  out["sent"] = static_cast<double>(sent);
  out["errors"] = static_cast<double>(request_attempts - sent);
  out["responses_total"] = static_cast<double>(sent);
  out["status_2xx"] = static_cast<double>(status_2xx);
  out["status_3xx"] = static_cast<double>(status_3xx);
  out["status_4xx"] = static_cast<double>(status_4xx);
  out["status_5xx"] = static_cast<double>(status_5xx);
  out["l7_flow_completed"] = static_cast<double>(sent);
  out["l7_conn_attempted"] = static_cast<double>(conn_attempted);
  out["l7_conn_established"] = static_cast<double>(conn_established);
  out["l7_conn_reused"] = static_cast<double>(conn_reused);
  out["l7_rx_bytes"] = static_cast<double>(rx_bytes);
  out["l7_tx_bytes"] = static_cast<double>(tx_bytes);
  out["l7_expectation_failures"] = static_cast<double>(expectation_failures);
  return out;
}

}  // namespace ddos_samurai::l7_emu_native
