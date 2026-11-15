#include "engine_internal.hpp"

namespace samurai::l7_emu_native {

bool is_custom_tcp_backend(TransportBackend backend) {
  return backend == TransportBackend::CustomTcp || backend == TransportBackend::DpdkDirect;
}

TransportBackend parse_transport_backend(const Profile& profile) {
  std::string backend = profile.transport_backend;
  std::transform(backend.begin(), backend.end(), backend.begin(), [](unsigned char c) {
    if (c >= 'A' && c <= 'Z') {
      return static_cast<char>(c - 'A' + 'a');
    }
    return static_cast<char>(c);
  });
  std::string s_backend = profile.stateful_runtime_backend;
  std::transform(s_backend.begin(), s_backend.end(), s_backend.begin(), [](unsigned char c) {
    if (c >= 'A' && c <= 'Z') {
      return static_cast<char>(c - 'A' + 'a');
    }
    return static_cast<char>(c);
  });

  if (backend.empty()) {
    backend = "custom_tcp";
  }
  if (profile.protocol == "quic") {
    return TransportBackend::CustomQuic;
  }
  if (backend == "kernel_socket") {
    return TransportBackend::KernelSocket;
  }
  if (backend == "dpdk" || backend == "dpdk_direct" || s_backend == "dpdk") {
    return TransportBackend::DpdkDirect;
  }
  return TransportBackend::CustomTcp;
}

bool parse_ipv4_u32(const std::string& text, uint32_t* out_ip) {
  if (out_ip == nullptr) {
    return false;
  }
  in_addr addr {};
  if (::inet_pton(AF_INET, text.c_str(), &addr) != 1) {
    return false;
  }
  *out_ip = ntohl(addr.s_addr);
  return true;
}

uint32_t custom_tcp_src_ip(const Profile& profile) {
  uint32_t src_ip = 0;
  if (!profile.source_ip.empty() && parse_ipv4_u32(profile.source_ip, &src_ip)) {
    return src_ip;
  }
  const char* env_src = std::getenv("SAMURAI_CUSTOM_TCP_SRC_IP");
  if (env_src != nullptr && parse_ipv4_u32(env_src, &src_ip)) {
    return src_ip;
  }
  uint32_t dst_ip = 0;
  if (parse_ipv4_u32(profile.target_ip, &dst_ip)) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd >= 0) {
      sockaddr_in dst_addr{};
      dst_addr.sin_family = AF_INET;
      dst_addr.sin_port = htons(static_cast<uint16_t>(std::max(1, profile.target_port)));
      dst_addr.sin_addr.s_addr = htonl(dst_ip);
      if (::connect(fd, reinterpret_cast<const sockaddr*>(&dst_addr), sizeof(dst_addr)) == 0) {
        sockaddr_in src_addr{};
        socklen_t src_len = sizeof(src_addr);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&src_addr), &src_len) == 0) {
          const uint32_t route_src_ip = ntohl(src_addr.sin_addr.s_addr);
          if (route_src_ip != 0U) {
            ::close(fd);
            return route_src_ip;
          }
        }
      }
      ::close(fd);
    }
  }
  return static_cast<uint32_t>((10U << 24U) | 1U);
}

int custom_tcp_connect_bridge(Http1Connection& conn, const Profile& profile) {
  uint32_t dst_ip = 0;
  if (!parse_ipv4_u32(profile.target_ip, &dst_ip)) {
    errno = EINVAL;
    return -1;
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
    return -1;
  }
  conn.custom_flow_id = flow_id;
  conn.custom_connect_ready = false;
  conn.custom_send_enqueued = false;
  conn.custom_send_outstanding = 0;
  conn.custom_send_queued_bytes = 0;
  conn.custom_send_enqueue_count = 0;
  conn.custom_terminal = false;
  conn.fd = kVirtualCustomTcpFd;
  return conn.fd;
}

ssize_t custom_tcp_send_bridge(Http1Connection& conn, const void* buf, std::size_t len) {
  if (!conn.custom_connect_ready) {
    errno = EAGAIN;
    return -1;
  }
  uint32_t queued = 0;
  const int rc = tcpdp_enqueue_send(
      conn.custom_flow_id,
      static_cast<const uint8_t*>(buf),
      len,
      &queued);
  if (rc != 0 || queued == 0) {
    errno = EAGAIN;
    return -1;
  }
  conn.custom_send_outstanding += 1;
  conn.custom_send_enqueued = conn.custom_send_outstanding > 0;
  conn.custom_send_queued_bytes += queued;
  conn.custom_send_enqueue_count += 1;
  return static_cast<ssize_t>(queued);
}

ssize_t custom_tcp_recv_bridge(Http1Connection& conn, void* buf, std::size_t len) {
  if (buf == nullptr || len == 0) {
    return 0;
  }
  if (!conn.read_buffer.empty()) {
    const std::string_view available = conn.read_buffer.view();
    const std::size_t copy_len = std::min(len, available.size());
    std::memcpy(buf, available.data(), copy_len);
    conn.read_buffer.consume(copy_len);
    return static_cast<ssize_t>(copy_len);
  }
  if (!conn.custom_terminal) {
    errno = EAGAIN;
    return -1;
  }
  return 0;
}

int custom_tcp_close_bridge(Http1Connection& conn) {
  conn.custom_flow_id = 0;
  conn.custom_connect_ready = false;
  conn.custom_send_enqueued = false;
  conn.custom_send_outstanding = 0;
  conn.custom_send_queued_bytes = 0;
  conn.custom_send_enqueue_count = 0;
  conn.custom_terminal = false;
  return 0;
}

int kernel_socket_connect_bridge(Http1Connection& conn, const Profile& profile) {
  addrinfo hints {};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo* results = nullptr;
  const std::string port = std::to_string(std::max(1, profile.target_port));
  if (::getaddrinfo(profile.target_ip.c_str(), port.c_str(), &hints, &results) != 0) {
    errno = EADDRNOTAVAIL;
    return -1;
  }
  int fd = -1;
  for (addrinfo* ai = results; ai != nullptr; ai = ai->ai_next) {
    fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
    if (fd < 0) {
      continue;
    }
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (!set_fd_nonblocking(fd)) {
      ::close(fd);
      fd = -1;
      continue;
    }
    const int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc == 0 || errno == EINPROGRESS) {
      break;
    }
    ::close(fd);
    fd = -1;
  }
  ::freeaddrinfo(results);
  if (fd < 0) {
    errno = ECONNREFUSED;
    return -1;
  }
  conn.fd = fd;
  conn.custom_flow_id = 0;
  return fd;
}

ssize_t kernel_socket_send_bridge(Http1Connection& conn, const void* buf, std::size_t len) {
  return ::send(conn.fd, buf, len, MSG_NOSIGNAL);
}

ssize_t kernel_socket_recv_bridge(Http1Connection& conn, void* buf, std::size_t len) {
  return ::recv(conn.fd, buf, len, 0);
}

int kernel_socket_close_bridge(Http1Connection& conn) {
  if (conn.fd >= 0) {
    ::close(conn.fd);
    conn.fd = -1;
  }
  return 0;
}

const H1TransportOps& resolve_h1_transport_ops(TransportBackend backend) {
  static const H1TransportOps custom_tcp_ops{
      custom_tcp_connect_bridge,
      custom_tcp_send_bridge,
      custom_tcp_recv_bridge,
      custom_tcp_close_bridge,
      "custom_tcp",
  };
  static const H1TransportOps kernel_socket_ops{
      kernel_socket_connect_bridge,
      kernel_socket_send_bridge,
      kernel_socket_recv_bridge,
      kernel_socket_close_bridge,
      "kernel_socket",
  };
  if (backend == TransportBackend::KernelSocket) {
    return kernel_socket_ops;
  }
  return custom_tcp_ops;
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
  if (g_perf_stats != nullptr) {
    g_perf_stats->epoll_wakeups += 1;
  }
  if (rc <= 0) {
    return false;
  }
  return (out.events & events) != 0 || (out.events & (EPOLLERR | EPOLLHUP)) != 0;
}

bool set_fd_nonblocking(int fd) {
  const int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return false;
  }
  return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

int connect_h2_tcp_socket(const Profile& profile, int epoll_fd) {
  addrinfo hints {};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo* results = nullptr;
  const std::string port = std::to_string(profile.target_port);
  if (::getaddrinfo(profile.target_ip.c_str(), port.c_str(), &hints, &results) != 0) {
    return -1;
  }
  int fd = -1;
  for (addrinfo* ai = results; ai != nullptr; ai = ai->ai_next) {
    fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
    if (fd < 0) {
      continue;
    }
    if (!set_fd_nonblocking(fd)) {
      ::close(fd);
      fd = -1;
      continue;
    }
    const int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc == 0) {
      break;
    }
    if (errno == EINPROGRESS) {
      if (wait_for_fd(epoll_fd, fd, EPOLLOUT, profile.timeout_ms)) {
        int so_error = 0;
        socklen_t so_error_len = sizeof(so_error);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) == 0 && so_error == 0) {
          break;
        }
      }
    }
    ::close(fd);
    fd = -1;
  }
  ::freeaddrinfo(results);
  return fd;
}

}  // namespace samurai::l7_emu_native
