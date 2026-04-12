#include "udp_io.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

namespace ddos_samurai::l7_emu_native::custom_quic_stack {
namespace {

bool resolve_udp_target(const Profile& profile, sockaddr_storage* out_addr, socklen_t* out_len) {
  if (out_addr == nullptr || out_len == nullptr) {
    return false;
  }
  std::memset(out_addr, 0, sizeof(*out_addr));
  *out_len = 0;

  addrinfo hints {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = AI_NUMERICHOST;

  addrinfo* result = nullptr;
  const std::string port = std::to_string(std::max(1, profile.target_port));
  const int rc = getaddrinfo(profile.target_ip.c_str(), port.c_str(), &hints, &result);
  if (rc != 0 || result == nullptr) {
    return false;
  }

  bool ok = false;
  for (addrinfo* it = result; it != nullptr; it = it->ai_next) {
    if (it->ai_addr == nullptr || it->ai_addrlen <= 0) {
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

  freeaddrinfo(result);
  return ok;
}

int create_udp_socket(int family, int timeout_ms) {
  const int fd = ::socket(family, SOCK_DGRAM, 0);
  if (fd < 0) {
    return -1;
  }

  timeval tv {};
  const int bounded_timeout = std::max(10, timeout_ms);
  tv.tv_sec = bounded_timeout / 1000;
  tv.tv_usec = (bounded_timeout % 1000) * 1000;
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  return fd;
}

}  // namespace

bool run_udp_probe_batch(
    const Profile& profile,
    int attempted,
    int timeout_ms,
    const unsigned char* payload_data,
    std::size_t payload_len,
    UdpResponseObserver observer,
    void* observer_ctx,
    UdpProbeCounters* out) {
  if (out == nullptr) {
    return false;
  }
  *out = UdpProbeCounters{};
  if (attempted <= 0) {
    return true;
  }
  if (payload_data == nullptr || payload_len == 0) {
    return false;
  }

  sockaddr_storage target_addr {};
  socklen_t target_len = 0;
  if (!resolve_udp_target(profile, &target_addr, &target_len)) {
    out->errors = attempted;
    out->connect_fail = attempted;
    out->handshake_fail = attempted;
    out->conn_attempted = attempted;
    return false;
  }

  for (int i = 0; i < attempted; ++i) {
    const int family = (target_addr.ss_family == AF_INET6) ? AF_INET6 : AF_INET;
    const int fd = create_udp_socket(family, timeout_ms);
    out->conn_attempted += 1;
    if (fd < 0) {
      out->errors += 1;
      out->connect_fail += 1;
      out->handshake_fail += 1;
      continue;
    }

    const ssize_t wr = ::sendto(
        fd,
        payload_data,
        payload_len,
        0,
        reinterpret_cast<const sockaddr*>(&target_addr),
        target_len);
    if (wr <= 0) {
      out->errors += 1;
      out->connect_fail += 1;
      out->handshake_fail += 1;
      (void)::close(fd);
      continue;
    }

    out->send_ok += 1;
    out->tx_bytes += static_cast<std::size_t>(wr);

    std::array<unsigned char, 2048> rx_buf {};
    const ssize_t rd = ::recvfrom(fd, rx_buf.data(), rx_buf.size(), 0, nullptr, nullptr);
    if (rd > 0) {
      out->conn_established += 1;
      out->responses += 1;
      out->rx_bytes += static_cast<std::size_t>(rd);
      bool valid = true;
      if (observer != nullptr) {
        valid = observer(rx_buf.data(), static_cast<std::size_t>(rd), observer_ctx);
      }
      if (!valid) {
        out->response_validation_fail += 1;
      }
    } else {
      out->errors += 1;
      out->timeouts += 1;
      out->handshake_fail += 1;
      out->response_validation_fail += 1;
    }

    (void)::close(fd);
  }

  out->errors = std::max(out->errors, attempted - out->send_ok);
  return true;
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
