#include "udp_io.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

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

  addrinfo* result = nullptr;
  const std::string port = std::to_string(std::max(1, profile.target_port));
  int rc = getaddrinfo(profile.target_ip.c_str(), port.c_str(), &hints, &result);
  if (rc != 0 || result == nullptr) {
    hints.ai_flags = AI_NUMERICHOST;
    rc = getaddrinfo(profile.target_ip.c_str(), port.c_str(), &hints, &result);
  }
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
  const int one = 1;
  (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
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

  const int family = (target_addr.ss_family == AF_INET6) ? AF_INET6 : AF_INET;
  const int fd = create_udp_socket(family, timeout_ms);
  if (fd < 0) {
    out->errors = attempted;
    out->connect_fail = attempted;
    out->handshake_fail = attempted;
    out->conn_attempted = attempted;
    return false;
  }

  int remaining = attempted;
  constexpr int kBatchMax = 32;
  while (remaining > 0) {
    const int batch = std::min(remaining, kBatchMax);
    out->conn_attempted += batch;

    int sent = 0;
#if defined(__linux__)
    std::vector<iovec> iov(static_cast<std::size_t>(batch));
    std::vector<mmsghdr> mmsg(static_cast<std::size_t>(batch));
    std::vector<sockaddr_storage> targets(static_cast<std::size_t>(batch));
    for (int i = 0; i < batch; ++i) {
      targets[static_cast<std::size_t>(i)] = target_addr;
      iov[static_cast<std::size_t>(i)].iov_base = const_cast<unsigned char*>(payload_data);
      iov[static_cast<std::size_t>(i)].iov_len = payload_len;
      mmsghdr mh{};
      mh.msg_hdr.msg_name = &targets[static_cast<std::size_t>(i)];
      mh.msg_hdr.msg_namelen = target_len;
      mh.msg_hdr.msg_iov = &iov[static_cast<std::size_t>(i)];
      mh.msg_hdr.msg_iovlen = 1;
      mmsg[static_cast<std::size_t>(i)] = mh;
    }
    const int sm = ::sendmmsg(fd, mmsg.data(), static_cast<unsigned int>(batch), 0);
    if (sm > 0) {
      sent = sm;
      for (int i = 0; i < sm; ++i) {
        out->send_ok += 1;
        out->tx_datagrams += 1;
        out->tx_bytes += static_cast<std::size_t>(mmsg[static_cast<std::size_t>(i)].msg_len);
      }
    }
#endif
    if (sent <= 0) {
      for (int i = 0; i < batch; ++i) {
        const ssize_t wr = ::sendto(
            fd,
            payload_data,
            payload_len,
            0,
            reinterpret_cast<const sockaddr*>(&target_addr),
            target_len);
        if (wr > 0) {
          sent += 1;
          out->send_ok += 1;
          out->tx_datagrams += 1;
          out->tx_bytes += static_cast<std::size_t>(wr);
        } else {
          out->errors += 1;
          out->connect_fail += 1;
          out->handshake_fail += 1;
        }
      }
    }

    int responses = 0;
#if defined(__linux__)
    if (sent > 0) {
      std::vector<std::array<unsigned char, 2048>> rx_buf(static_cast<std::size_t>(sent));
      std::vector<iovec> rx_iov(static_cast<std::size_t>(sent));
      std::vector<mmsghdr> rx_msg(static_cast<std::size_t>(sent));
      for (int i = 0; i < sent; ++i) {
        rx_iov[static_cast<std::size_t>(i)].iov_base = rx_buf[static_cast<std::size_t>(i)].data();
        rx_iov[static_cast<std::size_t>(i)].iov_len = rx_buf[static_cast<std::size_t>(i)].size();
        mmsghdr mh{};
        mh.msg_hdr.msg_iov = &rx_iov[static_cast<std::size_t>(i)];
        mh.msg_hdr.msg_iovlen = 1;
        rx_msg[static_cast<std::size_t>(i)] = mh;
      }
      timespec ts{};
      const int bounded_timeout = std::max(10, timeout_ms);
      ts.tv_sec = bounded_timeout / 1000;
      ts.tv_nsec = static_cast<long>((bounded_timeout % 1000) * 1000000L);
      const int rm = ::recvmmsg(
          fd,
          rx_msg.data(),
          static_cast<unsigned int>(sent),
          MSG_WAITFORONE,
          &ts);
      if (rm > 0) {
        responses = rm;
        for (int i = 0; i < rm; ++i) {
          const std::size_t rd = static_cast<std::size_t>(rx_msg[static_cast<std::size_t>(i)].msg_len);
          out->rx_datagrams += 1;
          out->rx_bytes += rd;
          bool valid = true;
          if (observer != nullptr) {
            valid = observer(
                rx_buf[static_cast<std::size_t>(i)].data(),
                rd,
                observer_ctx);
          }
          if (!valid) {
            out->response_validation_fail += 1;
          }
        }
      }
    }
#endif
    if (responses <= 0 && sent > 0) {
      for (int i = 0; i < sent; ++i) {
        std::array<unsigned char, 2048> rx_buf {};
        const ssize_t rd = ::recvfrom(fd, rx_buf.data(), rx_buf.size(), 0, nullptr, nullptr);
        if (rd > 0) {
          responses += 1;
          out->rx_datagrams += 1;
          out->rx_bytes += static_cast<std::size_t>(rd);
          bool valid = true;
          if (observer != nullptr) {
            valid = observer(rx_buf.data(), static_cast<std::size_t>(rd), observer_ctx);
          }
          if (!valid) {
            out->response_validation_fail += 1;
          }
        }
      }
    }

    out->conn_established += responses;
    out->responses += responses;
    if (sent > responses) {
      const int miss = sent - responses;
      out->errors += miss;
      out->timeouts += miss;
      out->handshake_fail += miss;
      out->response_validation_fail += miss;
      out->pacing_wait_events += 1;
    }
    remaining -= batch;
  }

  (void)::close(fd);

  out->errors = std::max(out->errors, attempted - out->send_ok);
  return true;
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
