#include "udp_io.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

namespace ddos_samurai::l7_emu_native::custom_quic_stack {
namespace {

std::string trim_ascii(std::string v) {
  std::size_t b = 0;
  while (b < v.size() && std::isspace(static_cast<unsigned char>(v[b])) != 0) {
    ++b;
  }
  std::size_t e = v.size();
  while (e > b && std::isspace(static_cast<unsigned char>(v[e - 1])) != 0) {
    --e;
  }
  return v.substr(b, e - b);
}

std::string to_lower_ascii(std::string v) {
  std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return v;
}

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

uint16_t fold_checksum(uint32_t sum) {
  while ((sum >> 16u) != 0u) {
    sum = (sum & 0xFFFFu) + (sum >> 16u);
  }
  return static_cast<uint16_t>(~sum & 0xFFFFu);
}

uint16_t ipv4_header_checksum(const iphdr* ip) {
  if (ip == nullptr) {
    return 0;
  }
  const auto* words = reinterpret_cast<const uint16_t*>(ip);
  uint32_t sum = 0;
  for (int i = 0; i < 10; ++i) {
    if (i == 5) {
      continue;
    }
    sum += ntohs(words[i]);
  }
  return htons(fold_checksum(sum));
}

uint16_t udp_ipv4_checksum(
    uint32_t src_ip_nbo,
    uint32_t dst_ip_nbo,
    const udphdr* udp,
    const uint8_t* payload,
    std::size_t payload_len) {
  if (udp == nullptr) {
    return 0;
  }
  uint32_t sum = 0;
  const uint16_t src_hi = static_cast<uint16_t>((ntohl(src_ip_nbo) >> 16) & 0xFFFFu);
  const uint16_t src_lo = static_cast<uint16_t>(ntohl(src_ip_nbo) & 0xFFFFu);
  const uint16_t dst_hi = static_cast<uint16_t>((ntohl(dst_ip_nbo) >> 16) & 0xFFFFu);
  const uint16_t dst_lo = static_cast<uint16_t>(ntohl(dst_ip_nbo) & 0xFFFFu);
  sum += src_hi;
  sum += src_lo;
  sum += dst_hi;
  sum += dst_lo;
  sum += static_cast<uint16_t>(IPPROTO_UDP);
  sum += ntohs(udp->len);

  const auto* udp_words = reinterpret_cast<const uint16_t*>(udp);
  sum += ntohs(udp_words[0]);
  sum += ntohs(udp_words[1]);
  sum += ntohs(udp_words[2]);

  std::size_t i = 0;
  while (i + 1 < payload_len) {
    const uint16_t w = static_cast<uint16_t>((static_cast<uint16_t>(payload[i]) << 8u) |
                                             static_cast<uint16_t>(payload[i + 1]));
    sum += w;
    i += 2;
  }
  if (i < payload_len) {
    const uint16_t w = static_cast<uint16_t>(static_cast<uint16_t>(payload[i]) << 8u);
    sum += w;
  }
  const uint16_t csum = fold_checksum(sum);
  return csum == 0 ? 0xFFFFu : htons(csum);
}

bool resolve_af_packet_macs(
    const std::string& iface,
    const std::string& target_ip,
    std::array<uint8_t, 6>* src_mac,
    std::array<uint8_t, 6>* dst_mac) {
  if (src_mac == nullptr || dst_mac == nullptr) {
    return false;
  }
  if (!read_iface_mac_address(iface, src_mac)) {
    return false;
  }
  bool got_dst = false;
  if (const char* dst_env = std::getenv("SAMURAI_QUIC_AF_XDP_DST_MAC");
      dst_env != nullptr && dst_env[0] != '\0') {
    got_dst = parse_mac_address(dst_env, dst_mac);
  }
  if (!got_dst) {
    if (const char* dst_env = std::getenv("SAMURAI_AF_PACKET_DST_MAC");
        dst_env != nullptr && dst_env[0] != '\0') {
      got_dst = parse_mac_address(dst_env, dst_mac);
    }
  }
  if (!got_dst) {
    if (const char* fallback = std::getenv("SAMURAI_GPU_TX_MAC");
        fallback != nullptr && fallback[0] != '\0') {
      got_dst = parse_mac_address(fallback, dst_mac);
    }
  }
  if (!got_dst && !target_ip.empty()) {
    const auto arp = lookup_arp_mac_address(iface, target_ip);
    if (arp.has_value()) {
      *dst_mac = *arp;
      got_dst = true;
    }
  }
  return got_dst;
}

}  // namespace

QuicUdpIoBackendCode parse_quic_udp_io_backend(const std::string& raw) {
  const std::string v = to_lower_ascii(trim_ascii(raw));
  if (v == "afxdp" || v == "af_xdp" || v == "xdp") {
    return QuicUdpIoBackendCode::AfXdp;
  }
  if (v == "dpdk") {
    return QuicUdpIoBackendCode::Dpdk;
  }
  if (v == "afpacket" || v == "af_packet" || v == "packet" || v == "raw") {
    return QuicUdpIoBackendCode::AfPacket;
  }
  return QuicUdpIoBackendCode::KernelSocket;
}

QuicUdpIoBackendCode resolve_quic_udp_io_backend(const Profile& profile) {
  std::string candidate = profile.stateful_runtime_backend;
  const char* env_backend = std::getenv("SAMURAI_STATEFUL_RUNTIME_BACKEND");
  if (env_backend != nullptr && env_backend[0] != '\0') {
    candidate = env_backend;
  }
  return parse_quic_udp_io_backend(candidate);
}

bool parse_mac_address(const std::string& text, std::array<uint8_t, 6>* out) {
  if (out == nullptr) {
    return false;
  }
  std::array<unsigned int, 6> tmp{};
  if (std::sscanf(
          text.c_str(),
          "%x:%x:%x:%x:%x:%x",
          &tmp[0],
          &tmp[1],
          &tmp[2],
          &tmp[3],
          &tmp[4],
          &tmp[5]) != 6) {
    return false;
  }
  for (std::size_t i = 0; i < out->size(); ++i) {
    if (tmp[i] > 0xFFu) {
      return false;
    }
    (*out)[i] = static_cast<uint8_t>(tmp[i]);
  }
  return true;
}

bool read_iface_mac_address(const std::string& iface, std::array<uint8_t, 6>* out) {
  if (out == nullptr || iface.empty()) {
    return false;
  }
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return false;
  }
  ifreq ifr{};
  std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface.c_str());
  bool ok = false;
  if (::ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
    const unsigned char* mac = reinterpret_cast<const unsigned char*>(ifr.ifr_hwaddr.sa_data);
    for (int i = 0; i < 6; ++i) {
      (*out)[static_cast<std::size_t>(i)] = mac[i];
    }
    ok = true;
  }
  (void)::close(fd);
  return ok;
}

bool read_iface_ipv4_nbo(const std::string& iface, uint32_t* out_nbo) {
  if (out_nbo == nullptr || iface.empty()) {
    return false;
  }
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return false;
  }
  ifreq ifr{};
  std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface.c_str());
  bool ok = false;
  if (::ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
    const auto* sa = reinterpret_cast<const sockaddr_in*>(&ifr.ifr_addr);
    *out_nbo = sa->sin_addr.s_addr;
    ok = true;
  }
  (void)::close(fd);
  return ok;
}

std::optional<std::array<uint8_t, 6>> lookup_arp_mac_address(
    const std::string& iface,
    const std::string& target_ip) {
  std::ifstream in("/proc/net/arp");
  if (!in.is_open()) {
    return std::nullopt;
  }
  std::string line{};
  if (!std::getline(in, line)) {
    return std::nullopt;
  }
  while (std::getline(in, line)) {
    std::istringstream iss(line);
    std::string ip{};
    std::string hw_type{};
    std::string flags{};
    std::string mac{};
    std::string mask{};
    std::string dev{};
    if (!(iss >> ip >> hw_type >> flags >> mac >> mask >> dev)) {
      continue;
    }
    if (ip != target_ip) {
      continue;
    }
    if (!iface.empty() && dev != iface) {
      continue;
    }
    std::array<uint8_t, 6> out{};
    if (parse_mac_address(mac, &out)) {
      return out;
    }
  }
  return std::nullopt;
}

bool build_ipv4_udp_ethernet_frame(
    const std::array<uint8_t, 6>& dst_mac,
    const std::array<uint8_t, 6>& src_mac,
    uint32_t src_ip_nbo,
    uint32_t dst_ip_nbo,
    uint16_t src_port_nbo,
    uint16_t dst_port_nbo,
    uint16_t* ip_id,
    const uint8_t* payload,
    std::size_t payload_len,
    uint8_t* out_frame,
    std::size_t out_frame_cap,
    std::size_t* out_frame_len) {
  if (ip_id == nullptr || payload == nullptr || out_frame == nullptr || out_frame_len == nullptr) {
    return false;
  }
  if (payload_len == 0 || payload_len > kUdpIoMaxUdpPayloadBytes ||
      out_frame_cap < kUdpIoMaxL2FrameBytes) {
    return false;
  }
  const std::size_t frame_len = 14u + sizeof(iphdr) + sizeof(udphdr) + payload_len;
  std::size_t off = 0;
  for (std::size_t i = 0; i < 6; ++i) {
    out_frame[off + i] = dst_mac[i];
    out_frame[off + 6 + i] = src_mac[i];
  }
  out_frame[off + 12] = 0x08;
  out_frame[off + 13] = 0x00;
  off += 14;

  auto* ip = reinterpret_cast<iphdr*>(out_frame + off);
  std::memset(ip, 0, sizeof(*ip));
  ip->version = 4;
  ip->ihl = 5;
  ip->ttl = 64;
  ip->protocol = IPPROTO_UDP;
  ip->id = htons((*ip_id)++);
  ip->frag_off = htons(0x4000);
  ip->tot_len = htons(static_cast<uint16_t>(sizeof(iphdr) + sizeof(udphdr) + payload_len));
  ip->saddr = src_ip_nbo;
  ip->daddr = dst_ip_nbo;
  ip->check = ipv4_header_checksum(ip);
  off += sizeof(iphdr);

  auto* udp = reinterpret_cast<udphdr*>(out_frame + off);
  std::memset(udp, 0, sizeof(*udp));
  udp->source = src_port_nbo;
  udp->dest = dst_port_nbo;
  udp->len = htons(static_cast<uint16_t>(sizeof(udphdr) + payload_len));
  off += sizeof(udphdr);
  std::memcpy(out_frame + off, payload, payload_len);
  udp->check = udp_ipv4_checksum(src_ip_nbo, dst_ip_nbo, udp, payload, payload_len);

  *out_frame_len = frame_len;
  return true;
}

// Thread-safe ephemeral src-port allocator for the af_packet QUIC endpoint. Each
// attempt opens its own raw socket and demuxes returns in software by exact
// dst-port match (see the recv filter: `udp->dest != ep->src_port_nbo` -> skip),
// so every *concurrent* attempt MUST get a distinct src port or two connections'
// responses become ambiguous. std::rand() risked birthday collisions once the
// fan-out runs attempts in parallel; a monotonic atomic counter over the
// ephemeral range is collision-free until it wraps (far beyond any load-test
// connection count) and needs no per-worker plumbing.
uint16_t next_af_packet_src_port() {
  static std::atomic<uint32_t> counter{0};
  constexpr uint16_t kBase = 20000;
  constexpr uint16_t kSpan = 45000;  // ephemeral range [20000, 65000)
  const uint32_t n = counter.fetch_add(1, std::memory_order_relaxed);
  return static_cast<uint16_t>(kBase + static_cast<uint16_t>(n % kSpan));
}

bool open_af_packet_udp(
    const Profile& profile,
    uint32_t dst_ip_nbo,
    uint16_t dst_port_host,
    AfPacketUdpEndpoint* out) {
  if (out == nullptr) {
    return false;
  }
  *out = AfPacketUdpEndpoint{};

  const char* iface_env = std::getenv("SAMURAI_XDP_INTERFACE");
  if (iface_env == nullptr || iface_env[0] == '\0') {
    iface_env = std::getenv("SAMURAI_AF_PACKET_IFACE");
  }
  const std::string iface = iface_env == nullptr ? "" : std::string(iface_env);
  if (iface.empty()) {
    return false;
  }

  const int ifindex = ::if_nametoindex(iface.c_str());
  if (ifindex <= 0) {
    return false;
  }

  uint32_t src_ip_nbo = 0;
  in_addr src_ip_addr{};
  if (!profile.source_ip.empty() && ::inet_pton(AF_INET, profile.source_ip.c_str(), &src_ip_addr) == 1) {
    src_ip_nbo = src_ip_addr.s_addr;
  } else if (!read_iface_ipv4_nbo(iface, &src_ip_nbo)) {
    return false;
  }

  std::array<uint8_t, 6> src_mac{};
  std::array<uint8_t, 6> dst_mac{};
  if (!resolve_af_packet_macs(iface, profile.target_ip, &src_mac, &dst_mac)) {
    return false;
  }

  const int fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0) {
    return false;
  }

  sockaddr_ll bind_addr{};
  bind_addr.sll_family = AF_PACKET;
  bind_addr.sll_protocol = htons(ETH_P_ALL);
  bind_addr.sll_ifindex = ifindex;
  if (::bind(fd, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
    (void)::close(fd);
    return false;
  }

  // Do not capture our own transmitted frames back into RX. Without this a raw
  // SOCK_RAW socket echoes every datagram we send (all QUIC TX) into its own
  // receive queue, where the software demux discards them -- but under the
  // threaded fan-out that self-echo (plus other workers' traffic on the shared
  // iface) can overflow the receive buffer and drop the actual server response
  // (notably the larger H3 DATA frames). Mirrors the L4/L7 custom_tcp own-wire.
#ifdef PACKET_IGNORE_OUTGOING
  {
    int ignore_outgoing = 1;
    (void)::setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_outgoing, sizeof(ignore_outgoing));
  }
#endif
  // Enlarge the receive buffer so a burst of response datagrams is not dropped
  // before the drive loop drains it.
  {
    int rcvbuf = 4 * 1024 * 1024;
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
  }

  timeval tv{};
  tv.tv_sec = 0;
  tv.tv_usec = 20000;
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  out->fd = fd;
  out->ifindex = ifindex;
  out->src_mac = src_mac;
  out->dst_mac = dst_mac;
  out->src_ip_nbo = src_ip_nbo;
  out->dst_ip_nbo = dst_ip_nbo;
  out->dst_port_nbo = htons(dst_port_host);
  // Ephemeral source port in the user-space range. Collision-free across
  // concurrent attempts (required for the threaded af_packet fan-out).
  const uint16_t sport = next_af_packet_src_port();
  out->src_port_nbo = htons(sport);
  out->ip_id = 1;
  return true;
}

void close_af_packet_udp(AfPacketUdpEndpoint* ep) {
  if (ep == nullptr) {
    return;
  }
  if (ep->fd >= 0) {
    (void)::close(ep->fd);
  }
  *ep = AfPacketUdpEndpoint{};
}

ssize_t af_packet_send_udp(AfPacketUdpEndpoint* ep, const uint8_t* payload, std::size_t payload_len) {
  if (ep == nullptr || ep->fd < 0 || payload == nullptr || payload_len == 0) {
    return -1;
  }
  std::size_t frame_len = 0;
  if (!build_ipv4_udp_ethernet_frame(
          ep->dst_mac,
          ep->src_mac,
          ep->src_ip_nbo,
          ep->dst_ip_nbo,
          ep->src_port_nbo,
          ep->dst_port_nbo,
          &ep->ip_id,
          payload,
          payload_len,
          ep->tx_frame.data(),
          ep->tx_frame.size(),
          &frame_len)) {
    return -1;
  }

  sockaddr_ll dst{};
  dst.sll_family = AF_PACKET;
  dst.sll_protocol = htons(ETH_P_IP);
  dst.sll_ifindex = ep->ifindex;
  dst.sll_halen = 6;
  std::memcpy(dst.sll_addr, ep->dst_mac.data(), 6);

  const ssize_t wr = ::sendto(
      ep->fd,
      ep->tx_frame.data(),
      frame_len,
      0,
      reinterpret_cast<sockaddr*>(&dst),
      sizeof(dst));
  if (wr <= 0) {
    return -1;
  }
  return static_cast<ssize_t>(payload_len);
}

int af_packet_recv_udp(
    AfPacketUdpEndpoint* ep,
    uint8_t* payload_buf,
    std::size_t stride,
    std::size_t* lens_out,
    int max_packets) {
  if (ep == nullptr || ep->fd < 0 || payload_buf == nullptr || lens_out == nullptr || stride == 0 ||
      max_packets <= 0) {
    return -1;
  }

  int accepted = 0;
  for (int i = 0; i < max_packets; ++i) {
    std::array<uint8_t, 2048> frame{};
    const ssize_t nread = ::recvfrom(ep->fd, frame.data(), frame.size(), MSG_DONTWAIT, nullptr, nullptr);
    if (nread <= 0) {
      break;
    }
    const std::size_t flen = static_cast<std::size_t>(nread);
    if (flen < 14u + sizeof(iphdr) + sizeof(udphdr)) {
      continue;
    }
    if (frame[12] != 0x08 || frame[13] != 0x00) {
      continue;
    }
    const auto* ip = reinterpret_cast<const iphdr*>(frame.data() + 14);
    if (ip->version != 4 || ip->protocol != IPPROTO_UDP) {
      continue;
    }
    const std::size_t ihl_bytes = static_cast<std::size_t>(ip->ihl) * 4u;
    if (14u + ihl_bytes + sizeof(udphdr) > flen) {
      continue;
    }
    const auto* udp = reinterpret_cast<const udphdr*>(frame.data() + 14u + ihl_bytes);
    if (udp->dest != ep->src_port_nbo) {
      continue;
    }
    if (ip->daddr != ep->src_ip_nbo) {
      continue;
    }
    if (udp->source != ep->dst_port_nbo) {
      continue;
    }
    const uint16_t udp_len = ntohs(udp->len);
    if (udp_len < sizeof(udphdr)) {
      continue;
    }
    const std::size_t payload_len = static_cast<std::size_t>(udp_len - sizeof(udphdr));
    const std::size_t payload_off = 14u + ihl_bytes + sizeof(udphdr);
    if (payload_off + payload_len > flen || payload_len > stride) {
      continue;
    }
    std::memcpy(payload_buf + static_cast<std::size_t>(accepted) * stride, frame.data() + payload_off, payload_len);
    lens_out[static_cast<std::size_t>(accepted)] = payload_len;
    ++accepted;
  }
  return accepted;
}

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

  const QuicUdpIoBackendCode requested = resolve_quic_udp_io_backend(profile);
  out->runtime_backend_requested = static_cast<int>(requested);

  sockaddr_storage target_addr {};
  socklen_t target_len = 0;
  if (!resolve_udp_target(profile, &target_addr, &target_len)) {
    out->errors = attempted;
    out->connect_fail = attempted;
    out->handshake_fail = attempted;
    out->conn_attempted = attempted;
    return false;
  }

  AfPacketUdpEndpoint afp{};
  int fd = -1;
  QuicUdpIoBackendCode active = QuicUdpIoBackendCode::KernelSocket;
  bool used_fallback = false;

  if (requested == QuicUdpIoBackendCode::AfPacket && target_addr.ss_family == AF_INET) {
    const auto* sin = reinterpret_cast<const sockaddr_in*>(&target_addr);
    if (open_af_packet_udp(profile, sin->sin_addr.s_addr, ntohs(sin->sin_port), &afp)) {
      active = QuicUdpIoBackendCode::AfPacket;
    } else if (profile.stateful_runtime_strict != 0) {
      out->errors = attempted;
      out->connect_fail = attempted;
      out->handshake_fail = attempted;
      out->conn_attempted = attempted;
      return false;
    } else {
      used_fallback = true;
    }
  } else if ((requested == QuicUdpIoBackendCode::AfXdp || requested == QuicUdpIoBackendCode::Dpdk) &&
             target_addr.ss_family == AF_INET) {
    const auto* sin = reinterpret_cast<const sockaddr_in*>(&target_addr);
    if (open_af_packet_udp(profile, sin->sin_addr.s_addr, ntohs(sin->sin_port), &afp)) {
      active = requested;
    } else if (profile.stateful_runtime_strict != 0) {
      out->errors = attempted;
      out->connect_fail = attempted;
      out->handshake_fail = attempted;
      out->conn_attempted = attempted;
      out->runtime_udp_io_backend = static_cast<int>(requested);
      return false;
    } else {
      used_fallback = true;
    }
  }

  if (active == QuicUdpIoBackendCode::KernelSocket) {
    const int family = (target_addr.ss_family == AF_INET6) ? AF_INET6 : AF_INET;
    fd = create_udp_socket(family, timeout_ms);
    if (fd < 0) {
      out->errors = attempted;
      out->connect_fail = attempted;
      out->handshake_fail = attempted;
      out->conn_attempted = attempted;
      return false;
    }
  }

  out->runtime_udp_io_backend = static_cast<int>(active);
  out->runtime_native_hot_path_ready = is_native_hot_path_backend(active) ? 1 : 0;
  if (used_fallback) {
    out->backend_fallback_count += 1;
  }

  int remaining = attempted;
  constexpr int kBatchMax = 32;
  while (remaining > 0) {
    const int batch = std::min(remaining, kBatchMax);
    out->conn_attempted += batch;

    int sent = 0;
    if (active == QuicUdpIoBackendCode::AfPacket) {
      for (int i = 0; i < batch; ++i) {
        const ssize_t wr = af_packet_send_udp(&afp, payload_data, payload_len);
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
    } else {
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
    }

    int responses = 0;
    if (active == QuicUdpIoBackendCode::AfPacket && sent > 0) {
      constexpr std::size_t kStride = 2048;
      std::vector<uint8_t> rx_blob(static_cast<std::size_t>(sent) * kStride, 0);
      std::vector<std::size_t> lens(static_cast<std::size_t>(sent), 0);
      const int got = af_packet_recv_udp(&afp, rx_blob.data(), kStride, lens.data(), sent);
      for (int i = 0; i < std::max(0, got); ++i) {
        const std::size_t rd = lens[static_cast<std::size_t>(i)];
        if (rd == 0) {
          continue;
        }
        responses += 1;
        out->rx_datagrams += 1;
        out->rx_bytes += rd;
        bool valid = true;
        if (observer != nullptr) {
          valid = observer(rx_blob.data() + static_cast<std::size_t>(i) * kStride, rd, observer_ctx);
        }
        if (!valid) {
          out->response_validation_fail += 1;
        }
      }
    } else if (sent > 0) {
#if defined(__linux__)
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
#endif
      if (responses <= 0) {
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

  if (fd >= 0) {
    (void)::close(fd);
  }
  close_af_packet_udp(&afp);

  out->errors = std::max(out->errors, attempted - out->send_ok);
  return true;
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
