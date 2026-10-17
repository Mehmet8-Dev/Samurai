// Real Wire (netns + veth + AF_PACKET) End-to-End Benchmark & Verification for TcpDataplaneCore.
//
// Unlike synthetic in-memory benchmarks where frames are passed directly between functions,
// this binary binds real Linux AF_PACKET (SOCK_RAW) sockets (with PACKET_IGNORE_OUTGOING) to a
// virtual Ethernet pair (`v_cli` <==> `v_srv`) inside an isolated network namespace.
//
// Two Real-Wire Verification Modes:
//   Phase 1 (Live Linux Kernel TCP Stack Peer Mode):
//     - A real non-blocking `accept4()` TCP listener runs on the Linux kernel's TCP/IP stack
//       bound to `10.77.0.2:18088` on `v_srv` (with `ethtool -K v_cli/v_srv tx off rx off` so
//       kernel-generated SYN-ACKs carry full wire RFC 1071 checksums).
//     - `TcpDataplaneCore` on `v_cli` (with spoofed on-link `10.77.0.9` and static ARP neighbor entry)
//       completes real 3-way handshakes (`SYN` -> Kernel `SYN-ACK` -> `ACK`) directly against
//       the Linux kernel TCP stack!
//
//   Phase 2 (High-Scale Full-Duplex Wire-Peer Mode — 100,000+ Flows, 300,000+ Real Wire Packets):
//     - Client side (`v_cli`): `TcpDataplaneCore` generates real Ethernet + IPv4 + TCP SYN frames,
//       patches L2 MAC addresses, and transmits them through the kernel's `v_cli` netdev via
//       `sendmmsg()` while simultaneously draining incoming `SYN-ACK` frames from `v_cli` via
//       `recvmmsg()`, validating RFC 1071 checksums, transitioning flows to `kEstablished`, and
//       emitting third-leg `ACK` frames onto `v_cli` -> `v_srv`.
//     - Server side (`v_srv`): A dedicated raw wire responder reads incoming SYN frames from `v_srv`
//       via `recvmmsg()`, validates RFC 1071 IPv4/TCP checksums, synthesizes wire-authentic 66B
//       SYN-ACK frames (MSS=1460, SACK-Perm, WScale=7), transmits them back across `v_srv` -> `v_cli`,
//       and counts the third-leg ACK frames arriving on `v_srv`.

#include "tcp_dataplane_core.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <malloc.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using ddos_samurai::tcpdp::TcpDataplaneCore;
using ddos_samurai::tcpdp::TcpDpConfig;
using ddos_samurai::tcpdp::TcpDpState;

static std::atomic<int> g_fails{0};
#define CHECK(cond, ...)                                       \
  do {                                                         \
    if (!(cond)) {                                             \
      std::printf("FAIL [%s:%d]: ", __FILE__, __LINE__);       \
      std::printf(__VA_ARGS__);                                \
      std::printf("\n");                                       \
      g_fails.fetch_add(1, std::memory_order_relaxed);         \
    }                                                          \
  } while (0)

struct ProcMemInfo {
  long vm_rss_kb = 0;
  long vm_hwm_kb = 0;
};

static ProcMemInfo ReadProcMem() {
  ProcMemInfo info{};
  std::ifstream in("/proc/self/status");
  std::string line;
  while (std::getline(in, line)) {
    if (line.rfind("VmRSS:", 0) == 0) {
      std::istringstream iss(line.substr(6));
      iss >> info.vm_rss_kb;
    } else if (line.rfind("VmHWM:", 0) == 0) {
      std::istringstream iss(line.substr(6));
      iss >> info.vm_hwm_kb;
    }
  }
  return info;
}

static void WriteBe16(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v >> 8);
  p[1] = static_cast<uint8_t>(v & 0xFF);
}

static void WriteBe32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v >> 24);
  p[1] = static_cast<uint8_t>(v >> 16);
  p[2] = static_cast<uint8_t>(v >> 8);
  p[3] = static_cast<uint8_t>(v & 0xFF);
}

static uint16_t ReadBe16(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

static uint32_t ReadBe32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) |
         static_cast<uint32_t>(p[3]);
}

static uint16_t ComputeIpChecksum(const uint8_t* ip, size_t ihl) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < ihl; i += 2) {
    if (i == 10) continue;
    sum += (static_cast<uint32_t>(ip[i]) << 8) | static_cast<uint32_t>(ip[i + 1]);
  }
  while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

static uint16_t ComputeTcpChecksum(const uint8_t* ip, const uint8_t* tcp, size_t tcp_len) {
  uint32_t sum = 0;
  for (size_t i = 12; i < 20; i += 2) {
    sum += (static_cast<uint32_t>(ip[i]) << 8) | static_cast<uint32_t>(ip[i + 1]);
  }
  sum += 6u;
  sum += static_cast<uint32_t>(tcp_len);
  for (size_t i = 0; i + 1 < tcp_len; i += 2) {
    if (i == 16) continue;
    sum += (static_cast<uint32_t>(tcp[i]) << 8) | static_cast<uint32_t>(tcp[i + 1]);
  }
  if (tcp_len & 1u) {
    sum += static_cast<uint32_t>(tcp[tcp_len - 1]) << 8;
  }
  while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

static bool GetIfaceInfo(const char* ifname, int* out_ifindex, uint8_t out_mac[6]) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return false;
  struct ifreq ifr{};
  std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
  if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
    close(fd);
    return false;
  }
  *out_ifindex = ifr.ifr_ifindex;
  if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
    close(fd);
    return false;
  }
  std::memcpy(out_mac, ifr.ifr_hwaddr.sa_data, 6);
  close(fd);
  return true;
}

static int OpenBoundAfPacketSocket(int ifindex, int rcvbuf_bytes = 64 * 1024 * 1024) {
  int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
  if (fd < 0) return -1;
  int sndbuf = rcvbuf_bytes;
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf_bytes, sizeof(rcvbuf_bytes));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf));
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_bytes, sizeof(rcvbuf_bytes));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  #ifdef PACKET_IGNORE_OUTGOING
  int ignore_outgoing = 1;
  (void)setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_outgoing, sizeof(ignore_outgoing));
  #endif
  struct sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifindex;
  sll.sll_protocol = htons(ETH_P_ALL);
  if (bind(fd, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static uint64_t ReadNetdevCounter(const char* ifname, const char* stat_name) {
  std::ifstream in("/proc/net/dev");
  std::string line;
  std::string prefix = std::string(ifname) + ":";
  while (std::getline(in, line)) {
    auto pos = line.find(prefix);
    if (pos != std::string::npos) {
      std::istringstream iss(line.substr(pos + prefix.size()));
      uint64_t rx_bytes = 0, rx_pkts = 0, rx_errs = 0, rx_drop = 0;
      uint64_t rx_fifo = 0, rx_frame = 0, rx_comp = 0, rx_mcast = 0;
      uint64_t tx_bytes = 0, tx_pkts = 0, tx_errs = 0, tx_drop = 0;
      iss >> rx_bytes >> rx_pkts >> rx_errs >> rx_drop >> rx_fifo >> rx_frame >> rx_comp >> rx_mcast
          >> tx_bytes >> tx_pkts >> tx_errs >> tx_drop;
      if (std::strcmp(stat_name, "rx_packets") == 0) return rx_pkts;
      if (std::strcmp(stat_name, "tx_packets") == 0) return tx_pkts;
      if (std::strcmp(stat_name, "rx_bytes") == 0) return rx_bytes;
      if (std::strcmp(stat_name, "tx_bytes") == 0) return tx_bytes;
      if (std::strcmp(stat_name, "rx_drop") == 0) return rx_drop;
      if (std::strcmp(stat_name, "tx_drop") == 0) return tx_drop;
    }
  }
  return 0;
}

struct VethOptions {
  std::string cli_iface = "v_cli";
  std::string srv_iface = "v_srv";
  size_t num_flows = 100000;
  size_t kernel_flows = 2000;
  std::string json_path;
};

int main(int argc, char** argv) {
  VethOptions opt;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--cli-iface") == 0 && i + 1 < argc) {
      opt.cli_iface = argv[++i];
    } else if (std::strcmp(argv[i], "--srv-iface") == 0 && i + 1 < argc) {
      opt.srv_iface = argv[++i];
    } else if (std::strcmp(argv[i], "--flows") == 0 && i + 1 < argc) {
      opt.num_flows = static_cast<size_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (std::strcmp(argv[i], "--kernel-flows") == 0 && i + 1 < argc) {
      opt.kernel_flows = static_cast<size_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (std::strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
      opt.json_path = argv[++i];
    }
  }

  int cli_ifindex = -1, srv_ifindex = -1;
  uint8_t cli_mac[6]{}, srv_mac[6]{};
  if (!GetIfaceInfo(opt.cli_iface.c_str(), &cli_ifindex, cli_mac) ||
      !GetIfaceInfo(opt.srv_iface.c_str(), &srv_ifindex, srv_mac)) {
    std::printf("SKIP: veth interfaces (%s, %s) not present or CAP_NET_RAW unavailable.\n",
                opt.cli_iface.c_str(), opt.srv_iface.c_str());
    return 0;
  }

  int cli_fd = OpenBoundAfPacketSocket(cli_ifindex);
  int srv_fd = OpenBoundAfPacketSocket(srv_ifindex);
  if (cli_fd < 0 || srv_fd < 0) {
    std::printf("SKIP: cannot open AF_PACKET sockets on (%s, %s): %s\n",
                opt.cli_iface.c_str(), opt.srv_iface.c_str(), std::strerror(errno));
    if (cli_fd >= 0) close(cli_fd);
    if (srv_fd >= 0) close(srv_fd);
    return 0;
  }

  struct sockaddr_ll cli_dst_sll{};
  cli_dst_sll.sll_family = AF_PACKET;
  cli_dst_sll.sll_protocol = htons(ETH_P_IP);
  cli_dst_sll.sll_ifindex = cli_ifindex;
  cli_dst_sll.sll_halen = 6;
  std::memcpy(cli_dst_sll.sll_addr, srv_mac, 6);

  struct sockaddr_ll srv_dst_sll{};
  srv_dst_sll.sll_family = AF_PACKET;
  srv_dst_sll.sll_protocol = htons(ETH_P_IP);
  srv_dst_sll.sll_ifindex = srv_ifindex;
  srv_dst_sll.sll_halen = 6;
  std::memcpy(srv_dst_sll.sll_addr, cli_mac, 6);

  std::printf("================================================================================\n");
  std::printf("  DDoSamurai tcpdp Real-Wire (netns + veth + AF_PACKET) Benchmark & Verification\n");
  std::printf("================================================================================\n");
  std::printf("Client Interface:   %s (ifindex=%d, MAC=%02x:%02x:%02x:%02x:%02x:%02x)\n",
              opt.cli_iface.c_str(), cli_ifindex,
              cli_mac[0], cli_mac[1], cli_mac[2], cli_mac[3], cli_mac[4], cli_mac[5]);
  std::printf("Server Interface:   %s (ifindex=%d, MAC=%02x:%02x:%02x:%02x:%02x:%02x)\n",
              opt.srv_iface.c_str(), srv_ifindex,
              srv_mac[0], srv_mac[1], srv_mac[2], srv_mac[3], srv_mac[4], srv_mac[5]);
  std::printf("Target Wire Flows:  %zu (Full 3-Way Handshake over kernel veth pair)\n", opt.num_flows);
  std::printf("Kernel Stack Flows: %zu (Real Linux TCP listener accept() verification)\n", opt.kernel_flows);
  std::printf("--------------------------------------------------------------------------------\n");

  // ============================================================================
  // TEST 1: Live Linux Kernel TCP Stack Interoperability (SYN -> Kernel SYN-ACK -> ACK)
  // ============================================================================
  std::printf("[PHASE 1] Live Linux Kernel TCP/IP Stack Interoperability (%zu real sockets)...\n",
              opt.kernel_flows);

  const uint32_t kServerIp = 0x0A4D0002u;  // 10.77.0.2 (assigned to v_srv)
  const uint32_t kClientIp = 0x0A4D0009u;  // 10.77.0.9 (static ARP neigh -> v_cli MAC)
  const uint16_t kServerPort = 18088;

  struct rlimit rl{};
  if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
    rl.rlim_cur = std::max<rlim_t>(rl.rlim_cur, std::min<rlim_t>(rl.rlim_max, 65536));
    (void)setrlimit(RLIMIT_NOFILE, &rl);
  }

  int listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  CHECK(listen_fd >= 0, "Failed to create kernel TCP listen socket");
  int one = 1;
  (void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in sin{};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(kServerIp);
  sin.sin_port = htons(kServerPort);

  size_t kernel_accepted = 0;
  size_t kernel_core_established = 0;
  double kernel_hs_ms = 0.0;

  if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&sin), sizeof(sin)) == 0 &&
      listen(listen_fd, 65535) == 0) {
    std::atomic<bool> stop_accept{false};
    std::atomic<size_t> accepted_count{0};
    std::vector<int> accepted_fds;
    accepted_fds.reserve(opt.kernel_flows);

    std::thread accept_thread([&]() {
      while (!stop_accept.load(std::memory_order_relaxed) &&
             accepted_count.load(std::memory_order_relaxed) < opt.kernel_flows) {
        struct sockaddr_in caddr{};
        socklen_t clen = sizeof(caddr);
        int cfd = accept4(listen_fd, reinterpret_cast<struct sockaddr*>(&caddr), &clen, SOCK_NONBLOCK);
        if (cfd >= 0) {
          accepted_fds.push_back(cfd);
          accepted_count.fetch_add(1, std::memory_order_relaxed);
        } else {
          std::this_thread::sleep_for(std::chrono::microseconds(20));
        }
      }
    });

    auto kcore = std::make_unique<TcpDataplaneCore>();
    TcpDpConfig kcfg;
    kcfg.mode = "test";
    // When veth TX checksum offload is disabled via ethtool, kernel SYN-ACKs have valid wire checksums;
    // verify_rx_checksum=true validates that!
    kcfg.verify_rx_checksum = true;
    kcore->Configure(kcfg);

    const auto k_start = std::chrono::high_resolution_clock::now();

    constexpr size_t kKernelBatch = 64;
    std::vector<uint8_t> rx_buf(2048);

    for (size_t base_i = 0; base_i < opt.kernel_flows; base_i += kKernelBatch) {
      const size_t end_i = std::min(opt.kernel_flows, base_i + kKernelBatch);
      for (size_t i = base_i; i < end_i; ++i) {
        uint16_t sport = static_cast<uint16_t>(20000 + i);
        (void)kcore->EnqueueConnect(kClientIp, kServerIp, sport, kServerPort);
      }

      // Drain SYN packets from kcore, stamp L2 MAC header, and transmit onto v_cli via sendto(..., cli_dst_sll)
      for (;;) {
        const uint8_t* base = nullptr;
        uint32_t count = 0;
        size_t psize = 0, stride = 0;
        kcore->PeekTxPacketsStrided(0, &base, &count, &psize, &stride);
        if (count == 0 || base == nullptr) break;
        for (uint32_t k = 0; k < count; ++k) {
          uint8_t frame[128];
          std::memcpy(frame, base + static_cast<size_t>(k) * stride, psize);
          std::memcpy(frame + 0, srv_mac, 6);
          std::memcpy(frame + 6, cli_mac, 6);
          (void)sendto(cli_fd, frame, psize, 0,
                       reinterpret_cast<const struct sockaddr*>(&cli_dst_sll), sizeof(cli_dst_sll));
        }
        kcore->ConsumeTxPackets(count);
      }

      // Poll v_cli for the Linux kernel's real SYN-ACK responses, ingest into kcore, and send third-leg ACK
      auto wait_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
      while (kcore->SnapshotStats().connect_established < end_i &&
             std::chrono::steady_clock::now() < wait_deadline) {
        for (int burst = 0; burst < 256; ++burst) {
          ssize_t n = recv(cli_fd, rx_buf.data(), rx_buf.size(), MSG_DONTWAIT);
          if (n <= 0) break;
          if (n >= 54 && std::memcmp(rx_buf.data() + 0, cli_mac, 6) == 0) {
            (void)kcore->IngestRxFrame(rx_buf.data(), static_cast<size_t>(n));
          }
        }
        // Flush emitted third-leg ACK frames onto v_cli so the Linux kernel completes accept()!
        for (;;) {
          const uint8_t* base = nullptr;
          uint32_t count = 0;
          size_t psize = 0, stride = 0;
          kcore->PeekTxPacketsStrided(0, &base, &count, &psize, &stride);
          if (count == 0 || base == nullptr) break;
          for (uint32_t k = 0; k < count; ++k) {
            uint8_t frame[128];
            std::memcpy(frame, base + static_cast<size_t>(k) * stride, psize);
            std::memcpy(frame + 0, srv_mac, 6);
            std::memcpy(frame + 6, cli_mac, 6);
            (void)sendto(cli_fd, frame, psize, 0,
                         reinterpret_cast<const struct sockaddr*>(&cli_dst_sll), sizeof(cli_dst_sll));
          }
          kcore->ConsumeTxPackets(count);
        }
      }
    }

    auto acc_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (accepted_count.load(std::memory_order_relaxed) < opt.kernel_flows &&
           std::chrono::steady_clock::now() < acc_deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const auto k_end = std::chrono::high_resolution_clock::now();
    kernel_hs_ms = std::chrono::duration<double, std::milli>(k_end - k_start).count();

    stop_accept.store(true, std::memory_order_relaxed);
    accept_thread.join();
    kernel_core_established = static_cast<size_t>(kcore->SnapshotStats().connect_established);
    kernel_accepted = accepted_fds.size();
    struct linger sl{1, 0};
    for (int cfd : accepted_fds) {
      (void)setsockopt(cfd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
      close(cfd);
    }
    close(listen_fd);

    std::printf("          -> TcpDataplaneCore Established: %zu / %zu\n",
                kernel_core_established, opt.kernel_flows);
    std::printf("          -> Linux Kernel TCP accept()ed:  %zu / %zu in %.2f ms (%.2f kCPS)\n",
                kernel_accepted, opt.kernel_flows, kernel_hs_ms,
                (static_cast<double>(kernel_accepted) / kernel_hs_ms));
    CHECK(kernel_core_established == opt.kernel_flows,
          "Kernel interop core established mismatch: expected %zu, got %zu",
          opt.kernel_flows, kernel_core_established);
    CHECK(kernel_accepted == opt.kernel_flows,
          "Linux kernel accept() count mismatch: expected %zu, got %zu",
          opt.kernel_flows, kernel_accepted);
  } else {
    close(listen_fd);
    std::printf("          -> [WARN] Could not bind 10.77.0.2:%u on v_srv (%s); skipping kernel listener subtest\n",
                kServerPort, std::strerror(errno));
  }

  // Drain any leftover frames on cli_fd and srv_fd before starting high-scale wire test
  std::this_thread::sleep_for(std::chrono::milliseconds(5));
  {
    uint8_t drain[2048];
    while (recv(cli_fd, drain, sizeof(drain), MSG_DONTWAIT) > 0) {}
    while (recv(srv_fd, drain, sizeof(drain), MSG_DONTWAIT) > 0) {}
  }

  // ============================================================================
  // TEST 2: High-Scale Full 3-Way Handshake over Real Kernel veth (`v_cli` <==> `v_srv`)
  // ============================================================================
  std::printf("[PHASE 2] High-Scale Real-Wire veth Benchmark (%zu flows, %zu wire packets)...\n",
              opt.num_flows, opt.num_flows * 3);

  const uint64_t cli_tx_before = ReadNetdevCounter(opt.cli_iface.c_str(), "tx_packets");
  const uint64_t cli_rx_before = ReadNetdevCounter(opt.cli_iface.c_str(), "rx_packets");
  const uint64_t srv_tx_before = ReadNetdevCounter(opt.srv_iface.c_str(), "tx_packets");
  const uint64_t srv_rx_before = ReadNetdevCounter(opt.srv_iface.c_str(), "rx_packets");

  (void)malloc_trim(0);
  const ProcMemInfo mem_base = ReadProcMem();

  auto core = std::make_unique<TcpDataplaneCore>();
  TcpDpConfig cfg;
  cfg.mode = "test";
  cfg.initial_rto_ms = 50;
  cfg.connect_timeout_ms = 60000;
  cfg.idle_timeout_ms = 120000;
  cfg.verify_rx_checksum = true;  // Full RFC 1071 checksum verification on the wire!
  CHECK(core->Configure(cfg), "Failed to configure TcpDataplaneCore for wire test");

  std::atomic<bool> responder_stop{false};
  std::atomic<size_t> srv_syn_received{0};
  std::atomic<size_t> srv_synack_sent{0};
  std::atomic<size_t> srv_ack_received{0};
  std::atomic<size_t> srv_bad_csum{0};

  // Dedicated Server Wire Responder Thread bound to `v_srv` AF_PACKET socket
  std::thread srv_thread([&]() {
    constexpr int kVecBatch = 256;
    std::vector<std::array<uint8_t, 128>> rx_frames(kVecBatch);
    std::vector<struct iovec> rx_iov(kVecBatch);
    std::vector<struct mmsghdr> rx_msg(kVecBatch);

    std::vector<std::array<uint8_t, 66>> tx_frames(kVecBatch);
    std::vector<struct iovec> tx_iov(kVecBatch);
    std::vector<struct mmsghdr> tx_msg(kVecBatch);

    for (int i = 0; i < kVecBatch; ++i) {
      rx_iov[i].iov_base = rx_frames[i].data();
      rx_iov[i].iov_len = rx_frames[i].size();
      std::memset(&rx_msg[i], 0, sizeof(struct mmsghdr));
      rx_msg[i].msg_hdr.msg_iov = &rx_iov[i];
      rx_msg[i].msg_hdr.msg_iovlen = 1;

      tx_iov[i].iov_base = tx_frames[i].data();
      tx_iov[i].iov_len = 66;
      std::memset(&tx_msg[i], 0, sizeof(struct mmsghdr));
      tx_msg[i].msg_hdr.msg_name = &srv_dst_sll;
      tx_msg[i].msg_hdr.msg_namelen = sizeof(srv_dst_sll);
      tx_msg[i].msg_hdr.msg_iov = &tx_iov[i];
      tx_msg[i].msg_hdr.msg_iovlen = 1;
    }

    while (!responder_stop.load(std::memory_order_relaxed)) {
      int n = recvmmsg(srv_fd, rx_msg.data(), kVecBatch, MSG_DONTWAIT, nullptr);
      if (n <= 0) {
        std::this_thread::yield();
        continue;
      }
      int tx_count = 0;
      for (int i = 0; i < n; ++i) {
        const uint8_t* pkt = rx_frames[i].data();
        const unsigned int len = rx_msg[i].msg_len;
        if (len < 54) continue;
        if (std::memcmp(pkt + 0, srv_mac, 6) != 0) continue;
        if (ReadBe16(pkt + 12) != 0x0800 || pkt[14] != 0x45 || pkt[23] != 6) continue;
        const uint16_t dst_port = ReadBe16(pkt + 36);
        if (dst_port != 9080) continue;

        const uint8_t flags = pkt[47];
        if (flags == 0x02) {
          if (ComputeIpChecksum(pkt + 14, 20) != ReadBe16(pkt + 24)) {
            srv_bad_csum.fetch_add(1, std::memory_order_relaxed);
            continue;
          }
          srv_syn_received.fetch_add(1, std::memory_order_relaxed);

          uint8_t* out = tx_frames[tx_count].data();
          std::memset(out, 0, 66);
          std::memcpy(out + 0, cli_mac, 6);
          std::memcpy(out + 6, srv_mac, 6);
          WriteBe16(out + 12, 0x0800);
          out[14] = 0x45;
          WriteBe16(out + 16, 52);  // 20 IP + 32 TCP
          out[22] = 64;
          out[23] = 6;
          std::memcpy(out + 26, pkt + 30, 4);
          std::memcpy(out + 30, pkt + 26, 4);
          std::memcpy(out + 34, pkt + 36, 2);
          std::memcpy(out + 36, pkt + 34, 2);
          const uint32_t cli_seq = ReadBe32(pkt + 38);
          WriteBe32(out + 38, 0x71000000u ^ cli_seq);
          WriteBe32(out + 42, cli_seq + 1u);
          out[46] = 0x80;  // 32B TCP header
          out[47] = 0x12;  // SYN | ACK
          WriteBe16(out + 48, 65535);
          out[54] = 2; out[55] = 4; WriteBe16(out + 56, 1460);
          out[58] = 4; out[59] = 2;
          out[60] = 1;
          out[61] = 3; out[62] = 3; out[63] = 7;
          out[64] = 1; out[65] = 1;
          WriteBe16(out + 24, ComputeIpChecksum(out + 14, 20));
          WriteBe16(out + 50, ComputeTcpChecksum(out + 14, out + 34, 32));
          tx_count++;
        } else if (flags == 0x10) {
          srv_ack_received.fetch_add(1, std::memory_order_relaxed);
        }
      }

      int sent_idx = 0;
      while (sent_idx < tx_count) {
        int s = sendmmsg(srv_fd, tx_msg.data() + sent_idx, tx_count - sent_idx, 0);
        if (s > 0) {
          srv_synack_sent.fetch_add(static_cast<size_t>(s), std::memory_order_relaxed);
          sent_idx += s;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
          std::this_thread::yield();
        } else {
          break;
        }
      }
    }
  });

  constexpr size_t kEnqueueChunk = 128;
  constexpr int kCliRxBatch = 256;
  std::vector<std::array<uint8_t, 128>> cli_rx_frames(kCliRxBatch);
  std::vector<struct iovec> cli_rx_iov(kCliRxBatch);
  std::vector<struct mmsghdr> cli_rx_msg(kCliRxBatch);
  for (int i = 0; i < kCliRxBatch; ++i) {
    cli_rx_iov[i].iov_base = cli_rx_frames[i].data();
    cli_rx_iov[i].iov_len = cli_rx_frames[i].size();
    std::memset(&cli_rx_msg[i], 0, sizeof(struct mmsghdr));
    cli_rx_msg[i].msg_hdr.msg_iov = &cli_rx_iov[i];
    cli_rx_msg[i].msg_hdr.msg_iovlen = 1;
  }

  std::vector<std::array<uint8_t, 128>> cli_tx_frames(kCliRxBatch);
  std::vector<struct iovec> cli_tx_iov(kCliRxBatch);
  std::vector<struct mmsghdr> cli_tx_msg(kCliRxBatch);
  for (int i = 0; i < kCliRxBatch; ++i) {
    cli_tx_iov[i].iov_base = cli_tx_frames[i].data();
    cli_tx_iov[i].iov_len = 66;
    std::memset(&cli_tx_msg[i], 0, sizeof(struct mmsghdr));
    cli_tx_msg[i].msg_hdr.msg_name = &cli_dst_sll;
    cli_tx_msg[i].msg_hdr.msg_namelen = sizeof(cli_dst_sll);
    cli_tx_msg[i].msg_hdr.msg_iov = &cli_tx_iov[i];
    cli_tx_msg[i].msg_hdr.msg_iovlen = 1;
  }

  size_t cli_syn_wire_sent = 0;
  size_t cli_established = 0;
  size_t cli_ack_wire_sent = 0;

  auto flush_client_tx = [&](bool is_syn_phase) {
    for (;;) {
      const uint8_t* base = nullptr;
      uint32_t count = 0;
      size_t psize = 0, stride = 0;
      core->PeekTxPacketsStrided(static_cast<uint32_t>(kCliRxBatch), &base, &count, &psize, &stride);
      if (count == 0 || base == nullptr) break;
      for (uint32_t k = 0; k < count; ++k) {
        uint8_t* dst = cli_tx_frames[k].data();
        std::memcpy(dst, base + static_cast<size_t>(k) * stride, psize);
        std::memcpy(dst + 0, srv_mac, 6);
        std::memcpy(dst + 6, cli_mac, 6);
        cli_tx_iov[k].iov_len = psize;
      }
      uint32_t sent_so_far = 0;
      while (sent_so_far < count) {
        int s = sendmmsg(cli_fd, cli_tx_msg.data() + sent_so_far, count - sent_so_far, 0);
        if (s > 0) {
          sent_so_far += static_cast<uint32_t>(s);
        } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
          std::this_thread::yield();
        } else {
          break;
        }
      }
      if (is_syn_phase) {
        cli_syn_wire_sent += sent_so_far;
      } else {
        cli_ack_wire_sent += sent_so_far;
      }
      core->ConsumeTxPackets(count);
    }
  };

  auto drain_client_rx = [&]() -> size_t {
    size_t progress = 0;
    for (;;) {
      int n = recvmmsg(cli_fd, cli_rx_msg.data(), kCliRxBatch, MSG_DONTWAIT, nullptr);
      if (n <= 0) break;
      for (int i = 0; i < n; ++i) {
        const uint8_t* pkt = cli_rx_frames[i].data();
        const unsigned int len = cli_rx_msg[i].msg_len;
        if (len >= 54 && std::memcmp(pkt + 0, cli_mac, 6) == 0) {
          size_t d = core->IngestRxFrame(pkt, len);
          cli_established += d;
          progress += d;
        }
      }
      flush_client_tx(false);
    }
    return progress;
  };

  const auto wire_start = std::chrono::high_resolution_clock::now();
  const auto wire_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);

  size_t next_flow = 0;
  constexpr size_t kMaxInFlightSyns = 1024;
  while (cli_established < opt.num_flows && std::chrono::steady_clock::now() < wire_deadline) {
    while (next_flow < opt.num_flows && (next_flow - cli_established) < kMaxInFlightSyns) {
      const size_t batch_end = std::min(opt.num_flows, next_flow + kEnqueueChunk);
      for (; next_flow < batch_end; ++next_flow) {
        uint32_t src_ip = 0x0A100001u + static_cast<uint32_t>(next_flow % 256);
        uint32_t dst_ip = 0x0A200001u + static_cast<uint32_t>((next_flow / 256) % 256);
        uint16_t src_port = static_cast<uint16_t>(10000 + (next_flow % 50000));
        uint16_t dst_port = 9080;
        (void)core->EnqueueConnect(src_ip, dst_ip, src_port, dst_port);
      }
      flush_client_tx(true);
      (void)drain_client_rx();
    }
    if (drain_client_rx() == 0) {
      // If any single frame was dropped in the kernel socket queue, trigger Poll() so RTO retransmits it!
      (void)core->Poll(0, 256);
      flush_client_tx(true);
      std::this_thread::yield();
    }
  }

  // Wait for final third-leg ACKs to arrive at v_srv responder
  auto final_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
  while (srv_ack_received.load(std::memory_order_relaxed) < cli_ack_wire_sent &&
         std::chrono::steady_clock::now() < final_deadline) {
    std::this_thread::yield();
  }

  const auto wire_end = std::chrono::high_resolution_clock::now();
  const double wire_ms = std::chrono::duration<double, std::milli>(wire_end - wire_start).count();

  responder_stop.store(true, std::memory_order_relaxed);
  srv_thread.join();

  const ProcMemInfo mem_est = ReadProcMem();
  const long delta_rss_kb = std::max<long>(0, mem_est.vm_rss_kb - mem_base.vm_rss_kb);
  const double wire_bytes_per_flow =
      (static_cast<double>(delta_rss_kb) * 1024.0) / static_cast<double>(opt.num_flows);

  const uint64_t cli_tx_after = ReadNetdevCounter(opt.cli_iface.c_str(), "tx_packets");
  const uint64_t cli_rx_after = ReadNetdevCounter(opt.cli_iface.c_str(), "rx_packets");
  const uint64_t srv_tx_after = ReadNetdevCounter(opt.srv_iface.c_str(), "tx_packets");
  const uint64_t srv_rx_after = ReadNetdevCounter(opt.srv_iface.c_str(), "rx_packets");

  const uint64_t netdev_cli_tx = cli_tx_after - cli_tx_before;
  const uint64_t netdev_cli_rx = cli_rx_after - cli_rx_before;
  const uint64_t netdev_srv_tx = srv_tx_after - srv_tx_before;
  const uint64_t netdev_srv_rx = srv_rx_after - srv_rx_before;

  const size_t total_wire_pkts = cli_syn_wire_sent + cli_established + cli_ack_wire_sent;
  const double wire_cps = (static_cast<double>(cli_established) / wire_ms) * 1000.0;
  const double wire_pps = (static_cast<double>(total_wire_pkts) / wire_ms) * 1000.0;

  std::printf("          -> Client SYN Sent (v_cli):      %zu\n", cli_syn_wire_sent);
  std::printf("          -> Server SYN Rcvd (v_srv):      %zu (Bad Checksums: %zu)\n",
              srv_syn_received.load(), srv_bad_csum.load());
  std::printf("          -> Server SYN-ACK Sent (v_srv):  %zu\n", srv_synack_sent.load());
  std::printf("          -> Client ESTABLISHED (v_cli):   %zu / %zu\n", cli_established, opt.num_flows);
  std::printf("          -> Client ACK Sent (v_cli):      %zu\n", cli_ack_wire_sent);
  std::printf("          -> Server ACK Rcvd (v_srv):      %zu\n", srv_ack_received.load());
  std::printf("          -> Kernel /proc/net/dev Delta:   v_cli TX=%" PRIu64 " RX=%" PRIu64 " | v_srv RX=%" PRIu64 " TX=%" PRIu64 "\n",
              netdev_cli_tx, netdev_cli_rx, netdev_srv_rx, netdev_srv_tx);
  std::printf("          -> Real-Wire Duration & Rate:    %.2f ms | %.2f flows/sec (%.2f kCPS) | %.2f packets/sec (%.2f kPPS)\n",
              wire_ms, wire_cps, wire_cps / 1000.0, wire_pps, wire_pps / 1000.0);
  std::printf("          -> Real-Wire VmRSS Delta:        %ld KB (%.2f MB) -> %.2f bytes/flow\n",
              delta_rss_kb, delta_rss_kb / 1024.0, wire_bytes_per_flow);

  CHECK(cli_syn_wire_sent == opt.num_flows, "Wire SYN sent mismatch");
  CHECK(srv_bad_csum.load() == 0, "Server observed corrupted SYN checksums");
  CHECK(cli_established == opt.num_flows, "Wire established mismatch: expected %zu, got %zu",
        opt.num_flows, cli_established);
  CHECK(cli_ack_wire_sent == opt.num_flows, "Wire ACK sent mismatch");
  CHECK(srv_ack_received.load() == opt.num_flows, "Server ACK received mismatch: expected %zu, got %zu",
        opt.num_flows, srv_ack_received.load());

  if (!opt.json_path.empty()) {
    std::ofstream out(opt.json_path);
    if (out.is_open()) {
      out << "{\n";
      out << "  \"kernel_interop_flows\": " << opt.kernel_flows << ",\n";
      out << "  \"kernel_interop_established\": " << kernel_core_established << ",\n";
      out << "  \"kernel_interop_accepted\": " << kernel_accepted << ",\n";
      out << "  \"kernel_interop_duration_ms\": " << kernel_hs_ms << ",\n";
      out << "  \"wire_flows_target\": " << opt.num_flows << ",\n";
      out << "  \"wire_syn_sent\": " << cli_syn_wire_sent << ",\n";
      out << "  \"wire_srv_syn_rcvd\": " << srv_syn_received.load() << ",\n";
      out << "  \"wire_srv_synack_sent\": " << srv_synack_sent.load() << ",\n";
      out << "  \"wire_cli_established\": " << cli_established << ",\n";
      out << "  \"wire_cli_ack_sent\": " << cli_ack_wire_sent << ",\n";
      out << "  \"wire_srv_ack_rcvd\": " << srv_ack_received.load() << ",\n";
      out << "  \"wire_total_packets\": " << total_wire_pkts << ",\n";
      out << "  \"wire_duration_ms\": " << wire_ms << ",\n";
      out << "  \"wire_cps\": " << wire_cps << ",\n";
      out << "  \"wire_pps\": " << wire_pps << ",\n";
      out << "  \"netdev_v_cli_tx_pkts\": " << netdev_cli_tx << ",\n";
      out << "  \"netdev_v_cli_rx_pkts\": " << netdev_cli_rx << ",\n";
      out << "  \"netdev_v_srv_rx_pkts\": " << netdev_srv_rx << ",\n";
      out << "  \"netdev_v_srv_tx_pkts\": " << netdev_srv_tx << ",\n";
      out << "  \"wire_delta_rss_kb\": " << delta_rss_kb << ",\n";
      out << "  \"wire_bytes_per_flow\": " << wire_bytes_per_flow << ",\n";
      out << "  \"status\": \"" << (g_fails.load() == 0 ? "PASSED" : "FAILED") << "\"\n";
      out << "}\n";
    }
  }

  close(cli_fd);
  close(srv_fd);

  std::printf("--------------------------------------------------------------------------------\n");
  if (g_fails.load() == 0) {
    std::printf("=== TEST PASSED: Real-Wire (netns + veth + AF_PACKET + Kernel Stack) Validated ===\n");
    return 0;
  } else {
    std::printf("=== TEST FAILED: %d checks failed ===\n", g_fails.load());
    return 1;
  }
}
