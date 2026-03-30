#include "l4_state_engine_ffi.h"

#include "l4_state_engine_core.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ddos_samurai::l4se {
namespace {

using Core = L4StateEngineCore;

Core& Engine() {
  static Core* core = new Core();
  return *core;
}

constexpr uint8_t kTcpFlagSyn = 0x02;
constexpr uint8_t kTcpFlagAck = 0x10;

inline uint16_t ReadBe16(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}

inline uint32_t ReadBe32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint16_t IpChecksum(const uint8_t* ptr, int nbytes) {
  uint32_t sum = 0;
  for (int i = 0; i < nbytes; i += 2) {
    if (i + 1 < nbytes) {
      sum += (static_cast<uint32_t>(ptr[i]) << 8) | static_cast<uint32_t>(ptr[i + 1]);
    } else {
      sum += static_cast<uint32_t>(ptr[i]) << 8;
    }
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFFU) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum);
}

uint16_t TcpChecksum(const uint8_t* ip_header, const uint8_t* tcp_header, int tcp_len) {
  uint32_t sum = 0;
  const uint8_t* src_ip = ip_header + 12;
  const uint8_t* dst_ip = ip_header + 16;

  sum += (static_cast<uint32_t>(src_ip[0]) << 8) | static_cast<uint32_t>(src_ip[1]);
  sum += (static_cast<uint32_t>(src_ip[2]) << 8) | static_cast<uint32_t>(src_ip[3]);
  sum += (static_cast<uint32_t>(dst_ip[0]) << 8) | static_cast<uint32_t>(dst_ip[1]);
  sum += (static_cast<uint32_t>(dst_ip[2]) << 8) | static_cast<uint32_t>(dst_ip[3]);
  sum += 6;
  sum += static_cast<uint32_t>(tcp_len);

  for (int i = 0; i < tcp_len; i += 2) {
    if (i + 1 < tcp_len) {
      sum += (static_cast<uint32_t>(tcp_header[i]) << 8) | static_cast<uint32_t>(tcp_header[i + 1]);
    } else {
      sum += static_cast<uint32_t>(tcp_header[i]) << 8;
    }
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFFU) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum);
}

bool ParseSynAckFrame(
    const uint8_t* pkt,
    size_t pkt_len,
    int* out_ip_offset,
    uint32_t* out_src_ip,
    uint32_t* out_dst_ip,
    uint16_t* out_src_port,
    uint16_t* out_dst_port,
    uint32_t* out_seq,
    uint32_t* out_ack) {
  if (!pkt || pkt_len < 54) {
    return false;
  }
  int ip_offset = -1;
  if (pkt_len >= 18) {
    const uint16_t eth_type = ReadBe16(pkt + 12);
    if (eth_type == 0x8100 && pkt_len >= 22) {
      const uint16_t inner_type = ReadBe16(pkt + 16);
      if (inner_type == 0x0800) {
        ip_offset = 18;
      }
    } else if (eth_type == 0x0800) {
      ip_offset = 14;
    }
  }
  if (ip_offset < 0) {
    return false;
  }
  if (pkt_len < static_cast<size_t>(ip_offset + 20)) {
    return false;
  }
  const uint8_t* ip = pkt + ip_offset;
  if (((ip[0] >> 4) & 0x0F) != 4) {
    return false;
  }
  const uint8_t ihl = static_cast<uint8_t>((ip[0] & 0x0F) * 4);
  if (ihl < 20 || pkt_len < static_cast<size_t>(ip_offset + ihl + 20)) {
    return false;
  }
  if (ip[9] != 6) {
    return false;
  }
  const uint8_t* tcp = ip + ihl;
  const uint8_t flags = tcp[13];
  if ((flags & (kTcpFlagSyn | kTcpFlagAck)) != (kTcpFlagSyn | kTcpFlagAck)) {
    return false;
  }

  if (out_ip_offset) {
    *out_ip_offset = ip_offset;
  }
  if (out_src_ip) {
    *out_src_ip = ReadBe32(ip + 12);
  }
  if (out_dst_ip) {
    *out_dst_ip = ReadBe32(ip + 16);
  }
  if (out_src_port) {
    *out_src_port = ReadBe16(tcp + 0);
  }
  if (out_dst_port) {
    *out_dst_port = ReadBe16(tcp + 2);
  }
  if (out_seq) {
    *out_seq = ReadBe32(tcp + 4);
  }
  if (out_ack) {
    *out_ack = ReadBe32(tcp + 8);
  }
  return true;
}

void BuildAckPacket(
    const uint8_t* rx_pkt,
    size_t rx_len,
    int ip_offset,
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t seq,
    uint32_t ack,
    uint16_t window,
    uint8_t ttl,
    std::array<uint8_t, 64>* out_pkt,
    size_t* out_len) {
  if (!rx_pkt || !out_pkt || !out_len) {
    return;
  }

  const bool vlan = (ip_offset == 18);
  const size_t ack_len = vlan ? 58U : 54U;
  out_pkt->fill(0);

  std::memcpy(out_pkt->data(), rx_pkt + 6, 6);
  std::memcpy(out_pkt->data() + 6, rx_pkt, 6);

  if (vlan) {
    (*out_pkt)[12] = 0x81;
    (*out_pkt)[13] = 0x00;
    (*out_pkt)[14] = rx_pkt[14];
    (*out_pkt)[15] = rx_pkt[15];
    (*out_pkt)[16] = 0x08;
    (*out_pkt)[17] = 0x00;
  } else {
    (*out_pkt)[12] = 0x08;
    (*out_pkt)[13] = 0x00;
  }

  const int l3 = ip_offset;
  uint8_t* ip = out_pkt->data() + l3;
  uint8_t* tcp = ip + 20;

  ip[0] = 0x45;
  ip[1] = 0x00;
  const uint16_t ip_total_len = htons(40);
  std::memcpy(ip + 2, &ip_total_len, sizeof(ip_total_len));
  ip[4] = 0;
  ip[5] = 0;
  ip[6] = 0;
  ip[7] = 0;
  ip[8] = ttl > 0 ? ttl : 64;
  ip[9] = 6;
  ip[10] = 0;
  ip[11] = 0;

  const uint32_t src_ip_be = htonl(dst_ip);
  const uint32_t dst_ip_be = htonl(src_ip);
  std::memcpy(ip + 12, &src_ip_be, sizeof(src_ip_be));
  std::memcpy(ip + 16, &dst_ip_be, sizeof(dst_ip_be));

  const uint16_t src_port_be = htons(dst_port);
  const uint16_t dst_port_be = htons(src_port);
  const uint32_t seq_be = htonl(seq);
  const uint32_t ack_be = htonl(ack);

  std::memcpy(tcp + 0, &src_port_be, sizeof(src_port_be));
  std::memcpy(tcp + 2, &dst_port_be, sizeof(dst_port_be));
  std::memcpy(tcp + 4, &seq_be, sizeof(seq_be));
  std::memcpy(tcp + 8, &ack_be, sizeof(ack_be));
  tcp[12] = 0x50;
  tcp[13] = 0x10;
  const uint16_t win_be = htons(window > 0 ? window : 64240);
  std::memcpy(tcp + 14, &win_be, sizeof(win_be));
  tcp[16] = 0;
  tcp[17] = 0;
  tcp[18] = 0;
  tcp[19] = 0;

  const uint16_t ip_cksum = htons(IpChecksum(ip, 20));
  std::memcpy(ip + 10, &ip_cksum, sizeof(ip_cksum));
  const uint16_t tcp_cksum = htons(TcpChecksum(ip, tcp, 20));
  std::memcpy(tcp + 16, &tcp_cksum, sizeof(tcp_cksum));

  *out_len = ack_len;
  (void)rx_len;
}

struct RxHandlerContext {
  int32_t id = 0;
  int sockfd = -1;
  std::string iface;
  std::atomic<bool> running{false};
  std::thread worker;
  struct sockaddr_ll bind_addr {};
};

std::atomic<int32_t> g_next_handler_id{1};
std::mutex g_handlers_mu;
std::unordered_map<int32_t, std::unique_ptr<RxHandlerContext>> g_handlers;

void RxLoop(RxHandlerContext* ctx) {
  if (!ctx) {
    return;
  }

  std::array<uint8_t, 2048> frame{};
  struct sockaddr_ll rx_addr {};
  socklen_t rx_addr_len = sizeof(rx_addr);

  while (ctx->running.load(std::memory_order_acquire)) {
    ssize_t n = recvfrom(
        ctx->sockfd,
        frame.data(),
        frame.size(),
        0,
        reinterpret_cast<struct sockaddr*>(&rx_addr),
        &rx_addr_len);

    if (n <= 0) {
      if (!ctx->running.load(std::memory_order_acquire)) {
        break;
      }
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      continue;
    }

    uint32_t updated = 0;
    (void)l4se_ingest_rx_frame(frame.data(), static_cast<size_t>(n), &updated);
    if (updated == 0) {
      continue;
    }

    int ip_offset = -1;
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    if (!ParseSynAckFrame(
            frame.data(),
            static_cast<size_t>(n),
            &ip_offset,
            &src_ip,
            &dst_ip,
            &src_port,
            &dst_port,
            &seq,
            &ack)) {
      continue;
    }

    uint32_t state_seq = ack;
    uint32_t state_ack = seq + 1U;
    uint8_t state_legacy = 0;
    uint16_t state_win = 64240;
    uint16_t state_mss = 1460;
    uint8_t state_ttl = 64;
    uint8_t found = 0;
    (void)l4se_get_tcp_state(
        dst_ip,
        dst_port,
        &state_seq,
        &state_ack,
        &state_legacy,
        &state_win,
        &state_mss,
        &state_ttl,
        &found);

    std::array<uint8_t, 64> ack_pkt{};
    size_t ack_len = 0;
    BuildAckPacket(
        frame.data(),
        static_cast<size_t>(n),
        ip_offset,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        found ? state_seq : ack,
        found ? state_ack : (seq + 1U),
        state_win,
        state_ttl,
        &ack_pkt,
        &ack_len);

    if (ack_len > 0) {
      (void)sendto(
          ctx->sockfd,
          ack_pkt.data(),
          ack_len,
          0,
          reinterpret_cast<const struct sockaddr*>(&ctx->bind_addr),
          sizeof(ctx->bind_addr));
    }
  }
}

}  // namespace
}  // namespace ddos_samurai::l4se

extern "C" {

int l4se_configure(uint32_t table_size, uint32_t lock_count, uint32_t timeout_sec) {
  if (!ddos_samurai::l4se::Engine().Configure(table_size, lock_count, timeout_sec)) {
    return -1;
  }
  return 0;
}

int l4se_set_mimicry(uint16_t window, uint16_t mss, uint8_t ttl) {
  ddos_samurai::l4se::Engine().SetMimicry(window, mss, ttl);
  return 0;
}

int l4se_ingest_tx_packets(const uint8_t* packets, size_t packet_size, size_t count, uint32_t* out_updated) {
  if (!packets || packet_size == 0 || count == 0 || !out_updated) {
    return -1;
  }
  const auto result = ddos_samurai::l4se::Engine().IngestTxPackets(packets, packet_size, count);
  *out_updated = result.updated;
  return 0;
}

int l4se_ingest_rx_frame(const uint8_t* frame, size_t frame_len, uint32_t* out_updated) {
  if (!frame || frame_len == 0 || !out_updated) {
    return -1;
  }
  const auto result = ddos_samurai::l4se::Engine().IngestRxFrame(frame, frame_len);
  *out_updated = result.updated;
  return 0;
}

int l4se_get_states_batch(
    uint32_t src_ip,
    uint16_t start_port,
    uint32_t count,
    uint32_t* out_seq,
    uint32_t* out_ack,
    uint8_t* out_state,
    uint16_t* out_window,
    uint16_t* out_mss,
    uint8_t* out_ttl,
    uint32_t* out_found) {
  if (!out_seq || !out_ack || !out_state || !out_window || !out_mss || !out_ttl || !out_found) {
    return -1;
  }
  *out_found = ddos_samurai::l4se::Engine().GetStatesBatch(
      src_ip,
      start_port,
      count,
      out_seq,
      out_ack,
      out_state,
      out_window,
      out_mss,
      out_ttl);
  return 0;
}

int l4se_get_tcp_state(
    uint32_t src_ip,
    uint16_t src_port,
    uint32_t* out_seq,
    uint32_t* out_ack,
    uint8_t* out_state,
    uint16_t* out_window,
    uint16_t* out_mss,
    uint8_t* out_ttl,
    uint8_t* out_found) {
  if (!out_seq || !out_ack || !out_state || !out_window || !out_mss || !out_ttl || !out_found) {
    return -1;
  }
  const auto snapshot = ddos_samurai::l4se::Engine().GetTcpState(src_ip, src_port);
  *out_seq = snapshot.seq;
  *out_ack = snapshot.ack;
  *out_state = snapshot.state;
  *out_window = snapshot.window;
  *out_mss = snapshot.mss;
  *out_ttl = snapshot.ttl;
  *out_found = snapshot.found ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0);
  return 0;
}

int l4se_sweep(uint32_t max_scan, uint32_t* out_removed) {
  if (!out_removed) {
    return -1;
  }
  *out_removed = ddos_samurai::l4se::Engine().Sweep(max_scan);
  return 0;
}

int l4se_stats_snapshot(l4se_stats_snapshot_t* out_stats) {
  if (!out_stats) {
    return -1;
  }
  const auto snap = ddos_samurai::l4se::Engine().Snapshot();
  out_stats->table_size = snap.table_size;
  out_stats->lock_count = snap.lock_count;
  out_stats->timeout_sec = snap.timeout_sec;
  out_stats->active_entries = snap.active_entries;
  out_stats->timeout_evictions = snap.timeout_evictions;
  out_stats->overwrites = snap.overwrites;
  out_stats->sweeps = snap.sweeps;
  out_stats->last_sweep_removed = snap.last_sweep_removed;
  out_stats->sweep_cursor = snap.sweep_cursor;
  out_stats->transition_total = snap.transition_total;
  for (size_t i = 0; i < snap.state_counts.size(); ++i) {
    out_stats->state_counts[i] = snap.state_counts[i];
  }
  return 0;
}

int l4se_start_rx_handler(const char* iface, int32_t* out_handler_id) {
  if (!iface || !iface[0] || !out_handler_id) {
    return -1;
  }

  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    return -1;
  }

  struct timeval tv {};
  tv.tv_sec = 0;
  tv.tv_usec = 200000;
  (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  int ignore_outgoing = 1;
  (void)setsockopt(sock, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_outgoing, sizeof(ignore_outgoing));

  struct sockaddr_ll sll {};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = if_nametoindex(iface);
  if (sll.sll_ifindex <= 0) {
    close(sock);
    return -1;
  }
  if (bind(sock, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
    close(sock);
    return -1;
  }

  auto ctx = std::make_unique<ddos_samurai::l4se::RxHandlerContext>();
  ctx->id = ddos_samurai::l4se::g_next_handler_id.fetch_add(1, std::memory_order_relaxed);
  ctx->sockfd = sock;
  ctx->iface = iface;
  ctx->bind_addr = sll;
  ctx->running.store(true, std::memory_order_release);
  ddos_samurai::l4se::RxHandlerContext* raw = ctx.get();
  ctx->worker = std::thread([raw]() { ddos_samurai::l4se::RxLoop(raw); });

  {
    std::lock_guard<std::mutex> guard(ddos_samurai::l4se::g_handlers_mu);
    ddos_samurai::l4se::g_handlers.emplace(ctx->id, std::move(ctx));
  }

  *out_handler_id = raw->id;
  return 0;
}

int l4se_stop_rx_handler(int32_t handler_id) {
  std::unique_ptr<ddos_samurai::l4se::RxHandlerContext> ctx;
  {
    std::lock_guard<std::mutex> guard(ddos_samurai::l4se::g_handlers_mu);
    auto it = ddos_samurai::l4se::g_handlers.find(handler_id);
    if (it == ddos_samurai::l4se::g_handlers.end()) {
      return -1;
    }
    ctx = std::move(it->second);
    ddos_samurai::l4se::g_handlers.erase(it);
  }

  if (ctx) {
    ctx->running.store(false, std::memory_order_release);
    if (ctx->sockfd >= 0) {
      shutdown(ctx->sockfd, SHUT_RDWR);
      close(ctx->sockfd);
      ctx->sockfd = -1;
    }
    if (ctx->worker.joinable()) {
      ctx->worker.join();
    }
  }
  return 0;
}

void l4se_shutdown_all_handlers(void) {
  std::vector<int32_t> ids;
  {
    std::lock_guard<std::mutex> guard(ddos_samurai::l4se::g_handlers_mu);
    ids.reserve(ddos_samurai::l4se::g_handlers.size());
    for (const auto& kv : ddos_samurai::l4se::g_handlers) {
      ids.push_back(kv.first);
    }
  }
  for (const auto id : ids) {
    (void)l4se_stop_rx_handler(id);
  }
}

}  // extern "C"
