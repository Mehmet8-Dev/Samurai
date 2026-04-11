#include "tcp_dataplane_ffi.h"

#include "tcp_dataplane_core.hpp"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ddos_samurai::tcpdp {
namespace {

TcpDataplaneCore& Core() {
  static TcpDataplaneCore* core = new TcpDataplaneCore();
  return *core;
}

struct RxHandlerContext {
  int32_t id = 0;
  int sockfd = -1;
  std::string iface;
  std::atomic<bool> running{false};
  std::thread worker;
};

std::atomic<int32_t> g_next_handler_id{1};
std::mutex g_handlers_mu;
std::unordered_map<int32_t, std::unique_ptr<RxHandlerContext>> g_handlers;

void RxLoop(RxHandlerContext* ctx) {
  if (!ctx) {
    return;
  }
  std::array<uint8_t, 2048> frame{};
  while (ctx->running.load(std::memory_order_acquire)) {
    ssize_t n = recvfrom(ctx->sockfd, frame.data(), frame.size(), 0, nullptr, nullptr);
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
    (void)tcpdp_ingest_rx_frame(frame.data(), static_cast<size_t>(n), &updated);
  }
}

}  // namespace
}  // namespace ddos_samurai::tcpdp

extern "C" {

int tcpdp_configure(const tcpdp_config_t* config) {
  if (!config) {
    return -1;
  }
  ddos_samurai::tcpdp::TcpDpConfig cfg;
  cfg.mode = config->mode ? config->mode : "off";
  cfg.backend = config->backend ? config->backend : "af_xdp";
  cfg.initial_rto_ms = config->initial_rto_ms;
  cfg.max_retransmits = config->max_retransmits;
  cfg.connect_timeout_ms = config->connect_timeout_ms;
  cfg.idle_timeout_ms = config->idle_timeout_ms;
  return ddos_samurai::tcpdp::Core().Configure(cfg) ? 0 : -1;
}

int tcpdp_ingest_tx_packets(const uint8_t* packets, size_t packet_size, size_t count, uint32_t* out_updated) {
  if (!packets || packet_size == 0 || count == 0 || !out_updated) {
    return -1;
  }
  *out_updated = ddos_samurai::tcpdp::Core().IngestTxPackets(packets, packet_size, count);
  return 0;
}

int tcpdp_enqueue_connect(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint64_t* out_flow_id) {
  if (!out_flow_id) {
    return -1;
  }
  *out_flow_id = ddos_samurai::tcpdp::Core().EnqueueConnect(src_ip, dst_ip, src_port, dst_port);
  return *out_flow_id == 0 ? -1 : 0;
}

int tcpdp_enqueue_send(uint64_t flow_id, const uint8_t* payload, size_t payload_len, uint32_t* out_queued_bytes) {
  if (!payload || payload_len == 0 || !out_queued_bytes) {
    return -1;
  }
  *out_queued_bytes = ddos_samurai::tcpdp::Core().EnqueueSend(flow_id, payload, payload_len);
  return *out_queued_bytes == 0 ? -1 : 0;
}

int tcpdp_ingest_rx_frame(const uint8_t* frame, size_t frame_len, uint32_t* out_updated) {
  if (!frame || frame_len == 0 || !out_updated) {
    return -1;
  }
  *out_updated = ddos_samurai::tcpdp::Core().IngestRxFrame(frame, frame_len);
  return 0;
}

int tcpdp_poll(uint64_t now_ns, uint32_t budget, uint32_t* out_actions) {
  if (!out_actions) {
    return -1;
  }
  *out_actions = ddos_samurai::tcpdp::Core().Poll(now_ns, budget);
  return 0;
}

int tcpdp_drain_tx_packets(uint32_t max_packets, const uint8_t*** out_packets, size_t** out_packet_lens, uint32_t* out_count) {
  if (!out_packets || !out_packet_lens || !out_count) {
    return -1;
  }
  auto drained = ddos_samurai::tcpdp::Core().DrainTxPackets(max_packets);
  *out_count = static_cast<uint32_t>(drained.size());
  if (drained.empty()) {
    *out_packets = nullptr;
    *out_packet_lens = nullptr;
    return 0;
  }

  auto** packets = new const uint8_t*[*out_count];
  auto* lens = new size_t[*out_count];
  for (uint32_t i = 0; i < *out_count; ++i) {
    lens[i] = drained[i].size();
    auto* copy = new uint8_t[lens[i]];
    std::memcpy(copy, drained[i].data(), lens[i]);
    packets[i] = copy;
  }
  *out_packets = packets;
  *out_packet_lens = lens;
  return 0;
}

void tcpdp_free_drained_packets(const uint8_t** packets, size_t* packet_lens, uint32_t count) {
  (void)packet_lens;
  if (!packets) {
    return;
  }
  for (uint32_t i = 0; i < count; ++i) {
    delete[] packets[i];
  }
  delete[] packets;
  delete[] packet_lens;
}

int tcpdp_collect_completions(tcpdp_completion_t** out_items, uint32_t* out_count) {
  if (!out_items || !out_count) {
    return -1;
  }
  auto items = ddos_samurai::tcpdp::Core().CollectCompletions();
  *out_count = static_cast<uint32_t>(items.size());
  if (items.empty()) {
    *out_items = nullptr;
    return 0;
  }
  auto* raw = new tcpdp_completion_t[*out_count];
  for (uint32_t i = 0; i < *out_count; ++i) {
    raw[i].flow_id = items[i].flow_id;
    raw[i].state = items[i].state;
    raw[i].success = items[i].success;
    if (items[i].event) {
      const size_t len = std::strlen(items[i].event);
      auto* str = new char[len + 1];
      std::memcpy(str, items[i].event, len + 1);
      raw[i].event = str;
    } else {
      raw[i].event = nullptr;
    }
  }
  *out_items = raw;
  return 0;
}

void tcpdp_free_completions(tcpdp_completion_t* items, uint32_t count) {
  if (!items) {
    return;
  }
  for (uint32_t i = 0; i < count; ++i) {
    delete[] items[i].event;
  }
  delete[] items;
}

int tcpdp_collect_rx_payloads(tcpdp_rx_payload_t** out_items, uint32_t* out_count) {
  if (!out_items || !out_count) {
    return -1;
  }
  auto items = ddos_samurai::tcpdp::Core().CollectRxPayloads();
  *out_count = static_cast<uint32_t>(items.size());
  if (items.empty()) {
    *out_items = nullptr;
    return 0;
  }
  auto* raw = new tcpdp_rx_payload_t[*out_count];
  for (uint32_t i = 0; i < *out_count; ++i) {
    raw[i].flow_id = items[i].flow_id;
    raw[i].payload_len = items[i].payload.size();
    if (raw[i].payload_len > 0) {
      auto* payload = new uint8_t[raw[i].payload_len];
      std::memcpy(payload, items[i].payload.data(), raw[i].payload_len);
      raw[i].payload = payload;
    } else {
      raw[i].payload = nullptr;
    }
  }
  *out_items = raw;
  return 0;
}

void tcpdp_free_rx_payloads(tcpdp_rx_payload_t* items, uint32_t count) {
  if (!items) {
    return;
  }
  for (uint32_t i = 0; i < count; ++i) {
    delete[] items[i].payload;
  }
  delete[] items;
}

int tcpdp_snapshot_stats(tcpdp_stats_snapshot_t* out_stats) {
  if (!out_stats) {
    return -1;
  }
  const auto stats = ddos_samurai::tcpdp::Core().SnapshotStats();
  out_stats->flows_active = stats.flows_active;
  out_stats->connect_attempts = stats.connect_attempts;
  out_stats->connect_established = stats.connect_established;
  out_stats->retransmit_count = stats.retransmit_count;
  out_stats->timeout_close_count = stats.timeout_close_count;
  out_stats->connect_timeout_count = stats.connect_timeout_count;
  out_stats->idle_timeout_count = stats.idle_timeout_count;
  out_stats->retransmit_exhausted_count = stats.retransmit_exhausted_count;
  out_stats->rx_ack_count = stats.rx_ack_count;
  out_stats->dup_ack_count = stats.dup_ack_count;
  out_stats->partial_ack_count = stats.partial_ack_count;
  out_stats->fast_retransmit_count = stats.fast_retransmit_count;
  out_stats->unexpected_ack_count = stats.unexpected_ack_count;
  out_stats->tx_data_bytes = stats.tx_data_bytes;
  out_stats->rx_data_bytes = stats.rx_data_bytes;
  out_stats->tx_packets_queued = stats.tx_packets_queued;
  out_stats->tx_packets_drained = stats.tx_packets_drained;
  out_stats->tx_packets_sent = stats.tx_packets_sent;
  out_stats->poll_calls = stats.poll_calls;
  out_stats->rx_frames = stats.rx_frames;
  out_stats->unexpected_rx = stats.unexpected_rx;
  out_stats->out_of_order_rx_count = stats.out_of_order_rx_count;
  out_stats->peer_rst_count = stats.peer_rst_count;
  out_stats->peer_fin_count = stats.peer_fin_count;
  return 0;
}

int tcpdp_get_flow(uint64_t flow_id, tcpdp_flow_snapshot_t* out_flow) {
  if (!out_flow) {
    return -1;
  }
  const auto flow = ddos_samurai::tcpdp::Core().GetFlow(flow_id);
  out_flow->flow_id = flow.flow_id;
  out_flow->src_ip = flow.src_ip;
  out_flow->dst_ip = flow.dst_ip;
  out_flow->src_port = flow.src_port;
  out_flow->dst_port = flow.dst_port;
  out_flow->iss = flow.iss;
  out_flow->snd_una = flow.snd_una;
  out_flow->snd_nxt = flow.snd_nxt;
  out_flow->rcv_nxt = flow.rcv_nxt;
  out_flow->peer_window = flow.peer_window;
  out_flow->local_window = flow.local_window;
  out_flow->mss = flow.mss;
  out_flow->ttl = flow.ttl;
  out_flow->state = flow.state;
  out_flow->retransmit_count = flow.retransmit_count;
  out_flow->rto_deadline_ns = flow.rto_deadline_ns;
  out_flow->last_activity_ns = flow.last_activity_ns;
  out_flow->found = flow.found ? 1 : 0;
  return 0;
}

int tcpdp_start_rx_handler(const char* iface, int32_t* out_handler_id) {
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

  auto ctx = std::make_unique<ddos_samurai::tcpdp::RxHandlerContext>();
  ctx->id = ddos_samurai::tcpdp::g_next_handler_id.fetch_add(1, std::memory_order_relaxed);
  ctx->sockfd = sock;
  ctx->iface = iface;
  ctx->running.store(true, std::memory_order_release);
  ddos_samurai::tcpdp::RxHandlerContext* raw = ctx.get();
  ctx->worker = std::thread([raw]() { ddos_samurai::tcpdp::RxLoop(raw); });

  {
    std::lock_guard<std::mutex> guard(ddos_samurai::tcpdp::g_handlers_mu);
    ddos_samurai::tcpdp::g_handlers.emplace(ctx->id, std::move(ctx));
  }

  *out_handler_id = raw->id;
  return 0;
}

int tcpdp_stop_rx_handler(int32_t handler_id) {
  std::unique_ptr<ddos_samurai::tcpdp::RxHandlerContext> ctx;
  {
    std::lock_guard<std::mutex> guard(ddos_samurai::tcpdp::g_handlers_mu);
    auto it = ddos_samurai::tcpdp::g_handlers.find(handler_id);
    if (it == ddos_samurai::tcpdp::g_handlers.end()) {
      return -1;
    }
    ctx = std::move(it->second);
    ddos_samurai::tcpdp::g_handlers.erase(it);
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

}
