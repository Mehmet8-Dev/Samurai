#include "tcp_dataplane_ffi.h"

#include "tcp_dataplane_core.hpp"

#include <errno.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

// af_packet: the kernel-socket wire backend used to run the custom_tcp
// dataplane on commodity NICs (no AF_XDP/DPDK). Self-guarded extern "C" header.
#include "af_packet.h"

namespace ddos_samurai::tcpdp {
namespace {

TcpDataplaneCore& Core() {
  static TcpDataplaneCore* core = new TcpDataplaneCore();
  return *core;
}

// ---- af_packet wire pump (commodity-NIC custom_tcp transport) --------------
//
// The dataplane core is backend-agnostic: it produces MAC-less L2 frames into a
// TX ring and ingests inbound L2 frames. This pump bridges that ring to the wire
// over kernel sockets — an af_packet RX pump feeds captured frames into the TCP
// state machine, and a TX thread drains the ring, completes the Ethernet header
// with the interface's source MAC (and a configured/broadcast destination MAC),
// and transmits via AF_PACKET TX_RING.
struct AfPacketWirePump {
  std::atomic<bool> run{false};
  std::thread tx_thread;
  std::string iface;
  uint8_t src_mac[6]{};
  uint8_t dst_mac[6]{};
};

AfPacketWirePump* g_wire_pump = nullptr;

bool ResolveIfaceMac(const char* iface, uint8_t out[6]) {
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return false;
  struct ifreq ifr;
  std::memset(&ifr, 0, sizeof(ifr));
  std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  const bool ok = ::ioctl(fd, SIOCGIFHWADDR, &ifr) == 0;
  if (ok) std::memcpy(out, ifr.ifr_hwaddr.sa_data, 6);
  ::close(fd);
  return ok;
}

bool ParseMac(const char* s, uint8_t out[6]) {
  if (!s || !s[0]) return false;
  unsigned int b[6];
  if (std::sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
    return false;
  }
  for (int i = 0; i < 6; ++i) out[i] = static_cast<uint8_t>(b[i] & 0xffu);
  return true;
}

void RxIngestCb(void* /*user*/, const uint8_t* frame, uint32_t len) {
  (void)Core().IngestRxFrame(frame, static_cast<size_t>(len));
}

void TxPumpLoop(AfPacketWirePump* p) {
  std::vector<uint8_t> batch;
  while (p->run.load(std::memory_order_relaxed)) {
    const uint8_t* base = nullptr;
    uint32_t count = 0;
    size_t psize = 0;
    size_t stride = 0;
    if (Core().PeekTxPacketsStrided(64, &base, &count, &psize, &stride) &&
        base != nullptr && count > 0 && psize >= 14) {
      // Compact the strided ring slice into contiguous packet_size frames and
      // complete the (dst,src) Ethernet MACs the dataplane left zeroed.
      batch.resize(static_cast<size_t>(count) * psize);
      for (uint32_t i = 0; i < count; ++i) {
        uint8_t* dst = batch.data() + static_cast<size_t>(i) * psize;
        std::memcpy(dst, base + static_cast<size_t>(i) * stride, psize);
        std::memcpy(dst, p->dst_mac, 6);
        std::memcpy(dst + 6, p->src_mac, 6);
      }
      afpkt_tx_metrics_t metrics;
      char err[64];
      (void)afpkt_send_ring(p->iface.c_str(), batch.data(), batch.size(),
                            static_cast<int>(psize), static_cast<int>(count),
                            p->src_mac, &metrics, err, sizeof(err));
      (void)Core().ConsumeTxPackets(count);
    } else {
      std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
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

int tcpdp_peek_tx_packets_strided(
    uint32_t max_packets,
    const uint8_t** out_base,
    uint32_t* out_count,
    size_t* out_packet_size,
    size_t* out_stride) {
  if (!out_base || !out_count || !out_packet_size || !out_stride) {
    return -1;
  }
  *out_base = nullptr;
  *out_count = 0;
  *out_packet_size = 0;
  *out_stride = 0;
  if (!ddos_samurai::tcpdp::Core().PeekTxPacketsStrided(
          max_packets, out_base, out_count, out_packet_size, out_stride)) {
    *out_base = nullptr;
    *out_count = 0;
    *out_packet_size = 0;
    *out_stride = 0;
    return -1;
  }
  return 0;
}

int tcpdp_consume_tx_packets(uint32_t max_packets, uint32_t* out_consumed) {
  if (!out_consumed) {
    return -1;
  }
  *out_consumed = ddos_samurai::tcpdp::Core().ConsumeTxPackets(max_packets);
  return 0;
}

int tcpdp_ingest_dpdk_rx_burst(void** mbufs, uint16_t count, uint32_t* out_ingested) {
  if (!mbufs || !out_ingested) {
    return -1;
  }
  *out_ingested = ddos_samurai::tcpdp::Core().IngestDpdkRxBurst(mbufs, count);
  return 0;
}

int tcpdp_drain_dpdk_tx_burst(void* mempool, void** out_mbufs, uint16_t max_burst, uint32_t* out_produced) {
  if (!out_mbufs || !out_produced) {
    return -1;
  }
  *out_produced = ddos_samurai::tcpdp::Core().DrainDpdkTxBurst(mempool, out_mbufs, max_burst);
  return 0;
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
  using namespace ddos_samurai::tcpdp;
  if (!iface || !iface[0] || !out_handler_id) {
    errno = EINVAL;
    return -1;
  }
  if (g_wire_pump != nullptr) {  // idempotent: one wire pump per process
    *out_handler_id = 1;
    return 0;
  }

  auto* p = new AfPacketWirePump();
  p->iface = iface;
  if (!ResolveIfaceMac(iface, p->src_mac)) {
    std::memset(p->src_mac, 0, 6);  // best effort; kernel may still source it
  }
  if (!ParseMac(std::getenv("SAMURAI_CUSTOM_TCP_DST_MAC"), p->dst_mac)) {
    std::memset(p->dst_mac, 0xff, 6);  // broadcast default (same-segment lab use)
  }

  // RX: capture inbound frames into the TCP state machine (needs CAP_NET_RAW).
  if (afpkt_start_rx_pump(iface, &RxIngestCb, nullptr) != 0) {
    delete p;
    errno = EACCES;
    return -1;
  }

  // TX: drain the dataplane TX ring onto the wire as MAC-completed L2 frames.
  p->run.store(true, std::memory_order_relaxed);
  p->tx_thread = std::thread(TxPumpLoop, p);
  g_wire_pump = p;
  *out_handler_id = 1;
  return 0;
}

int tcpdp_stop_rx_handler(int32_t /*handler_id*/) {
  using namespace ddos_samurai::tcpdp;
  if (g_wire_pump == nullptr) {
    return 0;
  }
  g_wire_pump->run.store(false, std::memory_order_relaxed);
  if (g_wire_pump->tx_thread.joinable()) {
    g_wire_pump->tx_thread.join();
  }
  afpkt_stop_rx_handler();
  afpkt_cleanup_ring();
  delete g_wire_pump;
  g_wire_pump = nullptr;
  return 0;
}

}
