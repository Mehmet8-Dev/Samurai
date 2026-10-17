#include "engine_internal.hpp"
#include "../xdp/xdp_native_api.h"
#include <dlfcn.h>
#ifdef SAMURAI_WITH_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

namespace ddos_samurai::l7_emu_native {

std::mutex& custom_tcp_registry_mu() {
  static std::mutex mu;
  return mu;
}

std::mutex& custom_tcp_shard_stats_mu() {
  static std::mutex mu;
  return mu;
}

void accumulate_custom_tcp_shard_stats(NativeRuntime& runtime) {
  tcpdp_stats_snapshot_t s{};
  if (tcpdp_snapshot_stats(&s) != 0) {
    return;
  }
  std::lock_guard<std::mutex> lk(custom_tcp_shard_stats_mu());
  auto& a = runtime.custom_tcp_shard_stats;
  a.flows_active += s.flows_active;
  a.connect_attempts += s.connect_attempts;
  a.connect_established += s.connect_established;
  a.retransmit_count += s.retransmit_count;
  a.timeout_close_count += s.timeout_close_count;
  a.connect_timeout_count += s.connect_timeout_count;
  a.idle_timeout_count += s.idle_timeout_count;
  a.retransmit_exhausted_count += s.retransmit_exhausted_count;
  a.rx_ack_count += s.rx_ack_count;
  a.dup_ack_count += s.dup_ack_count;
  a.partial_ack_count += s.partial_ack_count;
  a.fast_retransmit_count += s.fast_retransmit_count;
  a.unexpected_ack_count += s.unexpected_ack_count;
  a.tx_data_bytes += s.tx_data_bytes;
  a.rx_data_bytes += s.rx_data_bytes;
  a.peer_rst_count += s.peer_rst_count;
  a.peer_fin_count += s.peer_fin_count;
  runtime.custom_tcp_own_wire_used = true;
}

void unregister_custom_tcp_flow_binding(NativeRuntime& runtime, uint64_t flow_id) {
  if (flow_id == 0) {
    return;
  }
  const uint64_t sh_prefix = flow_id >> 40;
  if (sh_prefix > 0 && (sh_prefix - 1) < runtime.local_shards.size()) {
    runtime.local_shards[sh_prefix - 1].custom_tcp_flow_registry.erase(flow_id);
    return;
  }
  std::lock_guard<std::mutex> lk(custom_tcp_registry_mu());
  runtime.custom_tcp_flow_registry.erase(flow_id);
}

void register_custom_tcp_h1_flow_binding(
    NativeRuntime& runtime,
    std::size_t shard_idx,
    std::size_t lane_idx,
    H1Lane& lane) {
  if (!lane.conn || !is_custom_tcp_backend(lane.transport_backend)) {
    return;
  }
  if (lane.conn->custom_flow_id == 0) {
    return;
  }
  NativeRuntime::CustomTcpFlowBinding binding{};
  binding.kind = ReactorLaneKind::H1;
  binding.shard_idx = shard_idx;
  binding.lane_idx = lane_idx;
  binding.h1_lane = &lane;
#ifdef SAMURAI_WITH_NGHTTP2
  binding.h2_session = nullptr;
#endif
  const uint64_t sh_prefix = lane.conn->custom_flow_id >> 40;
  if (sh_prefix > 0 && (sh_prefix - 1) < runtime.local_shards.size()) {
    runtime.local_shards[sh_prefix - 1].custom_tcp_flow_registry[lane.conn->custom_flow_id] = binding;
    return;
  }
  std::lock_guard<std::mutex> lk(custom_tcp_registry_mu());
  runtime.custom_tcp_flow_registry[lane.conn->custom_flow_id] = binding;
}

NativeRuntime::CustomTcpFlowBinding* find_custom_tcp_flow_binding(
    NativeRuntime& runtime,
    uint64_t flow_id) {
  if (flow_id == 0) {
    return nullptr;
  }
  const uint64_t sh_prefix = flow_id >> 40;
  if (sh_prefix > 0 && (sh_prefix - 1) < runtime.local_shards.size()) {
    auto& reg = runtime.local_shards[sh_prefix - 1].custom_tcp_flow_registry;
    auto it = reg.find(flow_id);
    if (it == reg.end()) {
      return nullptr;
    }
    if (it->second.kind == ReactorLaneKind::H1) {
      H1Lane* lane = it->second.h1_lane;
      if (lane == nullptr || !lane->conn ||
          !is_custom_tcp_backend(lane->transport_backend) ||
          lane->conn->custom_flow_id != flow_id) {
        reg.erase(it);
        return nullptr;
      }
      return &it->second;
    }
#ifdef SAMURAI_WITH_NGHTTP2
    if (it->second.kind == ReactorLaneKind::H2) {
      if (it->second.h2_session == nullptr) {
        reg.erase(it);
        return nullptr;
      }
      return &it->second;
    }
#endif
    reg.erase(it);
    return nullptr;
  }
  std::lock_guard<std::mutex> lk(custom_tcp_registry_mu());
  auto it = runtime.custom_tcp_flow_registry.find(flow_id);
  if (it == runtime.custom_tcp_flow_registry.end()) {
    return nullptr;
  }
  if (it->second.kind == ReactorLaneKind::H1) {
    H1Lane* lane = it->second.h1_lane;
    if (lane == nullptr || !lane->conn ||
        !is_custom_tcp_backend(lane->transport_backend) ||
        lane->conn->custom_flow_id != flow_id) {
      runtime.custom_tcp_flow_registry.erase(it);
      return nullptr;
    }
    return &it->second;
  }
#ifdef SAMURAI_WITH_NGHTTP2
  if (it->second.kind == ReactorLaneKind::H2) {
    if (it->second.h2_session == nullptr) {
      runtime.custom_tcp_flow_registry.erase(it);
      return nullptr;
    }
    return &it->second;
  }
#endif
  runtime.custom_tcp_flow_registry.erase(it);
  return nullptr;
}

void apply_custom_tcp_core_events(NativeRuntime& runtime) {
  uint32_t actions = 0;
  (void)tcpdp_poll(0, 1024, &actions);

  tcpdp_rx_payload_t* payload_items = nullptr;
  uint32_t payload_count = 0;
  if (tcpdp_collect_rx_payloads(&payload_items, &payload_count) == 0 && payload_items != nullptr) {
    for (uint32_t idx = 0; idx < payload_count; ++idx) {
      const auto& item = payload_items[idx];
      if (item.payload == nullptr || item.payload_len == 0) {
        continue;
      }
      NativeRuntime::CustomTcpFlowBinding* binding =
          find_custom_tcp_flow_binding(runtime, item.flow_id);
      if (binding == nullptr) {
        continue;
      }
      if (binding->kind == ReactorLaneKind::H1 && binding->h1_lane != nullptr &&
          binding->h1_lane->conn != nullptr) {
        auto& lane = *binding->h1_lane;
        auto& conn = *lane.conn;
        conn.read_buffer.append(
            reinterpret_cast<const char*>(item.payload),
            item.payload_len);
        conn.custom_rx_pending = true;
        lane.response.bytes_received += item.payload_len;
        lane.rx_bytes += item.payload_len;
        if (conn.custom_send_outstanding > 0) {
          conn.custom_send_outstanding -= 1;
        }
        conn.custom_send_enqueued = conn.custom_send_outstanding > 0;
      }
#ifdef SAMURAI_WITH_NGHTTP2
      else if (binding->kind == ReactorLaneKind::H2 && binding->h2_session != nullptr) {
        binding->h2_session->ctx.read_buffer.append(
            reinterpret_cast<const char*>(item.payload),
            item.payload_len);
      }
#endif
    }
    tcpdp_free_rx_payloads(payload_items, payload_count);
  }

  tcpdp_completion_t* items = nullptr;
  uint32_t item_count = 0;
  if (tcpdp_collect_completions(&items, &item_count) == 0 && items != nullptr) {
    for (uint32_t idx = 0; idx < item_count; ++idx) {
      const auto& item = items[idx];
      NativeRuntime::CustomTcpFlowBinding* binding =
          find_custom_tcp_flow_binding(runtime, item.flow_id);
      if (binding == nullptr) {
        continue;
      }
      const bool connect_established =
          item.event != nullptr && std::strcmp(item.event, "connect_established") == 0;
      const bool graceful_eof = !connect_established && item.success != 0;
      if (binding->kind == ReactorLaneKind::H1 && binding->h1_lane != nullptr &&
          binding->h1_lane->conn != nullptr) {
        auto& lane = *binding->h1_lane;
        auto& conn = *lane.conn;
        if (connect_established) {
          conn.custom_connect_ready = true;
        } else {
          conn.custom_terminal = true;
          conn.custom_send_enqueued = false;
          conn.custom_send_outstanding = 0;
          if (!graceful_eof) {
            lane.phase = H1LanePhase::Failed;
          }
          unregister_custom_tcp_flow_binding(runtime, item.flow_id);
        }
      }
#ifdef SAMURAI_WITH_NGHTTP2
      else if (binding->kind == ReactorLaneKind::H2 && binding->h2_session != nullptr) {
        auto& ctx = binding->h2_session->ctx;
        if (connect_established) {
          ctx.custom_connect_ready = true;
        } else {
          ctx.custom_terminal = true;
          if (!graceful_eof) {
            ctx.transport_error = 1;
          }
          unregister_custom_tcp_flow_binding(runtime, item.flow_id);
        }
      }
#endif
    }
    tcpdp_free_completions(items, item_count);
  }
}

bool pump_custom_tcp_shard_wire(NativeRuntime& runtime, afpkt_wire_t* wire,
                                const uint8_t dst_mac[6], uint8_t* rxbuf,
                                uint16_t* rxlens, uint16_t rx_budget) {
  bool did_work = false;
  const int n = afpkt_wire_recv(wire, rxbuf, kCustomTcpWireStride, rxlens, rx_budget);
  for (int i = 0; i < n; ++i) {
    uint32_t updated = 0;
    (void)tcpdp_ingest_rx_frame(
        rxbuf + static_cast<std::size_t>(i) * kCustomTcpWireStride,
        rxlens[static_cast<std::size_t>(i)], &updated);
  }
  if (n > 0) did_work = true;

  apply_custom_tcp_core_events(runtime);

  for (int guard = 0; guard < 16; ++guard) {
    const uint8_t* base = nullptr;
    uint32_t count = 0;
    size_t psize = 0;
    size_t stride = 0;
    if (tcpdp_peek_tx_packets_strided(0, &base, &count, &psize, &stride) != 0) break;
    if (base == nullptr || count == 0 || psize == 0) break;
    const int sent = afpkt_wire_send(wire, base, psize, stride, count, dst_mac);
    if (sent <= 0) {
      if (sent < 0) {
        uint32_t consumed = 0;
        (void)tcpdp_consume_tx_packets(count, &consumed);
      }
      break;
    }
    uint32_t consumed = 0;
    (void)tcpdp_consume_tx_packets(static_cast<uint32_t>(sent), &consumed);
    did_work = true;
    if (static_cast<uint32_t>(sent) < count) break;
  }
  return did_work;
}

bool resolve_wire_iface_mac(const std::string& iface, uint8_t out[6]) {
#if defined(__linux__)
  if (iface.empty()) return false;
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return false;
  ifreq ifr{};
  std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface.c_str());
  const int rc = ::ioctl(fd, SIOCGIFHWADDR, &ifr);
  ::close(fd);
  if (rc != 0) return false;
  std::memcpy(out, ifr.ifr_hwaddr.sa_data, 6);
  return true;
#else
  (void)iface;
  (void)out;
  return false;
#endif
}

CustomTcpWireConfig resolve_custom_tcp_wire_config() {
  CustomTcpWireConfig c;
  std::memset(c.dst_mac, 0xff, sizeof(c.dst_mac));
  std::memset(c.src_mac, 0x00, sizeof(c.src_mac));
  const char* iface = std::getenv("SAMURAI_CUSTOM_TCP_RX_IFACE");
  if (iface == nullptr || iface[0] == '\0') {
    iface = std::getenv("SAMURAI_XDP_INTERFACE");
  }
  if (iface != nullptr && iface[0] != '\0') {
    c.iface = iface;
    c.have_iface = true;
  }
  const char* m = std::getenv("SAMURAI_CUSTOM_TCP_DST_MAC");
  unsigned int b[6];
  if (m != nullptr &&
      std::sscanf(m, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
    for (int i = 0; i < 6; ++i) c.dst_mac[i] = static_cast<uint8_t>(b[i] & 0xffu);
  }
  unsigned int sb[6];
  const char* sm = std::getenv("SAMURAI_CUSTOM_TCP_SRC_MAC");
  if (sm != nullptr &&
      std::sscanf(sm, "%x:%x:%x:%x:%x:%x", &sb[0], &sb[1], &sb[2], &sb[3], &sb[4], &sb[5]) == 6) {
    for (int i = 0; i < 6; ++i) c.src_mac[i] = static_cast<uint8_t>(sb[i] & 0xffu);
    c.have_src_mac = true;
  } else if (resolve_wire_iface_mac(c.iface, c.src_mac)) {
    c.have_src_mac = true;
  }
  const char* wire = std::getenv("SAMURAI_CUSTOM_TCP_WIRE");
  if (wire != nullptr &&
      (std::strcmp(wire, "in_memory") == 0 || std::strcmp(wire, "inmem") == 0)) {
    c.kind = WireKind::InMemory;
  } else if (wire != nullptr && (std::strcmp(wire, "dpdk") == 0) && samurai::dpdk::available()) {
    c.kind = WireKind::Dpdk;
    if (const char* p = std::getenv("SAMURAI_DPDK_PORT"); p != nullptr && p[0] != '\0') {
      const long v = std::strtol(p, nullptr, 10);
      if (v >= 0 && v <= 0xFFFF) c.dpdk_port = static_cast<uint16_t>(v);
    }
  } else if (wire != nullptr &&
             (std::strcmp(wire, "af_xdp") == 0 || std::strcmp(wire, "afxdp") == 0)) {
    c.kind = WireKind::AfXdp;
  }
  return c;
}

ShardPortRange custom_tcp_shard_port_range(std::size_t sh, std::size_t n) {
  if (n == 0) n = 1;
  const std::uint32_t span = static_cast<std::uint32_t>((65535u - 40000u) / n);
  const std::uint32_t lo = 40000u + static_cast<std::uint32_t>(sh) * span;
  std::uint32_t hi = lo + span - 1u;
  if (hi > 65535u || sh + 1 == n) hi = 65535u;
  ShardPortRange r;
  r.lo = static_cast<std::uint16_t>(lo);
  r.hi = static_cast<std::uint16_t>(hi);
  return r;
}

void maybe_pin_shard_worker(std::size_t sh) {
  const char* pin = std::getenv("SAMURAI_L7_PIN");
  if (pin == nullptr || pin[0] == '\0' || pin[0] == '0') {
    return;
  }
  cpu_set_t allowed;
  CPU_ZERO(&allowed);
  if (::sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
    return;
  }
  std::vector<int> cpus;
  for (int c = 0; c < CPU_SETSIZE; ++c) {
    if (CPU_ISSET(c, &allowed)) {
      cpus.push_back(c);
    }
  }
  if (cpus.empty()) {
    return;
  }
  const int target = cpus[sh % cpus.size()];
  cpu_set_t one;
  CPU_ZERO(&one);
  CPU_SET(target, &one);
  (void)::sched_setaffinity(0, sizeof(one), &one);
}

bool custom_tcp_use_own_wire(const NativeRuntime& runtime, TransportBackend backend,
                             const std::string& protocol) {
  if (backend != TransportBackend::CustomTcp && backend != TransportBackend::DpdkDirect) {
    return false;
  }
  if (protocol != "http1" && protocol != "http2") {
    return false;
  }
  const char* wire = std::getenv("SAMURAI_CUSTOM_TCP_WIRE");
  if (wire != nullptr &&
      (std::strcmp(wire, "in_memory") == 0 || std::strcmp(wire, "inmem") == 0)) {
    return true;
  }
  const bool force_afxdp =
      wire != nullptr && (std::strcmp(wire, "af_xdp") == 0 || std::strcmp(wire, "afxdp") == 0);
  if (runtime.shards.size() <= 1 && !force_afxdp) {
    return false;
  }
  const char* iface = std::getenv("SAMURAI_CUSTOM_TCP_RX_IFACE");
  if (iface == nullptr || iface[0] == '\0') {
    iface = std::getenv("SAMURAI_XDP_INTERFACE");
  }
  return iface != nullptr && iface[0] != '\0';
}

std::string dpdk_eal_args_from_env() {
  const char* a = std::getenv("SAMURAI_DPDK_EAL_ARGS");
  return (a != nullptr && a[0] != '\0') ? std::string(a) : std::string();
}

uint16_t custom_tcp_dpdk_mask(std::size_t shard_count) {
  if (shard_count <= 1) return 0;
  uint16_t m = 1;
  while (m < shard_count) m = static_cast<uint16_t>(m << 1);
  return static_cast<uint16_t>(m - 1);
}

namespace {

inline void write_be16_inmem(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v >> 8);
  p[1] = static_cast<uint8_t>(v & 0xFFu);
}
inline void write_be32_inmem(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>((v >> 24) & 0xFFu);
  p[1] = static_cast<uint8_t>((v >> 16) & 0xFFu);
  p[2] = static_cast<uint8_t>((v >> 8) & 0xFFu);
  p[3] = static_cast<uint8_t>(v & 0xFFu);
}
inline uint16_t read_be16_inmem(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}
inline uint32_t read_be32_inmem(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

struct InMemoryShardPeer {
  struct FlowState {
    uint32_t peer_seq{0};
    uint32_t cli_ack{0};
    uint32_t srv_ip{0};
    uint32_t cli_ip{0};
    uint16_t srv_port{0};
    uint16_t cli_port{0};
    bool is_h2{false};
#ifdef SAMURAI_WITH_NGHTTP2
    nghttp2_session* h2_sess{nullptr};
#endif
  };

  std::deque<std::vector<uint8_t>> rx_queue;
  std::unordered_map<uint64_t, FlowState> flows;
  uint32_t iss_gen{0x61000000u};

  ~InMemoryShardPeer() {
#ifdef SAMURAI_WITH_NGHTTP2
    for (auto& kv : flows) {
      if (kv.second.h2_sess != nullptr) {
        nghttp2_session_del(kv.second.h2_sess);
      }
    }
#endif
  }

  static uint64_t make_key(uint32_t ip, uint16_t port) {
    return (static_cast<uint64_t>(ip) << 16) | port;
  }

  static std::vector<uint8_t> build_frame(
      uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port,
      uint32_t seq, uint32_t ack, uint8_t flags, const uint8_t* payload, std::size_t payload_len) {
    std::vector<uint8_t> f(54 + payload_len, 0);
    write_be16_inmem(f.data() + 12, 0x0800);
    f[14] = 0x45;
    write_be16_inmem(f.data() + 16, static_cast<uint16_t>(40 + payload_len));
    f[22] = 64;
    f[23] = 6;
    write_be32_inmem(f.data() + 26, src_ip);
    write_be32_inmem(f.data() + 30, dst_ip);
    write_be16_inmem(f.data() + 34, src_port);
    write_be16_inmem(f.data() + 36, dst_port);
    write_be32_inmem(f.data() + 38, seq);
    write_be32_inmem(f.data() + 42, ack);
    f[46] = 0x50;
    f[47] = flags;
    write_be16_inmem(f.data() + 48, 65535);
    if (payload != nullptr && payload_len > 0) {
      std::memcpy(f.data() + 54, payload, payload_len);
    }
    return f;
  }

#ifdef SAMURAI_WITH_NGHTTP2
  static ssize_t h2_data_read_cb(
      nghttp2_session*, int32_t, uint8_t* buf, std::size_t length,
      uint32_t* data_flags, nghttp2_data_source*, void*) {
    static const char kBody[] = "OK";
    std::size_t n = sizeof(kBody) - 1;
    if (n > length) n = length;
    std::memcpy(buf, kBody, n);
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<ssize_t>(n);
  }

  static int h2_on_frame_recv_cb(nghttp2_session* s, const nghttp2_frame* f, void*) {
    if (f->hd.type == NGHTTP2_HEADERS && f->headers.cat == NGHTTP2_HCAT_REQUEST &&
        (f->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
      nghttp2_nv nv[] = {
          {(uint8_t*)":status", (uint8_t*)"200", 7, 3, NGHTTP2_NV_FLAG_NONE},
          {(uint8_t*)"content-length", (uint8_t*)"2", 14, 1, NGHTTP2_NV_FLAG_NONE},
      };
      nghttp2_data_provider prd{};
      prd.read_callback = &InMemoryShardPeer::h2_data_read_cb;
      nghttp2_submit_response(s, f->hd.stream_id, nv, 2, &prd);
    }
    return 0;
  }

  void ensure_h2_session(FlowState& fl) {
    if (fl.h2_sess != nullptr) return;
    nghttp2_session_callbacks* cbs = nullptr;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, &InMemoryShardPeer::h2_on_frame_recv_cb);
    nghttp2_session_server_new(&fl.h2_sess, cbs, this);
    nghttp2_session_callbacks_del(cbs);
    nghttp2_settings_entry iv[1] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1024}};
    nghttp2_submit_settings(fl.h2_sess, NGHTTP2_FLAG_NONE, iv, 1);
  }

  void pump_h2_out(FlowState& fl) {
    if (fl.h2_sess == nullptr) return;
    std::vector<uint8_t> outbuf;
    const uint8_t* data = nullptr;
    for (;;) {
      const ssize_t n = nghttp2_session_mem_send(fl.h2_sess, &data);
      if (n <= 0) break;
      outbuf.insert(outbuf.end(), data, data + n);
    }
    if (!outbuf.empty()) {
      constexpr std::size_t kMaxSeg = 1400;
      std::size_t off = 0;
      while (off < outbuf.size()) {
        const std::size_t chunk = std::min<std::size_t>(kMaxSeg, outbuf.size() - off);
        rx_queue.push_back(build_frame(
            fl.srv_ip, fl.cli_ip, fl.srv_port, fl.cli_port,
            fl.peer_seq, fl.cli_ack, 0x18u /* PSH|ACK */,
            outbuf.data() + off, chunk));
        fl.peer_seq += static_cast<uint32_t>(chunk);
        off += chunk;
      }
    }
  }
#endif

  void ingest_tx_packet(const uint8_t* pkt, std::size_t psize) {
    if (psize < 54 || read_be16_inmem(pkt + 12) != 0x0800u || pkt[23] != 6u) return;
    const uint16_t ip_total = read_be16_inmem(pkt + 16);
    const std::size_t ihl = static_cast<std::size_t>(pkt[14] & 0x0Fu) * 4u;
    if (ihl < 20u || 14u + ihl + 20u > psize) return;
    const uint8_t* tcp = pkt + 14u + ihl;
    const std::size_t tcphl = static_cast<std::size_t>((tcp[12] >> 4u) & 0x0Fu) * 4u;
    if (tcphl < 20u || 14u + ihl + tcphl > psize) return;
    const uint8_t flags = tcp[13];
    const uint32_t cli_ip = read_be32_inmem(pkt + 26);
    const uint32_t srv_ip = read_be32_inmem(pkt + 30);
    const uint16_t cli_port = read_be16_inmem(tcp);
    const uint16_t srv_port = read_be16_inmem(tcp + 2);
    const uint32_t cli_seq = read_be32_inmem(tcp + 4);
    const std::size_t payload_len =
        ip_total >= (ihl + tcphl) ? static_cast<std::size_t>(ip_total) - (ihl + tcphl) : 0u;
    const uint8_t* payload = tcp + tcphl;
    if (14u + ihl + tcphl + payload_len > psize) return;

    const uint64_t key = make_key(cli_ip, cli_port);
    constexpr uint8_t kFin = 0x01u, kSyn = 0x02u, kPsh = 0x08u, kAck = 0x10u;

    if ((flags & kSyn) != 0 && (flags & kAck) == 0) {
      const uint32_t my_iss = ++iss_gen;
      FlowState& fl = flows[key];
      fl.peer_seq = my_iss + 1u;
      fl.cli_ack = cli_seq + 1u;
      fl.srv_ip = srv_ip;
      fl.cli_ip = cli_ip;
      fl.srv_port = srv_port;
      fl.cli_port = cli_port;
      fl.is_h2 = false;
      rx_queue.push_back(build_frame(
          srv_ip, cli_ip, srv_port, cli_port, my_iss, cli_seq + 1u, kSyn | kAck, nullptr, 0));
      return;
    }

    if (payload_len > 0) {
      FlowState& fl = flows[key];
      fl.srv_ip = srv_ip;
      fl.cli_ip = cli_ip;
      fl.srv_port = srv_port;
      fl.cli_port = cli_port;
      fl.cli_ack = cli_seq + static_cast<uint32_t>(payload_len);
      if (!fl.is_h2 && payload_len >= 16 &&
          std::memcmp(payload, "PRI * HTTP/2.0\r\n", 16) == 0) {
        fl.is_h2 = true;
      }
      if (fl.is_h2) {
#ifdef SAMURAI_WITH_NGHTTP2
        ensure_h2_session(fl);
        nghttp2_session_mem_recv(fl.h2_sess, payload, payload_len);
        pump_h2_out(fl);
#endif
      } else {
        const bool req_close = (payload_len >= 17 &&
            std::string_view(reinterpret_cast<const char*>(payload), payload_len).find("close") != std::string_view::npos);
        const char* kResp = req_close
            ? "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"
            : "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK";
        const std::size_t kRespLen = std::strlen(kResp);
        rx_queue.push_back(build_frame(
            srv_ip, cli_ip, srv_port, cli_port,
            fl.peer_seq, fl.cli_ack, kPsh | kAck,
            reinterpret_cast<const uint8_t*>(kResp), kRespLen));
        fl.peer_seq += static_cast<uint32_t>(kRespLen);
      }
      return;
    }

    if ((flags & kFin) != 0) {
      auto it = flows.find(key);
      if (it != flows.end()) {
        FlowState& fl = it->second;
        fl.cli_ack = cli_seq + 1u;
        rx_queue.push_back(build_frame(
            srv_ip, cli_ip, srv_port, cli_port,
            fl.peer_seq, fl.cli_ack, kAck, nullptr, 0));
        flows.erase(it);
      }
    }
  }
};

struct SharedAfXdpWireState {
  std::mutex mu;
  const xdp_native_api_v1* api{nullptr};
  int handle{0};
  int refcount{0};
  std::size_t shard_count{0};
  std::vector<ShardPortRange> port_ranges;
  struct QueuedFrame {
    std::vector<uint8_t> data;
  };
  std::vector<std::deque<QueuedFrame>> shard_rx_queues;

  const xdp_native_api_v1* load_api() {
    if (api != nullptr) return api;
    static const char* kCandidates[] = {
        "ddos_samurai/xdp/xdp_sender.so",
        "ddos_samurai/xdp_sender.so",
        "ddos_samurai/xdp_sender.cpython-312-x86_64-linux-gnu.so",
        "xdp_sender.so",
        "./ddos_samurai/xdp_sender.so",
    };
    for (const char* path : kCandidates) {
      dlerror();
      void* h = ::dlopen(path, RTLD_LAZY | RTLD_LOCAL);
      if (!h) continue;
      using GetApiFn = xdp_native_api_v1* (*)();
      auto fn = reinterpret_cast<GetApiFn>(::dlsym(h, "samurai_xdp_get_native_api_v1"));
      if (!fn) {
        ::dlclose(h);
        continue;
      }
      const xdp_native_api_v1* a = fn();
      if (a && a->version == XDP_NATIVE_API_VERSION && a->create_ctx && a->destroy_ctx &&
          a->send_buffer && a->recv_frames) {
        api = a;
        return api;
      }
      ::dlclose(h);
    }
    return nullptr;
  }
};

SharedAfXdpWireState& shared_afxdp_wire_state() {
  static SharedAfXdpWireState s;
  return s;
}

bool extract_ipv4_tcp_dst_port(const uint8_t* frame, std::size_t flen, uint16_t* out_dport) {
  if (frame == nullptr || flen < 14 + 20 + 20 || out_dport == nullptr) return false;
  const uint16_t ethertype =
      static_cast<uint16_t>((static_cast<uint16_t>(frame[12]) << 8u) | frame[13]);
  if (ethertype != 0x0800u) return false;
  const uint8_t vihl = frame[14];
  if ((vihl >> 4u) != 4u) return false;
  const std::size_t ihl = static_cast<std::size_t>(vihl & 0x0fu) * 4u;
  if (ihl < 20u || 14u + ihl + 20u > flen) return false;
  if (frame[14 + 9] != IPPROTO_TCP) return false;
  const uint8_t* tcp = frame + 14u + ihl;
  *out_dport = static_cast<uint16_t>((static_cast<uint16_t>(tcp[2]) << 8u) | tcp[3]);
  return true;
}

}  // namespace

bool pump_custom_tcp_shard_inmem(NativeRuntime& runtime, void* peer_ptr) {
  auto* peer = static_cast<InMemoryShardPeer*>(peer_ptr);
  if (peer == nullptr) return false;
  bool did_work = false;
  int rx_count = 0;
  while (!peer->rx_queue.empty() && rx_count < 256) {
    const auto& front = peer->rx_queue.front();
    uint32_t updated = 0;
    (void)tcpdp_ingest_rx_frame(front.data(), front.size(), &updated);
    peer->rx_queue.pop_front();
    ++rx_count;
  }
  if (rx_count > 0) did_work = true;

  apply_custom_tcp_core_events(runtime);

  for (int guard = 0; guard < 16; ++guard) {
    const uint8_t* base = nullptr;
    uint32_t count = 0;
    size_t psize = 0;
    size_t stride = 0;
    if (tcpdp_peek_tx_packets_strided(0, &base, &count, &psize, &stride) != 0) break;
    if (base == nullptr || count == 0 || psize == 0) break;
    for (uint32_t i = 0; i < count; ++i) {
      peer->ingest_tx_packet(base + static_cast<std::size_t>(i) * stride, psize);
    }
    uint32_t consumed = 0;
    (void)tcpdp_consume_tx_packets(count, &consumed);
    did_work = true;
  }
  return did_work;
}

bool pump_custom_tcp_shard_afxdp(NativeRuntime& runtime, std::size_t sh,
                                 const uint8_t dst_mac[6], const uint8_t src_mac[6],
                                 uint8_t* rxbuf, uint16_t* rxlens, uint16_t rx_budget,
                                 std::vector<std::uint8_t>& txscratch) {
  bool did_work = false;
  auto& st = shared_afxdp_wire_state();
  int got_for_shard = 0;
  {
    std::lock_guard<std::mutex> lk(st.mu);
    if (st.api != nullptr && st.handle > 0) {
      char err[160]{};
      const int n = st.api->recv_frames(
          st.handle, rxbuf, static_cast<int>(kCustomTcpWireStride), rxlens,
          static_cast<int>(rx_budget), static_cast<int>(kCustomTcpWireStride),
          err, sizeof(err));
      for (int i = 0; i < n; ++i) {
        const uint8_t* f = rxbuf + static_cast<std::size_t>(i) * kCustomTcpWireStride;
        const uint16_t flen = rxlens[static_cast<std::size_t>(i)];
        uint16_t dport = 0;
        if (!extract_ipv4_tcp_dst_port(f, flen, &dport)) continue;
        for (std::size_t s = 0; s < st.shard_count; ++s) {
          if (dport >= st.port_ranges[s].lo && dport <= st.port_ranges[s].hi) {
            SharedAfXdpWireState::QueuedFrame qf;
            qf.data.assign(f, f + flen);
            st.shard_rx_queues[s].push_back(std::move(qf));
            break;
          }
        }
      }
    }
    if (sh < st.shard_rx_queues.size()) {
      auto& q = st.shard_rx_queues[sh];
      while (!q.empty() && got_for_shard < static_cast<int>(rx_budget)) {
        const auto& front = q.front();
        const std::size_t copy_len =
            std::min<std::size_t>(front.data.size(), kCustomTcpWireStride);
        std::memcpy(
            rxbuf + static_cast<std::size_t>(got_for_shard) * kCustomTcpWireStride,
            front.data.data(), copy_len);
        rxlens[static_cast<std::size_t>(got_for_shard)] = static_cast<uint16_t>(copy_len);
        q.pop_front();
        ++got_for_shard;
      }
    }
  }

  for (int i = 0; i < got_for_shard; ++i) {
    uint32_t updated = 0;
    (void)tcpdp_ingest_rx_frame(
        rxbuf + static_cast<std::size_t>(i) * kCustomTcpWireStride,
        rxlens[static_cast<std::size_t>(i)], &updated);
  }
  if (got_for_shard > 0) did_work = true;

  apply_custom_tcp_core_events(runtime);

  for (int guard = 0; guard < 16; ++guard) {
    const uint8_t* base = nullptr;
    uint32_t count = 0;
    size_t psize = 0;
    size_t stride = 0;
    if (tcpdp_peek_tx_packets_strided(0, &base, &count, &psize, &stride) != 0) break;
    if (base == nullptr || count == 0 || psize < 14) {
      if (base != nullptr && count > 0 && psize < 14) {
        uint32_t consumed = 0;
        (void)tcpdp_consume_tx_packets(count, &consumed);
      }
      break;
    }
    const uint32_t cap = txscratch.empty()
                             ? 0u
                             : static_cast<uint32_t>(txscratch.size() / psize);
    const uint32_t batch = std::min<uint32_t>(count, cap);
    if (batch == 0) break;
    for (uint32_t i = 0; i < batch; ++i) {
      uint8_t* d = txscratch.data() + static_cast<std::size_t>(i) * psize;
      std::memcpy(d, base + static_cast<size_t>(i) * stride, psize);
      std::memcpy(d, dst_mac, 6);
      std::memcpy(d + 6, src_mac, 6);
    }
    int sent = 0;
    {
      std::lock_guard<std::mutex> lk(st.mu);
      if (st.api != nullptr && st.handle > 0) {
        char err[160]{};
        if (st.api->send_buffer_strided != nullptr) {
          sent = st.api->send_buffer_strided(
              st.handle, txscratch.data(), static_cast<int>(psize),
              static_cast<int>(psize), static_cast<int>(batch), err, sizeof(err));
        } else {
          sent = st.api->send_buffer(
              st.handle, txscratch.data(), static_cast<int>(psize),
              static_cast<int>(batch), err, sizeof(err));
        }
      }
    }
    if (sent <= 0) break;
    uint32_t consumed = 0;
    (void)tcpdp_consume_tx_packets(static_cast<uint32_t>(sent), &consumed);
    did_work = true;
    if (static_cast<uint32_t>(sent) < count) break;
  }
  return did_work;
}

bool pump_custom_tcp_shard_dpdk(NativeRuntime& runtime, long handle, uint16_t queue,
                                const uint8_t dst_mac[6], const uint8_t src_mac[6],
                                uint8_t* rxbuf, uint16_t* rxlens, uint16_t rx_budget,
                                std::vector<std::uint8_t>& txscratch) {
  bool did_work = false;
  const int n = samurai::dpdk::poll_rx(handle, queue, rx_budget, rxbuf,
                                       kCustomTcpWireStride, rxlens);
  for (int i = 0; i < n; ++i) {
    uint32_t updated = 0;
    (void)tcpdp_ingest_rx_frame(
        rxbuf + static_cast<std::size_t>(i) * kCustomTcpWireStride,
        rxlens[static_cast<std::size_t>(i)], &updated);
  }
  if (n > 0) did_work = true;

  apply_custom_tcp_core_events(runtime);

  for (int guard = 0; guard < 16; ++guard) {
    const uint8_t* base = nullptr;
    uint32_t count = 0;
    size_t psize = 0;
    size_t stride = 0;
    if (tcpdp_peek_tx_packets_strided(0, &base, &count, &psize, &stride) != 0) break;
    if (base == nullptr || count == 0 || psize < 14) {
      if (base != nullptr && count > 0 && psize < 14) {
        uint32_t consumed = 0;
        (void)tcpdp_consume_tx_packets(count, &consumed);
      }
      break;
    }
    const uint32_t cap = txscratch.empty()
                             ? 0u
                             : static_cast<uint32_t>(txscratch.size() / psize);
    const uint32_t batch = std::min<uint32_t>(count, cap);
    if (batch == 0) break;
    for (uint32_t i = 0; i < batch; ++i) {
      uint8_t* d = txscratch.data() + static_cast<std::size_t>(i) * psize;
      std::memcpy(d, base + static_cast<std::size_t>(i) * stride, psize);
      std::memcpy(d, dst_mac, 6);
      std::memcpy(d + 6, src_mac, 6);
    }
    const samurai::dpdk::TxResult r = samurai::dpdk::send_batch(
        handle, queue, txscratch.data(), static_cast<uint16_t>(psize), batch);
    if (r.sent == 0) break;
    uint32_t consumed = 0;
    (void)tcpdp_consume_tx_packets(static_cast<uint32_t>(r.sent), &consumed);
    did_work = true;
    if (r.sent < count) break;
  }
  return did_work;
}

DpdkOwnWire open_dpdk_own_wire(const CustomTcpWireConfig& cfg, std::size_t shard_count) {
  DpdkOwnWire dw;
  if (cfg.kind != WireKind::Dpdk || !samurai::dpdk::available() || shard_count <= 1) {
    return dw;
  }
  dw.mask = custom_tcp_dpdk_mask(shard_count);
  samurai::dpdk::OpenConfig oc;
  oc.port_id = cfg.dpdk_port;
  oc.num_tx_queues = static_cast<uint16_t>(shard_count);
  oc.num_rx_queues = static_cast<uint16_t>(shard_count);
  oc.enable_rss = true;
  oc.eal_args = dpdk_eal_args_from_env();
  std::string err;
  const long manager = samurai::dpdk::open_port(oc, err);
  if (manager <= 0) {
    return dw;
  }
  for (std::size_t q = 0; q < shard_count; ++q) {
    std::string serr;
    if (!samurai::dpdk::steer_l4_dst_port_to_queue(
            manager, IPPROTO_TCP, static_cast<uint16_t>(q), static_cast<uint16_t>(q),
            dw.mask, serr)) {
      samurai::dpdk::close_port(manager);
      return dw;
    }
  }
  dw.manager = manager;
  dw.active = true;
  return dw;
}

void close_dpdk_own_wire(DpdkOwnWire& dw) {
  if (dw.manager > 0) {
    samurai::dpdk::close_port(dw.manager);
  }
  dw.manager = 0;
  dw.active = false;
}

ShardWire open_shard_wire(const CustomTcpWireConfig& cfg, const DpdkOwnWire& dw,
                          std::size_t sh, std::size_t shard_count,
                          const ShardPortRange& pr) {
  ShardWire w;
  if (cfg.kind == WireKind::InMemory) {
    w.kind = WireKind::InMemory;
    w.dpdk_queue = static_cast<uint16_t>(sh);
    tcpdp_set_ephemeral_port_base(pr.lo);
    w.inmem_peer = new InMemoryShardPeer();
    return w;
  }
  if (cfg.kind == WireKind::Dpdk && dw.active) {
    w.kind = WireKind::Dpdk;
    const uint16_t stride = static_cast<uint16_t>(dw.mask + 1);
    uint32_t base = 40000u - (40000u % stride) + static_cast<uint32_t>(sh % stride);
    if (base < 40000u) base += stride;
    tcpdp_set_ephemeral_port_base(static_cast<uint16_t>(base));
    tcpdp_set_ephemeral_port_stride(stride);
    w.lcore_registered = samurai::dpdk::register_lcore_thread();
    samurai::dpdk::OpenConfig oc;
    oc.port_id = cfg.dpdk_port;
    oc.num_tx_queues = static_cast<uint16_t>(shard_count);
    oc.num_rx_queues = static_cast<uint16_t>(shard_count);
    oc.enable_rss = true;
    oc.eal_args = dpdk_eal_args_from_env();
    std::string err;
    w.dpdk_handle = samurai::dpdk::open_port(oc, err);
    w.dpdk_queue = static_cast<uint16_t>(sh);
    return w;
  }
  if (cfg.kind == WireKind::AfXdp) {
    w.kind = WireKind::AfXdp;
    w.dpdk_queue = static_cast<uint16_t>(sh);
    tcpdp_set_ephemeral_port_base(pr.lo);
    auto& st = shared_afxdp_wire_state();
    std::lock_guard<std::mutex> lk(st.mu);
    if (st.refcount == 0) {
      const xdp_native_api_v1* api = st.load_api();
      if (api != nullptr) {
        int queue_id = 0;
        if (const char* qenv = std::getenv("SAMURAI_XDP_QUEUE_ID"); qenv != nullptr) {
          queue_id = std::max(0, std::atoi(qenv));
        }
        int mode = 0;  // Default to SKB/Copy mode (0) unless overridden
        if (const char* menv = std::getenv("SAMURAI_XDP_MODE"); menv != nullptr) {
          mode = std::clamp(std::atoi(menv), 0, 2);
        }
        char err[160]{};
        st.handle = api->create_ctx(cfg.iface.c_str(), queue_id, mode, err, sizeof(err));
        st.shard_count = shard_count;
        st.port_ranges.resize(shard_count);
        st.shard_rx_queues.assign(shard_count, {});
        for (std::size_t i = 0; i < shard_count; ++i) {
          st.port_ranges[i] = custom_tcp_shard_port_range(i, shard_count);
        }
      }
    }
    if (st.handle > 0) {
      st.refcount += 1;
      w.dpdk_handle = st.handle;
    }
    return w;
  }
  w.kind = WireKind::AfPacket;
  tcpdp_set_ephemeral_port_base(pr.lo);
  (void)afpkt_wire_open(cfg.iface.c_str(), pr.lo, pr.hi, &w.afpkt);
  return w;
}

bool pump_shard_wire(NativeRuntime& runtime, const CustomTcpWireConfig& cfg,
                     ShardWire& w, uint8_t* rxbuf, uint16_t* rxlens, uint16_t budget,
                     std::vector<std::uint8_t>& txscratch) {
  if (w.kind == WireKind::InMemory) {
    return pump_custom_tcp_shard_inmem(runtime, w.inmem_peer);
  }
  if (w.kind == WireKind::Dpdk) {
    if (w.dpdk_handle <= 0) return false;
    return pump_custom_tcp_shard_dpdk(runtime, w.dpdk_handle, w.dpdk_queue,
                                      cfg.dst_mac, cfg.src_mac, rxbuf, rxlens, budget,
                                      txscratch);
  }
  if (w.kind == WireKind::AfXdp) {
    if (w.dpdk_handle <= 0) return false;
    return pump_custom_tcp_shard_afxdp(runtime, w.dpdk_queue, cfg.dst_mac, cfg.src_mac,
                                       rxbuf, rxlens, budget, txscratch);
  }
  if (w.afpkt != nullptr) {
    return pump_custom_tcp_shard_wire(runtime, w.afpkt, cfg.dst_mac, rxbuf, rxlens, budget);
  }
  return false;
}

void close_shard_wire(ShardWire& w) {
  if (w.kind == WireKind::InMemory) {
    delete static_cast<InMemoryShardPeer*>(w.inmem_peer);
    w.inmem_peer = nullptr;
  } else if (w.kind == WireKind::Dpdk) {
    if (w.dpdk_handle > 0) samurai::dpdk::close_port(w.dpdk_handle);
    if (w.lcore_registered) samurai::dpdk::unregister_lcore_thread();
  } else if (w.kind == WireKind::AfXdp) {
    auto& st = shared_afxdp_wire_state();
    std::lock_guard<std::mutex> lk(st.mu);
    if (w.dpdk_handle > 0 && st.refcount > 0) {
      st.refcount -= 1;
      if (st.refcount == 0 && st.api != nullptr && st.handle > 0) {
        char err[160]{};
        (void)st.api->destroy_ctx(st.handle, err, sizeof(err));
        st.handle = 0;
        st.shard_rx_queues.clear();
      }
    }
    w.dpdk_handle = 0;
  } else if (w.afpkt != nullptr) {
    afpkt_wire_close(w.afpkt);
  }
}

void service_custom_tcp_lanes(NativeRuntime& runtime, const Profile& profile) {
  if (!is_custom_tcp_backend(parse_transport_backend(profile))) {
    return;
  }
  apply_custom_tcp_core_events(runtime);

  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    service_custom_tcp_shard_lanes(runtime, shard_idx);
  }

#ifdef SAMURAI_WITH_NGHTTP2
  for (std::size_t shard_idx = 0; shard_idx < runtime.local_shards.size(); ++shard_idx) {
    service_custom_tcp_h2_shard_sessions(runtime, profile, shard_idx);
  }
#endif
}

void custom_tcp_wire_pump(
    NativeRuntime& runtime,
    std::vector<std::unique_ptr<ShardIo>>& shard_io,
    std::atomic<bool>& wire_stop,
    ReactorLaneKind want_kind) {
  const std::size_t shard_count = shard_io.size();
  struct Held {
    uint64_t flow_id{0};
    InboxEvent ev{};
    int retries{0};
  };
  constexpr int kMaxHeldRetries = 2000;
  std::deque<Held> held;

  auto route = [&](uint64_t flow_id, InboxEvent&& ev, bool erase_on_hit) -> bool {
    std::size_t sh = 0;
    std::size_t ln = 0;
    bool found = false;
    {
      std::lock_guard<std::mutex> lk(custom_tcp_registry_mu());
      auto it = runtime.custom_tcp_flow_registry.find(flow_id);
      if (it != runtime.custom_tcp_flow_registry.end() && it->second.kind == want_kind) {
        sh = it->second.shard_idx;
        ln = it->second.lane_idx;
        found = true;
        if (erase_on_hit) {
          runtime.custom_tcp_flow_registry.erase(it);
        }
      }
    }
    if (!found || sh >= shard_count) {
      return false;
    }
    ev.lane_idx = ln;
    std::lock_guard<std::mutex> lk(shard_io[sh]->mu);
    shard_io[sh]->inbox.push_back(std::move(ev));
    return true;
  };

  while (!wire_stop.load(std::memory_order_relaxed)) {
    bool did = false;
    for (std::size_t i = 0; i < held.size();) {
      const bool terminal = held[i].ev.kind == InboxEvent::Kind::Terminal;
      if (route(held[i].flow_id, std::move(held[i].ev), terminal)) {
        held.erase(held.begin() + static_cast<long>(i));
        did = true;
      } else if (++held[i].retries > kMaxHeldRetries) {
        held.erase(held.begin() + static_cast<long>(i));
      } else {
        ++i;
      }
    }
    uint32_t actions = 0;
    (void)tcpdp_poll(0, 2048, &actions);
    tcpdp_completion_t* items = nullptr;
    uint32_t item_count = 0;
    if (tcpdp_collect_completions(&items, &item_count) == 0 && items != nullptr) {
      for (uint32_t idx = 0; idx < item_count; ++idx) {
        const auto& item = items[idx];
        const bool established = item.event != nullptr &&
            std::strcmp(item.event, "connect_established") == 0;
        const auto kind = established ? InboxEvent::Kind::ConnectEstablished
                                      : InboxEvent::Kind::Terminal;
        InboxEvent ev;
        ev.kind = kind;
        if (route(item.flow_id, std::move(ev), !established)) {
          did = true;
        } else {
          InboxEvent hev;
          hev.kind = kind;
          held.push_back(Held{item.flow_id, std::move(hev), 0});
        }
      }
      tcpdp_free_completions(items, item_count);
    }
    tcpdp_rx_payload_t* pitems = nullptr;
    uint32_t pcount = 0;
    if (tcpdp_collect_rx_payloads(&pitems, &pcount) == 0 && pitems != nullptr) {
      for (uint32_t idx = 0; idx < pcount; ++idx) {
        const auto& item = pitems[idx];
        if (item.payload == nullptr || item.payload_len == 0) {
          continue;
        }
        InboxEvent ev;
        ev.kind = InboxEvent::Kind::RxPayload;
        ev.payload.assign(reinterpret_cast<const char*>(item.payload), item.payload_len);
        if (route(item.flow_id, std::move(ev), false)) {
          did = true;
        } else {
          InboxEvent hev;
          hev.kind = InboxEvent::Kind::RxPayload;
          hev.payload.assign(reinterpret_cast<const char*>(item.payload), item.payload_len);
          held.push_back(Held{item.flow_id, std::move(hev), 0});
        }
      }
      tcpdp_free_rx_payloads(pitems, pcount);
    }
    if (!did) {
      worker_idle_backoff();
    } else {
      worker_idle_reset();
    }
  }
}

bool configure_custom_tcp_bridge(const Profile& profile) {
  auto env_u32 = [](const char* name, uint32_t fallback) -> uint32_t {
    const char* raw = std::getenv(name);
    if (raw == nullptr || raw[0] == '\0') {
      return fallback;
    }
    char* end_ptr = nullptr;
    const unsigned long parsed = std::strtoul(raw, &end_ptr, 10);
    if (end_ptr == raw || (end_ptr != nullptr && *end_ptr != '\0')) {
      return fallback;
    }
    if (parsed == 0UL || parsed > 0xffffffffUL) {
      return fallback;
    }
    return static_cast<uint32_t>(parsed);
  };
  tcpdp_config_t config{};
  const uint32_t timeout_ms = static_cast<uint32_t>(std::max(1, profile.timeout_ms));
  const uint32_t initial_rto_ms = env_u32(
      "SAMURAI_CUSTOM_TCP_INITIAL_RTO_MS",
      static_cast<uint32_t>(std::max<uint32_t>(25U, std::min<uint32_t>(timeout_ms / 4U, 1000U))));
  const uint32_t connect_timeout_ms = env_u32(
      "SAMURAI_CUSTOM_TCP_CONNECT_TIMEOUT_MS",
      static_cast<uint32_t>(std::max<uint32_t>(timeout_ms, initial_rto_ms * 4U)));
  config.mode = std::getenv("SAMURAI_CUSTOM_TCP_MODE") != nullptr ? std::getenv("SAMURAI_CUSTOM_TCP_MODE") : "required";
  config.backend = std::getenv("SAMURAI_CUSTOM_TCP_BACKEND") != nullptr ? std::getenv("SAMURAI_CUSTOM_TCP_BACKEND") : "af_xdp";
  config.initial_rto_ms = initial_rto_ms;
  config.max_retransmits = env_u32("SAMURAI_CUSTOM_TCP_MAX_RETRANSMITS", 5);
  config.connect_timeout_ms = connect_timeout_ms;
  config.idle_timeout_ms = env_u32(
      "SAMURAI_CUSTOM_TCP_IDLE_TIMEOUT_MS",
      static_cast<uint32_t>(std::max<uint32_t>(connect_timeout_ms * 4U, timeout_ms * 6U)));
  return tcpdp_configure(&config) == 0;
}

int32_t maybe_start_custom_tcp_rx_bridge() {
  const char* iface = std::getenv("SAMURAI_CUSTOM_TCP_RX_IFACE");
  if (iface == nullptr || iface[0] == '\0') {
    return 0;
  }
  int32_t handler_id = 0;
  if (tcpdp_start_rx_handler(iface, &handler_id) != 0) {
    return -1;
  }
  return handler_id;
}

void merge_custom_tcp_stats(const NativeRuntime& runtime, std::map<std::string, double>& out) {
  tcpdp_stats_snapshot_t stats{};
  if (runtime.custom_tcp_own_wire_used) {
    stats = runtime.custom_tcp_shard_stats;
  } else if (tcpdp_snapshot_stats(&stats) != 0) {
    return;
  }
  out["tcp_flows_active"] = static_cast<double>(stats.flows_active);
  out["tcp_connect_attempts"] = static_cast<double>(stats.connect_attempts);
  out["tcp_connect_established"] = static_cast<double>(stats.connect_established);
  out["tcp_retransmit_count"] = static_cast<double>(stats.retransmit_count);
  out["tcp_timeout_close_count"] = static_cast<double>(stats.timeout_close_count);
  out["tcp_connect_timeout_count"] = static_cast<double>(stats.connect_timeout_count);
  out["tcp_idle_timeout_count"] = static_cast<double>(stats.idle_timeout_count);
  out["tcp_retransmit_exhausted_count"] = static_cast<double>(stats.retransmit_exhausted_count);
  out["tcp_rx_ack_count"] = static_cast<double>(stats.rx_ack_count);
  out["tcp_dup_ack_count"] = static_cast<double>(stats.dup_ack_count);
  out["tcp_unexpected_ack_count"] = static_cast<double>(stats.unexpected_ack_count);
  out["tcp_tx_data_bytes"] = static_cast<double>(stats.tx_data_bytes);
  out["tcp_rx_data_bytes"] = static_cast<double>(stats.rx_data_bytes);
  out["tcp_peer_rst_count"] = static_cast<double>(stats.peer_rst_count);
  out["tcp_peer_fin_count"] = static_cast<double>(stats.peer_fin_count);
}

}  // namespace ddos_samurai::l7_emu_native
