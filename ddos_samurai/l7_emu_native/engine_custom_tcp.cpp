#include "engine_internal.hpp"

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
  std::lock_guard<std::mutex> lk(custom_tcp_registry_mu());
  runtime.custom_tcp_flow_registry[lane.conn->custom_flow_id] = binding;
}

NativeRuntime::CustomTcpFlowBinding* find_custom_tcp_flow_binding(
    NativeRuntime& runtime,
    uint64_t flow_id) {
  if (flow_id == 0) {
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
  const char* wire = std::getenv("SAMURAI_CUSTOM_TCP_WIRE");
  if (wire != nullptr && (std::strcmp(wire, "dpdk") == 0) && samurai::dpdk::available()) {
    c.kind = WireKind::Dpdk;
    if (const char* p = std::getenv("SAMURAI_DPDK_PORT"); p != nullptr && p[0] != '\0') {
      const long v = std::strtol(p, nullptr, 10);
      if (v >= 0 && v <= 0xFFFF) c.dpdk_port = static_cast<uint16_t>(v);
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
  if (backend != TransportBackend::CustomTcp || runtime.shards.size() <= 1) {
    return false;
  }
  if (protocol != "http1" && protocol != "http2") {
    return false;
  }
  const char* iface = std::getenv("SAMURAI_CUSTOM_TCP_RX_IFACE");
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
  w.kind = WireKind::AfPacket;
  tcpdp_set_ephemeral_port_base(pr.lo);
  (void)afpkt_wire_open(cfg.iface.c_str(), pr.lo, pr.hi, &w.afpkt);
  return w;
}

bool pump_shard_wire(NativeRuntime& runtime, const CustomTcpWireConfig& cfg,
                     ShardWire& w, uint8_t* rxbuf, uint16_t* rxlens, uint16_t budget,
                     std::vector<std::uint8_t>& txscratch) {
  if (w.kind == WireKind::Dpdk) {
    if (w.dpdk_handle <= 0) return false;
    return pump_custom_tcp_shard_dpdk(runtime, w.dpdk_handle, w.dpdk_queue,
                                      cfg.dst_mac, cfg.src_mac, rxbuf, rxlens, budget,
                                      txscratch);
  }
  if (w.afpkt != nullptr) {
    return pump_custom_tcp_shard_wire(runtime, w.afpkt, cfg.dst_mac, rxbuf, rxlens, budget);
  }
  return false;
}

void close_shard_wire(ShardWire& w) {
  if (w.kind == WireKind::Dpdk) {
    if (w.dpdk_handle > 0) samurai::dpdk::close_port(w.dpdk_handle);
    if (w.lcore_registered) samurai::dpdk::unregister_lcore_thread();
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
