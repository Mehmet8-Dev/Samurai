#include "l4_state_engine_ffi.h"

#include "l4_state_engine_core.hpp"

#include <errno.h>

#include <cstddef>
#include <cstdint>

namespace ddos_samurai::l4se {
namespace {

using Core = L4StateEngineCore;

Core& Engine() {
  static Core* core = new Core();
  return *core;
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
  errno = ENOTSUP;
  (void)iface;
  (void)out_handler_id;
  return -1;
}

int l4se_stop_rx_handler(int32_t handler_id) {
  (void)handler_id;
  errno = ENOTSUP;
  return -1;
}

void l4se_shutdown_all_handlers(void) {
  // User-space custom stack only; kernel RX handlers were removed.
}

}  // extern "C"
