#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct l4se_stats_snapshot_t {
  uint32_t table_size;
  uint32_t lock_count;
  uint32_t timeout_sec;
  uint64_t active_entries;
  uint64_t timeout_evictions;
  uint64_t overwrites;
  uint64_t sweeps;
  uint64_t last_sweep_removed;
  uint32_t sweep_cursor;
  uint64_t transition_total;
  uint64_t state_counts[7];
} l4se_stats_snapshot_t;

int l4se_configure(uint32_t table_size, uint32_t lock_count, uint32_t timeout_sec);
int l4se_set_mimicry(uint16_t window, uint16_t mss, uint8_t ttl);
int l4se_ingest_tx_packets(const uint8_t* packets, size_t packet_size, size_t count, uint32_t* out_updated);
int l4se_ingest_rx_frame(const uint8_t* frame, size_t frame_len, uint32_t* out_updated);
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
    uint32_t* out_found);
int l4se_get_tcp_state(
    uint32_t src_ip,
    uint16_t src_port,
    uint32_t* out_seq,
    uint32_t* out_ack,
    uint8_t* out_state,
    uint16_t* out_window,
    uint16_t* out_mss,
    uint8_t* out_ttl,
    uint8_t* out_found);
int l4se_sweep(uint32_t max_scan, uint32_t* out_removed);
int l4se_stats_snapshot(l4se_stats_snapshot_t* out_stats);
int l4se_start_rx_handler(const char* iface, int32_t* out_handler_id);
int l4se_stop_rx_handler(int32_t handler_id);
void l4se_shutdown_all_handlers(void);

#ifdef __cplusplus
}
#endif
