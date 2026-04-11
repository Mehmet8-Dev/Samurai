#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tcpdp_config_t {
  const char* mode;
  const char* backend;
  uint32_t initial_rto_ms;
  uint32_t max_retransmits;
  uint32_t connect_timeout_ms;
  uint32_t idle_timeout_ms;
} tcpdp_config_t;

typedef struct tcpdp_stats_snapshot_t {
  uint64_t flows_active;
  uint64_t connect_attempts;
  uint64_t connect_established;
  uint64_t retransmit_count;
  uint64_t timeout_close_count;
  uint64_t connect_timeout_count;
  uint64_t idle_timeout_count;
  uint64_t retransmit_exhausted_count;
  uint64_t rx_ack_count;
  uint64_t dup_ack_count;
  uint64_t partial_ack_count;
  uint64_t fast_retransmit_count;
  uint64_t unexpected_ack_count;
  uint64_t tx_data_bytes;
  uint64_t rx_data_bytes;
  uint64_t tx_packets_queued;
  uint64_t tx_packets_drained;
  uint64_t tx_packets_sent;
  uint64_t poll_calls;
  uint64_t rx_frames;
  uint64_t unexpected_rx;
  uint64_t out_of_order_rx_count;
  uint64_t peer_rst_count;
  uint64_t peer_fin_count;
} tcpdp_stats_snapshot_t;

typedef struct tcpdp_flow_snapshot_t {
  uint64_t flow_id;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t iss;
  uint32_t snd_una;
  uint32_t snd_nxt;
  uint32_t rcv_nxt;
  uint16_t peer_window;
  uint16_t local_window;
  uint16_t mss;
  uint8_t ttl;
  uint8_t state;
  uint32_t retransmit_count;
  uint64_t rto_deadline_ns;
  uint64_t last_activity_ns;
  uint8_t found;
} tcpdp_flow_snapshot_t;

typedef struct tcpdp_completion_t {
  uint64_t flow_id;
  uint8_t state;
  uint8_t success;
  const char* event;
} tcpdp_completion_t;

typedef struct tcpdp_rx_payload_t {
  uint64_t flow_id;
  const uint8_t* payload;
  size_t payload_len;
} tcpdp_rx_payload_t;

int tcpdp_configure(const tcpdp_config_t* config);
int tcpdp_ingest_tx_packets(const uint8_t* packets, size_t packet_size, size_t count, uint32_t* out_updated);
int tcpdp_enqueue_connect(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint64_t* out_flow_id);
int tcpdp_enqueue_send(uint64_t flow_id, const uint8_t* payload, size_t payload_len, uint32_t* out_queued_bytes);
int tcpdp_ingest_rx_frame(const uint8_t* frame, size_t frame_len, uint32_t* out_updated);
int tcpdp_poll(uint64_t now_ns, uint32_t budget, uint32_t* out_actions);
int tcpdp_drain_tx_packets(uint32_t max_packets, const uint8_t*** out_packets, size_t** out_packet_lens, uint32_t* out_count);
void tcpdp_free_drained_packets(const uint8_t** packets, size_t* packet_lens, uint32_t count);
int tcpdp_collect_completions(tcpdp_completion_t** out_items, uint32_t* out_count);
void tcpdp_free_completions(tcpdp_completion_t* items, uint32_t count);
int tcpdp_collect_rx_payloads(tcpdp_rx_payload_t** out_items, uint32_t* out_count);
void tcpdp_free_rx_payloads(tcpdp_rx_payload_t* items, uint32_t count);
int tcpdp_snapshot_stats(tcpdp_stats_snapshot_t* out_stats);
int tcpdp_get_flow(uint64_t flow_id, tcpdp_flow_snapshot_t* out_flow);
int tcpdp_start_rx_handler(const char* iface, int32_t* out_handler_id);
int tcpdp_stop_rx_handler(int32_t handler_id);

#ifdef __cplusplus
}
#endif
