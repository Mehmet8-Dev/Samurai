#pragma once

#include <cstddef>
#include <cstdint>

namespace samurai::wire {

inline constexpr std::uint32_t kMagic = 0x534D5249u;  // "SMRI"
inline constexpr std::uint8_t kVersionV1 = 1u;
// V2 adds L7 profile fields (concurrency, connection pool, scheme/TLS, etc.)
// behind a JobEnvelopeV2 that embeds JobEnvelopeV1 as its first member, so the
// V1 prefix stays binary-compatible with existing V1-only parsers.
inline constexpr std::uint8_t kVersionV2 = 2u;

#pragma pack(push, 1)

struct SamuraiWireHeaderV1 {
  std::uint32_t magic;
  std::uint8_t version;
  std::uint8_t msg_type;
  std::uint32_t payload_len;
  std::uint16_t flags;
  std::uint64_t correlation_id;
  std::uint8_t worker_kind;
  char job_id[32];
  std::uint8_t pad[3];
};

struct JobEnvelopeV1 {
  char target_ip[16];
  std::uint16_t target_port;
  std::uint32_t packet_count;
  std::uint32_t packet_size;
  std::uint8_t pacing_mode;
  double target_rps;
  std::uint64_t ipg_ns;
  std::uint32_t burst_size;
  std::uint64_t burst_gap_ns;
  std::uint8_t jitter_model;
  double jitter_pct;
  std::int32_t pin_cpu;
  std::uint8_t use_so_txtime;
  char xdp_interface[16];
  std::uint32_t xdp_queue_id;
  std::uint32_t xdp_mode;
  char scenario_payload_ref[64];
  char protocol[8];
  char tcp_flags[8];
  std::uint8_t spoof_enabled;
  char spoof_mode[16];
  char spoof_subnet[32];
  char spoof_list_file[64];
  std::uint8_t has_payload;
  char payload_ref[64];
  std::uint32_t pad_size;
  std::uint8_t ttl;
  std::uint8_t tos;
  std::uint16_t window;
  std::uint8_t fragment_enabled;
  std::uint16_t fragment_size;
  char attack_vector[16];
  char dns_name[64];
  char dns_qtype[32];
  std::uint8_t dns_edns;
  std::uint8_t dns_recursive;
  std::uint8_t pad[4];
};

// V2 envelope: JobEnvelopeV1 plus L7 stateful-runtime fields. The V1 struct is
// embedded first so a V2 payload can be downgraded to V1 by reading only `base`
// (and V1-only workers reject V2 by the size check). New fields live in the
// tail and are consumed only by workers that negotiate version 2.
struct JobEnvelopeV2 {
  JobEnvelopeV1 base;

  std::uint32_t concurrency;                 // L7: parallel lanes/threads (>=1)
  std::uint32_t max_connections;             // L7: connection pool size (>=1)
  std::uint32_t max_streams_per_connection;  // L7: H2/H3 streams per connection
  std::uint8_t verify_tls;                   // L7: 1 = verify peer cert
  std::uint8_t keepalive;                    // L7: 1 = reuse connections
  char scheme[16];                           // L7: http | https
  char host_header[128];                     // L7: Host/SNI override
  std::uint32_t l7_timeout_ms;               // L7: per-request timeout
  std::uint8_t pad2[8];
};

struct MetricSnapshotV1 {
  std::uint64_t timestamp_ns;
  std::uint64_t packets_sent;
  std::uint64_t packets_errors;
  std::uint64_t bytes_sent;
  double actual_rps;
  double jitter_p99_ns;
  double rate_accuracy_pct;
  std::uint32_t busywait_cycles;
  std::uint32_t sleep_calls;
};

// V2 extensions for Phase 6 L7 protocol and TRex parity telemetry.
struct MetricSnapshotV2 {
  MetricSnapshotV1 base;
  std::uint32_t tcp_active_tcb_count;
  std::uint32_t tcp_timer_wheel_overflows;
  std::uint32_t tls_handshakes_completed;
  std::uint32_t tls_session_reuse_hits;
  std::uint32_t dns_queries_sent;
  std::uint32_t dns_responses_parsed;
  std::uint32_t dns_ecs_injected;
  std::uint32_t dhcp_leases_active;
  std::uint32_t arp_resolved_entries;
  std::uint32_t igmp_active_groups;
  std::uint64_t hot_path_zero_copy_tx_bytes;
  std::uint64_t hot_path_zero_copy_rx_bytes;
};

struct FlowUpdateEventV1 {
  std::uint64_t version;
  std::uint64_t epoch;
  std::uint32_t flow_id;
  std::uint32_t tcp_seq;
  std::uint32_t tcp_ack;
  std::uint16_t src_port;
  std::uint16_t dst_port;
  std::uint8_t tcp_state;
  std::uint8_t proto;
  std::uint16_t flags;
  std::uint32_t rtt_us;
  std::uint64_t dpu_ts_ns;
};

struct FlowStreamUpsertV1 {
  std::uint64_t version;
  std::uint64_t epoch;
  std::uint32_t flow_id;
  std::uint32_t tcp_seq;
  std::uint32_t tcp_ack;
  std::uint16_t src_port;
  std::uint16_t dst_port;
  std::uint8_t tcp_state;
  std::uint8_t proto;
  std::uint16_t flags;
  std::uint32_t rtt_us;
  std::uint32_t quota;
  std::uint64_t tx_ipg_ns;
  std::uint64_t dpu_ts_ns;
  char target_ip[16];
  std::uint16_t payload_len;
  std::uint8_t payload_byte;
  std::uint8_t weight;
  std::uint32_t template_id;
};

#pragma pack(pop)

enum class MessageType : std::uint8_t {
  START_JOB = 1,
  STOP_JOB = 2,
  SHUTDOWN = 3,

  ACK = 10,
  HEARTBEAT = 11,

  METRIC_SNAPSHOT = 20,
  FLOW_UPDATE = 21,
  FLOW_STREAM_UPSERT = 22,

  ERROR = 30,

  JOB_DONE = 40,
};

// Some Linux headers define AF_XDP / AF_PACKET as preprocessor macro
// socket-family values. Those macros collide with our enum member names and can
// break parsing depending on include order (e.g. when sys/socket.h or
// linux/if_packet.h is included before this header).
#ifdef AF_XDP
#undef AF_XDP
#endif
#ifdef AF_PACKET
#undef AF_PACKET
#endif

enum class WorkerKind : std::uint8_t {
  CPU = 1,
  GPU = 2,
  DPDK = 3,
  AF_XDP = 4,
  DOCA = 5,
  L7 = 6,
  DEFENSE = 7,
  SCENARIO = 8,
  AF_PACKET = 9,
};

static_assert(sizeof(SamuraiWireHeaderV1) == 56, "SamuraiWireHeaderV1 size mismatch");
static_assert(sizeof(JobEnvelopeV1) == 480, "JobEnvelopeV1 size mismatch");
static_assert(sizeof(JobEnvelopeV2) > sizeof(JobEnvelopeV1), "JobEnvelopeV2 must extend V1");
static_assert(offsetof(JobEnvelopeV2, base) == 0, "JobEnvelopeV2 must embed V1 at offset 0");
static_assert(sizeof(MetricSnapshotV1) == 64, "MetricSnapshotV1 size mismatch");
static_assert(sizeof(FlowUpdateEventV1) == 48, "FlowUpdateEventV1 size mismatch");
static_assert(sizeof(FlowStreamUpsertV1) == 84, "FlowStreamUpsertV1 size mismatch");

inline constexpr bool IsVersionSupported(std::uint8_t version) {
  return version == kVersionV1 || version == kVersionV2;
}

inline constexpr bool IsHeaderV1Compatible(const SamuraiWireHeaderV1& header) {
  return header.magic == kMagic && IsVersionSupported(header.version);
}

}  // namespace samurai::wire
