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
  // Mahoraga shaping levers (RL action dims). Carved out of the former pad2[8]
  // tail so sizeof(JobEnvelopeV2) is unchanged and older blobs (which zeroed the
  // pad) decode as request_mix=0 / source_rotation=0 = "no shaping".
  std::uint32_t request_mix;                  // L7: request-variant selector (0 = baseline GET /)
  std::uint32_t source_rotation;             // L7: client source-identity spread (0/1 = single)
  std::uint32_t auth_mode;                   // L7: 0=Anon, 1=Bearer JWT, 2=Cookie
  std::uint32_t evasion_tactic;              // L7: 0=Normal, 1=Path Traversal, 2=URL Encoded, 3=Header Spoof
  char auth_payload[128];                   // L7: dynamic json auth payload
};

// Telco GPU job envelope: embeds JobEnvelopeV1 for base rate/timing/spoof config,
// and appends 3GPP TS 29.281 GTP-U and 5G TS 38.415 QFI dataplane parameters.
enum TelcoGpuJobFlags : std::uint8_t {
  kTelcoGpuJobFlagNone       = 0u,
  kTelcoGpuJobFlagBar1P2p    = 1u << 0,
  kTelcoGpuJobFlagPersistent = 1u << 1,
};

enum TelcoGpuTunnelUpsertFlags : std::uint32_t {
  kTelcoTunnelUpsertFlagNone              = 0u,
  kTelcoTunnelUpsertFlagClearBeforeUpsert = 1u << 0,
};

struct TelcoGpuJobEnvelopeV1 {
  JobEnvelopeV1 base; // 480B

  std::uint32_t teid_start;
  std::uint32_t teid_count;
  std::uint32_t ue_src_ip_start;
  std::uint32_t ue_src_ip_count;
  std::uint32_t inner_dst_ip;
  std::uint16_t inner_src_port;
  std::uint16_t inner_dst_port;
  std::uint16_t svlan_tci;
  std::uint16_t cvlan_tci;
  std::uint8_t  qfi;             // 0..63
  std::uint8_t  pdu_type;        // 1=UL, 0=DL
  std::uint8_t  inner_proto;     // 17=UDP, 6=TCP, 1=ICMP
  std::uint8_t  vlan_depth;      // 0=none, 1=802.1Q, 2=802.1ad
  std::uint8_t  with_seq;        // 1 or 0
  std::uint8_t  with_qfi_ext;    // 1 or 0
  std::uint8_t  echo_mode;       // 1 or 0
  std::uint8_t  flags;           // Bitmask of TelcoGpuJobFlags
  std::uint8_t  pad[12];
};

struct TelcoGpuTunnelUpsertV1 {
  std::uint32_t count;
  std::uint32_t flags; // 1 = clear_before_upsert
  std::uint8_t  pad[8];
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
  ABORT = 4,

  ACK = 10,
  HEARTBEAT = 11,

  METRIC_SNAPSHOT = 20,
  FLOW_UPDATE = 21,
  FLOW_STREAM_UPSERT = 22,
  TELCO_TUNNEL_UPSERT = 23,

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
  TELCO = 10,
};

enum class TelcoMsgType : uint16_t {
  START_PPPOE_EMULATION = 0x0501,
  STOP_PPPOE_EMULATION  = 0x0502,
  START_GTPU_EMULATION  = 0x0503,
  STOP_GTPU_EMULATION   = 0x0504,
  START_DHCP_EMULATION  = 0x0505,
  STOP_DHCP_EMULATION   = 0x0506,
  START_BFD_EMULATION   = 0x0507,
  STOP_BFD_EMULATION    = 0x0508,
  START_QINQ_SWEEP      = 0x0509,
  STOP_QINQ_SWEEP       = 0x050A,
  START_ARP_FLOOD       = 0x050B,
  STOP_ARP_FLOOD        = 0x050C,
  TELCO_STATS_REQUEST   = 0x050D,
  TELCO_STATS_REPORT    = 0x050E,
  TELCO_CHAOS_INJECT    = 0x050F,
};

enum class TelcoProtocolKind : uint8_t {
  PPPOE = 1,
  DHCP  = 2,
  BFD   = 3,
  GTPU  = 4,
  QINQ  = 5,
  ARP   = 6,
};

#pragma pack(push, 1)

struct TelcoJobPayload {
  uint32_t subscriber_start_idx;
  uint32_t subscriber_count;
  uint32_t rate_cps;
  uint8_t  protocol_kind;
  uint16_t base_vlan_s;
  uint16_t base_vlan_c;
  uint8_t  base_mac[6];
  uint32_t base_client_ip;
  uint32_t gateway_ip;
  char     auth_username[32];
  char     auth_password[32];
  int32_t  pin_cpu;
  uint16_t db_port;
  uint8_t  pad[3];
};

struct TelcoChaosPayload {
  uint8_t  chaos_type; // 1: PADT/Release flood, 2: link flap, 3: packet drop
  uint32_t duration_ms;
  uint32_t drop_ratio_pct;
  uint32_t affected_subscribers;
  uint8_t  pad[3];
};

struct TelcoStatsPayload {
  uint32_t active_sessions;
  uint32_t established_sessions;
  uint32_t failed_sessions;
  uint32_t current_cps;
  uint64_t tx_packets;
  uint64_t rx_packets;
  uint64_t tx_bytes;
  uint64_t rx_bytes;
  uint32_t avg_setup_latency_us;
  uint32_t p99_setup_latency_us;
  uint32_t retransmit_count;
  uint16_t db_port;
  uint8_t  pad[2];
};

#pragma pack(pop)

static_assert(sizeof(SamuraiWireHeaderV1) == 56, "SamuraiWireHeaderV1 size mismatch");
static_assert(sizeof(JobEnvelopeV1) == 480, "JobEnvelopeV1 size mismatch");
static_assert(sizeof(JobEnvelopeV2) > sizeof(JobEnvelopeV1), "JobEnvelopeV2 must extend V1");
static_assert(sizeof(JobEnvelopeV2) == 786, "JobEnvelopeV2 size pinned (request_mix/source_rotation/auth/evasion)");
static_assert(offsetof(JobEnvelopeV2, base) == 0, "JobEnvelopeV2 must embed V1 at offset 0");
static_assert(sizeof(MetricSnapshotV1) == 64, "MetricSnapshotV1 size mismatch");
static_assert(sizeof(FlowUpdateEventV1) == 48, "FlowUpdateEventV1 size mismatch");
static_assert(sizeof(FlowStreamUpsertV1) == 84, "FlowStreamUpsertV1 size mismatch");
static_assert(sizeof(TelcoJobPayload) == 104, "TelcoJobPayload size mismatch");
static_assert(sizeof(TelcoChaosPayload) == 16, "TelcoChaosPayload size mismatch");
static_assert(sizeof(TelcoStatsPayload) == 64, "TelcoStatsPayload size mismatch");
static_assert(sizeof(TelcoGpuJobEnvelopeV1) == 528, "TelcoGpuJobEnvelopeV1 size mismatch");
static_assert(offsetof(TelcoGpuJobEnvelopeV1, base) == 0, "TelcoGpuJobEnvelopeV1 must embed V1 at offset 0");
static_assert(sizeof(TelcoGpuTunnelUpsertV1) == 16, "TelcoGpuTunnelUpsertV1 size mismatch");

inline constexpr bool IsVersionSupported(std::uint8_t version) {
  return version == kVersionV1 || version == kVersionV2;
}

inline constexpr bool IsHeaderV1Compatible(const SamuraiWireHeaderV1& header) {
  return header.magic == kMagic && IsVersionSupported(header.version);
}

}  // namespace samurai::wire
