#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace samurai::wire {

inline constexpr std::uint32_t kMagic = 0x534D5249u;  // "SMRI"
inline constexpr std::uint8_t kVersionV1 = 1u;
// V2 adds L7 profile fields (concurrency, connection pool, scheme/TLS, etc.)
// behind a JobEnvelopeV2 that embeds JobEnvelopeV1 as its first member, so the
// V1 prefix stays binary-compatible with existing V1-only parsers.
inline constexpr std::uint8_t kVersionV2 = 2u;
// V3 introduces a naturally 8-byte aligned, non-packed, self-describing wire
// header and sectioned job envelope (base + optional L7/Telco/Telemetry
// sections) so fields never rely on `#pragma pack` and unknown extensions are
// skipped cleanly for forward compatibility.
inline constexpr std::uint8_t kVersionV3 = 3u;
inline constexpr std::uint16_t kSchemaMajorV3 = 3u;
inline constexpr std::uint16_t kSchemaMinorV3 = 0u;

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
  RECONFIGURE_JOB = 5,
  SET_TELEMETRY = 6,
  PING = 7,

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

enum class TelcoProtocolKind : std::uint8_t {
  PPPOE = 1,
  DHCP  = 2,
  BFD   = 3,
  GTPU  = 4,
  QINQ  = 5,
  ARP   = 6,
  PFCP  = 7,
  SCTP  = 8,
  DIAMETER = 9,
  SIP_RTP = 10,
  MULTI = 11,
};

namespace ReconfigureFlag {
inline constexpr std::uint32_t kRps = 1u << 0;
inline constexpr std::uint32_t kPacingMode = 1u << 1;
inline constexpr std::uint32_t kJitter = 1u << 2;
inline constexpr std::uint32_t kBurst = 1u << 3;
inline constexpr std::uint32_t kRequestMix = 1u << 4;
inline constexpr std::uint32_t kSourceRotation = 1u << 5;
inline constexpr std::uint32_t kTelcoCps = 1u << 6;
inline constexpr std::uint32_t kIpg = 1u << 7;
}  // namespace ReconfigureFlag

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

struct TelemetryConfigV1 {
  std::uint8_t enabled;
  std::uint8_t netflow_v9;
  std::uint16_t collector_port;
  std::uint32_t sample_rate;
  std::uint32_t domain_id;
  std::uint32_t export_interval_ms;
  char collector_ip[16];
};

struct ReconfigureWindowV1 {
  std::uint32_t flags;
  std::uint8_t pacing_mode;
  std::uint8_t jitter_model;
  std::uint16_t pad0;
  double target_rps;
  double jitter_pct;
  std::uint64_t ipg_ns;
  std::uint32_t burst_size;
  std::uint32_t request_mix;
  std::uint32_t source_rotation;
  std::uint32_t telco_rate_cps;
};

struct TelcoJobEnvelopeV1 {
  JobEnvelopeV1 base;
  std::uint32_t subscriber_start_idx;
  std::uint32_t subscriber_count;
  std::uint32_t rate_cps;
  std::uint32_t sctp_rate;
  std::uint32_t diameter_rate;
  std::uint32_t sip_rate;
  std::uint32_t teid_start;
  std::uint32_t teid_count;
  std::uint32_t base_client_ip;
  std::uint32_t gateway_ip;
  std::uint32_t duration_ms;
  std::uint16_t base_vlan_s;
  std::uint16_t base_vlan_c;
  std::uint16_t db_port;
  std::uint8_t qfi;
  std::uint8_t inner_proto;
  std::uint8_t enable_srtp;
  std::uint8_t telco_protocol_kind;
  std::uint8_t base_mac[6];
  char telco_protocol_name[16];
  char auth_username[32];
  char auth_password[32];
  std::uint8_t pad[20];
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
static_assert(sizeof(TelemetryConfigV1) == 32, "TelemetryConfigV1 size mismatch");
static_assert(sizeof(ReconfigureWindowV1) == 48, "ReconfigureWindowV1 size mismatch");
static_assert(sizeof(TelcoJobEnvelopeV1) == 640, "TelcoJobEnvelopeV1 size mismatch");
static_assert(offsetof(TelcoJobEnvelopeV1, base) == 0, "TelcoJobEnvelopeV1 must embed V1 at offset 0");

inline constexpr bool IsVersionSupported(std::uint8_t version) {
  return version == kVersionV1 || version == kVersionV2 || version == kVersionV3;
}

inline constexpr bool IsHeaderV1Compatible(const SamuraiWireHeaderV1& header) {
  return header.magic == kMagic && (header.version == kVersionV1 || header.version == kVersionV2);
}

// ============================================================================
// Wire Protocol ABI V3: Naturally 8-byte aligned, non-packed, extensible
// ============================================================================

enum class JobExtKind : std::uint16_t {
  NONE = 0,
  L7 = 1,
  TELCO = 2,
  TELEMETRY = 3,
};

struct alignas(8) SamuraiWireHeaderV3 {
  std::uint32_t magic;
  std::uint8_t version;
  std::uint8_t msg_type;
  std::uint16_t header_bytes;
  std::uint32_t payload_len;
  std::uint16_t schema_major;
  std::uint16_t schema_minor;
  std::uint64_t correlation_id;
  std::uint32_t flags;
  std::uint8_t worker_kind;
  std::uint8_t ext_count;
  std::uint16_t reserved;
  char job_id[32];
};

struct alignas(8) JobExtHeaderV3 {
  std::uint16_t kind;
  std::uint16_t version;
  std::uint32_t section_bytes;
  std::uint64_t flags;
};

struct alignas(8) JobEnvelopeV3 {
  std::uint16_t struct_bytes;
  std::uint16_t schema_minor;
  std::uint32_t section_flags;
  double target_rps;
  double jitter_pct;
  std::uint64_t ipg_ns;
  std::uint64_t burst_gap_ns;
  std::uint32_t packet_count;
  std::uint32_t packet_size;
  std::uint32_t burst_size;
  std::int32_t pin_cpu;
  std::uint32_t xdp_queue_id;
  std::uint32_t xdp_mode;
  std::uint32_t pad_size;
  std::uint32_t reserved0;
  std::uint16_t target_port;
  std::uint16_t window;
  std::uint16_t fragment_size;
  std::uint8_t pacing_mode;
  std::uint8_t jitter_model;
  std::uint8_t use_so_txtime;
  std::uint8_t spoof_enabled;
  std::uint8_t has_payload;
  std::uint8_t ttl;
  std::uint8_t tos;
  std::uint8_t fragment_enabled;
  std::uint8_t dns_edns;
  std::uint8_t dns_recursive;
  char target_ip[16];
  char xdp_interface[16];
  char scenario_payload_ref[64];
  char protocol[8];
  char tcp_flags[8];
  char spoof_mode[16];
  char spoof_subnet[32];
  char spoof_list_file[64];
  char payload_ref[64];
  char attack_vector[16];
  char dns_name[64];
  char dns_qtype[32];
};

struct alignas(8) JobSectionL7V3 {
  std::uint32_t concurrency;
  std::uint32_t max_connections;
  std::uint32_t max_streams_per_connection;
  std::uint32_t l7_timeout_ms;
  std::uint32_t request_mix;
  std::uint32_t source_rotation;
  std::uint32_t auth_mode;
  std::uint32_t evasion_tactic;
  std::uint8_t verify_tls;
  std::uint8_t keepalive;
  std::uint8_t reserved[6];
  char scheme[16];
  char host_header[128];
  char auth_payload[128];
};

struct alignas(8) JobSectionTelcoV3 {
  std::uint32_t subscriber_start_idx;
  std::uint32_t subscriber_count;
  std::uint32_t rate_cps;
  std::uint32_t sctp_rate;
  std::uint32_t diameter_rate;
  std::uint32_t sip_rate;
  std::uint32_t teid_start;
  std::uint32_t teid_count;
  std::uint32_t base_client_ip;
  std::uint32_t gateway_ip;
  std::uint32_t duration_ms;
  std::uint32_t gtpu_flags;
  std::uint16_t base_vlan_s;
  std::uint16_t base_vlan_c;
  std::uint16_t db_port;
  std::uint8_t qfi;
  std::uint8_t inner_proto;
  std::uint8_t enable_srtp;
  std::uint8_t telco_protocol_kind;
  std::uint8_t base_mac[6];
  char telco_protocol_name[16];
  char auth_username[32];
  char auth_password[32];
};

struct alignas(8) JobSectionTelemetryV3 {
  std::uint8_t enabled;
  std::uint8_t netflow_v9;
  std::uint16_t collector_port;
  std::uint32_t sample_rate;
  std::uint32_t domain_id;
  std::uint32_t export_interval_ms;
  char collector_ip[16];
};

static_assert(alignof(SamuraiWireHeaderV3) == 8, "SamuraiWireHeaderV3 must be 8B aligned");
static_assert(sizeof(SamuraiWireHeaderV3) == 64, "SamuraiWireHeaderV3 size must be 64B");
static_assert(alignof(JobExtHeaderV3) == 8, "JobExtHeaderV3 must be 8B aligned");
static_assert(sizeof(JobExtHeaderV3) == 16, "JobExtHeaderV3 size must be 16B");
static_assert(alignof(JobEnvelopeV3) == 8, "JobEnvelopeV3 must be 8B aligned");
static_assert(sizeof(JobEnvelopeV3) == 488, "JobEnvelopeV3 size must be 488B");
static_assert(sizeof(JobEnvelopeV3) % 8 == 0, "JobEnvelopeV3 size must be multiple of 8");
static_assert(alignof(JobSectionL7V3) == 8, "JobSectionL7V3 must be 8B aligned");
static_assert(sizeof(JobSectionL7V3) == 312, "JobSectionL7V3 size must be 312B");
static_assert(alignof(JobSectionTelcoV3) == 8, "JobSectionTelcoV3 must be 8B aligned");
static_assert(sizeof(JobSectionTelcoV3) == 144, "JobSectionTelcoV3 size must be 144B");
static_assert(alignof(JobSectionTelemetryV3) == 8, "JobSectionTelemetryV3 must be 8B aligned");
static_assert(sizeof(JobSectionTelemetryV3) == 32, "JobSectionTelemetryV3 size must be 32B");

inline constexpr bool IsHeaderV3Compatible(const SamuraiWireHeaderV3& header) {
  return header.magic == kMagic &&
         header.version == kVersionV3 &&
         header.header_bytes >= sizeof(SamuraiWireHeaderV3);
}

inline JobEnvelopeV3 FromJobEnvelopeV1(const JobEnvelopeV1& v1) {
  JobEnvelopeV3 v3{};
  v3.struct_bytes = static_cast<std::uint16_t>(sizeof(JobEnvelopeV3));
  v3.schema_minor = kSchemaMinorV3;
  v3.target_rps = v1.target_rps;
  v3.jitter_pct = v1.jitter_pct;
  v3.ipg_ns = v1.ipg_ns;
  v3.burst_gap_ns = v1.burst_gap_ns;
  v3.packet_count = v1.packet_count;
  v3.packet_size = v1.packet_size;
  v3.burst_size = v1.burst_size;
  v3.pin_cpu = v1.pin_cpu;
  v3.xdp_queue_id = v1.xdp_queue_id;
  v3.xdp_mode = v1.xdp_mode;
  v3.pad_size = v1.pad_size;
  v3.target_port = v1.target_port;
  v3.window = v1.window;
  v3.fragment_size = v1.fragment_size;
  v3.pacing_mode = v1.pacing_mode;
  v3.jitter_model = v1.jitter_model;
  v3.use_so_txtime = v1.use_so_txtime;
  v3.spoof_enabled = v1.spoof_enabled;
  v3.has_payload = v1.has_payload;
  v3.ttl = v1.ttl;
  v3.tos = v1.tos;
  v3.fragment_enabled = v1.fragment_enabled;
  v3.dns_edns = v1.dns_edns;
  v3.dns_recursive = v1.dns_recursive;
  std::memcpy(v3.target_ip, v1.target_ip, sizeof(v3.target_ip));
  std::memcpy(v3.xdp_interface, v1.xdp_interface, sizeof(v3.xdp_interface));
  std::memcpy(v3.scenario_payload_ref, v1.scenario_payload_ref, sizeof(v3.scenario_payload_ref));
  std::memcpy(v3.protocol, v1.protocol, sizeof(v3.protocol));
  std::memcpy(v3.tcp_flags, v1.tcp_flags, sizeof(v3.tcp_flags));
  std::memcpy(v3.spoof_mode, v1.spoof_mode, sizeof(v3.spoof_mode));
  std::memcpy(v3.spoof_subnet, v1.spoof_subnet, sizeof(v3.spoof_subnet));
  std::memcpy(v3.spoof_list_file, v1.spoof_list_file, sizeof(v3.spoof_list_file));
  std::memcpy(v3.payload_ref, v1.payload_ref, sizeof(v3.payload_ref));
  std::memcpy(v3.attack_vector, v1.attack_vector, sizeof(v3.attack_vector));
  std::memcpy(v3.dns_name, v1.dns_name, sizeof(v3.dns_name));
  std::memcpy(v3.dns_qtype, v1.dns_qtype, sizeof(v3.dns_qtype));
  return v3;
}

inline JobEnvelopeV1 ToJobEnvelopeV1(const JobEnvelopeV3& v3) {
  JobEnvelopeV1 v1{};
  v1.target_rps = v3.target_rps;
  v1.jitter_pct = v3.jitter_pct;
  v1.ipg_ns = v3.ipg_ns;
  v1.burst_gap_ns = v3.burst_gap_ns;
  v1.packet_count = v3.packet_count;
  v1.packet_size = v3.packet_size;
  v1.burst_size = v3.burst_size;
  v1.pin_cpu = v3.pin_cpu;
  v1.xdp_queue_id = v3.xdp_queue_id;
  v1.xdp_mode = v3.xdp_mode;
  v1.pad_size = v3.pad_size;
  v1.target_port = v3.target_port;
  v1.window = v3.window;
  v1.fragment_size = v3.fragment_size;
  v1.pacing_mode = v3.pacing_mode;
  v1.jitter_model = v3.jitter_model;
  v1.use_so_txtime = v3.use_so_txtime;
  v1.spoof_enabled = v3.spoof_enabled;
  v1.has_payload = v3.has_payload;
  v1.ttl = v3.ttl;
  v1.tos = v3.tos;
  v1.fragment_enabled = v3.fragment_enabled;
  v1.dns_edns = v3.dns_edns;
  v1.dns_recursive = v3.dns_recursive;
  std::memcpy(v1.target_ip, v3.target_ip, sizeof(v1.target_ip));
  std::memcpy(v1.xdp_interface, v3.xdp_interface, sizeof(v1.xdp_interface));
  std::memcpy(v1.scenario_payload_ref, v3.scenario_payload_ref, sizeof(v1.scenario_payload_ref));
  std::memcpy(v1.protocol, v3.protocol, sizeof(v1.protocol));
  std::memcpy(v1.tcp_flags, v3.tcp_flags, sizeof(v1.tcp_flags));
  std::memcpy(v1.spoof_mode, v3.spoof_mode, sizeof(v1.spoof_mode));
  std::memcpy(v1.spoof_subnet, v3.spoof_subnet, sizeof(v1.spoof_subnet));
  std::memcpy(v1.spoof_list_file, v3.spoof_list_file, sizeof(v1.spoof_list_file));
  std::memcpy(v1.payload_ref, v3.payload_ref, sizeof(v1.payload_ref));
  std::memcpy(v1.attack_vector, v3.attack_vector, sizeof(v1.attack_vector));
  std::memcpy(v1.dns_name, v3.dns_name, sizeof(v1.dns_name));
  std::memcpy(v1.dns_qtype, v3.dns_qtype, sizeof(v1.dns_qtype));
  return v1;
}

inline void FromJobEnvelopeV2(const JobEnvelopeV2& v2, JobEnvelopeV3& base, JobSectionL7V3& l7) {
  base = FromJobEnvelopeV1(v2.base);
  base.section_flags |= static_cast<std::uint32_t>(JobExtKind::L7);
  l7 = JobSectionL7V3{};
  l7.concurrency = v2.concurrency;
  l7.max_connections = v2.max_connections;
  l7.max_streams_per_connection = v2.max_streams_per_connection;
  l7.l7_timeout_ms = v2.l7_timeout_ms;
  l7.request_mix = v2.request_mix;
  l7.source_rotation = v2.source_rotation;
  l7.auth_mode = v2.auth_mode;
  l7.evasion_tactic = v2.evasion_tactic;
  l7.verify_tls = v2.verify_tls;
  l7.keepalive = v2.keepalive;
  std::memcpy(l7.scheme, v2.scheme, sizeof(l7.scheme));
  std::memcpy(l7.host_header, v2.host_header, sizeof(l7.host_header));
  std::memcpy(l7.auth_payload, v2.auth_payload, sizeof(l7.auth_payload));
}

inline JobEnvelopeV2 ToJobEnvelopeV2(const JobEnvelopeV3& base, const JobSectionL7V3& l7) {
  JobEnvelopeV2 v2{};
  v2.base = ToJobEnvelopeV1(base);
  v2.concurrency = l7.concurrency;
  v2.max_connections = l7.max_connections;
  v2.max_streams_per_connection = l7.max_streams_per_connection;
  v2.l7_timeout_ms = l7.l7_timeout_ms;
  v2.request_mix = l7.request_mix;
  v2.source_rotation = l7.source_rotation;
  v2.auth_mode = l7.auth_mode;
  v2.evasion_tactic = l7.evasion_tactic;
  v2.verify_tls = l7.verify_tls;
  v2.keepalive = l7.keepalive;
  std::memcpy(v2.scheme, l7.scheme, sizeof(v2.scheme));
  std::memcpy(v2.host_header, l7.host_header, sizeof(v2.host_header));
  std::memcpy(v2.auth_payload, l7.auth_payload, sizeof(v2.auth_payload));
  return v2;
}

inline void FromTelcoJobEnvelopeV1(
    const TelcoJobEnvelopeV1& te, JobEnvelopeV3& base, JobSectionTelcoV3& telco) {
  base = FromJobEnvelopeV1(te.base);
  base.section_flags |= static_cast<std::uint32_t>(JobExtKind::TELCO);
  telco = JobSectionTelcoV3{};
  telco.subscriber_start_idx = te.subscriber_start_idx;
  telco.subscriber_count = te.subscriber_count;
  telco.rate_cps = te.rate_cps;
  telco.sctp_rate = te.sctp_rate;
  telco.diameter_rate = te.diameter_rate;
  telco.sip_rate = te.sip_rate;
  telco.teid_start = te.teid_start;
  telco.teid_count = te.teid_count;
  telco.base_client_ip = te.base_client_ip;
  telco.gateway_ip = te.gateway_ip;
  telco.duration_ms = te.duration_ms;
  telco.base_vlan_s = te.base_vlan_s;
  telco.base_vlan_c = te.base_vlan_c;
  telco.db_port = te.db_port;
  telco.qfi = te.qfi;
  telco.inner_proto = te.inner_proto;
  telco.enable_srtp = te.enable_srtp;
  telco.telco_protocol_kind = te.telco_protocol_kind;
  std::memcpy(telco.base_mac, te.base_mac, sizeof(telco.base_mac));
  std::memcpy(telco.telco_protocol_name, te.telco_protocol_name, sizeof(telco.telco_protocol_name));
  std::memcpy(telco.auth_username, te.auth_username, sizeof(telco.auth_username));
  std::memcpy(telco.auth_password, te.auth_password, sizeof(telco.auth_password));
}

inline TelcoJobEnvelopeV1 ToTelcoJobEnvelopeV1(
    const JobEnvelopeV3& base, const JobSectionTelcoV3& telco) {
  TelcoJobEnvelopeV1 te{};
  te.base = ToJobEnvelopeV1(base);
  te.subscriber_start_idx = telco.subscriber_start_idx;
  te.subscriber_count = telco.subscriber_count;
  te.rate_cps = telco.rate_cps;
  te.sctp_rate = telco.sctp_rate;
  te.diameter_rate = telco.diameter_rate;
  te.sip_rate = telco.sip_rate;
  te.teid_start = telco.teid_start;
  te.teid_count = telco.teid_count;
  te.base_client_ip = telco.base_client_ip;
  te.gateway_ip = telco.gateway_ip;
  te.duration_ms = telco.duration_ms;
  te.base_vlan_s = telco.base_vlan_s;
  te.base_vlan_c = telco.base_vlan_c;
  te.db_port = telco.db_port;
  te.qfi = telco.qfi;
  te.inner_proto = telco.inner_proto;
  te.enable_srtp = telco.enable_srtp;
  te.telco_protocol_kind = telco.telco_protocol_kind;
  std::memcpy(te.base_mac, telco.base_mac, sizeof(te.base_mac));
  std::memcpy(te.telco_protocol_name, telco.telco_protocol_name, sizeof(te.telco_protocol_name));
  std::memcpy(te.auth_username, telco.auth_username, sizeof(te.auth_username));
  std::memcpy(te.auth_password, telco.auth_password, sizeof(te.auth_password));
  return te;
}

inline void FromTelcoGpuJobEnvelopeV1(
    const TelcoGpuJobEnvelopeV1& tge, JobEnvelopeV3& base, JobSectionTelcoV3& telco) {
  base = FromJobEnvelopeV1(tge.base);
  base.section_flags |= static_cast<std::uint32_t>(JobExtKind::TELCO);
  telco = JobSectionTelcoV3{};
  telco.teid_start = tge.teid_start;
  telco.teid_count = tge.teid_count;
  telco.subscriber_count = tge.teid_count;
  telco.base_client_ip = tge.ue_src_ip_start;
  telco.base_vlan_s = tge.svlan_tci;
  telco.base_vlan_c = tge.cvlan_tci;
  telco.qfi = tge.qfi;
  telco.inner_proto = tge.inner_proto;
  telco.gtpu_flags = tge.flags;
}

inline TelcoGpuJobEnvelopeV1 ToTelcoGpuJobEnvelopeV1(
    const JobEnvelopeV3& base, const JobSectionTelcoV3& telco) {
  TelcoGpuJobEnvelopeV1 tge{};
  tge.base = ToJobEnvelopeV1(base);
  tge.teid_start = telco.teid_start;
  tge.teid_count = telco.teid_count;
  tge.ue_src_ip_start = telco.base_client_ip;
  tge.svlan_tci = telco.base_vlan_s;
  tge.cvlan_tci = telco.base_vlan_c;
  tge.qfi = telco.qfi;
  tge.inner_proto = telco.inner_proto;
  tge.flags = static_cast<std::uint8_t>(telco.gtpu_flags & 0xFFu);
  return tge;
}

struct JobV3Payload {
  JobEnvelopeV3 base{};
  bool has_l7 = false;
  JobSectionL7V3 l7{};
  bool has_telco = false;
  JobSectionTelcoV3 telco{};
  bool has_telemetry = false;
  JobSectionTelemetryV3 telemetry{};
};

inline std::vector<std::uint8_t> SerializeJobV3Payload(
    const JobV3Payload& in, std::uint8_t* out_ext_count = nullptr) {
  JobEnvelopeV3 base = in.base;
  base.struct_bytes = static_cast<std::uint16_t>(sizeof(JobEnvelopeV3));
  base.schema_minor = kSchemaMinorV3;
  std::uint8_t ext_cnt = 0;
  std::vector<std::uint8_t> buf(sizeof(base));

  auto append_section = [&](JobExtKind kind, const void* sec, std::size_t sec_sz) {
    JobExtHeaderV3 eh{};
    eh.kind = static_cast<std::uint16_t>(kind);
    eh.version = 1;
    eh.section_bytes = static_cast<std::uint32_t>(sec_sz);
    eh.flags = 0;
    const std::size_t off = buf.size();
    buf.resize(off + sizeof(eh) + sec_sz);
    std::memcpy(buf.data() + off, &eh, sizeof(eh));
    std::memcpy(buf.data() + off + sizeof(eh), sec, sec_sz);
    ++ext_cnt;
  };

  if (in.has_l7) {
    base.section_flags |= (1u << 0);
    append_section(JobExtKind::L7, &in.l7, sizeof(in.l7));
  }
  if (in.has_telco) {
    base.section_flags |= (1u << 1);
    append_section(JobExtKind::TELCO, &in.telco, sizeof(in.telco));
  }
  if (in.has_telemetry) {
    base.section_flags |= (1u << 2);
    append_section(JobExtKind::TELEMETRY, &in.telemetry, sizeof(in.telemetry));
  }
  std::memcpy(buf.data(), &base, sizeof(base));
  if (out_ext_count) *out_ext_count = ext_cnt;
  return buf;
}

inline bool ParseJobV3Payload(
    const std::uint8_t* payload,
    std::size_t payload_len,
    std::uint8_t ext_count,
    JobV3Payload& out) {
  out = JobV3Payload{};
  if (!payload || payload_len < sizeof(std::uint16_t)) return false;
  std::uint16_t base_bytes = 0;
  std::memcpy(&base_bytes, payload, sizeof(base_bytes));
  if (base_bytes < 64 || base_bytes > payload_len) return false;
  const std::size_t base_copy = std::min<std::size_t>(base_bytes, sizeof(JobEnvelopeV3));
  std::memcpy(&out.base, payload, base_copy);

  std::size_t offset = base_bytes;
  for (std::uint8_t i = 0; i < ext_count; ++i) {
    if (offset + sizeof(JobExtHeaderV3) > payload_len) return false;
    JobExtHeaderV3 eh{};
    std::memcpy(&eh, payload + offset, sizeof(eh));
    offset += sizeof(eh);
    if (offset + eh.section_bytes > payload_len) return false;
    const auto kind = static_cast<JobExtKind>(eh.kind);
    if (kind == JobExtKind::L7) {
      out.has_l7 = true;
      std::memcpy(&out.l7, payload + offset,
                  std::min<std::size_t>(eh.section_bytes, sizeof(JobSectionL7V3)));
    } else if (kind == JobExtKind::TELCO) {
      out.has_telco = true;
      std::memcpy(&out.telco, payload + offset,
                  std::min<std::size_t>(eh.section_bytes, sizeof(JobSectionTelcoV3)));
    } else if (kind == JobExtKind::TELEMETRY) {
      out.has_telemetry = true;
      std::memcpy(&out.telemetry, payload + offset,
                  std::min<std::size_t>(eh.section_bytes, sizeof(JobSectionTelemetryV3)));
    }
    offset += eh.section_bytes;
  }
  return true;
}

struct DecodedWireFrame {
  std::uint8_t version = 0;
  std::uint8_t msg_type = 0;
  std::uint8_t worker_kind = 0;
  std::uint8_t ext_count = 0;
  std::uint16_t flags = 0;
  std::uint32_t payload_len = 0;
  std::uint64_t correlation_id = 0;
  std::string job_id;
  const std::uint8_t* payload_ptr = nullptr;
  std::size_t actual_payload_len = 0;
  SamuraiWireHeaderV1 as_v1_header{};
};

inline bool DecodeWireFrame(const void* data, std::size_t size, DecodedWireFrame& out) {
  out = DecodedWireFrame{};
  if (!data || size < 6) return false;
  const auto* raw = static_cast<const std::uint8_t*>(data);
  std::uint32_t magic = 0;
  std::memcpy(&magic, raw, sizeof(magic));
  if (magic != kMagic) return false;
  const std::uint8_t ver = raw[4];

  if (ver == kVersionV1 || ver == kVersionV2) {
    if (size < sizeof(SamuraiWireHeaderV1)) return false;
    SamuraiWireHeaderV1 h1{};
    std::memcpy(&h1, raw, sizeof(h1));
    out.version = h1.version;
    out.msg_type = h1.msg_type;
    out.worker_kind = h1.worker_kind;
    out.flags = h1.flags;
    out.payload_len = h1.payload_len;
    out.correlation_id = h1.correlation_id;
    out.job_id.assign(h1.job_id, strnlen(h1.job_id, sizeof(h1.job_id)));
    out.payload_ptr = raw + sizeof(h1);
    out.actual_payload_len = size - sizeof(h1);
    out.as_v1_header = h1;
    return true;
  }

  if (ver == kVersionV3) {
    if (size < sizeof(SamuraiWireHeaderV3)) return false;
    SamuraiWireHeaderV3 h3{};
    std::memcpy(&h3, raw, sizeof(h3));
    if (!IsHeaderV3Compatible(h3) || size < h3.header_bytes) return false;
    out.version = h3.version;
    out.msg_type = h3.msg_type;
    out.worker_kind = h3.worker_kind;
    out.ext_count = h3.ext_count;
    out.flags = static_cast<std::uint16_t>(h3.flags & 0xFFFFu);
    out.payload_len = h3.payload_len;
    out.correlation_id = h3.correlation_id;
    out.job_id.assign(h3.job_id, strnlen(h3.job_id, sizeof(h3.job_id)));
    out.payload_ptr = raw + h3.header_bytes;
    out.actual_payload_len = size - h3.header_bytes;
    // Synthesize a V1 header view so shared helpers work seamlessly across V1/V2/V3.
    out.as_v1_header.magic = h3.magic;
    out.as_v1_header.version = h3.version;
    out.as_v1_header.msg_type = h3.msg_type;
    out.as_v1_header.payload_len = h3.payload_len;
    out.as_v1_header.flags = out.flags;
    out.as_v1_header.correlation_id = h3.correlation_id;
    out.as_v1_header.worker_kind = h3.worker_kind;
    std::memcpy(out.as_v1_header.job_id, h3.job_id, sizeof(out.as_v1_header.job_id));
    return true;
  }

  return false;
}

}  // namespace samurai::wire
