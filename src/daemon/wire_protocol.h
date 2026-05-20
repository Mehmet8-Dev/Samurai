#pragma once

#include <cstddef>
#include <cstdint>

namespace samurai::wire {

inline constexpr std::uint32_t kMagic = 0x534D5249u;  // "SMRI"
inline constexpr std::uint8_t kVersionV1 = 1u;

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
  std::uint8_t pad[3];
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

#pragma pack(pop)

enum class MessageType : std::uint8_t {
  START_JOB = 1,
  STOP_JOB = 2,
  SHUTDOWN = 3,

  ACK = 10,
  HEARTBEAT = 11,

  METRIC_SNAPSHOT = 20,

  ERROR = 30,

  JOB_DONE = 40,
};

enum class WorkerKind : std::uint8_t {
  CPU = 1,
  GPU = 2,
  DPDK = 3,
  AF_XDP = 4,
  DOCA = 5,
  L7 = 6,
  DEFENSE = 7,
};

static_assert(sizeof(SamuraiWireHeaderV1) == 56, "SamuraiWireHeaderV1 size mismatch");
static_assert(sizeof(JobEnvelopeV1) == 160, "JobEnvelopeV1 size mismatch");
static_assert(sizeof(MetricSnapshotV1) == 64, "MetricSnapshotV1 size mismatch");

inline constexpr bool IsHeaderV1Compatible(const SamuraiWireHeaderV1& header) {
  return header.magic == kMagic && header.version == kVersionV1;
}

}  // namespace samurai::wire
