#pragma once

#include <cstdint>

namespace ddos_samurai::gpu_packet_cuda::zero_copy {

enum class RingOverflowPolicy : int32_t {
  kHardFail = 0,
  kControlledDrop = 1,
};

enum class DescriptorOwnershipState : int32_t {
  kFree = 0,
  kGpuWriting = 1,
  kReadyForNic = 2,
  kNicOwned = 3,
  kComplete = 4,
};

struct alignas(64) FlowUpdateEventV1 {
  uint64_t version = 0u;
  uint64_t epoch = 0u;
  uint32_t flow_id = 0u;
  uint32_t tcp_seq = 0u;
  uint32_t tcp_ack = 0u;
  uint16_t src_port = 0u;
  uint16_t dst_port = 0u;
  uint8_t tcp_state = 0u;
  uint8_t proto = 0u;
  uint16_t flags = 0u;
  uint32_t rtt_us = 0u;
  uint64_t dpu_ts_ns = 0u;
};

struct FlowAffinityV1 {
  int64_t global_tid = 0;
  int32_t global_warp_id = 0;
  int32_t lane = 0;
  int64_t flow_start = 0;
  int64_t flow_id = 0;
};

inline bool version_write_in_progress(uint64_t version) {
  return (version & 1ull) != 0ull;
}

inline uint64_t normalize_even_version(uint64_t version) {
  return version_write_in_progress(version) ? (version + 1ull) : version;
}

inline void next_seqlock_versions(uint64_t current_version, uint64_t* out_write_begin, uint64_t* out_write_commit) {
  const uint64_t base = normalize_even_version(current_version);
  if (out_write_begin) {
    *out_write_begin = base + 1ull;
  }
  if (out_write_commit) {
    *out_write_commit = base + 2ull;
  }
}

inline uint32_t publication_budget_us(uint32_t rtt_us) {
  constexpr uint32_t kMinUs = 50u;
  constexpr uint32_t kMaxUs = 1000u;
  uint32_t target = rtt_us / 10u;
  if (target < kMinUs) {
    target = kMinUs;
  } else if (target > kMaxUs) {
    target = kMaxUs;
  }
  return target;
}

inline bool is_valid_descriptor_transition(DescriptorOwnershipState from, DescriptorOwnershipState to) {
  switch (from) {
    case DescriptorOwnershipState::kFree:
      return to == DescriptorOwnershipState::kGpuWriting;
    case DescriptorOwnershipState::kGpuWriting:
      return to == DescriptorOwnershipState::kReadyForNic;
    case DescriptorOwnershipState::kReadyForNic:
      return to == DescriptorOwnershipState::kNicOwned;
    case DescriptorOwnershipState::kNicOwned:
      return to == DescriptorOwnershipState::kComplete;
    case DescriptorOwnershipState::kComplete:
      return to == DescriptorOwnershipState::kFree;
    default:
      return false;
  }
}

inline FlowAffinityV1 compute_flow_affinity(
    int32_t block_idx,
    int32_t block_dim,
    int32_t thread_idx,
    int32_t flows_per_warp,
    int32_t warp_size) {
  if (block_dim <= 0) {
    block_dim = 1;
  }
  if (warp_size <= 0) {
    warp_size = 32;
  }
  if (flows_per_warp <= 0) {
    flows_per_warp = warp_size;
  }
  const int64_t global_tid = static_cast<int64_t>(block_idx) * static_cast<int64_t>(block_dim) +
      static_cast<int64_t>(thread_idx);
  const int32_t global_warp_id = static_cast<int32_t>(global_tid / static_cast<int64_t>(warp_size));
  const int32_t lane = thread_idx % warp_size;
  const int64_t flow_start = static_cast<int64_t>(global_warp_id) * static_cast<int64_t>(flows_per_warp);
  const int64_t flow_id = flow_start + static_cast<int64_t>(lane);
  return FlowAffinityV1{global_tid, global_warp_id, lane, flow_start, flow_id};
}

enum class TelcoGpuProtocolKind : uint8_t {
  kNone = 0,
  kGtpu = 1,
  kPppoeQinq = 2,
  kSctp = 3,
  kSrtp = 4,
};

enum class TelcoGpuTunnelFlags : uint8_t {
  kActive     = 1 << 0,
  kWithSeq    = 1 << 1,
  kWithQfiExt = 1 << 2,
  kEchoMode   = 1 << 3,
};

struct alignas(64) TelcoGpuTunnelEntryV1 {
  uint64_t version;         // Monotonic seqlock version (odd: write in progress, even: committed)
  uint32_t uplink_teid;     // Host byte order (serialized big-endian on wire by device_write32)
  uint32_t downlink_teid;   // Host byte order (serialized big-endian on wire by device_write32)
  uint32_t outer_src_ip;    // Host byte order IPv4 (e.g. 0x0A000001 for 10.0.0.1)
  uint32_t outer_dst_ip;    // Host byte order IPv4
  uint32_t ue_src_ip;       // Host byte order IPv4 (inner UE source IP)
  uint32_t inner_dst_ip;    // Host byte order IPv4 (inner DN destination IP)
  uint16_t svlan_tci;       // Host byte order 802.1ad Service VLAN TCI (0 = disabled)
  uint16_t cvlan_tci;       // Host byte order 802.1Q Customer VLAN TCI (0 = disabled)
  uint16_t inner_src_port;  // Host byte order L4 source port
  uint16_t inner_dst_port;  // Host byte order L4 destination port
  uint8_t  qfi;             // 3GPP 5G QoS Flow Identifier (0..63)
  uint8_t  pdu_type;        // 1 = Uplink PDU Session, 0 = Downlink PDU Session
  uint8_t  inner_proto;     // 17 = UDP, 6 = TCP, 1 = ICMP
  uint8_t  vlan_depth;      // 0 = None, 1 = Single 802.1Q, 2 = QinQ (802.1ad + 802.1Q)
  uint8_t  flags;           // Bitmask of TelcoGpuTunnelFlags
  uint8_t  pad0[3];
  uint8_t  outer_dst_mac[6];
  uint16_t pad1;
  uint32_t tx_packets;      // Atomic per-tunnel packet counter
  uint32_t tx_bytes;        // Atomic per-tunnel byte counter
};
static_assert(sizeof(TelcoGpuTunnelEntryV1) == 64, "TelcoGpuTunnelEntryV1 must be exactly 64 bytes");

inline constexpr uint32_t kDpuCupsSharedMagicV1 = 0x53505543u;  // "CUPS"
inline constexpr uint32_t kDpuCupsSharedVersionV1 = 1u;

enum class DpuCupsArchFlags : uint32_t {
  kNone          = 0u,
  kAarch64Host   = 1u << 0,
  kHwCrc32       = 1u << 1,
  kUpfResponder  = 1u << 2,
};

struct alignas(64) DpuCupsSharedRegionHeaderV1 {
  uint32_t magic;             // kDpuCupsSharedMagicV1 ("CUPS")
  uint32_t version;           // kDpuCupsSharedVersionV1 (1)
  uint32_t capacity;          // Total allocated TelcoGpuTunnelEntryV1 slots following header
  uint32_t active_span;       // High-water active slot span (0..capacity) for GPU indexing
  uint64_t commit_epoch;      // Monotonic DPU ARM N4 PFCP table commit epoch
  uint64_t dpu_heartbeat_ns;  // Monotonic DPU ARM timestamp in nanoseconds
  uint32_t active_sessions;   // Currently active N4 PFCP sessions (kActive set)
  uint32_t established_total; // Cumulative N4 Session Establishment count
  uint32_t modified_total;    // Cumulative N4 Session Modification count
  uint32_t deleted_total;     // Cumulative N4 Session Deletion count
  uint32_t arch_flags;        // Bitmask of DpuCupsArchFlags
  uint8_t  reserved[12];
};
static_assert(sizeof(DpuCupsSharedRegionHeaderV1) == 64, "DpuCupsSharedRegionHeaderV1 must be 64 bytes");

struct alignas(64) TelcoGpuRxStatsV1 {
  unsigned long long rx_packets;
  unsigned long long rx_bytes;
  unsigned long long rx_gtpu_packets;
  unsigned long long rx_echo_req;
  unsigned long long rx_echo_resp;
  unsigned long long rx_error_ind;
  unsigned long long rx_invalid_checksum;
  unsigned long long rx_corrupt_packets;
  unsigned long long rx_qfi_packets[64];
};

}  // namespace ddos_samurai::gpu_packet_cuda::zero_copy
