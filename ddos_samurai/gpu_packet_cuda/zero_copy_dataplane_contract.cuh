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

}  // namespace ddos_samurai::gpu_packet_cuda::zero_copy
