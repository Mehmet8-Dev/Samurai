#pragma once

#include "ipfix_types.hpp"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <memory>

#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
#endif

namespace ddos_samurai::telemetry {

// Wire-speed 5-tuple hash calculation
inline uint32_t ComputeFlowKeyHash(const SamuraiFlowKey& key) noexcept {
#if defined(__SSE4_2__)
  uint64_t w1 = (static_cast<uint64_t>(key.src_ip) << 32) | key.dst_ip;
  uint32_t w2 = (static_cast<uint32_t>(key.src_port) << 16) | key.dst_port;
  uint32_t w3 = (static_cast<uint32_t>(key.protocol) << 16) | key.vlan_id;
  uint64_t crc = _mm_crc32_u64(0xFFFFFFFFULL, w1);
  crc = _mm_crc32_u32(static_cast<uint32_t>(crc), w2);
  crc = _mm_crc32_u32(static_cast<uint32_t>(crc), w3);
  return static_cast<uint32_t>(crc);
#else
  // High-performance Murmur3/SplitMix64 bit mixer fallback
  uint64_t w1 = (static_cast<uint64_t>(key.src_ip) << 32) | key.dst_ip;
  uint32_t w2 = (static_cast<uint32_t>(key.src_port) << 16) | key.dst_port;
  uint32_t w3 = (static_cast<uint32_t>(key.protocol) << 16) | key.vlan_id;
  uint64_t h = w1 ^ (static_cast<uint64_t>(w2) << 32) ^ w3;
  h ^= (h >> 33);
  h *= 0xff51afd7ed558ccdULL;
  h ^= (h >> 33);
  h *= 0xc4ceb9fe1a85ec53ULL;
  h ^= (h >> 33);
  return static_cast<uint32_t>(h);
#endif
}

inline bool AreFlowKeysEqual(const SamuraiFlowKey& a, const SamuraiFlowKey& b) noexcept {
  return a.src_ip == b.src_ip &&
         a.dst_ip == b.dst_ip &&
         a.src_port == b.src_port &&
         a.dst_port == b.dst_port &&
         a.protocol == b.protocol &&
         a.vlan_id == b.vlan_id;
}

// Tek bir Dataplane Worker Core'a tahsis edilen Akış Tablosu Shard'ı
// Shared-nothing, sıfır kilit, NUMA yerel bellek.
class alignas(64) FlowTableShard {
 public:
  static constexpr size_t DEFAULT_CAPACITY = 65536; // 64K aktif akış (4 MB bellek)
  static constexpr size_t MAX_PROBE_DISTANCE = 16;  // Sınırlı doğrusal arama (bounded linear probe)

  explicit FlowTableShard(size_t capacity = DEFAULT_CAPACITY);
  ~FlowTableShard() = default;

  // Kopyalama engellenir, taşıma serbesttir
  FlowTableShard(const FlowTableShard&) = delete;
  FlowTableShard& operator=(const FlowTableShard&) = delete;
  FlowTableShard(FlowTableShard&&) noexcept = default;
  FlowTableShard& operator=(FlowTableShard&&) noexcept = default;

  // Dataplane hot-path O(1) akış arama veya yeni giriş oluşturma
  SamuraiFlowRecord* LookupOrInsert(const SamuraiFlowKey& key, uint64_t now_tsc, bool& out_is_new) noexcept;

  // Salt okunur akış araması
  const SamuraiFlowRecord* Lookup(const SamuraiFlowKey& key) const noexcept;

  // İstatistik güncelleme (sıcak yol)
  static inline void UpdateStats(SamuraiFlowRecord* rec, uint32_t bytes, uint8_t tcp_flags, uint64_t now_tsc) noexcept {
    if (!rec) return;
    rec->packet_count++;
    rec->byte_count += bytes;
    rec->last_tsc = now_tsc;
    rec->tcp_flags_or |= tcp_flags;
  }

  // Aktif ve inaktif zaman aşımına uğramış akışları tahliye eder (Aging & Eviction)
  size_t EvictTimedOut(uint64_t now_tsc, uint64_t active_timeout_tsc, uint64_t inactive_timeout_tsc,
                       std::vector<SamuraiFlowRecord>& out_evicted, size_t max_evict = 256) noexcept;

  void Clear() noexcept;

  size_t active_flow_count() const noexcept { return active_count_; }
  size_t capacity() const noexcept { return capacity_; }
  size_t collision_drop_count() const noexcept { return collision_drops_; }

 private:
  size_t capacity_;
  size_t mask_;
  size_t active_count_{0};
  size_t next_flow_id_{1};
  size_t collision_drops_{0};
  size_t eviction_cursor_{0}; // Round-robin tahliye imleci

  // 64-bayt hizalı contiguous bellek alanı
  std::vector<SamuraiFlowRecord> table_;
};

}  // namespace ddos_samurai::telemetry
