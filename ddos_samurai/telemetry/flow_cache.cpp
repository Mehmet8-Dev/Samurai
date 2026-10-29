#include "flow_cache.hpp"

namespace ddos_samurai::telemetry {

namespace {

size_t round_to_power_of_two(size_t val) {
  size_t p = 1024;
  while (p < val && p < (1ULL << 30)) {
    p <<= 1;
  }
  return p;
}

}  // namespace

FlowTableShard::FlowTableShard(size_t capacity)
    : capacity_(round_to_power_of_two(capacity)),
      mask_(capacity_ - 1),
      table_(capacity_) {
  Clear();
}

void FlowTableShard::Clear() noexcept {
  for (auto& entry : table_) {
    entry.state = 0;
    entry.flow_id = 0;
    entry.packet_count = 0;
    entry.byte_count = 0;
    entry.tcp_flags_or = 0;
    entry.security_flags = 0;
    std::memset(&entry.key, 0, sizeof(entry.key));
  }
  active_count_ = 0;
  collision_drops_ = 0;
  eviction_cursor_ = 0;
}

SamuraiFlowRecord* FlowTableShard::LookupOrInsert(
    const SamuraiFlowKey& key, uint64_t now_tsc, bool& out_is_new) noexcept {

  uint32_t hash = ComputeFlowKeyHash(key);
  size_t base_idx = hash & mask_;

  // 1. Arama (Lookup) ve Boş Yuva Tespiti
  size_t first_free_idx = capacity_;
  for (size_t i = 0; i < MAX_PROBE_DISTANCE; ++i) {
    size_t idx = (base_idx + i) & mask_;
    auto& entry = table_[idx];

    if (entry.state == 1) { // Aktif akış
      if (AreFlowKeysEqual(entry.key, key)) {
        out_is_new = false;
        return &entry;
      }
    } else if (first_free_idx == capacity_) {
      first_free_idx = idx; // İlk boş slot
    }
  }

  // 2. Yeni Akış Ekleme (Insert)
  if (first_free_idx < capacity_) {
    auto& entry = table_[first_free_idx];
    entry.key = key;
    entry.start_tsc = now_tsc;
    entry.last_tsc = now_tsc;
    entry.packet_count = 0;
    entry.byte_count = 0;
    entry.flow_id = static_cast<uint32_t>(next_flow_id_++);
    entry.rtt_us = 0;
    entry.retransmit_cnt = 0;
    entry.out_of_order_cnt = 0;
    entry.tcp_flags_or = 0;
    entry.security_flags = 0;
    entry.state = 1; // Aktif

    active_count_++;
    out_is_new = true;
    return &entry;
  }

  // Probe mesafesi aşıldı (Hash collision / doluluk)
  collision_drops_++;
  out_is_new = false;
  return nullptr;
}

const SamuraiFlowRecord* FlowTableShard::Lookup(const SamuraiFlowKey& key) const noexcept {
  uint32_t hash = ComputeFlowKeyHash(key);
  size_t base_idx = hash & mask_;

  for (size_t i = 0; i < MAX_PROBE_DISTANCE; ++i) {
    size_t idx = (base_idx + i) & mask_;
    const auto& entry = table_[idx];
    if (entry.state == 1 && AreFlowKeysEqual(entry.key, key)) {
      return &entry;
    }
  }
  return nullptr;
}

size_t FlowTableShard::EvictTimedOut(
    uint64_t now_tsc, uint64_t active_timeout_tsc, uint64_t inactive_timeout_tsc,
    std::vector<SamuraiFlowRecord>& out_evicted, size_t max_evict) noexcept {

  if (active_count_ == 0 || max_evict == 0) return 0;

  size_t evicted = 0;
  size_t scanned = 0;
  size_t start_cursor = eviction_cursor_;

  while (scanned < capacity_ && evicted < max_evict) {
    size_t idx = (start_cursor + scanned) & mask_;
    auto& entry = table_[idx];

    if (entry.state == 1) { // Sadece aktif akışlar incelenir
      bool is_inactive_timeout = (now_tsc > entry.last_tsc) &&
                                 ((now_tsc - entry.last_tsc) >= inactive_timeout_tsc);
      bool is_active_timeout = (now_tsc > entry.start_tsc) &&
                               ((now_tsc - entry.start_tsc) >= active_timeout_tsc);

      // TCP FIN (0x01) veya RST (0x04) bayrağı görülmüşse erken tahliye
      bool is_tcp_closed = (entry.key.protocol == 6) && (entry.tcp_flags_or & 0x05);

      if (is_inactive_timeout || is_active_timeout || is_tcp_closed) {
        out_evicted.push_back(entry);
        entry.state = 0; // Boşalt
        active_count_--;
        evicted++;
      }
    }
    scanned++;
  }

  eviction_cursor_ = (start_cursor + scanned) & mask_;
  return evicted;
}

}  // namespace ddos_samurai::telemetry
