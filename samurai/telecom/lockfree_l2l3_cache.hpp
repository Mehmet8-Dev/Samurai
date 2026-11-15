#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <cstring>
#include <array>
#include <memory>
#include <algorithm>

namespace samurai::telecom {

// 64-bayt hizalı tekil ARP önbellek kaydı (Tek bir CPU Cache-Line)
// Seqlock atomik sürüm sayacı ile veri yarışsız (Data-race free) eşzamanlı okuma/yazma
struct alignas(64) AtomicArpEntry {
  std::atomic<uint32_t> seq{0};     // 4 bayt: Seqlock sürüm sayacı (tek=yazılıyor, çift=kararlı)
  std::uint32_t ipv4_be{0};          // 4 bayt: Ağ sırasındaki hedef IPv4 adresi
  std::uint16_t vlan_id{0};          // 2 bayt: VLAN etiket kimliği (0 ise untagged)
  std::uint8_t  state{0};            // 1 bayt: 0=Free, 1=Updating, 2=Resolved, 3=Static
  std::uint8_t  pad0{0};             // 1 bayt: Hizalama
  std::uint8_t  mac[6]{0};           // 6 bayt: Çözümlenen MAC adresi
  std::uint8_t  pad1[6]{0};          // 6 bayt: 8-bayt hizalama dolgusu (offset 24)
  std::uint64_t last_updated_tsc{0}; // 8 bayt: Zaman damgası (TSC) (offset 32)
  std::uint8_t  pad2[32]{0};         // 32 bayt: Tam 64 bayt önbellek satırını doldurma
};
static_assert(sizeof(AtomicArpEntry) == 64, "AtomicArpEntry must be exactly 64 bytes");

// 65.536 kayıtlık kilit içermeyen ARP tablosu (Seqlock + 2-Way Set Associative)
class alignas(64) LockfreeArpTable {
 public:
  static constexpr std::size_t TABLE_SIZE = 65536;
  static constexpr std::size_t TABLE_MASK = TABLE_SIZE - 1;

  LockfreeArpTable()
      : entries_(std::make_unique<std::array<AtomicArpEntry, TABLE_SIZE>>()) {
    for (auto& entry : *entries_) {
      entry.seq.store(0, std::memory_order_relaxed);
      entry.state = 0;
      entry.ipv4_be = 0;
      entry.vlan_id = 0;
      entry.last_updated_tsc = 0;
      std::memset(entry.mac, 0, 6);
    }
  }

  // Hash fonksiyonu: IPv4 ve VLAN kimliğini birlikte harmanlar
  static inline std::size_t HashArp(std::uint32_t ipv4_be, std::uint16_t vlan_id) noexcept {
    std::uint32_t h = ipv4_be ^ (ipv4_be >> 16);
    h ^= (static_cast<std::uint32_t>(vlan_id) * 0x85ebca6b);
    return static_cast<std::size_t>(h & TABLE_MASK);
  }

  // Dataplane Worker tarafından çağrılır: WAIT-FREE SEQLOCK OKUMA (SIFIR KİLİT, SIFIR HEAP)
  inline bool LookupMac(std::uint32_t ipv4_be, std::uint8_t out_mac[6], std::uint16_t vlan_id = 0) const noexcept {
    std::size_t base_idx = HashArp(ipv4_be, vlan_id);

    // 2-Way arama: base_idx ve base_idx ^ 1 (veya +1)
    for (std::size_t way = 0; way < 2; ++way) {
      std::size_t idx = (base_idx + way) & TABLE_MASK;
      const auto& entry = (*entries_)[idx];

      for (int retry = 0; retry < 3; ++retry) {
        uint32_t s1 = entry.seq.load(std::memory_order_acquire);
        if ((s1 & 1) != 0) continue; // Yazma işlemde, tekrar dene

        if (entry.state >= 2 && entry.ipv4_be == ipv4_be && entry.vlan_id == vlan_id) {
          uint8_t temp_mac[6];
          std::memcpy(temp_mac, entry.mac, 6);

          std::atomic_thread_fence(std::memory_order_acquire);
          uint32_t s2 = entry.seq.load(std::memory_order_acquire);
          if (s1 == s2) {
            std::memcpy(out_mac, temp_mac, 6);
            return true;
          }
        } else {
          uint32_t s2 = entry.seq.load(std::memory_order_acquire);
          if (s1 == s2 && (s1 & 1) == 0) {
            break; // Bu slot gerçekten eşleşmiyor
          }
        }
      }
    }
    return false;
  }

  // Kontrol Düzlemi (Slow-Path) tarafından çağrılır: Seqlock Güvenli Güncelleme
  inline void UpdateEntry(std::uint32_t ipv4_be, const std::uint8_t mac[6],
                          std::uint16_t vlan_id, std::uint64_t now_tsc) noexcept {
    std::size_t base_idx = HashArp(ipv4_be, vlan_id);
    std::size_t target_idx = base_idx;
    bool found_slot = false;

    // 1. Önce mevcut eşleşen kaydı veya boş yuva ara
    for (std::size_t way = 0; way < 2; ++way) {
      std::size_t idx = (base_idx + way) & TABLE_MASK;
      const auto& entry = (*entries_)[idx];
      if (entry.state >= 2 && entry.ipv4_be == ipv4_be && entry.vlan_id == vlan_id) {
        target_idx = idx;
        found_slot = true;
        break;
      }
      if (entry.state == 0 && !found_slot) {
        target_idx = idx;
        found_slot = true;
      }
    }

    // 2. Boş veya eşleşen bulunamadıysa en eski (LRU/TSC) yuvanın üzerine yaz
    if (!found_slot) {
      std::size_t idx0 = base_idx;
      std::size_t idx1 = (base_idx + 1) & TABLE_MASK;
      if ((*entries_)[idx1].last_updated_tsc < (*entries_)[idx0].last_updated_tsc) {
        target_idx = idx1;
      } else {
        target_idx = idx0;
      }
    }

    auto& entry = (*entries_)[target_idx];
    uint32_t s = entry.seq.load(std::memory_order_relaxed);
    entry.seq.store(s + 1, std::memory_order_release); // Tekil: yazım başladı
    std::atomic_thread_fence(std::memory_order_release);

    entry.ipv4_be = ipv4_be;
    std::memcpy(entry.mac, mac, 6);
    entry.vlan_id = vlan_id;
    entry.last_updated_tsc = now_tsc;
    entry.state = 2; // Resolved

    std::atomic_thread_fence(std::memory_order_release);
    entry.seq.store(s + 2, std::memory_order_release); // Çift: kararlı yayınlandı
  }

  inline void Invalidate(std::uint32_t ipv4_be, std::uint16_t vlan_id = 0) noexcept {
    std::size_t base_idx = HashArp(ipv4_be, vlan_id);
    for (std::size_t way = 0; way < 2; ++way) {
      std::size_t idx = (base_idx + way) & TABLE_MASK;
      auto& entry = (*entries_)[idx];
      if (entry.ipv4_be == ipv4_be && entry.vlan_id == vlan_id) {
        uint32_t s = entry.seq.load(std::memory_order_relaxed);
        entry.seq.store(s + 1, std::memory_order_release);
        std::atomic_thread_fence(std::memory_order_release);
        entry.state = 0;
        std::atomic_thread_fence(std::memory_order_release);
        entry.seq.store(s + 2, std::memory_order_release);
      }
    }
  }

 private:
  std::unique_ptr<std::array<AtomicArpEntry, TABLE_SIZE>> entries_;
};

// 64-bayt hizalı IPv6 Neighbor Discovery (ND) önbellek kaydı
struct alignas(64) AtomicNdEntry {
  std::atomic<uint32_t> seq{0};     // 4 bayt: Seqlock sürüm sayacı
  std::uint16_t vlan_id{0};          // 2 bayt: VLAN etiket kimliği
  std::uint8_t  state{0};            // 1 bayt: 0=Free, 1=Updating, 2=Resolved, 3=Static
  std::uint8_t  pad0{0};             // 1 bayt: Hizalama
  std::uint8_t  ipv6[16]{0};         // 16 bayt: IPv6 adresi
  std::uint8_t  mac[6]{0};           // 6 bayt: Çözümlenen MAC
  std::uint16_t pad1{0};             // 2 bayt: Hizalama
  std::uint64_t last_updated_tsc{0}; // 8 bayt: Zaman damgası
  std::uint8_t  pad2[24]{0};         // 24 bayt: Tam 64 bayt hizalama
};
static_assert(sizeof(AtomicNdEntry) == 64, "AtomicNdEntry must be exactly 64 bytes");

class alignas(64) LockfreeNdTable {
 public:
  static constexpr std::size_t TABLE_SIZE = 65536;
  static constexpr std::size_t TABLE_MASK = TABLE_SIZE - 1;

  LockfreeNdTable()
      : entries_(std::make_unique<std::array<AtomicNdEntry, TABLE_SIZE>>()) {
    for (auto& entry : *entries_) {
      entry.seq.store(0, std::memory_order_relaxed);
      entry.state = 0;
      entry.vlan_id = 0;
      entry.last_updated_tsc = 0;
      std::memset(entry.ipv6, 0, 16);
      std::memset(entry.mac, 0, 6);
    }
  }

  // Güvenli taşınabilir bayt kopyalamalı Hash (hizasız cast tehlikesi yoktur)
  static inline std::size_t HashNd(const std::uint8_t ipv6[16], std::uint16_t vlan_id) noexcept {
    std::uint64_t h1 = 0;
    std::uint64_t h2 = 0;
    std::memcpy(&h1, ipv6, 8);
    std::memcpy(&h2, ipv6 + 8, 8);
    std::uint64_t h = h1 ^ h2 ^ (h1 >> 32) ^ (h2 >> 32);
    h ^= (static_cast<std::uint64_t>(vlan_id) * 0x9e3779b97f4a7c15ULL);
    return static_cast<std::size_t>(h & TABLE_MASK);
  }

  inline bool LookupMac(const std::uint8_t ipv6[16], std::uint8_t out_mac[6], std::uint16_t vlan_id = 0) const noexcept {
    std::size_t base_idx = HashNd(ipv6, vlan_id);

    for (std::size_t way = 0; way < 2; ++way) {
      std::size_t idx = (base_idx + way) & TABLE_MASK;
      const auto& entry = (*entries_)[idx];

      for (int retry = 0; retry < 3; ++retry) {
        uint32_t s1 = entry.seq.load(std::memory_order_acquire);
        if ((s1 & 1) != 0) continue;

        if (entry.state >= 2 && entry.vlan_id == vlan_id && std::memcmp(entry.ipv6, ipv6, 16) == 0) {
          uint8_t temp_mac[6];
          std::memcpy(temp_mac, entry.mac, 6);

          std::atomic_thread_fence(std::memory_order_acquire);
          uint32_t s2 = entry.seq.load(std::memory_order_acquire);
          if (s1 == s2) {
            std::memcpy(out_mac, temp_mac, 6);
            return true;
          }
        } else {
          uint32_t s2 = entry.seq.load(std::memory_order_acquire);
          if (s1 == s2 && (s1 & 1) == 0) {
            break; // Bu slot gerçekten eşleşmiyor
          }
        }
      }
    }
    return false;
  }

  inline void UpdateEntry(const std::uint8_t ipv6[16], const std::uint8_t mac[6],
                          std::uint16_t vlan_id, std::uint64_t now_tsc) noexcept {
    std::size_t base_idx = HashNd(ipv6, vlan_id);
    std::size_t target_idx = base_idx;
    bool found_slot = false;

    for (std::size_t way = 0; way < 2; ++way) {
      std::size_t idx = (base_idx + way) & TABLE_MASK;
      const auto& entry = (*entries_)[idx];
      if (entry.state >= 2 && entry.vlan_id == vlan_id && std::memcmp(entry.ipv6, ipv6, 16) == 0) {
        target_idx = idx;
        found_slot = true;
        break;
      }
      if (entry.state == 0 && !found_slot) {
        target_idx = idx;
        found_slot = true;
      }
    }

    if (!found_slot) {
      std::size_t idx0 = base_idx;
      std::size_t idx1 = (base_idx + 1) & TABLE_MASK;
      if ((*entries_)[idx1].last_updated_tsc < (*entries_)[idx0].last_updated_tsc) {
        target_idx = idx1;
      } else {
        target_idx = idx0;
      }
    }

    auto& entry = (*entries_)[target_idx];
    uint32_t s = entry.seq.load(std::memory_order_relaxed);
    entry.seq.store(s + 1, std::memory_order_release);
    std::atomic_thread_fence(std::memory_order_release);

    std::memcpy(entry.ipv6, ipv6, 16);
    std::memcpy(entry.mac, mac, 6);
    entry.vlan_id = vlan_id;
    entry.last_updated_tsc = now_tsc;
    entry.state = 2;

    std::atomic_thread_fence(std::memory_order_release);
    entry.seq.store(s + 2, std::memory_order_release);
  }

  inline void Invalidate(const std::uint8_t ipv6[16], std::uint16_t vlan_id = 0) noexcept {
    std::size_t base_idx = HashNd(ipv6, vlan_id);
    for (std::size_t way = 0; way < 2; ++way) {
      std::size_t idx = (base_idx + way) & TABLE_MASK;
      auto& entry = (*entries_)[idx];
      if (entry.vlan_id == vlan_id && std::memcmp(entry.ipv6, ipv6, 16) == 0) {
        uint32_t s = entry.seq.load(std::memory_order_relaxed);
        entry.seq.store(s + 1, std::memory_order_release);
        std::atomic_thread_fence(std::memory_order_release);
        entry.state = 0;
        std::atomic_thread_fence(std::memory_order_release);
        entry.seq.store(s + 2, std::memory_order_release);
      }
    }
  }

 private:
  std::unique_ptr<std::array<AtomicNdEntry, TABLE_SIZE>> entries_;
};

}  // namespace samurai::telecom
