#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <cstring>
#include <array>
#include <memory>

namespace ddos_samurai::telecom {

// 64-bayt hizalı tekil ARP önbellek kaydı (Tek bir CPU Cache-Line)
struct alignas(64) AtomicArpEntry {
  std::uint32_t ipv4_be;          // 4 bayt: Ağ sırasındaki hedef IPv4 adresi
  std::uint8_t  mac[6];           // 6 bayt: Çözümlenen MAC adresi
  std::uint16_t vlan_id;          // 2 bayt: VLAN etiket kimliği (0 ise untagged)
  std::uint64_t last_updated_tsc; // 8 bayt: Zaman damgası (TSC)
  std::uint8_t  state;            // 1 bayt: 0=Free, 1=Updating, 2=Resolved, 3=Static
  std::uint8_t  pad[39];          // 39 bayt: 64 bayt önbellek satırını doldurma
};
static_assert(sizeof(AtomicArpEntry) == 64, "AtomicArpEntry must be exactly 64 bytes");

// 65.536 kayıtlık kilit içermeyen sabit ARP tablosu (Wait-free Okuma)
class alignas(64) LockfreeArpTable {
 public:
  static constexpr std::size_t TABLE_SIZE = 65536;
  static constexpr std::size_t TABLE_MASK = TABLE_SIZE - 1;

  LockfreeArpTable()
      : entries_(std::make_unique<std::array<AtomicArpEntry, TABLE_SIZE>>()) {
    for (auto& entry : *entries_) {
      entry.state = 0;
      entry.ipv4_be = 0;
      entry.vlan_id = 0;
      entry.last_updated_tsc = 0;
      std::memset(entry.mac, 0, 6);
    }
  }

  // Dataplane Worker tarafından çağrılır: WAIT-FREE, SIFIR KİLİT, SIFIR HEAP ALLOCATION
  inline bool LookupMac(std::uint32_t ipv4_be, std::uint8_t out_mac[6]) const noexcept {
    std::size_t idx = (ipv4_be ^ (ipv4_be >> 16)) & TABLE_MASK;
    const auto& entry = (*entries_)[idx];
    if (entry.state >= 2 && entry.ipv4_be == ipv4_be) {
      std::memcpy(out_mac, entry.mac, 6);
      return true;
    }
    return false;
  }

  // Kontrol Düzlemi (Slow-Path) tarafından çağrılır: Atomik tek yazıcı (Single-writer)
  inline void UpdateEntry(std::uint32_t ipv4_be, const std::uint8_t mac[6],
                          std::uint16_t vlan_id, std::uint64_t now_tsc) noexcept {
    std::size_t idx = (ipv4_be ^ (ipv4_be >> 16)) & TABLE_MASK;
    auto& entry = (*entries_)[idx];
    entry.state = 1; // Updating
    std::atomic_thread_fence(std::memory_order_release);
    entry.ipv4_be = ipv4_be;
    std::memcpy(entry.mac, mac, 6);
    entry.vlan_id = vlan_id;
    entry.last_updated_tsc = now_tsc;
    std::atomic_thread_fence(std::memory_order_release);
    entry.state = 2; // Resolved
  }

  inline void Invalidate(std::uint32_t ipv4_be) noexcept {
    std::size_t idx = (ipv4_be ^ (ipv4_be >> 16)) & TABLE_MASK;
    auto& entry = (*entries_)[idx];
    if (entry.ipv4_be == ipv4_be) {
      entry.state = 0;
    }
  }

 private:
  std::unique_ptr<std::array<AtomicArpEntry, TABLE_SIZE>> entries_;
};

// 64-bayt hizalı IPv6 Neighbor Discovery (ND) önbellek kaydı
struct alignas(64) AtomicNdEntry {
  std::uint8_t  ipv6[16];         // 16 bayt: IPv6 adresi
  std::uint8_t  mac[6];           // 6 bayt: Çözümlenen MAC
  std::uint16_t vlan_id;          // 2 bayt
  std::uint64_t last_updated_tsc; // 8 bayt
  std::uint8_t  state;            // 1 bayt: 0=Free, 1=Updating, 2=Resolved, 3=Static
  std::uint8_t  pad[31];          // 31 bayt: Tam 64 bayt hizalama
};
static_assert(sizeof(AtomicNdEntry) == 64, "AtomicNdEntry must be exactly 64 bytes");

class alignas(64) LockfreeNdTable {
 public:
  static constexpr std::size_t TABLE_SIZE = 65536;
  static constexpr std::size_t TABLE_MASK = TABLE_SIZE - 1;

  LockfreeNdTable()
      : entries_(std::make_unique<std::array<AtomicNdEntry, TABLE_SIZE>>()) {
    for (auto& entry : *entries_) {
      entry.state = 0;
      entry.vlan_id = 0;
      entry.last_updated_tsc = 0;
      std::memset(entry.ipv6, 0, 16);
      std::memset(entry.mac, 0, 6);
    }
  }

  inline bool LookupMac(const std::uint8_t ipv6[16], std::uint8_t out_mac[6]) const noexcept {
    std::uint64_t h1 = *reinterpret_cast<const std::uint64_t*>(ipv6);
    std::uint64_t h2 = *reinterpret_cast<const std::uint64_t*>(ipv6 + 8);
    std::size_t idx = (h1 ^ h2 ^ (h1 >> 32) ^ (h2 >> 32)) & TABLE_MASK;

    const auto& entry = (*entries_)[idx];
    if (entry.state >= 2 && std::memcmp(entry.ipv6, ipv6, 16) == 0) {
      std::memcpy(out_mac, entry.mac, 6);
      return true;
    }
    return false;
  }

  inline void UpdateEntry(const std::uint8_t ipv6[16], const std::uint8_t mac[6],
                          std::uint16_t vlan_id, std::uint64_t now_tsc) noexcept {
    std::uint64_t h1 = *reinterpret_cast<const std::uint64_t*>(ipv6);
    std::uint64_t h2 = *reinterpret_cast<const std::uint64_t*>(ipv6 + 8);
    std::size_t idx = (h1 ^ h2 ^ (h1 >> 32) ^ (h2 >> 32)) & TABLE_MASK;

    auto& entry = (*entries_)[idx];
    entry.state = 1;
    std::atomic_thread_fence(std::memory_order_release);
    std::memcpy(entry.ipv6, ipv6, 16);
    std::memcpy(entry.mac, mac, 6);
    entry.vlan_id = vlan_id;
    entry.last_updated_tsc = now_tsc;
    std::atomic_thread_fence(std::memory_order_release);
    entry.state = 2;
  }

 private:
  std::unique_ptr<std::array<AtomicNdEntry, TABLE_SIZE>> entries_;
};

}  // namespace ddos_samurai::telecom
