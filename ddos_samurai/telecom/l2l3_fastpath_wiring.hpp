#pragma once

#include "l2l3_stack/arp_engine.hpp"
#include "l2l3_stack/dhcp_state_machine.hpp"
#include "l2l3_stack/nd_engine.hpp"
#include "l2l3_stack/igmp_engine.hpp"
#include "l2l3_stack/bfd_engine.hpp"
#include "telecom/lockfree_l2l3_cache.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>

namespace ddos_samurai::telecom {

enum class ControlFrameType : uint8_t {
  None = 0,
  Arp = 1,
  Dhcp = 2,
  Icmpv6Nd = 3,
  Igmp = 4,
  Bfd = 5,
  Pppoe = 6,
  Eapol = 7
};

class alignas(64) L2L3FastpathWiring {
 public:
  L2L3FastpathWiring() = default;
  ~L2L3FastpathWiring() = default;

  // Hızlı L2/L3 kontrol paketi sınıflandırıcı (Dataplane worker hot-path)
  // Veri düzleminde (Fast-path) nanometrik hızda çalışır, sıfır kopyadır.
  static inline ControlFrameType ClassifyFrame(const uint8_t* frame, std::size_t len) noexcept {
    if (!frame || len < 14) return ControlFrameType::None;

    uint16_t ether_type = (static_cast<uint16_t>(frame[12]) << 8) | frame[13];
    if (ether_type == 0x0806) return ControlFrameType::Arp;
    if (ether_type == 0x8863 || ether_type == 0x8864) return ControlFrameType::Pppoe;
    if (ether_type == 0x888E) return ControlFrameType::Eapol;

    // IPv6 kontrol paketleri (ICMPv6 / NDP)
    if (ether_type == 0x86DD && len >= 54) {
      if (frame[20] == 58) return ControlFrameType::Icmpv6Nd;
    }

    // IPv4 kontrol paketleri (IGMP, DHCP, BFD)
    if (ether_type == 0x0800 && len >= 34) {
      uint8_t proto = frame[23];
      if (proto == 2) return ControlFrameType::Igmp;
      if (proto == 17 && len >= 42) {
        // UDP destination port
        uint16_t dst_port = (static_cast<uint16_t>(frame[36]) << 8) | frame[37];
        if (dst_port == 67 || dst_port == 68) return ControlFrameType::Dhcp;
        if (dst_port == 3784 || dst_port == 3785) return ControlFrameType::Bfd;
      }
    }

    return ControlFrameType::None;
  }

  static inline bool IsControlFrame(const uint8_t* frame, std::size_t len) noexcept {
    return ClassifyFrame(frame, len) != ControlFrameType::None;
  }

  // Fast-path'ten veya slow-path ringinden gelen paketi ilgili motora yönlendirir (Demux)
  bool DispatchRxControlFrame(const uint8_t* data, std::size_t len, uint64_t now_tsc);

  // Periyodik kontrol adımı (BFD keepalive, ARP/ND zaman aşımı)
  void StepTimers(uint64_t now_tsc, uint64_t tsc_hz);

  // Dataplane iş parçacıklarının kilit beklemeden çağırdığı O(1) MAC sorgusu
  inline bool ResolveIpv4Mac(uint32_t ip_be, uint8_t out_mac[6]) const noexcept {
    return lockfree_arp_.LookupMac(ip_be, out_mac);
  }

  inline bool ResolveIpv6Mac(const uint8_t ipv6[16], uint8_t out_mac[6]) const noexcept {
    return lockfree_nd_.LookupMac(ipv6, out_mac);
  }

  // Motor erişimleri (Erişim ve kontrol)
  l7_emu_native::l2l3::ArpEngine& arp() noexcept { return arp_engine_; }
  l7_emu_native::l2l3::DhcpStateMachine& dhcp() noexcept { return dhcp_engine_; }
  l7_emu_native::l2l3::NdEngine& ndp() noexcept { return nd_engine_; }
  l7_emu_native::l2l3::IgmpEngine& igmp() noexcept { return igmp_engine_; }
  l7_emu_native::l2l3::BfdEngine& bfd() noexcept { return bfd_engine_; }
  LockfreeArpTable& lockfree_arp() noexcept { return lockfree_arp_; }
  LockfreeNdTable& lockfree_nd() noexcept { return lockfree_nd_; }

  // Kontrol düzlemi tarafından üretilen son TX paketini döner
  const std::vector<uint8_t>& last_tx_packet() const noexcept { return last_out_packet_; }

 private:
  // Mevcut çalışan C++ L2/L3 motorları
  l7_emu_native::l2l3::ArpEngine arp_engine_;
  l7_emu_native::l2l3::DhcpStateMachine dhcp_engine_;
  l7_emu_native::l2l3::NdEngine nd_engine_;
  l7_emu_native::l2l3::IgmpEngine igmp_engine_;

  // Yeni RFC 5880 BFD motoru
  l7_emu_native::l2l3::BfdEngine bfd_engine_;

  // 100 Gbps hat hızı kilit içermeyen önbellekler
  LockfreeArpTable lockfree_arp_;
  LockfreeNdTable lockfree_nd_;

  std::vector<uint8_t> last_out_packet_;
};

}  // namespace ddos_samurai::telecom
