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
#include <functional>

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
  using TxPacketCallback = std::function<void(const uint8_t* data, size_t len)>;

  L2L3FastpathWiring() = default;
  ~L2L3FastpathWiring() = default;

  // Hızlı L2/L3 kontrol paketi sınıflandırıcı (Dataplane worker hot-path)
  // Tekli (802.1Q) ve çiftli (802.1ad QinQ) VLAN etiketlerini soyarak iç EtherType'a ulaşır.
  static inline ControlFrameType ClassifyFrame(const uint8_t* frame, std::size_t len,
                                               uint16_t* out_vlan = nullptr) noexcept {
    if (!frame || len < 14) return ControlFrameType::None;

    std::size_t offset = 12;
    uint16_t ether_type = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
    offset += 2;
    uint16_t vlan = 0;

    // 802.1ad (QinQ Service Tag)
    if ((ether_type == 0x88A8 || ether_type == 0x9100) && len >= offset + 4) {
      vlan = ((static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1]) & 0x0FFF;
      offset += 2;
      ether_type = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
      offset += 2;
    }

    // 802.1Q (Customer Tag)
    if (ether_type == 0x8100 && len >= offset + 4) {
      uint16_t c_vlan = ((static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1]) & 0x0FFF;
      if (vlan == 0) vlan = c_vlan;
      offset += 2;
      ether_type = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
      offset += 2;
    }

    if (out_vlan) *out_vlan = vlan;

    if (ether_type == 0x0806) return ControlFrameType::Arp;
    if (ether_type == 0x8863 || ether_type == 0x8864) return ControlFrameType::Pppoe;
    if (ether_type == 0x888E) return ControlFrameType::Eapol;

    // IPv6 kontrol paketleri (ICMPv6 / NDP)
    if (ether_type == 0x86DD && len >= offset + 40) {
      if (frame[offset + 6] == 58) return ControlFrameType::Icmpv6Nd;
    }

    // IPv4 kontrol paketleri (IGMP, DHCP, BFD)
    if (ether_type == 0x0800 && len >= offset + 20) {
      uint8_t ihl = (frame[offset] & 0x0F) * 4;
      if (ihl < 20 || len < offset + ihl) return ControlFrameType::None;
      uint8_t proto = frame[offset + 9];
      if (proto == 2) return ControlFrameType::Igmp;
      if (proto == 17 && len >= offset + ihl + 8) {
        std::size_t udp_offset = offset + ihl;
        uint16_t dst_port = (static_cast<uint16_t>(frame[udp_offset + 2]) << 8) | frame[udp_offset + 3];
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

  // Dataplane iş parçacıklarının kilit beklemeden çağırdığı O(1) MAC sorgusu (VLAN-farkındalıklı)
  inline bool ResolveIpv4Mac(uint32_t ip_be, uint8_t out_mac[6], uint16_t vlan_id = 0) const noexcept {
    return lockfree_arp_.LookupMac(ip_be, out_mac, vlan_id);
  }

  inline bool ResolveIpv6Mac(const uint8_t ipv6[16], uint8_t out_mac[6], uint16_t vlan_id = 0) const noexcept {
    return lockfree_nd_.LookupMac(ipv6, out_mac, vlan_id);
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

  // Gerçek DPDK / XDP TX kuyruğuna aktarma kancası (TX Buffer Bridge)
  void SetTxCallback(TxPacketCallback cb) { tx_callback_ = std::move(cb); }

 private:
  // Mevcut çalışan C++ L2/L3 motorları
  l7_emu_native::l2l3::ArpEngine arp_engine_;
  l7_emu_native::l2l3::DhcpStateMachine dhcp_engine_;
  l7_emu_native::l2l3::NdEngine nd_engine_;
  l7_emu_native::l2l3::IgmpEngine igmp_engine_;

  // RFC 5880 / 5881 BFD motoru
  l7_emu_native::l2l3::BfdEngine bfd_engine_;

  // 100 Gbps hat hızı kilit içermeyen önbellekler (VLAN + Seqlock)
  LockfreeArpTable lockfree_arp_;
  LockfreeNdTable lockfree_nd_;

  std::vector<uint8_t> last_out_packet_;
  TxPacketCallback tx_callback_{nullptr};

  void EmitTxPacket(const std::vector<uint8_t>& pkt) {
    last_out_packet_ = pkt;
    if (tx_callback_ && !pkt.empty()) {
      tx_callback_(pkt.data(), pkt.size());
    }
  }
};

}  // namespace ddos_samurai::telecom
