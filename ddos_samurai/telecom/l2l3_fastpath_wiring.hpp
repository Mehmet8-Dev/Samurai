#pragma once

#include "l2l3_stack/arp_engine.hpp"
#include "l2l3_stack/dhcp_state_machine.hpp"
#include "l2l3_stack/nd_engine.hpp"
#include "l2l3_stack/igmp_engine.hpp"
#include "l2l3_stack/bfd_engine.hpp"
#include "telecom/lockfree_l2l3_cache.hpp"
#include "ddos_samurai/telecom/core/fastpath_classifier.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "ddos_samurai/telecom/protocols/stateful/sctp/sctp_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/diameter/diameter_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/sip_rtp/sip_rtp_engine.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>
#include <functional>

namespace ddos_samurai::telecom {

using ControlFrameType = TelcoFrameType;

class alignas(64) L2L3FastpathWiring {
 public:
  using TxPacketCallback = std::function<void(const uint8_t* data, size_t len)>;

  explicit L2L3FastpathWiring(uint32_t session_capacity = 4096, uint64_t tsc_hz = 2400000000ULL);
  ~L2L3FastpathWiring();

  L2L3FastpathWiring(const L2L3FastpathWiring&) = delete;
  L2L3FastpathWiring& operator=(const L2L3FastpathWiring&) = delete;
  L2L3FastpathWiring(L2L3FastpathWiring&&) = default;
  L2L3FastpathWiring& operator=(L2L3FastpathWiring&&) = default;

  // Hızlı L2/L3 kontrol paketi sınıflandırıcı (Dataplane worker hot-path)
  // Tekli (802.1Q) ve çiftli (802.1ad QinQ) VLAN etiketlerini soyarak iç EtherType'a ulaşır.
  static inline TelcoFrameType ClassifyFrame(const uint8_t* frame, std::size_t len,
                                             uint16_t* out_vlan = nullptr) noexcept {
    PacketMetadata meta{};
    TelcoFrameType type = TelcoFrameType::Unknown;
    if (!FastpathClassifier::Classify(frame, len, meta, type)) {
      if (out_vlan) *out_vlan = 0;
      return TelcoFrameType::Unknown;
    }
    if (out_vlan) {
      *out_vlan = meta.outer_vlan != 0 ? meta.outer_vlan : meta.inner_vlan;
    }
    return type;
  }

  static inline bool IsControlFrame(const uint8_t* frame, std::size_t len) noexcept {
    PacketMetadata meta{};
    TelcoFrameType type = TelcoFrameType::Unknown;
    if (!FastpathClassifier::Classify(frame, len, meta, type)) return false;
    return FastpathClassifier::IsControlFrame(type);
  }

  // Fast-path'ten veya slow-path ringinden gelen paketi ilgili motora yönlendirir (Demux)
  bool DispatchRxControlFrame(const uint8_t* data, std::size_t len, uint64_t now_tsc);

  // Periyodik kontrol adımı (BFD keepalive, timing wheel, SCTP/Diameter/SIP zaman aşımı)
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

  sctp::SctpEngine& sctp() noexcept { return sctp_engine_; }
  diameter::DiameterEngine& diameter() noexcept { return diameter_engine_; }
  sip_rtp::SipRtpEngine& sip_rtp() noexcept { return sip_rtp_engine_; }
  SessionManager& session_mgr() noexcept { return session_mgr_; }
  HierarchicalTimingWheel& timing_wheel() noexcept { return timing_wheel_; }

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

  // Stateful Telecom Session Management & Timing
  SessionManager session_mgr_;
  HierarchicalTimingWheel timing_wheel_;

  // Stateful Carrier Telecom Engines
  sctp::SctpEngine sctp_engine_;
  diameter::DiameterEngine diameter_engine_;
  sip_rtp::SipRtpEngine sip_rtp_engine_;

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
