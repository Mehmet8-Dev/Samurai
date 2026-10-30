#include "l2l3_fastpath_wiring.hpp"

#include <arpa/inet.h>
#include <cstring>

namespace ddos_samurai::telecom {

namespace {

bool parse_mac_string(const std::string& mac_str, uint8_t out[6]) {
  int values[6];
  if (std::sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
                  &values[0], &values[1], &values[2],
                  &values[3], &values[4], &values[5]) == 6) {
    for (int i = 0; i < 6; ++i) out[i] = static_cast<uint8_t>(values[i]);
    return true;
  }
  std::memset(out, 0, 6);
  return false;
}

}  // namespace

bool L2L3FastpathWiring::DispatchRxControlFrame(
    const uint8_t* data, std::size_t len, uint64_t now_tsc) {

  uint16_t vlan_id = 0;
  ControlFrameType type = ClassifyFrame(data, len, &vlan_id);
  last_out_packet_.clear();

  switch (type) {
    case ControlFrameType::Arp: {
      std::string sender_ip, sender_mac;
      uint16_t oper = 0;
      if (l7_emu_native::l2l3::ArpEngine::parse_arp_packet(data, len, sender_ip, sender_mac, oper)) {
        arp_engine_.process_arp_reply(sender_ip, sender_mac);

        // Lock-free tablosunu VLAN farkındalıklı güncelle (Wait-free Okuma için)
        uint32_t sender_ip_be = 0;
        inet_pton(AF_INET, sender_ip.c_str(), &sender_ip_be);
        uint8_t mac_bytes[6];
        if (parse_mac_string(sender_mac, mac_bytes)) {
          lockfree_arp_.UpdateEntry(sender_ip_be, mac_bytes, vlan_id, now_tsc);
        }
        return true;
      }
      return false;
    }

    case ControlFrameType::Dhcp: {
      uint32_t xid = 0;
      std::string yiaddr, server_ip;
      int msg_type = 0;
      if (l7_emu_native::l2l3::DhcpStateMachine::parse_dhcp_packet(data, len, xid, yiaddr, server_ip, msg_type)) {
        if (msg_type == 2) { // DHCPOFFER
          dhcp_engine_.process_offer(yiaddr, server_ip);
          EmitTxPacket(dhcp_engine_.last_tx_packet());
        } else if (msg_type == 5) { // DHCPACK
          dhcp_engine_.process_ack(yiaddr);
        }
        return true;
      }
      return false;
    }

    case ControlFrameType::Icmpv6Nd: {
      std::string sender_ip, sender_mac;
      if (l7_emu_native::l2l3::NdEngine::parse_neighbor_advertisement(data, len, sender_ip, sender_mac)) {
        nd_engine_.process_neighbor_advertisement(sender_ip, sender_mac);

        // Lock-free IPv6 tablosunu VLAN farkındalıklı güncelle
        uint8_t ip6_bytes[16];
        inet_pton(AF_INET6, sender_ip.c_str(), ip6_bytes);
        uint8_t mac_bytes[6];
        if (parse_mac_string(sender_mac, mac_bytes)) {
          lockfree_nd_.UpdateEntry(ip6_bytes, mac_bytes, vlan_id, now_tsc);
        }
        return true;
      }
      return false;
    }

    case ControlFrameType::Bfd: {
      if (bfd_engine_.process_rx_packet(data, len, now_tsc)) {
        EmitTxPacket(bfd_engine_.last_tx_packet());
        return true;
      }
      return false;
    }

    case ControlFrameType::Igmp:
    case ControlFrameType::Pppoe:
    case ControlFrameType::Eapol:
    case ControlFrameType::None:
    default:
      return false;
  }
}

void L2L3FastpathWiring::StepTimers(uint64_t now_tsc, uint64_t tsc_hz) {
  last_out_packet_.clear();

  // BFD periyodik adımı
  if (bfd_engine_.step_timer(now_tsc, tsc_hz)) {
    EmitTxPacket(bfd_engine_.last_tx_packet());
  }
}

}  // namespace ddos_samurai::telecom
