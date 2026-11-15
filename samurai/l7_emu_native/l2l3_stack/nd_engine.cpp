#include "nd_engine.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <vector>

namespace samurai::l7_emu_native::l2l3 {

namespace {

#pragma pack(push, 1)
struct EthHeader {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint16_t eth_type;  // 0x86DD for IPv6
};

struct Ipv6Header {
  uint32_t vtc_fl;     // Version (6), Traffic Class, Flow Label
  uint16_t payload_len;
  uint8_t next_header; // 58 = ICMPv6
  uint8_t hop_limit;   // 255 for Neighbor Discovery
  uint8_t src_ip[16];
  uint8_t dst_ip[16];
};

struct Icmpv6NsHeader {
  uint8_t type;        // 135 (Neighbor Solicitation)
  uint8_t code;        // 0
  uint16_t checksum;
  uint32_t reserved;
  uint8_t target_ip[16];
  // Option 1: Source Link-layer Address (8 bytes)
  uint8_t opt_type;    // 1
  uint8_t opt_len;     // 1 (unit of 8 bytes)
  uint8_t opt_mac[6];
};

struct Icmpv6NaHeader {
  uint8_t type;        // 136 (Neighbor Advertisement)
  uint8_t code;        // 0
  uint16_t checksum;
  uint32_t flags;      // R=1, S=1, O=1 (0x60000000)
  uint8_t target_ip[16];
  // Option 2: Target Link-layer Address (8 bytes)
  uint8_t opt_type;    // 2
  uint8_t opt_len;     // 1
  uint8_t opt_mac[6];
};
#pragma pack(pop)

bool parse_mac(const std::string& mac_str, uint8_t out[6]) {
  int values[6];
  if (sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
             &values[0], &values[1], &values[2],
             &values[3], &values[4], &values[5]) == 6) {
    for (int i = 0; i < 6; ++i) out[i] = static_cast<uint8_t>(values[i]);
    return true;
  }
  std::memset(out, 0, 6);
  return false;
}

std::string format_mac(const uint8_t mac[6]) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return std::string(buf);
}

}  // namespace

void NdEngine::send_neighbor_solicitation(const std::string& target_ip) {
  send_neighbor_solicitation("00:00:00:00:00:01", "fe80::1", target_ip);
}

void NdEngine::send_neighbor_solicitation(
    const std::string& src_mac, const std::string& src_ip, const std::string& target_ip) {
  last_tx_packet_ = build_neighbor_solicitation(src_mac, src_ip, target_ip);
}

std::vector<uint8_t> NdEngine::build_neighbor_solicitation(
    const std::string& src_mac, const std::string& src_ip, const std::string& target_ip) {
  std::vector<uint8_t> frame(sizeof(EthHeader) + sizeof(Ipv6Header) + sizeof(Icmpv6NsHeader));
  auto* eth = reinterpret_cast<EthHeader*>(frame.data());
  auto* ip6 = reinterpret_cast<Ipv6Header*>(frame.data() + sizeof(EthHeader));
  auto* ns = reinterpret_cast<Icmpv6NsHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv6Header));

  // Solicited-node multicast dst mac (33:33:ff:xx:xx:xx)
  eth->dst_mac[0] = 0x33; eth->dst_mac[1] = 0x33; eth->dst_mac[2] = 0xFF;
  eth->dst_mac[3] = 0x00; eth->dst_mac[4] = 0x00; eth->dst_mac[5] = 0x01;
  parse_mac(src_mac, eth->src_mac);
  eth->eth_type = htons(0x86DD);

  ip6->vtc_fl = htonl(0x60000000);
  ip6->payload_len = htons(sizeof(Icmpv6NsHeader));
  ip6->next_header = 58; // ICMPv6
  ip6->hop_limit = 255;  // Required for ND
  inet_pton(AF_INET6, src_ip.c_str(), ip6->src_ip);
  inet_pton(AF_INET6, target_ip.c_str(), ip6->dst_ip);

  ns->type = 135;
  ns->code = 0;
  ns->checksum = 0;
  ns->reserved = 0;
  inet_pton(AF_INET6, target_ip.c_str(), ns->target_ip);
  ns->opt_type = 1; // Source Link-Layer Address
  ns->opt_len = 1;  // 8 bytes
  parse_mac(src_mac, ns->opt_mac);

  return frame;
}

std::vector<uint8_t> NdEngine::build_neighbor_advertisement(
    const std::string& src_mac, const std::string& src_ip,
    const std::string& dst_mac, const std::string& dst_ip) {
  std::vector<uint8_t> frame(sizeof(EthHeader) + sizeof(Ipv6Header) + sizeof(Icmpv6NaHeader));
  auto* eth = reinterpret_cast<EthHeader*>(frame.data());
  auto* ip6 = reinterpret_cast<Ipv6Header*>(frame.data() + sizeof(EthHeader));
  auto* na = reinterpret_cast<Icmpv6NaHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv6Header));

  parse_mac(dst_mac, eth->dst_mac);
  parse_mac(src_mac, eth->src_mac);
  eth->eth_type = htons(0x86DD);

  ip6->vtc_fl = htonl(0x60000000);
  ip6->payload_len = htons(sizeof(Icmpv6NaHeader));
  ip6->next_header = 58;
  ip6->hop_limit = 255;
  inet_pton(AF_INET6, src_ip.c_str(), ip6->src_ip);
  inet_pton(AF_INET6, dst_ip.c_str(), ip6->dst_ip);

  na->type = 136;
  na->code = 0;
  na->checksum = 0;
  na->flags = htonl(0x60000000); // Router + Solicited
  inet_pton(AF_INET6, src_ip.c_str(), na->target_ip);
  na->opt_type = 2; // Target Link-Layer Address
  na->opt_len = 1;
  parse_mac(src_mac, na->opt_mac);

  return frame;
}

bool NdEngine::parse_neighbor_advertisement(
    const uint8_t* data, size_t len,
    std::string& out_sender_ip, std::string& out_sender_mac) {
  if (data == nullptr || len < sizeof(EthHeader) + sizeof(Ipv6Header) + sizeof(Icmpv6NaHeader)) {
    return false;
  }
  const auto* eth = reinterpret_cast<const EthHeader*>(data);
  if (ntohs(eth->eth_type) != 0x86DD) return false;
  const auto* ip6 = reinterpret_cast<const Ipv6Header*>(data + sizeof(EthHeader));
  if (ip6->next_header != 58) return false;
  const auto* na = reinterpret_cast<const Icmpv6NaHeader*>(data + sizeof(EthHeader) + sizeof(Ipv6Header));
  if (na->type != 136) return false;

  char ip_buf[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, na->target_ip, ip_buf, sizeof(ip_buf));
  out_sender_ip = ip_buf;
  out_sender_mac = format_mac(na->opt_mac);
  return true;
}

void NdEngine::process_neighbor_advertisement(const std::string& sender_ip, const std::string& sender_mac) {
  nd_cache_[sender_ip] = sender_mac;
}

std::string NdEngine::get_mac(const std::string& target_ip) const {
  auto it = nd_cache_.find(target_ip);
  if (it != nd_cache_.end()) {
    return it->second;
  }
  return "";
}

bool NdEngine::is_resolved(const std::string& target_ip) const {
  return nd_cache_.find(target_ip) != nd_cache_.end();
}

}  // namespace samurai::l7_emu_native::l2l3

