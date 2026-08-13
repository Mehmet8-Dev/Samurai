#include "arp_engine.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace ddos_samurai::l7_emu_native::l2l3 {

namespace {

#pragma pack(push, 1)
struct EthHeader {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint16_t eth_type;  // 0x0806 for ARP
};

struct ArpHeader {
  uint16_t htype;     // 0x0001
  uint16_t ptype;     // 0x0800
  uint8_t hlen;       // 6
  uint8_t plen;       // 4
  uint16_t oper;      // 1=REQ, 2=REPLY
  uint8_t sender_mac[6];
  uint32_t sender_ip;
  uint8_t target_mac[6];
  uint32_t target_ip;
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

void ArpEngine::send_arp_request(const std::string& target_ip) {
  send_arp_request("00:00:00:00:00:01", "10.0.0.1", target_ip);
}

void ArpEngine::send_arp_request(const std::string& src_mac, const std::string& src_ip, const std::string& target_ip) {
  last_tx_packet_ = build_arp_request(src_mac, src_ip, target_ip);
}

std::vector<uint8_t> ArpEngine::build_arp_request(
    const std::string& src_mac, const std::string& src_ip, const std::string& target_ip) {
  std::vector<uint8_t> frame(sizeof(EthHeader) + sizeof(ArpHeader));
  auto* eth = reinterpret_cast<EthHeader*>(frame.data());
  auto* arp = reinterpret_cast<ArpHeader*>(frame.data() + sizeof(EthHeader));

  // Ethernet broadcast
  std::memset(eth->dst_mac, 0xFF, 6);
  parse_mac(src_mac, eth->src_mac);
  eth->eth_type = htons(0x0806);

  arp->htype = htons(1);       // Ethernet
  arp->ptype = htons(0x0800);  // IPv4
  arp->hlen = 6;
  arp->plen = 4;
  arp->oper = htons(1);        // ARP Request

  parse_mac(src_mac, arp->sender_mac);
  inet_pton(AF_INET, src_ip.c_str(), &arp->sender_ip);
  std::memset(arp->target_mac, 0x00, 6);
  inet_pton(AF_INET, target_ip.c_str(), &arp->target_ip);

  return frame;
}

std::vector<uint8_t> ArpEngine::build_arp_reply(
    const std::string& src_mac, const std::string& src_ip,
    const std::string& dst_mac, const std::string& dst_ip) {
  std::vector<uint8_t> frame(sizeof(EthHeader) + sizeof(ArpHeader));
  auto* eth = reinterpret_cast<EthHeader*>(frame.data());
  auto* arp = reinterpret_cast<ArpHeader*>(frame.data() + sizeof(EthHeader));

  parse_mac(dst_mac, eth->dst_mac);
  parse_mac(src_mac, eth->src_mac);
  eth->eth_type = htons(0x0806);

  arp->htype = htons(1);
  arp->ptype = htons(0x0800);
  arp->hlen = 6;
  arp->plen = 4;
  arp->oper = htons(2);        // ARP Reply

  parse_mac(src_mac, arp->sender_mac);
  inet_pton(AF_INET, src_ip.c_str(), &arp->sender_ip);
  parse_mac(dst_mac, arp->target_mac);
  inet_pton(AF_INET, dst_ip.c_str(), &arp->target_ip);

  return frame;
}

bool ArpEngine::parse_arp_packet(
    const uint8_t* data, size_t len,
    std::string& out_sender_ip, std::string& out_sender_mac, uint16_t& out_op) {
  if (data == nullptr || len < sizeof(EthHeader) + sizeof(ArpHeader)) {
    return false;
  }
  const auto* eth = reinterpret_cast<const EthHeader*>(data);
  if (ntohs(eth->eth_type) != 0x0806) {
    return false;
  }
  const auto* arp = reinterpret_cast<const ArpHeader*>(data + sizeof(EthHeader));
  out_op = ntohs(arp->oper);

  char ip_buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &arp->sender_ip, ip_buf, sizeof(ip_buf));
  out_sender_ip = ip_buf;
  out_sender_mac = format_mac(arp->sender_mac);
  return true;
}

void ArpEngine::process_arp_reply(const std::string& sender_ip, const std::string& sender_mac) {
  arp_cache_[sender_ip] = sender_mac;
}

std::string ArpEngine::get_mac(const std::string& target_ip) const {
  auto it = arp_cache_.find(target_ip);
  if (it != arp_cache_.end()) {
    return it->second;
  }
  return "";
}

bool ArpEngine::is_resolved(const std::string& target_ip) const {
  return arp_cache_.find(target_ip) != arp_cache_.end();
}

}  // namespace ddos_samurai::l7_emu_native::l2l3

