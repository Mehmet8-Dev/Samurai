#include "igmp_engine.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <vector>

namespace samurai::l7_emu_native::l2l3 {

namespace {

#pragma pack(push, 1)
struct EthHeader {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint16_t eth_type;  // 0x0800 for IPv4
};

struct IpHeader {
  uint8_t ver_ihl;     // 0x46 (with Router Alert option if needed) or 0x45
  uint8_t tos;
  uint16_t total_len;
  uint16_t id;
  uint16_t flags_offset;
  uint8_t ttl;         // 1 for IGMP
  uint8_t protocol;    // 2 for IGMP
  uint16_t checksum;
  uint32_t src_ip;
  uint32_t dst_ip;
};

struct Igmpv2Header {
  uint8_t type;        // 0x16 = v2 Report, 0x17 = Leave Group
  uint8_t max_resp_time;
  uint16_t checksum;
  uint32_t group_ip;
};
#pragma pack(pop)

uint16_t calculate_checksum(const uint16_t* buf, size_t nwords) {
  uint32_t sum = 0;
  for (; nwords > 0; nwords--) sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

}  // namespace

void IgmpEngine::join_group(const std::string& group_ip, int version) {
  active_groups_.insert(group_ip);
  last_tx_packet_ = build_igmp_report(group_ip, version);
}

void IgmpEngine::leave_group(const std::string& group_ip, int version) {
  active_groups_.erase(group_ip);
  last_tx_packet_ = build_igmp_leave(group_ip, version);
}

std::vector<uint8_t> IgmpEngine::build_igmp_report(
    const std::string& group_ip, int version, const std::string& src_ip) {
  (void)version;
  std::vector<uint8_t> frame(sizeof(EthHeader) + sizeof(IpHeader) + sizeof(Igmpv2Header));
  auto* eth = reinterpret_cast<EthHeader*>(frame.data());
  auto* ip = reinterpret_cast<IpHeader*>(frame.data() + sizeof(EthHeader));
  auto* igmp = reinterpret_cast<Igmpv2Header*>(frame.data() + sizeof(EthHeader) + sizeof(IpHeader));

  // Multicast destination MAC (01:00:5e:xx:xx:xx)
  uint32_t g_ip_be = 0;
  inet_pton(AF_INET, group_ip.c_str(), &g_ip_be);
  uint32_t g_ip_host = ntohl(g_ip_be);

  eth->dst_mac[0] = 0x01;
  eth->dst_mac[1] = 0x00;
  eth->dst_mac[2] = 0x5e;
  eth->dst_mac[3] = static_cast<uint8_t>((g_ip_host >> 16) & 0x7f);
  eth->dst_mac[4] = static_cast<uint8_t>((g_ip_host >> 8) & 0xff);
  eth->dst_mac[5] = static_cast<uint8_t>(g_ip_host & 0xff);

  std::memset(eth->src_mac, 0x02, 6);
  eth->eth_type = htons(0x0800);

  ip->ver_ihl = 0x45;
  ip->tos = 0xC0; // Internet Control
  ip->total_len = htons(sizeof(IpHeader) + sizeof(Igmpv2Header));
  ip->id = htons(0x4321);
  ip->flags_offset = 0;
  ip->ttl = 1;
  ip->protocol = 2; // IGMP
  inet_pton(AF_INET, src_ip.c_str(), &ip->src_ip);
  ip->dst_ip = g_ip_be;
  ip->checksum = 0;
  ip->checksum = calculate_checksum(reinterpret_cast<const uint16_t*>(ip), sizeof(IpHeader) / 2);

  igmp->type = 0x16; // v2 Membership Report
  igmp->max_resp_time = 0;
  igmp->group_ip = g_ip_be;
  igmp->checksum = 0;
  igmp->checksum = calculate_checksum(reinterpret_cast<const uint16_t*>(igmp), sizeof(Igmpv2Header) / 2);

  return frame;
}

std::vector<uint8_t> IgmpEngine::build_igmp_leave(
    const std::string& group_ip, int version, const std::string& src_ip) {
  (void)version;
  std::vector<uint8_t> frame(sizeof(EthHeader) + sizeof(IpHeader) + sizeof(Igmpv2Header));
  auto* eth = reinterpret_cast<EthHeader*>(frame.data());
  auto* ip = reinterpret_cast<IpHeader*>(frame.data() + sizeof(EthHeader));
  auto* igmp = reinterpret_cast<Igmpv2Header*>(frame.data() + sizeof(EthHeader) + sizeof(IpHeader));

  // Leave packet sent to all-routers multicast (224.0.0.2)
  eth->dst_mac[0] = 0x01; eth->dst_mac[1] = 0x00; eth->dst_mac[2] = 0x5e;
  eth->dst_mac[3] = 0x00; eth->dst_mac[4] = 0x00; eth->dst_mac[5] = 0x02;
  std::memset(eth->src_mac, 0x02, 6);
  eth->eth_type = htons(0x0800);

  uint32_t g_ip_be = 0;
  inet_pton(AF_INET, group_ip.c_str(), &g_ip_be);

  ip->ver_ihl = 0x45;
  ip->tos = 0xC0;
  ip->total_len = htons(sizeof(IpHeader) + sizeof(Igmpv2Header));
  ip->id = htons(0x4322);
  ip->flags_offset = 0;
  ip->ttl = 1;
  ip->protocol = 2;
  inet_pton(AF_INET, src_ip.c_str(), &ip->src_ip);
  inet_pton(AF_INET, "224.0.0.2", &ip->dst_ip);
  ip->checksum = 0;
  ip->checksum = calculate_checksum(reinterpret_cast<const uint16_t*>(ip), sizeof(IpHeader) / 2);

  igmp->type = 0x17; // Leave Group
  igmp->max_resp_time = 0;
  igmp->group_ip = g_ip_be;
  igmp->checksum = 0;
  igmp->checksum = calculate_checksum(reinterpret_cast<const uint16_t*>(igmp), sizeof(Igmpv2Header) / 2);

  return frame;
}

bool IgmpEngine::is_member(const std::string& group_ip) const {
  return active_groups_.find(group_ip) != active_groups_.end();
}

}  // namespace samurai::l7_emu_native::l2l3

