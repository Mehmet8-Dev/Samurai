#include "dhcp_state_machine.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <vector>

namespace ddos_samurai::l7_emu_native::l2l3 {

namespace {

#pragma pack(push, 1)
struct EthHeader {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint16_t eth_type;  // 0x0800 for IPv4
};

struct IpHeader {
  uint8_t ver_ihl;     // 0x45
  uint8_t tos;
  uint16_t total_len;
  uint16_t id;
  uint16_t flags_offset;
  uint8_t ttl;
  uint8_t protocol;    // 17 for UDP
  uint16_t checksum;
  uint32_t src_ip;
  uint32_t dst_ip;
};

struct UdpHeader {
  uint16_t src_port;   // 68
  uint16_t dst_port;   // 67
  uint16_t length;
  uint16_t checksum;
};

struct DhcpHeader {
  uint8_t op;          // 1=BOOTREQUEST, 2=BOOTREPLY
  uint8_t htype;       // 1=Ethernet
  uint8_t hlen;        // 6
  uint8_t hops;        // 0
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;      // 0x8000 (broadcast)
  uint32_t ciaddr;
  uint32_t yiaddr;
  uint32_t siaddr;
  uint32_t giaddr;
  uint8_t chaddr[16];
  uint8_t sname[64];
  uint8_t file[128];
  uint32_t magic_cookie; // 0x63825363 (network order)
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

uint16_t calculate_checksum(const uint16_t* buf, size_t nwords) {
  uint32_t sum = 0;
  for (; nwords > 0; nwords--) sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

}  // namespace

void DhcpStateMachine::start(const DhcpConfig& config) {
  config_ = config;
  state_ = DhcpState::Selecting;
  last_tx_packet_ = build_dhcp_discover(config_.client_mac.empty() ? "00:11:22:33:44:55" : config_.client_mac, config_.xid);
}

void DhcpStateMachine::process_offer(const std::string& offered_ip, const std::string& server_ip) {
  if (state_ == DhcpState::Selecting) {
    state_ = DhcpState::Requesting;
    if (!offered_ip.empty()) ip_ = offered_ip;
    if (!server_ip.empty()) server_ip_ = server_ip;
    last_tx_packet_ = build_dhcp_request(
        config_.client_mac.empty() ? "00:11:22:33:44:55" : config_.client_mac,
        config_.xid,
        ip_.empty() ? "10.0.0.100" : ip_,
        server_ip_.empty() ? "10.0.0.1" : server_ip_);
  }
}

void DhcpStateMachine::process_ack(const std::string& acked_ip) {
  if (state_ == DhcpState::Requesting) {
    state_ = DhcpState::Bound;
    if (!acked_ip.empty()) {
      ip_ = acked_ip;
    } else if (ip_.empty()) {
      ip_ = (config_.version == 4) ? "10.0.0.100" : "fe80::100";
    }
  }
}

std::vector<uint8_t> DhcpStateMachine::build_dhcp_discover(
    const std::string& client_mac, uint32_t xid) {
  std::vector<uint8_t> frame(sizeof(EthHeader) + sizeof(IpHeader) + sizeof(UdpHeader) + sizeof(DhcpHeader));

  // Options payload: Option 53 (Discover = 1), Option 55 (Param Req), Option 255 (End)
  const uint8_t options[] = {
      53, 1, 1,                   // DHCP Message Type: Discover
      55, 4, 1, 3, 6, 15,         // Parameter Request List: Subnet, Router, DNS, Domain
      255                         // End
  };

  frame.insert(frame.end(), options, options + sizeof(options));

  auto* eth = reinterpret_cast<EthHeader*>(frame.data());
  auto* ip = reinterpret_cast<IpHeader*>(frame.data() + sizeof(EthHeader));
  auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(IpHeader));
  auto* dhcp = reinterpret_cast<DhcpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(IpHeader) + sizeof(UdpHeader));

  std::memset(eth->dst_mac, 0xFF, 6);
  parse_mac(client_mac, eth->src_mac);
  eth->eth_type = htons(0x0800);

  const uint16_t total_ip_len = static_cast<uint16_t>(frame.size() - sizeof(EthHeader));
  const uint16_t udp_len = static_cast<uint16_t>(frame.size() - sizeof(EthHeader) - sizeof(IpHeader));

  ip->ver_ihl = 0x45;
  ip->tos = 0;
  ip->total_len = htons(total_ip_len);
  ip->id = htons(0x1234);
  ip->flags_offset = 0;
  ip->ttl = 64;
  ip->protocol = 17; // UDP
  ip->src_ip = 0;    // 0.0.0.0
  ip->dst_ip = 0xFFFFFFFF; // 255.255.255.255
  ip->checksum = 0;
  ip->checksum = calculate_checksum(reinterpret_cast<const uint16_t*>(ip), sizeof(IpHeader) / 2);

  udp->src_port = htons(68);
  udp->dst_port = htons(67);
  udp->length = htons(udp_len);
  udp->checksum = 0;

  std::memset(dhcp, 0, sizeof(DhcpHeader));
  dhcp->op = 1;      // BOOTREQUEST
  dhcp->htype = 1;   // Ethernet
  dhcp->hlen = 6;
  dhcp->xid = htonl(xid);
  dhcp->flags = htons(0x8000); // Broadcast
  parse_mac(client_mac, dhcp->chaddr);
  dhcp->magic_cookie = htonl(0x63825363);

  return frame;
}

std::vector<uint8_t> DhcpStateMachine::build_dhcp_request(
    const std::string& client_mac, uint32_t xid,
    const std::string& requested_ip, const std::string& server_ip) {
  std::vector<uint8_t> frame(sizeof(EthHeader) + sizeof(IpHeader) + sizeof(UdpHeader) + sizeof(DhcpHeader));

  uint32_t req_ip_be = 0;
  uint32_t srv_ip_be = 0;
  inet_pton(AF_INET, requested_ip.c_str(), &req_ip_be);
  inet_pton(AF_INET, server_ip.c_str(), &srv_ip_be);

  const uint8_t req_ip_bytes[4] = {
      static_cast<uint8_t>(req_ip_be & 0xFF),
      static_cast<uint8_t>((req_ip_be >> 8) & 0xFF),
      static_cast<uint8_t>((req_ip_be >> 16) & 0xFF),
      static_cast<uint8_t>((req_ip_be >> 24) & 0xFF)};

  const uint8_t srv_ip_bytes[4] = {
      static_cast<uint8_t>(srv_ip_be & 0xFF),
      static_cast<uint8_t>((srv_ip_be >> 8) & 0xFF),
      static_cast<uint8_t>((srv_ip_be >> 16) & 0xFF),
      static_cast<uint8_t>((srv_ip_be >> 24) & 0xFF)};

  std::vector<uint8_t> options = {
      53, 1, 3,                            // Option 53: DHCP Request
      50, 4, req_ip_bytes[0], req_ip_bytes[1], req_ip_bytes[2], req_ip_bytes[3], // Option 50: Requested IP
      54, 4, srv_ip_bytes[0], srv_ip_bytes[1], srv_ip_bytes[2], srv_ip_bytes[3], // Option 54: Server ID
      255                                  // End
  };

  frame.insert(frame.end(), options.begin(), options.end());

  auto* eth = reinterpret_cast<EthHeader*>(frame.data());
  auto* ip = reinterpret_cast<IpHeader*>(frame.data() + sizeof(EthHeader));
  auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(IpHeader));
  auto* dhcp = reinterpret_cast<DhcpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(IpHeader) + sizeof(UdpHeader));

  std::memset(eth->dst_mac, 0xFF, 6);
  parse_mac(client_mac, eth->src_mac);
  eth->eth_type = htons(0x0800);

  const uint16_t total_ip_len = static_cast<uint16_t>(frame.size() - sizeof(EthHeader));
  const uint16_t udp_len = static_cast<uint16_t>(frame.size() - sizeof(EthHeader) - sizeof(IpHeader));

  ip->ver_ihl = 0x45;
  ip->tos = 0;
  ip->total_len = htons(total_ip_len);
  ip->id = htons(0x1235);
  ip->flags_offset = 0;
  ip->ttl = 64;
  ip->protocol = 17;
  ip->src_ip = 0;
  ip->dst_ip = 0xFFFFFFFF;
  ip->checksum = 0;
  ip->checksum = calculate_checksum(reinterpret_cast<const uint16_t*>(ip), sizeof(IpHeader) / 2);

  udp->src_port = htons(68);
  udp->dst_port = htons(67);
  udp->length = htons(udp_len);
  udp->checksum = 0;

  std::memset(dhcp, 0, sizeof(DhcpHeader));
  dhcp->op = 1;
  dhcp->htype = 1;
  dhcp->hlen = 6;
  dhcp->xid = htonl(xid);
  dhcp->flags = htons(0x8000);
  parse_mac(client_mac, dhcp->chaddr);
  dhcp->magic_cookie = htonl(0x63825363);

  return frame;
}

bool DhcpStateMachine::parse_dhcp_packet(
    const uint8_t* data, size_t len,
    uint32_t& out_xid, std::string& out_yiaddr,
    std::string& out_server_ip, int& out_msg_type) {
  if (data == nullptr || len < sizeof(EthHeader) + sizeof(IpHeader) + sizeof(UdpHeader) + sizeof(DhcpHeader)) {
    return false;
  }
  const auto* dhcp = reinterpret_cast<const DhcpHeader*>(
      data + sizeof(EthHeader) + sizeof(IpHeader) + sizeof(UdpHeader));

  if (ntohl(dhcp->magic_cookie) != 0x63825363) {
    return false;
  }

  out_xid = ntohl(dhcp->xid);

  char ip_buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &dhcp->yiaddr, ip_buf, sizeof(ip_buf));
  out_yiaddr = ip_buf;

  inet_ntop(AF_INET, &dhcp->siaddr, ip_buf, sizeof(ip_buf));
  out_server_ip = ip_buf;

  out_msg_type = 0;
  const uint8_t* opts = data + sizeof(EthHeader) + sizeof(IpHeader) + sizeof(UdpHeader) + sizeof(DhcpHeader);
  size_t opt_len = len - (sizeof(EthHeader) + sizeof(IpHeader) + sizeof(UdpHeader) + sizeof(DhcpHeader));
  size_t i = 0;
  while (i < opt_len) {
    if (opts[i] == 255) break;
    if (opts[i] == 0) { i++; continue; }
    if (i + 1 >= opt_len) break;
    uint8_t code = opts[i];
    uint8_t l = opts[i + 1];
    if (i + 2 + l > opt_len) break;
    if (code == 53 && l >= 1) {
      out_msg_type = opts[i + 2];
    }
    i += 2 + l;
  }

  return true;
}

}  // namespace ddos_samurai::l7_emu_native::l2l3

