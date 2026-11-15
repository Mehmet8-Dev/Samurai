#include "bfd_engine.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace samurai::l7_emu_native::l2l3 {

namespace {

#pragma pack(push, 1)
struct EthHeader {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint16_t eth_type;  // 0x0800 for IPv4
};

struct Ipv4Header {
  uint8_t ihl_version; // 0x45
  uint8_t tos;
  uint16_t total_length;
  uint16_t id;
  uint16_t flags_fragment;
  uint8_t ttl;
  uint8_t protocol;    // 17 (UDP)
  uint16_t checksum;
  uint32_t src_ip;
  uint32_t dst_ip;
};

struct UdpHeader {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
};
#pragma pack(pop)

bool parse_mac_bytes(const std::string& mac_str, uint8_t out[6]) {
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

uint16_t compute_checksum(const uint16_t* data, size_t bytes) {
  uint32_t sum = 0;
  while (bytes > 1) {
    sum += *data++;
    bytes -= 2;
  }
  if (bytes == 1) {
    sum += *reinterpret_cast<const uint8_t*>(data);
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum);
}

}  // namespace

void BfdEngine::start_session(const BfdSessionConfig& cfg) {
  cfg_ = cfg;
  state_ = BfdState::Down;
  local_diag_ = BfdDiag::None;
  remote_disc_ = 0;
  negotiated_rx_us_ = cfg_.required_rx_interval_us;
  negotiated_tx_us_ = cfg_.desired_tx_interval_us;
  last_tx_tsc_ = 0;
  last_rx_tsc_ = 0;
  detection_time_tsc_ = 0;
  failover_triggered_ = false;
  is_active_ = true;

  // Build initial Down/Poll packet
  last_tx_packet_ = build_bfd_control_packet(
      cfg_, state_, local_diag_, remote_disc_, true, false);
}

void BfdEngine::stop_session() {
  if (is_active_) {
    state_ = BfdState::AdminDown;
    local_diag_ = BfdDiag::AdministrativelyDown;
    last_tx_packet_ = build_bfd_control_packet(
        cfg_, state_, local_diag_, remote_disc_, false, false);
    is_active_ = false;
  }
}

bool BfdEngine::process_rx_packet(const uint8_t* data, size_t len, uint64_t now_tsc) {
  if (!is_active_ || !data || len < sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(BfdControlHeader)) {
    return false;
  }

  BfdControlHeader rx_hdr{};
  uint32_t received_remote_disc = 0;
  if (!parse_bfd_control_packet(data, len, rx_hdr, received_remote_disc)) {
    return false;
  }

  // Verify your_discriminator matches our local_disc if not in Down state
  uint32_t your_disc = ntohl(rx_hdr.your_discriminator);
  if (your_disc != 0 && your_disc != cfg_.local_disc) {
    return false; // Packet not destined for this session
  }

  remote_disc_ = received_remote_disc;
  last_rx_tsc_ = now_tsc;

  // Extract remote state (bits 7-6 of sta_flags)
  uint8_t r_state_val = (rx_hdr.sta_flags >> 6) & 0x03;
  auto r_state = static_cast<BfdState>(r_state_val);

  // Negotiate intervals (RFC 5880 Section 6.8.3)
  uint32_t remote_min_rx_us = ntohl(rx_hdr.min_rx_interval_us);
  uint32_t remote_min_tx_us = ntohl(rx_hdr.min_tx_interval_us);
  negotiated_tx_us_ = std::max(cfg_.desired_tx_interval_us, remote_min_rx_us);
  negotiated_rx_us_ = std::max(cfg_.required_rx_interval_us, remote_min_tx_us);

  // FSM State transitions (RFC 5880 Section 6.8.1)
  if (r_state == BfdState::AdminDown) {
    state_ = BfdState::Down;
    local_diag_ = BfdDiag::NeighborSignaledDown;
    failover_triggered_ = true;
  } else if (state_ == BfdState::Down) {
    if (r_state == BfdState::Down) {
      state_ = BfdState::Init;
    } else if (r_state == BfdState::Init) {
      state_ = BfdState::Up;
    }
  } else if (state_ == BfdState::Init) {
    if (r_state == BfdState::Init || r_state == BfdState::Up) {
      state_ = BfdState::Up;
    }
  } else if (state_ == BfdState::Up) {
    if (r_state == BfdState::Down) {
      state_ = BfdState::Down;
      local_diag_ = BfdDiag::NeighborSignaledDown;
      failover_triggered_ = true;
    }
  }

  // Generate response packet with current state
  last_tx_packet_ = build_bfd_control_packet(
      cfg_, state_, local_diag_, remote_disc_, false, false);
  return true;
}

bool BfdEngine::step_timer(uint64_t now_tsc, uint64_t tsc_hz) {
  if (!is_active_) return false;

  bool tx_due = false;

  // 1. Calculate detection interval in TSC ticks
  if (tsc_hz > 0 && negotiated_rx_us_ > 0) {
    uint64_t rx_interval_tsc = (static_cast<uint64_t>(negotiated_rx_us_) * tsc_hz) / 1000000ULL;
    detection_time_tsc_ = rx_interval_tsc * cfg_.detect_multiplier;

    // Detection timeout check (RFC 5880 Section 6.8.4)
    if (state_ == BfdState::Up && last_rx_tsc_ > 0) {
      if (now_tsc > last_rx_tsc_ && (now_tsc - last_rx_tsc_) > detection_time_tsc_) {
        state_ = BfdState::Down;
        local_diag_ = BfdDiag::ControlDetectionTimeExpired;
        failover_triggered_ = true;

        // Immediate state change transmission
        last_tx_packet_ = build_bfd_control_packet(
            cfg_, state_, local_diag_, remote_disc_, false, false);
        last_tx_tsc_ = now_tsc;
        return true;
      }
    }

    // 2. Transmit interval check
    uint64_t tx_interval_tsc = (static_cast<uint64_t>(negotiated_tx_us_) * tsc_hz) / 1000000ULL;
    if (last_tx_tsc_ == 0 || (now_tsc - last_tx_tsc_) >= tx_interval_tsc) {
      last_tx_packet_ = build_bfd_control_packet(
          cfg_, state_, local_diag_, remote_disc_, false, false);
      last_tx_tsc_ = now_tsc;
      tx_due = true;
    }
  }

  return tx_due;
}

std::vector<uint8_t> BfdEngine::build_bfd_control_packet(
    const BfdSessionConfig& cfg, BfdState state, BfdDiag diag,
    uint32_t remote_disc, bool poll, bool final_flag) {

  size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(BfdControlHeader);
  std::vector<uint8_t> packet(total_len, 0);

  // 1. Ethernet Header
  auto* eth = reinterpret_cast<EthHeader*>(packet.data());
  parse_mac_bytes(cfg.remote_mac, eth->dst_mac);
  parse_mac_bytes(cfg.local_mac, eth->src_mac);
  eth->eth_type = htons(0x0800);

  // 2. IPv4 Header
  auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
  ip->ihl_version = 0x45;
  ip->tos = 0xC0; // CS6 / Network Control DSCP (RFC 5881)
  ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(BfdControlHeader)));
  ip->id = htons(0xBFD1);
  ip->flags_fragment = 0;
  ip->ttl = 255; // Strict TTL 255 verification required by RFC 5881
  ip->protocol = 17; // UDP
  inet_pton(AF_INET, cfg.local_ip.c_str(), &ip->src_ip);
  inet_pton(AF_INET, cfg.remote_ip.c_str(), &ip->dst_ip);
  ip->checksum = compute_checksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

  // 3. UDP Header
  auto* udp = reinterpret_cast<UdpHeader*>(packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
  udp->src_port = htons(cfg.udp_src_port);
  udp->dst_port = htons(cfg.udp_dst_port);
  udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + sizeof(BfdControlHeader)));
  udp->checksum = 0; // Optional in IPv4

  // 4. BFD Control Header
  auto* bfd = reinterpret_cast<BfdControlHeader*>(
      packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader));
  
  // Vers (1) = 3 bits (001b = 0x20), Diag = 5 bits
  uint8_t diag_val = static_cast<uint8_t>(diag) & 0x1F;
  bfd->vers_diag = 0x20 | diag_val;

  // Sta = 2 bits (bits 7-6), P = bit 5, F = bit 4
  uint8_t sta_val = (static_cast<uint8_t>(state) & 0x03) << 6;
  if (poll) sta_val |= 0x20;
  if (final_flag) sta_val |= 0x10;
  bfd->sta_flags = sta_val;

  bfd->detect_mult = cfg.detect_multiplier;
  bfd->length = sizeof(BfdControlHeader);
  bfd->my_discriminator = htonl(cfg.local_disc);
  bfd->your_discriminator = htonl(remote_disc);
  bfd->min_tx_interval_us = htonl(cfg.desired_tx_interval_us);
  bfd->min_rx_interval_us = htonl(cfg.required_rx_interval_us);
  bfd->min_echo_rx_interval = 0;

  return packet;
}

bool BfdEngine::parse_bfd_control_packet(
    const uint8_t* data, size_t len,
    BfdControlHeader& out_hdr, uint32_t& out_remote_disc) {

  size_t min_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(BfdControlHeader);
  if (!data || len < min_len) return false;

  const auto* eth = reinterpret_cast<const EthHeader*>(data);
  if (ntohs(eth->eth_type) != 0x0800) return false;

  const auto* ip = reinterpret_cast<const Ipv4Header*>(data + sizeof(EthHeader));
  if ((ip->ihl_version >> 4) != 4 || ip->protocol != 17) return false;

  // RFC 5881 Section 4: The TTL (or Hop Limit) value of all incoming single-hop BFD packets
  // MUST be validated to have a TTL of 255. Packets with any other TTL value MUST be dropped.
  if (ip->ttl != 255) return false;

  size_t ip_hdr_len = (ip->ihl_version & 0x0F) * 4;
  if (ip_hdr_len < sizeof(Ipv4Header) || len < sizeof(EthHeader) + ip_hdr_len + sizeof(UdpHeader) + sizeof(BfdControlHeader)) {
    return false;
  }

  // IPv4 Header Checksum Doğrulaması
  if (compute_checksum(reinterpret_cast<const uint16_t*>(ip), ip_hdr_len) != 0) {
    return false;
  }

  uint16_t ip_total_len = ntohs(ip->total_length);
  if (len < sizeof(EthHeader) + ip_total_len || ip_total_len < ip_hdr_len + sizeof(UdpHeader) + sizeof(BfdControlHeader)) {
    return false;
  }

  const auto* udp = reinterpret_cast<const UdpHeader*>(data + sizeof(EthHeader) + ip_hdr_len);
  uint16_t dst_port = ntohs(udp->dst_port);
  if (dst_port != 3784 && dst_port != 3785) return false;

  uint16_t udp_len = ntohs(udp->length);
  if (udp_len < sizeof(UdpHeader) + sizeof(BfdControlHeader) || ip_total_len < ip_hdr_len + udp_len) {
    return false;
  }

  const auto* bfd = reinterpret_cast<const BfdControlHeader*>(
      data + sizeof(EthHeader) + ip_hdr_len + sizeof(UdpHeader));

  uint8_t version = (bfd->vers_diag >> 5) & 0x07;
  if (version != 1) return false; // Must be BFD version 1

  // RFC 5880 Section 4.1: BFD Length must be at least 24 bytes
  if (bfd->length < sizeof(BfdControlHeader)) return false;

  // RFC 5880 Section 6.8.6: If the Detect Mult field is zero, the packet MUST be discarded
  if (bfd->detect_mult == 0) return false;

  // RFC 5880 Section 6.8.6: If the My Discriminator field is zero, the packet MUST be discarded
  if (bfd->my_discriminator == 0) return false;

  out_hdr = *bfd;
  out_remote_disc = ntohl(bfd->my_discriminator);
  return true;
}

}  // namespace samurai::l7_emu_native::l2l3
