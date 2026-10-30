#include "bfd_engine.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <algorithm>

namespace ddos_samurai::telecom::bfd {

namespace {

#pragma pack(push, 1)
struct EthHeader {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
};

struct Ipv4Header {
    uint8_t  ihl_version; // 0x45
    uint8_t  tos;         // 0xC0 (CS6)
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment;
    uint8_t  ttl;         // 255 (RFC 5881 strict)
    uint8_t  protocol;    // 17 (UDP)
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

uint16_t ComputeChecksum(const uint16_t* data, size_t bytes) {
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

void ParseMac(const std::string& mac_str, uint8_t* out) {
    unsigned int bytes[6];
    if (std::sscanf(mac_str.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                    &bytes[0], &bytes[1], &bytes[2],
                    &bytes[3], &bytes[4], &bytes[5]) == 6) {
        for (int i = 0; i < 6; ++i) out[i] = static_cast<uint8_t>(bytes[i]);
    } else {
        std::memset(out, 0, 6);
    }
}

} // namespace

BfdEngine::BfdEngine(SessionManager& session_mgr, HierarchicalTimingWheel* wheel)
    : session_mgr_(session_mgr),
      timing_wheel_(wheel) {}

bool BfdEngine::Init(const ProtocolConfig& cfg) {
    config_ = cfg;
    return true;
}

void BfdEngine::Shutdown() {
    uint32_t cap = session_mgr_.GetCapacity();
    for (uint32_t i = 0; i < cap; ++i) {
        TelcoSessionContext* s = session_mgr_.GetSessionByIndex(i);
        if (s && s->protocol_id == static_cast<uint8_t>(TelcoProtocolId::BFD)) {
            if (timing_wheel_) {
                timing_wheel_->Cancel(s);
            }
            session_mgr_.ReleaseSession(s);
        }
    }
}

BfdState BfdEngine::GetState(const TelcoSessionContext* session) const noexcept {
    return BfdFsm::GetState(session);
}

bool BfdEngine::IsUp(const TelcoSessionContext* session) const noexcept {
    return GetState(session) == BfdState::Up;
}

bool BfdEngine::HasFailed(const TelcoSessionContext* /*session*/) const noexcept {
    return failover_triggered_;
}

void BfdEngine::StartSession(TelcoSessionContext* session, const BfdConfig& bfd_cfg) {
    if (!session) return;

    session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::BFD);
    session->SetBfdLocalDisc(bfd_cfg.local_disc);
    session->SetBfdRemoteDisc(0);
    session->client_port = 49152;
    session->peer_port = BFD_CONTROL_PORT;
    session->ip_proto = 17;

    negotiated_tx_us_ = bfd_cfg.desired_tx_interval_us;
    negotiated_rx_us_ = bfd_cfg.required_rx_interval_us;
    detect_mult_ = bfd_cfg.detect_multiplier;
    failover_triggered_ = false;

    session_mgr_.BindBfdSession(session, bfd_cfg.local_disc);
    BfdFsm::SetState(session, BfdState::Down);

    // Send initial Down/Poll packet
    last_tx_frame_ = BuildBfdControlPacket(session, BfdState::Down, BfdDiag::None, true, false);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    // Schedule 10ms heartbeat in Tier 0 (1ms) timing wheel
    uint32_t interval_ms = std::max(1u, negotiated_tx_us_ / 1000);
    if (timing_wheel_) {
        timing_wheel_->Schedule(session, interval_ms);
    }
}

void BfdEngine::StopSession(TelcoSessionContext* session) {
    if (!session) return;

    if (timing_wheel_) {
        timing_wheel_->Cancel(session);
    }

    BfdFsm::SetState(session, BfdState::AdminDown);
    last_tx_frame_ = BuildBfdControlPacket(session, BfdState::AdminDown, BfdDiag::AdministrativelyDown, false, false);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    session_mgr_.UnbindBfdSession(session);
}

void BfdEngine::HandleTimerStep(TelcoSessionContext* session, uint64_t now_tsc) {
    if (!session) return;

    BfdState current = GetState(session);
    if (current == BfdState::AdminDown) return;

    // Detection timeout check (RFC 5880 Section 6.8.4)
    if (timing_wheel_ && timing_wheel_->GetTscHz() > 0) {
        uint64_t tsc_hz = timing_wheel_->GetTscHz();
        uint64_t rx_interval_tsc = (static_cast<uint64_t>(negotiated_rx_us_) * tsc_hz) / 1000000ULL;
        uint64_t detection_time_tsc = rx_interval_tsc * detect_mult_;

        if (current == BfdState::Up && session->last_activity_tsc > 0) {
            if (now_tsc > session->last_activity_tsc && (now_tsc - session->last_activity_tsc) > detection_time_tsc) {
                BfdDiag diag;
                BfdFsm::TransitionOnTimeout(session, diag);
                failover_triggered_ = true;

                // Immediate state change transmission
                last_tx_frame_ = BuildBfdControlPacket(session, BfdState::Down, diag, false, false);
                session->tx_packets++;
                session->tx_bytes += last_tx_frame_.size();
                return;
            }
        }
    }

    // Transmit heartbeat keepalive
    last_tx_frame_ = BuildBfdControlPacket(session, current, BfdDiag::None, false, false);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    // Reschedule next heartbeat in Tier 0 (1ms resolution)
    uint32_t interval_ms = std::max(1u, negotiated_tx_us_ / 1000);
    if (timing_wheel_) {
        timing_wheel_->Schedule(session, interval_ms);
    }
}

uint32_t BfdEngine::OnTimerTick(uint64_t current_tsc) {
    if (!timing_wheel_) return 0;
    return timing_wheel_->Advance(current_tsc, [this, current_tsc](TelcoSessionContext* s) {
        HandleTimerStep(s, current_tsc);
    });
}

void BfdEngine::OnRxPacket(rte_mbuf* /*mbuf*/, const PacketMetadata& meta, TelcoSessionContext* session) {
    if (meta.raw_frame && meta.raw_len >= 14) {
        ProcessRxFrame(meta.raw_frame, meta.raw_len, 0, session);
    } else if (meta.payload_ptr && meta.payload_len > 0) {
        ProcessRxFrame(meta.payload_ptr, meta.payload_len, 0, session);
    }
}

rte_mbuf* BfdEngine::BuildTxPacket(rte_mempool* /*pool*/, TelcoSessionContext* /*session*/, uint16_t /*event_type*/) {
    return nullptr;
}

// ---------------------------------------------------------------------------
// Gelen Paket Ayrıştırma ve Durum Makinesi
// ---------------------------------------------------------------------------

bool BfdEngine::ProcessRxFrame(const uint8_t* frame, size_t len, uint64_t now_tsc, TelcoSessionContext* session) {
    BfdControlHeader rx_hdr{};
    uint32_t received_remote_disc = 0;

    if (!ParseBfdControlPacket(frame, len, rx_hdr, received_remote_disc)) {
        return false;
    }

    uint32_t your_disc = ntohl(rx_hdr.your_discriminator);

    if (!session) {
        // Demux by discriminator
        if (your_disc != 0) {
            session = session_mgr_.FindBfdSession(your_disc);
        } else {
            // Down packet initial discovery: find session by 5-tuple or active BFD session
            session = session_mgr_.FindBfdSession(0x10000001); // fallback default
        }
        if (!session) return false;
    }

    if (your_disc != 0 && your_disc != session->GetBfdLocalDisc()) {
        return false; // Discriminator mismatch
    }

    session->SetBfdRemoteDisc(received_remote_disc);
    session->last_activity_tsc = now_tsc > 0 ? now_tsc : 1;
    session->rx_packets++;
    session->rx_bytes += len;

    // Remote state
    uint8_t r_state_val = (rx_hdr.sta_flags >> 6) & 0x03;
    auto r_state = static_cast<BfdState>(r_state_val);

    // Negotiate timing intervals (RFC 5880 Section 6.8.3)
    uint32_t remote_min_rx_us = ntohl(rx_hdr.min_rx_interval_us);
    uint32_t remote_min_tx_us = ntohl(rx_hdr.min_tx_interval_us);
    if (remote_min_rx_us > 0) negotiated_tx_us_ = std::max(negotiated_tx_us_, remote_min_rx_us);
    if (remote_min_tx_us > 0) negotiated_rx_us_ = std::max(negotiated_rx_us_, remote_min_tx_us);

    // FSM Transition
    BfdDiag diag;
    bool fail = BfdFsm::TransitionOnRx(session, r_state, diag);
    if (fail) {
        failover_triggered_ = true;
    }

    // Build immediate response packet
    last_tx_frame_ = BuildBfdControlPacket(session, GetState(session), diag, false, false);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    return true;
}

std::vector<uint8_t> BfdEngine::BuildBfdControlPacket(TelcoSessionContext* session, 
                                                     BfdState state, 
                                                     BfdDiag diag, 
                                                     bool poll, 
                                                     bool final_flag) {
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(BfdControlHeader);
    std::vector<uint8_t> packet(total_len, 0);

    // 1. Ethernet Header
    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    if (session) {
        std::memcpy(eth->dst_mac, session->peer_mac, 6);
        std::memcpy(eth->src_mac, session->client_mac, 6);
    } else {
        std::memset(eth->dst_mac, 0xFF, 6);
    }
    eth->ethertype = htons(0x0800);

    // 2. IPv4 Header (RFC 5881 strict TTL 255 & CS6 DSCP)
    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->tos = 0xC0; // CS6 / Network Control DSCP
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(BfdControlHeader)));
    ip->id = htons(0xBFD1);
    ip->flags_fragment = 0;
    ip->ttl = 255; // Strict TTL 255 verification required by RFC 5881
    ip->protocol = 17; // UDP
    if (session) {
        ip->src_ip = htonl(session->client_ip);
        ip->dst_ip = htonl(session->peer_ip);
    }
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    // 3. UDP Header
    auto* udp = reinterpret_cast<UdpHeader*>(packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(session ? session->client_port : 49152);
    udp->dst_port = htons(BFD_CONTROL_PORT);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + sizeof(BfdControlHeader)));
    udp->checksum = 0;

    // 4. BFD Control Header
    auto* bfd = reinterpret_cast<BfdControlHeader*>(
        packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader));

    uint8_t diag_val = static_cast<uint8_t>(diag) & 0x1F;
    bfd->vers_diag = 0x20 | diag_val; // Version 1 (001b = 0x20)

    uint8_t sta_val = (static_cast<uint8_t>(state) & 0x03) << 6;
    if (poll) sta_val |= 0x20;
    if (final_flag) sta_val |= 0x10;
    bfd->sta_flags = sta_val;

    bfd->detect_mult = detect_mult_;
    bfd->length = sizeof(BfdControlHeader);
    bfd->my_discriminator = htonl(session ? session->GetBfdLocalDisc() : 0x10000001);
    bfd->your_discriminator = htonl(session ? session->GetBfdRemoteDisc() : 0);
    bfd->min_tx_interval_us = htonl(negotiated_tx_us_);
    bfd->min_rx_interval_us = htonl(negotiated_rx_us_);
    bfd->min_echo_rx_interval = 0;

    return packet;
}

std::vector<uint8_t> BfdEngine::build_bfd_control_packet(
    const BfdSessionConfig& cfg, 
    BfdState state, 
    BfdDiag diag, 
    uint32_t remote_disc, 
    bool poll, 
    bool final_flag) {

    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(BfdControlHeader);
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    ParseMac(cfg.remote_mac, eth->dst_mac);
    ParseMac(cfg.local_mac, eth->src_mac);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->tos = 0xC0; // CS6 / Network Control DSCP (RFC 5881)
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(BfdControlHeader)));
    ip->id = htons(0xBFD1);
    ip->flags_fragment = 0;
    ip->ttl = 255; // Strict TTL 255 required by RFC 5881
    ip->protocol = 17; // UDP
    inet_pton(AF_INET, cfg.local_ip.c_str(), &ip->src_ip);
    inet_pton(AF_INET, cfg.remote_ip.c_str(), &ip->dst_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(cfg.udp_src_port);
    udp->dst_port = htons(cfg.udp_dst_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + sizeof(BfdControlHeader)));
    udp->checksum = 0;

    auto* bfd = reinterpret_cast<BfdControlHeader*>(
        packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader));

    uint8_t diag_val = static_cast<uint8_t>(diag) & 0x1F;
    bfd->vers_diag = 0x20 | diag_val;

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

bool BfdEngine::ParseBfdControlPacket(const uint8_t* data, size_t len, 
                                     BfdControlHeader& out_hdr, 
                                     uint32_t& out_remote_disc) {
    size_t min_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(BfdControlHeader);
    if (!data || len < min_len) return false;

    size_t offset = 12;
    uint16_t ethertype = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
    offset += 2;

    // Handle VLAN
    if (ethertype == 0x88A8 && len >= offset + 4) {
        offset += 2;
        ethertype = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        offset += 2;
    }
    if (ethertype == 0x8100 && len >= offset + 4) {
        offset += 2;
        ethertype = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        offset += 2;
    }

    if (ethertype != 0x0800) return false;
    if (len < offset + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(BfdControlHeader)) return false;

    const auto* ip = reinterpret_cast<const Ipv4Header*>(data + offset);
    if ((ip->ihl_version >> 4) != 4 || (ip->ihl_version & 0x0F) < 5 || ip->protocol != 17) return false;

    // RFC 5881 strict TTL 255 check
    if (ip->ttl != 255) return false;

    size_t ip_hdr_len = (ip->ihl_version & 0x0F) * 4;
    if (len < offset + ip_hdr_len + sizeof(UdpHeader) + sizeof(BfdControlHeader)) return false;

    const auto* udp = reinterpret_cast<const UdpHeader*>(data + offset + ip_hdr_len);
    uint16_t dst_port = ntohs(udp->dst_port);
    if (dst_port != BFD_CONTROL_PORT && dst_port != BFD_ECHO_PORT) return false;

    const auto* bfd = reinterpret_cast<const BfdControlHeader*>(
        data + offset + ip_hdr_len + sizeof(UdpHeader));

    uint8_t version = (bfd->vers_diag >> 5) & 0x07;
    if (version != 1) return false;

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

} // namespace ddos_samurai::telecom::bfd
