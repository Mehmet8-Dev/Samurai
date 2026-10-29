#include "dhcp_engine.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <algorithm>

namespace ddos_samurai::telecom::dhcp {

namespace {

#pragma pack(push, 1)
struct EthHeader {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
};

struct Ipv4Header {
    uint8_t  ihl_version; // 0x45
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;    // 17 (UDP)
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct Ipv6Header {
    uint32_t vtc_flow;    // 0x60000000
    uint16_t payload_length;
    uint8_t  next_header; // 17 (UDP)
    uint8_t  hop_limit;
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
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

} // namespace

DhcpEngine::DhcpEngine(SessionManager& session_mgr, HierarchicalTimingWheel* wheel)
    : session_mgr_(session_mgr),
      timing_wheel_(wheel) {}

bool DhcpEngine::Init(const ProtocolConfig& cfg) {
    config_ = cfg;
    return true;
}

void DhcpEngine::Shutdown() {
    // Release all active sessions
    uint32_t cap = session_mgr_.GetCapacity();
    for (uint32_t i = 0; i < cap; ++i) {
        TelcoSessionContext* s = session_mgr_.GetSessionByIndex(i);
        if (s && (s->protocol_id == static_cast<uint8_t>(TelcoProtocolId::DHCPV4) ||
                  s->protocol_id == static_cast<uint8_t>(TelcoProtocolId::DHCPV6))) {
            if (timing_wheel_) {
                timing_wheel_->Cancel(s);
            }
            session_mgr_.ReleaseSession(s);
        }
    }
}

DhcpSubState DhcpEngine::GetSubState(const TelcoSessionContext* session) const noexcept {
    return DhcpFsm::GetState(session);
}

void DhcpEngine::SetSubState(TelcoSessionContext* session, DhcpSubState sub) noexcept {
    DhcpFsm::SetState(session, sub);
}

void DhcpEngine::SetRelayAgentInfo(const std::string& circuit_id, const std::string& remote_id) {
    circuit_id_ = circuit_id;
    remote_id_ = remote_id;
}

void DhcpEngine::StartDhcpv4(TelcoSessionContext* session, uint32_t xid) {
    if (!session) return;

    if (xid == 0) {
        // Generate pseudo-random transaction ID
        xid = static_cast<uint32_t>(session->client_mac[4]) << 24 |
              static_cast<uint32_t>(session->client_mac[5]) << 16 |
              0x1A2B;
        if (xid == 0) xid = 0x5A5A5A5A;
    }

    session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::DHCPV4);
    session->retry_count = 0;
    session->client_port = DHCPV4_CLIENT_PORT;
    session->peer_port = DHCPV4_SERVER_PORT;
    session->ip_proto = 17;

    session_mgr_.BindDhcpSession(session, xid);
    SetSubState(session, DhcpSubState::SELECTING);

    last_tx_frame_ = BuildDhcpv4Discover(session);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    if (timing_wheel_) {
        timing_wheel_->Schedule(session, config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 500);
    }
}

void DhcpEngine::StartDhcpv6(TelcoSessionContext* session, uint32_t xid) {
    if (!session) return;

    if (xid == 0) {
        xid = (static_cast<uint32_t>(session->client_mac[3]) << 16) |
              (static_cast<uint32_t>(session->client_mac[4]) << 8) |
              session->client_mac[5];
        if (xid == 0) xid = 0x123456;
    }

    session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::DHCPV6);
    session->retry_count = 0;
    session->client_port = DHCPV6_CLIENT_PORT;
    session->peer_port = DHCPV6_SERVER_PORT;
    session->ip_proto = 17;

    session_mgr_.BindDhcpSession(session, xid);
    SetSubState(session, DhcpSubState::SELECTING);

    last_tx_frame_ = BuildDhcpv6Solicit(session);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    if (timing_wheel_) {
        timing_wheel_->Schedule(session, config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 500);
    }
}

void DhcpEngine::RenewDhcp(TelcoSessionContext* session) {
    if (!session || GetSubState(session) != DhcpSubState::BOUND) return;

    SetSubState(session, DhcpSubState::RENEWING);
    session->retry_count = 0;

    if (session->protocol_id == static_cast<uint8_t>(TelcoProtocolId::DHCPV4)) {
        last_tx_frame_ = BuildDhcpv4Request(session, session->client_ip, session->peer_ip);
    } else {
        uint8_t ipv6[16] = {0};
        std::memcpy(ipv6, &session->client_ip, 4); // Simulative
        last_tx_frame_ = BuildDhcpv6Request(session, nullptr, 0, ipv6);
    }

    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    if (timing_wheel_) {
        timing_wheel_->Schedule(session, config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 500);
    }
}

void DhcpEngine::ReleaseDhcp(TelcoSessionContext* session) {
    if (!session) return;

    if (timing_wheel_) {
        timing_wheel_->Cancel(session);
    }

    if (session->protocol_id == static_cast<uint8_t>(TelcoProtocolId::DHCPV4)) {
        last_tx_frame_ = BuildDhcpv4Release(session);
    } else {
        last_tx_frame_ = BuildDhcpv6Release(session, nullptr, 0);
    }

    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    SetSubState(session, DhcpSubState::RELEASED);
    session_mgr_.UnbindDhcpSession(session);
}

void DhcpEngine::HandleTimeout(TelcoSessionContext* session) {
    if (!session) return;

    DhcpSubState state = GetSubState(session);

    if (state == DhcpSubState::BOUND) {
        // T1 Renewal time arrived!
        RenewDhcp(session);
        return;
    }

    if (state == DhcpSubState::SELECTING || state == DhcpSubState::REQUESTING ||
        state == DhcpSubState::RENEWING || state == DhcpSubState::REBINDING) {
        session->retry_count++;
        if (session->retry_count >= config_.max_retries) {
            SetSubState(session, DhcpSubState::FAILED);
            if (timing_wheel_) {
                timing_wheel_->Cancel(session);
            }
            return;
        }

        // Retransmit current message
        if (session->protocol_id == static_cast<uint8_t>(TelcoProtocolId::DHCPV4)) {
            if (state == DhcpSubState::SELECTING) {
                last_tx_frame_ = BuildDhcpv4Discover(session);
            } else {
                last_tx_frame_ = BuildDhcpv4Request(session, session->client_ip, session->peer_ip);
            }
        } else {
            if (state == DhcpSubState::SELECTING) {
                last_tx_frame_ = BuildDhcpv6Solicit(session);
            } else {
                uint8_t ipv6[16] = {0};
                last_tx_frame_ = BuildDhcpv6Request(session, nullptr, 0, ipv6);
            }
        }
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();

        // Exponential backoff
        uint32_t delay_ms = (config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 500) * (1 << session->retry_count);
        if (timing_wheel_) {
            timing_wheel_->Schedule(session, delay_ms);
        }
    }
}

uint32_t DhcpEngine::OnTimerTick(uint64_t current_tsc) {
    if (!timing_wheel_) return 0;
    return timing_wheel_->Advance(current_tsc, [this](TelcoSessionContext* s) {
        HandleTimeout(s);
    });
}

void DhcpEngine::OnRxPacket(rte_mbuf* /*mbuf*/, const PacketMetadata& meta, TelcoSessionContext* session) {
    if (meta.raw_frame && meta.raw_len >= 14) {
        ProcessRxFrame(meta.raw_frame, meta.raw_len, session);
    } else if (meta.payload_ptr && meta.payload_len > 0) {
        ProcessRxFrame(meta.payload_ptr, meta.payload_len, session);
    }
}

rte_mbuf* DhcpEngine::BuildTxPacket(rte_mempool* /*pool*/, TelcoSessionContext* /*session*/, uint16_t /*event_type*/) {
    return nullptr;
}

// ---------------------------------------------------------------------------
// Gelen Paket Ayrıştırma ve Durum Makinesi
// ---------------------------------------------------------------------------

bool DhcpEngine::ProcessRxFrame(const uint8_t* frame, size_t len, TelcoSessionContext* session) {
    if (!frame || len < 14) return false;

    size_t offset = 12;
    uint16_t ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
    offset += 2;

    // VLAN Headers
    if (ethertype == 0x88A8 && len >= offset + 4) {
        offset += 2;
        ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
        offset += 2;
    }
    if (ethertype == 0x8100 && len >= offset + 4) {
        offset += 2;
        ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
        offset += 2;
    }

    if (ethertype == 0x0800 && len >= offset + sizeof(Ipv4Header) + sizeof(UdpHeader)) {
        const auto* ip = reinterpret_cast<const Ipv4Header*>(frame + offset);
        if ((ip->ihl_version >> 4) != 4 || (ip->ihl_version & 0x0F) < 5) return false;
        uint8_t ihl = (ip->ihl_version & 0x0F) * 4;
        if (len < offset + ihl + sizeof(UdpHeader)) return false;

        if (ip->protocol == 17) { // UDP
            const auto* udp = reinterpret_cast<const UdpHeader*>(frame + offset + ihl);
            uint16_t src_port = ntohs(udp->src_port);
            uint16_t dst_port = ntohs(udp->dst_port);

            if ((src_port == DHCPV4_SERVER_PORT && dst_port == DHCPV4_CLIENT_PORT) ||
                (src_port == DHCPV4_CLIENT_PORT && dst_port == DHCPV4_SERVER_PORT)) {
                size_t dhcp_offset = offset + ihl + sizeof(UdpHeader);
                HandleDhcpv4Message(frame, dhcp_offset, len, session);
                return true;
            }
        }
    } else if (ethertype == 0x86DD && len >= offset + sizeof(Ipv6Header) + sizeof(UdpHeader)) {
        const auto* ip6 = reinterpret_cast<const Ipv6Header*>(frame + offset);
        if (ip6->next_header == 17) {
            const auto* udp = reinterpret_cast<const UdpHeader*>(frame + offset + sizeof(Ipv6Header));
            uint16_t src_port = ntohs(udp->src_port);
            uint16_t dst_port = ntohs(udp->dst_port);

            if ((src_port == DHCPV6_SERVER_PORT && dst_port == DHCPV6_CLIENT_PORT) ||
                (src_port == DHCPV6_CLIENT_PORT && dst_port == DHCPV6_SERVER_PORT)) {
                size_t dhcp6_offset = offset + sizeof(Ipv6Header) + sizeof(UdpHeader);
                HandleDhcpv6Message(frame, dhcp6_offset, len, session);
                return true;
            }
        }
    }

    return false;
}

void DhcpEngine::HandleDhcpv4Message(const uint8_t* frame, size_t offset, size_t len, TelcoSessionContext* session) {
    if (len < offset + sizeof(Dhcpv4Header)) return;

    const auto* dhcp = reinterpret_cast<const Dhcpv4Header*>(frame + offset);
    if (ntohl(dhcp->magic_cookie) != DHCPV4_MAGIC_COOKIE) return;

    uint32_t xid = ntohl(dhcp->xid);
    if (!session) {
        session = session_mgr_.FindDhcpSession(xid);
        if (!session) return;
    }

    session->rx_packets++;
    session->rx_bytes += (len - offset);

    // Options parsing
    const uint8_t* opts = frame + offset + sizeof(Dhcpv4Header);
    size_t opt_len = len - (offset + sizeof(Dhcpv4Header));

    uint8_t msg_type = 0;
    uint32_t server_id = 0;
    uint32_t lease_time = 3600;
    std::string circuit_id = "";
    std::string remote_id = "";

    size_t i = 0;
    while (i < opt_len) {
        uint8_t code = opts[i];
        if (code == static_cast<uint8_t>(Dhcpv4Option::END)) break;
        if (code == static_cast<uint8_t>(Dhcpv4Option::PAD)) { i++; continue; }
        if (i + 1 >= opt_len) break;

        uint8_t l = opts[i + 1];
        if (i + 2 + l > opt_len) break;

        if (code == static_cast<uint8_t>(Dhcpv4Option::MSG_TYPE) && l >= 1) {
            msg_type = opts[i + 2];
        } else if (code == static_cast<uint8_t>(Dhcpv4Option::SERVER_IDENTIFIER) && l >= 4) {
            std::memcpy(&server_id, opts + i + 2, 4);
        } else if (code == static_cast<uint8_t>(Dhcpv4Option::LEASE_TIME) && l >= 4) {
            uint32_t raw_lease = 0;
            std::memcpy(&raw_lease, opts + i + 2, 4);
            lease_time = ntohl(raw_lease);
        } else if (code == static_cast<uint8_t>(Dhcpv4Option::RELAY_AGENT_INFO)) {
            // Option 82 Sub-options parsing
            size_t sub_idx = 0;
            const uint8_t* sub_ptr = opts + i + 2;
            while (sub_idx + 1 < l) {
                uint8_t sub_code = sub_ptr[sub_idx];
                uint8_t sub_len = sub_ptr[sub_idx + 1];
                if (sub_idx + 2 + sub_len > l) break;
                if (sub_code == static_cast<uint8_t>(Dhcpv4RelaySubOption::CIRCUIT_ID)) {
                    circuit_id.assign(reinterpret_cast<const char*>(sub_ptr + sub_idx + 2), sub_len);
                } else if (sub_code == static_cast<uint8_t>(Dhcpv4RelaySubOption::REMOTE_ID)) {
                    remote_id.assign(reinterpret_cast<const char*>(sub_ptr + sub_idx + 2), sub_len);
                }
                sub_idx += 2 + sub_len;
            }
        }
        i += 2 + l;
    }

    DhcpSubState current_st = GetSubState(session);

    if (msg_type == static_cast<uint8_t>(Dhcpv4MsgType::OFFER)) {
        if (current_st == DhcpSubState::SELECTING) {
            session->client_ip = ntohl(dhcp->yiaddr);
            session->peer_ip = ntohl(server_id != 0 ? server_id : dhcp->siaddr);
            session->retry_count = 0;

            SetSubState(session, DhcpSubState::REQUESTING);
            last_tx_frame_ = BuildDhcpv4Request(session, session->client_ip, session->peer_ip);
            session->tx_packets++;
            session->tx_bytes += last_tx_frame_.size();

            if (timing_wheel_) {
                timing_wheel_->Schedule(session, config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 500);
            }
        }
    } else if (msg_type == static_cast<uint8_t>(Dhcpv4MsgType::ACK)) {
        if (current_st == DhcpSubState::REQUESTING || current_st == DhcpSubState::RENEWING || current_st == DhcpSubState::REBINDING) {
            session->client_ip = ntohl(dhcp->yiaddr);
            if (server_id != 0) {
                session->peer_ip = ntohl(server_id);
            }
            session->retry_count = 0;
            SetSubState(session, DhcpSubState::BOUND);

            if (timing_wheel_) {
                timing_wheel_->Cancel(session);
                // Schedule T1 renewal timer (0.5 * lease_time) with 64-bit overflow guard
                uint64_t t1_ms_64 = (static_cast<uint64_t>(lease_time) / 2) * 1000ULL;
                if (t1_ms_64 > 0xFFFFFFFFULL) t1_ms_64 = 0xFFFFFFFFULL;
                uint32_t t1_ms = static_cast<uint32_t>(t1_ms_64);
                if (t1_ms == 0) t1_ms = 1000;
                timing_wheel_->Schedule(session, t1_ms);
            }
        }
    } else if (msg_type == static_cast<uint8_t>(Dhcpv4MsgType::NAK)) {
        SetSubState(session, DhcpSubState::FAILED);
        if (timing_wheel_) {
            timing_wheel_->Cancel(session);
        }
    }
}

void DhcpEngine::HandleDhcpv6Message(const uint8_t* frame, size_t offset, size_t len, TelcoSessionContext* session) {
    if (len < offset + sizeof(Dhcpv6Header)) return;

    const auto* dhcp6 = reinterpret_cast<const Dhcpv6Header*>(frame + offset);
    uint32_t xid = (static_cast<uint32_t>(dhcp6->transaction_id[0]) << 16) |
                   (static_cast<uint32_t>(dhcp6->transaction_id[1]) << 8) |
                   dhcp6->transaction_id[2];

    if (!session) {
        session = session_mgr_.FindDhcpSession(xid);
        if (!session) return;
    }

    session->rx_packets++;
    session->rx_bytes += (len - offset);

    uint8_t msg_type = dhcp6->msg_type;
    DhcpSubState current_st = GetSubState(session);

    // Parse options
    const uint8_t* opts = frame + offset + sizeof(Dhcpv6Header);
    size_t opt_len = len - (offset + sizeof(Dhcpv6Header));

    const uint8_t* server_duid = nullptr;
    size_t server_duid_len = 0;
    uint8_t assigned_ipv6[16] = {0};
    bool has_ipv6 = false;

    size_t i = 0;
    while (i + 4 <= opt_len) {
        uint16_t code = (static_cast<uint16_t>(opts[i]) << 8) | opts[i + 1];
        uint16_t l = (static_cast<uint16_t>(opts[i + 2]) << 8) | opts[i + 3];
        if (i + 4 + l > opt_len) break;

        if (code == static_cast<uint16_t>(Dhcpv6Option::SERVERID)) {
            server_duid = opts + i + 4;
            server_duid_len = l;
        } else if (code == static_cast<uint16_t>(Dhcpv6Option::IA_NA) && l >= sizeof(Dhcpv6IaNaHeader)) {
            // Nested IA_ADDR option
            size_t sub_i = sizeof(Dhcpv6IaNaHeader);
            const uint8_t* ia_opts = opts + i + 4;
            while (sub_i + 4 <= l) {
                uint16_t sub_code = (static_cast<uint16_t>(ia_opts[sub_i]) << 8) | ia_opts[sub_i + 1];
                uint16_t sub_l = (static_cast<uint16_t>(ia_opts[sub_i + 2]) << 8) | ia_opts[sub_i + 3];
                if (sub_i + 4 + sub_l > l) break;
                if (sub_code == static_cast<uint16_t>(Dhcpv6Option::IA_ADDR) && sub_l >= sizeof(Dhcpv6IaAddrHeader)) {
                    std::memcpy(assigned_ipv6, ia_opts + sub_i + 4, 16);
                    has_ipv6 = true;
                }
                sub_i += 4 + sub_l;
            }
        }
        i += 4 + l;
    }

    if (msg_type == static_cast<uint8_t>(Dhcpv6MsgType::ADVERTISE)) {
        if (current_st == DhcpSubState::SELECTING) {
            SetSubState(session, DhcpSubState::REQUESTING);
            session->retry_count = 0;
            if (has_ipv6) {
                std::memcpy(&session->client_ip, assigned_ipv6 + 12, 4);
            }
            last_tx_frame_ = BuildDhcpv6Request(session, server_duid, server_duid_len, assigned_ipv6);
            session->tx_packets++;
            session->tx_bytes += last_tx_frame_.size();

            if (timing_wheel_) {
                timing_wheel_->Schedule(session, config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 500);
            }
        }
    } else if (msg_type == static_cast<uint8_t>(Dhcpv6MsgType::REPLY)) {
        if (current_st == DhcpSubState::REQUESTING || current_st == DhcpSubState::RENEWING) {
            SetSubState(session, DhcpSubState::BOUND);
            session->retry_count = 0;
            if (has_ipv6) {
                std::memcpy(&session->client_ip, assigned_ipv6 + 12, 4);
            }
            if (timing_wheel_) {
                timing_wheel_->Cancel(session);
                // Schedule T1 renewal (e.g. 1800s)
                timing_wheel_->Schedule(session, 1800000);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DHCPv4 Çerçeve Oluşturucuları
// ---------------------------------------------------------------------------

std::vector<uint8_t> DhcpEngine::BuildDhcpv4Discover(TelcoSessionContext* session) {
    std::vector<uint8_t> frame;
    frame.reserve(350);

    // Eth
    for (int i = 0; i < 6; ++i) frame.push_back(0xFF);
    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);
    frame.push_back(0x08); frame.push_back(0x00);

    size_t ip_start = frame.size();
    Ipv4Header ip{};
    ip.ihl_version = 0x45;
    ip.ttl = 64;
    ip.protocol = 17;
    ip.src_ip = 0; // 0.0.0.0
    ip.dst_ip = 0xFFFFFFFF; // 255.255.255.255
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&ip), reinterpret_cast<const uint8_t*>(&ip) + sizeof(Ipv4Header));

    size_t udp_start = frame.size();
    UdpHeader udp{};
    udp.src_port = htons(DHCPV4_CLIENT_PORT);
    udp.dst_port = htons(DHCPV4_SERVER_PORT);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&udp), reinterpret_cast<const uint8_t*>(&udp) + sizeof(UdpHeader));

    // Dhcpv4 Header
    Dhcpv4Header dhcp{};
    dhcp.op = static_cast<uint8_t>(Dhcpv4Op::BOOTREQUEST);
    dhcp.htype = DHCPV4_HTYPE_ETHERNET;
    dhcp.hlen = DHCPV4_HLEN_ETHERNET;
    dhcp.xid = htonl(session ? session->GetDhcpXid() : 0x12345678);
    dhcp.flags = htons(0x8000); // Broadcast flag
    if (session) std::memcpy(dhcp.chaddr, session->client_mac, 6);
    dhcp.magic_cookie = htonl(DHCPV4_MAGIC_COOKIE);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&dhcp), reinterpret_cast<const uint8_t*>(&dhcp) + sizeof(Dhcpv4Header));

    // Options: 53 (Discover), 55 (Param Req List)
    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::MSG_TYPE)); frame.push_back(1);
    frame.push_back(static_cast<uint8_t>(Dhcpv4MsgType::DISCOVER));

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::PARAM_REQ_LIST)); frame.push_back(4);
    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::SUBNET_MASK));
    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::ROUTER));
    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::DNS_SERVERS));
    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::DOMAIN_NAME));

    // Option 82 Relay Agent Info if configured
    if (!circuit_id_.empty() || !remote_id_.empty()) {
        size_t total_sub = (circuit_id_.empty() ? 0 : 2 + circuit_id_.size()) +
                           (remote_id_.empty() ? 0 : 2 + remote_id_.size());
        frame.push_back(static_cast<uint8_t>(Dhcpv4Option::RELAY_AGENT_INFO));
        frame.push_back(static_cast<uint8_t>(total_sub));
        if (!circuit_id_.empty()) {
            frame.push_back(static_cast<uint8_t>(Dhcpv4RelaySubOption::CIRCUIT_ID));
            frame.push_back(static_cast<uint8_t>(circuit_id_.size()));
            for (char c : circuit_id_) frame.push_back(static_cast<uint8_t>(c));
        }
        if (!remote_id_.empty()) {
            frame.push_back(static_cast<uint8_t>(Dhcpv4RelaySubOption::REMOTE_ID));
            frame.push_back(static_cast<uint8_t>(remote_id_.size()));
            for (char c : remote_id_) frame.push_back(static_cast<uint8_t>(c));
        }
    }

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::END));
    while (frame.size() < 300) frame.push_back(0); // Minimum length padding

    // Update lengths & checksum
    uint16_t total_ip_len = static_cast<uint16_t>(frame.size() - ip_start);
    uint16_t udp_len = static_cast<uint16_t>(frame.size() - udp_start);

    auto* ip_ptr = reinterpret_cast<Ipv4Header*>(frame.data() + ip_start);
    ip_ptr->total_length = htons(total_ip_len);
    ip_ptr->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip_ptr), sizeof(Ipv4Header));

    auto* udp_ptr = reinterpret_cast<UdpHeader*>(frame.data() + udp_start);
    udp_ptr->length = htons(udp_len);

    return frame;
}

std::vector<uint8_t> DhcpEngine::BuildDhcpv4Request(TelcoSessionContext* session, uint32_t req_ip, uint32_t server_ip) {
    std::vector<uint8_t> frame;
    frame.reserve(350);

    for (int i = 0; i < 6; ++i) frame.push_back(0xFF);
    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);
    frame.push_back(0x08); frame.push_back(0x00);

    size_t ip_start = frame.size();
    Ipv4Header ip{};
    ip.ihl_version = 0x45;
    ip.ttl = 64;
    ip.protocol = 17;
    ip.src_ip = 0;
    ip.dst_ip = 0xFFFFFFFF;
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&ip), reinterpret_cast<const uint8_t*>(&ip) + sizeof(Ipv4Header));

    size_t udp_start = frame.size();
    UdpHeader udp{};
    udp.src_port = htons(DHCPV4_CLIENT_PORT);
    udp.dst_port = htons(DHCPV4_SERVER_PORT);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&udp), reinterpret_cast<const uint8_t*>(&udp) + sizeof(UdpHeader));

    Dhcpv4Header dhcp{};
    dhcp.op = static_cast<uint8_t>(Dhcpv4Op::BOOTREQUEST);
    dhcp.htype = DHCPV4_HTYPE_ETHERNET;
    dhcp.hlen = DHCPV4_HLEN_ETHERNET;
    dhcp.xid = htonl(session ? session->GetDhcpXid() : 0x12345678);
    dhcp.flags = htons(0x8000);
    if (session) std::memcpy(dhcp.chaddr, session->client_mac, 6);
    dhcp.magic_cookie = htonl(DHCPV4_MAGIC_COOKIE);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&dhcp), reinterpret_cast<const uint8_t*>(&dhcp) + sizeof(Dhcpv4Header));

    // Options: 53 (Request), 50 (Requested IP), 54 (Server Identifier)
    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::MSG_TYPE)); frame.push_back(1);
    frame.push_back(static_cast<uint8_t>(Dhcpv4MsgType::REQUEST));

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::REQUESTED_IP)); frame.push_back(4);
    uint32_t req_be = htonl(req_ip);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&req_be), reinterpret_cast<const uint8_t*>(&req_be) + 4);

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::SERVER_IDENTIFIER)); frame.push_back(4);
    uint32_t srv_be = htonl(server_ip);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&srv_be), reinterpret_cast<const uint8_t*>(&srv_be) + 4);

    // Option 82 if present
    if (!circuit_id_.empty() || !remote_id_.empty()) {
        size_t total_sub = (circuit_id_.empty() ? 0 : 2 + circuit_id_.size()) +
                           (remote_id_.empty() ? 0 : 2 + remote_id_.size());
        frame.push_back(static_cast<uint8_t>(Dhcpv4Option::RELAY_AGENT_INFO));
        frame.push_back(static_cast<uint8_t>(total_sub));
        if (!circuit_id_.empty()) {
            frame.push_back(static_cast<uint8_t>(Dhcpv4RelaySubOption::CIRCUIT_ID));
            frame.push_back(static_cast<uint8_t>(circuit_id_.size()));
            for (char c : circuit_id_) frame.push_back(static_cast<uint8_t>(c));
        }
        if (!remote_id_.empty()) {
            frame.push_back(static_cast<uint8_t>(Dhcpv4RelaySubOption::REMOTE_ID));
            frame.push_back(static_cast<uint8_t>(remote_id_.size()));
            for (char c : remote_id_) frame.push_back(static_cast<uint8_t>(c));
        }
    }

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::END));
    while (frame.size() < 300) frame.push_back(0);

    uint16_t total_ip_len = static_cast<uint16_t>(frame.size() - ip_start);
    uint16_t udp_len = static_cast<uint16_t>(frame.size() - udp_start);

    auto* ip_ptr = reinterpret_cast<Ipv4Header*>(frame.data() + ip_start);
    ip_ptr->total_length = htons(total_ip_len);
    ip_ptr->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip_ptr), sizeof(Ipv4Header));

    auto* udp_ptr = reinterpret_cast<UdpHeader*>(frame.data() + udp_start);
    udp_ptr->length = htons(udp_len);

    return frame;
}

std::vector<uint8_t> DhcpEngine::BuildDhcpv4Release(TelcoSessionContext* session) {
    std::vector<uint8_t> frame;
    frame.reserve(350);

    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->peer_mac[i] : 0xFF);
    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);
    frame.push_back(0x08); frame.push_back(0x00);

    size_t ip_start = frame.size();
    Ipv4Header ip{};
    ip.ihl_version = 0x45;
    ip.ttl = 64;
    ip.protocol = 17;
    ip.src_ip = htonl(session ? session->client_ip : 0);
    ip.dst_ip = htonl(session ? session->peer_ip : 0xFFFFFFFF);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&ip), reinterpret_cast<const uint8_t*>(&ip) + sizeof(Ipv4Header));

    size_t udp_start = frame.size();
    UdpHeader udp{};
    udp.src_port = htons(DHCPV4_CLIENT_PORT);
    udp.dst_port = htons(DHCPV4_SERVER_PORT);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&udp), reinterpret_cast<const uint8_t*>(&udp) + sizeof(UdpHeader));

    Dhcpv4Header dhcp{};
    dhcp.op = static_cast<uint8_t>(Dhcpv4Op::BOOTREQUEST);
    dhcp.htype = DHCPV4_HTYPE_ETHERNET;
    dhcp.hlen = DHCPV4_HLEN_ETHERNET;
    dhcp.xid = htonl(session ? session->GetDhcpXid() : 0x12345678);
    dhcp.ciaddr = htonl(session ? session->client_ip : 0);
    if (session) std::memcpy(dhcp.chaddr, session->client_mac, 6);
    dhcp.magic_cookie = htonl(DHCPV4_MAGIC_COOKIE);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&dhcp), reinterpret_cast<const uint8_t*>(&dhcp) + sizeof(Dhcpv4Header));

    // Options: 53 (Release), 54 (Server ID)
    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::MSG_TYPE)); frame.push_back(1);
    frame.push_back(static_cast<uint8_t>(Dhcpv4MsgType::RELEASE));

    if (session && session->peer_ip != 0) {
        frame.push_back(static_cast<uint8_t>(Dhcpv4Option::SERVER_IDENTIFIER)); frame.push_back(4);
        uint32_t srv_be = htonl(session->peer_ip);
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&srv_be), reinterpret_cast<const uint8_t*>(&srv_be) + 4);
    }

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::END));
    while (frame.size() < 300) frame.push_back(0);

    uint16_t total_ip_len = static_cast<uint16_t>(frame.size() - ip_start);
    uint16_t udp_len = static_cast<uint16_t>(frame.size() - udp_start);

    auto* ip_ptr = reinterpret_cast<Ipv4Header*>(frame.data() + ip_start);
    ip_ptr->total_length = htons(total_ip_len);
    ip_ptr->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip_ptr), sizeof(Ipv4Header));

    auto* udp_ptr = reinterpret_cast<UdpHeader*>(frame.data() + udp_start);
    udp_ptr->length = htons(udp_len);

    return frame;
}

std::vector<uint8_t> DhcpEngine::BuildDhcpv4Inform(TelcoSessionContext* session) {
    std::vector<uint8_t> frame;
    frame.reserve(350);

    for (int i = 0; i < 6; ++i) frame.push_back(0xFF);
    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);
    frame.push_back(0x08); frame.push_back(0x00);

    size_t ip_start = frame.size();
    Ipv4Header ip{};
    ip.ihl_version = 0x45;
    ip.ttl = 64;
    ip.protocol = 17;
    ip.src_ip = htonl(session ? session->client_ip : 0);
    ip.dst_ip = 0xFFFFFFFF;
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&ip), reinterpret_cast<const uint8_t*>(&ip) + sizeof(Ipv4Header));

    size_t udp_start = frame.size();
    UdpHeader udp{};
    udp.src_port = htons(DHCPV4_CLIENT_PORT);
    udp.dst_port = htons(DHCPV4_SERVER_PORT);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&udp), reinterpret_cast<const uint8_t*>(&udp) + sizeof(UdpHeader));

    Dhcpv4Header dhcp{};
    dhcp.op = static_cast<uint8_t>(Dhcpv4Op::BOOTREQUEST);
    dhcp.htype = DHCPV4_HTYPE_ETHERNET;
    dhcp.hlen = DHCPV4_HLEN_ETHERNET;
    dhcp.xid = htonl(session ? session->GetDhcpXid() : 0x12345678);
    dhcp.ciaddr = htonl(session ? session->client_ip : 0);
    if (session) std::memcpy(dhcp.chaddr, session->client_mac, 6);
    dhcp.magic_cookie = htonl(DHCPV4_MAGIC_COOKIE);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&dhcp), reinterpret_cast<const uint8_t*>(&dhcp) + sizeof(Dhcpv4Header));

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::MSG_TYPE)); frame.push_back(1);
    frame.push_back(static_cast<uint8_t>(Dhcpv4MsgType::INFORM));
    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::END));
    while (frame.size() < 300) frame.push_back(0);

    uint16_t total_ip_len = static_cast<uint16_t>(frame.size() - ip_start);
    uint16_t udp_len = static_cast<uint16_t>(frame.size() - udp_start);

    auto* ip_ptr = reinterpret_cast<Ipv4Header*>(frame.data() + ip_start);
    ip_ptr->total_length = htons(total_ip_len);
    ip_ptr->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip_ptr), sizeof(Ipv4Header));

    auto* udp_ptr = reinterpret_cast<UdpHeader*>(frame.data() + udp_start);
    udp_ptr->length = htons(udp_len);

    return frame;
}

// ---------------------------------------------------------------------------
// DHCPv4 Server Simülatörleri (Testler İçin)
// ---------------------------------------------------------------------------

std::vector<uint8_t> DhcpEngine::BuildDhcpv4Offer(TelcoSessionContext* session, uint32_t offered_ip, uint32_t server_ip,
                                                  uint32_t lease_time, const std::string& circuit_id, const std::string& remote_id) {
    std::vector<uint8_t> frame;
    frame.reserve(350);

    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0xFF);
    for (int i = 0; i < 6; ++i) frame.push_back(0x52); // Server MAC
    frame.push_back(0x08); frame.push_back(0x00);

    size_t ip_start = frame.size();
    Ipv4Header ip{};
    ip.ihl_version = 0x45;
    ip.ttl = 64;
    ip.protocol = 17;
    ip.src_ip = htonl(server_ip);
    ip.dst_ip = 0xFFFFFFFF; // Broadcast
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&ip), reinterpret_cast<const uint8_t*>(&ip) + sizeof(Ipv4Header));

    size_t udp_start = frame.size();
    UdpHeader udp{};
    udp.src_port = htons(DHCPV4_SERVER_PORT);
    udp.dst_port = htons(DHCPV4_CLIENT_PORT);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&udp), reinterpret_cast<const uint8_t*>(&udp) + sizeof(UdpHeader));

    Dhcpv4Header dhcp{};
    dhcp.op = static_cast<uint8_t>(Dhcpv4Op::BOOTREPLY);
    dhcp.htype = DHCPV4_HTYPE_ETHERNET;
    dhcp.hlen = DHCPV4_HLEN_ETHERNET;
    dhcp.xid = htonl(session ? session->GetDhcpXid() : 0x12345678);
    dhcp.yiaddr = htonl(offered_ip);
    dhcp.siaddr = htonl(server_ip);
    if (session) std::memcpy(dhcp.chaddr, session->client_mac, 6);
    dhcp.magic_cookie = htonl(DHCPV4_MAGIC_COOKIE);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&dhcp), reinterpret_cast<const uint8_t*>(&dhcp) + sizeof(Dhcpv4Header));

    // Options: 53 (Offer), 54 (Server ID), 51 (Lease Time), 1 (Subnet), 3 (Router)
    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::MSG_TYPE)); frame.push_back(1);
    frame.push_back(static_cast<uint8_t>(Dhcpv4MsgType::OFFER));

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::SERVER_IDENTIFIER)); frame.push_back(4);
    uint32_t srv_be = htonl(server_ip);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&srv_be), reinterpret_cast<const uint8_t*>(&srv_be) + 4);

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::LEASE_TIME)); frame.push_back(4);
    uint32_t lease_be = htonl(lease_time);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&lease_be), reinterpret_cast<const uint8_t*>(&lease_be) + 4);

    // Option 82 Relay Agent Information echo if provided
    if (!circuit_id.empty() || !remote_id.empty()) {
        size_t total_sub = (circuit_id.empty() ? 0 : 2 + circuit_id.size()) +
                           (remote_id.empty() ? 0 : 2 + remote_id.size());
        frame.push_back(static_cast<uint8_t>(Dhcpv4Option::RELAY_AGENT_INFO));
        frame.push_back(static_cast<uint8_t>(total_sub));
        if (!circuit_id.empty()) {
            frame.push_back(static_cast<uint8_t>(Dhcpv4RelaySubOption::CIRCUIT_ID));
            frame.push_back(static_cast<uint8_t>(circuit_id.size()));
            for (char c : circuit_id) frame.push_back(static_cast<uint8_t>(c));
        }
        if (!remote_id.empty()) {
            frame.push_back(static_cast<uint8_t>(Dhcpv4RelaySubOption::REMOTE_ID));
            frame.push_back(static_cast<uint8_t>(remote_id.size()));
            for (char c : remote_id) frame.push_back(static_cast<uint8_t>(c));
        }
    }

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::END));
    while (frame.size() < 300) frame.push_back(0);

    uint16_t total_ip_len = static_cast<uint16_t>(frame.size() - ip_start);
    uint16_t udp_len = static_cast<uint16_t>(frame.size() - udp_start);

    auto* ip_ptr = reinterpret_cast<Ipv4Header*>(frame.data() + ip_start);
    ip_ptr->total_length = htons(total_ip_len);
    ip_ptr->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip_ptr), sizeof(Ipv4Header));

    auto* udp_ptr = reinterpret_cast<UdpHeader*>(frame.data() + udp_start);
    udp_ptr->length = htons(udp_len);

    return frame;
}

std::vector<uint8_t> DhcpEngine::BuildDhcpv4Ack(TelcoSessionContext* session, uint32_t acked_ip, uint32_t server_ip, uint32_t lease_time) {
    std::vector<uint8_t> frame;
    frame.reserve(350);

    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0xFF);
    for (int i = 0; i < 6; ++i) frame.push_back(0x52);
    frame.push_back(0x08); frame.push_back(0x00);

    size_t ip_start = frame.size();
    Ipv4Header ip{};
    ip.ihl_version = 0x45;
    ip.ttl = 64;
    ip.protocol = 17;
    ip.src_ip = htonl(server_ip);
    ip.dst_ip = 0xFFFFFFFF;
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&ip), reinterpret_cast<const uint8_t*>(&ip) + sizeof(Ipv4Header));

    size_t udp_start = frame.size();
    UdpHeader udp{};
    udp.src_port = htons(DHCPV4_SERVER_PORT);
    udp.dst_port = htons(DHCPV4_CLIENT_PORT);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&udp), reinterpret_cast<const uint8_t*>(&udp) + sizeof(UdpHeader));

    Dhcpv4Header dhcp{};
    dhcp.op = static_cast<uint8_t>(Dhcpv4Op::BOOTREPLY);
    dhcp.htype = DHCPV4_HTYPE_ETHERNET;
    dhcp.hlen = DHCPV4_HLEN_ETHERNET;
    dhcp.xid = htonl(session ? session->GetDhcpXid() : 0x12345678);
    dhcp.yiaddr = htonl(acked_ip);
    dhcp.siaddr = htonl(server_ip);
    if (session) std::memcpy(dhcp.chaddr, session->client_mac, 6);
    dhcp.magic_cookie = htonl(DHCPV4_MAGIC_COOKIE);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&dhcp), reinterpret_cast<const uint8_t*>(&dhcp) + sizeof(Dhcpv4Header));

    // Options: 53 (Ack), 54 (Server ID), 51 (Lease Time)
    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::MSG_TYPE)); frame.push_back(1);
    frame.push_back(static_cast<uint8_t>(Dhcpv4MsgType::ACK));

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::SERVER_IDENTIFIER)); frame.push_back(4);
    uint32_t srv_be = htonl(server_ip);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&srv_be), reinterpret_cast<const uint8_t*>(&srv_be) + 4);

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::LEASE_TIME)); frame.push_back(4);
    uint32_t lease_be = htonl(lease_time);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&lease_be), reinterpret_cast<const uint8_t*>(&lease_be) + 4);

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::END));
    while (frame.size() < 300) frame.push_back(0);

    uint16_t total_ip_len = static_cast<uint16_t>(frame.size() - ip_start);
    uint16_t udp_len = static_cast<uint16_t>(frame.size() - udp_start);

    auto* ip_ptr = reinterpret_cast<Ipv4Header*>(frame.data() + ip_start);
    ip_ptr->total_length = htons(total_ip_len);
    ip_ptr->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip_ptr), sizeof(Ipv4Header));

    auto* udp_ptr = reinterpret_cast<UdpHeader*>(frame.data() + udp_start);
    udp_ptr->length = htons(udp_len);

    return frame;
}

std::vector<uint8_t> DhcpEngine::BuildDhcpv4Nak(TelcoSessionContext* session, uint32_t server_ip) {
    std::vector<uint8_t> frame;
    frame.reserve(300);

    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0xFF);
    for (int i = 0; i < 6; ++i) frame.push_back(0x52);
    frame.push_back(0x08); frame.push_back(0x00);

    size_t ip_start = frame.size();
    Ipv4Header ip{};
    ip.ihl_version = 0x45;
    ip.ttl = 64;
    ip.protocol = 17;
    ip.src_ip = htonl(server_ip);
    ip.dst_ip = 0xFFFFFFFF;
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&ip), reinterpret_cast<const uint8_t*>(&ip) + sizeof(Ipv4Header));

    size_t udp_start = frame.size();
    UdpHeader udp{};
    udp.src_port = htons(DHCPV4_SERVER_PORT);
    udp.dst_port = htons(DHCPV4_CLIENT_PORT);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&udp), reinterpret_cast<const uint8_t*>(&udp) + sizeof(UdpHeader));

    Dhcpv4Header dhcp{};
    dhcp.op = static_cast<uint8_t>(Dhcpv4Op::BOOTREPLY);
    dhcp.htype = DHCPV4_HTYPE_ETHERNET;
    dhcp.hlen = DHCPV4_HLEN_ETHERNET;
    dhcp.xid = htonl(session ? session->GetDhcpXid() : 0x12345678);
    if (session) std::memcpy(dhcp.chaddr, session->client_mac, 6);
    dhcp.magic_cookie = htonl(DHCPV4_MAGIC_COOKIE);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&dhcp), reinterpret_cast<const uint8_t*>(&dhcp) + sizeof(Dhcpv4Header));

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::MSG_TYPE)); frame.push_back(1);
    frame.push_back(static_cast<uint8_t>(Dhcpv4MsgType::NAK));

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::SERVER_IDENTIFIER)); frame.push_back(4);
    uint32_t srv_be = htonl(server_ip);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&srv_be), reinterpret_cast<const uint8_t*>(&srv_be) + 4);

    frame.push_back(static_cast<uint8_t>(Dhcpv4Option::END));
    while (frame.size() < 300) frame.push_back(0);

    uint16_t total_ip_len = static_cast<uint16_t>(frame.size() - ip_start);
    uint16_t udp_len = static_cast<uint16_t>(frame.size() - udp_start);

    auto* ip_ptr = reinterpret_cast<Ipv4Header*>(frame.data() + ip_start);
    ip_ptr->total_length = htons(total_ip_len);
    ip_ptr->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip_ptr), sizeof(Ipv4Header));

    auto* udp_ptr = reinterpret_cast<UdpHeader*>(frame.data() + udp_start);
    udp_ptr->length = htons(udp_len);

    return frame;
}

// ---------------------------------------------------------------------------
// DHCPv6 Çerçeve Oluşturucuları (RFC 8415 SARR)
// ---------------------------------------------------------------------------

std::vector<uint8_t> DhcpEngine::BuildDhcpv6Solicit(TelcoSessionContext* session) {
    std::vector<uint8_t> frame;
    frame.reserve(256);

    // Multicast 33:33:00:01:00:02
    frame.push_back(0x33); frame.push_back(0x33);
    frame.push_back(0x00); frame.push_back(0x01);
    frame.push_back(0x00); frame.push_back(0x02);
    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);
    frame.push_back(0x86); frame.push_back(0xDD); // IPv6

    size_t ip6_start = frame.size();
    Ipv6Header ip6{};
    ip6.vtc_flow = htonl(0x60000000);
    ip6.next_header = 17; // UDP
    ip6.hop_limit = 64;
    // Link-local src fe80::...
    ip6.src_ip[0] = 0xFE; ip6.src_ip[1] = 0x80;
    if (session) {
        ip6.src_ip[8] = session->client_mac[0] ^ 0x02;
        ip6.src_ip[9] = session->client_mac[1];
        ip6.src_ip[10] = session->client_mac[2];
        ip6.src_ip[11] = 0xFF; ip6.src_ip[12] = 0xFE;
        ip6.src_ip[13] = session->client_mac[3];
        ip6.src_ip[14] = session->client_mac[4];
        ip6.src_ip[15] = session->client_mac[5];
    }
    // Dst: ff02::1:2
    ip6.dst_ip[0] = 0xFF; ip6.dst_ip[1] = 0x02;
    ip6.dst_ip[11] = 0x01; ip6.dst_ip[15] = 0x02;
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&ip6), reinterpret_cast<const uint8_t*>(&ip6) + sizeof(Ipv6Header));

    size_t udp_start = frame.size();
    UdpHeader udp{};
    udp.src_port = htons(DHCPV6_CLIENT_PORT);
    udp.dst_port = htons(DHCPV6_SERVER_PORT);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&udp), reinterpret_cast<const uint8_t*>(&udp) + sizeof(UdpHeader));

    // Dhcpv6 Header
    Dhcpv6Header dhcp6{};
    dhcp6.msg_type = static_cast<uint8_t>(Dhcpv6MsgType::SOLICIT);
    uint32_t xid = session ? session->GetDhcpXid() : 0x123456;
    dhcp6.transaction_id[0] = (xid >> 16) & 0xFF;
    dhcp6.transaction_id[1] = (xid >> 8) & 0xFF;
    dhcp6.transaction_id[2] = xid & 0xFF;
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&dhcp6), reinterpret_cast<const uint8_t*>(&dhcp6) + sizeof(Dhcpv6Header));

    // Option 1: Client ID (DUID-LL)
    Dhcpv6OptionHeader opt_cid{};
    opt_cid.code = htons(static_cast<uint16_t>(Dhcpv6Option::CLIENTID));
    opt_cid.length = htons(10); // DUID type (2) + HW type (2) + MAC (6)
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_cid), reinterpret_cast<const uint8_t*>(&opt_cid) + 4);
    frame.push_back(0x00); frame.push_back(0x03); // DUID-LL
    frame.push_back(0x00); frame.push_back(0x01); // Ethernet
    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);

    // Option 3: IA_NA
    Dhcpv6OptionHeader opt_iana{};
    opt_iana.code = htons(static_cast<uint16_t>(Dhcpv6Option::IA_NA));
    opt_iana.length = htons(sizeof(Dhcpv6IaNaHeader));
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_iana), reinterpret_cast<const uint8_t*>(&opt_iana) + 4);
    Dhcpv6IaNaHeader iana{};
    iana.iaid = htonl(1);
    iana.t1 = htonl(3600);
    iana.t2 = htonl(5400);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&iana), reinterpret_cast<const uint8_t*>(&iana) + sizeof(Dhcpv6IaNaHeader));

    // Option 6: ORO
    Dhcpv6OptionHeader opt_oro{};
    opt_oro.code = htons(static_cast<uint16_t>(Dhcpv6Option::ORO));
    opt_oro.length = htons(4);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_oro), reinterpret_cast<const uint8_t*>(&opt_oro) + 4);
    frame.push_back(0x00); frame.push_back(23); // DNS
    frame.push_back(0x00); frame.push_back(24); // Domain list

    // Update lengths
    uint16_t payload_len = static_cast<uint16_t>(frame.size() - udp_start);
    auto* ip6_ptr = reinterpret_cast<Ipv6Header*>(frame.data() + ip6_start);
    ip6_ptr->payload_length = htons(payload_len);

    auto* udp_ptr = reinterpret_cast<UdpHeader*>(frame.data() + udp_start);
    udp_ptr->length = htons(payload_len);

    return frame;
}

std::vector<uint8_t> DhcpEngine::BuildDhcpv6Request(TelcoSessionContext* session, const uint8_t* server_duid, size_t server_duid_len, const uint8_t ipv6_addr[16]) {
    std::vector<uint8_t> frame;
    frame.reserve(300);

    frame.push_back(0x33); frame.push_back(0x33);
    frame.push_back(0x00); frame.push_back(0x01);
    frame.push_back(0x00); frame.push_back(0x02);
    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);
    frame.push_back(0x86); frame.push_back(0xDD);

    size_t ip6_start = frame.size();
    Ipv6Header ip6{};
    ip6.vtc_flow = htonl(0x60000000);
    ip6.next_header = 17;
    ip6.hop_limit = 64;
    ip6.src_ip[0] = 0xFE; ip6.src_ip[1] = 0x80;
    if (session) {
        ip6.src_ip[8] = session->client_mac[0] ^ 0x02;
        ip6.src_ip[9] = session->client_mac[1];
        ip6.src_ip[10] = session->client_mac[2];
        ip6.src_ip[11] = 0xFF; ip6.src_ip[12] = 0xFE;
        ip6.src_ip[13] = session->client_mac[3];
        ip6.src_ip[14] = session->client_mac[4];
        ip6.src_ip[15] = session->client_mac[5];
    }
    ip6.dst_ip[0] = 0xFF; ip6.dst_ip[1] = 0x02;
    ip6.dst_ip[11] = 0x01; ip6.dst_ip[15] = 0x02;
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&ip6), reinterpret_cast<const uint8_t*>(&ip6) + sizeof(Ipv6Header));

    size_t udp_start = frame.size();
    UdpHeader udp{};
    udp.src_port = htons(DHCPV6_CLIENT_PORT);
    udp.dst_port = htons(DHCPV6_SERVER_PORT);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&udp), reinterpret_cast<const uint8_t*>(&udp) + sizeof(UdpHeader));

    Dhcpv6Header dhcp6{};
    dhcp6.msg_type = static_cast<uint8_t>(Dhcpv6MsgType::REQUEST);
    uint32_t xid = session ? session->GetDhcpXid() : 0x123456;
    dhcp6.transaction_id[0] = (xid >> 16) & 0xFF;
    dhcp6.transaction_id[1] = (xid >> 8) & 0xFF;
    dhcp6.transaction_id[2] = xid & 0xFF;
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&dhcp6), reinterpret_cast<const uint8_t*>(&dhcp6) + sizeof(Dhcpv6Header));

    // Client ID
    Dhcpv6OptionHeader opt_cid{};
    opt_cid.code = htons(static_cast<uint16_t>(Dhcpv6Option::CLIENTID));
    opt_cid.length = htons(10);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_cid), reinterpret_cast<const uint8_t*>(&opt_cid) + 4);
    frame.push_back(0x00); frame.push_back(0x03);
    frame.push_back(0x00); frame.push_back(0x01);
    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);

    // Server ID if provided
    if (server_duid && server_duid_len > 0) {
        Dhcpv6OptionHeader opt_sid{};
        opt_sid.code = htons(static_cast<uint16_t>(Dhcpv6Option::SERVERID));
        opt_sid.length = htons(static_cast<uint16_t>(server_duid_len));
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_sid), reinterpret_cast<const uint8_t*>(&opt_sid) + 4);
        frame.insert(frame.end(), server_duid, server_duid + server_duid_len);
    }

    // IA_NA + IA_ADDR
    uint16_t iana_sub_len = sizeof(Dhcpv6IaNaHeader) + (ipv6_addr ? 4 + sizeof(Dhcpv6IaAddrHeader) : 0);
    Dhcpv6OptionHeader opt_iana{};
    opt_iana.code = htons(static_cast<uint16_t>(Dhcpv6Option::IA_NA));
    opt_iana.length = htons(iana_sub_len);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_iana), reinterpret_cast<const uint8_t*>(&opt_iana) + 4);

    Dhcpv6IaNaHeader iana{};
    iana.iaid = htonl(1);
    iana.t1 = htonl(3600);
    iana.t2 = htonl(5400);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&iana), reinterpret_cast<const uint8_t*>(&iana) + sizeof(Dhcpv6IaNaHeader));

    if (ipv6_addr) {
        Dhcpv6OptionHeader opt_addr{};
        opt_addr.code = htons(static_cast<uint16_t>(Dhcpv6Option::IA_ADDR));
        opt_addr.length = htons(sizeof(Dhcpv6IaAddrHeader));
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_addr), reinterpret_cast<const uint8_t*>(&opt_addr) + 4);

        Dhcpv6IaAddrHeader addr{};
        std::memcpy(addr.ipv6_addr, ipv6_addr, 16);
        addr.preferred_lifetime = htonl(3600);
        addr.valid_lifetime = htonl(7200);
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&addr), reinterpret_cast<const uint8_t*>(&addr) + sizeof(Dhcpv6IaAddrHeader));
    }

    uint16_t payload_len = static_cast<uint16_t>(frame.size() - udp_start);
    auto* ip6_ptr = reinterpret_cast<Ipv6Header*>(frame.data() + ip6_start);
    ip6_ptr->payload_length = htons(payload_len);

    auto* udp_ptr = reinterpret_cast<UdpHeader*>(frame.data() + udp_start);
    udp_ptr->length = htons(payload_len);

    return frame;
}

std::vector<uint8_t> DhcpEngine::BuildDhcpv6Release(TelcoSessionContext* session, const uint8_t* server_duid, size_t server_duid_len) {
    std::vector<uint8_t> frame;
    frame.reserve(256);

    frame.push_back(0x33); frame.push_back(0x33);
    frame.push_back(0x00); frame.push_back(0x01);
    frame.push_back(0x00); frame.push_back(0x02);
    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);
    frame.push_back(0x86); frame.push_back(0xDD);

    size_t ip6_start = frame.size();
    Ipv6Header ip6{};
    ip6.vtc_flow = htonl(0x60000000);
    ip6.next_header = 17;
    ip6.hop_limit = 64;
    ip6.src_ip[0] = 0xFE; ip6.src_ip[1] = 0x80;
    ip6.dst_ip[0] = 0xFF; ip6.dst_ip[1] = 0x02;
    ip6.dst_ip[11] = 0x01; ip6.dst_ip[15] = 0x02;
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&ip6), reinterpret_cast<const uint8_t*>(&ip6) + sizeof(Ipv6Header));

    size_t udp_start = frame.size();
    UdpHeader udp{};
    udp.src_port = htons(DHCPV6_CLIENT_PORT);
    udp.dst_port = htons(DHCPV6_SERVER_PORT);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&udp), reinterpret_cast<const uint8_t*>(&udp) + sizeof(UdpHeader));

    Dhcpv6Header dhcp6{};
    dhcp6.msg_type = static_cast<uint8_t>(Dhcpv6MsgType::RELEASE);
    uint32_t xid = session ? session->GetDhcpXid() : 0x123456;
    dhcp6.transaction_id[0] = (xid >> 16) & 0xFF;
    dhcp6.transaction_id[1] = (xid >> 8) & 0xFF;
    dhcp6.transaction_id[2] = xid & 0xFF;
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&dhcp6), reinterpret_cast<const uint8_t*>(&dhcp6) + sizeof(Dhcpv6Header));

    // Client ID
    Dhcpv6OptionHeader opt_cid{};
    opt_cid.code = htons(static_cast<uint16_t>(Dhcpv6Option::CLIENTID));
    opt_cid.length = htons(10);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_cid), reinterpret_cast<const uint8_t*>(&opt_cid) + 4);
    frame.push_back(0x00); frame.push_back(0x03);
    frame.push_back(0x00); frame.push_back(0x01);
    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);

    // Server ID if available
    if (server_duid && server_duid_len > 0) {
        Dhcpv6OptionHeader opt_sid{};
        opt_sid.code = htons(static_cast<uint16_t>(Dhcpv6Option::SERVERID));
        opt_sid.length = htons(static_cast<uint16_t>(server_duid_len));
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_sid), reinterpret_cast<const uint8_t*>(&opt_sid) + 4);
        frame.insert(frame.end(), server_duid, server_duid + server_duid_len);
    }

    uint16_t payload_len = static_cast<uint16_t>(frame.size() - udp_start);
    auto* ip6_ptr = reinterpret_cast<Ipv6Header*>(frame.data() + ip6_start);
    ip6_ptr->payload_length = htons(payload_len);

    auto* udp_ptr = reinterpret_cast<UdpHeader*>(frame.data() + udp_start);
    udp_ptr->length = htons(payload_len);

    return frame;
}

std::vector<uint8_t> DhcpEngine::BuildDhcpv6Advertise(TelcoSessionContext* session, const uint8_t ipv6_addr[16],
                                                      const uint8_t* server_duid, size_t server_duid_len) {
    std::vector<uint8_t> frame;
    frame.reserve(256);

    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);
    for (int i = 0; i < 6; ++i) frame.push_back(0x52);
    frame.push_back(0x86); frame.push_back(0xDD);

    size_t ip6_start = frame.size();
    Ipv6Header ip6{};
    ip6.vtc_flow = htonl(0x60000000);
    ip6.next_header = 17;
    ip6.hop_limit = 64;
    ip6.src_ip[0] = 0xFE; ip6.src_ip[1] = 0x80;
    ip6.dst_ip[0] = 0xFE; ip6.dst_ip[1] = 0x80;
    if (session) {
        ip6.dst_ip[8] = session->client_mac[0] ^ 0x02;
        ip6.dst_ip[9] = session->client_mac[1];
        ip6.dst_ip[10] = session->client_mac[2];
        ip6.dst_ip[11] = 0xFF; ip6.dst_ip[12] = 0xFE;
        ip6.dst_ip[13] = session->client_mac[3];
        ip6.dst_ip[14] = session->client_mac[4];
        ip6.dst_ip[15] = session->client_mac[5];
    }
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&ip6), reinterpret_cast<const uint8_t*>(&ip6) + sizeof(Ipv6Header));

    size_t udp_start = frame.size();
    UdpHeader udp{};
    udp.src_port = htons(DHCPV6_SERVER_PORT);
    udp.dst_port = htons(DHCPV6_CLIENT_PORT);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&udp), reinterpret_cast<const uint8_t*>(&udp) + sizeof(UdpHeader));

    Dhcpv6Header dhcp6{};
    dhcp6.msg_type = static_cast<uint8_t>(Dhcpv6MsgType::ADVERTISE);
    uint32_t xid = session ? session->GetDhcpXid() : 0x123456;
    dhcp6.transaction_id[0] = (xid >> 16) & 0xFF;
    dhcp6.transaction_id[1] = (xid >> 8) & 0xFF;
    dhcp6.transaction_id[2] = xid & 0xFF;
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&dhcp6), reinterpret_cast<const uint8_t*>(&dhcp6) + sizeof(Dhcpv6Header));

    // Server ID
    Dhcpv6OptionHeader opt_sid{};
    opt_sid.code = htons(static_cast<uint16_t>(Dhcpv6Option::SERVERID));
    if (server_duid && server_duid_len > 0) {
        opt_sid.length = htons(static_cast<uint16_t>(server_duid_len));
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_sid), reinterpret_cast<const uint8_t*>(&opt_sid) + 4);
        frame.insert(frame.end(), server_duid, server_duid + server_duid_len);
    } else {
        opt_sid.length = htons(10);
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_sid), reinterpret_cast<const uint8_t*>(&opt_sid) + 4);
        frame.push_back(0x00); frame.push_back(0x03);
        frame.push_back(0x00); frame.push_back(0x01);
        for (int i = 0; i < 6; ++i) frame.push_back(0x52);
    }

    // Client ID
    Dhcpv6OptionHeader opt_cid{};
    opt_cid.code = htons(static_cast<uint16_t>(Dhcpv6Option::CLIENTID));
    opt_cid.length = htons(10);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_cid), reinterpret_cast<const uint8_t*>(&opt_cid) + 4);
    frame.push_back(0x00); frame.push_back(0x03);
    frame.push_back(0x00); frame.push_back(0x01);
    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);

    // IA_NA + IA_ADDR
    uint16_t iana_sub_len = sizeof(Dhcpv6IaNaHeader) + (ipv6_addr ? 4 + sizeof(Dhcpv6IaAddrHeader) : 0);
    Dhcpv6OptionHeader opt_iana{};
    opt_iana.code = htons(static_cast<uint16_t>(Dhcpv6Option::IA_NA));
    opt_iana.length = htons(iana_sub_len);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_iana), reinterpret_cast<const uint8_t*>(&opt_iana) + 4);

    Dhcpv6IaNaHeader iana{};
    iana.iaid = htonl(1);
    iana.t1 = htonl(3600);
    iana.t2 = htonl(5400);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&iana), reinterpret_cast<const uint8_t*>(&iana) + sizeof(Dhcpv6IaNaHeader));

    if (ipv6_addr) {
        Dhcpv6OptionHeader opt_addr{};
        opt_addr.code = htons(static_cast<uint16_t>(Dhcpv6Option::IA_ADDR));
        opt_addr.length = htons(sizeof(Dhcpv6IaAddrHeader));
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_addr), reinterpret_cast<const uint8_t*>(&opt_addr) + 4);

        Dhcpv6IaAddrHeader addr{};
        std::memcpy(addr.ipv6_addr, ipv6_addr, 16);
        addr.preferred_lifetime = htonl(3600);
        addr.valid_lifetime = htonl(7200);
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&addr), reinterpret_cast<const uint8_t*>(&addr) + sizeof(Dhcpv6IaAddrHeader));
    }

    uint16_t payload_len = static_cast<uint16_t>(frame.size() - udp_start);
    auto* ip6_ptr = reinterpret_cast<Ipv6Header*>(frame.data() + ip6_start);
    ip6_ptr->payload_length = htons(payload_len);

    auto* udp_ptr = reinterpret_cast<UdpHeader*>(frame.data() + udp_start);
    udp_ptr->length = htons(payload_len);

    return frame;
}

std::vector<uint8_t> DhcpEngine::BuildDhcpv6Reply(TelcoSessionContext* session, const uint8_t ipv6_addr[16],
                                                  const uint8_t* server_duid, size_t server_duid_len) {
    std::vector<uint8_t> frame;
    frame.reserve(256);

    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);
    for (int i = 0; i < 6; ++i) frame.push_back(0x52);
    frame.push_back(0x86); frame.push_back(0xDD);

    size_t ip6_start = frame.size();
    Ipv6Header ip6{};
    ip6.vtc_flow = htonl(0x60000000);
    ip6.next_header = 17;
    ip6.hop_limit = 64;
    ip6.src_ip[0] = 0xFE; ip6.src_ip[1] = 0x80;
    ip6.dst_ip[0] = 0xFE; ip6.dst_ip[1] = 0x80;
    if (session) {
        ip6.dst_ip[8] = session->client_mac[0] ^ 0x02;
        ip6.dst_ip[9] = session->client_mac[1];
        ip6.dst_ip[10] = session->client_mac[2];
        ip6.dst_ip[11] = 0xFF; ip6.dst_ip[12] = 0xFE;
        ip6.dst_ip[13] = session->client_mac[3];
        ip6.dst_ip[14] = session->client_mac[4];
        ip6.dst_ip[15] = session->client_mac[5];
    }
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&ip6), reinterpret_cast<const uint8_t*>(&ip6) + sizeof(Ipv6Header));

    size_t udp_start = frame.size();
    UdpHeader udp{};
    udp.src_port = htons(DHCPV6_SERVER_PORT);
    udp.dst_port = htons(DHCPV6_CLIENT_PORT);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&udp), reinterpret_cast<const uint8_t*>(&udp) + sizeof(UdpHeader));

    Dhcpv6Header dhcp6{};
    dhcp6.msg_type = static_cast<uint8_t>(Dhcpv6MsgType::REPLY);
    uint32_t xid = session ? session->GetDhcpXid() : 0x123456;
    dhcp6.transaction_id[0] = (xid >> 16) & 0xFF;
    dhcp6.transaction_id[1] = (xid >> 8) & 0xFF;
    dhcp6.transaction_id[2] = xid & 0xFF;
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&dhcp6), reinterpret_cast<const uint8_t*>(&dhcp6) + sizeof(Dhcpv6Header));

    // Server ID
    Dhcpv6OptionHeader opt_sid{};
    opt_sid.code = htons(static_cast<uint16_t>(Dhcpv6Option::SERVERID));
    if (server_duid && server_duid_len > 0) {
        opt_sid.length = htons(static_cast<uint16_t>(server_duid_len));
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_sid), reinterpret_cast<const uint8_t*>(&opt_sid) + 4);
        frame.insert(frame.end(), server_duid, server_duid + server_duid_len);
    } else {
        opt_sid.length = htons(10);
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_sid), reinterpret_cast<const uint8_t*>(&opt_sid) + 4);
        frame.push_back(0x00); frame.push_back(0x03);
        frame.push_back(0x00); frame.push_back(0x01);
        for (int i = 0; i < 6; ++i) frame.push_back(0x52);
    }

    // Client ID
    Dhcpv6OptionHeader opt_cid{};
    opt_cid.code = htons(static_cast<uint16_t>(Dhcpv6Option::CLIENTID));
    opt_cid.length = htons(10);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_cid), reinterpret_cast<const uint8_t*>(&opt_cid) + 4);
    frame.push_back(0x00); frame.push_back(0x03);
    frame.push_back(0x00); frame.push_back(0x01);
    for (int i = 0; i < 6; ++i) frame.push_back(session ? session->client_mac[i] : 0x00);

    // IA_NA + IA_ADDR
    uint16_t iana_sub_len = sizeof(Dhcpv6IaNaHeader) + (ipv6_addr ? 4 + sizeof(Dhcpv6IaAddrHeader) : 0);
    Dhcpv6OptionHeader opt_iana{};
    opt_iana.code = htons(static_cast<uint16_t>(Dhcpv6Option::IA_NA));
    opt_iana.length = htons(iana_sub_len);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_iana), reinterpret_cast<const uint8_t*>(&opt_iana) + 4);

    Dhcpv6IaNaHeader iana{};
    iana.iaid = htonl(1);
    iana.t1 = htonl(3600);
    iana.t2 = htonl(5400);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&iana), reinterpret_cast<const uint8_t*>(&iana) + sizeof(Dhcpv6IaNaHeader));

    if (ipv6_addr) {
        Dhcpv6OptionHeader opt_addr{};
        opt_addr.code = htons(static_cast<uint16_t>(Dhcpv6Option::IA_ADDR));
        opt_addr.length = htons(sizeof(Dhcpv6IaAddrHeader));
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&opt_addr), reinterpret_cast<const uint8_t*>(&opt_addr) + 4);

        Dhcpv6IaAddrHeader addr{};
        std::memcpy(addr.ipv6_addr, ipv6_addr, 16);
        addr.preferred_lifetime = htonl(3600);
        addr.valid_lifetime = htonl(7200);
        frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&addr), reinterpret_cast<const uint8_t*>(&addr) + sizeof(Dhcpv6IaAddrHeader));
    }

    uint16_t payload_len = static_cast<uint16_t>(frame.size() - udp_start);
    auto* ip6_ptr = reinterpret_cast<Ipv6Header*>(frame.data() + ip6_start);
    ip6_ptr->payload_length = htons(payload_len);

    auto* udp_ptr = reinterpret_cast<UdpHeader*>(frame.data() + udp_start);
    udp_ptr->length = htons(payload_len);

    return frame;
}

} // namespace ddos_samurai::telecom::dhcp
