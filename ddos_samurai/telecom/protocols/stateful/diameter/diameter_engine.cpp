#include "diameter_engine.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <algorithm>

namespace ddos_samurai::telecom::diameter {

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
    uint8_t  protocol;    // 6 (TCP)
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset; // 0x50 = 20 bayt
    uint8_t  flags;       // ACK=0x10, PSH=0x08
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
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

inline void Set24(uint8_t out[3], uint32_t val) {
    out[0] = static_cast<uint8_t>((val >> 16) & 0xFF);
    out[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>(val & 0xFF);
}

inline uint32_t Get24(const uint8_t in[3]) {
    return (static_cast<uint32_t>(in[0]) << 16) |
           (static_cast<uint32_t>(in[1]) << 8) |
           static_cast<uint32_t>(in[2]);
}

} // namespace

DiameterEngine::DiameterEngine(SessionManager& session_mgr, HierarchicalTimingWheel* timing_wheel)
    : session_mgr_(session_mgr),
      timing_wheel_(timing_wheel) {}

bool DiameterEngine::Init(const ProtocolConfig& cfg) {
    config_ = cfg;
    return true;
}

void DiameterEngine::Shutdown() {
    uint32_t cap = session_mgr_.GetCapacity();
    for (uint32_t i = 0; i < cap; ++i) {
        TelcoSessionContext* s = session_mgr_.GetSessionByIndex(i);
        if (s && s->protocol_id == static_cast<uint8_t>(TelcoProtocolId::DIAMETER)) {
            if (timing_wheel_) {
                timing_wheel_->Cancel(s);
            }
            session_mgr_.ReleaseSession(s);
        }
    }
}

DiameterPeerState DiameterEngine::GetState(const TelcoSessionContext* session) const noexcept {
    if (!session) return DiameterPeerState::CLOSED;
    return static_cast<DiameterPeerState>(session->ppp_lcp_identifier);
}

void DiameterEngine::SetState(TelcoSessionContext* session, DiameterPeerState state) noexcept {
    if (!session) return;
    session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::DIAMETER);
    session->ppp_lcp_identifier = static_cast<uint16_t>(state);
    switch (state) {
        case DiameterPeerState::OPEN:
            session->state = SessionState::ESTABLISHED;
            break;
        case DiameterPeerState::WAIT_CONN_ACK:
        case DiameterPeerState::WAIT_I_CEA:
            session->state = SessionState::DISCOVERING;
            break;
        case DiameterPeerState::CLOSING:
            session->state = SessionState::TERMINATING;
            break;
        case DiameterPeerState::FAILED:
            session->state = SessionState::FAILED;
            break;
        case DiameterPeerState::CLOSED:
        default:
            session->state = SessionState::IDLE;
            break;
    }
}

void DiameterEngine::AppendAvpString(std::vector<uint8_t>& buf, uint32_t code, uint8_t flags, const std::string& str, uint32_t vendor_id) {
    bool has_vendor = (flags & 0x80) != 0 || vendor_id != 0;
    if (has_vendor) flags |= 0x80;

    size_t header_len = has_vendor ? 12 : 8;
    size_t avp_len = header_len + str.size();
    size_t padded_len = (avp_len + 3) & ~3;

    size_t start = buf.size();
    buf.resize(start + padded_len, 0);

    auto* avp = reinterpret_cast<AvpHeader*>(buf.data() + start);
    avp->avp_code = htonl(code);
    avp->avp_flags = flags;
    Set24(avp->avp_length, static_cast<uint32_t>(avp_len));

    size_t data_offset = start + 8;
    if (has_vendor) {
        uint32_t v_be = htonl(vendor_id);
        std::memcpy(buf.data() + data_offset, &v_be, 4);
        data_offset += 4;
    }

    if (!str.empty()) {
        std::memcpy(buf.data() + data_offset, str.data(), str.size());
    }
}

void DiameterEngine::AppendAvpU32(std::vector<uint8_t>& buf, uint32_t code, uint8_t flags, uint32_t val, uint32_t vendor_id) {
    bool has_vendor = (flags & 0x80) != 0 || vendor_id != 0;
    if (has_vendor) flags |= 0x80;

    size_t header_len = has_vendor ? 12 : 8;
    size_t avp_len = header_len + 4;

    size_t start = buf.size();
    buf.resize(start + avp_len, 0);

    auto* avp = reinterpret_cast<AvpHeader*>(buf.data() + start);
    avp->avp_code = htonl(code);
    avp->avp_flags = flags;
    Set24(avp->avp_length, static_cast<uint32_t>(avp_len));

    size_t data_offset = start + 8;
    if (has_vendor) {
        uint32_t v_be = htonl(vendor_id);
        std::memcpy(buf.data() + data_offset, &v_be, 4);
        data_offset += 4;
    }

    uint32_t val_be = htonl(val);
    std::memcpy(buf.data() + data_offset, &val_be, 4);
}

void DiameterEngine::AppendAvpIp(std::vector<uint8_t>& buf, uint32_t code, uint8_t flags, uint32_t ipv4, uint32_t vendor_id) {
    bool has_vendor = (flags & 0x80) != 0 || vendor_id != 0;
    if (has_vendor) flags |= 0x80;

    size_t header_len = has_vendor ? 12 : 8;
    size_t avp_len = header_len + 6; // 2 bayt AddressType (1=IPv4) + 4 bayt IPv4
    size_t padded_len = (avp_len + 3) & ~3;

    size_t start = buf.size();
    buf.resize(start + padded_len, 0);

    auto* avp = reinterpret_cast<AvpHeader*>(buf.data() + start);
    avp->avp_code = htonl(code);
    avp->avp_flags = flags;
    Set24(avp->avp_length, static_cast<uint32_t>(avp_len));

    size_t data_offset = start + 8;
    if (has_vendor) {
        uint32_t v_be = htonl(vendor_id);
        std::memcpy(buf.data() + data_offset, &v_be, 4);
        data_offset += 4;
    }

    uint16_t addr_type = htons(1); // IPv4
    std::memcpy(buf.data() + data_offset, &addr_type, 2);
    uint32_t ip_be = htonl(ipv4);
    std::memcpy(buf.data() + data_offset + 2, &ip_be, 4);
}

void DiameterEngine::StartPeerSession(TelcoSessionContext* session, const DiameterPeerConfig& cfg) {
    if (!session) return;

    peer_cfg_ = cfg;
    session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::DIAMETER);
    session->client_ip = cfg.local_ip;
    session->peer_ip = cfg.peer_ip;
    session->client_port = cfg.local_port;
    session->peer_port = cfg.peer_port;
    session->ip_proto = 6; // TCP
    session->s_vlan = cfg.vlan_s;
    session->c_vlan = cfg.vlan_c;
    session->retry_count = 0;

    std::memcpy(session->client_mac, cfg.local_mac, 6);
    std::memcpy(session->peer_mac, cfg.peer_mac, 6);

    SetState(session, DiameterPeerState::WAIT_I_CEA);

    // CER Gönder
    last_tx_frame_ = BuildCerPacket(session);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    if (timing_wheel_) {
        timing_wheel_->Schedule(session, cfg.retransmit_timeout_ms > 0 ? cfg.retransmit_timeout_ms : 1000);
    }
}

void DiameterEngine::StopPeerSession(TelcoSessionContext* session) {
    if (!session) return;

    if (timing_wheel_) timing_wheel_->Cancel(session);

    if (GetState(session) == DiameterPeerState::OPEN) {
        SetState(session, DiameterPeerState::CLOSING);
        last_tx_frame_ = BuildDprPacket(session, 0); // 0 = DO_NOT_WANT_TO_TALK_TO_YOU
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        if (timing_wheel_) timing_wheel_->Schedule(session, 1000);
    } else {
        SetState(session, DiameterPeerState::CLOSED);
    }
}

std::vector<uint8_t> DiameterEngine::BuildCerPacket(TelcoSessionContext* session) {
    std::vector<uint8_t> avps;
    AppendAvpString(avps, AVP_ORIGIN_HOST, 0x40, peer_cfg_.origin_host);
    AppendAvpString(avps, AVP_ORIGIN_REALM, 0x40, peer_cfg_.origin_realm);
    AppendAvpIp(avps, AVP_HOST_IP_ADDRESS, 0x40, session->client_ip);
    AppendAvpU32(avps, AVP_VENDOR_ID, 0x40, peer_cfg_.vendor_id);
    AppendAvpString(avps, AVP_PRODUCT_NAME, 0x00, peer_cfg_.product_name);
    AppendAvpU32(avps, AVP_AUTH_APPLICATION_ID, 0x40, APP_DIAMETER_CREDIT_CONTROL);

    size_t diam_len = sizeof(DiameterHeader) + avps.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + diam_len;
    std::vector<uint8_t> packet(total_len, 0);

    // 1. Ethernet
    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    // 2. IPv4
    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 6; // TCP
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    // 3. TCP
    size_t tcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* tcp = reinterpret_cast<TcpHeader*>(packet.data() + tcp_offset);
    tcp->src_port = htons(session->client_port);
    tcp->dst_port = htons(session->peer_port);
    tcp->seq_num = htonl(100);
    tcp->ack_num = htonl(1);
    tcp->data_offset = 0x50; // 20 bayt
    tcp->flags = 0x18;       // ACK + PSH
    tcp->window_size = htons(65535);

    // 4. Diameter Header
    size_t diam_offset = tcp_offset + sizeof(TcpHeader);
    auto* diam = reinterpret_cast<DiameterHeader*>(packet.data() + diam_offset);
    diam->version = 1;
    Set24(diam->length, static_cast<uint32_t>(diam_len));
    diam->command_flags = 0x80; // R=1 (Request)
    Set24(diam->command_code, CMD_CAPABILITIES_EXCHANGE);
    diam->application_id = htonl(APP_DIAMETER_BASE_COMMON);
    diam->hop_by_hop_id = htonl(next_hop_by_hop_id_++);
    diam->end_to_end_id = htonl(next_end_to_end_id_++);

    // 5. AVPs
    std::memcpy(packet.data() + diam_offset + sizeof(DiameterHeader), avps.data(), avps.size());

    return packet;
}

std::vector<uint8_t> DiameterEngine::BuildCeaPacket(TelcoSessionContext* session, uint32_t result_code, uint32_t hop_id, uint32_t end_id) {
    std::vector<uint8_t> avps;
    AppendAvpU32(avps, AVP_RESULT_CODE, 0x40, result_code);
    AppendAvpString(avps, AVP_ORIGIN_HOST, 0x40, peer_cfg_.origin_host);
    AppendAvpString(avps, AVP_ORIGIN_REALM, 0x40, peer_cfg_.origin_realm);
    AppendAvpIp(avps, AVP_HOST_IP_ADDRESS, 0x40, session->client_ip);
    AppendAvpU32(avps, AVP_VENDOR_ID, 0x40, peer_cfg_.vendor_id);
    AppendAvpString(avps, AVP_PRODUCT_NAME, 0x00, peer_cfg_.product_name);

    size_t diam_len = sizeof(DiameterHeader) + avps.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + diam_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 6;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t tcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* tcp = reinterpret_cast<TcpHeader*>(packet.data() + tcp_offset);
    tcp->src_port = htons(session->client_port);
    tcp->dst_port = htons(session->peer_port);
    tcp->data_offset = 0x50;
    tcp->flags = 0x18;
    tcp->window_size = htons(65535);

    size_t diam_offset = tcp_offset + sizeof(TcpHeader);
    auto* diam = reinterpret_cast<DiameterHeader*>(packet.data() + diam_offset);
    diam->version = 1;
    Set24(diam->length, static_cast<uint32_t>(diam_len));
    diam->command_flags = 0x00; // Answer
    Set24(diam->command_code, CMD_CAPABILITIES_EXCHANGE);
    diam->application_id = htonl(APP_DIAMETER_BASE_COMMON);
    diam->hop_by_hop_id = htonl(hop_id);
    diam->end_to_end_id = htonl(end_id);

    std::memcpy(packet.data() + diam_offset + sizeof(DiameterHeader), avps.data(), avps.size());
    return packet;
}

std::vector<uint8_t> DiameterEngine::BuildDwrPacket(TelcoSessionContext* session) {
    std::vector<uint8_t> avps;
    AppendAvpString(avps, AVP_ORIGIN_HOST, 0x40, peer_cfg_.origin_host);
    AppendAvpString(avps, AVP_ORIGIN_REALM, 0x40, peer_cfg_.origin_realm);

    size_t diam_len = sizeof(DiameterHeader) + avps.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + diam_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 6;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t tcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* tcp = reinterpret_cast<TcpHeader*>(packet.data() + tcp_offset);
    tcp->src_port = htons(session->client_port);
    tcp->dst_port = htons(session->peer_port);
    tcp->data_offset = 0x50;
    tcp->flags = 0x18;
    tcp->window_size = htons(65535);

    size_t diam_offset = tcp_offset + sizeof(TcpHeader);
    auto* diam = reinterpret_cast<DiameterHeader*>(packet.data() + diam_offset);
    diam->version = 1;
    Set24(diam->length, static_cast<uint32_t>(diam_len));
    diam->command_flags = 0x80; // Request
    Set24(diam->command_code, CMD_DEVICE_WATCHDOG);
    diam->application_id = htonl(APP_DIAMETER_BASE_COMMON);
    diam->hop_by_hop_id = htonl(next_hop_by_hop_id_++);
    diam->end_to_end_id = htonl(next_end_to_end_id_++);

    std::memcpy(packet.data() + diam_offset + sizeof(DiameterHeader), avps.data(), avps.size());
    return packet;
}

std::vector<uint8_t> DiameterEngine::BuildDwaPacket(TelcoSessionContext* session, uint32_t result_code, uint32_t hop_id, uint32_t end_id) {
    std::vector<uint8_t> avps;
    AppendAvpU32(avps, AVP_RESULT_CODE, 0x40, result_code);
    AppendAvpString(avps, AVP_ORIGIN_HOST, 0x40, peer_cfg_.origin_host);
    AppendAvpString(avps, AVP_ORIGIN_REALM, 0x40, peer_cfg_.origin_realm);

    size_t diam_len = sizeof(DiameterHeader) + avps.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + diam_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 6;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t tcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* tcp = reinterpret_cast<TcpHeader*>(packet.data() + tcp_offset);
    tcp->src_port = htons(session->client_port);
    tcp->dst_port = htons(session->peer_port);
    tcp->data_offset = 0x50;
    tcp->flags = 0x18;
    tcp->window_size = htons(65535);

    size_t diam_offset = tcp_offset + sizeof(TcpHeader);
    auto* diam = reinterpret_cast<DiameterHeader*>(packet.data() + diam_offset);
    diam->version = 1;
    Set24(diam->length, static_cast<uint32_t>(diam_len));
    diam->command_flags = 0x00; // Answer
    Set24(diam->command_code, CMD_DEVICE_WATCHDOG);
    diam->application_id = htonl(APP_DIAMETER_BASE_COMMON);
    diam->hop_by_hop_id = htonl(hop_id);
    diam->end_to_end_id = htonl(end_id);

    std::memcpy(packet.data() + diam_offset + sizeof(DiameterHeader), avps.data(), avps.size());
    return packet;
}

std::vector<uint8_t> DiameterEngine::BuildDprPacket(TelcoSessionContext* session, uint32_t disconnect_cause) {
    std::vector<uint8_t> avps;
    AppendAvpString(avps, AVP_ORIGIN_HOST, 0x40, peer_cfg_.origin_host);
    AppendAvpString(avps, AVP_ORIGIN_REALM, 0x40, peer_cfg_.origin_realm);
    AppendAvpU32(avps, AVP_DISCONNECT_CAUSE, 0x40, disconnect_cause);

    size_t diam_len = sizeof(DiameterHeader) + avps.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + diam_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 6;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t tcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* tcp = reinterpret_cast<TcpHeader*>(packet.data() + tcp_offset);
    tcp->src_port = htons(session->client_port);
    tcp->dst_port = htons(session->peer_port);
    tcp->data_offset = 0x50;
    tcp->flags = 0x18;
    tcp->window_size = htons(65535);

    size_t diam_offset = tcp_offset + sizeof(TcpHeader);
    auto* diam = reinterpret_cast<DiameterHeader*>(packet.data() + diam_offset);
    diam->version = 1;
    Set24(diam->length, static_cast<uint32_t>(diam_len));
    diam->command_flags = 0x80;
    Set24(diam->command_code, CMD_DISCONNECT_PEER);
    diam->application_id = htonl(APP_DIAMETER_BASE_COMMON);
    diam->hop_by_hop_id = htonl(next_hop_by_hop_id_++);
    diam->end_to_end_id = htonl(next_end_to_end_id_++);

    std::memcpy(packet.data() + diam_offset + sizeof(DiameterHeader), avps.data(), avps.size());
    return packet;
}

std::vector<uint8_t> DiameterEngine::BuildDpaPacket(TelcoSessionContext* session, uint32_t result_code, uint32_t hop_id, uint32_t end_id) {
    std::vector<uint8_t> avps;
    AppendAvpU32(avps, AVP_RESULT_CODE, 0x40, result_code);
    AppendAvpString(avps, AVP_ORIGIN_HOST, 0x40, peer_cfg_.origin_host);
    AppendAvpString(avps, AVP_ORIGIN_REALM, 0x40, peer_cfg_.origin_realm);

    size_t diam_len = sizeof(DiameterHeader) + avps.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + diam_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 6;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t tcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* tcp = reinterpret_cast<TcpHeader*>(packet.data() + tcp_offset);
    tcp->src_port = htons(session->client_port);
    tcp->dst_port = htons(session->peer_port);
    tcp->data_offset = 0x50;
    tcp->flags = 0x18;
    tcp->window_size = htons(65535);

    size_t diam_offset = tcp_offset + sizeof(TcpHeader);
    auto* diam = reinterpret_cast<DiameterHeader*>(packet.data() + diam_offset);
    diam->version = 1;
    Set24(diam->length, static_cast<uint32_t>(diam_len));
    diam->command_flags = 0x00;
    Set24(diam->command_code, CMD_DISCONNECT_PEER);
    diam->application_id = htonl(APP_DIAMETER_BASE_COMMON);
    diam->hop_by_hop_id = htonl(hop_id);
    diam->end_to_end_id = htonl(end_id);

    std::memcpy(packet.data() + diam_offset + sizeof(DiameterHeader), avps.data(), avps.size());
    return packet;
}

std::vector<uint8_t> DiameterEngine::BuildCcrPacket(TelcoSessionContext* session, const std::string& session_id, CcRequestType req_type, uint32_t req_number) {
    std::vector<uint8_t> avps;
    AppendAvpString(avps, AVP_SESSION_ID, 0x40, session_id);
    AppendAvpString(avps, AVP_ORIGIN_HOST, 0x40, peer_cfg_.origin_host);
    AppendAvpString(avps, AVP_ORIGIN_REALM, 0x40, peer_cfg_.origin_realm);
    AppendAvpString(avps, AVP_DESTINATION_REALM, 0x40, peer_cfg_.destination_realm);
    AppendAvpU32(avps, AVP_AUTH_APPLICATION_ID, 0x40, APP_DIAMETER_CREDIT_CONTROL);
    AppendAvpU32(avps, AVP_CC_REQUEST_TYPE, 0x40, static_cast<uint32_t>(req_type));
    AppendAvpU32(avps, AVP_CC_REQUEST_NUMBER, 0x40, req_number);

    size_t diam_len = sizeof(DiameterHeader) + avps.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + diam_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 6;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t tcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* tcp = reinterpret_cast<TcpHeader*>(packet.data() + tcp_offset);
    tcp->src_port = htons(session->client_port);
    tcp->dst_port = htons(session->peer_port);
    tcp->data_offset = 0x50;
    tcp->flags = 0x18;
    tcp->window_size = htons(65535);

    size_t diam_offset = tcp_offset + sizeof(TcpHeader);
    auto* diam = reinterpret_cast<DiameterHeader*>(packet.data() + diam_offset);
    diam->version = 1;
    Set24(diam->length, static_cast<uint32_t>(diam_len));
    diam->command_flags = 0xC0; // R=1, P=1 (Proxiable)
    Set24(diam->command_code, CMD_CREDIT_CONTROL);
    diam->application_id = htonl(APP_DIAMETER_CREDIT_CONTROL);
    diam->hop_by_hop_id = htonl(next_hop_by_hop_id_++);
    diam->end_to_end_id = htonl(next_end_to_end_id_++);

    std::memcpy(packet.data() + diam_offset + sizeof(DiameterHeader), avps.data(), avps.size());
    return packet;
}

std::vector<uint8_t> DiameterEngine::BuildCcaPacket(TelcoSessionContext* session, const std::string& session_id, uint32_t result_code, CcRequestType req_type, uint32_t req_number, uint32_t hop_id, uint32_t end_id) {
    std::vector<uint8_t> avps;
    AppendAvpString(avps, AVP_SESSION_ID, 0x40, session_id);
    AppendAvpU32(avps, AVP_RESULT_CODE, 0x40, result_code);
    AppendAvpString(avps, AVP_ORIGIN_HOST, 0x40, peer_cfg_.origin_host);
    AppendAvpString(avps, AVP_ORIGIN_REALM, 0x40, peer_cfg_.origin_realm);
    AppendAvpU32(avps, AVP_AUTH_APPLICATION_ID, 0x40, APP_DIAMETER_CREDIT_CONTROL);
    AppendAvpU32(avps, AVP_CC_REQUEST_TYPE, 0x40, static_cast<uint32_t>(req_type));
    AppendAvpU32(avps, AVP_CC_REQUEST_NUMBER, 0x40, req_number);

    size_t diam_len = sizeof(DiameterHeader) + avps.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + diam_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 6;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t tcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* tcp = reinterpret_cast<TcpHeader*>(packet.data() + tcp_offset);
    tcp->src_port = htons(session->client_port);
    tcp->dst_port = htons(session->peer_port);
    tcp->data_offset = 0x50;
    tcp->flags = 0x18;
    tcp->window_size = htons(65535);

    size_t diam_offset = tcp_offset + sizeof(TcpHeader);
    auto* diam = reinterpret_cast<DiameterHeader*>(packet.data() + diam_offset);
    diam->version = 1;
    Set24(diam->length, static_cast<uint32_t>(diam_len));
    diam->command_flags = 0x40; // Answer, P=1
    Set24(diam->command_code, CMD_CREDIT_CONTROL);
    diam->application_id = htonl(APP_DIAMETER_CREDIT_CONTROL);
    diam->hop_by_hop_id = htonl(hop_id);
    diam->end_to_end_id = htonl(end_id);

    std::memcpy(packet.data() + diam_offset + sizeof(DiameterHeader), avps.data(), avps.size());
    return packet;
}

bool DiameterEngine::ProcessRxFrame(const uint8_t* frame, size_t len, uint64_t now_tsc) {
    size_t min_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + sizeof(DiameterHeader);
    if (!frame || len < min_len) return false;

    size_t offset = 12;
    uint16_t ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
    offset += 2;

    if ((ethertype == 0x88A8 || ethertype == 0x9100) && len >= offset + 4) {
        offset += 2;
        ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
        offset += 2;
    }
    if (ethertype == 0x8100 && len >= offset + 4) {
        offset += 2;
        ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
        offset += 2;
    }

    if (ethertype != 0x0800 || len < offset + sizeof(Ipv4Header) + sizeof(TcpHeader) + sizeof(DiameterHeader)) {
        return false;
    }

    const auto* ip = reinterpret_cast<const Ipv4Header*>(frame + offset);
    if ((ip->ihl_version >> 4) != 4 || ip->protocol != 6) return false;

    size_t ip_len = (ip->ihl_version & 0x0F) * 4;
    size_t tcp_offset = offset + ip_len;
    if (len < tcp_offset + sizeof(TcpHeader) + sizeof(DiameterHeader)) return false;

    const auto* tcp = reinterpret_cast<const TcpHeader*>(frame + tcp_offset);
    size_t tcp_hdr_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
    size_t diam_offset = tcp_offset + tcp_hdr_len;
    if (len < diam_offset + sizeof(DiameterHeader)) return false;

    uint32_t src_ip = ntohl(ip->src_ip);
    uint32_t dst_ip = ntohl(ip->dst_ip);
    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dst_port = ntohs(tcp->dst_port);

    TelcoSessionContext* session = session_mgr_.FindSessionBy5Tuple(dst_ip, src_ip, dst_port, src_port, 6);
    if (!session) {
        // Oturumu doğrudan ara
        uint32_t cap = session_mgr_.GetCapacity();
        for (uint32_t i = 0; i < cap; ++i) {
            TelcoSessionContext* s = session_mgr_.GetSessionByIndex(i);
            if (s && s->protocol_id == static_cast<uint8_t>(TelcoProtocolId::DIAMETER)) {
                session = s;
                break;
            }
        }
    }

    if (!session) return false;

    session->rx_packets++;
    session->rx_bytes += len;
    session->last_activity_tsc = now_tsc;

    return ProcessDiameterPayload(session, frame + diam_offset, len - diam_offset, now_tsc);
}

bool DiameterEngine::ProcessDiameterPayload(TelcoSessionContext* session, const uint8_t* payload, size_t len, uint64_t /*now_tsc*/) {
    if (len < sizeof(DiameterHeader)) return false;

    const auto* diam = reinterpret_cast<const DiameterHeader*>(payload);
    if (diam->version != 1) return false;

    uint32_t msg_len = Get24(diam->length);
    if (msg_len > len) return false;

    uint32_t cmd_code = Get24(diam->command_code);
    bool is_request = (diam->command_flags & 0x80) != 0;
    uint32_t hop_id = ntohl(diam->hop_by_hop_id);
    uint32_t end_id = ntohl(diam->end_to_end_id);

    // Decode incoming AVPs via Dynamic Dictionary
    std::vector<DecodedAvp> rx_avps;
    if (msg_len > sizeof(DiameterHeader)) {
        dictionary_.DecodeAvps(payload + sizeof(DiameterHeader), msg_len - sizeof(DiameterHeader), rx_avps);
    }

    // FSM Geçişleri
    if (cmd_code == CMD_CAPABILITIES_EXCHANGE) {
        if (!is_request) { // CEA alındı
            SetState(session, DiameterPeerState::OPEN);
            if (timing_wheel_) {
                timing_wheel_->Cancel(session);
                timing_wheel_->Schedule(session, peer_cfg_.watchdog_interval_ms > 0 ? peer_cfg_.watchdog_interval_ms : 5000);
            }
        } else { // CER alındı -> CEA gönder
            last_tx_frame_ = BuildCeaPacket(session, RESULT_DIAMETER_SUCCESS, hop_id, end_id);
            session->tx_packets++;
            session->tx_bytes += last_tx_frame_.size();
        }
        return true;
    }

    if (cmd_code == CMD_DEVICE_WATCHDOG) {
        if (!is_request) { // DWA alındı
            session->retry_count = 0;
            if (timing_wheel_) {
                timing_wheel_->Cancel(session);
                timing_wheel_->Schedule(session, peer_cfg_.watchdog_interval_ms > 0 ? peer_cfg_.watchdog_interval_ms : 5000);
            }
        } else { // DWR alındı -> DWA gönder
            last_tx_frame_ = BuildDwaPacket(session, RESULT_DIAMETER_SUCCESS, hop_id, end_id);
            session->tx_packets++;
            session->tx_bytes += last_tx_frame_.size();
        }
        return true;
    }

    if (cmd_code == CMD_CREDIT_CONTROL) {
        if (!is_request) { // CCA alındı
            // Başarılı billing oturumu
        } else { // CCR alındı -> CCA üret
            std::string session_id = "session-samurai-01";
            CcRequestType req_type = CcRequestType::INITIAL_REQUEST;
            uint32_t req_number = 0;
            for (const auto& a : rx_avps) {
                if (a.code == AVP_SESSION_ID) session_id = a.str_val;
                if (a.code == AVP_CC_REQUEST_TYPE) req_type = static_cast<CcRequestType>(a.u32_val);
                if (a.code == AVP_CC_REQUEST_NUMBER) req_number = a.u32_val;
            }
            last_tx_frame_ = BuildCcaPacket(session, session_id, RESULT_DIAMETER_SUCCESS, req_type, req_number, hop_id, end_id);
            session->tx_packets++;
            session->tx_bytes += last_tx_frame_.size();
        }
        return true;
    }

    if (cmd_code == CMD_DISCONNECT_PEER) {
        if (!is_request) { // DPA alındı
            SetState(session, DiameterPeerState::CLOSED);
            if (timing_wheel_) timing_wheel_->Cancel(session);
        } else { // DPR alındı -> DPA gönder
            SetState(session, DiameterPeerState::CLOSED);
            last_tx_frame_ = BuildDpaPacket(session, RESULT_DIAMETER_SUCCESS, hop_id, end_id);
            session->tx_packets++;
            session->tx_bytes += last_tx_frame_.size();
            if (timing_wheel_) timing_wheel_->Cancel(session);
        }
        return true;
    }

    return true;
}

void DiameterEngine::HandleTimeout(TelcoSessionContext* session) {
    if (!session) return;

    DiameterPeerState state = GetState(session);

    if (state == DiameterPeerState::WAIT_I_CEA) {
        session->retry_count++;
        if (session->retry_count >= config_.max_retries) {
            SetState(session, DiameterPeerState::FAILED);
            return;
        }
        last_tx_frame_ = BuildCerPacket(session);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        if (timing_wheel_) timing_wheel_->Schedule(session, 1000 * (1 << session->retry_count));
        return;
    }

    if (state == DiameterPeerState::OPEN) {
        // Watchdog (DWR) zamanı
        last_tx_frame_ = BuildDwrPacket(session);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        if (timing_wheel_) timing_wheel_->Schedule(session, 1000); // 1s DWA yanıt bekleme
        return;
    }
}

uint32_t DiameterEngine::OnTimerTick(uint64_t current_tsc) {
    if (!timing_wheel_) return 0;
    return timing_wheel_->Advance(current_tsc, [this](TelcoSessionContext* s) {
        HandleTimeout(s);
    });
}

void DiameterEngine::OnRxPacket(rte_mbuf* /*mbuf*/, const PacketMetadata& meta, TelcoSessionContext* session) {
    if (meta.raw_frame && meta.raw_len > 0) {
        ProcessRxFrame(meta.raw_frame, meta.raw_len, session ? session->last_activity_tsc : 0);
    }
}

rte_mbuf* DiameterEngine::BuildTxPacket(rte_mempool* /*pool*/, TelcoSessionContext* /*session*/, uint16_t /*event_type*/) {
    return nullptr;
}

bool DiameterEngine::DecodePayloadAvps(const uint8_t* avp_payload, size_t avp_len, std::vector<DecodedAvp>& out_avps) const {
    return dictionary_.DecodeAvps(avp_payload, avp_len, out_avps);
}

bool DiameterEngine::ValidateIncomingAvps(uint32_t cmd_code, uint32_t app_id, bool is_request,
                                          const uint8_t* avp_payload, size_t avp_len,
                                          std::vector<DecodedAvp>& out_avps, std::string& err) const {
    if (!dictionary_.DecodeAvps(avp_payload, avp_len, out_avps)) {
        err = "Failed to decode Diameter AVPs from payload";
        return false;
    }
    return dictionary_.ValidateMessage(cmd_code, app_id, is_request, out_avps, err);
}

std::vector<uint8_t> DiameterEngine::BuildDictionaryDrivenPacket(TelcoSessionContext* session,
                                                                uint32_t cmd_code,
                                                                uint32_t app_id,
                                                                bool is_request,
                                                                const std::vector<DecodedAvp>& avps,
                                                                uint32_t hop_id,
                                                                uint32_t end_id) {
    if (!session) return {};

    std::vector<uint8_t> avp_buf;
    for (const auto& a : avps) {
        if (!dictionary_.EncodeAvp(a, avp_buf)) {
            return {};
        }
    }

    size_t diam_len = sizeof(DiameterHeader) + avp_buf.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + diam_len;
    std::vector<uint8_t> packet(total_len, 0);

    // 1. Ethernet Header
    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    // 2. IPv4 Header
    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 6; // TCP
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    // 3. TCP Header
    size_t tcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* tcp = reinterpret_cast<TcpHeader*>(packet.data() + tcp_offset);
    tcp->src_port = htons(session->client_port);
    tcp->dst_port = htons(session->peer_port);
    tcp->seq_num = htonl(100);
    tcp->ack_num = htonl(1);
    tcp->data_offset = 0x50; // 20 bytes
    tcp->flags = 0x18;       // ACK + PSH
    tcp->window_size = htons(65535);

    // 4. Diameter Header
    size_t diam_offset = tcp_offset + sizeof(TcpHeader);
    auto* diam = reinterpret_cast<DiameterHeader*>(packet.data() + diam_offset);
    diam->version = 1;
    Set24(diam->length, static_cast<uint32_t>(diam_len));
    diam->command_flags = is_request ? 0x80 : 0x00;
    Set24(diam->command_code, cmd_code);
    diam->application_id = htonl(app_id);

    uint32_t h_id = (hop_id != 0) ? hop_id : ++next_hop_by_hop_id_;
    uint32_t e_id = (end_id != 0) ? end_id : ++next_end_to_end_id_;
    diam->hop_by_hop_id = htonl(h_id);
    diam->end_to_end_id = htonl(e_id);

    // 5. Copy AVPs
    if (!avp_buf.empty()) {
        std::memcpy(packet.data() + diam_offset + sizeof(DiameterHeader), avp_buf.data(), avp_buf.size());
    }

    return packet;
}

std::vector<uint8_t> DiameterEngine::BuildDictionaryDrivenCcr(TelcoSessionContext* session,
                                                             const std::string& session_id,
                                                             CcRequestType req_type,
                                                             uint32_t req_number,
                                                             const std::vector<DecodedAvp>& extra_avps,
                                                             uint32_t app_id) {
    std::vector<DecodedAvp> avps;
    avps.push_back(DecodedAvp::CreateString(AVP_SESSION_ID, session_id, AVP_FLAG_MANDATORY));
    avps.push_back(DecodedAvp::CreateString(AVP_ORIGIN_HOST, peer_cfg_.origin_host, AVP_FLAG_MANDATORY));
    avps.push_back(DecodedAvp::CreateString(AVP_ORIGIN_REALM, peer_cfg_.origin_realm, AVP_FLAG_MANDATORY));
    avps.push_back(DecodedAvp::CreateString(AVP_DESTINATION_REALM, peer_cfg_.destination_realm, AVP_FLAG_MANDATORY));
    avps.push_back(DecodedAvp::CreateU32(AVP_AUTH_APPLICATION_ID, app_id, AVP_FLAG_MANDATORY));
    avps.push_back(DecodedAvp::CreateString(461, "32251@3gpp.org", AVP_FLAG_MANDATORY)); // Service-Context-Id
    avps.push_back(DecodedAvp::CreateU32(AVP_CC_REQUEST_TYPE, static_cast<uint32_t>(req_type), AVP_FLAG_MANDATORY));
    avps.push_back(DecodedAvp::CreateU32(AVP_CC_REQUEST_NUMBER, req_number, AVP_FLAG_MANDATORY));

    for (const auto& a : extra_avps) {
        avps.push_back(a);
    }

    return BuildDictionaryDrivenPacket(session, CMD_CREDIT_CONTROL, app_id, true, avps);
}

std::vector<uint8_t> DiameterEngine::BuildDictionaryDrivenCca(TelcoSessionContext* session,
                                                             const std::string& session_id,
                                                             uint32_t result_code,
                                                             CcRequestType req_type,
                                                             uint32_t req_number,
                                                             uint32_t hop_id,
                                                             uint32_t end_id,
                                                             const std::vector<DecodedAvp>& extra_avps,
                                                             uint32_t app_id) {
    std::vector<DecodedAvp> avps;
    avps.push_back(DecodedAvp::CreateString(AVP_SESSION_ID, session_id, AVP_FLAG_MANDATORY));
    avps.push_back(DecodedAvp::CreateU32(AVP_RESULT_CODE, result_code, AVP_FLAG_MANDATORY));
    avps.push_back(DecodedAvp::CreateString(AVP_ORIGIN_HOST, peer_cfg_.origin_host, AVP_FLAG_MANDATORY));
    avps.push_back(DecodedAvp::CreateString(AVP_ORIGIN_REALM, peer_cfg_.origin_realm, AVP_FLAG_MANDATORY));
    avps.push_back(DecodedAvp::CreateU32(AVP_CC_REQUEST_TYPE, static_cast<uint32_t>(req_type), AVP_FLAG_MANDATORY));
    avps.push_back(DecodedAvp::CreateU32(AVP_CC_REQUEST_NUMBER, req_number, AVP_FLAG_MANDATORY));

    for (const auto& a : extra_avps) {
        avps.push_back(a);
    }

    return BuildDictionaryDrivenPacket(session, CMD_CREDIT_CONTROL, app_id, false, avps, hop_id, end_id);
}

} // namespace ddos_samurai::telecom::diameter
