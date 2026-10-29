#include "gtpu_engine.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <algorithm>

namespace ddos_samurai::telecom::mobile {

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

GtpuEngine::GtpuEngine(SessionManager& session_mgr, HierarchicalTimingWheel* wheel)
    : session_mgr_(session_mgr),
      timing_wheel_(wheel) {}

bool GtpuEngine::Init(const ProtocolConfig& cfg) {
    config_ = cfg;
    return true;
}

void GtpuEngine::Shutdown() {
    uint32_t cap = session_mgr_.GetCapacity();
    for (uint32_t i = 0; i < cap; ++i) {
        TelcoSessionContext* s = session_mgr_.GetSessionByIndex(i);
        if (s && s->protocol_id == static_cast<uint8_t>(TelcoProtocolId::GTPU)) {
            if (timing_wheel_) {
                timing_wheel_->Cancel(s);
            }
            session_mgr_.UnbindGtpuSession(s);
            session_mgr_.ReleaseSession(s);
        }
    }
}

GtpuSubState GtpuEngine::GetSubState(const TelcoSessionContext* session) const noexcept {
    if (!session) return GtpuSubState::IDLE;
    return static_cast<GtpuSubState>(session->ppp_lcp_identifier);
}

void GtpuEngine::SetSubState(TelcoSessionContext* session, GtpuSubState state) noexcept {
    if (!session) return;
    session->ppp_lcp_identifier = static_cast<uint16_t>(state);
    switch (state) {
        case GtpuSubState::ACTIVE:
            session->state = SessionState::ESTABLISHED;
            break;
        case GtpuSubState::ECHO_PENDING:
        case GtpuSubState::DEGRADED:
            session->state = SessionState::ESTABLISHED;
            break;
        case GtpuSubState::TEARDOWN:
            session->state = SessionState::TERMINATING;
            break;
        case GtpuSubState::FAILED:
            session->state = SessionState::FAILED;
            break;
        default:
            session->state = SessionState::IDLE;
            break;
    }
}

void GtpuEngine::StartSession(TelcoSessionContext* session, const GtpuTunnelConfig& tunnel_cfg) {
    if (!session) return;

    session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::GTPU);
    session->teid_uplink = tunnel_cfg.uplink_teid;
    session->teid_downlink = tunnel_cfg.downlink_teid;
    session->client_ip = tunnel_cfg.local_gnb_ip;
    session->peer_ip = tunnel_cfg.peer_upf_ip;
    session->client_port = tunnel_cfg.local_port;
    session->peer_port = tunnel_cfg.peer_port;
    session->ip_proto = 17;
    session->retry_count = 0;

    std::memcpy(session->client_mac, tunnel_cfg.local_mac, 6);
    std::memcpy(session->peer_mac, tunnel_cfg.peer_mac, 6);

    // Fastpath O(1) TEID Hash Tablosuna Bağla
    session_mgr_.BindGtpuSession(session, tunnel_cfg.uplink_teid);
    SetSubState(session, GtpuSubState::ACTIVE);

    // Zamanlayıcı Çarkına Canlılık (Echo Heartbeat) Ekle
    uint32_t interval_ms = tunnel_cfg.echo_interval_ms > 0 ? tunnel_cfg.echo_interval_ms : 5000;
    if (timing_wheel_) {
        timing_wheel_->Schedule(session, interval_ms);
    }
}

void GtpuEngine::StopSession(TelcoSessionContext* session) {
    if (!session) return;

    if (timing_wheel_) {
        timing_wheel_->Cancel(session);
    }

    SetSubState(session, GtpuSubState::TEARDOWN);
    session_mgr_.UnbindGtpuSession(session);
}

void GtpuEngine::HandleTimeout(TelcoSessionContext* session) {
    if (!session) return;

    GtpuSubState sub = GetSubState(session);

    if (sub == GtpuSubState::ACTIVE) {
        // Canlılık sorgusu zamanı: Echo Request gönder
        SetSubState(session, GtpuSubState::ECHO_PENDING);
        session->retry_count = 0;

        uint16_t seq = next_seq_num_++;
        last_tx_frame_ = BuildEchoRequest(session, seq);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();

        if (timing_wheel_) {
            timing_wheel_->Schedule(session, config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 500);
        }
        return;
    }

    if (sub == GtpuSubState::ECHO_PENDING || sub == GtpuSubState::DEGRADED) {
        session->retry_count++;
        if (session->retry_count >= config_.max_retries) {
            SetSubState(session, GtpuSubState::FAILED);
            if (timing_wheel_) {
                timing_wheel_->Cancel(session);
            }
            return;
        }

        SetSubState(session, GtpuSubState::DEGRADED);
        uint16_t seq = next_seq_num_++;
        last_tx_frame_ = BuildEchoRequest(session, seq);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();

        uint32_t backoff_ms = (config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 500) * (1 << session->retry_count);
        if (timing_wheel_) {
            timing_wheel_->Schedule(session, backoff_ms);
        }
    }
}

uint32_t GtpuEngine::OnTimerTick(uint64_t current_tsc) {
    if (!timing_wheel_) return 0;
    return timing_wheel_->Advance(current_tsc, [this](TelcoSessionContext* s) {
        HandleTimeout(s);
    });
}

void GtpuEngine::OnRxPacket(rte_mbuf* /*mbuf*/, const PacketMetadata& meta, TelcoSessionContext* session) {
    if (meta.raw_frame && meta.raw_len >= 14) {
        ProcessRxFrame(meta.raw_frame, meta.raw_len, session);
    } else if (meta.payload_ptr && meta.payload_len > 0) {
        ProcessRxFrame(meta.payload_ptr, meta.payload_len, session);
    }
}

rte_mbuf* GtpuEngine::BuildTxPacket(rte_mempool* /*pool*/, TelcoSessionContext* /*session*/, uint16_t /*event_type*/) {
    return nullptr;
}

// ---------------------------------------------------------------------------
// GTP-U Paket Kapsülleme (Encapsulation)
// ---------------------------------------------------------------------------

std::vector<uint8_t> GtpuEngine::Encapsulate(TelcoSessionContext* session, 
                                             const uint8_t* inner_pkt, 
                                             size_t inner_len, 
                                             uint16_t seq_num) {
    bool has_seq = (seq_num > 0);
    size_t opt_len = has_seq ? sizeof(GtpuOptFields) : 0;
    size_t gtp_payload_len = opt_len + inner_len;
    size_t gtp_hdr_len = sizeof(GtpuHeader) + opt_len;
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len + inner_len;

    std::vector<uint8_t> frame(total_len, 0);

    // 1. Ethernet Header
    auto* eth = reinterpret_cast<EthHeader*>(frame.data());
    if (session) {
        std::memcpy(eth->dst_mac, session->peer_mac, 6);
        std::memcpy(eth->src_mac, session->client_mac, 6);
    } else {
        std::memset(eth->dst_mac, 0xFF, 6);
    }
    eth->ethertype = htons(0x0800);

    // 2. IPv4 Outer Header
    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->tos = 0;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len + inner_len));
    ip->id = htons(0x4754); // "GT"
    ip->flags_fragment = 0;
    ip->ttl = 64;
    ip->protocol = 17; // UDP
    if (session) {
        ip->src_ip = htonl(session->client_ip);
        ip->dst_ip = htonl(session->peer_ip);
    }
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    // 3. UDP Header
    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(GTPU_PORT);
    udp->dst_port = htons(GTPU_PORT);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + gtp_hdr_len + inner_len));
    udp->checksum = 0; // IPv4 UDP opsiyonel

    // 4. GTP-U Header (3GPP TS 29.281)
    size_t gtp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* gtp = reinterpret_cast<GtpuHeader*>(frame.data() + gtp_offset);
    gtp->flags = GTPU_HDR_BASE_FLAGS | (has_seq ? GTPU_FLAG_S : 0);
    gtp->msg_type = static_cast<uint8_t>(GtpuMessageType::GPdu);
    gtp->length = htons(static_cast<uint16_t>(gtp_payload_len));
    gtp->teid = htonl(session ? session->teid_uplink : 0);

    // Opsiyonel Sequence Number Alanı
    if (has_seq) {
        auto* opt = reinterpret_cast<GtpuOptFields*>(frame.data() + gtp_offset + sizeof(GtpuHeader));
        opt->seq_num = htons(seq_num);
        opt->n_pdu = 0;
        opt->next_ext = 0;
    }

    // 5. İç Yük (Inner T-PDU / IP Packet)
    if (inner_pkt && inner_len > 0) {
        std::memcpy(frame.data() + gtp_offset + gtp_hdr_len, inner_pkt, inner_len);
    }

    if (session) {
        last_tx_frame_ = frame;
        session->tx_packets++;
        session->tx_bytes += frame.size();
    }

    return frame;
}

// ---------------------------------------------------------------------------
// GTP-U Tünel Çözme (Decapsulation)
// ---------------------------------------------------------------------------

bool GtpuEngine::Decapsulate(const uint8_t* frame, size_t len, GtpuDecapInfo& out_info) {
    out_info = {};
    if (!frame || len < (sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(GtpuHeader))) {
        return false;
    }

    size_t offset = 12;
    uint16_t ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
    offset += 2;

    // VLAN/QinQ Atla
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

    if (ethertype != 0x0800) return false;
    if (len < offset + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(GtpuHeader)) return false;

    const auto* ip = reinterpret_cast<const Ipv4Header*>(frame + offset);
    if ((ip->ihl_version >> 4) != 4 || ip->protocol != 17) return false;
    size_t ip_len = (ip->ihl_version & 0x0F) * 4;
    offset += ip_len;

    if (len < offset + sizeof(UdpHeader) + sizeof(GtpuHeader)) return false;
    const auto* udp = reinterpret_cast<const UdpHeader*>(frame + offset);
    uint16_t dst_port = ntohs(udp->dst_port);
    uint16_t src_port = ntohs(udp->src_port);
    if (dst_port != GTPU_PORT && src_port != GTPU_PORT) return false;
    offset += sizeof(UdpHeader);

    if (len < offset + sizeof(GtpuHeader)) return false;
    const auto* gtp = reinterpret_cast<const GtpuHeader*>(frame + offset);

    // 3GPP Sürüm ve Protokol Doğrulaması (Version 1, GTP Proto)
    uint8_t version = (gtp->flags >> 5) & 0x07;
    uint8_t proto_pt = (gtp->flags >> 4) & 0x01;
    if (version != 1 || proto_pt != 1) return false;

    out_info.msg_type = gtp->msg_type;
    out_info.teid = ntohl(gtp->teid);
    uint16_t gtp_payload_len = ntohs(gtp->length);

    offset += sizeof(GtpuHeader);
    bool has_e = (gtp->flags & GTPU_FLAG_E) != 0;
    bool has_s = (gtp->flags & GTPU_FLAG_S) != 0;
    bool has_pn = (gtp->flags & GTPU_FLAG_PN) != 0;

    if (has_e || has_s || has_pn) {
        if (len < offset + sizeof(GtpuOptFields)) return false;
        const auto* opt = reinterpret_cast<const GtpuOptFields*>(frame + offset);
        if (has_s) {
            out_info.has_seq = true;
            out_info.seq_num = ntohs(opt->seq_num);
        }
        offset += sizeof(GtpuOptFields);

        // Uzantı Başlıkları Zinciri
        uint8_t next_ext = opt->next_ext;
        while (next_ext != 0 && offset < len) {
            uint8_t ext_len_octets = frame[offset];
            if (ext_len_octets == 0) break;
            size_t ext_bytes = ext_len_octets * 4;
            if (offset + ext_bytes > len) return false;
            next_ext = frame[offset + ext_bytes - 1];
            offset += ext_bytes;
        }
    }

    if (offset <= len) {
        out_info.payload = frame + offset;
        out_info.payload_len = len - offset;
        (void)gtp_payload_len;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Gelen Paket İşleme (ProcessRxFrame)
// ---------------------------------------------------------------------------

bool GtpuEngine::ProcessRxFrame(const uint8_t* frame, size_t len, TelcoSessionContext* session) {
    GtpuDecapInfo info{};
    if (!Decapsulate(frame, len, info)) {
        return false;
    }

    if (!session) {
        // Demux by TEID (O(1) Hash Lookup)
        if (info.teid != 0) {
            session = session_mgr_.FindGtpuSession(info.teid);
        }
    }

    // 1. G-PDU Veri Düzlemi Paketi (Msg Type 255)
    if (info.msg_type == static_cast<uint8_t>(GtpuMessageType::GPdu)) {
        if (!session) return false; // Bilinmeyen tünel

        session->rx_packets++;
        session->rx_bytes += len;
        session->last_activity_tsc = 1;
        return true;
    }

    // 2. Path Management: Echo Request (Msg Type 1)
    if (info.msg_type == static_cast<uint8_t>(GtpuMessageType::EchoRequest)) {
        uint16_t seq = info.has_seq ? info.seq_num : 0;
        last_tx_frame_ = BuildEchoResponse(session, seq, restart_counter_);
        if (session) {
            session->tx_packets++;
            session->tx_bytes += last_tx_frame_.size();
        }
        return true;
    }

    // 3. Path Management: Echo Response (Msg Type 2)
    if (info.msg_type == static_cast<uint8_t>(GtpuMessageType::EchoResponse)) {
        if (session) {
            SetSubState(session, GtpuSubState::ACTIVE);
            session->retry_count = 0;
            session->rx_packets++;
            session->rx_bytes += len;

            // Reschedule regular heartbeat in Timing Wheel (5s)
            if (timing_wheel_) {
                timing_wheel_->Schedule(session, 5000);
            }
        }
        return true;
    }

    // 4. Error Indication (Msg Type 26) -> Peer UPF has no context for this TEID
    if (info.msg_type == static_cast<uint8_t>(GtpuMessageType::ErrorIndication)) {
        if (session) {
            SetSubState(session, GtpuSubState::FAILED);
            if (timing_wheel_) {
                timing_wheel_->Cancel(session);
            }
        }
        return true;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Canlılık ve Hata Mesaj Üreticileri
// ---------------------------------------------------------------------------

std::vector<uint8_t> GtpuEngine::BuildEchoRequest(TelcoSessionContext* session, uint16_t seq_num) {
    // 3GPP TS 29.281 Section 7.2.1: Echo Request (flags=0x32, TEID=0, SeqNum, Recovery IE)
    // Recovery IE (Type 14 = 0x0E), Restart Counter (1 byte)
    size_t gtp_hdr_len = sizeof(GtpuHeader) + sizeof(GtpuOptFields);
    size_t recovery_ie_len = 2; // Type(1) + RestartCounter(1)
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len + recovery_ie_len;

    std::vector<uint8_t> frame(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(frame.data());
    if (session) {
        std::memcpy(eth->dst_mac, session->peer_mac, 6);
        std::memcpy(eth->src_mac, session->client_mac, 6);
    }
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len + recovery_ie_len));
    ip->id = htons(0x4701);
    ip->ttl = 64;
    ip->protocol = 17;
    if (session) {
        ip->src_ip = htonl(session->client_ip);
        ip->dst_ip = htonl(session->peer_ip);
    }
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(session ? session->client_port : GTPU_PORT);
    udp->dst_port = htons(session ? session->peer_port : GTPU_PORT);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + gtp_hdr_len + recovery_ie_len));

    size_t gtp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* gtp = reinterpret_cast<GtpuHeader*>(frame.data() + gtp_offset);
    gtp->flags = GTPU_HDR_BASE_FLAGS | GTPU_FLAG_S;
    gtp->msg_type = static_cast<uint8_t>(GtpuMessageType::EchoRequest);
    gtp->length = htons(static_cast<uint16_t>(sizeof(GtpuOptFields) + recovery_ie_len));
    gtp->teid = 0; // TEID 0 for path management

    auto* opt = reinterpret_cast<GtpuOptFields*>(frame.data() + gtp_offset + sizeof(GtpuHeader));
    opt->seq_num = htons(seq_num);
    opt->n_pdu = 0;
    opt->next_ext = 0;

    // Recovery IE (Type 14, Restart Counter)
    size_t ie_offset = gtp_offset + gtp_hdr_len;
    frame[ie_offset] = 14;              // Type = 14 (Recovery)
    frame[ie_offset + 1] = restart_counter_; // Restart Counter

    return frame;
}

std::vector<uint8_t> GtpuEngine::BuildEchoResponse(TelcoSessionContext* session, uint16_t seq_num, uint8_t restart_counter) {
    size_t gtp_hdr_len = sizeof(GtpuHeader) + sizeof(GtpuOptFields);
    size_t recovery_ie_len = 2;
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len + recovery_ie_len;

    std::vector<uint8_t> frame(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(frame.data());
    if (session) {
        std::memcpy(eth->dst_mac, session->peer_mac, 6);
        std::memcpy(eth->src_mac, session->client_mac, 6);
    }
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len + recovery_ie_len));
    ip->id = htons(0x4702);
    ip->ttl = 64;
    ip->protocol = 17;
    if (session) {
        ip->src_ip = htonl(session->peer_ip);
        ip->dst_ip = htonl(session->client_ip);
    }
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(session ? session->peer_port : GTPU_PORT);
    udp->dst_port = htons(session ? session->client_port : GTPU_PORT);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + gtp_hdr_len + recovery_ie_len));

    size_t gtp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* gtp = reinterpret_cast<GtpuHeader*>(frame.data() + gtp_offset);
    gtp->flags = GTPU_HDR_BASE_FLAGS | GTPU_FLAG_S;
    gtp->msg_type = static_cast<uint8_t>(GtpuMessageType::EchoResponse);
    gtp->length = htons(static_cast<uint16_t>(sizeof(GtpuOptFields) + recovery_ie_len));
    gtp->teid = 0;

    auto* opt = reinterpret_cast<GtpuOptFields*>(frame.data() + gtp_offset + sizeof(GtpuHeader));
    opt->seq_num = htons(seq_num);
    opt->n_pdu = 0;
    opt->next_ext = 0;

    size_t ie_offset = gtp_offset + gtp_hdr_len;
    frame[ie_offset] = 14;
    frame[ie_offset + 1] = restart_counter;

    return frame;
}

std::vector<uint8_t> GtpuEngine::BuildErrorIndication(TelcoSessionContext* session, uint32_t teid, uint32_t peer_ip) {
    // 3GPP TS 29.281 Section 7.3.1: Error Indication (TEID Data I IE 16, GTP-U Peer Address IE 133)
    // IE 16: Type(1) + TEID(4) = 5 bayt
    // IE 133: Type(1) + Length(2) + IPv4(4) = 7 bayt
    size_t ies_len = 5 + 7;
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(GtpuHeader) + ies_len;

    std::vector<uint8_t> frame(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(frame.data());
    if (session) {
        std::memcpy(eth->dst_mac, session->peer_mac, 6);
        std::memcpy(eth->src_mac, session->client_mac, 6);
    }
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(GtpuHeader) + ies_len));
    ip->id = htons(0x471A);
    ip->ttl = 64;
    ip->protocol = 17;
    if (session) {
        ip->src_ip = htonl(session->client_ip);
        ip->dst_ip = htonl(peer_ip != 0 ? peer_ip : session->peer_ip);
    }
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(GTPU_PORT);
    udp->dst_port = htons(GTPU_PORT);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + sizeof(GtpuHeader) + ies_len));

    size_t gtp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* gtp = reinterpret_cast<GtpuHeader*>(frame.data() + gtp_offset);
    gtp->flags = GTPU_HDR_BASE_FLAGS; // No optional fields
    gtp->msg_type = static_cast<uint8_t>(GtpuMessageType::ErrorIndication);
    gtp->length = htons(static_cast<uint16_t>(ies_len));
    gtp->teid = 0;

    size_t offset = gtp_offset + sizeof(GtpuHeader);
    // IE 16: TEID Data I
    frame[offset++] = 16;
    uint32_t teid_be = htonl(teid);
    std::memcpy(frame.data() + offset, &teid_be, 4);
    offset += 4;

    // IE 133: GTP-U Peer Address
    frame[offset++] = 133;
    uint16_t ip_len_be = htons(4);
    std::memcpy(frame.data() + offset, &ip_len_be, 2);
    offset += 2;
    uint32_t peer_ip_be = htonl(peer_ip != 0 ? peer_ip : (session ? session->peer_ip : 0));
    std::memcpy(frame.data() + offset, &peer_ip_be, 4);

    return frame;
}

} // namespace ddos_samurai::telecom::mobile
