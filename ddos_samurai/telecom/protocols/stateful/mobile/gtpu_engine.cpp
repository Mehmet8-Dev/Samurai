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

struct Ipv6Header {
    uint32_t vtc_flow;
    uint16_t payload_length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
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
      timing_wheel_(wheel) {
    last_tx_frame_.reserve(2048);
}

bool GtpuEngine::Init(const ProtocolConfig& cfg) {
    config_ = cfg;
    if (last_tx_frame_.capacity() < 2048) {
        last_tx_frame_.reserve(2048);
    }
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
        // Canlılık sorgusu zamanı: Echo Request gönder (Zero-allocation into pre-reserved buffer)
        SetSubState(session, GtpuSubState::ECHO_PENDING);
        session->retry_count = 0;

        uint16_t seq = next_seq_num_++;
        last_tx_frame_.resize(128);
        size_t written = BuildEchoRequestInto(session, seq, last_tx_frame_.data(), last_tx_frame_.size());
        last_tx_frame_.resize(written);
        session->tx_packets++;
        session->tx_bytes += written;

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
        last_tx_frame_.resize(128);
        size_t written = BuildEchoRequestInto(session, seq, last_tx_frame_.data(), last_tx_frame_.size());
        last_tx_frame_.resize(written);
        session->tx_packets++;
        session->tx_bytes += written;

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

rte_mbuf* GtpuEngine::BuildTxPacket(rte_mempool* pool, TelcoSessionContext* session, uint16_t event_type) {
    if (!session) return nullptr;
    static const uint8_t inner_payload[28] = {
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0x00, 0x00,
        192, 168, 100, 1, 8, 8, 8, 8,
        0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01
    };

#ifdef SAMURAI_WITH_DPDK
    if (pool) {
        rte_mbuf* m = rte_pktmbuf_alloc(pool);
        if (!m) return nullptr;

        const size_t tailroom = rte_pktmbuf_tailroom(m);
        uint8_t* dst = rte_pktmbuf_mtod(m, uint8_t*);
        size_t written = 0;

        if (event_type == 1) { // GTP-U Echo Request (zero-allocation direct into mbuf)
            written = BuildEchoRequestInto(session, next_seq_num_++, dst, tailroom);
            if (written > 0) {
                session->tx_packets++;
                session->tx_bytes += written;
            }
        } else {
            written = EncapsulateInto(session, inner_payload, sizeof(inner_payload), dst, tailroom, next_seq_num_++);
        }

        if (written == 0 || !rte_pktmbuf_append(m, static_cast<uint16_t>(written))) {
            rte_pktmbuf_free(m);
            return nullptr;
        }
        last_tx_frame_.assign(dst, dst + written);
        return m;
    }
#else
    (void)pool;
#endif
    // Pool verilmediğinde önceden rezerve edilmiş last_tx_frame_ içine zero-heap-alloc yaz
    last_tx_frame_.resize(256);
    size_t written = 0;
    if (event_type == 1) {
        written = BuildEchoRequestInto(session, next_seq_num_++, last_tx_frame_.data(), last_tx_frame_.size());
        if (written > 0) {
            session->tx_packets++;
            session->tx_bytes += written;
        }
    } else {
        written = EncapsulateInto(session, inner_payload, sizeof(inner_payload),
                                  last_tx_frame_.data(), last_tx_frame_.size(), next_seq_num_++);
    }
    last_tx_frame_.resize(written);
    return nullptr;
}

// ---------------------------------------------------------------------------
// GTP-U Paket Kapsülleme (Encapsulation - Zero-Allocation Buffer & Vector API)
// ---------------------------------------------------------------------------

size_t GtpuEngine::EncapsulateInto(TelcoSessionContext* session,
                                   const uint8_t* inner_pkt,
                                   size_t inner_len,
                                   uint8_t* out_buf,
                                   size_t max_len,
                                   uint16_t seq_num) noexcept {
    if (!out_buf) return 0;
    const bool has_seq = (seq_num > 0);
    const size_t opt_len = has_seq ? sizeof(GtpuOptFields) : 0;
    const size_t gtp_payload_len = opt_len + inner_len;
    const size_t gtp_hdr_len = sizeof(GtpuHeader) + opt_len;
    const size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len + inner_len;
    if (max_len < total_len) return 0;

    std::memset(out_buf, 0, sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len);

    // 1. Ethernet Header
    auto* eth = reinterpret_cast<EthHeader*>(out_buf);
    if (session) {
        std::memcpy(eth->dst_mac, session->peer_mac, 6);
        std::memcpy(eth->src_mac, session->client_mac, 6);
    } else {
        std::memset(eth->dst_mac, 0xFF, 6);
    }
    eth->ethertype = htons(0x0800);

    // 2. IPv4 Outer Header
    auto* ip = reinterpret_cast<Ipv4Header*>(out_buf + sizeof(EthHeader));
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
    auto* udp = reinterpret_cast<UdpHeader*>(out_buf + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(GTPU_PORT);
    udp->dst_port = htons(GTPU_PORT);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + gtp_hdr_len + inner_len));
    udp->checksum = 0;

    // 4. GTP-U Header (3GPP TS 29.281)
    const size_t gtp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* gtp = reinterpret_cast<GtpuHeader*>(out_buf + gtp_offset);
    gtp->flags = GTPU_HDR_BASE_FLAGS | (has_seq ? GTPU_FLAG_S : 0);
    gtp->msg_type = static_cast<uint8_t>(GtpuMessageType::GPdu);
    gtp->length = htons(static_cast<uint16_t>(gtp_payload_len));
    gtp->teid = htonl(session ? session->teid_uplink : 0);

    if (has_seq) {
        auto* opt = reinterpret_cast<GtpuOptFields*>(out_buf + gtp_offset + sizeof(GtpuHeader));
        opt->seq_num = htons(seq_num);
        opt->n_pdu = 0;
        opt->next_ext = 0;
    }

    // 5. İç Yük (Inner T-PDU / IP Packet)
    if (inner_pkt && inner_len > 0) {
        std::memcpy(out_buf + gtp_offset + gtp_hdr_len, inner_pkt, inner_len);
    }

    if (session) {
        session->tx_packets++;
        session->tx_bytes += total_len;
    }

    return total_len;
}

std::vector<uint8_t> GtpuEngine::Encapsulate(TelcoSessionContext* session, 
                                             const uint8_t* inner_pkt, 
                                             size_t inner_len, 
                                             uint16_t seq_num) {
    const bool has_seq = (seq_num > 0);
    const size_t opt_len = has_seq ? sizeof(GtpuOptFields) : 0;
    const size_t gtp_hdr_len = sizeof(GtpuHeader) + opt_len;
    const size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len + inner_len;

    std::vector<uint8_t> frame(total_len, 0);
    const size_t written = EncapsulateInto(session, inner_pkt, inner_len, frame.data(), frame.size(), seq_num);
    frame.resize(written);
    if (session) {
        last_tx_frame_ = frame;
    }
    return frame;
}

// ---------------------------------------------------------------------------
// GTP-U Tünel Çözme (Decapsulation)
// ---------------------------------------------------------------------------

bool GtpuEngine::Decapsulate(const uint8_t* frame, size_t len, GtpuDecapInfo& out_info) {
    out_info = {};
    if (!frame || len < sizeof(GtpuHeader)) {
        return false;
    }

    size_t offset = 0;

    // Check if packet starts directly with a GTP-U header (payload pointer from upper layer)
    bool is_direct_gtp = false;
    if (len >= sizeof(GtpuHeader)) {
        uint8_t flags = frame[0];
        uint8_t version = (flags >> 5) & 0x07;
        uint8_t proto_pt = (flags >> 4) & 0x01;
        if (version == 1 && proto_pt == 1) {
            // Check if not an Ethernet header
            if (len < 14) {
                is_direct_gtp = true;
            } else {
                uint16_t eth_cand = (static_cast<uint16_t>(frame[12]) << 8) | frame[13];
                if (eth_cand != 0x0800 && eth_cand != 0x86DD && eth_cand != 0x8100 && eth_cand != 0x88A8) {
                    is_direct_gtp = true;
                }
            }
        }
    }

    if (!is_direct_gtp) {
        if (len < 14) return false;
        offset = 12;
        uint16_t ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
        offset += 2;

        // VLAN/QinQ
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

        if (ethertype == 0x0800) {
            if (len < offset + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(GtpuHeader)) return false;
            const auto* ip = reinterpret_cast<const Ipv4Header*>(frame + offset);
            if ((ip->ihl_version >> 4) != 4 || (ip->ihl_version & 0x0F) < 5 || ip->protocol != 17) return false;
            size_t ip_len = (ip->ihl_version & 0x0F) * 4;
            offset += ip_len;

            if (len < offset + sizeof(UdpHeader) + sizeof(GtpuHeader)) return false;
            const auto* udp = reinterpret_cast<const UdpHeader*>(frame + offset);
            uint16_t dst_port = ntohs(udp->dst_port);
            uint16_t src_port = ntohs(udp->src_port);
            if (dst_port != GTPU_PORT && src_port != GTPU_PORT) return false;
            offset += sizeof(UdpHeader);
        } else if (ethertype == 0x86DD) {
            if (len < offset + sizeof(Ipv6Header) + sizeof(UdpHeader) + sizeof(GtpuHeader)) return false;
            const auto* ip6 = reinterpret_cast<const Ipv6Header*>(frame + offset);
            if (ip6->next_header != 17) return false;
            offset += sizeof(Ipv6Header);

            if (len < offset + sizeof(UdpHeader) + sizeof(GtpuHeader)) return false;
            const auto* udp = reinterpret_cast<const UdpHeader*>(frame + offset);
            uint16_t dst_port = ntohs(udp->dst_port);
            uint16_t src_port = ntohs(udp->src_port);
            if (dst_port != GTPU_PORT && src_port != GTPU_PORT) return false;
            offset += sizeof(UdpHeader);
        } else {
            return false;
        }
    }

    size_t gtp_start = offset;
    if (len < gtp_start + sizeof(GtpuHeader)) return false;
    const auto* gtp = reinterpret_cast<const GtpuHeader*>(frame + gtp_start);

    // 3GPP Sürüm ve Protokol Doğrulaması (Version 1, GTP Proto)
    uint8_t version = (gtp->flags >> 5) & 0x07;
    uint8_t proto_pt = (gtp->flags >> 4) & 0x01;
    if (version != 1 || proto_pt != 1) return false;

    out_info.msg_type = gtp->msg_type;
    out_info.teid = ntohl(gtp->teid);
    uint16_t gtp_payload_len = ntohs(gtp->length);

    // Wire length check: frame MUST contain at least the claimed GTP payload
    if (len < gtp_start + sizeof(GtpuHeader) + gtp_payload_len) return false;

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
        uint32_t ext_count = 0;
        while (next_ext != 0 && offset < len) {
            if (++ext_count > 16) return false; // Prevent malformed infinite loops
            uint8_t ext_len_octets = frame[offset];
            if (ext_len_octets == 0) return false;
            size_t ext_bytes = ext_len_octets * 4;
            if (offset + ext_bytes > len) return false;
            next_ext = frame[offset + ext_bytes - 1];
            offset += ext_bytes;
        }
    }

    size_t hdr_and_opts = offset - (gtp_start + sizeof(GtpuHeader));
    if (gtp_payload_len < hdr_and_opts) return false;

    size_t inner_len = gtp_payload_len - hdr_and_opts;
    if (offset + inner_len > len) return false;

    out_info.payload = frame + offset;
    out_info.payload_len = inner_len;

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
        if (info.teid == 0) return false; // 3GPP TS 29.281: G-PDU TEID must not be 0
        if (!session) return false; // Bilinmeyen tünel

        session->rx_packets++;
        session->rx_bytes += len;
        session->last_activity_tsc = 1;
        return true;
    }

    // 2. Path Management: Echo Request (Msg Type 1)
    if (info.msg_type == static_cast<uint8_t>(GtpuMessageType::EchoRequest)) {
        uint16_t seq = info.has_seq ? info.seq_num : 0;
        last_tx_frame_.resize(128);
        size_t written = BuildEchoResponseInto(session, seq, restart_counter_, last_tx_frame_.data(), last_tx_frame_.size());
        last_tx_frame_.resize(written);
        if (session) {
            session->tx_packets++;
            session->tx_bytes += written;
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
// Canlılık ve Hata Mesaj Üreticileri (Zero-Allocation Buffer & Vector API)
// ---------------------------------------------------------------------------

size_t GtpuEngine::BuildEchoRequestInto(TelcoSessionContext* session,
                                        uint16_t seq_num,
                                        uint8_t* out_buf,
                                        size_t max_len) noexcept {
    if (!out_buf) return 0;
    const size_t gtp_hdr_len = sizeof(GtpuHeader) + sizeof(GtpuOptFields);
    const size_t recovery_ie_len = 2; // Type(1) + RestartCounter(1)
    const size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len + recovery_ie_len;
    if (max_len < total_len) return 0;

    std::memset(out_buf, 0, total_len);

    auto* eth = reinterpret_cast<EthHeader*>(out_buf);
    if (session) {
        std::memcpy(eth->dst_mac, session->peer_mac, 6);
        std::memcpy(eth->src_mac, session->client_mac, 6);
    }
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(out_buf + sizeof(EthHeader));
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

    auto* udp = reinterpret_cast<UdpHeader*>(out_buf + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(session ? session->client_port : GTPU_PORT);
    udp->dst_port = htons(session ? session->peer_port : GTPU_PORT);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + gtp_hdr_len + recovery_ie_len));

    const size_t gtp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* gtp = reinterpret_cast<GtpuHeader*>(out_buf + gtp_offset);
    gtp->flags = GTPU_HDR_BASE_FLAGS | GTPU_FLAG_S;
    gtp->msg_type = static_cast<uint8_t>(GtpuMessageType::EchoRequest);
    gtp->length = htons(static_cast<uint16_t>(sizeof(GtpuOptFields) + recovery_ie_len));
    gtp->teid = 0;

    auto* opt = reinterpret_cast<GtpuOptFields*>(out_buf + gtp_offset + sizeof(GtpuHeader));
    opt->seq_num = htons(seq_num);
    opt->n_pdu = 0;
    opt->next_ext = 0;

    const size_t ie_offset = gtp_offset + gtp_hdr_len;
    out_buf[ie_offset] = 14;              // Type = 14 (Recovery)
    out_buf[ie_offset + 1] = restart_counter_;
    return total_len;
}

std::vector<uint8_t> GtpuEngine::BuildEchoRequest(TelcoSessionContext* session, uint16_t seq_num) {
    const size_t gtp_hdr_len = sizeof(GtpuHeader) + sizeof(GtpuOptFields);
    const size_t recovery_ie_len = 2;
    const size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len + recovery_ie_len;
    std::vector<uint8_t> frame(total_len, 0);
    const size_t written = BuildEchoRequestInto(session, seq_num, frame.data(), frame.size());
    frame.resize(written);
    return frame;
}

size_t GtpuEngine::BuildEchoResponseInto(TelcoSessionContext* session,
                                         uint16_t seq_num,
                                         uint8_t restart_counter,
                                         uint8_t* out_buf,
                                         size_t max_len) noexcept {
    if (!out_buf) return 0;
    const size_t gtp_hdr_len = sizeof(GtpuHeader) + sizeof(GtpuOptFields);
    const size_t recovery_ie_len = 2;
    const size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len + recovery_ie_len;
    if (max_len < total_len) return 0;

    std::memset(out_buf, 0, total_len);

    auto* eth = reinterpret_cast<EthHeader*>(out_buf);
    if (session) {
        std::memcpy(eth->dst_mac, session->peer_mac, 6);
        std::memcpy(eth->src_mac, session->client_mac, 6);
    }
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(out_buf + sizeof(EthHeader));
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

    auto* udp = reinterpret_cast<UdpHeader*>(out_buf + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(session ? session->peer_port : GTPU_PORT);
    udp->dst_port = htons(session ? session->client_port : GTPU_PORT);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + gtp_hdr_len + recovery_ie_len));

    const size_t gtp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* gtp = reinterpret_cast<GtpuHeader*>(out_buf + gtp_offset);
    gtp->flags = GTPU_HDR_BASE_FLAGS | GTPU_FLAG_S;
    gtp->msg_type = static_cast<uint8_t>(GtpuMessageType::EchoResponse);
    gtp->length = htons(static_cast<uint16_t>(sizeof(GtpuOptFields) + recovery_ie_len));
    gtp->teid = 0;

    auto* opt = reinterpret_cast<GtpuOptFields*>(out_buf + gtp_offset + sizeof(GtpuHeader));
    opt->seq_num = htons(seq_num);
    opt->n_pdu = 0;
    opt->next_ext = 0;

    const size_t ie_offset = gtp_offset + gtp_hdr_len;
    out_buf[ie_offset] = 14;
    out_buf[ie_offset + 1] = restart_counter;
    return total_len;
}

std::vector<uint8_t> GtpuEngine::BuildEchoResponse(TelcoSessionContext* session, uint16_t seq_num, uint8_t restart_counter) {
    const size_t gtp_hdr_len = sizeof(GtpuHeader) + sizeof(GtpuOptFields);
    const size_t recovery_ie_len = 2;
    const size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + gtp_hdr_len + recovery_ie_len;
    std::vector<uint8_t> frame(total_len, 0);
    const size_t written = BuildEchoResponseInto(session, seq_num, restart_counter, frame.data(), frame.size());
    frame.resize(written);
    return frame;
}

size_t GtpuEngine::BuildErrorIndicationInto(TelcoSessionContext* session,
                                            uint32_t teid,
                                            uint32_t peer_ip,
                                            uint8_t* out_buf,
                                            size_t max_len) noexcept {
    if (!out_buf) return 0;
    const size_t ies_len = 5 + 7;
    const size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(GtpuHeader) + ies_len;
    if (max_len < total_len) return 0;

    std::memset(out_buf, 0, total_len);

    auto* eth = reinterpret_cast<EthHeader*>(out_buf);
    if (session) {
        std::memcpy(eth->dst_mac, session->peer_mac, 6);
        std::memcpy(eth->src_mac, session->client_mac, 6);
    }
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(out_buf + sizeof(EthHeader));
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

    auto* udp = reinterpret_cast<UdpHeader*>(out_buf + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(GTPU_PORT);
    udp->dst_port = htons(GTPU_PORT);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + sizeof(GtpuHeader) + ies_len));

    const size_t gtp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* gtp = reinterpret_cast<GtpuHeader*>(out_buf + gtp_offset);
    gtp->flags = GTPU_HDR_BASE_FLAGS;
    gtp->msg_type = static_cast<uint8_t>(GtpuMessageType::ErrorIndication);
    gtp->length = htons(static_cast<uint16_t>(ies_len));
    gtp->teid = 0;

    size_t offset = gtp_offset + sizeof(GtpuHeader);
    out_buf[offset++] = 16;
    const uint32_t teid_be = htonl(teid);
    std::memcpy(out_buf + offset, &teid_be, 4);
    offset += 4;

    out_buf[offset++] = 133;
    const uint16_t ip_len_be = htons(4);
    std::memcpy(out_buf + offset, &ip_len_be, 2);
    offset += 2;
    const uint32_t peer_ip_be = htonl(peer_ip != 0 ? peer_ip : (session ? session->peer_ip : 0));
    std::memcpy(out_buf + offset, &peer_ip_be, 4);

    return total_len;
}

std::vector<uint8_t> GtpuEngine::BuildErrorIndication(TelcoSessionContext* session, uint32_t teid, uint32_t peer_ip) {
    const size_t ies_len = 5 + 7;
    const size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(GtpuHeader) + ies_len;
    std::vector<uint8_t> frame(total_len, 0);
    const size_t written = BuildErrorIndicationInto(session, teid, peer_ip, frame.data(), frame.size());
    frame.resize(written);
    return frame;
}

} // namespace ddos_samurai::telecom::mobile
