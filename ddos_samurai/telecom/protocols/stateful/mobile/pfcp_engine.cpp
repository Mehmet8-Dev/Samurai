#include "pfcp_engine.hpp"

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

inline void SetSeq24(uint8_t out[3], uint32_t seq) {
    out[0] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    out[1] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>(seq & 0xFF);
}

inline uint32_t GetSeq24(const uint8_t in[3]) {
    return (static_cast<uint32_t>(in[0]) << 16) |
           (static_cast<uint32_t>(in[1]) << 8) |
           static_cast<uint32_t>(in[2]);
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
inline uint64_t Hton64(uint64_t val) { return __builtin_bswap64(val); }
inline uint64_t Ntoh64(uint64_t val) { return __builtin_bswap64(val); }
#else
inline uint64_t Hton64(uint64_t val) { return val; }
inline uint64_t Ntoh64(uint64_t val) { return val; }
#endif

void AppendIe(std::vector<uint8_t>& buf, PfcpIeType type, const uint8_t* val, uint16_t len) {
    uint16_t t_be = htons(static_cast<uint16_t>(type));
    uint16_t l_be = htons(len);
    const auto* t_ptr = reinterpret_cast<const uint8_t*>(&t_be);
    const auto* l_ptr = reinterpret_cast<const uint8_t*>(&l_be);
    buf.insert(buf.end(), t_ptr, t_ptr + 2);
    buf.insert(buf.end(), l_ptr, l_ptr + 2);
    if (val && len > 0) {
        buf.insert(buf.end(), val, val + len);
    }
}

void ScanIe(const uint8_t* data, size_t len, PfcpDecapInfo& out_info, uint32_t depth = 0) {
    if (depth > 8) return; // Recursion depth safeguard against malformed loops
    size_t curr = 0;
    while (curr + sizeof(PfcpIeHeader) <= len) {
        uint16_t ie_type = (static_cast<uint16_t>(data[curr]) << 8) | data[curr + 1];
        uint16_t ie_len = (static_cast<uint16_t>(data[curr + 2]) << 8) | data[curr + 3];
        curr += sizeof(PfcpIeHeader);
        if (curr + ie_len > len) break;

        const uint8_t* val = data + curr;

        if (ie_type == static_cast<uint16_t>(PfcpIeType::Cause) && ie_len >= 1) {
            out_info.cause = val[0];
            out_info.has_cause = true;
        } else if (ie_type == static_cast<uint16_t>(PfcpIeType::FSeid) && ie_len >= 9) {
            uint8_t flags = val[0];
            if ((flags & 0x03) != 0) { // 3GPP TS 29.244: Flags bit 1=V6, bit 2=V4 (SEID is always 8 bytes)
                out_info.has_f_seid = true;
                uint64_t raw_seid = 0;
                std::memcpy(&raw_seid, val + 1, 8);
                out_info.f_seid = Ntoh64(raw_seid);
            }
        } else if (ie_type == static_cast<uint16_t>(PfcpIeType::PdrId) && ie_len >= 2) {
            out_info.pdr_id = (static_cast<uint16_t>(val[0]) << 8) | val[1];
        } else if (ie_type == static_cast<uint16_t>(PfcpIeType::FarId) && ie_len >= 4) {
            uint32_t raw_fid = 0;
            std::memcpy(&raw_fid, val, 4);
            out_info.far_id = ntohl(raw_fid);
        } else if (ie_type == static_cast<uint16_t>(PfcpIeType::FTeid) && ie_len >= 5) {
            uint8_t flags = val[0];
            if (!(flags & 0x04)) { // CH (Choose) flag not set -> TEID present
                out_info.has_f_teid = true;
                uint32_t raw_teid = 0;
                std::memcpy(&raw_teid, val + 1, 4);
                out_info.f_teid = ntohl(raw_teid);
            }
        } else if (ie_type == static_cast<uint16_t>(PfcpIeType::UeIpAddress) && ie_len >= 5) {
            uint8_t flags = val[0];
            if (flags & 0x02) { // V4 present
                out_info.has_ue_ip = true;
                uint32_t raw_ue = 0;
                std::memcpy(&raw_ue, val + 1, 4);
                out_info.ue_ip = ntohl(raw_ue);
            }
        } else if (ie_type == static_cast<uint16_t>(PfcpIeType::CreatePdr) ||
                   ie_type == static_cast<uint16_t>(PfcpIeType::Pdi) ||
                   ie_type == static_cast<uint16_t>(PfcpIeType::CreateFar) ||
                   ie_type == static_cast<uint16_t>(PfcpIeType::ForwardingParameters) ||
                   ie_type == static_cast<uint16_t>(PfcpIeType::UpdateFar)) {
            ScanIe(val, ie_len, out_info, depth + 1);
        }

        curr += ie_len;
    }
}

} // namespace

PfcpEngine::PfcpEngine(SessionManager& session_mgr, HierarchicalTimingWheel* wheel)
    : session_mgr_(session_mgr),
      timing_wheel_(wheel) {}

bool PfcpEngine::Init(const ProtocolConfig& cfg) {
    config_ = cfg;
    return true;
}

void PfcpEngine::Shutdown() {
    uint32_t cap = session_mgr_.GetCapacity();
    for (uint32_t i = 0; i < cap; ++i) {
        TelcoSessionContext* s = session_mgr_.GetSessionByIndex(i);
        if (s && s->protocol_id == static_cast<uint8_t>(TelcoProtocolId::PFCP)) {
            if (timing_wheel_) {
                timing_wheel_->Cancel(s);
            }
            session_mgr_.UnbindPfcpSession(s);
            session_mgr_.ReleaseSession(s);
        }
    }
    is_associated_ = false;
}

PfcpSubState PfcpEngine::GetSubState(const TelcoSessionContext* session) const noexcept {
    if (!session) return PfcpSubState::IDLE;
    return static_cast<PfcpSubState>(session->ppp_lcp_identifier);
}

void PfcpEngine::SetSubState(TelcoSessionContext* session, PfcpSubState state) noexcept {
    if (!session) return;
    session->ppp_lcp_identifier = static_cast<uint16_t>(state);
    switch (state) {
        case PfcpSubState::ESTABLISHED:
            session->state = SessionState::ESTABLISHED;
            break;
        case PfcpSubState::ASSOC_PENDING:
        case PfcpSubState::SESSION_ESTAB_PENDING:
        case PfcpSubState::SESSION_MOD_PENDING:
            session->state = SessionState::DISCOVERING;
            break;
        case PfcpSubState::SESSION_DEL_PENDING:
            session->state = SessionState::TERMINATING;
            break;
        case PfcpSubState::RELEASED:
            session->state = SessionState::IDLE;
            break;
        case PfcpSubState::FAILED:
            session->state = SessionState::FAILED;
            break;
        default:
            session->state = SessionState::IDLE;
            break;
    }
}

void PfcpEngine::StartAssociation(const PfcpConfig& cfg) {
    pfcp_cfg_ = cfg;
    is_associated_ = false;

    // Send Association Setup Request
    last_tx_frame_ = BuildAssociationSetupRequest(next_seq_++, cfg.local_node_id, cfg.local_ip);
}

void PfcpEngine::EstablishSession(TelcoSessionContext* session, 
                                  uint64_t cp_seid, 
                                  const PfcpPdr& pdr, 
                                  const PfcpFar& far) {
    if (!session) return;

    session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::PFCP);
    session->SetPfcpSeid(cp_seid);
    session->teid_uplink = pdr.teid;
    session->teid_downlink = far.outer_teid;
    session->client_ip = pdr.ue_ip != 0 ? pdr.ue_ip : pfcp_cfg_.local_ip;
    session->peer_ip = pfcp_cfg_.remote_upf_ip;
    session->client_port = pfcp_cfg_.local_port;
    session->peer_port = pfcp_cfg_.remote_port;
    session->ip_proto = 17;
    session->retry_count = 0;

    std::memcpy(session->client_mac, pfcp_cfg_.local_mac, 6);
    std::memcpy(session->peer_mac, pfcp_cfg_.remote_mac, 6);

    last_pdr_ = pdr;
    last_far_ = far;

    // Bind SEID in SessionManager
    session_mgr_.BindPfcpSession(session, cp_seid);

    SetSubState(session, PfcpSubState::SESSION_ESTAB_PENDING);
    last_tx_frame_ = BuildSessionEstablishmentRequest(session, next_seq_++, cp_seid, pdr, far);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    if (timing_wheel_) {
        timing_wheel_->Schedule(session, config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 500);
    }
}

void PfcpEngine::ModifySession(TelcoSessionContext* session, const PfcpFar& updated_far) {
    if (!session || GetSubState(session) != PfcpSubState::ESTABLISHED) return;

    SetSubState(session, PfcpSubState::SESSION_MOD_PENDING);
    last_far_ = updated_far;
    session->teid_downlink = updated_far.outer_teid;

    last_tx_frame_ = BuildSessionModificationRequest(session, next_seq_++, updated_far);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    if (timing_wheel_) {
        timing_wheel_->Schedule(session, config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 500);
    }
}

void PfcpEngine::DeleteSession(TelcoSessionContext* session) {
    if (!session) return;

    if (timing_wheel_) {
        timing_wheel_->Cancel(session);
    }

    SetSubState(session, PfcpSubState::SESSION_DEL_PENDING);
    last_tx_frame_ = BuildSessionDeletionRequest(session, next_seq_++);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();
}

void PfcpEngine::HandleTimeout(TelcoSessionContext* session) {
    if (!session) return;

    PfcpSubState sub = GetSubState(session);

    if (sub == PfcpSubState::SESSION_ESTAB_PENDING || 
        sub == PfcpSubState::SESSION_MOD_PENDING || 
        sub == PfcpSubState::SESSION_DEL_PENDING) {

        session->retry_count++;
        if (session->retry_count >= config_.max_retries) {
            SetSubState(session, PfcpSubState::FAILED);
            if (timing_wheel_) {
                timing_wheel_->Cancel(session);
            }
            return;
        }

        // Retransmit
        if (sub == PfcpSubState::SESSION_ESTAB_PENDING) {
            last_tx_frame_ = BuildSessionEstablishmentRequest(session, next_seq_++, session->GetPfcpSeid(), last_pdr_, last_far_);
        } else if (sub == PfcpSubState::SESSION_MOD_PENDING) {
            last_tx_frame_ = BuildSessionModificationRequest(session, next_seq_++, last_far_);
        } else {
            last_tx_frame_ = BuildSessionDeletionRequest(session, next_seq_++);
        }

        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();

        uint32_t backoff_ms = (config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 500) * (1 << session->retry_count);
        if (timing_wheel_) {
            timing_wheel_->Schedule(session, backoff_ms);
        }
    }
}

uint32_t PfcpEngine::OnTimerTick(uint64_t current_tsc) {
    if (!timing_wheel_) return 0;
    return timing_wheel_->Advance(current_tsc, [this](TelcoSessionContext* s) {
        HandleTimeout(s);
    });
}

void PfcpEngine::OnRxPacket(rte_mbuf* /*mbuf*/, const PacketMetadata& meta, TelcoSessionContext* session) {
    if (meta.raw_frame && meta.raw_len >= 14) {
        ProcessRxFrame(meta.raw_frame, meta.raw_len, session);
    } else if (meta.payload_ptr && meta.payload_len > 0) {
        ProcessRxFrame(meta.payload_ptr, meta.payload_len, session);
    }
}

rte_mbuf* PfcpEngine::BuildTxPacket(rte_mempool* /*pool*/, TelcoSessionContext* /*session*/, uint16_t /*event_type*/) {
    return nullptr;
}

// ---------------------------------------------------------------------------
// Gelen Paket Ayrıştırma (ParsePfcpPacket)
// ---------------------------------------------------------------------------

bool PfcpEngine::ParsePfcpPacket(const uint8_t* frame, size_t len, PfcpDecapInfo& out_info) {
    out_info = {};
    if (!frame || len < sizeof(PfcpNodeHeader)) {
        return false;
    }

    size_t offset = 0;

    // Direct PFCP payload detection
    bool is_direct_pfcp = false;
    if (len >= sizeof(PfcpNodeHeader)) {
        uint8_t flags = frame[0];
        uint8_t version = (flags >> 5) & 0x07;
        if (version == 1) {
            if (len < 14) {
                is_direct_pfcp = true;
            } else {
                uint16_t eth_cand = (static_cast<uint16_t>(frame[12]) << 8) | frame[13];
                if (eth_cand != 0x0800 && eth_cand != 0x86DD && eth_cand != 0x8100 && eth_cand != 0x88A8) {
                    is_direct_pfcp = true;
                }
            }
        }
    }

    if (!is_direct_pfcp) {
        if (len < 14) return false;
        offset = 12;
        uint16_t ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
        offset += 2;

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
            if (len < offset + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(PfcpNodeHeader)) return false;
            const auto* ip = reinterpret_cast<const Ipv4Header*>(frame + offset);
            if ((ip->ihl_version >> 4) != 4 || (ip->ihl_version & 0x0F) < 5 || ip->protocol != 17) return false;
            size_t ip_len = (ip->ihl_version & 0x0F) * 4;
            offset += ip_len;

            if (len < offset + sizeof(UdpHeader) + sizeof(PfcpNodeHeader)) return false;
            const auto* udp = reinterpret_cast<const UdpHeader*>(frame + offset);
            uint16_t dst_port = ntohs(udp->dst_port);
            uint16_t src_port = ntohs(udp->src_port);
            if (dst_port != PFCP_PORT && src_port != PFCP_PORT) return false;
            offset += sizeof(UdpHeader);
        } else if (ethertype == 0x86DD) {
            if (len < offset + sizeof(Ipv6Header) + sizeof(UdpHeader) + sizeof(PfcpNodeHeader)) return false;
            const auto* ip6 = reinterpret_cast<const Ipv6Header*>(frame + offset);
            if (ip6->next_header != 17) return false;
            offset += sizeof(Ipv6Header);

            if (len < offset + sizeof(UdpHeader) + sizeof(PfcpNodeHeader)) return false;
            const auto* udp = reinterpret_cast<const UdpHeader*>(frame + offset);
            uint16_t dst_port = ntohs(udp->dst_port);
            uint16_t src_port = ntohs(udp->src_port);
            if (dst_port != PFCP_PORT && src_port != PFCP_PORT) return false;
            offset += sizeof(UdpHeader);
        } else {
            return false;
        }
    }

    size_t pfcp_start = offset;
    if (len < pfcp_start + sizeof(PfcpNodeHeader)) return false;

    uint8_t flags = frame[pfcp_start];
    uint8_t version = (flags >> 5) & 0x07;
    if (version != 1) return false;

    bool has_s = (flags & 0x01) != 0;
    out_info.is_session = has_s;
    out_info.msg_type = frame[pfcp_start + 1];

    uint16_t pfcp_len = (static_cast<uint16_t>(frame[pfcp_start + 2]) << 8) | frame[pfcp_start + 3];
    // 3GPP TS 29.244: length covers 4 octets following first 4 octets
    if (len < pfcp_start + 4 + pfcp_len) return false; // Truncated frame!

    size_t hdr_size = has_s ? sizeof(PfcpSessionHeader) : sizeof(PfcpNodeHeader);
    if (static_cast<size_t>(pfcp_len + 4) < hdr_size) return false;

    if (has_s) {
        const auto* s_hdr = reinterpret_cast<const PfcpSessionHeader*>(frame + pfcp_start);
        uint64_t raw_seid = 0;
        std::memcpy(&raw_seid, &s_hdr->seid, 8);
        out_info.seid = Ntoh64(raw_seid);
        out_info.seq_num = GetSeq24(s_hdr->seq_num);
    } else {
        const auto* n_hdr = reinterpret_cast<const PfcpNodeHeader*>(frame + pfcp_start);
        out_info.seid = 0;
        out_info.seq_num = GetSeq24(n_hdr->seq_num);
    }

    offset = pfcp_start + hdr_size;
    size_t ie_payload_len = (pfcp_start + 4 + pfcp_len) - offset;
    out_info.payload = frame + offset;
    out_info.payload_len = ie_payload_len;

    // Parse TLV IEs recursively bounded strictly by claimed PFCP message length
    ScanIe(frame + offset, ie_payload_len, out_info);

    return true;
}

// ---------------------------------------------------------------------------
// Gelen Paket İşleme (ProcessRxFrame)
// ---------------------------------------------------------------------------

bool PfcpEngine::ProcessRxFrame(const uint8_t* frame, size_t len, TelcoSessionContext* session) {
    PfcpDecapInfo info{};
    if (!ParsePfcpPacket(frame, len, info)) {
        return false;
    }

    // Node-Level Mesajlar (S = 0)
    if (!info.is_session) {
        if (info.msg_type == static_cast<uint8_t>(PfcpMessageType::AssociationSetupResponse)) {
            if (info.has_cause && info.cause == static_cast<uint8_t>(PfcpCause::RequestAccepted)) {
                is_associated_ = true;
            }
            return true;
        }
        if (info.msg_type == static_cast<uint8_t>(PfcpMessageType::HeartbeatRequest)) {
            last_tx_frame_ = BuildHeartbeatResponse(info.seq_num, recovery_timestamp_);
            return true;
        }
        if (info.msg_type == static_cast<uint8_t>(PfcpMessageType::HeartbeatResponse)) {
            return true;
        }
    }

    // Session-Level Mesajlar (S = 1)
    if (!session && info.seid != 0) {
        session = session_mgr_.FindPfcpSession(info.seid);
    }
    if (!session) return false;

    session->rx_packets++;
    session->rx_bytes += len;
    session->last_activity_tsc = 1;

    if (info.msg_type == static_cast<uint8_t>(PfcpMessageType::SessionEstablishmentResponse)) {
        if (info.has_cause && info.cause == static_cast<uint8_t>(PfcpCause::RequestAccepted)) {
            SetSubState(session, PfcpSubState::ESTABLISHED);
            if (info.has_f_seid) {
                // Store UPF assigned SEID in Remote SEID (Preserve downlink TEID!)
                session->SetPfcpRemoteSeid(info.f_seid);
            }
            if (timing_wheel_) {
                timing_wheel_->Schedule(session, pfcp_cfg_.heartbeat_interval_ms);
            }
        } else {
            SetSubState(session, PfcpSubState::FAILED);
        }
        return true;
    }

    if (info.msg_type == static_cast<uint8_t>(PfcpMessageType::SessionModificationResponse)) {
        if (info.has_cause && info.cause == static_cast<uint8_t>(PfcpCause::RequestAccepted)) {
            SetSubState(session, PfcpSubState::ESTABLISHED);
        }
        return true;
    }

    if (info.msg_type == static_cast<uint8_t>(PfcpMessageType::SessionDeletionResponse)) {
        if (!info.has_cause || info.cause == static_cast<uint8_t>(PfcpCause::RequestAccepted)) {
            SetSubState(session, PfcpSubState::RELEASED);
            session_mgr_.UnbindPfcpSession(session);
        } else {
            SetSubState(session, PfcpSubState::FAILED);
        }
        return true;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Düğüm Düzeyi Paket Üreticileri (S = 0)
// ---------------------------------------------------------------------------

std::vector<uint8_t> PfcpEngine::BuildAssociationSetupRequest(uint32_t seq, const std::string& node_id, uint32_t node_ip) {
    std::vector<uint8_t> payload;

    // Node ID IE (Type 60)
    std::vector<uint8_t> node_id_val;
    node_id_val.push_back(0); // Node ID Type = IPv4
    uint32_t ip_be = htonl(node_ip != 0 ? node_ip : pfcp_cfg_.local_ip);
    const auto* ip_ptr = reinterpret_cast<const uint8_t*>(&ip_be);
    node_id_val.insert(node_id_val.end(), ip_ptr, ip_ptr + 4);
    AppendIe(payload, PfcpIeType::NodeId, node_id_val.data(), node_id_val.size());

    // Recovery Time Stamp IE (Type 96)
    uint32_t rec_be = htonl(recovery_timestamp_);
    AppendIe(payload, PfcpIeType::RecoveryTimeStamp, reinterpret_cast<const uint8_t*>(&rec_be), 4);

    size_t pfcp_len = sizeof(PfcpNodeHeader) + payload.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len;
    std::vector<uint8_t> frame(total_len, 0);

    EthHeader eth{};
    std::memcpy(eth.dst_mac, pfcp_cfg_.remote_mac, 6);
    std::memcpy(eth.src_mac, pfcp_cfg_.local_mac, 6);
    eth.ethertype = htons(0x0800);
    std::memcpy(frame.data(), &eth, sizeof(EthHeader));

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len));
    ip->id = htons(0x5043);
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(node_ip != 0 ? node_ip : pfcp_cfg_.local_ip);
    ip->dst_ip = htonl(pfcp_cfg_.remote_upf_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(pfcp_cfg_.local_port);
    udp->dst_port = htons(pfcp_cfg_.remote_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + pfcp_len));

    size_t pfcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* pfcp = reinterpret_cast<PfcpNodeHeader*>(frame.data() + pfcp_offset);
    pfcp->flags = 0x20; // Version 1, S=0
    pfcp->msg_type = static_cast<uint8_t>(PfcpMessageType::AssociationSetupRequest);
    pfcp->length = htons(static_cast<uint16_t>(4 + payload.size()));
    SetSeq24(pfcp->seq_num, seq);
    pfcp->spare = 0;

    std::memcpy(frame.data() + pfcp_offset + sizeof(PfcpNodeHeader), payload.data(), payload.size());
    return frame;
}

std::vector<uint8_t> PfcpEngine::BuildAssociationSetupResponse(uint32_t seq, const std::string& /*node_id*/, uint32_t node_ip, PfcpCause cause) {
    std::vector<uint8_t> payload;

    // Node ID IE
    std::vector<uint8_t> node_id_val;
    node_id_val.push_back(0); // IPv4
    uint32_t ip_be = htonl(node_ip != 0 ? node_ip : pfcp_cfg_.remote_upf_ip);
    const auto* ip_ptr = reinterpret_cast<const uint8_t*>(&ip_be);
    node_id_val.insert(node_id_val.end(), ip_ptr, ip_ptr + 4);
    AppendIe(payload, PfcpIeType::NodeId, node_id_val.data(), node_id_val.size());

    // Cause IE
    uint8_t cause_val = static_cast<uint8_t>(cause);
    AppendIe(payload, PfcpIeType::Cause, &cause_val, 1);

    // Recovery Time Stamp IE
    uint32_t rec_be = htonl(recovery_timestamp_);
    AppendIe(payload, PfcpIeType::RecoveryTimeStamp, reinterpret_cast<const uint8_t*>(&rec_be), 4);

    size_t pfcp_len = sizeof(PfcpNodeHeader) + payload.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len;
    std::vector<uint8_t> frame(total_len, 0);

    EthHeader eth{};
    std::memcpy(eth.dst_mac, pfcp_cfg_.local_mac, 6);
    std::memcpy(eth.src_mac, pfcp_cfg_.remote_mac, 6);
    eth.ethertype = htons(0x0800);
    std::memcpy(frame.data(), &eth, sizeof(EthHeader));

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len));
    ip->id = htons(0x5044);
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(pfcp_cfg_.remote_upf_ip);
    ip->dst_ip = htonl(node_ip != 0 ? node_ip : pfcp_cfg_.local_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(pfcp_cfg_.remote_port);
    udp->dst_port = htons(pfcp_cfg_.local_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + pfcp_len));

    size_t pfcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* pfcp = reinterpret_cast<PfcpNodeHeader*>(frame.data() + pfcp_offset);
    pfcp->flags = 0x20;
    pfcp->msg_type = static_cast<uint8_t>(PfcpMessageType::AssociationSetupResponse);
    pfcp->length = htons(static_cast<uint16_t>(4 + payload.size()));
    SetSeq24(pfcp->seq_num, seq);
    pfcp->spare = 0;

    std::memcpy(frame.data() + pfcp_offset + sizeof(PfcpNodeHeader), payload.data(), payload.size());
    return frame;
}

std::vector<uint8_t> PfcpEngine::BuildHeartbeatRequest(uint32_t seq) {
    std::vector<uint8_t> payload;
    uint32_t rec_be = htonl(recovery_timestamp_);
    AppendIe(payload, PfcpIeType::RecoveryTimeStamp, reinterpret_cast<const uint8_t*>(&rec_be), 4);

    size_t pfcp_len = sizeof(PfcpNodeHeader) + payload.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len;
    std::vector<uint8_t> frame(total_len, 0);

    EthHeader eth{};
    std::memcpy(eth.dst_mac, pfcp_cfg_.remote_mac, 6);
    std::memcpy(eth.src_mac, pfcp_cfg_.local_mac, 6);
    eth.ethertype = htons(0x0800);
    std::memcpy(frame.data(), &eth, sizeof(EthHeader));

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len));
    ip->id = htons(0x5045);
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(pfcp_cfg_.local_ip);
    ip->dst_ip = htonl(pfcp_cfg_.remote_upf_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(pfcp_cfg_.local_port);
    udp->dst_port = htons(pfcp_cfg_.remote_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + pfcp_len));

    size_t pfcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* pfcp = reinterpret_cast<PfcpNodeHeader*>(frame.data() + pfcp_offset);
    pfcp->flags = 0x20;
    pfcp->msg_type = static_cast<uint8_t>(PfcpMessageType::HeartbeatRequest);
    pfcp->length = htons(static_cast<uint16_t>(4 + payload.size()));
    SetSeq24(pfcp->seq_num, seq);
    pfcp->spare = 0;

    std::memcpy(frame.data() + pfcp_offset + sizeof(PfcpNodeHeader), payload.data(), payload.size());
    return frame;
}

std::vector<uint8_t> PfcpEngine::BuildHeartbeatResponse(uint32_t seq, uint32_t recovery_timestamp) {
    std::vector<uint8_t> payload;
    uint32_t rec_be = htonl(recovery_timestamp);
    AppendIe(payload, PfcpIeType::RecoveryTimeStamp, reinterpret_cast<const uint8_t*>(&rec_be), 4);

    size_t pfcp_len = sizeof(PfcpNodeHeader) + payload.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len;
    std::vector<uint8_t> frame(total_len, 0);

    EthHeader eth{};
    std::memcpy(eth.dst_mac, pfcp_cfg_.local_mac, 6);
    std::memcpy(eth.src_mac, pfcp_cfg_.remote_mac, 6);
    eth.ethertype = htons(0x0800);
    std::memcpy(frame.data(), &eth, sizeof(EthHeader));

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len));
    ip->id = htons(0x5046);
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(pfcp_cfg_.remote_upf_ip);
    ip->dst_ip = htonl(pfcp_cfg_.local_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(pfcp_cfg_.remote_port);
    udp->dst_port = htons(pfcp_cfg_.local_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + pfcp_len));

    size_t pfcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* pfcp = reinterpret_cast<PfcpNodeHeader*>(frame.data() + pfcp_offset);
    pfcp->flags = 0x20;
    pfcp->msg_type = static_cast<uint8_t>(PfcpMessageType::HeartbeatResponse);
    pfcp->length = htons(static_cast<uint16_t>(4 + payload.size()));
    SetSeq24(pfcp->seq_num, seq);
    pfcp->spare = 0;

    std::memcpy(frame.data() + pfcp_offset + sizeof(PfcpNodeHeader), payload.data(), payload.size());
    return frame;
}

// ---------------------------------------------------------------------------
// Oturum Düzeyi Paket Üreticileri (S = 1)
// ---------------------------------------------------------------------------

std::vector<uint8_t> PfcpEngine::BuildSessionEstablishmentRequest(TelcoSessionContext* session, 
                                                                 uint32_t seq, 
                                                                 uint64_t cp_seid, 
                                                                 const PfcpPdr& pdr, 
                                                                 const PfcpFar& far) {
    std::vector<uint8_t> payload;

    // Node ID IE
    std::vector<uint8_t> node_id_val;
    node_id_val.push_back(0); // IPv4
    uint32_t ip_be = htonl(pfcp_cfg_.local_ip);
    const auto* ip_ptr = reinterpret_cast<const uint8_t*>(&ip_be);
    node_id_val.insert(node_id_val.end(), ip_ptr, ip_ptr + 4);
    AppendIe(payload, PfcpIeType::NodeId, node_id_val.data(), node_id_val.size());

    // CP F-SEID IE (Type 57)
    uint8_t fseid_buf[13];
    fseid_buf[0] = 0x02; // Flags: V4
    uint64_t seid_be = Hton64(cp_seid);
    std::memcpy(fseid_buf + 1, &seid_be, 8);
    std::memcpy(fseid_buf + 9, &ip_be, 4);
    AppendIe(payload, PfcpIeType::FSeid, fseid_buf, 13);

    // Create PDR Grouped IE (Type 1)
    {
        std::vector<uint8_t> pdr_val;
        uint16_t pdr_id_be = htons(pdr.pdr_id);
        AppendIe(pdr_val, PfcpIeType::PdrId, reinterpret_cast<const uint8_t*>(&pdr_id_be), 2);
        uint32_t prec_be = htonl(pdr.precedence);
        AppendIe(pdr_val, static_cast<PfcpIeType>(29), reinterpret_cast<const uint8_t*>(&prec_be), 4); // Precedence

        // PDI Grouped IE (Type 2)
        std::vector<uint8_t> pdi_val;
        uint8_t src_intf = static_cast<uint8_t>(pdr.source_interface);
        AppendIe(pdi_val, PfcpIeType::SourceInterface, &src_intf, 1);

        // F-TEID IE (Type 21)
        uint8_t fteid_buf[9];
        fteid_buf[0] = 0x01; // Flags: V4
        uint32_t teid_be = htonl(pdr.teid);
        std::memcpy(fteid_buf + 1, &teid_be, 4);
        uint32_t upf_ip_be = htonl(pfcp_cfg_.remote_upf_ip);
        std::memcpy(fteid_buf + 5, &upf_ip_be, 4);
        AppendIe(pdi_val, PfcpIeType::FTeid, fteid_buf, 9);

        // UE IP Address IE (Type 93)
        uint8_t ue_ip_buf[5];
        ue_ip_buf[0] = 0x02; // Flags: V4
        uint32_t ue_be = htonl(pdr.ue_ip != 0 ? pdr.ue_ip : session->client_ip);
        std::memcpy(ue_ip_buf + 1, &ue_be, 4);
        AppendIe(pdi_val, PfcpIeType::UeIpAddress, ue_ip_buf, 5);

        AppendIe(pdr_val, PfcpIeType::Pdi, pdi_val.data(), pdi_val.size());

        uint32_t far_id_be = htonl(pdr.far_id);
        AppendIe(pdr_val, PfcpIeType::FarId, reinterpret_cast<const uint8_t*>(&far_id_be), 4);

        AppendIe(payload, PfcpIeType::CreatePdr, pdr_val.data(), pdr_val.size());
    }

    // Create FAR Grouped IE (Type 3)
    {
        std::vector<uint8_t> far_val;
        uint32_t far_id_be = htonl(far.far_id);
        AppendIe(far_val, PfcpIeType::FarId, reinterpret_cast<const uint8_t*>(&far_id_be), 4);
        uint8_t action = far.apply_action;
        AppendIe(far_val, PfcpIeType::ApplyAction, &action, 1);

        // Forwarding Parameters Grouped IE (Type 4)
        std::vector<uint8_t> fp_val;
        uint8_t dst_intf = static_cast<uint8_t>(far.destination_interface);
        AppendIe(fp_val, PfcpIeType::DestinationInterface, &dst_intf, 1);

        if (far.outer_teid != 0) {
            // Outer Header Creation IE (Type 84)
            uint8_t ohc_buf[10];
            uint16_t ohc_desc = htons(0x0100); // GTP-U/UDP/IPv4
            std::memcpy(ohc_buf, &ohc_desc, 2);
            uint32_t o_teid = htonl(far.outer_teid);
            std::memcpy(ohc_buf + 2, &o_teid, 4);
            uint32_t o_ip = htonl(far.peer_upf_ip != 0 ? far.peer_upf_ip : pfcp_cfg_.remote_upf_ip);
            std::memcpy(ohc_buf + 6, &o_ip, 4);
            AppendIe(fp_val, PfcpIeType::OuterHeaderCreation, ohc_buf, 10);
        }
        AppendIe(far_val, PfcpIeType::ForwardingParameters, fp_val.data(), fp_val.size());

        AppendIe(payload, PfcpIeType::CreateFar, far_val.data(), far_val.size());
    }

    size_t pfcp_len = sizeof(PfcpSessionHeader) + payload.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len;
    std::vector<uint8_t> frame(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(frame.data());
    std::memcpy(eth->dst_mac, session ? session->peer_mac : pfcp_cfg_.remote_mac, 6);
    std::memcpy(eth->src_mac, session ? session->client_mac : pfcp_cfg_.local_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len));
    ip->id = htons(0x5050);
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(pfcp_cfg_.local_ip);
    ip->dst_ip = htonl(pfcp_cfg_.remote_upf_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(pfcp_cfg_.local_port);
    udp->dst_port = htons(pfcp_cfg_.remote_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + pfcp_len));

    size_t pfcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* pfcp = reinterpret_cast<PfcpSessionHeader*>(frame.data() + pfcp_offset);
    pfcp->flags = 0x21; // Version 1, S=1
    pfcp->msg_type = static_cast<uint8_t>(PfcpMessageType::SessionEstablishmentRequest);
    pfcp->length = htons(static_cast<uint16_t>(12 + payload.size()));
    pfcp->seid = 0; // Initial request has SEID 0 in header
    SetSeq24(pfcp->seq_num, seq);
    pfcp->spare = 0;

    std::memcpy(frame.data() + pfcp_offset + sizeof(PfcpSessionHeader), payload.data(), payload.size());
    return frame;
}

std::vector<uint8_t> PfcpEngine::BuildSessionEstablishmentResponse(TelcoSessionContext* session, 
                                                                  uint32_t seq, 
                                                                  uint64_t cp_seid, 
                                                                  uint64_t up_seid, 
                                                                  PfcpCause cause) {
    std::vector<uint8_t> payload;

    // Node ID IE
    std::vector<uint8_t> node_id_val;
    node_id_val.push_back(0); // IPv4
    uint32_t ip_be = htonl(pfcp_cfg_.remote_upf_ip);
    const auto* ip_ptr = reinterpret_cast<const uint8_t*>(&ip_be);
    node_id_val.insert(node_id_val.end(), ip_ptr, ip_ptr + 4);
    AppendIe(payload, PfcpIeType::NodeId, node_id_val.data(), node_id_val.size());

    // Cause IE
    uint8_t cause_val = static_cast<uint8_t>(cause);
    AppendIe(payload, PfcpIeType::Cause, &cause_val, 1);

    // UP F-SEID IE
    uint8_t fseid_buf[13];
    fseid_buf[0] = 0x02; // Flags: V4
    uint64_t up_seid_be = Hton64(up_seid);
    std::memcpy(fseid_buf + 1, &up_seid_be, 8);
    std::memcpy(fseid_buf + 9, &ip_be, 4);
    AppendIe(payload, PfcpIeType::FSeid, fseid_buf, 13);

    size_t pfcp_len = sizeof(PfcpSessionHeader) + payload.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len;
    std::vector<uint8_t> frame(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(frame.data());
    std::memcpy(eth->dst_mac, session ? session->client_mac : pfcp_cfg_.local_mac, 6);
    std::memcpy(eth->src_mac, session ? session->peer_mac : pfcp_cfg_.remote_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len));
    ip->id = htons(0x5051);
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(pfcp_cfg_.remote_upf_ip);
    ip->dst_ip = htonl(pfcp_cfg_.local_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(pfcp_cfg_.remote_port);
    udp->dst_port = htons(pfcp_cfg_.local_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + pfcp_len));

    size_t pfcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* pfcp = reinterpret_cast<PfcpSessionHeader*>(frame.data() + pfcp_offset);
    pfcp->flags = 0x21;
    pfcp->msg_type = static_cast<uint8_t>(PfcpMessageType::SessionEstablishmentResponse);
    pfcp->length = htons(static_cast<uint16_t>(12 + payload.size()));
    pfcp->seid = Hton64(cp_seid); // Response addresses CP SEID
    SetSeq24(pfcp->seq_num, seq);
    pfcp->spare = 0;

    std::memcpy(frame.data() + pfcp_offset + sizeof(PfcpSessionHeader), payload.data(), payload.size());
    return frame;
}

std::vector<uint8_t> PfcpEngine::BuildSessionModificationRequest(TelcoSessionContext* session, 
                                                                uint32_t seq, 
                                                                const PfcpFar& updated_far) {
    std::vector<uint8_t> payload;

    // Update FAR Grouped IE (Type 124)
    std::vector<uint8_t> ufar_val;
    uint32_t far_id_be = htonl(updated_far.far_id);
    AppendIe(ufar_val, PfcpIeType::FarId, reinterpret_cast<const uint8_t*>(&far_id_be), 4);
    uint8_t action = updated_far.apply_action;
    AppendIe(ufar_val, PfcpIeType::ApplyAction, &action, 1);
    AppendIe(payload, PfcpIeType::UpdateFar, ufar_val.data(), ufar_val.size());

    size_t pfcp_len = sizeof(PfcpSessionHeader) + payload.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len;
    std::vector<uint8_t> frame(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(frame.data());
    std::memcpy(eth->dst_mac, session ? session->peer_mac : pfcp_cfg_.remote_mac, 6);
    std::memcpy(eth->src_mac, session ? session->client_mac : pfcp_cfg_.local_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len));
    ip->id = htons(0x5052);
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(pfcp_cfg_.local_ip);
    ip->dst_ip = htonl(pfcp_cfg_.remote_upf_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(pfcp_cfg_.local_port);
    udp->dst_port = htons(pfcp_cfg_.remote_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + pfcp_len));

    size_t pfcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* pfcp = reinterpret_cast<PfcpSessionHeader*>(frame.data() + pfcp_offset);
    pfcp->flags = 0x21;
    pfcp->msg_type = static_cast<uint8_t>(PfcpMessageType::SessionModificationRequest);
    pfcp->length = htons(static_cast<uint16_t>(12 + payload.size()));
    uint64_t target_seid = session ? (session->GetPfcpRemoteSeid() != 0 ? session->GetPfcpRemoteSeid() : session->GetPfcpSeid()) : 0;
    pfcp->seid = Hton64(target_seid);
    SetSeq24(pfcp->seq_num, seq);
    pfcp->spare = 0;

    std::memcpy(frame.data() + pfcp_offset + sizeof(PfcpSessionHeader), payload.data(), payload.size());
    return frame;
}

std::vector<uint8_t> PfcpEngine::BuildSessionModificationResponse(TelcoSessionContext* session, 
                                                                 uint32_t seq, 
                                                                 PfcpCause cause) {
    std::vector<uint8_t> payload;
    uint8_t cause_val = static_cast<uint8_t>(cause);
    AppendIe(payload, PfcpIeType::Cause, &cause_val, 1);

    size_t pfcp_len = sizeof(PfcpSessionHeader) + payload.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len;
    std::vector<uint8_t> frame(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(frame.data());
    std::memcpy(eth->dst_mac, session ? session->client_mac : pfcp_cfg_.local_mac, 6);
    std::memcpy(eth->src_mac, session ? session->peer_mac : pfcp_cfg_.remote_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len));
    ip->id = htons(0x5053);
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(pfcp_cfg_.remote_upf_ip);
    ip->dst_ip = htonl(pfcp_cfg_.local_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(pfcp_cfg_.remote_port);
    udp->dst_port = htons(pfcp_cfg_.local_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + pfcp_len));

    size_t pfcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* pfcp = reinterpret_cast<PfcpSessionHeader*>(frame.data() + pfcp_offset);
    pfcp->flags = 0x21;
    pfcp->msg_type = static_cast<uint8_t>(PfcpMessageType::SessionModificationResponse);
    pfcp->length = htons(static_cast<uint16_t>(12 + payload.size()));
    pfcp->seid = Hton64(session ? session->GetPfcpSeid() : 0);
    SetSeq24(pfcp->seq_num, seq);
    pfcp->spare = 0;

    std::memcpy(frame.data() + pfcp_offset + sizeof(PfcpSessionHeader), payload.data(), payload.size());
    return frame;
}

std::vector<uint8_t> PfcpEngine::BuildSessionDeletionRequest(TelcoSessionContext* session, uint32_t seq) {
    size_t pfcp_len = sizeof(PfcpSessionHeader);
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len;
    std::vector<uint8_t> frame(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(frame.data());
    std::memcpy(eth->dst_mac, session ? session->peer_mac : pfcp_cfg_.remote_mac, 6);
    std::memcpy(eth->src_mac, session ? session->client_mac : pfcp_cfg_.local_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len));
    ip->id = htons(0x5054);
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(pfcp_cfg_.local_ip);
    ip->dst_ip = htonl(pfcp_cfg_.remote_upf_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(pfcp_cfg_.local_port);
    udp->dst_port = htons(pfcp_cfg_.remote_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + pfcp_len));

    size_t pfcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* pfcp = reinterpret_cast<PfcpSessionHeader*>(frame.data() + pfcp_offset);
    pfcp->flags = 0x21;
    pfcp->msg_type = static_cast<uint8_t>(PfcpMessageType::SessionDeletionRequest);
    pfcp->length = htons(12);
    uint64_t target_seid = session ? (session->GetPfcpRemoteSeid() != 0 ? session->GetPfcpRemoteSeid() : session->GetPfcpSeid()) : 0;
    pfcp->seid = Hton64(target_seid);
    SetSeq24(pfcp->seq_num, seq);
    pfcp->spare = 0;

    return frame;
}

std::vector<uint8_t> PfcpEngine::BuildSessionDeletionResponse(TelcoSessionContext* session, 
                                                             uint32_t seq, 
                                                             PfcpCause cause) {
    std::vector<uint8_t> payload;
    uint8_t cause_val = static_cast<uint8_t>(cause);
    AppendIe(payload, PfcpIeType::Cause, &cause_val, 1);

    size_t pfcp_len = sizeof(PfcpSessionHeader) + payload.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len;
    std::vector<uint8_t> frame(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(frame.data());
    std::memcpy(eth->dst_mac, session ? session->client_mac : pfcp_cfg_.local_mac, 6);
    std::memcpy(eth->src_mac, session ? session->peer_mac : pfcp_cfg_.remote_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(frame.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(UdpHeader) + pfcp_len));
    ip->id = htons(0x5055);
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(pfcp_cfg_.remote_upf_ip);
    ip->dst_ip = htonl(pfcp_cfg_.local_ip);
    ip->checksum = ComputeChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(frame.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(pfcp_cfg_.remote_port);
    udp->dst_port = htons(pfcp_cfg_.local_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + pfcp_len));

    size_t pfcp_offset = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
    auto* pfcp = reinterpret_cast<PfcpSessionHeader*>(frame.data() + pfcp_offset);
    pfcp->flags = 0x21;
    pfcp->msg_type = static_cast<uint8_t>(PfcpMessageType::SessionDeletionResponse);
    pfcp->length = htons(static_cast<uint16_t>(12 + payload.size()));
    pfcp->seid = Hton64(session ? session->GetPfcpSeid() : 0);
    SetSeq24(pfcp->seq_num, seq);
    pfcp->spare = 0;

    std::memcpy(frame.data() + pfcp_offset + sizeof(PfcpSessionHeader), payload.data(), payload.size());
    return frame;
}

} // namespace ddos_samurai::telecom::mobile
