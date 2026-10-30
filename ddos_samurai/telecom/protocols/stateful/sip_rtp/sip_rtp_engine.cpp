#include "sip_rtp_engine.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <cmath>

namespace ddos_samurai::telecom::sip_rtp {

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

uint16_t ComputeIpChecksum(const uint16_t* data, size_t bytes) {
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

SipRtpEngine::SipRtpEngine(SessionManager& session_mgr, HierarchicalTimingWheel* timing_wheel)
    : session_mgr_(session_mgr),
      timing_wheel_(timing_wheel) {}

bool SipRtpEngine::Init(const ProtocolConfig& cfg) {
    config_ = cfg;
    return true;
}

void SipRtpEngine::Shutdown() {
    uint32_t cap = session_mgr_.GetCapacity();
    for (uint32_t i = 0; i < cap; ++i) {
        TelcoSessionContext* s = session_mgr_.GetSessionByIndex(i);
        if (s && s->protocol_id == static_cast<uint8_t>(TelcoProtocolId::SIP_RTP)) {
            if (timing_wheel_) {
                timing_wheel_->Cancel(s);
            }
            session_mgr_.ReleaseSession(s);
        }
    }
}

SipCallState SipRtpEngine::GetState(const TelcoSessionContext* session) const noexcept {
    if (!session) return SipCallState::IDLE;
    return static_cast<SipCallState>(session->ppp_lcp_identifier);
}

void SipRtpEngine::SetState(TelcoSessionContext* session, SipCallState state) noexcept {
    if (!session) return;
    session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::SIP_RTP);
    session->ppp_lcp_identifier = static_cast<uint16_t>(state);
    switch (state) {
        case SipCallState::ESTABLISHED:
            session->state = SessionState::ESTABLISHED;
            break;
        case SipCallState::CALLING:
        case SipCallState::AUTHENTICATING:
        case SipCallState::PROCEEDING:
            session->state = SessionState::DISCOVERING;
            break;
        case SipCallState::TERMINATING:
            session->state = SessionState::TERMINATING;
            break;
        case SipCallState::FAILED:
            session->state = SessionState::FAILED;
            break;
        case SipCallState::TERMINATED:
        case SipCallState::IDLE:
        default:
            session->state = SessionState::IDLE;
            break;
    }
}

void SipRtpEngine::StartCall(TelcoSessionContext* session, const SipCallConfig& cfg) {
    if (!session) return;

    call_cfg_ = cfg;
    current_cseq_ = 1;
    auth_header_.clear();

    if (cfg.enable_srtp) {
        SrtpKeyConfig key_cfg{};
        std::memcpy(key_cfg.master_key, cfg.master_key, SRTP_MASTER_KEY_LEN);
        std::memcpy(key_cfg.master_salt, cfg.master_salt, SRTP_MASTER_SALT_LEN);
        srtp_tx_.InitKeys(key_cfg);
        srtp_rx_.InitKeys(key_cfg);
    }
    session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::SIP_RTP);
    session->client_ip = cfg.local_ip;
    session->peer_ip = cfg.peer_ip;
    session->client_port = cfg.local_sip_port;
    session->peer_port = cfg.peer_sip_port;
    session->ip_proto = 17; // UDP
    session->s_vlan = cfg.vlan_s;
    session->c_vlan = cfg.vlan_c;
    session->teid_uplink = cfg.ssrc; // SSRC in teid_uplink
    session->teid_downlink = 0;
    session->retry_count = 0;

    std::memcpy(session->client_mac, cfg.local_mac, 6);
    std::memcpy(session->peer_mac, cfg.peer_mac, 6);

    session_mgr_.Bind5Tuple(session, cfg.local_ip, cfg.peer_ip, cfg.local_sip_port, cfg.peer_sip_port, 17);

    SetState(session, SipCallState::CALLING);

    // SIP INVITE paketi üret
    last_tx_frame_ = BuildInvitePacket(session);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    if (timing_wheel_) {
        timing_wheel_->Schedule(session, 1000); // 1s INVITE timeout
    }
}

void SipRtpEngine::TerminateCall(TelcoSessionContext* session) {
    if (!session) return;

    if (timing_wheel_) timing_wheel_->Cancel(session);

    if (GetState(session) == SipCallState::ESTABLISHED) {
        SetState(session, SipCallState::TERMINATING);
        last_tx_frame_ = BuildByePacket(session);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        if (timing_wheel_) timing_wheel_->Schedule(session, 1000);
    } else {
        SetState(session, SipCallState::TERMINATED);
    }
}

std::vector<uint8_t> SipRtpEngine::BuildInvitePacket(TelcoSessionContext* session) {
    if (!session) return {};
    // 1. SDP Body
    std::string sdp = 
        "v=0\r\n"
        "o=samurai 123456 654321 IN IP4 " + call_cfg_.local_ip_str + "\r\n"
        "s=Samurai-VoIP-Session\r\n"
        "c=IN IP4 " + call_cfg_.local_ip_str + "\r\n"
        "t=0 0\r\n"
        "m=audio " + std::to_string(call_cfg_.local_rtp_port) + " RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=ptime:" + std::to_string(call_cfg_.ptime_ms) + "\r\n";

    // 2. SIP Header
    std::string sip = 
        "INVITE " + call_cfg_.to_uri + " SIP/2.0\r\n"
        "Via: SIP/2.0/UDP " + call_cfg_.local_ip_str + ":" + std::to_string(call_cfg_.local_sip_port) + ";branch=z9hG4bK-samurai-" + std::to_string(current_cseq_) + "\r\n"
        "Max-Forwards: 70\r\n"
        "From: <" + call_cfg_.from_uri + ">;tag=tag-samurai-client\r\n"
        "To: <" + call_cfg_.to_uri + ">\r\n"
        "Call-ID: " + call_cfg_.call_id + "\r\n"
        "CSeq: " + std::to_string(current_cseq_) + " INVITE\r\n"
        "Contact: <sip:alice@" + call_cfg_.local_ip_str + ":" + std::to_string(call_cfg_.local_sip_port) + ">\r\n"
        + auth_header_ +
        "Content-Type: application/sdp\r\n"
        "Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;

    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sip.size();
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(packet.data(), session->peer_mac, 6);
    std::memcpy(packet.data() + 6, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 17; // UDP
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(session->client_port);
    udp->dst_port = htons(session->peer_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + sip.size()));
    udp->checksum = 0;

    std::memcpy(packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader),
                sip.data(), sip.size());

    return packet;
}

std::vector<uint8_t> SipRtpEngine::BuildAckPacket(TelcoSessionContext* session) {
    if (!session) return {};
    std::string sip = 
        "ACK " + call_cfg_.to_uri + " SIP/2.0\r\n"
        "Via: SIP/2.0/UDP " + call_cfg_.local_ip_str + ":" + std::to_string(call_cfg_.local_sip_port) + ";branch=z9hG4bK-samurai-ack\r\n"
        "Max-Forwards: 70\r\n"
        "From: <" + call_cfg_.from_uri + ">;tag=tag-samurai-client\r\n"
        "To: <" + call_cfg_.to_uri + ">;tag=tag-samurai-server\r\n"
        "Call-ID: " + call_cfg_.call_id + "\r\n"
        "CSeq: " + std::to_string(current_cseq_) + " ACK\r\n"
        "Content-Length: 0\r\n\r\n";

    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sip.size();
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(packet.data(), session->peer_mac, 6);
    std::memcpy(packet.data() + 6, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(session->client_port);
    udp->dst_port = htons(session->peer_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + sip.size()));
    udp->checksum = 0;

    std::memcpy(packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader),
                sip.data(), sip.size());

    return packet;
}

std::vector<uint8_t> SipRtpEngine::BuildByePacket(TelcoSessionContext* session) {
    if (!session) return {};
    std::string sip = 
        "BYE " + call_cfg_.to_uri + " SIP/2.0\r\n"
        "Via: SIP/2.0/UDP " + call_cfg_.local_ip_str + ":" + std::to_string(call_cfg_.local_sip_port) + ";branch=z9hG4bK-samurai-bye\r\n"
        "Max-Forwards: 70\r\n"
        "From: <" + call_cfg_.from_uri + ">;tag=tag-samurai-client\r\n"
        "To: <" + call_cfg_.to_uri + ">;tag=tag-samurai-server\r\n"
        "Call-ID: " + call_cfg_.call_id + "\r\n"
        "CSeq: " + std::to_string(current_cseq_ + 1) + " BYE\r\n"
        "Content-Length: 0\r\n\r\n";

    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sip.size();
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(packet.data(), session->peer_mac, 6);
    std::memcpy(packet.data() + 6, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(session->client_port);
    udp->dst_port = htons(session->peer_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + sip.size()));
    udp->checksum = 0;

    std::memcpy(packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader),
                sip.data(), sip.size());

    return packet;
}

std::vector<uint8_t> SipRtpEngine::BuildResponsePacket(TelcoSessionContext* session, int status_code, const std::string& reason) {
    if (!session) return {};
    std::string sip = 
        "SIP/2.0 " + std::to_string(status_code) + " " + reason + "\r\n"
        "Via: SIP/2.0/UDP " + call_cfg_.peer_ip_str + ":" + std::to_string(call_cfg_.peer_sip_port) + ";branch=z9hG4bK-peer\r\n"
        "From: <" + call_cfg_.from_uri + ">;tag=tag-samurai-client\r\n"
        "To: <" + call_cfg_.to_uri + ">;tag=tag-samurai-server\r\n"
        "Call-ID: " + call_cfg_.call_id + "\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";

    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sip.size();
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(packet.data(), session->peer_mac, 6);
    std::memcpy(packet.data() + 6, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 17;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    auto* udp = reinterpret_cast<UdpHeader*>(packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header));
    udp->src_port = htons(session->client_port);
    udp->dst_port = htons(session->peer_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + sip.size()));
    udp->checksum = 0;

    std::memcpy(packet.data() + sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader),
                sip.data(), sip.size());

    return packet;
}

std::vector<uint8_t> SipRtpEngine::BuildRtpPacket(TelcoSessionContext* session, const uint8_t* audio_samples, size_t sample_len) {
    if (!session) return {};

    size_t srtp_auth_len = call_cfg_.enable_srtp ? SRTP_AUTH_TAG_LEN : 0;
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(RtpHeader) + sample_len + srtp_auth_len;
    std::vector<uint8_t> packet(total_len, 0);

    // 1. Ethernet
    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(packet.data(), session->peer_mac, 6);
    std::memcpy(packet.data() + 6, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    // 2. IPv4
    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->tos = 0xB8; // Expedited Forwarding (EF) DSCP for voice media
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = 17; // UDP
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    // 3. UDP
    size_t udp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* udp = reinterpret_cast<UdpHeader*>(packet.data() + udp_offset);
    udp->src_port = htons(call_cfg_.local_rtp_port);
    udp->dst_port = htons(call_cfg_.peer_rtp_port);
    udp->length = htons(static_cast<uint16_t>(sizeof(UdpHeader) + sizeof(RtpHeader) + sample_len + srtp_auth_len));
    udp->checksum = 0;

    // 4. RTP Header (RFC 3550)
    size_t rtp_offset = udp_offset + sizeof(UdpHeader);
    auto* rtp = reinterpret_cast<RtpHeader*>(packet.data() + rtp_offset);
    rtp->v_p_x_cc = 0x80; // V=2, P=0, X=0, CC=0
    rtp->m_pt = call_cfg_.payload_type & 0x7F;
    rtp->seq_number = htons(current_rtp_seq_++);
    rtp->timestamp = htonl(current_rtp_ts_);
    current_rtp_ts_ += 160; // 20ms G.711 = 160 samples @ 8kHz
    rtp->ssrc = htonl(call_cfg_.ssrc);

    // 5. Audio Payload
    if (audio_samples && sample_len > 0) {
        std::memcpy(packet.data() + rtp_offset + sizeof(RtpHeader), audio_samples, sample_len);
    }

    // 6. SRTP Encryption & Authentication Tag (RFC 3711)
    if (call_cfg_.enable_srtp) {
        size_t out_len = 0;
        srtp_tx_.ProtectRtpInPlace(packet.data() + rtp_offset,
                                   sizeof(RtpHeader),
                                   sample_len,
                                   packet.size() - rtp_offset,
                                   out_len);
    }

    return packet;
}

bool SipRtpEngine::ProcessRxFrame(const uint8_t* frame, size_t len, uint64_t now_tsc) {
    size_t min_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader);
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

    if (ethertype != 0x0800 || len < offset + sizeof(Ipv4Header) + sizeof(UdpHeader)) {
        return false;
    }

    const auto* ip = reinterpret_cast<const Ipv4Header*>(frame + offset);
    if ((ip->ihl_version >> 4) != 4 || ip->protocol != 17) return false;

    size_t ip_len = (ip->ihl_version & 0x0F) * 4;
    size_t udp_offset = offset + ip_len;
    if (len < udp_offset + sizeof(UdpHeader)) return false;

    const auto* udp = reinterpret_cast<const UdpHeader*>(frame + udp_offset);
    uint16_t dst_port = ntohs(udp->dst_port);
    uint32_t src_ip = ntohl(ip->src_ip);
    uint32_t dst_ip = ntohl(ip->dst_ip);
    uint16_t src_port = ntohs(udp->src_port);

    TelcoSessionContext* session = session_mgr_.FindSessionBy5Tuple(dst_ip, src_ip, dst_port, src_port, 17);
    if (!session) {
        uint32_t cap = session_mgr_.GetCapacity();
        for (uint32_t i = 0; i < cap; ++i) {
            TelcoSessionContext* s = session_mgr_.GetSessionByIndex(i);
            if (s && s->protocol_id == static_cast<uint8_t>(TelcoProtocolId::SIP_RTP)) {
                session = s;
                break;
            }
        }
    }

    if (!session) return false;

    session->rx_packets++;
    session->rx_bytes += len;
    session->last_activity_tsc = now_tsc;

    const uint8_t* payload = frame + udp_offset + sizeof(UdpHeader);
    size_t payload_len = len - (udp_offset + sizeof(UdpHeader));

    if (dst_port == SIP_STANDARD_PORT || src_port == SIP_STANDARD_PORT) {
        std::string sip_str(reinterpret_cast<const char*>(payload), payload_len);
        return ProcessSipMessage(session, sip_str, now_tsc);
    } else {
        // RTP Medya Paketi
        return ProcessRtpPacket(session, payload, payload_len, now_tsc);
    }
}

bool SipRtpEngine::ProcessSipMessage(TelcoSessionContext* session, const std::string& sip_msg, uint64_t /*now_tsc*/) {
    // 401 Unauthorized veya 407 Proxy Authentication Required kontrolü
    if (sip_msg.find("401 Unauthorized") != std::string::npos ||
        sip_msg.find("407 Proxy Authentication Required") != std::string::npos) {
        if (GetState(session) == SipCallState::CALLING) {
            DigestChallenge challenge;
            bool is_proxy = false;
            if (ExtractDigestChallengeFromSipMessage(sip_msg, challenge, is_proxy)) {
                SetState(session, SipCallState::AUTHENTICATING);
                current_cseq_++; // RFC 3261 Section 22.2: Bump CSeq for re-INVITE

                DigestCredentials creds;
                creds.username = call_cfg_.auth_username;
                creds.realm = challenge.realm;
                creds.nonce = challenge.nonce;
                creds.uri = call_cfg_.to_uri;
                creds.algorithm = challenge.algorithm.empty() ? "MD5" : challenge.algorithm;
                creds.opaque = challenge.opaque;
                creds.qop = challenge.qop;
                char nc_buf[16];
                std::snprintf(nc_buf, sizeof(nc_buf), "%08x", call_cfg_.auth_nc);
                creds.nc = nc_buf;
                creds.cnonce = call_cfg_.auth_cnonce;

                creds.response = CalculateDigestResponse(
                    creds.username,
                    creds.realm,
                    call_cfg_.auth_password,
                    "INVITE",
                    creds.uri,
                    creds.nonce,
                    creds.nc,
                    creds.cnonce,
                    creds.qop,
                    creds.algorithm
                );

                auth_header_ = BuildAuthorizationHeader(creds, is_proxy);

                // Yetkilendirme başlığı eklenmiş yeni INVITE gönder
                last_tx_frame_ = BuildInvitePacket(session);
                session->tx_packets++;
                session->tx_bytes += last_tx_frame_.size();

                if (timing_wheel_) {
                    timing_wheel_->Cancel(session);
                    timing_wheel_->Schedule(session, 1000);
                }
                return true;
            }
        }
    }

    if (sip_msg.find("100 Trying") != std::string::npos || sip_msg.find("180 Ringing") != std::string::npos) {
        SetState(session, SipCallState::PROCEEDING);
        return true;
    }

    if (sip_msg.find("200 OK") != std::string::npos) {
        if (GetState(session) == SipCallState::CALLING ||
            GetState(session) == SipCallState::AUTHENTICATING ||
            GetState(session) == SipCallState::PROCEEDING) {
            SetState(session, SipCallState::ESTABLISHED);
            // 200 OK alındı; hemen ACK üret
            last_tx_frame_ = BuildAckPacket(session);
            session->tx_packets++;
            session->tx_bytes += last_tx_frame_.size();
            if (timing_wheel_) {
                timing_wheel_->Cancel(session);
                // 20ms sonra ilk ses RTP paketini zamanla
                timing_wheel_->Schedule(session, call_cfg_.ptime_ms > 0 ? call_cfg_.ptime_ms : 20);
            }
            return true;
        } else if (GetState(session) == SipCallState::TERMINATING) {
            SetState(session, SipCallState::TERMINATED);
            if (timing_wheel_) timing_wheel_->Cancel(session);
            return true;
        }
    }

    if (sip_msg.find("BYE") == 0) {
        // Karşı taraftan BYE geldi; 200 OK yanıtı ver
        SetState(session, SipCallState::TERMINATED);
        last_tx_frame_ = BuildResponsePacket(session, 200, "OK");
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        if (timing_wheel_) timing_wheel_->Cancel(session);
        return true;
    }

    return true;
}

bool SipRtpEngine::ProcessRtpPacket(TelcoSessionContext* /*session*/, const uint8_t* rtp_data, size_t len, uint64_t now_tsc) {
    if (!rtp_data) return false;

    if (call_cfg_.enable_srtp) {
        if (len < sizeof(RtpHeader) + SRTP_AUTH_TAG_LEN) {
            jitter_stats_.packets_lost++;
            return false;
        }

        // SRTP Doğrulama ve Deşifreleme (Zero Heap Allocation)
        uint8_t audio_buf[2048];
        size_t audio_len = 0;
        if (!srtp_rx_.UnprotectRtpBuffer(rtp_data, len, audio_buf, sizeof(audio_buf), audio_len)) {
            // Kimlik doğrulama başarısız veya replay saldırısı tespit edildi
            jitter_stats_.packets_lost++;
            return false;
        }
    } else {
        if (len < sizeof(RtpHeader)) return false;
    }

    const auto* rtp = reinterpret_cast<const RtpHeader*>(rtp_data);
    uint32_t rtp_ts = ntohl(rtp->timestamp);

    jitter_stats_.packets_received++;

    // RFC 3550 Appendix A.8 Jitter Hesabı
    if (jitter_stats_.packets_received > 1 && jitter_stats_.last_arrival_tsc > 0) {
        int64_t transit = static_cast<int64_t>(now_tsc) - static_cast<int64_t>(rtp_ts);
        int64_t prev_transit = static_cast<int64_t>(jitter_stats_.last_arrival_tsc) - static_cast<int64_t>(jitter_stats_.last_rtp_timestamp);
        int64_t d = transit - prev_transit;
        if (d < 0) d = -d;

        // J(i) = J(i-1) + (|D(i-1, i)| - J(i-1)) / 16
        jitter_stats_.jitter_us += (static_cast<double>(d) - jitter_stats_.jitter_us) / 16.0;
    }

    jitter_stats_.last_rtp_timestamp = rtp_ts;
    jitter_stats_.last_arrival_tsc = now_tsc;

    return true;
}

void SipRtpEngine::HandleTimeout(TelcoSessionContext* session) {
    if (!session) return;

    SipCallState state = GetState(session);

    if (state == SipCallState::CALLING || state == SipCallState::AUTHENTICATING) {
        session->retry_count++;
        if (session->retry_count >= config_.max_retries) {
            SetState(session, SipCallState::FAILED);
            return;
        }
        last_tx_frame_ = BuildInvitePacket(session);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        if (timing_wheel_) timing_wheel_->Schedule(session, 1000 * (1 << session->retry_count));
        return;
    }

    if (state == SipCallState::ESTABLISHED) {
        // 20ms ses RTP akış paketi bas
        uint8_t dummy_pcm[160];
        std::memset(dummy_pcm, 0xD5, sizeof(dummy_pcm)); // PCMU silence
        last_tx_frame_ = BuildRtpPacket(session, dummy_pcm, sizeof(dummy_pcm));
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();

        if (timing_wheel_) {
            timing_wheel_->Schedule(session, call_cfg_.ptime_ms > 0 ? call_cfg_.ptime_ms : 20);
        }
        return;
    }

    if (state == SipCallState::TERMINATING) {
        session->retry_count++;
        if (session->retry_count >= config_.max_retries) {
            SetState(session, SipCallState::TERMINATED);
            return;
        }
        last_tx_frame_ = BuildByePacket(session);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        if (timing_wheel_) timing_wheel_->Schedule(session, 1000);
        return;
    }
}

uint32_t SipRtpEngine::OnTimerTick(uint64_t current_tsc) {
    if (!timing_wheel_) return 0;
    return timing_wheel_->Advance(current_tsc, [this](TelcoSessionContext* s) {
        HandleTimeout(s);
    });
}

void SipRtpEngine::OnRxPacket(rte_mbuf* /*mbuf*/, const PacketMetadata& meta, TelcoSessionContext* session) {
    if (meta.raw_frame && meta.raw_len > 0) {
        ProcessRxFrame(meta.raw_frame, meta.raw_len, session ? session->last_activity_tsc : 0);
    }
}

rte_mbuf* SipRtpEngine::BuildTxPacket(rte_mempool* /*pool*/, TelcoSessionContext* /*session*/, uint16_t /*event_type*/) {
    return nullptr;
}

} // namespace ddos_samurai::telecom::sip_rtp
