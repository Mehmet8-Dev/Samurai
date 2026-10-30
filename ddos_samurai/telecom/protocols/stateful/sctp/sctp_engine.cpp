#include "sctp_engine.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <algorithm>

#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
#endif

namespace ddos_samurai::telecom::sctp {

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
    uint8_t  protocol;    // 132 (SCTP)
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
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

// RFC 4960 Software Fallback Table for Castagnoli CRC32c
constexpr uint32_t CRC32C_POLYNOMIAL = 0x82F63B78;

uint32_t SoftwareCrc32c(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            crc = (crc >> 1) ^ ((crc & 1) ? CRC32C_POLYNOMIAL : 0);
        }
    }
    return crc ^ 0xFFFFFFFF;
}

} // namespace

#if defined(__SSE4_2__) || defined(__x86_64__)
#if !defined(__SSE4_2__)
__attribute__((target("sse4.2")))
#endif
uint32_t SctpEngine::ComputeCrc32c(const uint8_t* data, size_t len) noexcept {
    uint32_t crc = 0xFFFFFFFF;
    size_t i = 0;

    // 8-bayt bloklar halinde donanım SSE4.2 hızlandırması
    while (i + 8 <= len) {
        uint64_t v = 0;
        std::memcpy(&v, data + i, 8);
        crc = static_cast<uint32_t>(__builtin_ia32_crc32di(crc, v));
        i += 8;
    }

    // 4-bayt blok
    if (i + 4 <= len) {
        uint32_t v = 0;
        std::memcpy(&v, data + i, 4);
        crc = __builtin_ia32_crc32si(crc, v);
        i += 4;
    }

    // Kalan baytlar
    while (i < len) {
        crc = __builtin_ia32_crc32qi(crc, data[i]);
        i++;
    }

    return crc ^ 0xFFFFFFFF;
}
#else
uint32_t SctpEngine::ComputeCrc32c(const uint8_t* data, size_t len) noexcept {
    return SoftwareCrc32c(data, len);
}
#endif

SctpEngine::SctpEngine(SessionManager& session_mgr, HierarchicalTimingWheel* timing_wheel)
    : session_mgr_(session_mgr),
      timing_wheel_(timing_wheel) {
    uint32_t cap = session_mgr_.GetCapacity();
    if (cap > 0) {
        assoc_states_.resize(cap);
        for (auto& s : assoc_states_) {
            s.Reset();
        }
    }
}

bool SctpEngine::Init(const ProtocolConfig& cfg) {
    config_ = cfg;
    uint32_t cap = session_mgr_.GetCapacity();
    if (cap > 0 && assoc_states_.size() < cap) {
        assoc_states_.resize(cap);
        for (auto& s : assoc_states_) {
            s.Reset();
        }
    }
    return true;
}

SctpAssociationState& SctpEngine::GetAssocState(TelcoSessionContext* session) {
    if (!session) return fallback_state_;
    int32_t idx = session_mgr_.GetSessionIndex(session);
    if (idx >= 0 && static_cast<size_t>(idx) < assoc_states_.size()) {
        return assoc_states_[idx];
    }
    return fallback_state_;
}

const SctpAssociationState& SctpEngine::GetAssocState(const TelcoSessionContext* session) const {
    if (!session) return fallback_state_;
    int32_t idx = session_mgr_.GetSessionIndex(session);
    if (idx >= 0 && static_cast<size_t>(idx) < assoc_states_.size()) {
        return assoc_states_[idx];
    }
    return fallback_state_;
}

void SctpEngine::Shutdown() {
    active_sctp_sessions_.clear();
    uint32_t cap = session_mgr_.GetCapacity();
    for (uint32_t i = 0; i < cap; ++i) {
        TelcoSessionContext* s = session_mgr_.GetSessionByIndex(i);
        if (s && s->protocol_id == static_cast<uint8_t>(TelcoProtocolId::SCTP)) {
            if (timing_wheel_) {
                timing_wheel_->Cancel(s);
            }
            if (i < assoc_states_.size()) {
                assoc_states_[i].Reset();
            }
            session_mgr_.ReleaseSession(s);
        }
    }
}

SctpState SctpEngine::GetState(const TelcoSessionContext* session) const noexcept {
    if (!session) return SctpState::CLOSED;
    return static_cast<SctpState>(session->ppp_lcp_identifier);
}

void SctpEngine::SetState(TelcoSessionContext* session, SctpState state) noexcept {
    if (!session) return;
    session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::SCTP);
    session->ppp_lcp_identifier = static_cast<uint16_t>(state);

    if (state != SctpState::CLOSED) {
        if (std::find(active_sctp_sessions_.begin(), active_sctp_sessions_.end(), session) == active_sctp_sessions_.end()) {
            active_sctp_sessions_.push_back(session);
        }
    } else {
        auto it = std::find(active_sctp_sessions_.begin(), active_sctp_sessions_.end(), session);
        if (it != active_sctp_sessions_.end()) {
            active_sctp_sessions_.erase(it);
        }
    }

    switch (state) {
        case SctpState::ESTABLISHED:
            session->state = SessionState::ESTABLISHED;
            break;
        case SctpState::COOKIE_WAIT:
        case SctpState::COOKIE_ECHOED:
            session->state = SessionState::DISCOVERING;
            break;
        case SctpState::SHUTDOWN_PENDING:
        case SctpState::SHUTDOWN_SENT:
        case SctpState::SHUTDOWN_RECEIVED:
        case SctpState::SHUTDOWN_ACK_SENT:
            session->state = SessionState::TERMINATING;
            break;
        case SctpState::FAILED:
            session->state = SessionState::FAILED;
            break;
        case SctpState::CLOSED:
        default:
            session->state = SessionState::IDLE;
            break;
    }
}

bool SctpEngine::AddPath(TelcoSessionContext* session, uint32_t peer_ip, bool is_primary) {
    if (!session || peer_ip == 0) return false;
    auto& state = GetAssocState(session);

    for (size_t i = 0; i < state.path_count; ++i) {
        if (state.paths[i].ip == peer_ip) {
            if (is_primary) {
                SetPrimaryPath(session, peer_ip);
            }
            return true;
        }
    }

    if (state.path_count >= SCTP_MAX_PATHS) {
        return false;
    }

    size_t idx = state.path_count;
    state.paths[idx].ip = peer_ip;
    state.paths[idx].port = session->peer_port;
    std::memcpy(state.paths[idx].mac, session->peer_mac, 6);
    state.paths[idx].status = SctpPathStatus::UNCONFIRMED;
    state.paths[idx].error_counter = 0;
    state.paths[idx].rto_ms = config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 1000;
    state.paths[idx].is_primary = is_primary;
    state.path_count++;

    session->SetSctpPathCount(state.path_count);

    if (is_primary) {
        SetPrimaryPath(session, peer_ip);
    }
    return true;
}

bool SctpEngine::RemovePath(TelcoSessionContext* session, uint32_t peer_ip) {
    if (!session || peer_ip == 0) return false;
    auto& state = GetAssocState(session);

    size_t found_idx = SIZE_MAX;
    for (size_t i = 0; i < state.path_count; ++i) {
        if (state.paths[i].ip == peer_ip) {
            found_idx = i;
            break;
        }
    }

    if (found_idx == SIZE_MAX || state.path_count <= 1) {
        return false;
    }

    bool was_primary = state.paths[found_idx].is_primary;
    bool was_active = (state.active_path_idx == found_idx);

    for (size_t i = found_idx; i + 1 < state.path_count; ++i) {
        state.paths[i] = state.paths[i + 1];
    }
    state.path_count--;
    state.paths[state.path_count] = SctpPath{};

    session->SetSctpPathCount(state.path_count);

    if (was_primary || state.primary_path_idx >= state.path_count) {
        state.primary_path_idx = 0;
        state.paths[0].is_primary = true;
        session->SetSctpPrimaryPathIndex(0);
    }
    if (was_active || state.active_path_idx >= state.path_count) {
        state.active_path_idx = state.primary_path_idx;
        session->SetSctpActivePathIndex(state.active_path_idx);
        session->peer_ip = state.paths[state.active_path_idx].ip;
    }
    return true;
}

bool SctpEngine::SetPrimaryPath(TelcoSessionContext* session, uint32_t peer_ip) {
    if (!session || peer_ip == 0) return false;
    auto& state = GetAssocState(session);

    size_t found_idx = SIZE_MAX;
    for (size_t i = 0; i < state.path_count; ++i) {
        if (state.paths[i].ip == peer_ip) {
            found_idx = i;
            break;
        }
    }

    if (found_idx == SIZE_MAX) return false;

    for (size_t i = 0; i < state.path_count; ++i) {
        state.paths[i].is_primary = (i == found_idx);
    }
    state.primary_path_idx = static_cast<uint8_t>(found_idx);
    state.active_path_idx = static_cast<uint8_t>(found_idx);
    session->peer_ip = peer_ip;
    session->SetSctpPrimaryPathIndex(state.primary_path_idx);
    session->SetSctpActivePathIndex(state.active_path_idx);
    return true;
}

size_t SctpEngine::GetPathCount(const TelcoSessionContext* session) const {
    if (!session) return 0;
    return GetAssocState(session).path_count;
}

const SctpPath* SctpEngine::GetPath(const TelcoSessionContext* session, size_t index) const {
    if (!session) return nullptr;
    const auto& state = GetAssocState(session);
    if (index >= state.path_count) return nullptr;
    return &state.paths[index];
}

const SctpPath* SctpEngine::GetPrimaryPath(const TelcoSessionContext* session) const {
    if (!session) return nullptr;
    const auto& state = GetAssocState(session);
    if (state.primary_path_idx < state.path_count) {
        return &state.paths[state.primary_path_idx];
    }
    return nullptr;
}

const SctpPath* SctpEngine::GetActivePath(const TelcoSessionContext* session) const {
    if (!session) return nullptr;
    const auto& state = GetAssocState(session);
    if (state.active_path_idx < state.path_count) {
        return &state.paths[state.active_path_idx];
    }
    return nullptr;
}

size_t SctpEngine::GetActivePathIndex(const TelcoSessionContext* session) const {
    if (!session) return 0;
    return GetAssocState(session).active_path_idx;
}

void SctpEngine::HandlePathError(TelcoSessionContext* session, size_t path_idx) {
    if (!session) return;
    auto& state = GetAssocState(session);
    if (path_idx >= state.path_count) return;

    state.paths[path_idx].error_counter++;
    if (state.paths[path_idx].error_counter >= state.path_max_retrans) {
        state.paths[path_idx].status = SctpPathStatus::INACTIVE;
        if (state.active_path_idx == path_idx) {
            FailoverPath(session);
        }
    }
}

bool SctpEngine::FailoverPath(TelcoSessionContext* session) {
    if (!session) return false;
    auto& state = GetAssocState(session);
    if (state.path_count <= 1) return false;

    size_t new_idx = SIZE_MAX;
    // 1. Önce başka bir ACTIVE yol ara
    for (size_t i = 0; i < state.path_count; ++i) {
        if (i != state.active_path_idx && state.paths[i].status == SctpPathStatus::ACTIVE) {
            new_idx = i;
            break;
        }
    }

    // 2. Bulunamazsa UNCONFIRMED yol ara
    if (new_idx == SIZE_MAX) {
        for (size_t i = 0; i < state.path_count; ++i) {
            if (i != state.active_path_idx && state.paths[i].status == SctpPathStatus::UNCONFIRMED) {
                new_idx = i;
                break;
            }
        }
    }

    if (new_idx == SIZE_MAX) {
        return false;
    }

    // Aktif yolu güncelle
    state.active_path_idx = static_cast<uint8_t>(new_idx);
    uint32_t new_peer_ip = state.paths[new_idx].ip;

    session_mgr_.Unbind5Tuple(session);
    session->peer_ip = new_peer_ip;
    std::memcpy(session->peer_mac, state.paths[new_idx].mac, 6);
    session->SetSctpActivePathIndex(state.active_path_idx);
    session_mgr_.Bind5Tuple(session, session->client_ip, new_peer_ip, session->client_port, session->peer_port, IP_PROTO_SCTP);

    return true;
}

uint32_t SctpEngine::GetAsconfSerial(const TelcoSessionContext* session) const {
    if (!session) return 0;
    return GetAssocState(session).asconf_serial;
}

uint32_t SctpEngine::GetAsconfAckSerial(const TelcoSessionContext* session) const {
    if (!session) return 0;
    return GetAssocState(session).asconf_ack_serial;
}

void SctpEngine::StartAssociation(TelcoSessionContext* session, const SctpAssociationConfig& cfg) {
    if (!session) return;

    session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::SCTP);
    session->client_ip = cfg.local_ip;
    session->peer_ip = cfg.peer_ip;
    session->client_port = cfg.local_port;
    session->peer_port = cfg.peer_port;
    session->ip_proto = IP_PROTO_SCTP;
    session->s_vlan = cfg.vlan_s;
    session->c_vlan = cfg.vlan_c;
    session->session_id = cfg.my_vtag;
    session->ppp_magic_number = cfg.peer_vtag; // remote vtag
    session->teid_uplink = cfg.my_initial_tsn;
    session->teid_downlink = cfg.peer_initial_tsn;
    session->retry_count = 0;

    std::memcpy(session->client_mac, cfg.local_mac, 6);
    std::memcpy(session->peer_mac, cfg.peer_mac, 6);

    // Multihoming Yol Durumunu Başlat (RFC 4960 §5.1.2)
    auto& state = GetAssocState(session);
    state.Reset();
    state.path_max_retrans = cfg.path_max_retrans > 0 ? cfg.path_max_retrans : 3;

    state.paths[0].ip = cfg.peer_ip;
    state.paths[0].port = cfg.peer_port;
    std::memcpy(state.paths[0].mac, cfg.peer_mac, 6);
    state.paths[0].status = SctpPathStatus::ACTIVE;
    state.paths[0].is_primary = true;
    state.paths[0].rto_ms = cfg.retransmit_timeout_ms > 0 ? cfg.retransmit_timeout_ms : 1000;
    state.paths[0].error_counter = 0;
    state.path_count = 1;

    for (uint32_t sec_ip : cfg.peer_secondary_ips) {
        if (state.path_count >= SCTP_MAX_PATHS) break;
        if (sec_ip == cfg.peer_ip || sec_ip == 0) continue;
        size_t idx = state.path_count;
        state.paths[idx].ip = sec_ip;
        state.paths[idx].port = cfg.peer_port;
        std::memcpy(state.paths[idx].mac, cfg.peer_mac, 6);
        state.paths[idx].status = SctpPathStatus::UNCONFIRMED;
        state.paths[idx].is_primary = false;
        state.paths[idx].rto_ms = cfg.retransmit_timeout_ms > 0 ? cfg.retransmit_timeout_ms : 1000;
        state.paths[idx].error_counter = 0;
        state.path_count++;
    }

    state.primary_path_idx = 0;
    state.active_path_idx = 0;

    session->SetSctpPrimaryPathIndex(0);
    session->SetSctpActivePathIndex(0);
    session->SetSctpPathCount(state.path_count);

    session_mgr_.Bind5Tuple(session, cfg.local_ip, cfg.peer_ip, cfg.local_port, cfg.peer_port, IP_PROTO_SCTP);

    SetState(session, SctpState::COOKIE_WAIT);

    // INIT paketi üret ve ilet
    last_tx_frame_ = BuildInitPacket(session);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    if (timing_wheel_) {
        timing_wheel_->Schedule(session, cfg.retransmit_timeout_ms > 0 ? cfg.retransmit_timeout_ms : 1000);
    }
}

void SctpEngine::StopAssociation(TelcoSessionContext* session) {
    if (!session) return;

    if (timing_wheel_) {
        timing_wheel_->Cancel(session);
    }

    if (GetState(session) == SctpState::ESTABLISHED) {
        SetState(session, SctpState::SHUTDOWN_SENT);
        last_tx_frame_ = BuildShutdownPacket(session);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        if (timing_wheel_) {
            timing_wheel_->Schedule(session, config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 1000);
        }
    } else {
        SetState(session, SctpState::CLOSED);
    }
}

std::vector<uint8_t> SctpEngine::BuildInitPacket(TelcoSessionContext* session) {
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + 
                       sizeof(SctpChunkHeader) + sizeof(SctpInitChunkBody);
    std::vector<uint8_t> packet(total_len, 0);

    // 1. Ethernet
    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    // 2. IPv4
    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->tos = 0;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->id = htons(0x5C71);
    ip->flags_fragment = 0;
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    // 3. SCTP Common Header
    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = 0; // INIT'te VTag daima 0'dır (RFC 4960)
    sctp->checksum = 0;

    // 4. INIT Chunk Header
    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::INIT);
    chunk->flags = 0;
    chunk->length = htons(sizeof(SctpChunkHeader) + sizeof(SctpInitChunkBody));

    // 5. INIT Chunk Body
    auto* body = reinterpret_cast<SctpInitChunkBody*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader));
    body->initiate_tag = htonl(session->session_id); // My VTag
    body->a_rwnd = htonl(65536);
    body->num_outbound_streams = htons(10);
    body->num_inbound_streams = htons(10);
    body->initial_tsn = htonl(session->teid_uplink); // My Initial TSN

    // 6. Compute CRC32c over SCTP PDU
    size_t sctp_len = total_len - sctp_offset;
    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, sctp_len);
    std::memcpy(&sctp->checksum, &crc, 4);

    return packet;
}

std::vector<uint8_t> SctpEngine::BuildInitAckPacket(TelcoSessionContext* session, uint32_t peer_initiate_tag, uint32_t peer_initial_tsn) {
    session->ppp_magic_number = peer_initiate_tag; // Remote VTag
    session->teid_downlink = peer_initial_tsn;    // Remote TSN

    // Basit 16 baytlık State Cookie simülasyonu
    uint8_t cookie_data[16] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
                               0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00};
    last_cookie_.assign(cookie_data, cookie_data + 16);

    // RFC 4960 §3.3.3.1: State Cookie değişken parametresi TLV olarak eklenir (Type=7, Len=4+16=20)
    constexpr uint16_t kCookieParamType = 7;
    constexpr uint16_t kCookieParamLen = 4 + sizeof(cookie_data);
    size_t sctp_payload_len = sizeof(SctpChunkHeader) + sizeof(SctpInitChunkBody) + kCookieParamLen;
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + sctp_payload_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->id = htons(0x5C72);
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(peer_initiate_tag);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::INIT_ACK);
    chunk->flags = 0;
    chunk->length = htons(static_cast<uint16_t>(sctp_payload_len));

    auto* body = reinterpret_cast<SctpInitChunkBody*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader));
    body->initiate_tag = htonl(session->session_id);
    body->a_rwnd = htonl(65536);
    body->num_outbound_streams = htons(10);
    body->num_inbound_streams = htons(10);
    body->initial_tsn = htonl(session->teid_uplink);

    uint8_t* param_ptr = packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader) + sizeof(SctpInitChunkBody);
    uint16_t param_type_net = htons(kCookieParamType);
    uint16_t param_len_net = htons(kCookieParamLen);
    std::memcpy(param_ptr, &param_type_net, 2);
    std::memcpy(param_ptr + 2, &param_len_net, 2);
    std::memcpy(param_ptr + 4, cookie_data, sizeof(cookie_data));

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    return packet;
}

std::vector<uint8_t> SctpEngine::BuildCookieEchoPacket(TelcoSessionContext* session, const std::vector<uint8_t>& cookie) {
    size_t chunk_len = sizeof(SctpChunkHeader) + cookie.size();
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number); // Remote VTag
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::COOKIE_ECHO);
    chunk->flags = 0;
    chunk->length = htons(static_cast<uint16_t>(chunk_len));

    std::memcpy(packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader),
                cookie.data(), cookie.size());

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    return packet;
}

std::vector<uint8_t> SctpEngine::BuildCookieAckPacket(TelcoSessionContext* session) {
    size_t chunk_len = sizeof(SctpChunkHeader);
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::COOKIE_ACK);
    chunk->flags = 0;
    chunk->length = htons(sizeof(SctpChunkHeader));

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    return packet;
}

std::vector<uint8_t> SctpEngine::BuildHeartbeatPacket(TelcoSessionContext* session, size_t path_idx) {
    if (!session) return {};

    const auto& state = GetAssocState(session);
    uint32_t target_ip = session->peer_ip;
    const uint8_t* target_mac = session->peer_mac;

    if (path_idx < state.path_count) {
        target_ip = state.paths[path_idx].ip;
        target_mac = state.paths[path_idx].mac;
    }

    // RFC 4960 §3.3.5 Heartbeat Info Parametresi (16 Bayt)
    uint8_t hb_info[16];
    uint16_t param_type = htons(0x0001); // Heartbeat Info Type
    uint16_t param_len = htons(16);      // Param Length
    uint32_t sender_ip = htonl(session->client_ip);
    uint32_t target_ip_net = htonl(target_ip);
    uint32_t nonce = htonl(static_cast<uint32_t>(path_idx) ^ 0xCAFEBABE);

    std::memcpy(hb_info, &param_type, 2);
    std::memcpy(hb_info + 2, &param_len, 2);
    std::memcpy(hb_info + 4, &sender_ip, 4);
    std::memcpy(hb_info + 8, &target_ip_net, 4);
    std::memcpy(hb_info + 12, &nonce, 4);

    size_t chunk_len = sizeof(SctpChunkHeader) + sizeof(hb_info);
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, target_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(target_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::HEARTBEAT);
    chunk->flags = 0;
    chunk->length = htons(static_cast<uint16_t>(chunk_len));

    std::memcpy(packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader),
                hb_info, sizeof(hb_info));

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    return packet;
}

bool SctpEngine::ProbePathHeartbeat(TelcoSessionContext* session, size_t path_idx, uint64_t now_tsc) {
    if (!session) return false;
    auto& state = GetAssocState(session);
    if (path_idx >= state.path_count) return false;

    state.paths[path_idx].last_hb_tsc = now_tsc;
    last_tx_frame_ = BuildHeartbeatPacket(session, path_idx);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();
    return true;
}

std::vector<uint8_t> SctpEngine::BuildHeartbeatAckPacket(TelcoSessionContext* session, const uint8_t* info_param, size_t info_len) {
    size_t chunk_len = sizeof(SctpChunkHeader) + info_len;
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::HEARTBEAT_ACK);
    chunk->flags = 0;
    chunk->length = htons(static_cast<uint16_t>(chunk_len));

    if (info_param && info_len > 0) {
        std::memcpy(packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader),
                    info_param, info_len);
    }

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    return packet;
}

std::vector<uint8_t> SctpEngine::BuildDataPacket(TelcoSessionContext* session, uint32_t ppid, const uint8_t* payload, size_t payload_len) {
    size_t chunk_len = sizeof(SctpChunkHeader) + sizeof(SctpDataChunkBody) + payload_len;
    size_t padded_chunk_len = (chunk_len + 3) & ~3; // 4-byte padding per RFC 4960
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + padded_chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::DATA);
    chunk->flags = 0x03; // B=1, E=1 (unfragmented message)
    chunk->length = htons(static_cast<uint16_t>(chunk_len));

    auto* data_body = reinterpret_cast<SctpDataChunkBody*>(
        packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader));
    data_body->tsn = htonl(session->teid_uplink++);
    data_body->stream_id = htons(0);
    data_body->stream_seq = htons(0);
    data_body->ppid = htonl(ppid);

    if (payload && payload_len > 0) {
        std::memcpy(packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader) + sizeof(SctpDataChunkBody),
                    payload, payload_len);
    }

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    return packet;
}

std::vector<uint8_t> SctpEngine::BuildSackPacket(TelcoSessionContext* session, uint32_t cumulative_tsn) {
    size_t chunk_len = sizeof(SctpChunkHeader) + sizeof(SctpSackChunkBody);
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::SACK);
    chunk->flags = 0;
    chunk->length = htons(sizeof(SctpChunkHeader) + sizeof(SctpSackChunkBody));

    auto* sack = reinterpret_cast<SctpSackChunkBody*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader));
    sack->cumulative_tsn_ack = htonl(cumulative_tsn);
    sack->a_rwnd = htonl(65536);
    sack->num_gap_ack_blocks = 0;
    sack->num_duplicate_tsn = 0;

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    return packet;
}

std::vector<uint8_t> SctpEngine::BuildShutdownPacket(TelcoSessionContext* session) {
    size_t chunk_len = sizeof(SctpChunkHeader) + 4; // 4-byte cumulative TSN
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::SHUTDOWN);
    chunk->flags = 0;
    chunk->length = htons(static_cast<uint16_t>(chunk_len));

    uint32_t cum_tsn = htonl(session->teid_downlink);
    std::memcpy(packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader), &cum_tsn, 4);

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    return packet;
}

std::vector<uint8_t> SctpEngine::BuildShutdownAckPacket(TelcoSessionContext* session) {
    size_t chunk_len = sizeof(SctpChunkHeader);
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::SHUTDOWN_ACK);
    chunk->flags = 0;
    chunk->length = htons(sizeof(SctpChunkHeader));

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    return packet;
}

std::vector<uint8_t> SctpEngine::BuildShutdownCompletePacket(TelcoSessionContext* session) {
    size_t chunk_len = sizeof(SctpChunkHeader);
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::SHUTDOWN_COMPLETE);
    chunk->flags = 0;
    chunk->length = htons(sizeof(SctpChunkHeader));

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    return packet;
}

std::vector<uint8_t> SctpEngine::BuildForwardTsnPacket(TelcoSessionContext* session, 
                                                      uint32_t new_cumulative_tsn, 
                                                      const std::vector<std::pair<uint16_t, uint16_t>>& abandoned_streams) {
    if (!session) return {};

    size_t streams_len = abandoned_streams.size() * sizeof(SctpForwardTsnStreamEntry);
    size_t chunk_len = sizeof(SctpChunkHeader) + sizeof(SctpForwardTsnChunkBody) + streams_len;
    size_t padded_chunk_len = (chunk_len + 3) & ~3;
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + padded_chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::FORWARD_TSN);
    chunk->flags = 0;
    chunk->length = htons(static_cast<uint16_t>(chunk_len));

    auto* fwd_body = reinterpret_cast<SctpForwardTsnChunkBody*>(
        packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader));
    fwd_body->new_cumulative_tsn = htonl(new_cumulative_tsn);

    uint8_t* stream_ptr = packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader) + sizeof(SctpForwardTsnChunkBody);
    for (const auto& s : abandoned_streams) {
        auto* entry = reinterpret_cast<SctpForwardTsnStreamEntry*>(stream_ptr);
        entry->stream_id = htons(s.first);
        entry->stream_seq = htons(s.second);
        stream_ptr += sizeof(SctpForwardTsnStreamEntry);
    }

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    return packet;
}

std::vector<uint8_t> SctpEngine::BuildTimedDataPacket(TelcoSessionContext* session, 
                                                     uint16_t stream_id, 
                                                     uint32_t ppid, 
                                                     const uint8_t* payload, 
                                                     size_t payload_len, 
                                                     uint32_t lifetime_ms, 
                                                     uint64_t now_tsc) {
    if (!session) return {};

    auto& state = GetAssocState(session);
    uint32_t assigned_tsn = session->teid_uplink++;
    uint16_t s_idx = stream_id < SctpAssociationState::MAX_STREAMS ? stream_id : 0;
    uint16_t assigned_seq = state.next_stream_seq[s_idx]++;

    size_t slot = state.unacked_head % SctpAssociationState::MAX_UNACKED_CHUNKS;
    state.unacked_chunks[slot].tsn = assigned_tsn;
    state.unacked_chunks[slot].stream_id = stream_id;
    state.unacked_chunks[slot].stream_seq = assigned_seq;
    state.unacked_chunks[slot].expire_tsc = now_tsc + lifetime_ms * 2400000ULL;
    state.unacked_chunks[slot].active = true;
    state.unacked_chunks[slot].abandoned = false;
    state.unacked_head++;

    size_t chunk_len = sizeof(SctpChunkHeader) + sizeof(SctpDataChunkBody) + payload_len;
    size_t padded_chunk_len = (chunk_len + 3) & ~3;
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + padded_chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::DATA);
    chunk->flags = 0x03; // B=1, E=1
    chunk->length = htons(static_cast<uint16_t>(chunk_len));

    auto* data_body = reinterpret_cast<SctpDataChunkBody*>(
        packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader));
    data_body->tsn = htonl(assigned_tsn);
    data_body->stream_id = htons(stream_id);
    data_body->stream_seq = htons(assigned_seq);
    data_body->ppid = htonl(ppid);

    if (payload && payload_len > 0) {
        std::memcpy(packet.data() + sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader) + sizeof(SctpDataChunkBody),
                    payload, payload_len);
    }

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    last_tx_frame_ = packet;
    session->tx_packets++;
    session->tx_bytes += packet.size();

    return packet;
}

std::vector<uint8_t> SctpEngine::CheckTimedReliability(TelcoSessionContext* session, uint64_t now_tsc) {
    if (!session) return {};

    auto& state = GetAssocState(session);
    uint32_t highest_abandoned = 0;
    std::vector<std::pair<uint16_t, uint16_t>> abandoned_streams;

    for (size_t i = 0; i < SctpAssociationState::MAX_UNACKED_CHUNKS; ++i) {
        auto& c = state.unacked_chunks[i];
        if (c.active && !c.abandoned && now_tsc >= c.expire_tsc) {
            c.abandoned = true;
            c.active = false;
            if (c.tsn > highest_abandoned) {
                highest_abandoned = c.tsn;
            }
            abandoned_streams.emplace_back(c.stream_id, c.stream_seq);
        }
    }

    if (highest_abandoned > 0) {
        last_tx_frame_ = BuildForwardTsnPacket(session, highest_abandoned, abandoned_streams);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        return last_tx_frame_;
    }

    return {};
}

std::vector<uint8_t> SctpEngine::BuildAsconfPacket(TelcoSessionContext* session, 
                                                  uint16_t param_type, 
                                                  uint32_t ip_address, 
                                                  uint32_t correlation_id) {
    if (!session) return {};

    auto& state = GetAssocState(session);
    uint32_t serial = state.asconf_serial++;

    size_t chunk_len = sizeof(SctpChunkHeader) + sizeof(SctpAsconfChunkBody) + 
                       sizeof(SctpIpv4AddressParam) + sizeof(SctpAsconfAddressParam);
    size_t padded_chunk_len = (chunk_len + 3) & ~3;
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + padded_chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::ASCONF);
    chunk->flags = 0;
    chunk->length = htons(static_cast<uint16_t>(chunk_len));

    size_t body_offset = sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader);
    auto* asconf_body = reinterpret_cast<SctpAsconfChunkBody*>(packet.data() + body_offset);
    asconf_body->serial_number = htonl(serial);

    size_t addr_offset = body_offset + sizeof(SctpAsconfChunkBody);
    auto* lookup_addr = reinterpret_cast<SctpIpv4AddressParam*>(packet.data() + addr_offset);
    lookup_addr->type = htons(SCTP_ASCONF_PARAM_IPV4);
    lookup_addr->length = htons(sizeof(SctpIpv4AddressParam));
    lookup_addr->ipv4_address = htonl(session->client_ip);

    size_t param_offset = addr_offset + sizeof(SctpIpv4AddressParam);
    auto* asconf_param = reinterpret_cast<SctpAsconfAddressParam*>(packet.data() + param_offset);
    asconf_param->type = htons(param_type);
    asconf_param->length = htons(sizeof(SctpAsconfAddressParam));
    asconf_param->correlation_id = htonl(correlation_id);
    asconf_param->addr.type = htons(SCTP_ASCONF_PARAM_IPV4);
    asconf_param->addr.length = htons(sizeof(SctpIpv4AddressParam));
    asconf_param->addr.ipv4_address = htonl(ip_address);

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    last_tx_frame_ = packet;
    session->tx_packets++;
    session->tx_bytes += packet.size();

    return packet;
}

std::vector<uint8_t> SctpEngine::BuildAsconfAddIpPacket(TelcoSessionContext* session, uint32_t new_ip, uint32_t correlation_id) {
    return BuildAsconfPacket(session, SCTP_ASCONF_PARAM_ADD_IP, new_ip, correlation_id);
}

std::vector<uint8_t> SctpEngine::BuildAsconfDeleteIpPacket(TelcoSessionContext* session, uint32_t del_ip, uint32_t correlation_id) {
    return BuildAsconfPacket(session, SCTP_ASCONF_PARAM_DEL_IP, del_ip, correlation_id);
}

std::vector<uint8_t> SctpEngine::BuildAsconfSetPrimaryIpPacket(TelcoSessionContext* session, uint32_t primary_ip, uint32_t correlation_id) {
    return BuildAsconfPacket(session, SCTP_ASCONF_PARAM_SET_PRIMARY, primary_ip, correlation_id);
}

std::vector<uint8_t> SctpEngine::BuildAsconfAckPacket(TelcoSessionContext* session, 
                                                     uint32_t serial_number, 
                                                     const std::vector<uint32_t>& correlation_ids) {
    if (!session) return {};

    size_t params_len = correlation_ids.size() * sizeof(SctpAsconfSuccessParam);
    size_t chunk_len = sizeof(SctpChunkHeader) + sizeof(SctpAsconfAckChunkBody) + params_len;
    size_t padded_chunk_len = (chunk_len + 3) & ~3;
    size_t total_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader) + padded_chunk_len;
    std::vector<uint8_t> packet(total_len, 0);

    auto* eth = reinterpret_cast<EthHeader*>(packet.data());
    std::memcpy(eth->dst_mac, session->peer_mac, 6);
    std::memcpy(eth->src_mac, session->client_mac, 6);
    eth->ethertype = htons(0x0800);

    auto* ip = reinterpret_cast<Ipv4Header*>(packet.data() + sizeof(EthHeader));
    ip->ihl_version = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total_len - sizeof(EthHeader)));
    ip->ttl = 64;
    ip->protocol = IP_PROTO_SCTP;
    ip->src_ip = htonl(session->client_ip);
    ip->dst_ip = htonl(session->peer_ip);
    ip->checksum = ComputeIpChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));

    size_t sctp_offset = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* sctp = reinterpret_cast<SctpCommonHeader*>(packet.data() + sctp_offset);
    sctp->src_port = htons(session->client_port);
    sctp->dst_port = htons(session->peer_port);
    sctp->verification_tag = htonl(session->ppp_magic_number);
    sctp->checksum = 0;

    auto* chunk = reinterpret_cast<SctpChunkHeader*>(packet.data() + sctp_offset + sizeof(SctpCommonHeader));
    chunk->type = static_cast<uint8_t>(SctpChunkType::ASCONF_ACK);
    chunk->flags = 0;
    chunk->length = htons(static_cast<uint16_t>(chunk_len));

    size_t body_offset = sctp_offset + sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader);
    auto* ack_body = reinterpret_cast<SctpAsconfAckChunkBody*>(packet.data() + body_offset);
    ack_body->serial_number = htonl(serial_number);

    uint8_t* p_ptr = packet.data() + body_offset + sizeof(SctpAsconfAckChunkBody);
    for (uint32_t cid : correlation_ids) {
        auto* succ = reinterpret_cast<SctpAsconfSuccessParam*>(p_ptr);
        succ->type = htons(SCTP_ASCONF_PARAM_SUCCESS);
        succ->length = htons(sizeof(SctpAsconfSuccessParam));
        succ->correlation_id = htonl(cid);
        p_ptr += sizeof(SctpAsconfSuccessParam);
    }

    uint32_t crc = ComputeCrc32c(packet.data() + sctp_offset, total_len - sctp_offset);
    std::memcpy(&sctp->checksum, &crc, 4);

    last_tx_frame_ = packet;
    session->tx_packets++;
    session->tx_bytes += packet.size();

    return packet;
}

bool SctpEngine::ProcessRxFrame(const uint8_t* frame, size_t len, uint64_t now_tsc) {
    size_t min_len = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(SctpCommonHeader);
    if (!frame || len < min_len) return false;

    size_t offset = 12;
    uint16_t ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
    offset += 2;

    // Peel VLAN tags
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

    if (ethertype != 0x0800 || len < offset + sizeof(Ipv4Header) + sizeof(SctpCommonHeader)) {
        return false;
    }

    const auto* ip = reinterpret_cast<const Ipv4Header*>(frame + offset);
    if ((ip->ihl_version >> 4) != 4 || ip->protocol != IP_PROTO_SCTP) return false;

    size_t ip_len = (ip->ihl_version & 0x0F) * 4;
    size_t sctp_offset = offset + ip_len;
    if (len < sctp_offset + sizeof(SctpCommonHeader)) return false;

    const auto* sctp = reinterpret_cast<const SctpCommonHeader*>(frame + sctp_offset);
    size_t sctp_len = len - sctp_offset;

    // CRC32c Doğrulaması
    uint32_t wire_crc = 0;
    std::memcpy(&wire_crc, &sctp->checksum, 4);

    // Checksum alanını 0 kabul ederek hesapla
    std::vector<uint8_t> sctp_buf(frame + sctp_offset, frame + len);
    std::memset(sctp_buf.data() + 8, 0, 4);
    uint32_t calc_crc = ComputeCrc32c(sctp_buf.data(), sctp_buf.size());

    if (wire_crc != calc_crc) {
        return false; // Hatalı CRC32c paketi doğrudan reddedilir!
    }

    uint32_t vtag = ntohl(sctp->verification_tag);
    uint32_t src_ip = ntohl(ip->src_ip);
    uint32_t dst_ip = ntohl(ip->dst_ip);
    uint16_t src_port = ntohs(sctp->src_port);
    uint16_t dst_port = ntohs(sctp->dst_port);

    // Oturum eşleştirme: 5-Tuple veya aktif oturumlarda VTag
    TelcoSessionContext* session = session_mgr_.FindSessionBy5Tuple(dst_ip, src_ip, dst_port, src_port, IP_PROTO_SCTP);
    if (!session && vtag != 0) {
        for (TelcoSessionContext* s : active_sctp_sessions_) {
            if (s && s->protocol_id == static_cast<uint8_t>(TelcoProtocolId::SCTP) && s->session_id == vtag) {
                session = s;
                break;
            }
        }
    }

    if (!session) {
        // İlk INIT paketi olabilir; yeni oturum tahsis et
        const auto* first_chunk = reinterpret_cast<const SctpChunkHeader*>(frame + sctp_offset + sizeof(SctpCommonHeader));
        if (sctp_len >= sizeof(SctpCommonHeader) + sizeof(SctpChunkHeader) &&
            first_chunk->type == static_cast<uint8_t>(SctpChunkType::INIT)) {
            session = session_mgr_.AcquireSession();
            if (session) {
                session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::SCTP);
                session->client_ip = dst_ip;
                session->peer_ip = src_ip;
                session->client_port = dst_port;
                session->peer_port = src_port;
                session->ip_proto = IP_PROTO_SCTP;
                session->session_id = 0x98765432; // Local VTag
                session_mgr_.Bind5Tuple(session, dst_ip, src_ip, dst_port, src_port, IP_PROTO_SCTP);
                active_sctp_sessions_.push_back(session);
            }
        }
    }

    if (!session) return false;

    session->rx_packets++;
    session->rx_bytes += len;
    session->last_activity_tsc = now_tsc;

    return ParseAndProcessChunks(session, frame + sctp_offset, sctp_len, now_tsc);
}

bool SctpEngine::ParseAndProcessChunks(TelcoSessionContext* session, const uint8_t* sctp_pkt, size_t sctp_len, uint64_t now_tsc) {
    size_t offset = sizeof(SctpCommonHeader);

    while (offset + sizeof(SctpChunkHeader) <= sctp_len) {
        const auto* chunk = reinterpret_cast<const SctpChunkHeader*>(sctp_pkt + offset);
        uint16_t chunk_len = ntohs(chunk->length);
        if (chunk_len < sizeof(SctpChunkHeader) || offset + chunk_len > sctp_len) break;

        auto type = static_cast<SctpChunkType>(chunk->type);
        const uint8_t* chunk_body = sctp_pkt + offset + sizeof(SctpChunkHeader);
        size_t body_len = chunk_len - sizeof(SctpChunkHeader);

        switch (type) {
            case SctpChunkType::INIT: {
                if (body_len >= sizeof(SctpInitChunkBody)) {
                    const auto* init_body = reinterpret_cast<const SctpInitChunkBody*>(chunk_body);
                    uint32_t peer_vtag = ntohl(init_body->initiate_tag);
                    uint32_t peer_tsn = ntohl(init_body->initial_tsn);

                    SetState(session, SctpState::CLOSED);
                    last_tx_frame_ = BuildInitAckPacket(session, peer_vtag, peer_tsn);
                    session->tx_packets++;
                    session->tx_bytes += last_tx_frame_.size();
                }
                break;
            }

            case SctpChunkType::INIT_ACK: {
                if (body_len >= sizeof(SctpInitChunkBody)) {
                    const auto* init_ack_body = reinterpret_cast<const SctpInitChunkBody*>(chunk_body);
                    session->ppp_magic_number = ntohl(init_ack_body->initiate_tag);
                    session->teid_downlink = ntohl(init_ack_body->initial_tsn);

                    // RFC 4960 §3.3.3.1 TLV parametrelerini tara (Type 7: State Cookie)
                    size_t param_offset = sizeof(SctpInitChunkBody);
                    std::vector<uint8_t> cookie;
                    while (param_offset + 4 <= body_len) {
                        uint16_t p_type = (static_cast<uint16_t>(chunk_body[param_offset]) << 8) | chunk_body[param_offset + 1];
                        uint16_t p_len = (static_cast<uint16_t>(chunk_body[param_offset + 2]) << 8) | chunk_body[param_offset + 3];
                        if (p_len < 4 || param_offset + p_len > body_len) break;
                        if (p_type == 7) {
                            cookie.assign(chunk_body + param_offset + 4, chunk_body + param_offset + p_len);
                            break;
                        }
                        size_t padded_len = (p_len + 3) & ~3;
                        param_offset += padded_len;
                    }
                    if (cookie.empty()) {
                        // Geriye dönük uyumluluk: ham cookie verisi
                        if (body_len > sizeof(SctpInitChunkBody)) {
                            cookie.assign(chunk_body + sizeof(SctpInitChunkBody), chunk_body + body_len);
                        } else {
                            cookie.assign(16, 0x5A);
                        }
                    }

                    SetState(session, SctpState::COOKIE_ECHOED);
                    last_tx_frame_ = BuildCookieEchoPacket(session, cookie);
                    session->tx_packets++;
                    session->tx_bytes += last_tx_frame_.size();

                    if (timing_wheel_) {
                        timing_wheel_->Schedule(session, config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 1000);
                    }
                }
                break;
            }

            case SctpChunkType::COOKIE_ECHO: {
                SetState(session, SctpState::ESTABLISHED);
                last_tx_frame_ = BuildCookieAckPacket(session);
                session->tx_packets++;
                session->tx_bytes += last_tx_frame_.size();
                break;
            }

            case SctpChunkType::COOKIE_ACK: {
                if (GetState(session) == SctpState::COOKIE_ECHOED) {
                    SetState(session, SctpState::ESTABLISHED);
                    if (timing_wheel_) {
                        timing_wheel_->Cancel(session);
                        timing_wheel_->Schedule(session, 5000); // 5s Heartbeat
                    }
                }
                break;
            }

            case SctpChunkType::HEARTBEAT: {
                last_tx_frame_ = BuildHeartbeatAckPacket(session, chunk_body, body_len);
                session->tx_packets++;
                session->tx_bytes += last_tx_frame_.size();
                break;
            }

            case SctpChunkType::HEARTBEAT_ACK: {
                session->retry_count = 0;
                auto& state = GetAssocState(session);
                uint32_t acked_path_ip = 0;
                if (body_len >= 16) {
                    uint16_t param_type = (static_cast<uint16_t>(chunk_body[0]) << 8) | chunk_body[1];
                    if (param_type == 0x0001) {
                        std::memcpy(&acked_path_ip, chunk_body + 8, 4);
                        acked_path_ip = ntohl(acked_path_ip);
                    }
                }
                if (acked_path_ip == 0) {
                    acked_path_ip = session->peer_ip;
                }

                for (size_t i = 0; i < state.path_count; ++i) {
                    if (state.paths[i].ip == acked_path_ip) {
                        state.paths[i].error_counter = 0;
                        if (state.paths[i].status == SctpPathStatus::UNCONFIRMED ||
                            state.paths[i].status == SctpPathStatus::INACTIVE) {
                            state.paths[i].status = SctpPathStatus::ACTIVE;
                        }
                        break;
                    }
                }

                if (timing_wheel_) {
                    timing_wheel_->Cancel(session);
                    timing_wheel_->Schedule(session, 5000); // Yeniden 5s sonra Heartbeat
                }
                break;
            }

            case SctpChunkType::DATA: {
                if (body_len >= sizeof(SctpDataChunkBody)) {
                    const auto* data_body = reinterpret_cast<const SctpDataChunkBody*>(chunk_body);
                    uint32_t tsn = ntohl(data_body->tsn);
                    session->teid_downlink = tsn;

                    // Otomatik SACK üret
                    last_tx_frame_ = BuildSackPacket(session, tsn);
                    session->tx_packets++;
                    session->tx_bytes += last_tx_frame_.size();
                }
                break;
            }

            case SctpChunkType::FORWARD_TSN: {
                if (body_len >= sizeof(SctpForwardTsnChunkBody)) {
                    const auto* fwd = reinterpret_cast<const SctpForwardTsnChunkBody*>(chunk_body);
                    uint32_t new_cum_tsn = ntohl(fwd->new_cumulative_tsn);
                    if (new_cum_tsn > session->teid_downlink) {
                        session->teid_downlink = new_cum_tsn;
                    }

                    auto& state = GetAssocState(session);
                    size_t entry_bytes = body_len - sizeof(SctpForwardTsnChunkBody);
                    size_t num_entries = entry_bytes / sizeof(SctpForwardTsnStreamEntry);
                    const auto* entries = reinterpret_cast<const SctpForwardTsnStreamEntry*>(
                        chunk_body + sizeof(SctpForwardTsnChunkBody));

                    for (size_t i = 0; i < num_entries; ++i) {
                        uint16_t sid = ntohs(entries[i].stream_id);
                        uint16_t sseq = ntohs(entries[i].stream_seq);
                        if (sid < SctpAssociationState::MAX_STREAMS) {
                            if (sseq >= state.next_stream_seq[sid]) {
                                state.next_stream_seq[sid] = sseq + 1;
                            }
                        }
                    }

                    // RFC 3758 §3.5: FORWARD_TSN işlendiğinde hemen güncel SACK üret
                    last_tx_frame_ = BuildSackPacket(session, session->teid_downlink);
                    session->tx_packets++;
                    session->tx_bytes += last_tx_frame_.size();
                }
                break;
            }

            case SctpChunkType::ASCONF: {
                if (body_len >= sizeof(SctpAsconfChunkBody)) {
                    const auto* asconf_body = reinterpret_cast<const SctpAsconfChunkBody*>(chunk_body);
                    uint32_t serial = ntohl(asconf_body->serial_number);

                    std::vector<uint32_t> success_correlations;
                    size_t p_offset = sizeof(SctpAsconfChunkBody);

                    // Adres parametresini kontrol et ve atla (RFC 5061)
                    if (p_offset + sizeof(SctpAsconfParamHeader) <= body_len) {
                        const auto* p_hdr = reinterpret_cast<const SctpAsconfParamHeader*>(chunk_body + p_offset);
                        uint16_t p_type = ntohs(p_hdr->type);
                        uint16_t p_len = ntohs(p_hdr->length);
                        if (p_type == SCTP_ASCONF_PARAM_IPV4 && p_len <= body_len - p_offset) {
                            p_offset += (p_len + 3) & ~3;
                        }
                    }

                    // TLV parametrelerini işle (Add IP, Del IP, Set Primary IP)
                    while (p_offset + sizeof(SctpAsconfParamHeader) <= body_len) {
                        const auto* p_hdr = reinterpret_cast<const SctpAsconfParamHeader*>(chunk_body + p_offset);
                        uint16_t p_type = ntohs(p_hdr->type);
                        uint16_t p_len = ntohs(p_hdr->length);
                        if (p_len < sizeof(SctpAsconfParamHeader) || p_offset + p_len > body_len) break;

                        if (p_type == SCTP_ASCONF_PARAM_ADD_IP && p_len >= sizeof(SctpAsconfAddressParam)) {
                            const auto* a_param = reinterpret_cast<const SctpAsconfAddressParam*>(chunk_body + p_offset);
                            uint32_t ip = ntohl(a_param->addr.ipv4_address);
                            uint32_t cid = ntohl(a_param->correlation_id);
                            AddPath(session, ip, false);
                            success_correlations.push_back(cid);
                        } else if (p_type == SCTP_ASCONF_PARAM_DEL_IP && p_len >= sizeof(SctpAsconfAddressParam)) {
                            const auto* a_param = reinterpret_cast<const SctpAsconfAddressParam*>(chunk_body + p_offset);
                            uint32_t ip = ntohl(a_param->addr.ipv4_address);
                            uint32_t cid = ntohl(a_param->correlation_id);
                            RemovePath(session, ip);
                            success_correlations.push_back(cid);
                        } else if (p_type == SCTP_ASCONF_PARAM_SET_PRIMARY && p_len >= sizeof(SctpAsconfAddressParam)) {
                            const auto* a_param = reinterpret_cast<const SctpAsconfAddressParam*>(chunk_body + p_offset);
                            uint32_t ip = ntohl(a_param->addr.ipv4_address);
                            uint32_t cid = ntohl(a_param->correlation_id);
                            SetPrimaryPath(session, ip);
                            success_correlations.push_back(cid);
                        }

                        p_offset += (p_len + 3) & ~3;
                    }

                    // ASCONF_ACK yanıtını derle ve gönder (RFC 5061 §3.1.2)
                    last_tx_frame_ = BuildAsconfAckPacket(session, serial, success_correlations);
                    session->tx_packets++;
                    session->tx_bytes += last_tx_frame_.size();
                }
                break;
            }

            case SctpChunkType::ASCONF_ACK: {
                if (body_len >= sizeof(SctpAsconfAckChunkBody)) {
                    const auto* ack_body = reinterpret_cast<const SctpAsconfAckChunkBody*>(chunk_body);
                    uint32_t serial = ntohl(ack_body->serial_number);
                    auto& state = GetAssocState(session);
                    state.asconf_ack_serial = serial;
                }
                break;
            }

            case SctpChunkType::SACK: {
                // SACK başarıyla işlendi
                break;
            }

            case SctpChunkType::SHUTDOWN: {
                SetState(session, SctpState::SHUTDOWN_RECEIVED);
                last_tx_frame_ = BuildShutdownAckPacket(session);
                session->tx_packets++;
                session->tx_bytes += last_tx_frame_.size();
                break;
            }

            case SctpChunkType::SHUTDOWN_ACK: {
                SetState(session, SctpState::CLOSED);
                last_tx_frame_ = BuildShutdownCompletePacket(session);
                session->tx_packets++;
                session->tx_bytes += last_tx_frame_.size();
                if (timing_wheel_) timing_wheel_->Cancel(session);
                break;
            }

            case SctpChunkType::SHUTDOWN_COMPLETE: {
                SetState(session, SctpState::CLOSED);
                if (timing_wheel_) timing_wheel_->Cancel(session);
                break;
            }

            case SctpChunkType::ABORT: {
                SetState(session, SctpState::CLOSED);
                if (timing_wheel_) timing_wheel_->Cancel(session);
                break;
            }

            default:
                break;
        }

        // 4 bayt hizalamaya yuvarla
        size_t padded_len = (chunk_len + 3) & ~3;
        offset += padded_len;
    }

    return true;
}

void SctpEngine::HandleTimeout(TelcoSessionContext* session) {
    if (!session) return;

    SctpState state = GetState(session);

    if (state == SctpState::COOKIE_WAIT) {
        session->retry_count++;
        if (session->retry_count >= config_.max_retries) {
            SetState(session, SctpState::FAILED);
            return;
        }
        last_tx_frame_ = BuildInitPacket(session);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        if (timing_wheel_) timing_wheel_->Schedule(session, (config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 1000) * (1 << session->retry_count));
        return;
    }

    if (state == SctpState::COOKIE_ECHOED) {
        session->retry_count++;
        if (session->retry_count >= config_.max_retries) {
            SetState(session, SctpState::FAILED);
            return;
        }
        last_tx_frame_ = BuildCookieEchoPacket(session, last_cookie_);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        if (timing_wheel_) timing_wheel_->Schedule(session, (config_.retransmit_timeout_ms > 0 ? config_.retransmit_timeout_ms : 1000) * (1 << session->retry_count));
        return;
    }

    if (state == SctpState::ESTABLISHED) {
        auto& a_state = GetAssocState(session);
        HandlePathError(session, a_state.active_path_idx);

        // Canlılık Heartbeat zamanı (aktif yola gönder)
        last_tx_frame_ = BuildHeartbeatPacket(session, a_state.active_path_idx);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        if (timing_wheel_) timing_wheel_->Schedule(session, 1000); // 1s Heartbeat Ack bekle
        return;
    }

    if (state == SctpState::SHUTDOWN_SENT) {
        session->retry_count++;
        if (session->retry_count >= config_.max_retries) {
            SetState(session, SctpState::CLOSED);
            return;
        }
        last_tx_frame_ = BuildShutdownPacket(session);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
        if (timing_wheel_) timing_wheel_->Schedule(session, 1000);
        return;
    }
}

uint32_t SctpEngine::OnTimerTick(uint64_t current_tsc) {
    if (!timing_wheel_) return 0;
    return timing_wheel_->Advance(current_tsc, [this](TelcoSessionContext* s) {
        HandleTimeout(s);
    });
}

void SctpEngine::OnRxPacket(rte_mbuf* /*mbuf*/, const PacketMetadata& meta, TelcoSessionContext* session) {
    if (meta.raw_frame && meta.raw_len > 0) {
        ProcessRxFrame(meta.raw_frame, meta.raw_len, session ? session->last_activity_tsc : 0);
    }
}

rte_mbuf* SctpEngine::BuildTxPacket(rte_mempool* /*pool*/, TelcoSessionContext* /*session*/, uint16_t /*event_type*/) {
    return nullptr;
}

} // namespace ddos_samurai::telecom::sctp
