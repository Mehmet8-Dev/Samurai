#include "samurai/telecom/protocols/stateful/pppoe/pppoe_engine.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <iostream>

namespace samurai::telecom::pppoe {

namespace {

// ---------------------------------------------------------------------------
// Standart RFC 1321 Uyumlu Bağımsız MD5 Gerçekleştirmesi (CHAP için)
// ---------------------------------------------------------------------------
struct Md5Context {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
};

#define F_MD5(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G_MD5(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H_MD5(x, y, z) ((x) ^ (y) ^ (z))
#define I_MD5(x, y, z) ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define FF(a, b, c, d, x, s, ac) { \
    (a) += F_MD5((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
    (a) += G_MD5((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
    (a) += H_MD5((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
    (a) += I_MD5((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

void Md5Transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    for (int i = 0, j = 0; j < 64; ++i, j += 4) {
        x[i] = (static_cast<uint32_t>(block[j])) |
               (static_cast<uint32_t>(block[j + 1]) << 8) |
               (static_cast<uint32_t>(block[j + 2]) << 16) |
               (static_cast<uint32_t>(block[j + 3]) << 24);
    }

    // Round 1
    FF(a, b, c, d, x[ 0],  7, 0xd76aa478);
    FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
    FF(c, d, a, b, x[ 2], 17, 0x242070db);
    FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
    FF(a, b, c, d, x[ 4],  7, 0xf57c0faf);
    FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
    FF(c, d, a, b, x[ 6], 17, 0xa8304613);
    FF(b, c, d, a, x[ 7], 22, 0xfd469501);
    FF(a, b, c, d, x[ 8],  7, 0x698098d8);
    FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
    FF(c, d, a, b, x[10], 17, 0xffff5bb1);
    FF(b, c, d, a, x[11], 22, 0x895cd7be);
    FF(a, b, c, d, x[12],  7, 0x6b901122);
    FF(d, a, b, c, x[13], 12, 0xfd987193);
    FF(c, d, a, b, x[14], 17, 0xa679438e);
    FF(b, c, d, a, x[15], 22, 0x49b40821);

    // Round 2
    GG(a, b, c, d, x[ 1],  5, 0xf61e2562);
    GG(d, a, b, c, x[ 6],  9, 0xc040b340);
    GG(c, d, a, b, x[11], 14, 0x265e5a51);
    GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
    GG(a, b, c, d, x[ 5],  5, 0xd62f105d);
    GG(d, a, b, c, x[10],  9, 0x02441453);
    GG(c, d, a, b, x[15], 14, 0xd8a1e681);
    GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
    GG(a, b, c, d, x[ 9],  5, 0x21e1cde6);
    GG(d, a, b, c, x[14],  9, 0xc33707d6);
    GG(c, d, a, b, x[ 3], 14, 0xf4d50d87);
    GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
    GG(a, b, c, d, x[13],  5, 0xa9e3e905);
    GG(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
    GG(c, d, a, b, x[ 7], 14, 0x676f02d9);
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

    // Round 3
    HH(a, b, c, d, x[ 5],  4, 0xfffa3942);
    HH(d, a, b, c, x[ 8], 11, 0x8771f681);
    HH(c, d, a, b, x[11], 16, 0x6d9d6122);
    HH(b, c, d, a, x[14], 23, 0xfde5380c);
    HH(a, b, c, d, x[ 1],  4, 0xa4beea44);
    HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
    HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60);
    HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    HH(a, b, c, d, x[13],  4, 0x289b7ec6);
    HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
    HH(c, d, a, b, x[ 3], 16, 0xd4ef3085);
    HH(b, c, d, a, x[ 6], 23, 0x04881d05);
    HH(a, b, c, d, x[ 9],  4, 0xd9d4d039);
    HH(d, a, b, c, x[12], 11, 0xe6db99e5);
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
    HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);

    // Round 4
    II(a, b, c, d, x[ 0],  6, 0xf4292244);
    II(d, a, b, c, x[ 7], 10, 0x432aff97);
    II(c, d, a, b, x[14], 15, 0xab9423a7);
    II(b, c, d, a, x[ 5], 21, 0xfc93a039);
    II(a, b, c, d, x[12],  6, 0x655b59c3);
    II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
    II(c, d, a, b, x[10], 15, 0xffeff47d);
    II(b, c, d, a, x[ 1], 21, 0x85845dd1);
    II(a, b, c, d, x[ 8],  6, 0x6fa87e4f);
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    II(c, d, a, b, x[ 6], 15, 0xa3014314);
    II(b, c, d, a, x[13], 21, 0x4e0811a1);
    II(a, b, c, d, x[ 4],  6, 0xf7537e82);
    II(d, a, b, c, x[11], 10, 0xbd3af235);
    II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
    II(b, c, d, a, x[ 9], 21, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void Md5Init(Md5Context* ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

void Md5Update(Md5Context* ctx, const uint8_t* input, size_t input_len) {
    uint32_t i = 0, index = (ctx->count[0] >> 3) & 63;
    if ((ctx->count[0] += (static_cast<uint32_t>(input_len) << 3)) < (static_cast<uint32_t>(input_len) << 3)) {
        ctx->count[1]++;
    }
    ctx->count[1] += static_cast<uint32_t>(input_len >> 29);

    uint32_t part_len = 64 - index;
    if (input_len >= part_len) {
        std::memcpy(&ctx->buffer[index], input, part_len);
        Md5Transform(ctx->state, ctx->buffer);
        for (i = part_len; i + 63 < input_len; i += 64) {
            Md5Transform(ctx->state, &input[i]);
        }
        index = 0;
    }
    std::memcpy(&ctx->buffer[index], &input[i], input_len - i);
}

void Md5Final(uint8_t digest[16], Md5Context* ctx) {
    static const uint8_t PADDING[64] = { 0x80 };
    uint8_t bits[8];
    for (int i = 0; i < 4; ++i) {
        bits[i] = (ctx->count[0] >> (i * 8)) & 0xFF;
        bits[i + 4] = (ctx->count[1] >> (i * 8)) & 0xFF;
    }

    uint32_t index = (ctx->count[0] >> 3) & 63;
    uint32_t pad_len = (index < 56) ? (56 - index) : (120 - index);
    Md5Update(ctx, PADDING, pad_len);
    Md5Update(ctx, bits, 8);

    for (int i = 0; i < 4; ++i) {
        digest[i * 4]     = (ctx->state[i]) & 0xFF;
        digest[i * 4 + 1] = (ctx->state[i] >> 8) & 0xFF;
        digest[i * 4 + 2] = (ctx->state[i] >> 16) & 0xFF;
        digest[i * 4 + 3] = (ctx->state[i] >> 24) & 0xFF;
    }
}

void ComputeChapMd5(uint8_t id, const std::string& secret, const uint8_t* challenge, size_t challenge_len, uint8_t out_digest[16]) {
    Md5Context ctx;
    Md5Init(&ctx);
    Md5Update(&ctx, &id, 1);
    Md5Update(&ctx, reinterpret_cast<const uint8_t*>(secret.data()), secret.size());
    Md5Update(&ctx, challenge, challenge_len);
    Md5Final(out_digest, &ctx);
}

} // namespace

// ---------------------------------------------------------------------------
// PppoeEngine Gerçekleştirmesi
// ---------------------------------------------------------------------------

PppoeEngine::PppoeEngine(SessionManager& session_mgr, HierarchicalTimingWheel* wheel)
    : session_mgr_(session_mgr), timing_wheel_(wheel) {}

bool PppoeEngine::Init(const ProtocolConfig& cfg) {
    config_ = cfg;
    return true;
}

void PppoeEngine::Shutdown() {
    last_tx_frame_.clear();
}

PppoeSubState PppoeEngine::GetSubState(const TelcoSessionContext* session) const noexcept {
    if (!session) return PppoeSubState::IDLE;
    return static_cast<PppoeSubState>(session->pad1[0]);
}

void PppoeEngine::SetSubState(TelcoSessionContext* session, PppoeSubState sub) noexcept {
    if (!session) return;
    session->pad1[0] = static_cast<uint8_t>(sub);
}

void PppoeEngine::SetCredentials(const std::string& username, const std::string& password, AuthProtocol proto) {
    username_ = username;
    password_ = password;
    auth_proto_ = proto;
}

void PppoeEngine::StartSession(TelcoSessionContext* session) {
    if (!session) return;

    session->state = SessionState::DISCOVERING;
    SetSubState(session, PppoeSubState::DISCOVERY_PADI_SENT);
    session->retry_count = 0;
    session->protocol_id = static_cast<uint8_t>(TelcoProtocolId::PPPOE);

    last_tx_frame_ = BuildPadiFrame(session);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    if (timing_wheel_) {
        timing_wheel_->Schedule(session, config_.retransmit_timeout_ms);
    }
}

void PppoeEngine::TerminateSession(TelcoSessionContext* session) {
    if (!session) return;

    if (session->session_id != 0) {
        last_tx_frame_ = BuildPadtFrame(session);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
    }

    session->state = SessionState::TERMINATING;
    SetSubState(session, PppoeSubState::TERMINATING);

    if (timing_wheel_) {
        timing_wheel_->Cancel(session);
    }

    session_mgr_.Unbind5Tuple(session);
}

uint32_t PppoeEngine::OnTimerTick(uint64_t current_tsc) {
    if (!timing_wheel_) return 0;
    return timing_wheel_->Advance(current_tsc, [this](TelcoSessionContext* session) {
        this->HandleTimeout(session);
    });
}

void PppoeEngine::HandleTimeout(TelcoSessionContext* session) {
    if (!session) return;

    PppoeSubState sub = GetSubState(session);

    // Aktif oturumda periyodik LCP Echo keepalive
    if (session->state == SessionState::ESTABLISHED && sub == PppoeSubState::ESTABLISHED) {
        last_tx_frame_ = BuildLcpEchoReqFrame(session);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();

        if (timing_wheel_) {
            timing_wheel_->Schedule(session, 1000); // 1 saniye sonraki echo
        }
        return;
    }

    // Kurulum aşamasında yeniden deneme
    session->retry_count++;
    if (session->retry_count <= config_.max_retries) {
        // Son çerçeveyi tekrar ilet (Retransmit)
        if (!last_tx_frame_.empty()) {
            session->tx_packets++;
            session->tx_bytes += last_tx_frame_.size();
        }
        if (timing_wheel_) {
            timing_wheel_->Schedule(session, config_.retransmit_timeout_ms);
        }
    } else {
        // Maksimum deneme aşıldı -> FAILED
        session->state = SessionState::FAILED;
        SetSubState(session, PppoeSubState::FAILED);
        if (timing_wheel_) {
            timing_wheel_->Cancel(session);
        }
    }
}

void PppoeEngine::OnRxPacket(rte_mbuf* /*mbuf*/, const PacketMetadata& meta, TelcoSessionContext* session) {
    if (meta.raw_frame && meta.raw_len >= 14) {
        ProcessRxFrame(meta.raw_frame, meta.raw_len, session);
    } else if (meta.payload_ptr && meta.payload_len > 0) {
        ProcessRxFrame(meta.payload_ptr, meta.payload_len, session);
    }
}

rte_mbuf* PppoeEngine::BuildTxPacket(rte_mempool* /*pool*/, TelcoSessionContext* /*session*/, uint16_t /*event_type*/) {
    // DPDK derlenmediğinde nullptr; raw byte builder'lar kullanılır
    return nullptr;
}

// ---------------------------------------------------------------------------
// Gelen Paket İşleme ve FSM Yönlendirmesi
// ---------------------------------------------------------------------------

bool PppoeEngine::ProcessRxFrame(const uint8_t* frame, size_t len, TelcoSessionContext* session) {
    if (!frame || len < 14) return false;

    size_t offset = 12;
    uint16_t ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
    offset += 2;

    uint16_t s_vlan = 0;
    uint16_t c_vlan = 0;

    // VLAN başlıklarını geç
    if (ethertype == 0x88A8 && len >= offset + 4) {
        s_vlan = ((static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1]) & 0x0FFF;
        offset += 2;
        ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
        offset += 2;
    }
    if (ethertype == 0x8100 && len >= offset + 4) {
        uint16_t vlan = ((static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1]) & 0x0FFF;
        if (s_vlan == 0) {
            c_vlan = vlan;
        } else {
            c_vlan = vlan;
        }
        offset += 2;
        ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
        offset += 2;
    }

    if (ethertype == ETHERTYPE_PPPOE_DISCOVERY) {
        if (len < offset + sizeof(PppoeHeader)) return false;
        const auto* hdr = reinterpret_cast<const PppoeHeader*>(frame + offset);

        if (!session) {
            // Unicast gelen çerçevelerde oturumu bul
            session = session_mgr_.FindPppoeSession(frame, ntohs(hdr->session_id));
        }

        if (session) {
            if (s_vlan != 0) session->s_vlan = s_vlan;
            if (c_vlan != 0) session->c_vlan = c_vlan;
            session->rx_packets++;
            session->rx_bytes += len;
            session->last_activity_tsc = __builtin_ia32_rdtsc();
        }

        if (hdr->code == static_cast<uint8_t>(PppoeCode::PADO)) {
            HandlePado(frame, offset, len, session);
            return true;
        } else if (hdr->code == static_cast<uint8_t>(PppoeCode::PADS)) {
            HandlePads(frame, offset, len, session);
            return true;
        } else if (hdr->code == static_cast<uint8_t>(PppoeCode::PADT)) {
            HandlePadt(frame, offset, len, session);
            return true;
        }
        return false;
    }

    if (ethertype == ETHERTYPE_PPPOE_SESSION) {
        if (len < offset + sizeof(PppoeHeader) + sizeof(PppHeader)) return false;
        const auto* pppoe_hdr = reinterpret_cast<const PppoeHeader*>(frame + offset);
        uint16_t session_id = ntohs(pppoe_hdr->session_id);
        offset += sizeof(PppoeHeader);

        if (!session) {
            session = session_mgr_.FindPppoeSession(frame, session_id);
        }

        if (session) {
            if (s_vlan != 0) session->s_vlan = s_vlan;
            if (c_vlan != 0) session->c_vlan = c_vlan;
            session->rx_packets++;
            session->rx_bytes += len;
            session->last_activity_tsc = __builtin_ia32_rdtsc();
        }

        const auto* ppp_hdr = reinterpret_cast<const PppHeader*>(frame + offset);
        uint16_t ppp_proto = ntohs(ppp_hdr->protocol);
        offset += sizeof(PppHeader);

        if (ppp_proto == PPP_PROTOCOL_LCP) {
            HandleLcp(frame + offset, len - offset, session);
            return true;
        } else if (ppp_proto == PPP_PROTOCOL_PAP) {
            HandlePap(frame + offset, len - offset, session);
            return true;
        } else if (ppp_proto == PPP_PROTOCOL_CHAP) {
            HandleChap(frame + offset, len - offset, session);
            return true;
        } else if (ppp_proto == PPP_PROTOCOL_IPCP) {
            HandleIpcp(frame + offset, len - offset, session);
            return true;
        }
    }

    return false;
}

void PppoeEngine::HandlePado(const uint8_t* frame, size_t offset, size_t len, TelcoSessionContext* session) {
    if (!session || GetSubState(session) != PppoeSubState::DISCOVERY_PADI_SENT) return;
    if (len < offset + sizeof(PppoeHeader)) return;

    const auto* pppoe_hdr = reinterpret_cast<const PppoeHeader*>(frame + offset);
    uint16_t pppoe_payload_len = ntohs(pppoe_hdr->length);

    // BRAS MAC adresini kaydet
    std::memcpy(session->peer_mac, frame + 6, 6);

    // Tag'leri ayrıştır (AC-Cookie'yi bul)
    size_t tag_offset = offset + sizeof(PppoeHeader);
    size_t max_tag_offset = std::min(len, tag_offset + pppoe_payload_len);
    const uint8_t* ac_cookie = nullptr;
    size_t cookie_len = 0;

    while (tag_offset + sizeof(PppoeTag) <= max_tag_offset) {
        const auto* tag = reinterpret_cast<const PppoeTag*>(frame + tag_offset);
        uint16_t tag_type = ntohs(tag->type);
        uint16_t tag_len = ntohs(tag->length);
        tag_offset += sizeof(PppoeTag);

        if (tag_offset + tag_len > max_tag_offset) break;

        if (tag_type == static_cast<uint16_t>(PppoeTagType::AC_COOKIE)) {
            ac_cookie = frame + tag_offset;
            cookie_len = tag_len;
        }
        tag_offset += tag_len;
    }

    SetSubState(session, PppoeSubState::DISCOVERY_PADR_SENT);
    session->retry_count = 0;

    last_tx_frame_ = BuildPadrFrame(session, "", ac_cookie, cookie_len);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    if (timing_wheel_) {
        timing_wheel_->Schedule(session, config_.retransmit_timeout_ms);
    }
}

void PppoeEngine::HandlePads(const uint8_t* frame, size_t offset, size_t len, TelcoSessionContext* session) {
    if (!session || GetSubState(session) != PppoeSubState::DISCOVERY_PADR_SENT) return;
    if (len < offset + sizeof(PppoeHeader)) return;

    const auto* pppoe_hdr = reinterpret_cast<const PppoeHeader*>(frame + offset);
    uint16_t session_id = ntohs(pppoe_hdr->session_id);

    session->session_id = session_id;
    session_mgr_.BindPppoeSession(session, session->client_mac, session_id);

    session->state = SessionState::AUTHENTICATING;
    SetSubState(session, PppoeSubState::LCP_REQ_SENT);
    session->retry_count = 0;

    session->ppp_lcp_identifier = 1;
    session->ppp_magic_number = 0x534D5249; // "SMRI"

    last_tx_frame_ = BuildLcpConfReqFrame(session, 1492, session->ppp_magic_number);
    session->tx_packets++;
    session->tx_bytes += last_tx_frame_.size();

    if (timing_wheel_) {
        timing_wheel_->Schedule(session, config_.retransmit_timeout_ms);
    }
}

void PppoeEngine::HandlePadt(const uint8_t* /*frame*/, size_t /*offset*/, size_t /*len*/, TelcoSessionContext* session) {
    if (!session) return;
    session->state = SessionState::TERMINATING;
    SetSubState(session, PppoeSubState::TERMINATING);
    if (timing_wheel_) {
        timing_wheel_->Cancel(session);
    }
    session_mgr_.ReleaseSession(session);
}

void PppoeEngine::HandleLcp(const uint8_t* payload, size_t len, TelcoSessionContext* session) {
    if (!session || len < sizeof(PppControlHeader)) return;

    const auto* ctrl = reinterpret_cast<const PppControlHeader*>(payload);
    uint8_t code = ctrl->code;
    uint8_t id = ctrl->identifier;
    uint16_t ctrl_len = ntohs(ctrl->length);
    if (ctrl_len < sizeof(PppControlHeader) || ctrl_len > len) return;

    if (code == static_cast<uint8_t>(LcpCode::CONF_REQ)) {
        // Sunucu teklifine Conf-Ack ile onay ver
        const uint8_t* opts = payload + sizeof(PppControlHeader);
        size_t opt_len = ctrl_len - sizeof(PppControlHeader);

        last_tx_frame_ = BuildLcpConfAckFrame(session, id, opts, opt_len);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();

        PppoeSubState sub = GetSubState(session);
        if (sub == PppoeSubState::LCP_ACK_RCVD) {
            SetSubState(session, PppoeSubState::LCP_OPENED);
            // LCP tamamlandı -> Kimlik doğrulamaya geç
            if (auth_proto_ == AuthProtocol::PAP) {
                SetSubState(session, PppoeSubState::PAP_REQ_SENT);
                session->retry_count = 0;
                last_tx_frame_ = BuildPapAuthReqFrame(session, username_, password_);
                session->tx_packets++;
                session->tx_bytes += last_tx_frame_.size();
                if (timing_wheel_) {
                    timing_wheel_->Schedule(session, config_.retransmit_timeout_ms);
                }
            }
        } else {
            SetSubState(session, PppoeSubState::LCP_ACK_SENT);
        }
    } else if (code == static_cast<uint8_t>(LcpCode::CONF_ACK)) {
        PppoeSubState sub = GetSubState(session);
        if (sub == PppoeSubState::LCP_ACK_SENT) {
            SetSubState(session, PppoeSubState::LCP_OPENED);
            if (auth_proto_ == AuthProtocol::PAP) {
                SetSubState(session, PppoeSubState::PAP_REQ_SENT);
                session->retry_count = 0;
                last_tx_frame_ = BuildPapAuthReqFrame(session, username_, password_);
                session->tx_packets++;
                session->tx_bytes += last_tx_frame_.size();
                if (timing_wheel_) {
                    timing_wheel_->Schedule(session, config_.retransmit_timeout_ms);
                }
            }
        } else {
            SetSubState(session, PppoeSubState::LCP_ACK_RCVD);
        }
    } else if (code == static_cast<uint8_t>(LcpCode::ECHO_REQ)) {
        // Echo-Reply yanıtla
        last_tx_frame_ = BuildLcpEchoRepFrame(session, id, session->ppp_magic_number);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
    } else if (code == static_cast<uint8_t>(LcpCode::ECHO_REP)) {
        session->retry_count = 0;
        session->last_activity_tsc = __builtin_ia32_rdtsc();
    } else if (code == static_cast<uint8_t>(LcpCode::TERM_REQ)) {
        session->state = SessionState::TERMINATING;
        SetSubState(session, PppoeSubState::TERMINATING);
    }
}

void PppoeEngine::HandlePap(const uint8_t* payload, size_t len, TelcoSessionContext* session) {
    if (!session || len < sizeof(PppControlHeader)) return;
    const auto* ctrl = reinterpret_cast<const PppControlHeader*>(payload);
    uint16_t ctrl_len = ntohs(ctrl->length);
    if (ctrl_len < sizeof(PppControlHeader) || ctrl_len > len) return;

    PppoeSubState sub = GetSubState(session);
    if (sub != PppoeSubState::PAP_REQ_SENT) return;

    if (ctrl->code == static_cast<uint8_t>(PapCode::AUTH_ACK)) {
        SetSubState(session, PppoeSubState::AUTH_SUCCESS);
        session->retry_count = 0;

        // IPCP aşamasını başlat (0.0.0.0 IP talebi)
        SetSubState(session, PppoeSubState::IPCP_REQ_SENT);
        last_tx_frame_ = BuildIpcpConfReqFrame(session, 0, 0, 0);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();

        if (timing_wheel_) {
            timing_wheel_->Schedule(session, config_.retransmit_timeout_ms);
        }
    } else if (ctrl->code == static_cast<uint8_t>(PapCode::AUTH_NAK)) {
        session->state = SessionState::FAILED;
        SetSubState(session, PppoeSubState::FAILED);
        if (timing_wheel_) {
            timing_wheel_->Cancel(session);
        }
    }
}

void PppoeEngine::HandleChap(const uint8_t* payload, size_t len, TelcoSessionContext* session) {
    if (!session || len < sizeof(PppControlHeader)) return;
    const auto* ctrl = reinterpret_cast<const PppControlHeader*>(payload);
    uint16_t ctrl_len = ntohs(ctrl->length);
    if (ctrl_len < sizeof(PppControlHeader) || ctrl_len > len) return;

    if (ctrl->code == static_cast<uint8_t>(ChapCode::CHALLENGE)) {
        uint8_t id = ctrl->identifier;
        if (ctrl_len < sizeof(PppControlHeader) + 1) return;
        uint8_t challenge_len = payload[sizeof(PppControlHeader)];
        if (ctrl_len < sizeof(PppControlHeader) + 1 + challenge_len) return;
        const uint8_t* challenge = payload + sizeof(PppControlHeader) + 1;

        SetSubState(session, PppoeSubState::CHAP_RESP_SENT);
        session->retry_count = 0;

        last_tx_frame_ = BuildChapResponseFrame(session, id, challenge, challenge_len, password_);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();

        if (timing_wheel_) {
            timing_wheel_->Schedule(session, config_.retransmit_timeout_ms);
        }
    } else if (ctrl->code == static_cast<uint8_t>(ChapCode::SUCCESS)) {
        PppoeSubState sub = GetSubState(session);
        if (sub != PppoeSubState::CHAP_RESP_SENT) return;

        SetSubState(session, PppoeSubState::AUTH_SUCCESS);
        session->retry_count = 0;

        // IPCP aşamasını başlat
        SetSubState(session, PppoeSubState::IPCP_REQ_SENT);
        last_tx_frame_ = BuildIpcpConfReqFrame(session, 0, 0, 0);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();

        if (timing_wheel_) {
            timing_wheel_->Schedule(session, config_.retransmit_timeout_ms);
        }
    } else if (ctrl->code == static_cast<uint8_t>(ChapCode::FAILURE)) {
        session->state = SessionState::FAILED;
        SetSubState(session, PppoeSubState::FAILED);
        if (timing_wheel_) {
            timing_wheel_->Cancel(session);
        }
    }
}

void PppoeEngine::HandleIpcp(const uint8_t* payload, size_t len, TelcoSessionContext* session) {
    if (!session || len < sizeof(PppControlHeader)) return;

    const auto* ctrl = reinterpret_cast<const PppControlHeader*>(payload);
    uint8_t code = ctrl->code;
    uint8_t id = ctrl->identifier;
    uint16_t ctrl_len = ntohs(ctrl->length);
    if (ctrl_len < sizeof(PppControlHeader) || ctrl_len > len) return;

    if (code == static_cast<uint8_t>(LcpCode::CONF_NAK)) {
        // BRAS atadığı IP adresini iletti
        size_t offset = sizeof(PppControlHeader);
        uint32_t assigned_ip = 0;
        uint32_t dns1 = 0;

        while (offset + sizeof(PppOptionHeader) <= ctrl_len) {
            const auto* opt = reinterpret_cast<const PppOptionHeader*>(payload + offset);
            uint8_t opt_type = opt->type;
            uint8_t opt_len = opt->length;
            if (opt_len < 2 || offset + opt_len > ctrl_len) break;

            if (opt_type == IPCP_OPT_IP && opt_len == 6) {
                std::memcpy(&assigned_ip, payload + offset + 2, 4);
                assigned_ip = ntohl(assigned_ip);
            } else if (opt_type == IPCP_OPT_PRIMARY_DNS && opt_len == 6) {
                std::memcpy(&dns1, payload + offset + 2, 4);
                dns1 = ntohl(dns1);
            }
            offset += opt_len;
        }

        if (assigned_ip != 0) {
            session->client_ip = assigned_ip;
            SetSubState(session, PppoeSubState::IPCP_NAK_RCVD);

            // Yeni atanan IP ile tekrar Conf-Req gönder
            last_tx_frame_ = BuildIpcpConfReqFrame(session, assigned_ip, dns1);
            session->tx_packets++;
            session->tx_bytes += last_tx_frame_.size();

            if (timing_wheel_) {
                timing_wheel_->Schedule(session, config_.retransmit_timeout_ms);
            }
        }
    } else if (code == static_cast<uint8_t>(LcpCode::CONF_REQ)) {
        // Sunucunun IPCP yapılandırmasını onayla
        size_t offset = sizeof(PppControlHeader);
        uint32_t srv_ip = 0;
        uint32_t dns1 = 0;

        while (offset + sizeof(PppOptionHeader) <= ctrl_len) {
            const auto* opt = reinterpret_cast<const PppOptionHeader*>(payload + offset);
            uint8_t opt_type = opt->type;
            uint8_t opt_len = opt->length;
            if (opt_len < 2 || offset + opt_len > ctrl_len) break;

            if (opt_type == IPCP_OPT_IP && opt_len == 6) {
                std::memcpy(&srv_ip, payload + offset + 2, 4);
                srv_ip = ntohl(srv_ip);
                session->peer_ip = srv_ip;
            } else if (opt_type == IPCP_OPT_PRIMARY_DNS && opt_len == 6) {
                std::memcpy(&dns1, payload + offset + 2, 4);
                dns1 = ntohl(dns1);
            }
            offset += opt_len;
        }

        last_tx_frame_ = BuildIpcpConfAckFrame(session, id, session->peer_ip, dns1);
        session->tx_packets++;
        session->tx_bytes += last_tx_frame_.size();
    } else if (code == static_cast<uint8_t>(LcpCode::CONF_ACK)) {
        // IPCP onaylandı -> Abone hattı bağlandı (ESTABLISHED)
        session->state = SessionState::ESTABLISHED;
        SetSubState(session, PppoeSubState::ESTABLISHED);
        session->retry_count = 0;

        // 5-Tuple araması için bağla
        session_mgr_.Bind5Tuple(session, session->client_ip, session->peer_ip, 0, 0, 0);

        // Keepalive döngüsünü başlat (1 saniyelik aralık)
        if (timing_wheel_) {
            timing_wheel_->Schedule(session, 1000);
        }
    }
}

// ---------------------------------------------------------------------------
// Wire-Format Paket Üreticileri (RFC 2516, RFC 1661, RFC 1332, RFC 1994)
// ---------------------------------------------------------------------------

std::vector<uint8_t> PppoeEngine::BuildPadiFrame(TelcoSessionContext* session, const std::string& service_name) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    // 1. Ethernet Header (Broadcast)
    for (int i = 0; i < 6; ++i) frame.push_back(0xFF);
    for (int i = 0; i < 6; ++i) frame.push_back(session->client_mac[i]);
    frame.push_back(0x88); frame.push_back(0x63); // 0x8863

    // 2. PPPoE Header
    size_t tag_bytes = sizeof(PppoeTag) + service_name.size();
    frame.push_back(0x11); // Ver=1, Type=1
    frame.push_back(static_cast<uint8_t>(PppoeCode::PADI));
    frame.push_back(0x00); frame.push_back(0x00); // Session ID = 0
    frame.push_back((tag_bytes >> 8) & 0xFF);
    frame.push_back(tag_bytes & 0xFF);

    // 3. Service-Name Tag
    frame.push_back(0x01); frame.push_back(0x01); // 0x0101
    frame.push_back((service_name.size() >> 8) & 0xFF);
    frame.push_back(service_name.size() & 0xFF);
    for (char c : service_name) frame.push_back(static_cast<uint8_t>(c));

    // Minimum Ethernet boyutu dolgusu (60 bayt + 4 bayt FCS = 64)
    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> PppoeEngine::BuildPadrFrame(TelcoSessionContext* session, const std::string& service_name,
                                                const uint8_t* ac_cookie, size_t cookie_len) {
    std::vector<uint8_t> frame;
    frame.reserve(128);

    // 1. Ethernet Header (Unicast to BRAS)
    for (int i = 0; i < 6; ++i) frame.push_back(session->peer_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(session->client_mac[i]);
    frame.push_back(0x88); frame.push_back(0x63);

    // 2. PPPoE Header
    size_t tag_bytes = sizeof(PppoeTag) + service_name.size();
    if (ac_cookie && cookie_len > 0) tag_bytes += sizeof(PppoeTag) + cookie_len;

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::PADR));
    frame.push_back(0x00); frame.push_back(0x00);
    frame.push_back((tag_bytes >> 8) & 0xFF);
    frame.push_back(tag_bytes & 0xFF);

    // 3. Service-Name Tag
    frame.push_back(0x01); frame.push_back(0x01);
    frame.push_back((service_name.size() >> 8) & 0xFF);
    frame.push_back(service_name.size() & 0xFF);
    for (char c : service_name) frame.push_back(static_cast<uint8_t>(c));

    // 4. AC-Cookie Tag (Geldiyse aynen geri iletilir)
    if (ac_cookie && cookie_len > 0) {
        frame.push_back(0x01); frame.push_back(0x04);
        frame.push_back((cookie_len >> 8) & 0xFF);
        frame.push_back(cookie_len & 0xFF);
        for (size_t i = 0; i < cookie_len; ++i) frame.push_back(ac_cookie[i]);
    }

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> PppoeEngine::BuildPadtFrame(TelcoSessionContext* session) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    for (int i = 0; i < 6; ++i) frame.push_back(session->peer_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(session->client_mac[i]);
    frame.push_back(0x88); frame.push_back(0x63);

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::PADT));
    frame.push_back((session->session_id >> 8) & 0xFF);
    frame.push_back(session->session_id & 0xFF);
    frame.push_back(0x00); frame.push_back(0x00);

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> PppoeEngine::BuildLcpConfReqFrame(TelcoSessionContext* session, uint16_t mru, uint32_t magic) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    // Ethernet
    for (int i = 0; i < 6; ++i) frame.push_back(session->peer_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(session->client_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    // LCP Options: MRU (4 bytes) + Magic (6 bytes) = 10 bytes. Control header: 4 bytes. Total PPP: 14 bytes.
    uint16_t ppp_ctrl_len = 4 + 4 + 6;
    uint16_t pppoe_payload_len = sizeof(PppHeader) + ppp_ctrl_len;

    // PPPoE
    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session->session_id >> 8) & 0xFF);
    frame.push_back(session->session_id & 0xFF);
    frame.push_back((pppoe_payload_len >> 8) & 0xFF);
    frame.push_back(pppoe_payload_len & 0xFF);

    // PPP Header
    frame.push_back(0xC0); frame.push_back(0x21); // LCP

    // PPP Control Header
    frame.push_back(static_cast<uint8_t>(LcpCode::CONF_REQ));
    frame.push_back(session->ppp_lcp_identifier);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    // Option: MRU
    frame.push_back(LCP_OPT_MRU);
    frame.push_back(4);
    frame.push_back((mru >> 8) & 0xFF);
    frame.push_back(mru & 0xFF);

    // Option: Magic Number
    frame.push_back(LCP_OPT_MAGIC);
    frame.push_back(6);
    frame.push_back((magic >> 24) & 0xFF);
    frame.push_back((magic >> 16) & 0xFF);
    frame.push_back((magic >> 8) & 0xFF);
    frame.push_back(magic & 0xFF);

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> PppoeEngine::BuildLcpConfAckFrame(TelcoSessionContext* session, uint8_t identifier,
                                                      const uint8_t* raw_options, size_t opt_len) {
    std::vector<uint8_t> frame;
    frame.reserve(64 + opt_len);

    for (int i = 0; i < 6; ++i) frame.push_back(session->peer_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(session->client_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    uint16_t ppp_ctrl_len = static_cast<uint16_t>(4 + opt_len);
    uint16_t pppoe_payload_len = static_cast<uint16_t>(sizeof(PppHeader) + ppp_ctrl_len);

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session->session_id >> 8) & 0xFF);
    frame.push_back(session->session_id & 0xFF);
    frame.push_back((pppoe_payload_len >> 8) & 0xFF);
    frame.push_back(pppoe_payload_len & 0xFF);

    frame.push_back(0xC0); frame.push_back(0x21);

    frame.push_back(static_cast<uint8_t>(LcpCode::CONF_ACK));
    frame.push_back(identifier);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    if (raw_options && opt_len > 0) {
        for (size_t i = 0; i < opt_len; ++i) frame.push_back(raw_options[i]);
    }

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> PppoeEngine::BuildLcpEchoReqFrame(TelcoSessionContext* session) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    for (int i = 0; i < 6; ++i) frame.push_back(session->peer_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(session->client_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    uint16_t ppp_ctrl_len = 4 + 4; // Header + 4 bayt magic number
    uint16_t pppoe_len = sizeof(PppHeader) + ppp_ctrl_len;

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session->session_id >> 8) & 0xFF);
    frame.push_back(session->session_id & 0xFF);
    frame.push_back((pppoe_len >> 8) & 0xFF);
    frame.push_back(pppoe_len & 0xFF);

    frame.push_back(0xC0); frame.push_back(0x21);

    frame.push_back(static_cast<uint8_t>(LcpCode::ECHO_REQ));
    frame.push_back(session->ppp_lcp_identifier++);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    frame.push_back((session->ppp_magic_number >> 24) & 0xFF);
    frame.push_back((session->ppp_magic_number >> 16) & 0xFF);
    frame.push_back((session->ppp_magic_number >> 8) & 0xFF);
    frame.push_back(session->ppp_magic_number & 0xFF);

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> PppoeEngine::BuildLcpEchoRepFrame(TelcoSessionContext* session, uint8_t identifier,
                                                      uint32_t magic, const uint8_t* data, size_t data_len) {
    std::vector<uint8_t> frame;
    frame.reserve(64 + data_len);

    for (int i = 0; i < 6; ++i) frame.push_back(session->peer_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(session->client_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    uint16_t ppp_ctrl_len = static_cast<uint16_t>(4 + 4 + data_len);
    uint16_t pppoe_len = static_cast<uint16_t>(sizeof(PppHeader) + ppp_ctrl_len);

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session->session_id >> 8) & 0xFF);
    frame.push_back(session->session_id & 0xFF);
    frame.push_back((pppoe_len >> 8) & 0xFF);
    frame.push_back(pppoe_len & 0xFF);

    frame.push_back(0xC0); frame.push_back(0x21);

    frame.push_back(static_cast<uint8_t>(LcpCode::ECHO_REP));
    frame.push_back(identifier);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    frame.push_back((magic >> 24) & 0xFF);
    frame.push_back((magic >> 16) & 0xFF);
    frame.push_back((magic >> 8) & 0xFF);
    frame.push_back(magic & 0xFF);

    if (data && data_len > 0) {
        for (size_t i = 0; i < data_len; ++i) frame.push_back(data[i]);
    }

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> PppoeEngine::BuildPapAuthReqFrame(TelcoSessionContext* session, const std::string& username, const std::string& password) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    for (int i = 0; i < 6; ++i) frame.push_back(session->peer_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(session->client_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    uint16_t ppp_ctrl_len = static_cast<uint16_t>(4 + 1 + username.size() + 1 + password.size());
    uint16_t pppoe_len = static_cast<uint16_t>(sizeof(PppHeader) + ppp_ctrl_len);

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session->session_id >> 8) & 0xFF);
    frame.push_back(session->session_id & 0xFF);
    frame.push_back((pppoe_len >> 8) & 0xFF);
    frame.push_back(pppoe_len & 0xFF);

    frame.push_back(0xC0); frame.push_back(0x23); // PAP

    frame.push_back(static_cast<uint8_t>(PapCode::AUTH_REQ));
    frame.push_back(1);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    frame.push_back(static_cast<uint8_t>(username.size()));
    for (char c : username) frame.push_back(static_cast<uint8_t>(c));

    frame.push_back(static_cast<uint8_t>(password.size()));
    for (char c : password) frame.push_back(static_cast<uint8_t>(c));

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> PppoeEngine::BuildChapResponseFrame(TelcoSessionContext* session, uint8_t identifier,
                                                        const uint8_t* challenge, size_t challenge_len, const std::string& secret) {
    std::vector<uint8_t> frame;
    frame.reserve(128);

    uint8_t digest[16];
    ComputeChapMd5(identifier, secret, challenge, challenge_len, digest);

    for (int i = 0; i < 6; ++i) frame.push_back(session->peer_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(session->client_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    uint16_t ppp_ctrl_len = static_cast<uint16_t>(4 + 1 + 16 + username_.size());
    uint16_t pppoe_len = static_cast<uint16_t>(sizeof(PppHeader) + ppp_ctrl_len);

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session->session_id >> 8) & 0xFF);
    frame.push_back(session->session_id & 0xFF);
    frame.push_back((pppoe_len >> 8) & 0xFF);
    frame.push_back(pppoe_len & 0xFF);

    frame.push_back(0xC2); frame.push_back(0x23); // CHAP

    frame.push_back(static_cast<uint8_t>(ChapCode::RESPONSE));
    frame.push_back(identifier);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    frame.push_back(16); // MD5 hash length
    for (int i = 0; i < 16; ++i) frame.push_back(digest[i]);

    for (char c : username_) frame.push_back(static_cast<uint8_t>(c));

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> PppoeEngine::BuildIpcpConfReqFrame(TelcoSessionContext* session, uint32_t req_ip, uint32_t dns1, uint32_t dns2) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    for (int i = 0; i < 6; ++i) frame.push_back(session->peer_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(session->client_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    uint16_t ppp_ctrl_len = 4 + 6; // Header + IP option (6 bytes)
    if (dns1 != 0) ppp_ctrl_len += 6;
    if (dns2 != 0) ppp_ctrl_len += 6;

    uint16_t pppoe_len = sizeof(PppHeader) + ppp_ctrl_len;

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session->session_id >> 8) & 0xFF);
    frame.push_back(session->session_id & 0xFF);
    frame.push_back((pppoe_len >> 8) & 0xFF);
    frame.push_back(pppoe_len & 0xFF);

    frame.push_back(0x80); frame.push_back(0x21); // IPCP

    frame.push_back(static_cast<uint8_t>(LcpCode::CONF_REQ));
    frame.push_back(1);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    // IP Option
    frame.push_back(IPCP_OPT_IP);
    frame.push_back(6);
    frame.push_back((req_ip >> 24) & 0xFF);
    frame.push_back((req_ip >> 16) & 0xFF);
    frame.push_back((req_ip >> 8) & 0xFF);
    frame.push_back(req_ip & 0xFF);

    if (dns1 != 0) {
        frame.push_back(IPCP_OPT_PRIMARY_DNS);
        frame.push_back(6);
        frame.push_back((dns1 >> 24) & 0xFF);
        frame.push_back((dns1 >> 16) & 0xFF);
        frame.push_back((dns1 >> 8) & 0xFF);
        frame.push_back(dns1 & 0xFF);
    }

    if (dns2 != 0) {
        frame.push_back(IPCP_OPT_SECONDARY_DNS);
        frame.push_back(6);
        frame.push_back((dns2 >> 24) & 0xFF);
        frame.push_back((dns2 >> 16) & 0xFF);
        frame.push_back((dns2 >> 8) & 0xFF);
        frame.push_back(dns2 & 0xFF);
    }

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> PppoeEngine::BuildIpcpConfAckFrame(TelcoSessionContext* session, uint8_t identifier,
                                                      uint32_t ip, uint32_t dns1, uint32_t dns2) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    for (int i = 0; i < 6; ++i) frame.push_back(session->peer_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(session->client_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    uint16_t ppp_ctrl_len = 4 + 6;
    if (dns1 != 0) ppp_ctrl_len += 6;
    if (dns2 != 0) ppp_ctrl_len += 6;

    uint16_t pppoe_len = sizeof(PppHeader) + ppp_ctrl_len;

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session->session_id >> 8) & 0xFF);
    frame.push_back(session->session_id & 0xFF);
    frame.push_back((pppoe_len >> 8) & 0xFF);
    frame.push_back(pppoe_len & 0xFF);

    frame.push_back(0x80); frame.push_back(0x21);

    frame.push_back(static_cast<uint8_t>(LcpCode::CONF_ACK));
    frame.push_back(identifier);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    frame.push_back(IPCP_OPT_IP);
    frame.push_back(6);
    frame.push_back((ip >> 24) & 0xFF);
    frame.push_back((ip >> 16) & 0xFF);
    frame.push_back((ip >> 8) & 0xFF);
    frame.push_back(ip & 0xFF);

    if (dns1 != 0) {
        frame.push_back(IPCP_OPT_PRIMARY_DNS);
        frame.push_back(6);
        frame.push_back((dns1 >> 24) & 0xFF);
        frame.push_back((dns1 >> 16) & 0xFF);
        frame.push_back((dns1 >> 8) & 0xFF);
        frame.push_back(dns1 & 0xFF);
    }

    if (dns2 != 0) {
        frame.push_back(IPCP_OPT_SECONDARY_DNS);
        frame.push_back(6);
        frame.push_back((dns2 >> 24) & 0xFF);
        frame.push_back((dns2 >> 16) & 0xFF);
        frame.push_back((dns2 >> 8) & 0xFF);
        frame.push_back(dns2 & 0xFF);
    }

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

} // namespace samurai::telecom::pppoe
