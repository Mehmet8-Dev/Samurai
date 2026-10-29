#include "qinq_generator.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <algorithm>

namespace ddos_samurai::telecom::stateless {

namespace {

#pragma pack(push, 1)
struct Ipv4HeaderWire {
    uint8_t  ihl_version; // 0x45
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct UdpHeaderWire {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

static inline uint16_t CalculateChecksum(const uint16_t* buf, size_t nbytes) noexcept {
    uint32_t sum = 0;
    while (nbytes > 1) {
        sum += *buf++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        sum += *reinterpret_cast<const uint8_t*>(buf);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

} // namespace

QinQGenerator::QinQGenerator() {
    QinQGeneratorConfig default_cfg;
    Init(default_cfg);
}

QinQGenerator::QinQGenerator(const QinQGeneratorConfig& cfg) {
    Init(cfg);
}

bool QinQGenerator::Init(const ProtocolConfig& cfg) {
    QinQGeneratorConfig qcfg;
    qcfg.s_vlan_min = cfg.base_vlan_s > 0 ? cfg.base_vlan_s : 100;
    qcfg.s_vlan_max = std::min<uint32_t>(qcfg.s_vlan_min + 10, 4094);
    qcfg.c_vlan_min = cfg.base_vlan_c > 0 ? cfg.base_vlan_c : 200;
    qcfg.c_vlan_max = std::min<uint32_t>(qcfg.c_vlan_min + 100, 4094);
    return Init(qcfg);
}

bool QinQGenerator::Init(const QinQGeneratorConfig& cfg) {
    config_ = cfg;

    // Validate VLAN ranges (1..4094 per 802.1Q standard)
    if (config_.s_vlan_min < 1) config_.s_vlan_min = 1;
    if (config_.s_vlan_max > 4094) config_.s_vlan_max = 4094;
    if (config_.s_vlan_min > config_.s_vlan_max) {
        std::swap(config_.s_vlan_min, config_.s_vlan_max);
    }
    if (config_.s_vlan_step == 0) config_.s_vlan_step = 1;

    if (config_.c_vlan_min < 1) config_.c_vlan_min = 1;
    if (config_.c_vlan_max > 4094) config_.c_vlan_max = 4094;
    if (config_.c_vlan_min > config_.c_vlan_max) {
        std::swap(config_.c_vlan_min, config_.c_vlan_max);
    }
    if (config_.c_vlan_step == 0) config_.c_vlan_step = 1;

    if (config_.prng_seed == 0) config_.prng_seed = 0x98765432;
    rng_state_ = config_.prng_seed;

    current_s_vlan_ = config_.s_vlan_min;
    current_c_vlan_ = config_.c_vlan_min;
    stats_ = QinQGenStats{};

    BuildTemplate();
    initialized_ = true;
    return true;
}

void QinQGenerator::Shutdown() {
    initialized_ = false;
    ResetStats();
}

void QinQGenerator::ResetStats() noexcept {
    stats_ = QinQGenStats{};
}

void QinQGenerator::OnRxPacket(rte_mbuf* /*mbuf*/, 
                              const PacketMetadata& /*meta*/, 
                              TelcoSessionContext* /*session*/) {
    // Stateless generator does not track RX state
}

uint32_t QinQGenerator::OnTimerTick(uint64_t /*current_tsc*/) {
    return 0;
}

rte_mbuf* QinQGenerator::BuildTxPacket(rte_mempool* /*pool*/, 
                                      TelcoSessionContext* /*session*/, 
                                      uint16_t /*event_type*/) {
    return nullptr;
}

void QinQGenerator::BuildTemplate() {
    std::memset(template_buf_, 0, sizeof(template_buf_));

    // Clamp payload_size so total_len_ fits within template_buf_
    constexpr size_t kMaxPayload = sizeof(template_buf_) - sizeof(QinQEthernetHeader) - 64;
    if (config_.payload_size > kMaxPayload) {
        config_.payload_size = static_cast<uint16_t>(kMaxPayload);
    }

    // 1. QinQ Dual VLAN Ethernet Header (22 Bytes)
    auto* eth = reinterpret_cast<QinQEthernetHeader*>(template_buf_);
    std::memcpy(eth->dst_mac, config_.dst_mac, 6);
    std::memcpy(eth->src_mac, config_.src_mac, 6);

    eth->s_tag.tpid = htons(config_.s_tpid);
    eth->s_tag.tci = EncodeTci(config_.s_vlan_min, config_.s_pcp, config_.s_dei);

    eth->c_tag.tpid = htons(config_.c_tpid);
    eth->c_tag.tci = EncodeTci(config_.c_vlan_min, config_.c_pcp, config_.c_dei);

    eth->inner_ethertype = htons(config_.inner_ethertype);

    s_tci_offset_ = 14;
    c_tci_offset_ = 18;

    // 2. Inner IPv4 + UDP payload to guarantee wire size >= 64 bytes
    size_t payload_len = config_.payload_size >= 28 ? config_.payload_size : 28;
    total_len_ = sizeof(QinQEthernetHeader) + payload_len;
    if (total_len_ < 64) {
        total_len_ = 64; // Pad to Ethernet minimum frame size (with QinQ = 64/68)
        payload_len = total_len_ - sizeof(QinQEthernetHeader);
    }

    if (config_.inner_ethertype == 0x0800) {
        auto* ip = reinterpret_cast<Ipv4HeaderWire*>(template_buf_ + sizeof(QinQEthernetHeader));
        ip->ihl_version = 0x45;
        ip->tos = 0;
        ip->total_length = htons(static_cast<uint16_t>(payload_len));
        ip->id = htons(0x5151); // "QQ"
        ip->flags_fragment = 0;
        ip->ttl = 64;
        ip->protocol = 17; // UDP
        ip->src_ip = htonl(config_.inner_src_ip);
        ip->dst_ip = htonl(config_.inner_dst_ip);
        ip->checksum = 0;
        ip->checksum = CalculateChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4HeaderWire));

        if (payload_len >= sizeof(Ipv4HeaderWire) + sizeof(UdpHeaderWire)) {
            auto* udp = reinterpret_cast<UdpHeaderWire*>(template_buf_ + sizeof(QinQEthernetHeader) + sizeof(Ipv4HeaderWire));
            udp->src_port = htons(10001);
            udp->dst_port = htons(10002);
            udp->length = htons(static_cast<uint16_t>(payload_len - sizeof(Ipv4HeaderWire)));
            udp->checksum = 0;
        }
    }
}

inline void QinQGenerator::AdvanceVlanIndices() noexcept {
    switch (config_.sweep_mode) {
        case QinQSweepMode::S_THEN_C: {
            uint32_t next_c = current_c_vlan_ + config_.c_vlan_step;
            if (next_c > config_.c_vlan_max) {
                current_c_vlan_ = config_.c_vlan_min;
                uint32_t next_s = current_s_vlan_ + config_.s_vlan_step;
                if (next_s > config_.s_vlan_max) {
                    current_s_vlan_ = config_.s_vlan_min;
                    stats_.sweep_cycles++;
                } else {
                    current_s_vlan_ = static_cast<uint16_t>(next_s);
                }
            } else {
                current_c_vlan_ = static_cast<uint16_t>(next_c);
            }
            break;
        }

        case QinQSweepMode::C_THEN_S: {
            uint32_t next_s = current_s_vlan_ + config_.s_vlan_step;
            if (next_s > config_.s_vlan_max) {
                current_s_vlan_ = config_.s_vlan_min;
                uint32_t next_c = current_c_vlan_ + config_.c_vlan_step;
                if (next_c > config_.c_vlan_max) {
                    current_c_vlan_ = config_.c_vlan_min;
                    stats_.sweep_cycles++;
                } else {
                    current_c_vlan_ = static_cast<uint16_t>(next_c);
                }
            } else {
                current_s_vlan_ = static_cast<uint16_t>(next_s);
            }
            break;
        }

        case QinQSweepMode::PSEUDO_RANDOM: {
            rng_state_ ^= rng_state_ << 13;
            rng_state_ ^= rng_state_ >> 17;
            rng_state_ ^= rng_state_ << 5;
            uint32_t s_range = (config_.s_vlan_max >= config_.s_vlan_min) 
                               ? (config_.s_vlan_max - config_.s_vlan_min + 1) : 1;
            current_s_vlan_ = static_cast<uint16_t>(config_.s_vlan_min + (rng_state_ % s_range));

            rng_state_ ^= rng_state_ << 13;
            rng_state_ ^= rng_state_ >> 17;
            rng_state_ ^= rng_state_ << 5;
            uint32_t c_range = (config_.c_vlan_max >= config_.c_vlan_min) 
                               ? (config_.c_vlan_max - config_.c_vlan_min + 1) : 1;
            current_c_vlan_ = static_cast<uint16_t>(config_.c_vlan_min + (rng_state_ % c_range));
            break;
        }

        case QinQSweepMode::FLAT_FIXED:
        default:
            // Do not advance
            break;
    }
}

uint32_t QinQGenerator::GeneratePacket(uint8_t* out_buf, size_t max_len) noexcept {
    if (!out_buf || max_len < total_len_) {
        return 0;
    }

    std::memcpy(out_buf, template_buf_, total_len_);

    uint16_t s_vlan = current_s_vlan_;
    uint16_t c_vlan = current_c_vlan_;

    uint16_t s_tci = EncodeTci(s_vlan, config_.s_pcp, config_.s_dei);
    uint16_t c_tci = EncodeTci(c_vlan, config_.c_pcp, config_.c_dei);
    std::memcpy(out_buf + s_tci_offset_, &s_tci, sizeof(s_tci));
    std::memcpy(out_buf + c_tci_offset_, &c_tci, sizeof(c_tci));

    if (config_.cycle_src_mac) {
        out_buf[10] = static_cast<uint8_t>((s_vlan >> 8) & 0x0F);
        out_buf[11] = static_cast<uint8_t>(s_vlan & 0xFF);
    }

    stats_.packets_generated++;
    stats_.bytes_generated += total_len_;
    stats_.current_s_vlan = s_vlan;
    stats_.current_c_vlan = c_vlan;

    AdvanceVlanIndices();
    return static_cast<uint32_t>(total_len_);
}

uint32_t QinQGenerator::GenerateBatch(uint8_t* out_ptrs[], uint32_t* out_lens, 
                                    uint32_t count, size_t single_buf_capacity) noexcept {
    if (!out_ptrs || !out_lens || count == 0 || single_buf_capacity < total_len_) {
        return 0;
    }

    for (uint32_t i = 0; i < count; ++i) {
        uint32_t len = GeneratePacket(out_ptrs[i], single_buf_capacity);
        out_lens[i] = len;
    }
    return count;
}

bool QinQGenerator::VerifyFrame(const uint8_t* frame, size_t len, QinQVerificationInfo& out_verif) noexcept {
    out_verif = QinQVerificationInfo{};
    if (!frame || len < sizeof(QinQEthernetHeader)) {
        return false;
    }

    const auto* hdr = reinterpret_cast<const QinQEthernetHeader*>(frame);
    std::memcpy(out_verif.dst_mac, hdr->dst_mac, 6);
    std::memcpy(out_verif.src_mac, hdr->src_mac, 6);

    out_verif.s_tpid = ntohs(hdr->s_tag.tpid);
    // Outer tag must be valid TPID (0x88A8, 0x9100, or 0x8100)
    if (out_verif.s_tpid != ETHERTYPE_8021AD && 
        out_verif.s_tpid != ETHERTYPE_9100 && 
        out_verif.s_tpid != ETHERTYPE_8021Q) {
        return false;
    }
    DecodeTci(hdr->s_tag.tci, out_verif.s_vlan, out_verif.s_pcp, out_verif.s_dei);

    out_verif.c_tpid = ntohs(hdr->c_tag.tpid);
    if (out_verif.c_tpid != ETHERTYPE_8021Q) {
        return false;
    }
    DecodeTci(hdr->c_tag.tci, out_verif.c_vlan, out_verif.c_pcp, out_verif.c_dei);

    out_verif.inner_ethertype = ntohs(hdr->inner_ethertype);
    out_verif.frame_len = len;
    out_verif.is_valid = true;
    return true;
}

} // namespace ddos_samurai::telecom::stateless
