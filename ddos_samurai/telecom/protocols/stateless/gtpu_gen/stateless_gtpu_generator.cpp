#include "stateless_gtpu_generator.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <algorithm>

namespace ddos_samurai::telecom::stateless {

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
    uint8_t  protocol;
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

struct GtpuHeaderWire {
    uint8_t  flags;
    uint8_t  msg_type;
    uint16_t length;
    uint32_t teid;
};

struct GtpuOptFieldsWire {
    uint16_t seq_num;
    uint8_t  n_pdu;
    uint8_t  next_ext;
};

struct IcmpHeaderWire {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
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

StatelessGtpuGenerator::StatelessGtpuGenerator() {
    GtpuGenConfig default_cfg;
    Init(default_cfg);
}

StatelessGtpuGenerator::StatelessGtpuGenerator(const GtpuGenConfig& cfg) {
    Init(cfg);
}

bool StatelessGtpuGenerator::Init(const ProtocolConfig& cfg) {
    GtpuGenConfig gcfg;
    gcfg.outer_src_ip = 0x0A000001;
    gcfg.outer_dst_ip = 0x0A000002;
    gcfg.teid_start = 1;
    gcfg.teid_end = cfg.max_sessions > 0 ? cfg.max_sessions : 1000000;
    return Init(gcfg);
}

bool StatelessGtpuGenerator::Init(const GtpuGenConfig& cfg) {
    config_ = cfg;
    if (config_.teid_start > config_.teid_end) {
        std::swap(config_.teid_start, config_.teid_end);
    }
    if (config_.teid_step == 0) {
        config_.teid_step = 1;
    }
    if (config_.prng_seed == 0) {
        config_.prng_seed = 0x12345678;
    }
    rng_state_ = config_.prng_seed;
    current_teid_ = config_.teid_start;
    current_inner_ip_ = config_.inner_ip_start;
    current_seq_ = 1;
    stats_ = GtpuGenStats{};

    BuildTemplate();
    initialized_ = true;
    return true;
}

void StatelessGtpuGenerator::Shutdown() {
    initialized_ = false;
    ResetStats();
}

void StatelessGtpuGenerator::ResetStats() noexcept {
    stats_ = GtpuGenStats{};
}

void StatelessGtpuGenerator::OnRxPacket(rte_mbuf* /*mbuf*/, 
                                       const PacketMetadata& /*meta*/, 
                                       TelcoSessionContext* /*session*/) {
    // Stateless generator does not track RX state
}

uint32_t StatelessGtpuGenerator::OnTimerTick(uint64_t /*current_tsc*/) {
    return 0;
}

rte_mbuf* StatelessGtpuGenerator::BuildTxPacket(rte_mempool* /*pool*/, 
                                               TelcoSessionContext* /*session*/, 
                                               uint16_t /*event_type*/) {
    // Pure memory generator does not require DPDK mempool directly
    return nullptr;
}

void StatelessGtpuGenerator::BuildTemplate() {
    std::memset(template_buf_, 0, sizeof(template_buf_));

    eth_offset_ = 0;
    outer_ip_offset_ = sizeof(EthHeader);
    outer_udp_offset_ = outer_ip_offset_ + sizeof(Ipv4Header);
    gtpu_offset_ = outer_udp_offset_ + sizeof(UdpHeader);
    teid_offset_ = gtpu_offset_ + 4;

    size_t gtp_hdr_len = sizeof(GtpuHeaderWire);
    if (config_.with_seq_num) {
        seq_offset_ = gtpu_offset_ + sizeof(GtpuHeaderWire);
        gtp_hdr_len += sizeof(GtpuOptFieldsWire);
    }

    inner_ip_offset_ = gtpu_offset_ + gtp_hdr_len;
    inner_src_ip_offset_ = inner_ip_offset_ + 12;
    inner_ip_csum_offset_ = inner_ip_offset_ + 10;
    inner_l4_offset_ = inner_ip_offset_ + sizeof(Ipv4Header);

    size_t inner_l4_len = 0;
    if (config_.inner_proto == InnerProtocol::ICMP_ECHO) {
        inner_l4_len = sizeof(IcmpHeaderWire) + config_.inner_payload_size;
    } else {
        inner_l4_len = sizeof(UdpHeader) + config_.inner_payload_size;
    }

    size_t inner_total_len = sizeof(Ipv4Header) + inner_l4_len;
    size_t gtp_payload_len = (config_.with_seq_num ? sizeof(GtpuOptFieldsWire) : 0) + inner_total_len;
    size_t outer_udp_len = sizeof(UdpHeader) + sizeof(GtpuHeaderWire) + gtp_payload_len;
    size_t outer_ip_len = sizeof(Ipv4Header) + outer_udp_len;
    total_len_ = sizeof(EthHeader) + outer_ip_len;

    // 1. Ethernet Header
    auto* eth = reinterpret_cast<EthHeader*>(template_buf_ + eth_offset_);
    std::memcpy(eth->dst_mac, config_.dst_mac, 6);
    std::memcpy(eth->src_mac, config_.src_mac, 6);
    eth->ethertype = htons(0x0800); // IPv4

    // 2. Outer IPv4 Header
    auto* o_ip = reinterpret_cast<Ipv4Header*>(template_buf_ + outer_ip_offset_);
    o_ip->ihl_version = 0x45;
    o_ip->tos = config_.outer_tos;
    o_ip->total_length = htons(static_cast<uint16_t>(outer_ip_len));
    o_ip->id = htons(0x4755); // "GU"
    o_ip->flags_fragment = 0;
    o_ip->ttl = config_.outer_ttl > 0 ? config_.outer_ttl : 64;
    o_ip->protocol = 17; // UDP
    o_ip->src_ip = htonl(config_.outer_src_ip);
    o_ip->dst_ip = htonl(config_.outer_dst_ip);
    o_ip->checksum = 0;
    o_ip->checksum = CalculateChecksum(reinterpret_cast<const uint16_t*>(o_ip), sizeof(Ipv4Header));

    // 3. Outer UDP Header
    auto* o_udp = reinterpret_cast<UdpHeader*>(template_buf_ + outer_udp_offset_);
    o_udp->src_port = htons(config_.outer_src_port);
    o_udp->dst_port = htons(config_.outer_dst_port);
    o_udp->length = htons(static_cast<uint16_t>(outer_udp_len));
    o_udp->checksum = 0; // IPv4 UDP checksum optional

    // 4. GTP-U Header
    auto* gtp = reinterpret_cast<GtpuHeaderWire*>(template_buf_ + gtpu_offset_);
    gtp->flags = config_.gtpu_flags | (config_.with_seq_num ? 0x02 : 0x00);
    gtp->msg_type = config_.gtpu_msg_type;
    gtp->length = htons(static_cast<uint16_t>(gtp_payload_len));
    gtp->teid = htonl(config_.teid_start);

    if (config_.with_seq_num) {
        auto* opt = reinterpret_cast<GtpuOptFieldsWire*>(template_buf_ + seq_offset_);
        opt->seq_num = htons(1);
        opt->n_pdu = 0;
        opt->next_ext = 0;
    }

    // 5. Inner IPv4 Header
    auto* i_ip = reinterpret_cast<Ipv4Header*>(template_buf_ + inner_ip_offset_);
    i_ip->ihl_version = 0x45;
    i_ip->tos = 0;
    i_ip->total_length = htons(static_cast<uint16_t>(inner_total_len));
    i_ip->id = htons(0x1122);
    i_ip->flags_fragment = 0;
    i_ip->ttl = config_.inner_ttl > 0 ? config_.inner_ttl : 64;
    i_ip->protocol = (config_.inner_proto == InnerProtocol::ICMP_ECHO) ? 1 : 17;
    i_ip->src_ip = htonl(config_.inner_src_ip);
    i_ip->dst_ip = htonl(config_.inner_dst_ip);
    i_ip->checksum = 0;
    i_ip->checksum = CalculateChecksum(reinterpret_cast<const uint16_t*>(i_ip), sizeof(Ipv4Header));

    // 6. Inner L4 & Payload
    inner_payload_offset_ = inner_l4_offset_ + (config_.inner_proto == InnerProtocol::ICMP_ECHO ? sizeof(IcmpHeaderWire) : sizeof(UdpHeader));
    
    // Fill dummy payload bytes
    for (size_t i = 0; i < config_.inner_payload_size; ++i) {
        template_buf_[inner_payload_offset_ + i] = static_cast<uint8_t>(i & 0xFF);
    }

    if (config_.inner_proto == InnerProtocol::ICMP_ECHO) {
        auto* icmp = reinterpret_cast<IcmpHeaderWire*>(template_buf_ + inner_l4_offset_);
        icmp->type = 8; // Echo Request
        icmp->code = 0;
        icmp->id = htons(0xABCD);
        icmp->sequence = htons(1);
        icmp->checksum = 0;
        icmp->checksum = CalculateChecksum(reinterpret_cast<const uint16_t*>(icmp), inner_l4_len);
    } else {
        auto* i_udp = reinterpret_cast<UdpHeader*>(template_buf_ + inner_l4_offset_);
        i_udp->src_port = htons(config_.inner_src_port);
        i_udp->dst_port = htons(config_.inner_dst_port);
        i_udp->length = htons(static_cast<uint16_t>(inner_l4_len));
        i_udp->checksum = 0;
    }
}

inline uint32_t StatelessGtpuGenerator::NextTeid() noexcept {
    uint32_t teid = current_teid_;
    if (config_.teid_mode == TeidCycleMode::PSEUDO_RANDOM) {
        rng_state_ ^= rng_state_ << 13;
        rng_state_ ^= rng_state_ >> 17;
        rng_state_ ^= rng_state_ << 5;
        uint32_t range = (config_.teid_end >= config_.teid_start) 
                         ? (config_.teid_end - config_.teid_start + 1) : 1;
        teid = config_.teid_start + (range > 0 ? (rng_state_ % range) : 0);
        return teid;
    }

    uint32_t step = config_.teid_step > 0 ? config_.teid_step : 1;
    if (current_teid_ + step > config_.teid_end || current_teid_ + step < current_teid_) {
        current_teid_ = config_.teid_start;
        stats_.teid_wraparounds++;
    } else {
        current_teid_ += step;
    }
    return teid;
}

inline uint32_t StatelessGtpuGenerator::NextInnerIp() noexcept {
    uint32_t ip = current_inner_ip_;
    uint32_t step = config_.inner_ip_step > 0 ? config_.inner_ip_step : 1;
    if (current_inner_ip_ + step > config_.inner_ip_end || current_inner_ip_ + step < current_inner_ip_) {
        current_inner_ip_ = config_.inner_ip_start;
    } else {
        current_inner_ip_ += step;
    }
    return ip;
}

inline void StatelessGtpuGenerator::UpdateInnerIpChecksum(uint8_t* packet) noexcept {
    auto* ip = reinterpret_cast<Ipv4Header*>(packet + inner_ip_offset_);
    ip->checksum = 0;
    ip->checksum = CalculateChecksum(reinterpret_cast<const uint16_t*>(ip), sizeof(Ipv4Header));
}

uint32_t StatelessGtpuGenerator::GeneratePacket(uint8_t* out_buf, size_t max_len) noexcept {
    if (!out_buf || max_len < total_len_) {
        return 0;
    }

    std::memcpy(out_buf, template_buf_, total_len_);

    uint32_t teid = NextTeid();
    *reinterpret_cast<uint32_t*>(out_buf + teid_offset_) = htonl(teid);

    if (config_.with_seq_num) {
        *reinterpret_cast<uint16_t*>(out_buf + seq_offset_) = htons(current_seq_++);
    }

    if (config_.cycle_inner_ip) {
        uint32_t inner_ip = NextInnerIp();
        *reinterpret_cast<uint32_t*>(out_buf + inner_src_ip_offset_) = htonl(inner_ip);
        UpdateInnerIpChecksum(out_buf);
    }

    stats_.packets_generated++;
    stats_.bytes_generated += total_len_;
    stats_.current_teid = teid;
    return static_cast<uint32_t>(total_len_);
}

uint32_t StatelessGtpuGenerator::GenerateBatch(uint8_t* out_ptrs[], uint32_t* out_lens, 
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

bool StatelessGtpuGenerator::VerifyFrame(const uint8_t* frame, size_t len, GtpuGenVerification& out_verif) noexcept {
    out_verif = GtpuGenVerification{};
    if (!frame || len < (sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(GtpuHeaderWire) + sizeof(Ipv4Header))) {
        return false;
    }

    const auto* eth = reinterpret_cast<const EthHeader*>(frame);
    if (ntohs(eth->ethertype) != 0x0800) {
        return false;
    }
    std::memcpy(out_verif.dst_mac, eth->dst_mac, 6);
    std::memcpy(out_verif.src_mac, eth->src_mac, 6);

    size_t offset = sizeof(EthHeader);
    const auto* o_ip = reinterpret_cast<const Ipv4Header*>(frame + offset);
    if ((o_ip->ihl_version >> 4) != 4 || (o_ip->ihl_version & 0x0F) < 5 || o_ip->protocol != 17) {
        return false;
    }
    out_verif.outer_src_ip = ntohl(o_ip->src_ip);
    out_verif.outer_dst_ip = ntohl(o_ip->dst_ip);
    offset += (o_ip->ihl_version & 0x0F) * 4;

    if (len < offset + sizeof(UdpHeader)) return false;
    const auto* o_udp = reinterpret_cast<const UdpHeader*>(frame + offset);
    out_verif.outer_src_port = ntohs(o_udp->src_port);
    out_verif.outer_dst_port = ntohs(o_udp->dst_port);
    offset += sizeof(UdpHeader);

    if (len < offset + sizeof(GtpuHeaderWire)) return false;
    const auto* gtp = reinterpret_cast<const GtpuHeaderWire*>(frame + offset);
    if ((gtp->flags & 0xE0) != 0x20) { // Version 1
        return false;
    }
    out_verif.gtpu_flags = gtp->flags;
    out_verif.gtpu_msg_type = gtp->msg_type;
    out_verif.gtpu_len = ntohs(gtp->length);
    out_verif.teid = ntohl(gtp->teid);
    offset += sizeof(GtpuHeaderWire);

    if (gtp->flags & 0x07) { // S, E, or PN flag
        if (len < offset + sizeof(GtpuOptFieldsWire)) return false;
        const auto* opt = reinterpret_cast<const GtpuOptFieldsWire*>(frame + offset);
        out_verif.has_seq = (gtp->flags & 0x02) != 0;
        out_verif.seq_num = ntohs(opt->seq_num);
        offset += sizeof(GtpuOptFieldsWire);
    }

    if (len < offset + sizeof(Ipv4Header)) return false;
    const auto* i_ip = reinterpret_cast<const Ipv4Header*>(frame + offset);
    if ((i_ip->ihl_version >> 4) != 4 || (i_ip->ihl_version & 0x0F) < 5) {
        return false;
    }
    out_verif.inner_src_ip = ntohl(i_ip->src_ip);
    out_verif.inner_dst_ip = ntohl(i_ip->dst_ip);
    out_verif.inner_proto = i_ip->protocol;
    out_verif.frame_len = len;
    out_verif.is_valid = true;
    return true;
}

} // namespace ddos_samurai::telecom::stateless
