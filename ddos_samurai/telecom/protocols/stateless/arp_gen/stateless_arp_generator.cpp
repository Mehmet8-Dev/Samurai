#include "stateless_arp_generator.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <algorithm>

namespace ddos_samurai::telecom::stateless {

StatelessArpGenerator::StatelessArpGenerator() {
    ArpGeneratorConfig default_cfg;
    Init(default_cfg);
}

StatelessArpGenerator::StatelessArpGenerator(const ArpGeneratorConfig& cfg) {
    Init(cfg);
}

bool StatelessArpGenerator::Init(const ProtocolConfig& cfg) {
    ArpGeneratorConfig acfg;
    acfg.target_ip_start = 0x0A000001;
    acfg.target_ip_end = acfg.target_ip_start + (cfg.max_sessions > 0 ? cfg.max_sessions : 1000);
    if (cfg.enable_vlan_tagging) {
        acfg.enable_vlan = true;
        acfg.vlan_id = cfg.base_vlan_s > 0 ? cfg.base_vlan_s : (cfg.base_vlan_c > 0 ? cfg.base_vlan_c : 100);
    }
    return Init(acfg);
}

bool StatelessArpGenerator::Init(const ArpGeneratorConfig& cfg) {
    config_ = cfg;

    if (config_.target_ip_start > config_.target_ip_end) {
        std::swap(config_.target_ip_start, config_.target_ip_end);
    }
    if (config_.target_ip_step == 0) {
        config_.target_ip_step = 1;
    }
    if (config_.prng_seed == 0) {
        config_.prng_seed = 0x55AA55AA;
    }
    rng_state_ = config_.prng_seed;
    current_ip_ = config_.target_ip_start;
    current_mac_seq_ = 1;
    stats_ = ArpGenStats{};

    BuildTemplate();
    initialized_ = true;
    return true;
}

void StatelessArpGenerator::Shutdown() {
    initialized_ = false;
    ResetStats();
}

void StatelessArpGenerator::ResetStats() noexcept {
    stats_ = ArpGenStats{};
}

void StatelessArpGenerator::OnRxPacket(rte_mbuf* /*mbuf*/, 
                                      const PacketMetadata& /*meta*/, 
                                      TelcoSessionContext* /*session*/) {
    // Stateless generator does not track RX state
}

uint32_t StatelessArpGenerator::OnTimerTick(uint64_t /*current_tsc*/) {
    return 0;
}

rte_mbuf* StatelessArpGenerator::BuildTxPacket(rte_mempool* /*pool*/, 
                                              TelcoSessionContext* /*session*/, 
                                              uint16_t /*event_type*/) {
    return nullptr;
}

void StatelessArpGenerator::SetSubnetCidr(uint32_t network_ip, uint8_t prefix_len) {
    if (prefix_len > 32) prefix_len = 32;
    uint32_t mask = (prefix_len == 0) ? 0 : (0xFFFFFFFFU << (32 - prefix_len));
    uint32_t base = network_ip & mask;
    uint32_t broadcast = base | (~mask);

    if (prefix_len <= 30) {
        config_.target_ip_start = base + 1;
        config_.target_ip_end = broadcast - 1;
    } else {
        config_.target_ip_start = base;
        config_.target_ip_end = broadcast;
    }
    current_ip_ = config_.target_ip_start;
    BuildTemplate();
}

void StatelessArpGenerator::BuildTemplate() {
    std::memset(template_buf_, 0, sizeof(template_buf_));

    if (config_.min_frame_size > sizeof(template_buf_)) {
        config_.min_frame_size = static_cast<uint16_t>(sizeof(template_buf_));
    }

    if (config_.enable_vlan) {
        eth_header_len_ = sizeof(ArpVlanEthernetHeaderRaw);
        arp_payload_offset_ = eth_header_len_;

        auto* eth = reinterpret_cast<ArpVlanEthernetHeaderRaw*>(template_buf_);
        std::memcpy(eth->dst_mac, config_.eth_dst_mac, 6);
        std::memcpy(eth->src_mac, config_.sender_mac, 6);
        eth->vlan_tpid = htons(0x8100);
        eth->vlan_tci = htons(((config_.vlan_pcp & 0x07) << 13) | (config_.vlan_id & 0x0FFF));
        eth->ethertype = htons(ETHERTYPE_ARP_VAL);
    } else {
        eth_header_len_ = sizeof(ArpEthernetHeaderRaw);
        arp_payload_offset_ = eth_header_len_;

        auto* eth = reinterpret_cast<ArpEthernetHeaderRaw*>(template_buf_);
        std::memcpy(eth->dst_mac, config_.eth_dst_mac, 6);
        std::memcpy(eth->src_mac, config_.sender_mac, 6);
        eth->ethertype = htons(ETHERTYPE_ARP_VAL);
    }

    sender_mac_offset_ = arp_payload_offset_ + 8;
    sender_ip_offset_  = arp_payload_offset_ + 14;
    target_mac_offset_ = arp_payload_offset_ + 18;
    target_ip_offset_  = arp_payload_offset_ + 24;

    auto* arp = reinterpret_cast<ArpPayloadRaw*>(template_buf_ + arp_payload_offset_);
    arp->htype = htons(ARP_HTYPE_ETHERNET_VAL);
    arp->ptype = htons(ARP_PTYPE_IPV4_VAL);
    arp->hlen = 6;
    arp->plen = 4;

    bool is_reply = (config_.probe_mode == ArpProbeMode::GARP_REPLY || 
                     config_.probe_mode == ArpProbeMode::ARP_REPLY_FLOOD);
    arp->opcode = htons(is_reply ? static_cast<uint16_t>(ArpOpcode::REPLY) 
                                 : static_cast<uint16_t>(ArpOpcode::REQUEST));

    std::memcpy(arp->sender_mac, config_.sender_mac, 6);
    arp->sender_ip = htonl(config_.sender_ip);
    std::memcpy(arp->target_mac, config_.target_mac, 6);
    arp->target_ip = htonl(config_.target_ip_start);

    size_t raw_len = eth_header_len_ + sizeof(ArpPayloadRaw);
    if (config_.pad_to_min_frame && config_.min_frame_size > raw_len) {
        total_len_ = config_.min_frame_size;
    } else {
        total_len_ = raw_len;
    }
}

inline uint32_t StatelessArpGenerator::NextIp() noexcept {
    uint32_t ip = current_ip_;
    if (config_.ip_cycle_mode == ArpIpCycleMode::PSEUDO_RANDOM) {
        rng_state_ ^= rng_state_ << 13;
        rng_state_ ^= rng_state_ >> 17;
        rng_state_ ^= rng_state_ << 5;
        if (rng_state_ == 0) rng_state_ = 0x55AA55AA;
        uint64_t range = (static_cast<uint64_t>(config_.target_ip_end) >= config_.target_ip_start) 
                         ? (static_cast<uint64_t>(config_.target_ip_end) - config_.target_ip_start + 1) : 1;
        ip = config_.target_ip_start + static_cast<uint32_t>(rng_state_ % range);
        return ip;
    }

    uint32_t step = config_.target_ip_step > 0 ? config_.target_ip_step : 1;
    if (current_ip_ + step > config_.target_ip_end || current_ip_ + step < current_ip_) {
        current_ip_ = config_.target_ip_start;
        stats_.ip_sweep_cycles++;
    } else {
        current_ip_ += step;
    }
    return ip;
}

uint32_t StatelessArpGenerator::GeneratePacket(uint8_t* out_buf, size_t max_len) noexcept {
    if (!out_buf || max_len < total_len_) {
        return 0;
    }

    std::memcpy(out_buf, template_buf_, total_len_);

    uint32_t ip = NextIp();

    // 1. MAC format derivation
    uint8_t smac[6];
    std::memcpy(smac, config_.sender_mac, 6);
    if (config_.mac_cycle_mode == ArpMacCycleMode::DERIVED_FROM_IP) {
        smac[0] = config_.mac_prefix[0];
        smac[1] = config_.mac_prefix[1];
        smac[2] = config_.mac_prefix[2];
        smac[3] = static_cast<uint8_t>((ip >> 16) & 0xFF);
        smac[4] = static_cast<uint8_t>((ip >> 8) & 0xFF);
        smac[5] = static_cast<uint8_t>(ip & 0xFF);
    } else if (config_.mac_cycle_mode == ArpMacCycleMode::SEQUENTIAL) {
        uint32_t seq = current_mac_seq_++;
        smac[0] = config_.mac_prefix[0];
        smac[1] = config_.mac_prefix[1];
        smac[2] = config_.mac_prefix[2];
        smac[3] = static_cast<uint8_t>((seq >> 16) & 0xFF);
        smac[4] = static_cast<uint8_t>((seq >> 8) & 0xFF);
        smac[5] = static_cast<uint8_t>(seq & 0xFF);
    }

    // 2. Ethernet Header fields update
    std::memcpy(out_buf + 6, smac, 6); // Ethernet Src MAC

    auto* arp = reinterpret_cast<ArpPayloadRaw*>(out_buf + arp_payload_offset_);

    switch (config_.probe_mode) {
        case ArpProbeMode::ARP_REQUEST:
            arp->opcode = htons(static_cast<uint16_t>(ArpOpcode::REQUEST));
            std::memcpy(arp->sender_mac, smac, 6);
            arp->sender_ip = htonl(config_.cycle_sender_ip ? ip : config_.sender_ip);
            std::memset(arp->target_mac, 0x00, 6);
            arp->target_ip = htonl(config_.cycle_sender_ip ? config_.sender_ip : ip);
            break;

        case ArpProbeMode::GARP_REQUEST:
            arp->opcode = htons(static_cast<uint16_t>(ArpOpcode::REQUEST));
            std::memcpy(arp->sender_mac, smac, 6);
            arp->sender_ip = htonl(ip);
            std::memset(arp->target_mac, 0x00, 6);
            arp->target_ip = htonl(ip);
            break;

        case ArpProbeMode::GARP_REPLY:
            arp->opcode = htons(static_cast<uint16_t>(ArpOpcode::REPLY));
            std::memcpy(arp->sender_mac, smac, 6);
            arp->sender_ip = htonl(ip);
            std::memcpy(arp->target_mac, smac, 6);
            arp->target_ip = htonl(ip);
            break;

        case ArpProbeMode::ARP_REPLY_FLOOD:
            arp->opcode = htons(static_cast<uint16_t>(ArpOpcode::REPLY));
            std::memcpy(arp->sender_mac, smac, 6);
            arp->sender_ip = htonl(ip);
            std::memcpy(arp->target_mac, config_.target_mac, 6);
            arp->target_ip = htonl(config_.sender_ip);
            std::memcpy(out_buf, config_.eth_dst_mac, 6); // Directed router destination MAC
            break;
    }

    stats_.packets_generated++;
    stats_.bytes_generated += total_len_;
    stats_.current_target_ip = (config_.probe_mode == ArpProbeMode::ARP_REQUEST && config_.cycle_sender_ip)
                               ? config_.sender_ip : ip;
    return static_cast<uint32_t>(total_len_);
}

uint32_t StatelessArpGenerator::GenerateBatch(uint8_t* out_ptrs[], uint32_t* out_lens, 
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

bool StatelessArpGenerator::VerifyFrame(const uint8_t* frame, size_t len, ArpVerificationInfo& out_verif) noexcept {
    out_verif = ArpVerificationInfo{};
    if (!frame || len < (sizeof(ArpEthernetHeaderRaw) + sizeof(ArpPayloadRaw))) {
        return false;
    }

    std::memcpy(out_verif.eth_dst_mac, frame, 6);
    std::memcpy(out_verif.eth_src_mac, frame + 6, 6);

    size_t offset = 12;
    uint16_t ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
    offset += 2;

    if (ethertype == 0x8100) { // 802.1Q tagged
        if (len < offset + 4 + sizeof(ArpPayloadRaw)) return false;
        out_verif.has_vlan = true;
        uint16_t tci = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
        out_verif.vlan_pcp = static_cast<uint8_t>((tci >> 13) & 0x07);
        out_verif.vlan_id = tci & 0x0FFF;
        offset += 2;
        ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
        offset += 2;
    }

    if (ethertype != ETHERTYPE_ARP_VAL) {
        return false;
    }

    if (len < offset + sizeof(ArpPayloadRaw)) {
        return false;
    }

    const auto* arp = reinterpret_cast<const ArpPayloadRaw*>(frame + offset);
    if (ntohs(arp->htype) != ARP_HTYPE_ETHERNET_VAL || 
        ntohs(arp->ptype) != ARP_PTYPE_IPV4_VAL || 
        arp->hlen != 6 || arp->plen != 4) {
        return false;
    }

    out_verif.opcode = ntohs(arp->opcode);
    std::memcpy(out_verif.sender_mac, arp->sender_mac, 6);
    out_verif.sender_ip = ntohl(arp->sender_ip);
    std::memcpy(out_verif.target_mac, arp->target_mac, 6);
    out_verif.target_ip = ntohl(arp->target_ip);
    out_verif.frame_len = len;
    out_verif.is_valid = true;
    return true;
}

} // namespace ddos_samurai::telecom::stateless
