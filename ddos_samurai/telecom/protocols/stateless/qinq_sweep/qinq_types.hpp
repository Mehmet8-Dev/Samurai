#pragma once

#include <cstdint>
#include <cstddef>
#include <string_view>
#include <arpa/inet.h>

namespace ddos_samurai::telecom::stateless {

inline constexpr uint16_t ETHERTYPE_8021AD = 0x88A8; // Outer S-Tag (IEEE 802.1ad Provider Bridging)
inline constexpr uint16_t ETHERTYPE_8021Q  = 0x8100; // Inner C-Tag (IEEE 802.1Q Customer Tag)
inline constexpr uint16_t ETHERTYPE_9100   = 0x9100; // Alternate QinQ S-Tag for legacy telecom switches

enum class QinQSweepMode : uint8_t {
    S_THEN_C = 0,      // Fix S-VLAN, cycle all C-VLANs, then increment S-VLAN
    C_THEN_S = 1,      // Fix C-VLAN, cycle all S-VLANs, then increment C-VLAN
    PSEUDO_RANDOM = 2, // Pseudo-random valid (S, C) pair within ranges
    FLAT_FIXED = 3     // Constant fixed S-VLAN and C-VLAN
};

inline std::string_view QinQSweepModeToString(QinQSweepMode mode) noexcept {
    switch (mode) {
        case QinQSweepMode::S_THEN_C: return "S_THEN_C";
        case QinQSweepMode::C_THEN_S: return "C_THEN_S";
        case QinQSweepMode::PSEUDO_RANDOM: return "PSEUDO_RANDOM";
        case QinQSweepMode::FLAT_FIXED: return "FLAT_FIXED";
        default: return "UNKNOWN";
    }
}

#pragma pack(push, 1)
struct VlanTagRaw {
    uint16_t tpid; // 0x88A8 or 0x8100 (network byte order)
    uint16_t tci;  // PCP (3 bits) | DEI (1 bit) | VID (12 bits) (network byte order)
};

struct QinQEthernetHeader {
    uint8_t    dst_mac[6];
    uint8_t    src_mac[6];
    VlanTagRaw s_tag; // Outer 802.1ad
    VlanTagRaw c_tag; // Inner 802.1Q
    uint16_t   inner_ethertype; // e.g. 0x0800 (IPv4)
};
#pragma pack(pop)

static_assert(sizeof(VlanTagRaw) == 4, "VlanTagRaw must be 4 bytes");
static_assert(sizeof(QinQEthernetHeader) == 22, "QinQEthernetHeader must be 22 bytes");

inline uint16_t EncodeTci(uint16_t vid, uint8_t pcp, bool dei) noexcept {
    uint16_t val = static_cast<uint16_t>(((pcp & 0x07) << 13) | ((dei ? 1 : 0) << 12) | (vid & 0x0FFF));
    return htons(val);
}

inline void DecodeTci(uint16_t tci_be, uint16_t& out_vid, uint8_t& out_pcp, bool& out_dei) noexcept {
    uint16_t val = ntohs(tci_be);
    out_pcp = static_cast<uint8_t>((val >> 13) & 0x07);
    out_dei = ((val >> 12) & 0x01) != 0;
    out_vid = val & 0x0FFF;
}

struct QinQGeneratorConfig {
    // Outer L2 MACs
    uint8_t  src_mac[6]{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x01};
    uint8_t  dst_mac[6]{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x02};

    // Outer S-VLAN (802.1ad Service Tag)
    uint16_t s_tpid{ETHERTYPE_8021AD}; // default 0x88A8
    uint16_t s_vlan_min{1};
    uint16_t s_vlan_max{4094};
    uint16_t s_vlan_step{1};
    uint8_t  s_pcp{0}; // 0..7 (Priority Code Point)
    bool     s_dei{false}; // Drop Eligible Indicator

    // Inner C-VLAN (802.1Q Customer Tag)
    uint16_t c_tpid{ETHERTYPE_8021Q}; // default 0x8100
    uint16_t c_vlan_min{1};
    uint16_t c_vlan_max{4094};
    uint16_t c_vlan_step{1};
    uint8_t  c_pcp{0};
    bool     c_dei{false};

    // Sweep Configuration
    QinQSweepMode sweep_mode{QinQSweepMode::S_THEN_C};
    uint32_t prng_seed{0x98765432};

    // Inner Payload (Default: IPv4 UDP test frame)
    uint16_t inner_ethertype{0x0800};
    uint32_t inner_src_ip{0xC0A80102}; // 192.168.1.2
    uint32_t inner_dst_ip{0xC0A80101}; // 192.168.1.1
    uint16_t payload_size{28}; // Minimum 28 bytes payload for >=64B Ethernet wire frame
    bool     cycle_src_mac{false}; // If true, low bytes of src MAC reflect current VLAN IDs
};

struct QinQGenStats {
    uint64_t packets_generated{0};
    uint64_t bytes_generated{0};
    uint16_t current_s_vlan{0};
    uint16_t current_c_vlan{0};
    uint32_t sweep_cycles{0};
};

struct QinQVerificationInfo {
    bool     is_valid{false};
    uint8_t  src_mac[6]{0};
    uint8_t  dst_mac[6]{0};
    uint16_t s_tpid{0};
    uint16_t s_vlan{0};
    uint8_t  s_pcp{0};
    bool     s_dei{false};
    uint16_t c_tpid{0};
    uint16_t c_vlan{0};
    uint8_t  c_pcp{0};
    bool     c_dei{false};
    uint16_t inner_ethertype{0};
    size_t   frame_len{0};
};

} // namespace ddos_samurai::telecom::stateless
