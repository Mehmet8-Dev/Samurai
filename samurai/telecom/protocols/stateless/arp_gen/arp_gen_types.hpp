#pragma once

#include <cstdint>
#include <cstddef>
#include <string_view>
#include <arpa/inet.h>

namespace samurai::telecom::stateless {

// RFC 826 / IEEE 802.3 Constants
inline constexpr uint16_t ETHERTYPE_ARP_VAL      = 0x0806;
inline constexpr uint16_t ARP_HTYPE_ETHERNET_VAL = 0x0001;
inline constexpr uint16_t ARP_PTYPE_IPV4_VAL     = 0x0800;

enum class ArpOpcode : uint16_t {
    REQUEST = 1,
    REPLY   = 2
};

enum class ArpProbeMode : uint8_t {
    ARP_REQUEST     = 0, // RFC 826 ARP Request probe to target IP range
    GARP_REQUEST    = 1, // Gratuitous ARP Request (RFC 5227, sender_ip == target_ip)
    GARP_REPLY      = 2, // Gratuitous ARP Announcement / Reply
    ARP_REPLY_FLOOD = 3  // Directed unicast ARP Reply flood to inject into DUT ARP cache
};

inline std::string_view ArpProbeModeToString(ArpProbeMode mode) noexcept {
    switch (mode) {
        case ArpProbeMode::ARP_REQUEST: return "ARP_REQUEST";
        case ArpProbeMode::GARP_REQUEST: return "GARP_REQUEST";
        case ArpProbeMode::GARP_REPLY: return "GARP_REPLY";
        case ArpProbeMode::ARP_REPLY_FLOOD: return "ARP_REPLY_FLOOD";
        default: return "UNKNOWN";
    }
}

enum class ArpIpCycleMode : uint8_t {
    SEQUENTIAL = 0,
    PSEUDO_RANDOM = 1
};

enum class ArpMacCycleMode : uint8_t {
    FIXED = 0,
    DERIVED_FROM_IP = 1, // Lower 3 bytes of MAC match lower 3 bytes of sweeping IP
    SEQUENTIAL = 2       // Lower 3 bytes increment sequentially
};

#pragma pack(push, 1)
struct ArpEthernetHeaderRaw {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype; // 0x0806
};

struct ArpVlanEthernetHeaderRaw {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t vlan_tpid; // 0x8100
    uint16_t vlan_tci;  // PCP (3) | DEI (1) | VID (12)
    uint16_t ethertype; // 0x0806
};

// RFC 826 28-Bayt ARP PDU
struct ArpPayloadRaw {
    uint16_t htype;       // Hardware Type (1 = Ethernet)
    uint16_t ptype;       // Protocol Type (0x0800 = IPv4)
    uint8_t  hlen;        // Hardware address length (6)
    uint8_t  plen;        // Protocol address length (4)
    uint16_t opcode;      // Opcode (1 = Request, 2 = Reply)
    uint8_t  sender_mac[6];
    uint32_t sender_ip;   // Network byte order
    uint8_t  target_mac[6];
    uint32_t target_ip;   // Network byte order
};
#pragma pack(pop)

static_assert(sizeof(ArpPayloadRaw) == 28, "ArpPayloadRaw must be exactly 28 bytes");
static_assert(sizeof(ArpEthernetHeaderRaw) == 14, "ArpEthernetHeaderRaw must be 14 bytes");
static_assert(sizeof(ArpVlanEthernetHeaderRaw) == 18, "ArpVlanEthernetHeaderRaw must be 18 bytes");

struct ArpGeneratorConfig {
    ArpProbeMode probe_mode{ArpProbeMode::ARP_REQUEST};

    // Target IP range / Subnet Sweep (Host byte order)
    uint32_t target_ip_start{0x0A000001}; // 10.0.0.1
    uint32_t target_ip_end{0x0A00FFFF};   // 10.0.255.255 (/16 sweep)
    uint32_t target_ip_step{1};
    ArpIpCycleMode ip_cycle_mode{ArpIpCycleMode::SEQUENTIAL};
    uint32_t prng_seed{0x55AA55AA};

    // Sender IP
    uint32_t sender_ip{0x0A0000FE};       // 10.0.0.254 (Gateway / Prober)
    bool     cycle_sender_ip{false};

    // MAC Configuration
    uint8_t  sender_mac[6]{0x00, 0x50, 0x56, 0x11, 0x22, 0x33};
    uint8_t  target_mac[6]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t  eth_dst_mac[6]{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ArpMacCycleMode mac_cycle_mode{ArpMacCycleMode::FIXED};
    uint8_t  mac_prefix[3]{0x00, 0x50, 0x56}; // Base OUI for generated MACs

    // Optional 802.1Q VLAN Tagging
    bool     enable_vlan{false};
    uint16_t vlan_id{100};
    uint8_t  vlan_pcp{0};

    // Padding to Ethernet minimum frame (60 bytes without FCS / 64 bytes wire)
    bool     pad_to_min_frame{true};
    uint16_t min_frame_size{60};
};

struct ArpGenStats {
    uint64_t packets_generated{0};
    uint64_t bytes_generated{0};
    uint32_t current_target_ip{0};
    uint32_t ip_sweep_cycles{0};
};

struct ArpVerificationInfo {
    bool     is_valid{false};
    bool     has_vlan{false};
    uint16_t vlan_id{0};
    uint8_t  vlan_pcp{0};
    uint16_t opcode{0};
    uint8_t  eth_dst_mac[6]{0};
    uint8_t  eth_src_mac[6]{0};
    uint8_t  sender_mac[6]{0};
    uint32_t sender_ip{0};
    uint8_t  target_mac[6]{0};
    uint32_t target_ip{0};
    size_t   frame_len{0};
};

} // namespace samurai::telecom::stateless
