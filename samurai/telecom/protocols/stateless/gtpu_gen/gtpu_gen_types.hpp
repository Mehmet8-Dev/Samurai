#pragma once

#include <cstdint>
#include <cstddef>
#include <string_view>

namespace samurai::telecom::stateless {

// 3GPP TS 29.281 Constants
inline constexpr uint16_t GTPU_PORT_DEFAULT = 2152;
inline constexpr uint8_t  GTPU_MSG_GPDU     = 255;
inline constexpr uint8_t  GTPU_BASE_FLAGS   = 0x30; // GTPv1 (0x20) | PT=1 (0x10)

enum class TeidCycleMode : uint8_t {
    SEQUENTIAL = 0,
    PSEUDO_RANDOM = 1,
    RANGE_SWEEP = 2
};

inline std::string_view TeidCycleModeToString(TeidCycleMode mode) noexcept {
    switch (mode) {
        case TeidCycleMode::SEQUENTIAL: return "SEQUENTIAL";
        case TeidCycleMode::PSEUDO_RANDOM: return "PSEUDO_RANDOM";
        case TeidCycleMode::RANGE_SWEEP: return "RANGE_SWEEP";
        default: return "UNKNOWN";
    }
}

enum class InnerProtocol : uint8_t {
    ICMP_ECHO = 1,
    UDP = 17
};

inline std::string_view InnerProtocolToString(InnerProtocol proto) noexcept {
    switch (proto) {
        case InnerProtocol::ICMP_ECHO: return "ICMP_ECHO";
        case InnerProtocol::UDP: return "UDP";
        default: return "UNKNOWN";
    }
}

struct GtpuGenConfig {
    // Outer L2 Ethernet
    uint8_t  src_mac[6]{0x00, 0x16, 0x3E, 0x10, 0x00, 0x01};
    uint8_t  dst_mac[6]{0x00, 0x16, 0x3E, 0x20, 0x00, 0x01};

    // Outer L3 IPv4 (Host Byte Order)
    uint32_t outer_src_ip{0x0A000001}; // 10.0.0.1
    uint32_t outer_dst_ip{0x0A000002}; // 10.0.0.2
    uint8_t  outer_ttl{64};
    uint8_t  outer_tos{0};

    // Outer L4 UDP
    uint16_t outer_src_port{GTPU_PORT_DEFAULT};
    uint16_t outer_dst_port{GTPU_PORT_DEFAULT};

    // GTP-U Header Options
    uint8_t  gtpu_flags{GTPU_BASE_FLAGS};
    uint8_t  gtpu_msg_type{GTPU_MSG_GPDU};
    bool     with_seq_num{false};

    // TEID Cycling Configuration
    TeidCycleMode teid_mode{TeidCycleMode::SEQUENTIAL};
    uint32_t teid_start{1};
    uint32_t teid_end{1000000};
    uint32_t teid_step{1};
    uint32_t prng_seed{0x12345678};

    // Inner L3/L4 Packet (Host Byte Order)
    uint32_t inner_src_ip{0x0A2D0002}; // 10.45.0.2
    uint32_t inner_dst_ip{0x08080808}; // 8.8.8.8
    uint8_t  inner_ttl{64};
    InnerProtocol inner_proto{InnerProtocol::ICMP_ECHO};
    uint16_t inner_src_port{12345};
    uint16_t inner_dst_port{80};
    uint16_t inner_payload_size{16}; // Dummy payload bytes after ICMP/UDP header

    // Inner IP Cycling
    bool     cycle_inner_ip{false};
    uint32_t inner_ip_start{0x0A2D0002};
    uint32_t inner_ip_end{0x0A2DFFFF};
    uint32_t inner_ip_step{1};
};

struct GtpuGenStats {
    uint64_t packets_generated{0};
    uint64_t bytes_generated{0};
    uint32_t current_teid{0};
    uint32_t teid_wraparounds{0};
};

struct GtpuGenVerification {
    bool     is_valid{false};
    uint8_t  src_mac[6]{0};
    uint8_t  dst_mac[6]{0};
    uint32_t outer_src_ip{0};
    uint32_t outer_dst_ip{0};
    uint16_t outer_src_port{0};
    uint16_t outer_dst_port{0};
    uint8_t  gtpu_flags{0};
    uint8_t  gtpu_msg_type{0};
    uint16_t gtpu_len{0};
    uint32_t teid{0};
    bool     has_seq{false};
    uint16_t seq_num{0};
    uint32_t inner_src_ip{0};
    uint32_t inner_dst_ip{0};
    uint8_t  inner_proto{0};
    size_t   frame_len{0};
};

} // namespace samurai::telecom::stateless
